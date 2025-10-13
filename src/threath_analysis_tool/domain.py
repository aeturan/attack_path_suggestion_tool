"""
Contains all data structures and domain models for the application.
"""
import uuid
from abc import ABC, abstractmethod
from typing import Dict, List, Literal, Optional, Union, Tuple

from pydantic import BaseModel, Field


# --- Command Pattern Abstract Base Class ---
class Command(ABC):
    @abstractmethod
    def execute(self): pass
    @abstractmethod
    def undo(self): pass
    @property
    @abstractmethod
    def description(self) -> str: pass

# --- Trigger Models ---
class BaseTrigger(BaseModel):
    type: str
class SelfTrigger(BaseTrigger):
    type: Literal["self"] = "self"
class DatasourceTrigger(BaseTrigger):
    type: Literal["datasource"] = "datasource"
    datasource_id: str
class CommunicationTrigger(BaseTrigger):
    type: Literal["communication"] = "communication"
    source_actor_id: str
    edge_type: Literal["communicate", "respond"]

Trigger = Union[SelfTrigger, DatasourceTrigger, CommunicationTrigger]

# --- Core Graph Element Models ---
class Node(BaseModel):
    id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    type: Literal["Actor", "Datasource"]
class Actor(Node):
    type: Literal["Actor"] = "Actor"
    triggers: List[Trigger] = Field(default_factory=list)
class Datasource(Node):
    type: Literal["Datasource"] = "Datasource"

class Edge(BaseModel):
    source: str
    target: str
    type: Literal["read", "write", "communicate", "respond"]

# --- Analysis Result Models (REDESIGNED) ---

class Action(BaseModel):
    """Represents a single atomic action, like 'write' or 'communicate'."""
    source_id: str
    edge_type: str
    target_id: str

class TriggerChain(BaseModel):
    """
    Represents a sequence of actions that causes an actor to be triggered.
    UPDATED: Now contains a full list of AttackStep objects for recursive rendering.
    """
    steps: List["AttackStep"] = Field(default_factory=list) # Changed from List[Action]
    cost: int

class AttackStep(BaseModel):
    """
    Represents one step in an Attempt. It includes the main action and the
    triggers required to make it happen.
    """
    push_poison_action: Action
    consumption_trigger: Optional[TriggerChain] = None
    edge_activation_trigger: Optional[TriggerChain] = None
    total_step_cost: int

# This is required for Pydantic to resolve the recursive model reference
TriggerChain.model_rebuild()

class Attempt(BaseModel):
    """
    Represents a self-contained sequence of steps initiated by the attacker
    to achieve a specific subgoal (e.g., compromise an actor).
    """
    steps: List[AttackStep] = Field(default_factory=list)
    total_attempt_cost: int
    summary: str 

class AttackPlan(BaseModel):
    """
    The final output of the planner. It is a sequence of one or more
    Attempts that lead to the final goal.
    """
    attempts: List[Attempt] = Field(default_factory=list)
    total_cost: int


# --- Main Graph & History Models ---
class Graph(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "Untitled Graph"
    nodes: List[Union[Actor, Datasource]] = []
    edges: List[Edge] = []
    attacker_id: str | None = None
    victim_id: str | None = None
    def get_node(self, node_id: str) -> Union[Actor, Datasource, None]:
        for node in self.nodes:
            if node.id == node_id: return node
        return None
    def get_edge(self, source_id: str, target_id: str) -> Edge | None:
        for edge in self.edges:
            if edge.source == source_id and edge.target == target_id: return edge
        return None

class CommandHistory(BaseModel):
    undo_stack: List[Command] = []
    redo_stack: List[Command] = []
    class Config: arbitrary_types_allowed = True
    def execute(self, command: Command):
        command.execute()
        self.undo_stack.append(command)
        self.redo_stack.clear()
    def undo(self):
        if self.undo_stack:
            command = self.undo_stack.pop()
            command.undo()
            self.redo_stack.append(command)
    def redo(self):
        if self.redo_stack:
            command = self.redo_stack.pop()
            command.execute()
            self.undo_stack.append(command)