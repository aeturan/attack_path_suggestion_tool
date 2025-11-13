"""
Contains all data structures and domain models for the application.
"""
import uuid
from abc import ABC, abstractmethod
from typing import List, Literal, Optional, Union, Tuple, Set, TypeAlias

from pydantic import BaseModel, Field, ConfigDict


# Core action/edge semantics typed once to keep string literals consistent.
EdgeType: TypeAlias = Literal["read", "write", "communicate", "respond"]
CommunicationTriggerType: TypeAlias = Literal["communicate", "respond"]
DerivedTriggerActionType: TypeAlias = Literal["self_trigger", "datasource", "trigger"]
SpecialActionType: TypeAlias = Literal["exploit"]
ActionType: TypeAlias = EdgeType | DerivedTriggerActionType | SpecialActionType


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
    edge_type: CommunicationTriggerType

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
    type: EdgeType

# --- Analysis Result Models ---

class Action(BaseModel):
    source_id: str
    edge_type: ActionType
    target_id: str

class TriggerChain(BaseModel):
    steps: List["AttackStep"] = Field(default_factory=list)
    cost: int

class AttackStep(BaseModel):
    push_poison_action: Action
    target_actor_id: str
    compromise_edge: Tuple[str, str]
    consumption_trigger: Optional[TriggerChain] = None
    edge_activation_trigger: Optional[TriggerChain] = None
    cost: int
    summary: str

TriggerChain.model_rebuild()

class AttackPlan(BaseModel):
    steps: List[AttackStep] = Field(default_factory=list)
    total_cost: int
    # Add a transient field to carry the active channels state during the search
    active_channels: Set[Tuple[str, str]] = Field(default_factory=set, exclude=True)


# --- Main Graph & History Models ---
class Graph(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "Untitled Graph"
    nodes: List[Union[Actor, Datasource]] = Field(default_factory=list)
    edges: List[Edge] = Field(default_factory=list)
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
    undo_stack: List[Command] = Field(default_factory=list)
    redo_stack: List[Command] = Field(default_factory=list)
    model_config = ConfigDict(arbitrary_types_allowed=True)
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