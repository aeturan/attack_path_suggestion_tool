"""
Contains all data structures and domain models for the application.

This module defines the "nouns" of our system using Pydantic for validation.
It includes models for graph elements (Nodes, Edges), commands (Command Pattern),
and application configuration. It has no dependencies on other local modules.
"""
import uuid
from abc import ABC, abstractmethod
from typing import Dict, List, Literal, Union

from pydantic import BaseModel, Field, model_validator

# --- Command Pattern Abstract Base Class ---

class Command(ABC):
    """Abstract base class for a command in the Command Pattern."""
    @abstractmethod
    def execute(self):
        """Executes the command, changing the application state."""
        pass

    @abstractmethod
    def undo(self):
        """Reverts the changes made by the execute method."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """A human-readable description for the action history UI."""
        pass

# --- Core Graph Element Models ---

class Node(BaseModel):
    id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    type: Literal["Actor", "Datasource"]
    description: str = ""
    tags: List[str] = []
    assumptions: List[str] = []

class Actor(Node):
    type: Literal["Actor"] = "Actor"
    max_self_triggers: int = Field(default=1, ge=0)
    triggers: List[Dict[str, str]] = []

class Datasource(Node):
    type: Literal["Datasource"] = "Datasource"

class Edge(BaseModel):
    source: str
    target: str
    type: Literal["read", "write", "communicate"]
    response_only: bool = False
    cardinality: Literal["request-response", "streaming"] = "request-response"

    @model_validator(mode='after')
    def check_communication_properties(self) -> 'Edge':
        """
        Ensures that properties specific to 'communicate' edges are only used for that type
        and have default values for other types. This enforces internal model consistency.
        """
        if self.type != 'communicate':
            if self.response_only is not False:
                raise ValueError("The 'response_only' property is only applicable for 'communicate' edges.")
            if self.cardinality != 'request-response':
                raise ValueError("The 'cardinality' property is only applicable for 'communicate' edges.")
        return self

# --- Analysis Result Models ---

class PathStep(BaseModel):
    actor_id: str
    action: str
    target_id: str
    step_type: Literal["poison", "trigger"]

class AttackChain(BaseModel):
    steps: List[PathStep] = []

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
            if node.id == node_id:
                return node
        return None

    def get_edge(self, source_id: str, target_id: str) -> Edge | None:
        for edge in self.edges:
            if edge.source == source_id and edge.target == target_id:
                return edge
        return None

class CommandHistory(BaseModel):
    undo_stack: List[Command] = []
    redo_stack: List[Command] = []

    class Config:
        arbitrary_types_allowed = True

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
