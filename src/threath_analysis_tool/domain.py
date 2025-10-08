"""
Contains all data structures and domain models for the application.

This module defines the "nouns" of our system using Pydantic for validation.
It includes models for graph elements (Nodes, Edges), commands (Command Pattern),
and application configuration. It has no dependencies on other local modules.
"""
import uuid
from abc import ABC, abstractmethod
from typing import Dict, List, Literal, Union

from pydantic import BaseModel, Field

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
    can_self_trigger: bool = False

class Datasource(Node):
    type: Literal["Datasource"] = "Datasource"

class Edge(BaseModel):
    source: str
    target: str
    # The 'type' is now more explicit, removing the need for boolean flags.
    # 'communicate' is an initiating action.
    # 'respond' is a non-initiating, reply-only action.
    type: Literal["read", "write", "communicate", "respond"]

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