"""
Contains all data structures and domain models for the application.

This module defines the "nouns" of our system using Pydantic for validation.
It includes models for graph elements (Nodes, Edges), commands (Command Pattern),
and application configuration. It has no dependencies on other local modules.
"""
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Literal, Union

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

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

    @field_validator('type')
    def comm_props_only_for_communicate(cls, v, values):
        # Pydantic v2 style validator access
        data = values.data
        if v != 'communicate' and (data.get('response_only') or data.get('cardinality') != 'request-response'):
            raise ValueError("response_only and cardinality properties are only applicable for 'communicate' edges.")
        return v

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

# --- Concrete Command Implementations ---

class AddNodeCommand(Command):
    def __init__(self, graph: Graph, node_data: Dict[str, Any]):
        self.graph = graph
        self.node_data = node_data
        if self.node_data['type'] == 'Actor':
            self.node = Actor(**self.node_data)
        else:
            self.node = Datasource(**self.node_data)

    def execute(self):
        self.graph.nodes.append(self.node)

    def undo(self):
        self.graph.nodes = [n for n in self.graph.nodes if n.id != self.node.id]

    @property
    def description(self) -> str:
        return f"Add {self.node.type}: '{self.node.name}'"

class DeleteNodeCommand(Command):
    def __init__(self, graph: Graph, node_id: str):
        self.graph = graph
        self.node_id = node_id
        self.node: Node | None = self.graph.get_node(node_id)
        self.deleted_edges = [edge for edge in self.graph.edges if edge.source == node_id or edge.target == node_id]

    def execute(self):
        if self.node:
            self.graph.nodes = [n for n in self.graph.nodes if n.id != self.node_id]
            self.graph.edges = [e for e in self.graph.edges if e.source != self.node_id and e.target != self.node_id]

    def undo(self):
        if self.node:
            self.graph.nodes.append(self.node)
            self.graph.edges.extend(self.deleted_edges)

    @property
    def description(self) -> str:
        return f"Delete Node: '{self.node.name if self.node else self.node_id}'"

class AddEdgeCommand(Command):
    def __init__(self, graph: Graph, edge_data: Dict[str, Any]):
        self.graph = graph
        self.edge_data = edge_data
        self.edge = Edge(**self.edge_data)

    def execute(self):
        if not self.graph.get_edge(self.edge.source, self.edge.target):
            self.graph.edges.append(self.edge)

    def undo(self):
        self.graph.edges = [e for e in self.graph.edges if not (e.source == self.edge.source and e.target == self.edge.target)]

    @property
    def description(self) -> str:
        source_name = self.graph.get_node(self.edge.source).name
        target_name = self.graph.get_node(self.edge.target).name
        return f"Add Edge: '{source_name}' → '{target_name}'"

class SetRoleCommand(Command):
    def __init__(self, graph: Graph, role: Literal['attacker', 'victim'], actor_id: str):
        self.graph = graph
        self.role = role
        self.actor_id = actor_id
        self.previous_id: str | None = getattr(self.graph, f"{role}_id")

    def execute(self):
        setattr(self.graph, f"{self.role}_id", self.actor_id)

    def undo(self):
        setattr(self.graph, f"{self.role}_id", self.previous_id)

    @property
    def description(self) -> str:
        actor_name = self.graph.get_node(self.actor_id).name
        return f"Set {self.role.capitalize()}: '{actor_name}'"

# --- Application Configuration ---

class StorageConfig(BaseSettings):
    sessions_dir: Path = Field(default=Path("sessions"), description="Directory to store graph session files.")

class AnalysisConfig(BaseSettings):
    max_path_length: int = Field(default=10, gt=0, description="Maximum number of steps to explore in a single attack path.")
    default_strategy: str = Field(default="GreedyDFSStrategy", description="The default pathfinding strategy to use.")

class AppConfig(BaseSettings):
    model_config = SettingsConfigDict(env_nested_delimiter="__")
    storage: StorageConfig = StorageConfig()
    analysis: AnalysisConfig = AnalysisConfig()

APP_CONFIG = AppConfig()