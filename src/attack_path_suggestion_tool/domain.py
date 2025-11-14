"""Typed domain objects shared between the UI, analysis engine, and storage."""

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
    """Minimal interface for undoable UI actions.

    Each UI interaction (adding nodes, wiring edges, etc.) is captured as a
    concrete command so the sidebar can provide undo/redo. Commands should be
    side-effect free until :meth:`execute` is invoked.
    """

    @abstractmethod
    def execute(self) -> None:
        """Apply the change to the current graph session."""

    @abstractmethod
    def undo(self) -> None:
        """Reverse the change performed by :meth:`execute`."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-friendly summary used inside the undo stack UI."""

# --- Trigger Models ---
class BaseTrigger(BaseModel):
    """Marker base-class for triggers that awaken actors."""

    type: str


class SelfTrigger(BaseTrigger):
    """An actor that can always re-activate itself."""

    type: Literal["self"] = "self"


class DatasourceTrigger(BaseTrigger):
    """Trigger fired when a watched datasource receives a write."""

    type: Literal["datasource"] = "datasource"
    datasource_id: str


class CommunicationTrigger(BaseTrigger):
    """Trigger fired when another actor communicates/responds."""

    type: Literal["communication"] = "communication"
    source_actor_id: str
    edge_type: CommunicationTriggerType

Trigger = Union[SelfTrigger, DatasourceTrigger, CommunicationTrigger]

# --- Core Graph Element Models ---
class Node(BaseModel):
    """Base class for all graph nodes exposed in the UI."""

    id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    type: Literal["Actor", "Datasource"]


class Actor(Node):
    """Active component capable of performing actions."""

    type: Literal["Actor"] = "Actor"
    triggers: List[Trigger] = Field(default_factory=list)


class Datasource(Node):
    """Passive container component used by actors."""

    type: Literal["Datasource"] = "Datasource"


class Edge(BaseModel):
    """Directed interaction between two nodes."""

    source: str
    target: str
    type: EdgeType

# --- Analysis Result Models ---

class Action(BaseModel):
    """Primitive action that pushes poison or activates a trigger."""

    source_id: str
    edge_type: ActionType
    target_id: str

class TriggerChain(BaseModel):
    """Nested list of attack steps required to trigger an action."""

    steps: List["AttackStep"] = Field(default_factory=list)
    cost: int

class AttackStep(BaseModel):
    """Single hop inside an attack plan, including supporting triggers."""

    push_poison_action: Action
    target_actor_id: str
    compromise_edge: Tuple[str, str]
    consumption_trigger: Optional[TriggerChain] = None
    edge_activation_trigger: Optional[TriggerChain] = None
    cost: int
    summary: str

TriggerChain.model_rebuild()

class AttackPlan(BaseModel):
    """Ordered list of steps from attacker to assets."""

    steps: List[AttackStep] = Field(default_factory=list)
    total_cost: int
    # Add a transient field to carry the active channels state during the search
    active_channels: Set[Tuple[str, str]] = Field(default_factory=set, exclude=True)


# --- Main Graph & History Models ---
class Graph(BaseModel):
    """Mutable, user-defined architecture graph."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "Untitled Graph"
    nodes: List[Union[Actor, Datasource]] = Field(default_factory=list)
    edges: List[Edge] = Field(default_factory=list)
    attacker_id: str | None = None
    victim_id: str | None = None

    def get_node(self, node_id: str) -> Union[Actor, Datasource, None]:
        """Return the node with ``node_id`` if it exists."""

        for node in self.nodes:
            if node.id == node_id:
                return node
        return None

    def get_edge(self, source_id: str, target_id: str) -> Edge | None:
        """Return the edge connecting ``source_id`` → ``target_id`` if present."""

        for edge in self.edges:
            if edge.source == source_id and edge.target == target_id:
                return edge
        return None

class CommandHistory(BaseModel):
    """Bounded command stack powering undo/redo inside Streamlit state."""

    undo_stack: List[Command] = Field(default_factory=list)
    redo_stack: List[Command] = Field(default_factory=list)
    model_config = ConfigDict(arbitrary_types_allowed=True)

    def execute(self, command: Command) -> None:
        """Execute a command and push it to the undo stack."""

        command.execute()
        self.undo_stack.append(command)
        self.redo_stack.clear()

    def undo(self) -> None:
        """Pop from the undo stack and revert the change."""

        if self.undo_stack:
            command = self.undo_stack.pop()
            command.undo()
            self.redo_stack.append(command)

    def redo(self) -> None:
        """Replay the most recent undone command."""

        if self.redo_stack:
            command = self.redo_stack.pop()
            command.execute()
            self.undo_stack.append(command)