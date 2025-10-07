from typing import Any, Dict, Literal

from domain import Actor, Command, Datasource, Edge, Graph, Node


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

        # --- CONTEXTUAL VALIDATION ---
        # Perform validation before creating the Edge object to provide immediate, clear feedback to the user.
        # This is the correct layer for this logic, as it requires context from the graph.
        source_node = graph.get_node(edge_data['source'])
        target_node = graph.get_node(edge_data['target'])
        edge_type = edge_data['type']

        if not source_node or not target_node:
            raise ValueError("Edge source or target node not found.")

        source_type = source_node.type
        target_type = target_node.type

        error_msg = None
        if edge_type == 'read' and not (source_type == 'Datasource' and target_type == 'Actor'):
            error_msg = "Invalid 'read' edge: Must be from a Datasource to an Actor."
        elif edge_type == 'write' and not (source_type == 'Actor' and target_type == 'Datasource'):
            error_msg = "Invalid 'write' edge: Must be from an Actor to a Datasource."
        elif edge_type == 'communicate' and not (source_type == 'Actor' and target_type == 'Actor'):
            error_msg = "Invalid 'communicate' edge: Must be between two Actors."
        
        if error_msg:
            raise ValueError(f"{error_msg} (Attempted: {source_type} -> {target_type})")
        # --- END VALIDATION ---

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
