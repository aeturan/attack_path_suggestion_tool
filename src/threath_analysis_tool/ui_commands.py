from typing import Any, Dict, List, Literal

from domain import (
    Actor,
    Command,
    CommunicationTrigger,
    Datasource,
    DatasourceTrigger,
    Edge,
    Graph,
    Node,
    SelfTrigger,
    Trigger,
)


class AddNodeCommand(Command):
    def __init__(self, graph: Graph, node_data: Dict[str, Any]):
        self.graph = graph
        
        has_self_trigger = node_data.pop("has_self_trigger", False)
        watched_ds_ids = node_data.pop("watches_datasources", [])
        
        self.node_data = node_data
        
        if self.node_data['type'] == 'Actor':
            self.node = Actor(**self.node_data)
            if has_self_trigger:
                self.node.triggers.append(SelfTrigger())
            for ds_id in watched_ds_ids:
                self.node.triggers.append(DatasourceTrigger(datasource_id=ds_id))
        else:
            self.node = Datasource(**self.node_data)

    def execute(self):
        self.graph.nodes.append(self.node)

    def undo(self):
        self.graph.nodes = [n for n in self.graph.nodes if n.id != self.node.id]

    @property
    def description(self) -> str:
        return f"Add {self.node.type}: '{self.node.name}'"

class EditNodeCommand(Command):
    def __init__(self, graph: Graph, node_id: str, new_data: Dict[str, Any]):
        self.graph = graph
        self.node_id = node_id
        self.new_data = new_data
        
        node = self.graph.get_node(node_id)
        self.node_before = node.model_copy(deep=True)

    def execute(self):
        node = self.graph.get_node(self.node_id)
        if not node:
            return

        node.name = self.new_data['name']

        if isinstance(node, Actor):
            new_triggers = []
            if self.new_data.get('has_self_trigger'):
                new_triggers.append(SelfTrigger())
            for ds_id in self.new_data.get('watches_datasources', []):
                new_triggers.append(DatasourceTrigger(datasource_id=ds_id))
            
            for trigger in node.triggers:
                if isinstance(trigger, CommunicationTrigger):
                    new_triggers.append(trigger)
            
            node.triggers = new_triggers

    def undo(self):
        for i, n in enumerate(self.graph.nodes):
            if n.id == self.node_id:
                self.graph.nodes[i] = self.node_before
                break
    
    @property
    def description(self) -> str:
        if self.node_before.name != self.new_data['name']:
            return f"Rename Node: '{self.node_before.name}' → '{self.new_data['name']}'"
        return f"Edit Node: '{self.node_before.name}'"


class DeleteNodeCommand(Command):
    def __init__(self, graph: Graph, node_id: str):
        self.graph = graph
        self.node_id = node_id
        self.node: Node | None = self.graph.get_node(node_id)
        self.deleted_edges = [edge for edge in self.graph.edges if edge.source == node_id or edge.target == node_id]
        
        self.modified_actors_before: Dict[str, Actor] = {}
        if self.node:
            if self.node.type == 'Actor':
                for actor in self.graph.nodes:
                    if isinstance(actor, Actor) and actor.id != self.node_id:
                        if any(isinstance(t, CommunicationTrigger) and t.source_actor_id == self.node_id for t in actor.triggers):
                            self.modified_actors_before[actor.id] = actor.model_copy(deep=True)
            elif self.node.type == 'Datasource':
                for actor in self.graph.nodes:
                    if isinstance(actor, Actor):
                        if any(isinstance(t, DatasourceTrigger) and t.datasource_id == self.node_id for t in actor.triggers):
                            self.modified_actors_before[actor.id] = actor.model_copy(deep=True)


    def execute(self):
        if not self.node:
            return
            
        if self.node.type == 'Actor':
            for actor_model in self.graph.nodes:
                if isinstance(actor_model, Actor) and actor_model.id in self.modified_actors_before:
                    actor_model.triggers = [t for t in actor_model.triggers if not (isinstance(t, CommunicationTrigger) and t.source_actor_id == self.node_id)]
        elif self.node.type == 'Datasource':
            for actor_model in self.graph.nodes:
                if isinstance(actor_model, Actor) and actor_model.id in self.modified_actors_before:
                    actor_model.triggers = [t for t in actor_model.triggers if not (isinstance(t, DatasourceTrigger) and t.datasource_id == self.node_id)]

        self.graph.nodes = [n for n in self.graph.nodes if n.id != self.node_id]
        self.graph.edges = [e for e in self.graph.edges if e.source != self.node_id and e.target != self.node_id]

    def undo(self):
        if not self.node:
            return
            
        self.graph.nodes.append(self.node)
        self.graph.edges.extend(self.deleted_edges)
        
        for actor_id, original_actor_state in self.modified_actors_before.items():
            for i, n in enumerate(self.graph.nodes):
                if n.id == actor_id:
                    self.graph.nodes[i] = original_actor_state
                    break

    @property
    def description(self) -> str:
        return f"Delete Node: '{self.node.name if self.node else self.node_id}'"

class AddEdgeCommand(Command):
    def __init__(self, graph: Graph, edge_data: Dict[str, Any]):
        self.graph = graph
        self.edge = Edge(**edge_data)
        self.target_actor_before: Actor | None = None

        if self.edge.type in ["communicate", "respond"]:
            target_node = self.graph.get_node(self.edge.target)
            if isinstance(target_node, Actor):
                self.target_actor_before = target_node.model_copy(deep=True)

    def execute(self):
        if self.graph.get_edge(self.edge.source, self.edge.target):
            return 
            
        self.graph.edges.append(self.edge)
        
        if self.target_actor_before:
            target_node = self.graph.get_node(self.edge.target)
            if isinstance(target_node, Actor):
                new_trigger = CommunicationTrigger(
                    source_actor_id=self.edge.source,
                    edge_type=self.edge.type
                )
                if not any(t == new_trigger for t in target_node.triggers):
                    target_node.triggers.append(new_trigger)

    def undo(self):
        self.graph.edges = [e for e in self.graph.edges if not (e.source == self.edge.source and e.target == self.edge.target)]
        
        if self.target_actor_before:
            for i, n in enumerate(self.graph.nodes):
                if n.id == self.target_actor_before.id:
                    self.graph.nodes[i] = self.target_actor_before
                    break

    @property
    def description(self) -> str:
        source_name = self.graph.get_node(self.edge.source).name
        target_name = self.graph.get_node(self.edge.target).name
        return f"Add Edge ({self.edge.type}): '{source_name}' → '{target_name}'"

class CreateRespondAndActivatorCommand(Command):
    """A composite command to add a respond edge and its activating communicate edge."""
    def __init__(self, graph: Graph, respond_edge_data: Dict[str, Any], comm_edge_data: Dict[str, Any]):
        # This order is important for the undo state of AddEdgeCommand to be captured correctly.
        # The state before the first command is the baseline.
        self.sub_commands = [
            AddEdgeCommand(graph, comm_edge_data),
            AddEdgeCommand(graph, respond_edge_data)
        ]

    def execute(self):
        for command in self.sub_commands:
            command.execute()

    def undo(self):
        for command in reversed(self.sub_commands):
            command.undo()
            
    @property
    def description(self) -> str:
        return "Create `respond` edge with activator"

class DeleteEdgeCommand(Command):
    def __init__(self, graph: Graph, source_id: str, target_id: str):
        self.graph = graph
        self.source_id = source_id
        self.target_id = target_id
        self.edge: Edge | None = self.graph.get_edge(source_id, target_id)
        self.target_actor_before: Actor | None = None

        if self.edge and self.edge.type in ["communicate", "respond"]:
            target_node = self.graph.get_node(self.edge.target)
            if isinstance(target_node, Actor):
                self.target_actor_before = target_node.model_copy(deep=True)

    def execute(self):
        if not self.edge:
            return
            
        self.graph.edges = [e for e in self.graph.edges if not (e.source == self.source_id and e.target == self.target_id)]
        
        if self.target_actor_before:
            target_node = self.graph.get_node(self.edge.target)
            if isinstance(target_node, Actor):
                target_node.triggers = [
                    t for t in target_node.triggers 
                    if not (isinstance(t, CommunicationTrigger) and t.source_actor_id == self.source_id)
                ]

    def undo(self):
        if not self.edge:
            return

        self.graph.edges.append(self.edge)
        
        if self.target_actor_before:
            for i, n in enumerate(self.graph.nodes):
                if n.id == self.target_actor_before.id:
                    self.graph.nodes[i] = self.target_actor_before
                    break

    @property
    def description(self) -> str:
        if not self.edge:
            return "Delete Edge: (edge not found)"
        source_name = self.graph.get_node(self.edge.source).name
        target_name = self.graph.get_node(self.edge.target).name
        return f"Delete Edge ({self.edge.type}): '{source_name}' → '{target_name}'"

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