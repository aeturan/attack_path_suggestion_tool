from collections import deque
from typing import Dict, List, Optional

import streamlit as st

from attack_path_suggestion_tool.analysis.pathfinding import PathfindingStrategy
from attack_path_suggestion_tool.domain import (
    Action,
    Actor,
    AttackPlan,
    AttackStep,
    CommunicationTrigger,
    DatasourceTrigger,
    Graph,
    SelfTrigger,
    TriggerChain,
)


class GraphAnalysis:
    ASSETS_NODE_ID = "assets_node"

    def __init__(self, graph: Graph):
        self.graph = graph
        self.trigger_graph: Dict[str, List[str]] = self._build_trigger_graph()
        self.poison_graph: Dict[str, List[str]] = self._build_poison_graph()
        self.poison_heuristic: Dict[str, int] = self._compute_poison_heuristic_bfs()

    def _build_trigger_graph(self) -> Dict[str, List[str]]:
        trigger_graph: Dict[str, List[str]] = {}
        writers_by_ds: Dict[str, List[str]] = {}
        for edge in self.graph.edges:
            if edge.type == "write":
                writers_by_ds.setdefault(edge.target, []).append(edge.source)

        for node in self.graph.nodes:
            if isinstance(node, Actor):
                for trigger in node.triggers:
                    if isinstance(trigger, SelfTrigger):
                        trigger_graph.setdefault(node.id, []).append(node.id)
                    elif isinstance(trigger, CommunicationTrigger):
                        trigger_graph.setdefault(trigger.source_actor_id, []).append(node.id)
                    elif isinstance(trigger, DatasourceTrigger):
                        for writer_actor_id in writers_by_ds.get(trigger.datasource_id, []):
                            trigger_graph.setdefault(writer_actor_id, []).append(node.id)
        return trigger_graph

    def find_cheapest_trigger_chain(self, potential_source_ids: set[str], target_id: str, active_channels: set[tuple[str, str]]) -> TriggerChain | None:
        """
        Performs a dynamic, multi-source BFS on the trigger graph to find the cheapest
        valid trigger chain from any potential source to the target, respecting the
        current state of active 'respond' channels.
        """
        # A source is only valid if it's actually in the trigger graph model
        valid_sources = {sid for sid in potential_source_ids if sid in self.trigger_graph or any(sid in v for v in self.trigger_graph.values())}
        if not valid_sources:
            return None

        # Queue stores tuples of (path_list)
        queue = deque([[source_id] for source_id in valid_sources])
        
        # Visited dictionary to store the shortest path to a node
        visited = {source_id: [source_id] for source_id in valid_sources}

        while queue:
            path = queue.popleft()
            current_node_id = path[-1]

            if current_node_id == target_id:
                # We found the shortest path. Now, build the TriggerChain object.
                steps = []
                for i in range(len(path) - 1):
                    source_step_id = path[i]
                    target_step_id = path[i+1]

                    edge = self.graph.get_edge(source_step_id, target_step_id)
                    if edge:
                        edge_type = edge.type
                    else:
                        # No explicit graph edge — infer the trigger kind.
                        if source_step_id == target_step_id:
                            edge_type = "self_trigger"
                        else:
                            # Check if this is a datasource-watch activation: see if source writes to a datasource
                            # that the target actor is watching.
                            target_node = self.graph.get_node(target_step_id)
                            is_datasource_watch = False
                            if target_node:
                                # Find datasources written by source_step_id
                                written_ds = {e.target for e in self.graph.edges if e.type == 'write' and e.source == source_step_id}
                                for trig in getattr(target_node, 'triggers', []):
                                    if isinstance(trig, DatasourceTrigger) and trig.datasource_id in written_ds:
                                        is_datasource_watch = True
                                        break
                            edge_type = "datasource" if is_datasource_watch else "trigger"
                    
                    action = Action(source_id=source_step_id, edge_type=edge_type, target_id=target_step_id)
                    step = AttackStep(
                        push_poison_action=action,
                        target_actor_id=action.target_id,
                        compromise_edge=(action.source_id, action.target_id),
                        total_step_cost=1
                    )
                    steps.append(step)
                return TriggerChain(steps=steps, cost=len(steps))

            for neighbor_id in self.trigger_graph.get(current_node_id, []):
                if neighbor_id not in visited:
                    # THE CORE LOGIC: Check if this path is valid
                    is_valid_transition = True
                    edge_to_neighbor = self.graph.get_edge(current_node_id, neighbor_id)
                    
                    if edge_to_neighbor and edge_to_neighbor.type == 'respond':
                        # This is a conditional edge. It's only traversable if the
                        # inverse 'communicate' channel is in the active_channels set.
                        required_channel = (neighbor_id, current_node_id)
                        if required_channel not in active_channels:
                            is_valid_transition = False # This path is blocked in the current state.

                    if is_valid_transition:
                        new_path = path + [neighbor_id]
                        visited[neighbor_id] = new_path
                        queue.append(new_path)

        return None # Target is not reachable with a valid trigger chain

    def _build_poison_graph(self) -> Dict[str, List[str]]:
        poison_graph: Dict[str, List[str]] = {}
        for edge in self.graph.edges:
            if edge.type in ["communicate", "respond"]:
                poison_graph.setdefault(edge.source, []).append(edge.target)
        writes = [e for e in self.graph.edges if e.type == "write"]
        reads = [e for e in self.graph.edges if e.type == "read"]
        for write_edge in writes:
            writer_actor = write_edge.source
            datasource = write_edge.target
            for read_edge in reads:
                if read_edge.source == datasource:
                    reader_actor = read_edge.target
                    poison_graph.setdefault(writer_actor, []).append(reader_actor)
        if self.graph.victim_id:
            poison_graph.setdefault(self.graph.victim_id, []).append(self.ASSETS_NODE_ID)
        return poison_graph

    def _compute_poison_heuristic_bfs(self) -> Dict[str, int]:
        if not self.graph.victim_id:
            return {}
        rev_poison_graph: Dict[str, List[str]] = {}
        for src, targets in self.poison_graph.items():
            for target in targets:
                rev_poison_graph.setdefault(target, []).append(src)
        distances: Dict[str, int] = {self.ASSETS_NODE_ID: 0}
        queue = deque([self.ASSETS_NODE_ID])
        visited = {self.ASSETS_NODE_ID}
        while queue:
            node = queue.popleft()
            for neighbor in rev_poison_graph.get(node, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    distances[neighbor] = distances[node] + 1
                    queue.append(neighbor)
        return distances

    def find_attack_paths(self, strategy: PathfindingStrategy, num_paths: int, max_cost: int) -> list[AttackPlan]:
        if not self.graph.attacker_id or not self.graph.victim_id: return []
        return strategy.find_paths(self, num_paths, max_cost)


@st.cache_data(hash_funcs={GraphAnalysis: lambda g: g.graph.model_dump_json()})
def find_attack_paths_cached(_graph: Graph, _strategy: PathfindingStrategy, num_paths: int, max_cost: int) -> list[AttackPlan]:
    analysis_engine = GraphAnalysis(_graph)
    return analysis_engine.find_attack_paths(_strategy, num_paths, max_cost)