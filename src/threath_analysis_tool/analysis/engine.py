from collections import deque
from typing import Dict, List, Optional

import streamlit as st

from analysis.pathfinding import PathfindingStrategy
from domain import (
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
        self.trigger_routing_table: Dict[str, Dict[str, Optional[TriggerChain]]] = self._compute_trigger_routing_table()
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

    def _compute_trigger_routing_table(self) -> Dict[str, Dict[str, Optional[TriggerChain]]]:
        routing_table = {}
        all_nodes = set(self.trigger_graph.keys())
        for targets in self.trigger_graph.values():
            all_nodes.update(targets)

        for start_node in all_nodes:
            node_obj = self.graph.get_node(start_node)
            has_self_trigger = isinstance(node_obj, Actor) and any(isinstance(t, SelfTrigger) for t in node_obj.triggers)
            
            if has_self_trigger:
                action = Action(source_id=start_node, edge_type="self_trigger", target_id=start_node)
                step = AttackStep(
                    push_poison_action=action,
                    target_actor_id=start_node,
                    compromise_edge=(start_node, start_node),
                    total_step_cost=1
                )
                routing_table[start_node] = {start_node: TriggerChain(steps=[step], cost=1)}
            else:
                routing_table[start_node] = {start_node: TriggerChain(steps=[], cost=0)}

            queue = deque([[start_node]])
            visited = {start_node}
            
            while queue:
                path = queue.popleft()
                node = path[-1]
                for neighbor in self.trigger_graph.get(node, []):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        new_path = list(path) + [neighbor]
                        
                        steps = []
                        for i in range(len(new_path) - 1):
                            source_node_id = new_path[i]
                            target_node_id = new_path[i+1]
                            
                            # --- FIX: Look up the actual edge type from the graph ---
                            edge = self.graph.get_edge(source_node_id, target_node_id)
                            # Default to 'unknown' if edge not found, though this shouldn't happen
                            edge_type = edge.type if edge else "unknown" 
                            
                            action = Action(source_id=source_node_id, edge_type=edge_type, target_id=target_node_id)
                            step = AttackStep(
                                push_poison_action=action,
                                target_actor_id=action.target_id,
                                compromise_edge=(action.source_id, action.target_id),
                                total_step_cost=1
                            )
                            steps.append(step)
                        routing_table[start_node][neighbor] = TriggerChain(steps=steps, cost=len(steps))
                        
                        queue.append(new_path)
        return routing_table

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

    def find_attack_paths(self, strategy: PathfindingStrategy, num_paths: int, max_cost: int, attempt_cost: int) -> list[AttackPlan]:
        if not self.graph.attacker_id or not self.graph.victim_id: return []
        return strategy.find_paths(self, num_paths, max_cost, attempt_cost)


@st.cache_data(hash_funcs={GraphAnalysis: lambda g: g.graph.model_dump_json()})
def find_attack_paths_cached(_graph: Graph, _strategy: PathfindingStrategy, num_paths: int, max_cost: int, attempt_cost: int) -> list[AttackPlan]:
    analysis_engine = GraphAnalysis(_graph)
    return analysis_engine.find_attack_paths(_strategy, num_paths, max_cost, attempt_cost)