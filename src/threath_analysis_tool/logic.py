"""
Contains all business logic, algorithms, and data persistence operations.
"""
import heapq
import itertools
from abc import ABC, abstractmethod
from collections import deque
from typing import Dict, List, Optional, Set, Tuple, FrozenSet

import streamlit as st
import streamlit.components.v1 as components

from config import APP_CONFIG
from domain import (
    Action,
    Actor,
    Attack,
    AttackStep,
    CommunicationTrigger,
    DatasourceTrigger,
    Graph,
    SelfTrigger,
    TriggerChain,
)


# --- Analysis Strategy Definition (Strategy Pattern) ---
class PathfindingStrategy(ABC):
    @abstractmethod
    def find_paths(
        self,
        graph_analysis,
        start_node_id: str,
        end_node_id: str,
        num_paths: int,
        max_cost: int,
        attempt_cost: int,
    ) -> List[Attack]:
        pass


class AStarPathfindingStrategy(PathfindingStrategy):
    """
    An implementation of the A* algorithm for finding the lowest-cost attack path.
    """
    def find_paths(
        self,
        graph_analysis,
        start_node_id: str,
        end_node_id: str,
        num_paths: int,
        max_cost: int,
        attempt_cost: int,
    ) -> List[Attack]:

        h_cost = graph_analysis.get_heuristic_cost(start_node_id)
        tie_breaker = itertools.count()
        # State: (f_cost, g_cost, counter, steps, actor_path, used_self_triggers, active_resp_channels, num_attempts)
        pq: List[Tuple[int, int, int, List[AttackStep], List[str], FrozenSet[str], FrozenSet[Tuple[str, str]], int]] = [
            (h_cost, 0, next(tie_breaker), [], [start_node_id], frozenset(), frozenset(), 1)
        ]

        visited = set()
        found_paths = []

        while pq:
            _, g_cost, _, steps, actor_path, used_self_triggers, active_channels, num_attempts = heapq.heappop(pq)

            current_node_id = actor_path[-1]
            visited_key = (current_node_id, used_self_triggers, active_channels)
            if visited_key in visited: continue
            visited.add(visited_key)

            if current_node_id == end_node_id:
                found_paths.append(Attack(steps=steps, actor_path=actor_path, total_cost=g_cost))
                if len(found_paths) >= num_paths: break
                continue

            if g_cost >= max_cost: continue

            for action in graph_analysis.poison_graph.get(current_node_id, []):

                if action.target_id == start_node_id: continue

                if action.edge_type == "write":
                    for watcher_id in graph_analysis.get_datasource_watchers(action.target_id):
                        trigger, is_new_attempt = graph_analysis.find_shortest_trigger_chain(start_id=current_node_id, end_id=watcher_id, original_attacker=start_node_id)
                        if trigger is None: continue

                        step_cost = 1 + trigger.cost
                        new_g = g_cost + step_cost
                        if is_new_attempt: new_g += attempt_cost
                        
                        h = graph_analysis.get_heuristic_cost(watcher_id)

                        new_active_channels = active_channels.copy()
                        for trigger_action in trigger.actions:
                            if trigger_action.edge_type == "communicate":
                                new_active_channels = new_active_channels.union({(trigger_action.target_id, trigger_action.source_id)})
                        
                        new_num_attempts = num_attempts + 1 if is_new_attempt else num_attempts
                        new_step = AttackStep(push_poison_action=action, consumption_trigger=trigger, total_step_cost=step_cost)
                        heapq.heappush(pq, (new_g + h, new_g, next(tie_breaker), steps + [new_step], actor_path + [watcher_id], used_self_triggers, new_active_channels, new_num_attempts))

                elif action.edge_type == "respond":
                    activation_key = (action.source_id, action.target_id)
                    if activation_key not in active_channels: continue
                    new_active_channels = active_channels.difference({activation_key})

                    step_cost = 1
                    new_g_cost = g_cost + step_cost
                    h_cost = graph_analysis.get_heuristic_cost(action.target_id)
                    new_step = AttackStep(push_poison_action=action, consumption_trigger=TriggerChain(actions=[], cost=0), total_step_cost=step_cost)
                    heapq.heappush(pq, (new_g_cost + h_cost, new_g_cost, next(tie_breaker), steps + [new_step], actor_path + [action.target_id], used_self_triggers, new_active_channels, num_attempts))

                elif action.edge_type in ["communicate", "exploit"]:
                    new_active_channels = active_channels.union({(action.target_id, action.source_id)})
                    step_cost = 1
                    new_g_cost = g_cost + step_cost
                    h_cost = graph_analysis.get_heuristic_cost(action.target_id)
                    new_step = AttackStep(push_poison_action=action, consumption_trigger=TriggerChain(actions=[], cost=0), total_step_cost=step_cost)
                    heapq.heappush(pq, (new_g_cost + h_cost, new_g_cost, next(tie_breaker), steps + [new_step], actor_path + [action.target_id], used_self_triggers, new_active_channels, num_attempts))

                elif action.edge_type == "self_trigger":
                    if current_node_id in used_self_triggers: continue
                    new_used = used_self_triggers.union({current_node_id})
                    step_cost = 1
                    new_g = g_cost + step_cost
                    h = graph_analysis.get_heuristic_cost(current_node_id)
                    new_step = AttackStep(push_poison_action=action, consumption_trigger=TriggerChain(actions=[], cost=0), total_step_cost=step_cost)
                    heapq.heappush(pq, (new_g + h, new_g, next(tie_breaker), steps + [new_step], actor_path + [current_node_id], new_used, active_channels, num_attempts))

        return sorted(found_paths, key=lambda p: p.total_cost)


class GraphAnalysis:
    ASSETS_NODE_ID = "assets_node"
    def __init__(self, graph: Graph, strategy: PathfindingStrategy):
        self.graph, self.strategy = graph, strategy
        self.trigger_graph: Dict[str, List[str]] = {}
        self.poison_graph: Dict[str, List[Action]] = {}
        self.trigger_routing_table: Dict[str, Dict[str, Optional[TriggerChain]]] = {}
        self._build_internal_graphs()
        self._compute_trigger_routing_table()
        self.heuristic_costs = self._run_reverse_bfs([self.ASSETS_NODE_ID], self.trigger_graph)

    def get_heuristic_cost(self, node_id: str) -> int: return self.heuristic_costs.get(node_id, 999)
    def get_datasource_watchers(self, ds_id: str) -> List[str]:
        return [n.id for n in self.graph.nodes if isinstance(n, Actor) and any(isinstance(t, DatasourceTrigger) and t.datasource_id == ds_id for t in n.triggers)]

    def find_shortest_trigger_chain(self, start_id: str, end_id: str, original_attacker: str) -> Tuple[Optional[TriggerChain], bool]:
        chain = self.trigger_routing_table.get(start_id, {}).get(end_id)
        if chain is None:
            return None, False
        
        is_new_attempt = any(action.source_id == original_attacker for action in chain.actions) or start_id == original_attacker
        
        # Return a copy to avoid mutating the cache
        chain_copy = chain.model_copy(deep=True)
        return chain_copy, is_new_attempt

    def _build_internal_graphs(self):
        writers_by_ds: Dict[str, List[str]] = {}
        for edge in self.graph.edges:
            if edge.type == "write":
                writers_by_ds.setdefault(edge.target, []).append(edge.source)

        for node in self.graph.nodes:
            if isinstance(node, Actor):
                for trigger in node.triggers:
                    if isinstance(trigger, SelfTrigger):
                        self.trigger_graph.setdefault(node.id, []).append(node.id)
                    elif isinstance(trigger, CommunicationTrigger):
                        self.trigger_graph.setdefault(trigger.source_actor_id, []).append(node.id)
                    elif isinstance(trigger, DatasourceTrigger):
                        for writer_actor_id in writers_by_ds.get(trigger.datasource_id, []):
                            self.trigger_graph.setdefault(writer_actor_id, []).append(node.id)

        if self.graph.victim_id:
            self.trigger_graph.setdefault(self.graph.victim_id, []).append(self.ASSETS_NODE_ID)

        for edge in self.graph.edges:
            self.poison_graph.setdefault(edge.source, []).append(Action(source_id=edge.source, edge_type=edge.type, target_id=edge.target))
        for node in self.graph.nodes:
            if isinstance(node, Actor) and any(isinstance(t, SelfTrigger) for t in node.triggers):
                self.poison_graph.setdefault(node.id, []).append(Action(source_id=node.id, edge_type="self_trigger", target_id=node.id))
        if self.graph.victim_id:
            self.poison_graph.setdefault(self.graph.victim_id, []).append(Action(source_id=self.graph.victim_id, edge_type="exploit", target_id=self.ASSETS_NODE_ID))

    def _compute_trigger_routing_table(self):
        all_nodes = set(self.trigger_graph.keys())
        for targets in self.trigger_graph.values():
            all_nodes.update(targets)

        for start_node in all_nodes:
            if start_node not in self.trigger_routing_table:
                self.trigger_routing_table[start_node] = {start_node: TriggerChain(actions=[], cost=0)}
            
            queue = deque([[start_node]])
            visited = {start_node}
            
            while queue:
                path = queue.popleft()
                node = path[-1]
                
                for neighbor in self.trigger_graph.get(node, []):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        new_path = list(path) + [neighbor]
                        actions = [Action(source_id=new_path[i], edge_type="comm", target_id=new_path[i+1]) for i in range(len(new_path) - 1)]
                        self.trigger_routing_table[start_node][neighbor] = TriggerChain(actions=actions, cost=len(actions))
                        queue.append(new_path)

    def _run_reverse_bfs(self, start_nodes: List[str], graph_repr: Dict[str, List[str]]) -> Dict[str, int]:
        rev_graph: Dict[str, List[str]] = {}
        for src, targets in graph_repr.items():
            for target in targets: rev_graph.setdefault(target, []).append(src)
        distances, queue, visited = {n: 0 for n in start_nodes}, deque(start_nodes), set(start_nodes)
        while queue:
            node = queue.popleft()
            for neighbor in rev_graph.get(node, []):
                if neighbor not in visited:
                    visited.add(neighbor); distances[neighbor] = distances[node] + 1; queue.append(neighbor)
        return distances

    def find_attack_paths(self, num_paths: int, max_cost: int, attempt_cost: int) -> list[Attack]:
        if not self.graph.attacker_id or not self.graph.victim_id: return []
        if self.strategy is None: return []
        return self.strategy.find_paths(self, self.graph.attacker_id, self.ASSETS_NODE_ID, num_paths, max_cost, attempt_cost)

    def generate_mermaid_code(self, highlight_path: Attack | None = None) -> str:
        lines, h_nodes, h_edges = ["graph TD"], set(), set()
        if highlight_path:
            for step in highlight_path.steps:
                action = step.push_poison_action
                h_nodes.update([action.source_id, action.target_id])
                h_edges.add(tuple(sorted((action.source_id, action.target_id))))
            if highlight_path.steps: h_nodes.add(self.ASSETS_NODE_ID)
        for node in self.graph.nodes:
            shape, label = (("([", "])"), node.name) if isinstance(node, Actor) else (("[(", ")]"), node.name)
            if isinstance(node, Actor):
                inds = "".join(["🔄" if any(isinstance(t,SelfTrigger) for t in node.triggers) else "","🔔" if any(isinstance(t,DatasourceTrigger) for t in node.triggers) else ""])
                if inds: label = f"{node.name} {inds}"
            lines.append(f'    {node.id}{shape[0]}"{label}"{shape[1]}')
            if   node.id == self.graph.attacker_id: lines.append(f"    style {node.id} fill:#ffadad,stroke:#ff5959,stroke-width:2px")
            elif node.id == self.graph.victim_id:   lines.append(f"    style {node.id} fill:#ffd6a5,stroke:#ff9f43,stroke-width:2px")
            elif node.id in h_nodes:              lines.append(f"    style {node.id} fill:#caffbf,stroke:#80ed99,stroke-width:2px")
        arrows = {"write": "-- write -->","read": "-- read -->","communicate": "-- comm -->","respond": "-. resp .->"}
        for i, edge in enumerate(self.graph.edges):
            arrow = arrows.get(edge.type, "-->")
            lines.append(f"    {edge.source} {arrow} {edge.target}")
            if tuple(sorted((edge.source, edge.target))) in h_edges:
                lines.append(f"    linkStyle {i} stroke:#80ed99,stroke-width:4px")
        if self.graph.victim_id:
            lines.append(f'    {self.ASSETS_NODE_ID}(("Assets"))')
            lines.append(f"    {self.graph.victim_id} -- exploit --> {self.ASSETS_NODE_ID}")
            exploit_idx = len(self.graph.edges)
            if self.ASSETS_NODE_ID in h_nodes:
                lines.append(f"    style {self.ASSETS_NODE_ID} fill:#caffbf,stroke:#80ed99,stroke-width:4px")
                lines.append(f"    linkStyle {exploit_idx} stroke:#80ed99,stroke-width:4px")
            else:
                lines.append(f"    style {self.ASSETS_NODE_ID} fill:#ffd6a5,stroke:#ff9f43,stroke-width:4px")
                lines.append(f"    linkStyle {exploit_idx} stroke:red,stroke-width:4px")
        return "\n".join(lines)

    def render_mermaid(self, mermaid_code: str):
        html_code = f"""
        <script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
        <script>mermaid.initialize({{'startOnLoad': true, 'theme': 'base', 'themeVariables': {{'primaryColor': '#F0F2F6', 'primaryTextColor': '#262730'}}}});</script>
        <div class="mermaid">{mermaid_code}</div>"""
        components.html(html_code, height=800, scrolling=True)

@st.cache_data(hash_funcs={GraphAnalysis: lambda g: g.graph.model_dump_json()})
def find_attack_paths_cached(_graph: Graph, _strategy: PathfindingStrategy, num_paths: int, max_cost: int, attempt_cost: int) -> list[Attack]:
    analysis_engine = GraphAnalysis(_graph, _strategy)
    return analysis_engine.find_attack_paths(num_paths, max_cost, attempt_cost)