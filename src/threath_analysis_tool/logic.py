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
    AttackPlan,
    Attempt,
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
        num_paths: int,
        max_cost: int,
        attempt_cost: int,
    ) -> List[AttackPlan]:
        pass

# The core strategic planner algorithm.
class StrategicPlannerStrategy(PathfindingStrategy):
    def find_paths(
        self,
        graph_analysis: "GraphAnalysis",
        num_paths: int,
        max_cost: int,
        attempt_cost: int,
    ) -> List[AttackPlan]:

        attacker_id = graph_analysis.graph.attacker_id
        victim_id = graph_analysis.graph.victim_id
        
        tie_breaker = itertools.count()

        initial_compromised_state = {attacker_id: frozenset()}
        initial_state = (
            graph_analysis.poison_heuristic.get(attacker_id, 999),
            next(tie_breaker),
            0,
            AttackPlan(attempts=[], total_cost=0),
            attacker_id,
            frozenset(initial_compromised_state.items()),
            frozenset(),
        )

        pq = [initial_state]
        found_plans = []
        visited = set()

        while pq:
            _, g_cost, plan, last_compromised_actor_id, compromised_state_fs, active_channels = heapq.heappop(pq)[1:]
            compromised_edges_by_actor = dict(compromised_state_fs)

            if graph_analysis.ASSETS_NODE_ID in compromised_edges_by_actor:
                found_plans.append(plan)
                if len(found_plans) >= num_paths:
                    break
                continue

            if g_cost >= max_cost:
                continue
            
            visited_key = (last_compromised_actor_id, compromised_state_fs, active_channels)
            if visited_key in visited:
                continue
            visited.add(visited_key)

            actor_id = last_compromised_actor_id
            for target_id in graph_analysis.poison_graph.get(actor_id, []):
                
                if target_id == graph_analysis.ASSETS_NODE_ID:
                    if actor_id != victim_id: continue

                    push_action = Action(source_id=actor_id, edge_type="exploit", target_id=target_id)
                    compromise_edge = (actor_id, target_id)
                    
                    used_edges = compromised_edges_by_actor.get(target_id, frozenset())
                    if compromise_edge in used_edges: continue

                    step = AttackStep(
                        push_poison_action=push_action,
                        target_actor_id=target_id,
                        compromise_edge=compromise_edge,
                        total_step_cost=1
                    )
                    # The penalty is now passed in as `attempt_cost` (which will be 0)
                    new_attempt = Attempt(
                        steps=[step],
                        total_attempt_cost=attempt_cost + 1,
                        summary=f"Compromise Assets via '{graph_analysis.graph.get_node(actor_id).name}'."
                    )
                    
                    new_g_cost = g_cost + step.total_step_cost # Use step cost for plan cost
                    new_plan = AttackPlan(attempts=plan.attempts + [new_attempt], total_cost=new_g_cost)
                    
                    new_compromised_edges_by_actor = compromised_edges_by_actor.copy()
                    new_compromised_edges_by_actor[target_id] = used_edges.union({compromise_edge})
                    new_compromised_state_fs = frozenset(new_compromised_edges_by_actor.items())
                    
                    f_cost = new_g_cost
                    
                    heapq.heappush(pq, (f_cost, next(tie_breaker), new_g_cost, new_plan, target_id, new_compromised_state_fs, active_channels))
                    continue

                original_edge = graph_analysis.graph.get_edge(actor_id, target_id)
                new_attempt = None
                new_compromised_edges_by_actor = compromised_edges_by_actor.copy()
                new_active_channels = active_channels

                if original_edge and original_edge.type in ["communicate", "respond"]:
                    compromise_edge = (actor_id, target_id)
                    used_edges = compromised_edges_by_actor.get(target_id, frozenset())
                    if compromise_edge in used_edges: continue

                    push_action = Action(source_id=actor_id, edge_type=original_edge.type, target_id=target_id)
                    edge_trigger = None
                    activation_cost = 0
                    if original_edge.type == "respond":
                        activation_key = (target_id, actor_id)
                        if activation_key not in active_channels:
                            cheapest_activation_cost = float('inf')
                            best_activator = None
                            for activator_candidate in compromised_edges_by_actor:
                                trigger_chain = graph_analysis.trigger_routing_table.get(activator_candidate, {}).get(target_id)
                                if trigger_chain and trigger_chain.cost < cheapest_activation_cost:
                                    cheapest_activation_cost = trigger_chain.cost
                                    best_activator = trigger_chain
                            if best_activator:
                                edge_trigger = best_activator
                                activation_cost = best_activator.cost
                            else:
                                continue
                    
                    step_cost = 1 + activation_cost
                    step = AttackStep(push_poison_action=push_action, target_actor_id=target_id, compromise_edge=compromise_edge, edge_activation_trigger=edge_trigger, total_step_cost=step_cost)
                    new_attempt = Attempt(steps=[step], total_attempt_cost=attempt_cost + step_cost, summary=f"Compromise '{graph_analysis.graph.get_node(target_id).name}' via direct communication.")
                    new_compromised_edges_by_actor[target_id] = used_edges.union({compromise_edge})
                    if original_edge.type == "communicate":
                        new_active_channels = active_channels.union({(target_id, actor_id)})

                else:
                    read_edge = next((r for r in graph_analysis.graph.edges if r.type == "read" and r.target == target_id and any(w.source == actor_id and w.target == r.source for w in graph_analysis.graph.edges if w.type == "write")), None)
                    if not read_edge: continue
                    
                    compromise_edge = (read_edge.source, read_edge.target)
                    used_edges = compromised_edges_by_actor.get(target_id, frozenset())
                    if compromise_edge in used_edges: continue
                    
                    datasource_id = read_edge.source
                    cheapest_trigger_cost = float('inf')
                    best_trigger = None
                    for trigger_source in compromised_edges_by_actor:
                        trigger_chain = graph_analysis.trigger_routing_table.get(trigger_source, {}).get(target_id)
                        if trigger_chain and trigger_chain.cost < cheapest_trigger_cost:
                            cheapest_trigger_cost = trigger_chain.cost
                            best_trigger = trigger_chain
                    
                    if best_trigger is None: continue

                    write_action = Action(source_id=actor_id, edge_type="write", target_id=datasource_id)
                    write_step = AttackStep(push_poison_action=write_action, target_actor_id=target_id, compromise_edge=compromise_edge, consumption_trigger=best_trigger, total_step_cost=1 + best_trigger.cost)
                    new_attempt = Attempt(steps=[write_step], total_attempt_cost=attempt_cost + write_step.total_step_cost, summary=f"Compromise '{graph_analysis.graph.get_node(target_id).name}' via Datasource '{graph_analysis.graph.get_node(datasource_id).name}'.")
                    new_compromised_edges_by_actor[target_id] = used_edges.union({compromise_edge})

                if new_attempt:
                    # Use the step's actual cost for the plan's total cost
                    new_g_cost = g_cost + (new_attempt.total_attempt_cost - attempt_cost)
                    new_plan = AttackPlan(attempts=plan.attempts + [new_attempt], total_cost=new_g_cost)
                    
                    h_cost = graph_analysis.poison_heuristic.get(target_id, 999)
                    f_cost = new_g_cost + h_cost

                    new_compromised_state_fs = frozenset(new_compromised_edges_by_actor.items())
                    heapq.heappush(pq, (f_cost, next(tie_breaker), new_g_cost, new_plan, target_id, new_compromised_state_fs, new_active_channels))

        return sorted(found_plans, key=lambda p: p.total_cost)


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
                            action = Action(source_id=new_path[i], edge_type="comm", target_id=new_path[i+1])
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

    def generate_mermaid_code(self, highlight_path: AttackPlan | None = None) -> str:
        lines, h_nodes, h_edges = ["graph TD"], set(), set()
        if highlight_path:
            for attempt in highlight_path.attempts:
                for step in attempt.steps:
                    action = step.push_poison_action
                    h_nodes.update([action.source_id, action.target_id])
                    h_edges.add(tuple(sorted((action.source_id, action.target_id))))
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
def find_attack_paths_cached(_graph: Graph, _strategy: PathfindingStrategy, num_paths: int, max_cost: int, attempt_cost: int) -> list[AttackPlan]:
    analysis_engine = GraphAnalysis(_graph)
    return analysis_engine.find_attack_paths(_strategy, num_paths, max_cost, attempt_cost)