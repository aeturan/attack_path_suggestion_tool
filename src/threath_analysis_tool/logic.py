"""
Contains all business logic, algorithms, and data persistence operations.

This module defines the "verbs" of our system. It includes the session
manager for file I/O and the graph analysis engine with its pluggable
strategies. It only depends on the models defined in `domain.py`.
"""
from abc import ABC, abstractmethod
from collections import deque
from typing import Dict, List

import streamlit as st
import streamlit.components.v1 as components

from config import APP_CONFIG
from domain import (
    Actor,
    AttackChain,
    CommunicationTrigger,
    DatasourceTrigger,
    Graph,
    PathStep,
    SelfTrigger,
)


# --- Analysis Strategy Definition (Strategy Pattern) ---
class PathfindingStrategy(ABC):
    """Abstract base class for a pathfinding strategy."""

    @abstractmethod
    def find_paths(
        self,
        graph: Graph,
        trigger_graph: dict,
        reverse_poison_graph: dict,
        trigger_distances: dict,
        poison_distances: dict,
    ) -> list[AttackChain]:
        pass


class GreedyDFSStrategy(PathfindingStrategy):
    """Concrete implementation of a guided Depth-First Search algorithm."""

    def find_paths(
        self,
        graph: Graph,
        trigger_graph: dict,
        reverse_poison_graph: dict,
        trigger_distances: dict,
        poison_distances: dict,
    ) -> list[AttackChain]:
        solutions = []

        def dfs(current_actor_id: str, current_path: list[PathStep], visited: set):
            if trigger_distances.get(current_actor_id, float("inf")) == 0:
                final_step = PathStep(
                    actor_id=current_actor_id,
                    action="trigger",
                    target_id=graph.victim_id,
                    step_type="trigger",
                )
                solutions.append(AttackChain(steps=list(current_path) + [final_step]))
                return
            if len(current_path) >= APP_CONFIG.analysis.max_path_length:
                return

            possible_next_actors = sorted(
                trigger_graph.get(current_actor_id, []),
                key=lambda actor_id: trigger_distances.get(actor_id, float("inf")),
            )
            for next_actor_id in possible_next_actors:
                # This logic will need to be updated in Phase 2 to safely handle self-loops.
                is_self_loop = next_actor_id == current_actor_id
                if not is_self_loop and next_actor_id in visited:
                    continue

                if is_self_loop and current_actor_id in visited:
                    if (
                        len(current_path) > 0
                        and current_path[-1].actor_id == current_actor_id
                        and current_path[-1].target_id == current_actor_id
                    ):
                        continue

                new_visited = visited.copy()
                new_visited.add(next_actor_id)

                new_steps = [
                    PathStep(
                        actor_id=current_actor_id,
                        action="poison",
                        target_id=next_actor_id,
                        step_type="poison",
                    ),
                    PathStep(
                        actor_id=current_actor_id,
                        action="trigger",
                        target_id=next_actor_id,
                        step_type="trigger",
                    ),
                ]
                dfs(next_actor_id, current_path + new_steps, new_visited)

        dfs(graph.attacker_id, [], set())
        return solutions


# --- Graph Analysis Engine ---


@st.cache_data
def find_attack_paths_cached(
    _graph: Graph, _strategy: PathfindingStrategy
) -> list[AttackChain]:
    analysis_engine = GraphAnalysis(_graph, _strategy)
    return analysis_engine.find_attack_paths()


class GraphAnalysis:
    """Facade for the graph analysis subsystem."""

    def __init__(self, graph: Graph, strategy: PathfindingStrategy):
        self.graph = graph
        self.strategy = strategy
        self.trigger_graph: Dict[str, List[str]] = {}
        self.reverse_poison_graph: Dict[str, List[str]] = {}
        self._build_internal_graphs()

    def _build_internal_graphs(self):
        """
        Constructs the internal graph representations for the analysis engine.
        This is now driven by the unified trigger system.
        """
        # --- Build Trigger Graph ---
        writers_by_ds: Dict[str, List[str]] = {}
        for edge in self.graph.edges:
            if edge.type == "write":
                writers_by_ds.setdefault(edge.target, []).append(edge.source)

        for node in self.graph.nodes:
            if node.type == "Actor":
                for trigger in node.triggers:
                    if isinstance(trigger, SelfTrigger):
                        self.trigger_graph.setdefault(node.id, []).append(node.id)
                    elif isinstance(trigger, CommunicationTrigger):
                        self.trigger_graph.setdefault(
                            trigger.source_actor_id, []
                        ).append(node.id)
                    elif isinstance(trigger, DatasourceTrigger):
                        for writer_actor_id in writers_by_ds.get(
                            trigger.datasource_id, []
                        ):
                            self.trigger_graph.setdefault(writer_actor_id, []).append(
                                node.id
                            )

        # --- Build Reverse Poison Graph ---
        for edge in self.graph.edges:
            if edge.type == "write":
                self.reverse_poison_graph.setdefault(edge.target, []).append(
                    edge.source
                )
            elif edge.type == "read":
                self.reverse_poison_graph.setdefault(edge.source, []).append(
                    edge.target
                )

    def _run_reverse_bfs(
        self, start_nodes: List[str], graph_repr: Dict[str, List[str]]
    ) -> Dict[str, int]:
        distances = {node_id: 0 for node_id in start_nodes}
        queue = deque(start_nodes)
        visited = set(start_nodes)
        while queue:
            current_node = queue.popleft()
            for neighbor in graph_repr.get(current_node, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    distances[neighbor] = distances[current_node] + 1
                    queue.append(neighbor)
        return distances

    def find_attack_paths(self) -> list[AttackChain]:
        if not self.graph.attacker_id or not self.graph.victim_id:
            return []

        trigger_distances = self._run_reverse_bfs(
            [self.graph.victim_id], self.trigger_graph
        )
        victim_inputs = [
            edge.source
            for edge in self.graph.edges
            if edge.target == self.graph.victim_id and edge.type == "read"
        ]
        poison_distances = self._run_reverse_bfs(
            victim_inputs, self.reverse_poison_graph
        )

        return self.strategy.find_paths(
            self.graph,
            self.trigger_graph,
            self.reverse_poison_graph,
            trigger_distances,
            poison_distances,
        )

    def generate_mermaid_code(self, highlight_path: AttackChain | None = None) -> str:
        lines = ["graph TD"]
        highlight_nodes, highlight_edges = set(), set()
        if highlight_path:
            for step in highlight_path.steps:
                highlight_nodes.update([step.actor_id, step.target_id])
                highlight_edges.add(tuple(sorted((step.actor_id, step.target_id))))

        for node in self.graph.nodes:
            shape_start, shape_end = ("([", "])") if node.type == "Actor" else ("[(", ")]")

            label = node.name
            if isinstance(node, Actor):
                indicators = []
                if any(isinstance(t, SelfTrigger) for t in node.triggers):
                    indicators.append("🔄")
                if any(isinstance(t, DatasourceTrigger) for t in node.triggers):
                    indicators.append("🔔")
                if indicators:
                    label = f"{node.name} {''.join(indicators)}"

            lines.append(f'    {node.id}{shape_start}"{label}"{shape_end}')

            if node.id == self.graph.attacker_id:
                lines.append(
                    f"    style {node.id} fill:#ffadad,stroke:#ff5959,stroke-width:2px"
                )
            elif node.id == self.graph.victim_id:
                lines.append(
                    f"    style {node.id} fill:#ffd6a5,stroke:#ff9f43,stroke-width:2px"
                )
            elif node.id in highlight_nodes:
                lines.append(
                    f"    style {node.id} fill:#caffbf,stroke:#80ed99,stroke-width:2px"
                )

        arrow_styles = {
            "write": "-- write -->",
            "read": "-- read -->",
            "communicate": "-- comm -->",
            "respond": "-. resp .->",
        }

        for i, edge in enumerate(self.graph.edges):
            arrow = arrow_styles.get(edge.type, "-->")
            lines.append(f"    {edge.source} {arrow} {edge.target}")
            if tuple(sorted((edge.source, edge.target))) in highlight_edges:
                lines.append(f"    linkStyle {i} stroke:#80ed99,stroke-width:4px")
        return "\n".join(lines)

    def render_mermaid(self, mermaid_code: str):
        html_code = f"""
        <script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
        <script>mermaid.initialize({{'startOnLoad': true, 'theme': 'base', 'themeVariables': {{'primaryColor': '#F0F2F6', 'primaryTextColor': '#262730'}}}});</script>
        <div class="mermaid">{mermaid_code}</div>
        """
        components.html(html_code, height=800, scrolling=True)