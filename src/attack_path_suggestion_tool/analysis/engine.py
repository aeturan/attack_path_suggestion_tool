"""Graph analysis utilities for attack path planning."""
from collections import deque

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
    """Pre-compute helper structures that power the attack-path search."""

    ASSETS_NODE_ID = "assets_node"

    def __init__(self, graph: Graph):
        """Build trigger/poison graphs and heuristics for the provided graph."""

        self.graph = graph
        self.trigger_graph: dict[str, list[str]] = self._build_trigger_graph()
        self.poison_graph: dict[str, list[str]] = self._build_poison_graph()
        self.poison_heuristic: dict[str, int] = self._compute_poison_heuristic_bfs()

    def _build_trigger_graph(self) -> dict[str, list[str]]:
        """Return a graph describing how actors can activate each other."""

        trigger_graph: dict[str, list[str]] = {}
        writers_by_ds: dict[str, list[str]] = {}
        for edge in self.graph.edges:
            if edge.type == "write":
                writers_by_ds.setdefault(edge.target, []).append(edge.source)

        for node in self.graph.nodes:
            if not isinstance(node, Actor):
                continue

            for trigger in node.triggers:
                if isinstance(trigger, SelfTrigger):
                    trigger_graph.setdefault(node.id, []).append(node.id)
                elif isinstance(trigger, CommunicationTrigger):
                    trigger_graph.setdefault(trigger.source_actor_id, []).append(node.id)
                elif isinstance(trigger, DatasourceTrigger):
                    for writer_actor_id in writers_by_ds.get(trigger.datasource_id, []):
                        trigger_graph.setdefault(writer_actor_id, []).append(node.id)

        return trigger_graph

    def find_cheapest_trigger_chain(
        self,
        potential_source_ids: set[str],
        target_id: str,
        active_channels: set[tuple[str, str]],
    ) -> TriggerChain | None:
        """Return the cheapest trigger chain from any source to ``target_id``."""

        valid_sources = {
            sid
            for sid in potential_source_ids
            if sid in self.trigger_graph or any(sid in targets for targets in self.trigger_graph.values())
        }
        if not valid_sources:
            return None

        queue = deque([[source_id] for source_id in valid_sources])
        visited: dict[str, list[str]] = {source_id: [source_id] for source_id in valid_sources}

        while queue:
            path = queue.popleft()
            current_node_id = path[-1]

            if current_node_id == target_id:
                return self._build_trigger_chain_from_path(path)

            for neighbor_id in self.trigger_graph.get(current_node_id, []):
                if neighbor_id in visited:
                    continue

                edge_to_neighbor = self.graph.get_edge(current_node_id, neighbor_id)
                if edge_to_neighbor and edge_to_neighbor.type == "respond":
                    required_channel = (neighbor_id, current_node_id)
                    if required_channel not in active_channels:
                        continue

                new_path = path + [neighbor_id]
                visited[neighbor_id] = new_path
                queue.append(new_path)

        return None

    def _build_trigger_chain_from_path(self, path: list[str]) -> TriggerChain:
        """Convert a path of actor IDs into a structured TriggerChain."""

        steps: list[AttackStep] = []
        for idx in range(len(path) - 1):
            source_step_id = path[idx]
            target_step_id = path[idx + 1]
            
            inferred_kind = self._infer_trigger_kind(source_step_id, target_step_id)
            edge = self.graph.get_edge(source_step_id, target_step_id)

            if inferred_kind in ("datasource", "self_trigger"):
                edge_type = inferred_kind
            elif edge:
                edge_type = edge.type
            else:
                edge_type = inferred_kind # "trigger"

            action = Action(source_id=source_step_id, edge_type=edge_type, target_id=target_step_id)
            steps.append(
                AttackStep(
                    push_poison_action=action,
                    target_actor_id=action.target_id,
                    compromise_edge=(action.source_id, action.target_id),
                    cost=1,
                    summary=f"Trigger from {source_step_id} to {target_step_id} via {edge_type}",
                )
            )

        return TriggerChain(steps=steps, cost=len(steps))

    def _infer_trigger_kind(self, source_id: str, target_id: str) -> str:
        """Infer whether a trigger is datasource-driven or a generic trigger."""

        target_node = self.graph.get_node(target_id)
        if isinstance(target_node, Actor):
            written_datasources = {
                edge.target
                for edge in self.graph.edges
                if edge.type == "write" and edge.source == source_id
            }
            for trigger in target_node.triggers:
                if isinstance(trigger, DatasourceTrigger) and trigger.datasource_id in written_datasources:
                    return "datasource"
        if source_id == target_id:
            return "self_trigger"
        return "trigger"

    def _build_poison_graph(self) -> dict[str, list[str]]:
        """Describe how poisoned information can move between actors."""

        poison_graph: dict[str, list[str]] = {}

        for edge in self.graph.edges:
            if edge.type in ["communicate", "respond"]:
                poison_graph.setdefault(edge.source, []).append(edge.target)

        writes = [edge for edge in self.graph.edges if edge.type == "write"]
        reads = [edge for edge in self.graph.edges if edge.type == "read"]
        for write_edge in writes:
            datasource = write_edge.target
            writer_actor = write_edge.source
            for read_edge in reads:
                if read_edge.source == datasource:
                    poison_graph.setdefault(writer_actor, []).append(read_edge.target)

        if self.graph.victim_id:
            poison_graph.setdefault(self.graph.victim_id, []).append(self.ASSETS_NODE_ID)

        return poison_graph

    def _compute_poison_heuristic_bfs(self) -> dict[str, int]:
        """Compute a reverse-BFS distance-to-assets heuristic for A*."""

        if not self.graph.victim_id:
            return {}

        reverse_graph: dict[str, list[str]] = {}
        for src, targets in self.poison_graph.items():
            for target in targets:
                reverse_graph.setdefault(target, []).append(src)

        distances: dict[str, int] = {self.ASSETS_NODE_ID: 0}
        queue = deque([self.ASSETS_NODE_ID])
        visited = {self.ASSETS_NODE_ID}

        while queue:
            node = queue.popleft()
            for neighbor in reverse_graph.get(node, []):
                if neighbor in visited:
                    continue
                visited.add(neighbor)
                distances[neighbor] = distances[node] + 1
                queue.append(neighbor)

        return distances

    def find_attack_paths(
        self,
        strategy: PathfindingStrategy,
        num_paths: int,
        max_cost: int,
    ) -> list[AttackPlan]:
        """Delegate attack path search to the configured strategy."""

        if not self.graph.attacker_id or not self.graph.victim_id:
            return []
        return strategy.find_paths(self, num_paths, max_cost)