"""Pathfinding strategies that explore the trigger/poison search space."""

import heapq
import itertools
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, List, Set

from attack_path_suggestion_tool.domain import Action, AttackPlan, AttackStep

if TYPE_CHECKING:
    from attack_path_suggestion_tool.analysis.engine import GraphAnalysis


def _get_newly_activated_channels(steps: List[AttackStep]) -> Set:
    """Helper function to find all channels activated within the provided steps and triggers."""
    newly_activated = set()

    def find_channels_recursive(step: AttackStep):
        action = step.push_poison_action
        if action.edge_type == "communicate":
            newly_activated.add((action.target_id, action.source_id))
        if step.edge_activation_trigger:
            for sub_step in step.edge_activation_trigger.steps:
                find_channels_recursive(sub_step)
        if step.consumption_trigger:
            for sub_step in step.consumption_trigger.steps:
                find_channels_recursive(sub_step)

    for step in steps:
        find_channels_recursive(step)

    return newly_activated


class PathfindingStrategy(ABC):
    """Interface for algorithms that produce attack plans."""

    @abstractmethod
    def find_paths(
        self,
        graph_analysis: "GraphAnalysis",
        num_paths: int,
        max_cost: int,
    ) -> List[AttackPlan]:
        """Return up to ``num_paths`` plans that cost ``<= max_cost``."""

class StrategicPlannerStrategy(PathfindingStrategy):
    """Heuristic A*-style planner that balances triggers vs. poison hops."""

    def find_paths(
        self,
        graph_analysis: "GraphAnalysis",
        num_paths: int,
        max_cost: int,
    ) -> List[AttackPlan]:
        """Perform an A* search that uses poison distances as an admissible heuristic."""

        attacker_id = graph_analysis.graph.attacker_id
        victim_id = graph_analysis.graph.victim_id
        
        tie_breaker = itertools.count()

        initial_compromised_state = {attacker_id: frozenset()}

        heuristic_map = graph_analysis.poison_heuristic
        max_known_distance = max(heuristic_map.values(), default=0)
        fallback_heuristic = max_known_distance + 1 if heuristic_map else 0

        initial_state = (
            heuristic_map.get(attacker_id, fallback_heuristic),
            next(tie_breaker),
            0,
            AttackPlan(steps=[], total_cost=0),
            attacker_id,
            frozenset(initial_compromised_state.items()),
        )

        pq = [initial_state]
        found_plans = []
        visited = set()

        # A* search loop
        while pq and len(found_plans) < num_paths:
            _, g_cost, plan, last_compromised_actor_id, compromised_state_fs = heapq.heappop(pq)[1:] # min heap
            compromised_edges_by_actor = dict(compromised_state_fs)

            # Explicitly create a new set to ensure the type is correctly inferred by linters.
            current_channels = set(plan.active_channels)

            if graph_analysis.ASSETS_NODE_ID in compromised_edges_by_actor:
                found_plans.append(plan)
                if len(found_plans) >= num_paths:
                    break
                continue

            if g_cost >= max_cost:
                continue
            
            visited_key = (last_compromised_actor_id, compromised_state_fs, frozenset(current_channels))
            if visited_key in visited:
                continue
            visited.add(visited_key)

            actor_id = last_compromised_actor_id
            for target_id in graph_analysis.poison_graph.get(actor_id, []):
                
                if target_id == attacker_id:
                    continue

                if target_id == graph_analysis.ASSETS_NODE_ID:
                    if actor_id != victim_id: continue

                    push_action = Action(source_id=actor_id, edge_type="exploit", target_id=target_id)
                    compromise_edge = (actor_id, target_id)
                    
                    used_edges = compromised_edges_by_actor.get(target_id, frozenset())
                    # if compromise_edge in used_edges: continue

                    step = AttackStep(
                        push_poison_action=push_action,
                        target_actor_id=target_id,
                        compromise_edge=compromise_edge,
                        cost=1,
                        summary=f"Compromise Assets via '{graph_analysis.graph.get_node(actor_id).name}'."
                    )

                    new_g_cost = g_cost + step.cost
                    new_plan = AttackPlan(
                        steps=plan.steps + [step],
                        total_cost=new_g_cost,
                        active_channels=current_channels
                    )
                    
                    new_compromised_edges_by_actor = compromised_edges_by_actor.copy()
                    new_compromised_edges_by_actor[target_id] = used_edges.union({compromise_edge})
                    new_compromised_state_fs = frozenset(new_compromised_edges_by_actor.items())
                    
                    f_cost = new_g_cost
                    
                    heapq.heappush(pq, (f_cost, next(tie_breaker), new_g_cost, new_plan, target_id, new_compromised_state_fs))
                    continue

                original_edge = graph_analysis.graph.get_edge(actor_id, target_id)
                
                if original_edge and original_edge.type in ["communicate", "respond"]:
                    compromise_edge = (actor_id, target_id)
                    used_edges = compromised_edges_by_actor.get(target_id, frozenset())
                    # if compromise_edge in used_edges: continue

                    push_action = Action(source_id=actor_id, edge_type=original_edge.type, target_id=target_id)
                    edge_trigger = None
                    activation_cost = 0
                    valid_comm_step = True

                    if original_edge.type == "respond":
                        activation_key = (actor_id, target_id)
                        if activation_key not in current_channels:
                            best_activator = None
                            if attacker_id:
                                best_activator = graph_analysis.find_cheapest_trigger_chain(
                                    potential_source_ids={attacker_id},
                                    target_id=target_id,
                                    active_channels=current_channels
                                )
                            
                            if best_activator:
                                final_activator_trigger = best_activator.model_copy(deep=True)
                                activating_action = Action(source_id=target_id, edge_type='communicate', target_id=actor_id)
                                activating_step = AttackStep(
                                    push_poison_action=activating_action,
                                    target_actor_id=actor_id,
                                    compromise_edge=(activating_action.source_id, activating_action.target_id),
                                    cost=1,
                                    summary=f"Activate respond channel between '{graph_analysis.graph.get_node(target_id).name}' and '{graph_analysis.graph.get_node(actor_id).name}'."
                                )
                                final_activator_trigger.steps.append(activating_step)
                                final_activator_trigger.cost += 1
                                edge_trigger = final_activator_trigger
                                activation_cost = final_activator_trigger.cost
                            else:
                                valid_comm_step = False
                    
                    if valid_comm_step:
                        step_cost = 1 + activation_cost
                        comm_step = AttackStep(
                            push_poison_action=push_action,
                            target_actor_id=target_id,
                            compromise_edge=compromise_edge,
                            edge_activation_trigger=edge_trigger,
                            cost=step_cost,
                            summary=f"Compromise '{graph_analysis.graph.get_node(target_id).name}' via direct communication."
                        )

                        new_compromised_edges_by_actor = compromised_edges_by_actor.copy()
                        new_compromised_edges_by_actor[target_id] = used_edges.union({compromise_edge})

                        new_g_cost = g_cost + comm_step.cost

                        newly_activated = _get_newly_activated_channels([comm_step])
                        updated_channels = current_channels.union(newly_activated)

                        if original_edge.type == 'respond':
                            activation_key_to_consume = (actor_id, target_id)
                            updated_channels.discard(activation_key_to_consume)

                        new_plan = AttackPlan(
                            steps=plan.steps + [comm_step],
                            total_cost=new_g_cost,
                            active_channels=updated_channels
                        )
                        
                        h_cost = heuristic_map.get(target_id, fallback_heuristic)
                        f_cost = new_g_cost + h_cost

                        new_compromised_state_fs = frozenset(new_compromised_edges_by_actor.items())
                        heapq.heappush(pq, (f_cost, next(tie_breaker), new_g_cost, new_plan, target_id, new_compromised_state_fs))

                # Check for datasource write/read hop
                read_edge = next((r for r in graph_analysis.graph.edges if r.type == "read" and r.target == target_id and any(w.source == actor_id and w.target == r.source for w in graph_analysis.graph.edges if w.type == "write")), None)
                if read_edge:
                    compromise_edge = (read_edge.source, read_edge.target)
                    used_edges = compromised_edges_by_actor.get(target_id, frozenset())
                    # if compromise_edge in used_edges: continue
                    
                    datasource_id = read_edge.source
                    best_trigger = None
                    if attacker_id:
                        best_trigger = graph_analysis.find_cheapest_trigger_chain(
                            potential_source_ids={attacker_id, actor_id},
                            target_id=target_id,
                            active_channels=current_channels
                        )
                    
                    if best_trigger:
                        final_trigger = best_trigger.model_copy(deep=True)
                        read_action = Action(source_id=datasource_id, edge_type='read', target_id=target_id)
                        read_step = AttackStep(
                            push_poison_action=read_action,
                            target_actor_id=target_id,
                            compromise_edge=compromise_edge,
                            cost=1,
                            summary=f"{graph_analysis.graph.get_node(target_id).name} reads from datasource '{graph_analysis.graph.get_node(datasource_id).name}'."
                        )
                        final_trigger.steps.append(read_step)
                        final_trigger.cost += 1

                        write_action = Action(source_id=actor_id, edge_type="write", target_id=datasource_id)
                        ds_step = AttackStep(
                            push_poison_action=write_action,
                            target_actor_id=target_id,
                            compromise_edge=compromise_edge,
                            consumption_trigger=final_trigger,
                            cost=1 + final_trigger.cost,
                            summary=f"Compromise '{graph_analysis.graph.get_node(target_id).name}' via Datasource '{graph_analysis.graph.get_node(datasource_id).name}'."
                        )
                        
                        new_compromised_edges_by_actor = compromised_edges_by_actor.copy()
                        new_compromised_edges_by_actor[target_id] = used_edges.union({compromise_edge})

                        new_g_cost = g_cost + ds_step.cost

                        newly_activated = _get_newly_activated_channels([ds_step])
                        updated_channels = current_channels.union(newly_activated)

                        new_plan = AttackPlan(
                            steps=plan.steps + [ds_step],
                            total_cost=new_g_cost,
                            active_channels=updated_channels
                        )
                        
                        h_cost = heuristic_map.get(target_id, fallback_heuristic)
                        f_cost = new_g_cost + h_cost

                        new_compromised_state_fs = frozenset(new_compromised_edges_by_actor.items())
                        heapq.heappush(pq, (f_cost, next(tie_breaker), new_g_cost, new_plan, target_id, new_compromised_state_fs))

        return sorted(found_plans, key=lambda p: p.total_cost)