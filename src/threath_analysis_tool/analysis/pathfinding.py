import heapq
import itertools
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, List

from domain import Action, AttackPlan, Attempt, AttackStep

if TYPE_CHECKING:
    from analysis.engine import GraphAnalysis


# --- Analysis Strategy Definition (Strategy Pattern) ---
class PathfindingStrategy(ABC):
    @abstractmethod
    def find_paths(
        self,
        graph_analysis: "GraphAnalysis",
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

        while pq and len(found_plans) < num_paths:
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
                
                if target_id == attacker_id:
                    continue

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
                    new_attempt = Attempt(
                        steps=[step],
                        total_attempt_cost=attempt_cost + 1,
                        summary=f"Compromise Assets via '{graph_analysis.graph.get_node(actor_id).name}'."
                    )
                    
                    new_g_cost = g_cost + step.total_step_cost
                    new_plan = AttackPlan(attempts=plan.attempts + [new_attempt], total_cost=new_g_cost)
                    
                    new_compromised_edges_by_actor = compromised_edges_by_actor.copy()
                    new_compromised_edges_by_actor[target_id] = used_edges.union({compromise_edge})
                    new_compromised_state_fs = frozenset(new_compromised_edges_by_actor.items())
                    
                    f_cost = new_g_cost
                    
                    heapq.heappush(pq, (f_cost, next(tie_breaker), new_g_cost, new_plan, target_id, new_compromised_state_fs, active_channels))
                    continue

                original_edge = graph_analysis.graph.get_edge(actor_id, target_id)
                new_attempt = None
                
                if original_edge and original_edge.type in ["communicate", "respond"]:
                    compromise_edge = (actor_id, target_id)
                    used_edges = compromised_edges_by_actor.get(target_id, frozenset())
                    if compromise_edge in used_edges: continue

                    push_action = Action(source_id=actor_id, edge_type=original_edge.type, target_id=target_id)
                    edge_trigger = None
                    activation_cost = 0
                    if original_edge.type == "respond":
                        activation_key = (actor_id, target_id)
                        if activation_key not in active_channels:
                            cheapest_activation_cost = float('inf')
                            best_activator = None
                            for activator_candidate in compromised_edges_by_actor:
                                trigger_chain = graph_analysis.trigger_routing_table.get(activator_candidate, {}).get(target_id)
                                if trigger_chain and trigger_chain.cost < cheapest_activation_cost:
                                    cheapest_activation_cost = trigger_chain.cost
                                    best_activator = trigger_chain
                            
                            if best_activator:
                                # Create a deep copy to safely modify the trigger chain
                                final_activator_trigger = best_activator.model_copy(deep=True)
                                
                                # Define the final activating communication action
                                # (e.g., car_agent --comm--> email_tool)
                                activating_action = Action(
                                    source_id=target_id,
                                    edge_type='communicate',
                                    target_id=actor_id
                                )
                                
                                # Create the AttackStep for this final action
                                activating_step = AttackStep(
                                    push_poison_action=activating_action,
                                    target_actor_id=actor_id,
                                    compromise_edge=(activating_action.source_id, activating_action.target_id),
                                    total_step_cost=1
                                )
                                
                                # Append the final step to the chain and update its cost
                                final_activator_trigger.steps.append(activating_step)
                                final_activator_trigger.cost += 1
                                
                                # Use this enhanced trigger chain for the AttackStep
                                edge_trigger = final_activator_trigger
                                activation_cost = final_activator_trigger.cost
                            else:
                                continue
                    
                    step_cost = 1 + activation_cost
                    step = AttackStep(push_poison_action=push_action, target_actor_id=target_id, compromise_edge=compromise_edge, edge_activation_trigger=edge_trigger, total_step_cost=step_cost)
                    new_attempt = Attempt(steps=[step], total_attempt_cost=attempt_cost + step_cost, summary=f"Compromise '{graph_analysis.graph.get_node(target_id).name}' via direct communication.")
                    
                    new_compromised_edges_by_actor = compromised_edges_by_actor.copy()
                    new_compromised_edges_by_actor[target_id] = used_edges.union({compromise_edge})
                    
                    new_active_channels = active_channels
                    if original_edge.type == "communicate":
                        new_active_channels = active_channels.union({(target_id, actor_id)})
                    elif original_edge.type == "respond":
                        activation_key_to_consume = (actor_id, target_id)
                        new_active_channels = active_channels.difference({activation_key_to_consume})

                else: # This is a write/read hop
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

                    new_active_channels = active_channels
                    if best_trigger:
                        for trigger_step in best_trigger.steps:
                            trigger_action = trigger_step.push_poison_action
                            if trigger_action.edge_type == 'communicate':
                                new_active_channels = new_active_channels.union({
                                    (trigger_action.target_id, trigger_action.source_id)
                                })

                    final_trigger = best_trigger.model_copy(deep=True)
                    if final_trigger:
                        read_action = Action(source_id=datasource_id, edge_type='read', target_id=target_id)
                        read_step = AttackStep(
                            push_poison_action=read_action,
                            target_actor_id=target_id,
                            compromise_edge=compromise_edge,
                            total_step_cost=1
                        )
                        final_trigger.steps.append(read_step)
                        final_trigger.cost += 1

                    write_action = Action(source_id=actor_id, edge_type="write", target_id=datasource_id)
                    write_step = AttackStep(push_poison_action=write_action, target_actor_id=target_id, compromise_edge=compromise_edge, consumption_trigger=final_trigger, total_step_cost=1 + final_trigger.cost)
                    new_attempt = Attempt(steps=[write_step], total_attempt_cost=attempt_cost + write_step.total_step_cost, summary=f"Compromise '{graph_analysis.graph.get_node(target_id).name}' via Datasource '{graph_analysis.graph.get_node(datasource_id).name}'.")
                    
                    new_compromised_edges_by_actor = compromised_edges_by_actor.copy()
                    new_compromised_edges_by_actor[target_id] = used_edges.union({compromise_edge})

                if new_attempt:
                    new_g_cost = g_cost + (new_attempt.total_attempt_cost - attempt_cost)
                    new_plan = AttackPlan(attempts=plan.attempts + [new_attempt], total_cost=new_g_cost)
                    
                    h_cost = graph_analysis.poison_heuristic.get(target_id, 999)
                    f_cost = new_g_cost + h_cost

                    new_compromised_state_fs = frozenset(new_compromised_edges_by_actor.items())
                    heapq.heappush(pq, (f_cost, next(tie_breaker), new_g_cost, new_plan, target_id, new_compromised_state_fs, new_active_channels))

        return sorted(found_plans, key=lambda p: p.total_cost)