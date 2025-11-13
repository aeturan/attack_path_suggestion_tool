from typing import List
import streamlit as st

from attack_path_suggestion_tool.domain import AttackStep


def _count_attacker_turns(steps: List[AttackStep], attacker_id: str) -> int:
    """Recursively traverses all steps in a plan to count actions initiated by the attacker."""
    count = 0
    if not attacker_id:
        return 0
    for step in steps:
        # Count the current step if the source is the attacker
        if step.push_poison_action.source_id == attacker_id:
            count += 1
        # Recurse into the edge activation trigger if it exists
        if step.edge_activation_trigger:
            count += _count_attacker_turns(step.edge_activation_trigger.steps, attacker_id)
        # Recurse into the consumption trigger if it exists
        if step.consumption_trigger:
            count += _count_attacker_turns(step.consumption_trigger.steps, attacker_id)
    return count


def _render_attack_steps(
    steps: List[AttackStep],
    get_name_func: callable,
    is_sub_step: bool = False,
    start_index: int = 1,
    parent_step: AttackStep | None = None,
):
    """A recursive helper function to render a list of AttackSteps."""
    for k, step in enumerate(steps):
        
        action = step.push_poison_action
        
        # Detect explicit write steps or implicit write->datasource->read patterns
        is_write_pattern = False
        datasource_id = None
        if action.edge_type == 'write':
            is_write_pattern = True
            datasource_id = action.target_id
        elif step.consumption_trigger:
            # If the consumption trigger contains a read to this step's target, treat as a write->read pattern
            for sub in step.consumption_trigger.steps:
                sub_act = sub.push_poison_action
                if sub_act.edge_type == 'read' and sub_act.target_id == step.target_actor_id:
                    is_write_pattern = True
                    datasource_id = sub_act.source_id
                    break

        if action.edge_type == 'datasource' and parent_step and parent_step.push_poison_action.edge_type == 'write':
            source_actor_id = action.source_id
            datasource_id = parent_step.push_poison_action.target_id
            step_title = f"Step {start_index + k}: {get_name_func(source_actor_id)} `—(write)→` {get_name_func(datasource_id)}"
        elif is_write_pattern:
            source_actor_id = action.source_id
            target_actor_id = step.target_actor_id
            step_title = f"Step {start_index + k}: {get_name_func(source_actor_id)} `—(write)→` {get_name_func(datasource_id)} `—(read)→` {get_name_func(target_actor_id)}"
        else:
            source_actor_id = action.source_id
            target_actor_id = step.target_actor_id
            # Only show primitive edge labels in the inline step title. For inferred trigger kinds
            # (datasource / self_trigger / trigger) we omit the parenthetical label and rely on
            # the explanatory captions rendered inside the trigger blocks.
            primitive_types = {'write', 'read', 'communicate', 'respond', 'exploit'}
            if action.edge_type in primitive_types:
                display_edge_type = action.edge_type
                step_title = f"Step {start_index + k}: {get_name_func(source_actor_id)} `—({display_edge_type})→` {get_name_func(target_actor_id)}"
            else:
                # Show a neutral arrow without a label for inferred triggers.
                step_title = f"Step {start_index + k}: {get_name_func(source_actor_id)} `—→` {get_name_func(target_actor_id)}"
        
        with st.expander(step_title, expanded=False):
            st.write("**1. Edge Activation Trigger**")
            if step.edge_activation_trigger:
                with st.container(border=True):
                    st.caption(f"Required to activate conditional edge (Hops: {step.edge_activation_trigger.cost})")
                    # If the activation chain contains inferred auto-triggers, surface a concise note.
                    activation_types = {s.push_poison_action.edge_type for s in step.edge_activation_trigger.steps}
                    if 'self_trigger' in activation_types:
                        st.caption("Auto-trigger: the actor can self-trigger; assumed activated by poison arrival (no explicit trigger needed).")
                    if 'datasource' in activation_types:
                        st.caption("Auto-trigger: the actor watches a datasource and is triggered when that datasource is written.")
                    _render_attack_steps(
                        step.edge_activation_trigger.steps,
                        get_name_func,
                        is_sub_step=True,
                        parent_step=step,
                    )
            else:
                if action.edge_type == 'respond':
                    activator_step_index = -1
                    if not is_sub_step:
                        for i in range(k - 1, -1, -1):
                            prev_step_action = steps[i].push_poison_action
                            if (prev_step_action.source_id == step.target_actor_id and
                                prev_step_action.target_id == action.source_id and
                                prev_step_action.edge_type == 'communicate'):
                                activator_step_index = i + 1
                                break
                    if activator_step_index != -1:
                        st.caption(f"Not needed: The respond channel was already activated by **Step {activator_step_index}**.")
                    else:
                        st.caption("Not needed: The respond channel was pre-activated.")
                else:
                    st.caption("Not needed: The main action is not conditional.")

            st.write("**2. Push Poison**")
            # Show primitive edge labels for the push-poison action; omit labels for inferred triggers.
            primitive_types = {'write', 'read', 'communicate', 'respond', 'exploit'}
            # If we detected a write->read pattern but the action itself isn't typed as 'write', render the combined write->read line
            if is_write_pattern and action.edge_type != 'write' and datasource_id:
                st.markdown(f"> {get_name_func(action.source_id)} `—(write)→` {get_name_func(datasource_id)} `—(read)→` {get_name_func(step.target_actor_id)}")
            elif action.edge_type == 'datasource' and parent_step and parent_step.push_poison_action.edge_type == 'write':
                ds_id = parent_step.push_poison_action.target_id
                st.markdown(f"> {get_name_func(action.source_id)} `—(write)→` {get_name_func(ds_id)}")
            elif action.edge_type in primitive_types:
                st.markdown(f"> {get_name_func(action.source_id)} `—({action.edge_type})→` {get_name_func(action.target_id)}")
            else:
                st.markdown(f"> {get_name_func(action.source_id)} `—→` {get_name_func(action.target_id)}")
            
            st.write("**3. Consumption Trigger**")
            if step.consumption_trigger:
                with st.container(border=True):
                    st.caption(f"Required to make the target consume the poison (Hops: {step.consumption_trigger.cost})")
                    # If this is a write -> datasource -> read chain, explain that the reader was watching the datasource.
                    if action.edge_type == 'write':
                        read_source = get_name_func(action.target_id)
                        read_target = get_name_func(step.target_actor_id)
                        st.caption(f"Auto-trigger: {read_target} watches {read_source} and is triggered automatically when it is written.")
                    # Also detect self-trigger inside consumption steps
                    consumption_types = {s.push_poison_action.edge_type for s in step.consumption_trigger.steps}
                    if 'self_trigger' in consumption_types:
                        st.caption("Auto-trigger: the actor can self-trigger; assumed activated by poison arrival (no explicit trigger needed).")
                    _render_attack_steps(
                        step.consumption_trigger.steps,
                        get_name_func,
                        is_sub_step=True,
                        parent_step=step,
                    )

            else:
                if action.edge_type in ["communicate", "respond"]:
                    st.caption("Not needed: The communication action is its own trigger.")
                else:
                    st.caption("Not needed for this step.")

def render_attack_path_results():
    if 'attack_paths' not in st.session_state or not st.session_state.attack_paths:
        st.info("No attack plans generated. Select an attacker and victim, then run the analysis."); return
    
    st.write(f"Found **{len(st.session_state.attack_paths)}** potential attack plan(s).")
    
    graph = st.session_state.graph
    def get_name(node_id):
        if node_id == "assets_node": return "**Assets**"
        node = graph.get_node(node_id)
        return f"_{node.name}_" if node else "_Unknown_"

    plan_options = {i: f"Plan {i+1} (Hops: {p.total_cost})" for i, p in enumerate(st.session_state.attack_paths)}
    if len(plan_options) > 1:
        st.radio(
            "Select a plan to highlight in the graph:",
            options=list(plan_options.keys()),
            format_func=plan_options.get,
            horizontal=True,
            key="selected_path_index",
        )
    
    for i, plan in enumerate(st.session_state.attack_paths):
        attacker_id = st.session_state.graph.attacker_id
        turns = _count_attacker_turns(plan.steps, attacker_id)
        
        expander_title = f"Attack Plan {i+1} (Total Hops: {plan.total_cost}, Attacker Actions: {turns})"
        
        with st.expander(expander_title, expanded=False):
            if plan.steps:
                _render_attack_steps(plan.steps, get_name)
            else:
                st.caption("This plan has no steps.")