# view/results_panel.py
from typing import List
import streamlit as st

from domain import AttackStep


def _render_attack_steps(steps: List[AttackStep], get_name_func: callable, is_sub_step: bool = False, start_index: int = 1):
    """A recursive helper function to render a list of AttackSteps."""
    for k, step in enumerate(steps):
        
        action = step.push_poison_action
        
        if action.edge_type == 'write':
            source_actor_id = action.source_id
            datasource_id = action.target_id
            target_actor_id = step.target_actor_id
            step_title = f"Step {start_index + k}: {get_name_func(source_actor_id)} `—(write)→` {get_name_func(datasource_id)} `—(read)→` {get_name_func(target_actor_id)}"
        else:
            source_actor_id = action.source_id
            target_actor_id = step.target_actor_id
            step_title = f"Step {start_index + k}: {get_name_func(source_actor_id)} `—({action.edge_type})→` {get_name_func(target_actor_id)}"
        
        with st.expander(step_title, expanded=False):
            st.write("**1. Edge Activation Trigger**")
            if step.edge_activation_trigger:
                with st.container(border=True):
                    st.caption(f"Required to activate conditional edge (Cost: {step.edge_activation_trigger.cost})")
                    _render_attack_steps(step.edge_activation_trigger.steps, get_name_func, is_sub_step=True)
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

            st.write(f"**2. Push Poison**")
            st.markdown(f"> {get_name_func(action.source_id)} `—({action.edge_type})→` {get_name_func(action.target_id)}")
            
            st.write("**3. Consumption Trigger**")
            if step.consumption_trigger:
                with st.container(border=True):
                    st.caption(f"Required to make the target consume the poison (Cost: {step.consumption_trigger.cost})")
                    _render_attack_steps(step.consumption_trigger.steps, get_name_func, is_sub_step=True)
                    
                    # --- FINAL FIX: Move consumption text inside the trigger block ---
                    if action.edge_type == 'write':
                        read_source = get_name_func(action.target_id)
                        read_target = get_name_func(step.target_actor_id)
                        st.markdown(f"↳ *This trigger chain results in {read_target} consuming the poison by performing a `read` from {read_source}.*")

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

    plan_options = {i: f"Plan {i+1} (Cost: {p.total_cost})" for i, p in enumerate(st.session_state.attack_paths)}
    if len(plan_options) > 1:
        st.radio(
            "Select a plan to highlight in the graph:",
            options=list(plan_options.keys()),
            format_func=plan_options.get,
            horizontal=True,
            key="selected_path_index",
        )
    
    for i, plan in enumerate(st.session_state.attack_paths):
        with st.expander(f"Attack Plan {i+1} (Total Cost: {plan.total_cost}, Attempts: {len(plan.attempts)})", expanded=False):
            
            all_steps = []
            if plan.attempts:
                for sequence in plan.attempts:
                    all_steps.extend(sequence.steps)

            if all_steps:
                _render_attack_steps(all_steps, get_name)
            else:
                st.caption("This plan has no steps.")