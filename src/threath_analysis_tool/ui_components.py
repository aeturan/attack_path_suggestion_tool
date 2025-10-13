import uuid
import itertools
import streamlit as st
from pydantic import ValidationError

from config import APP_CONFIG
from domain import Actor, DatasourceTrigger, SelfTrigger, AttackPlan # Updated import
from logic import StrategicPlannerStrategy, find_attack_paths_cached # Updated import
from session_management import (
    create_new_session, delete_current_session, get_all_sessions,
    load_session_by_id, save_current_session
)
from ui_commands import (
    AddEdgeCommand, AddNodeCommand, CreateRespondAndActivatorCommand,
    DeleteEdgeCommand, DeleteNodeCommand, EditNodeCommand, SetRoleCommand
)

# --- Helper Functions ---
def execute_command(command):
    st.session_state.history.execute(command)
    save_current_session()
    st.toast(command.description, icon="✅")
    st.rerun()

# --- UI Rendering Functions ---
def render_sidebar():
    with st.sidebar:
        st.header("Session Management")
        if "add_expander_state" not in st.session_state: st.session_state.add_expander_state = True
        if "manage_expander_state" not in st.session_state: st.session_state.manage_expander_state = False
        if "about_expander_state" not in st.session_state: st.session_state.about_expander_state = False
        if "confirming_delete" not in st.session_state: st.session_state.confirming_delete = False
        if "node_to_delete" not in st.session_state: st.session_state.node_to_delete = None
        if "managed_node_id" not in st.session_state: st.session_state.managed_node_id = None
        if "show_respond_dialog" not in st.session_state: st.session_state.show_respond_dialog = False
        if "respond_dialog_data" not in st.session_state: st.session_state.respond_dialog_data = None

        sessions = get_all_sessions()
        session_names = {s_id: name for s_id, name in sessions.items()}
        selected_session = st.selectbox("Load Graph", list(session_names.keys()),
            format_func=lambda s_id: session_names.get(s_id, "Unknown"), index=None, placeholder="Select a graph to load...")
        if selected_session and selected_session != st.session_state.graph.id:
            st.session_state.confirming_delete = False
            load_session_by_id(selected_session)
            st.rerun()

        with st.form("new_session_form", clear_on_submit=True):
            new_graph_name = st.text_input("New Graph Name", placeholder="e.g., In-Car Agent System")
            if st.form_submit_button("Create New Graph"):
                if new_graph_name:
                    st.session_state.confirming_delete = False
                    create_new_session(new_graph_name)
                    st.rerun()
                else: st.warning("Please provide a name.")

        if st.session_state.graph.id:
            if st.button("🗑️ Delete Current Graph", use_container_width=True):
                st.session_state.confirming_delete = True
                st.rerun()
            if st.session_state.confirming_delete:
                @st.dialog("Confirm Deletion")
                def show_confirm_dialog():
                    st.warning(f"Are you sure you want to permanently delete the graph '{st.session_state.graph.name}'?")
                    c1, c2 = st.columns(2)
                    if c1.button("Yes, Delete It", use_container_width=True, type="primary"):
                        delete_current_session()
                        st.session_state.confirming_delete = False
                        st.rerun()
                    if c2.button("Cancel", use_container_width=True):
                        st.session_state.confirming_delete = False
                        st.rerun()
                show_confirm_dialog()

        st.header("Builder Controls")
        c1, c2 = st.columns(2)
        if c1.button("Undo", use_container_width=True, disabled=not st.session_state.history.undo_stack):
            st.session_state.history.undo()
            save_current_session()
            st.rerun()
        if c2.button("Redo", use_container_width=True, disabled=not st.session_state.history.redo_stack):
            st.session_state.history.redo()
            save_current_session()
            st.rerun()

        for cmd in reversed(st.session_state.history.undo_stack[-5:]): st.caption(f"↩️ {cmd.description}")
        with st.expander("➕ Add New Element", expanded=st.session_state.add_expander_state):
            render_add_node_form()
            st.divider()
            render_add_edge_workflow()
        with st.expander("✏️ Manage Elements", expanded=st.session_state.manage_expander_state):
            render_manage_node_workflow()
            st.divider()
            render_delete_edge_workflow()
        st.header("Analysis Controls")
        render_analysis_controls()
        st.markdown("---")
        with st.expander("About the Attack Model", expanded=st.session_state.about_expander_state):
            render_about_model()

def render_add_node_form():
    st.subheader("Add Node")
    node_type = st.radio("Node Type", ["Actor", "Datasource"], horizontal=True, key="add_node_type")
    node_name = st.text_input("Node Name", key="new_node_name")
    has_self_trigger, watched_ds_ids = False, []
    if node_type == "Actor":
        st.markdown("---"); st.caption("Actor Triggers")
        st.caption("An Actor can be triggered in three ways: by itself (`self-trigger`), by a change to a datasource it `watches`, or automatically by an incoming `communicate` or `respond` edge.")
        has_self_trigger = st.checkbox("Can self-trigger?", help="Allows the actor to initiate actions on its own.")
        ds_opts = {n.id: n.name for n in st.session_state.graph.nodes if n.type == "Datasource"}
        if ds_opts:
            watched_ds_ids = st.multiselect("Watches Datasources for changes?", options=list(ds_opts.keys()),
                format_func=lambda ds_id: ds_opts[ds_id], help="This actor will be triggered if an actor writes to any of the selected datasources.")
    if st.button("Add Node"):
        st.session_state.add_expander_state = True
        if node_name:
            try:
                node_data = {
                    "id": f"{node_name.replace(' ', '_')}_{str(uuid.uuid4())[:4]}", "name": node_name, "type": node_type,
                    "has_self_trigger": has_self_trigger, "watches_datasources": watched_ds_ids,
                }
                execute_command(AddNodeCommand(st.session_state.graph, node_data))
            except (ValidationError, ValueError) as e: st.error(f"Error: {e}")
        else: st.warning("Node name cannot be empty.")

def render_add_edge_workflow():
    st.subheader("Add Edge")
    node_opts = {n.id: n.name for n in st.session_state.graph.nodes}
    if not node_opts or len(node_opts) < 2:
        st.caption("Add at least two nodes to create an edge."); return
    if "edge_creation_source_id" not in st.session_state: st.session_state.edge_creation_source_id = None
    if st.session_state.edge_creation_source_id is None:
        src_id = st.selectbox("1. Select Source Node", [""] + list(node_opts.keys()), format_func=lambda x: node_opts.get(x, "Choose..."), index=0)
        if src_id: st.session_state.edge_creation_source_id = src_id; st.rerun()
    else:
        src_node = st.session_state.graph.get_node(st.session_state.edge_creation_source_id)
        if not src_node: st.session_state.edge_creation_source_id = None; st.rerun()
        st.info(f"Source selected: **{src_node.name}**")
        target_opts = {k: v for k, v in node_opts.items() if k != src_node.id}
        target_id = st.selectbox("2. Select Target Node", [""] + list(target_opts.keys()), format_func=lambda x: target_opts.get(x, "Choose..."), index=0)
        if target_id:
            edge_type = st.selectbox("Edge Type", ["read", "write", "communicate", "respond"])
            if st.button("✓ Add Edge", type="primary"):
                st.session_state.add_expander_state = True
                is_special = False
                if edge_type == "respond":
                    inv_edge = st.session_state.graph.get_edge(target_id, src_node.id)
                    if not (inv_edge and inv_edge.type == "communicate"):
                        st.session_state.show_respond_dialog, st.session_state.respond_dialog_data, is_special = True, {"source_id": src_node.id, "target_id": target_id}, True
                        st.rerun()
                if not is_special:
                    try:
                        cmd = AddEdgeCommand(st.session_state.graph, {"source": src_node.id, "target": target_id, "type": edge_type})
                        execute_command(cmd)
                        st.session_state.edge_creation_source_id = None; st.rerun()
                    except (ValidationError, ValueError) as e: st.error(f"Error: {e}")
        if st.button("Cancel Add Edge"): st.session_state.edge_creation_source_id = None; st.rerun()
    if st.session_state.show_respond_dialog:
        @st.dialog("Create Activator Edge?")
        def show_resp_dialog():
            data = st.session_state.respond_dialog_data
            src_name, target_name = st.session_state.graph.get_node(data['source_id']).name, st.session_state.graph.get_node(data['target_id']).name
            st.warning(f"A `respond` edge from **{src_name}** to **{target_name}** requires an activating `communicate` edge from **{target_name}** to **{src_name}**.")
            st.write("Do you want to create this missing `communicate` edge as well?")
            c1, c2 = st.columns(2)
            if c1.button("Yes, Create Both", use_container_width=True, type="primary"):
                resp_data, comm_data = {"source": data['source_id'], "target": data['target_id'], "type": "respond"}, {"source": data['target_id'], "target": data['source_id'], "type": "communicate"}
                cmd = CreateRespondAndActivatorCommand(st.session_state.graph, resp_data, comm_data)
                st.session_state.show_respond_dialog, st.session_state.respond_dialog_data, st.session_state.edge_creation_source_id = False, None, None
                execute_command(cmd)
            if c2.button("Cancel", use_container_width=True):
                st.session_state.show_respond_dialog, st.session_state.respond_dialog_data = False, None; st.rerun()
        show_resp_dialog()

def render_manage_node_workflow():
    st.subheader("Edit or Delete Node")
    node_opts = {n.id: n.name for n in st.session_state.graph.nodes}
    if not node_opts: st.caption("No nodes to manage."); return
    def on_change_node(): st.session_state.node_to_delete = None
    selected_id = st.selectbox("Select Node", [""] + list(node_opts.keys()), format_func=lambda x: node_opts.get(x, "Choose..."), key="managed_node_id", on_change=on_change_node)
    if selected_id:
        node = st.session_state.graph.get_node(selected_id)
        st.markdown("---"); new_name = st.text_input("Edit Name", value=node.name)
        has_self_trigger, watched_ds_ids = False, []
        if isinstance(node, Actor):
            st.caption("Edit Triggers")
            has_self_trigger = st.checkbox("Can self-trigger?", value=any(isinstance(t, SelfTrigger) for t in node.triggers))
            ds_opts = {n.id: n.name for n in st.session_state.graph.nodes if n.type == "Datasource"}
            if ds_opts:
                defaults = [t.datasource_id for t in node.triggers if isinstance(t, DatasourceTrigger)]
                watched_ds_ids = st.multiselect("Watches Datasources", list(ds_opts.keys()), format_func=lambda id: ds_opts[id], default=defaults)
        c1, c2 = st.columns(2)
        if c1.button("Save Changes", use_container_width=True, type="primary"):
            st.session_state.manage_expander_state = True
            new_data = {"name": new_name, "has_self_trigger": has_self_trigger, "watches_datasources": watched_ds_ids}
            execute_command(EditNodeCommand(st.session_state.graph, node.id, new_data))
        if c2.button("Delete Node", use_container_width=True):
            st.session_state.manage_expander_state, st.session_state.node_to_delete = True, node; st.rerun()
    if st.session_state.node_to_delete:
        @st.dialog("Confirm Node Deletion")
        def show_del_dialog():
            name = st.session_state.node_to_delete.name
            st.warning(f"Delete '{name}'? This also deletes all connected edges.")
            c1, c2 = st.columns(2)
            if c1.button("Confirm", use_container_width=True, type="primary"):
                cmd = DeleteNodeCommand(st.session_state.graph, st.session_state.node_to_delete.id)
                st.session_state.node_to_delete, st.session_state.managed_node_id = None, ""; execute_command(cmd)
            if c2.button("Cancel", use_container_width=True):
                st.session_state.node_to_delete = None; st.rerun()
        show_del_dialog()

def render_delete_edge_workflow():
    st.subheader("Delete Edge")
    edge_opts = {}
    for edge in st.session_state.graph.edges:
        src, tgt = st.session_state.graph.get_node(edge.source), st.session_state.graph.get_node(edge.target)
        if src and tgt: edge_opts[(edge.source, edge.target)] = f"{src.name} → {tgt.name} ({edge.type})"
    if not edge_opts: st.caption("No edges to delete."); return
    edge_key = st.selectbox("Select Edge", list(edge_opts.keys()), format_func=lambda k: edge_opts.get(k, "Choose..."), index=None, placeholder="Choose an edge...")
    if st.button("Delete Edge", disabled=not edge_key):
        st.session_state.manage_expander_state = True
        src_id, tgt_id = edge_key
        execute_command(DeleteEdgeCommand(st.session_state.graph, src_id, tgt_id))

def render_analysis_controls():
    st.subheader("Analysis Parameters")
    num_paths = st.number_input("Number of Paths to Find", 1, 50, APP_CONFIG.analysis.num_paths_to_find)
    max_cost = st.number_input("Max Attack Cost", 5, 100, APP_CONFIG.analysis.max_attack_cost)
    attempt_cost = st.number_input("Attempt Cost", 0, 20, APP_CONFIG.analysis.attempt_cost, help="Penalty for each new 'Attempt' by the attacker.")
    st.markdown("---")
    actor_opts = {n.id: n.name for n in st.session_state.graph.nodes if n.type == "Actor"}
    if not actor_opts: st.caption("Add actors to run an analysis."); return
    attacker_id = st.selectbox("Attacker", actor_opts.keys(), format_func=actor_opts.get, index=None)
    if attacker_id and attacker_id != st.session_state.graph.attacker_id:
        execute_command(SetRoleCommand(st.session_state.graph, "attacker", attacker_id))
    victim_id = st.selectbox("Victim", actor_opts.keys(), format_func=actor_opts.get, index=None)
    if victim_id and victim_id != st.session_state.graph.victim_id:
        execute_command(SetRoleCommand(st.session_state.graph, "victim", victim_id))
    if st.button("Generate Attack Plans", type="primary", use_container_width=True,
        disabled=not (st.session_state.graph.attacker_id and st.session_state.graph.victim_id)):
        with st.spinner("Analyzing graph..."):
            plans = find_attack_paths_cached(st.session_state.graph, StrategicPlannerStrategy(), num_paths, max_cost, attempt_cost)
            st.session_state.attack_paths, st.session_state.selected_path_index = plans, 0 if plans else None; st.rerun()

def render_attack_path_results():
    if 'attack_paths' not in st.session_state or not st.session_state.attack_paths:
        st.info("No attack plans generated. Select an attacker and victim, then run the analysis."); return
    
    st.write(f"Found **{len(st.session_state.attack_paths)}** potential attack plan(s).")
    
    graph = st.session_state.graph
    def get_name(node_id):
        if node_id == "assets_node": return "**Assets**"
        node = graph.get_node(node_id)
        return f"_{node.name}_" if node else "_Unknown_"

    # Let user select which plan to view and highlight
    plan_options = {i: f"Plan {i+1} (Cost: {p.total_cost})" for i, p in enumerate(st.session_state.attack_paths)}
    
    if len(plan_options) > 1:
        selected_idx = st.radio(
            "Select a plan to highlight in the graph:",
            options=list(plan_options.keys()),
            format_func=plan_options.get,
            horizontal=True,
            key="selected_path_index",
        )
    
    for i, plan in enumerate(st.session_state.attack_paths):
        with st.expander(f"Attack Plan {i+1} (Total Cost: {plan.total_cost})", expanded=True):
            for j, attempt in enumerate(plan.attempts):
                st.markdown(f"##### Attempt {j+1}: {attempt.summary} (Cost: {attempt.total_attempt_cost})")
                for k, step in enumerate(attempt.steps):
                     with st.container(border=True):
                        action = step.push_poison_action
                        step_summary = f"**Step {k+1}**: {get_name(action.source_id)} `—({action.edge_type})→` {get_name(action.target_id)}"
                        st.markdown(step_summary)

                        if step.edge_activation_trigger and step.edge_activation_trigger.actions:
                            chain = step.edge_activation_trigger
                            st.write(f"**Edge Activation Trigger** (Cost: {chain.cost})")
                            chain_summary = " → ".join([get_name(a.source_id) for a in chain.actions] + [get_name(chain.actions[-1].target_id)])
                            st.caption(f"⛓️ {chain_summary}")
                        
                        if step.consumption_trigger and step.consumption_trigger.actions:
                            chain = step.consumption_trigger
                            st.write(f"**Consumption Trigger** (Cost: {chain.cost})")
                            chain_summary = " → ".join([get_name(a.source_id) for a in chain.actions] + [get_name(chain.actions[-1].target_id)])
                            st.caption(f"⛓️ {chain_summary}")

def render_about_model():
    """Renders the explanation of the core attack modeling concepts."""
    st.markdown(
        """
        #### An Opinionated Framework for Modeling Attacks
        
        Welcome! This tool isn't just a diagrammer; it's a framework for thinking about system security. We've simplified complex systems into a few core ideas to help find attack paths you might otherwise miss.

        ---

        ##### **The Primitives: Actors & Datasources**

        * **Actors `([ ])`**: The "doers." These are the only components that can perform actions.
            * *Think: The AI Assistant, a Human Driver, an Email Tool.*
        
        * **Datasources `[( )]`**: The "things." These are passive buckets of data or state that get acted upon.
            * *Think: A database, the car's screen, the audio speakers.*

        This simple but strict separation helps clarify who can do what to whom.

        ---

        ##### **The Key: What is a "Trigger"?**

        An attack is just a chain of events. A **Trigger** is the spark that causes one of those events. It's how a dormant Actor wakes up and becomes active. The goal of this tool is to find the sequence of triggers that lets an Attacker compromise the Victim's Assets.

        There are only three ways an Actor can be triggered:
        1.  **Self-Trigger `🔄`**: The Actor activates itself (e.g., a scheduled task).
        2.  **Datasource Trigger `🔔`**: The Actor wakes up because data changed in a Datasource it's "watching".
        3.  **Communication Trigger (`comm`/`resp` edge)**: The Actor is activated by a direct command from another Actor.

        ---

        ##### **Our Thesis: A Grammar for Attacks**

        We believe any complex attack can be described using these simple primitives. Think of it as a **formal grammar for hacking**. By finding "sentences" in this grammar that start at the Attacker and end at the Victim's `Assets`, we can uncover surprising and non-obvious vulnerabilities.
        """
    )