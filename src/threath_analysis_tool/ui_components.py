import uuid

import streamlit as st
from pydantic import ValidationError

from logic import GreedyDFSStrategy, find_attack_paths_cached
from session_management import (
    create_new_session,
    delete_current_session,
    get_all_sessions,
    load_session_by_id,
    save_current_session,
)
from ui_commands import AddEdgeCommand, AddNodeCommand, DeleteEdgeCommand, DeleteNodeCommand, SetRoleCommand


# --- Helper Functions ---
def execute_command(command):
    """Helper to execute a command, save state, and rerun the app."""
    st.session_state.history.execute(command)
    save_current_session()
    st.toast(command.description, icon="✅")
    st.rerun()

# --- UI Rendering Functions ---
def render_sidebar():
    with st.sidebar:
        st.header("Session Management")

        # --- Initialize Expander State ---
        if 'add_expander_state' not in st.session_state:
            st.session_state.add_expander_state = True
        if 'manage_expander_state' not in st.session_state:
            st.session_state.manage_expander_state = False
        
        # --- Initialize Other States ---
        if 'confirming_delete' not in st.session_state:
            st.session_state.confirming_delete = False
        if 'node_to_delete' not in st.session_state:
            st.session_state.node_to_delete = None

        sessions = get_all_sessions()
        session_names = {s_id: name for s_id, name in sessions.items()}
        selected_session = st.selectbox(
            "Load Graph", list(session_names.keys()),
            format_func=lambda s_id: session_names.get(s_id, "Unknown"),
            index=None, placeholder="Select a graph to load..."
        )
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
                else:
                    st.warning("Please provide a name.")

        if st.session_state.graph.id:
            if st.button("🗑️ Delete Current Graph", use_container_width=True):
                st.session_state.confirming_delete = True
                st.rerun()
            
            if st.session_state.confirming_delete:
                @st.dialog("Confirm Deletion")
                def show_confirm_dialog():
                    st.warning(f"Are you sure you want to permanently delete the graph '{st.session_state.graph.name}'?")
                    col1, col2 = st.columns(2)
                    if col1.button("Yes, Delete It", use_container_width=True, type="primary"):
                        delete_current_session()
                        st.session_state.confirming_delete = False
                        st.rerun()
                    if col2.button("Cancel", use_container_width=True):
                        st.session_state.confirming_delete = False
                        st.rerun()
                
                show_confirm_dialog()


        st.header("Builder Controls")
        col1, col2 = st.columns(2)
        if col1.button("Undo", use_container_width=True, disabled=not st.session_state.history.undo_stack):
            st.session_state.history.undo()
            save_current_session()
            st.rerun()
        if col2.button("Redo", use_container_width=True, disabled=not st.session_state.history.redo_stack):
            st.session_state.history.redo()
            save_current_session()
            st.rerun()

        for command in reversed(st.session_state.history.undo_stack[-5:]):
            st.caption(f"↩️ {command.description}")

        with st.expander("➕ Add New Element", expanded=st.session_state.add_expander_state):
            render_add_node_form()
            st.divider()
            render_add_edge_workflow()
        
        with st.expander("✏️ Manage Elements", expanded=st.session_state.manage_expander_state):
            render_delete_node_workflow()
            st.divider()
            render_delete_edge_workflow()

        st.header("Analysis Controls")
        render_analysis_controls()

def render_add_node_form():
    st.subheader("Add Node")
    node_type = st.radio("Node Type", ["Actor", "Datasource"], horizontal=True, key="add_node_type")
    node_name = st.text_input("Node Name", key="new_node_name")
    if st.button("Add Node"):
        # Set expander state before executing command
        st.session_state.add_expander_state = True
        st.session_state.manage_expander_state = False
        if node_name:
            try:
                node_id = f"{node_name.replace(' ', '_')}_{str(uuid.uuid4())[:4]}"
                command = AddNodeCommand(st.session_state.graph, {"id": node_id, "name": node_name, "type": node_type})
                execute_command(command)
            except (ValidationError, ValueError) as e:
                st.error(f"Error: {e}")
        else:
            st.warning("Node name cannot be empty.")

def render_add_edge_workflow():
    st.subheader("Add Edge")
    node_options = {node.id: node.name for node in st.session_state.graph.nodes}
    if not node_options or len(node_options) < 2:
        st.caption("Add at least two nodes to create an edge.")
        return

    if st.session_state.edge_creation_source_id is None:
        source_id = st.selectbox(
            "1. Select Source Node", [""] + list(node_options.keys()),
            format_func=lambda x: node_options.get(x, "Choose..."), index=0
        )
        if source_id:
            st.session_state.edge_creation_source_id = source_id
            st.rerun()
    else:
        source_node = st.session_state.graph.get_node(st.session_state.edge_creation_source_id)
        if not source_node:
             st.session_state.edge_creation_source_id = None
             st.rerun()

        st.info(f"Source selected: **{source_node.name}**")
        target_options = {k: v for k, v in node_options.items() if k != source_node.id}
        target_id = st.selectbox(
            "2. Select Target Node", [""] + list(target_options.keys()),
            format_func=lambda x: target_options.get(x, "Choose..."), index=0
        )
        if target_id:
            edge_type = st.selectbox("Edge Type", ["read", "write", "communicate", "respond"])
            
            if st.button("✓ Add Edge", type="primary"):
                # Set expander state before executing command
                st.session_state.add_expander_state = True
                st.session_state.manage_expander_state = False
                try:
                    command = AddEdgeCommand(st.session_state.graph, {"source": source_node.id, "target": target_id, "type": edge_type})
                    execute_command(command)
                    st.session_state.edge_creation_source_id = None
                    st.rerun()
                except (ValidationError, ValueError) as e:
                    st.error(f"Error: {e}")
        if st.button("Cancel Add Edge"):
            st.session_state.edge_creation_source_id = None
            st.rerun()

def render_delete_node_workflow():
    st.subheader("Delete Node")
    node_options = {node.id: node.name for node in st.session_state.graph.nodes}
    if not node_options:
        st.caption("No nodes to delete.")
        return

    node_id_to_delete = st.selectbox("Select Node", [""] + list(node_options.keys()), format_func=lambda x: node_options.get(x, "Choose..."))
    
    if st.button("Delete Node", disabled=not node_id_to_delete):
        # Set expander state before showing dialog
        st.session_state.add_expander_state = False
        st.session_state.manage_expander_state = True
        st.session_state.node_to_delete = st.session_state.graph.get_node(node_id_to_delete)
        st.rerun()

    if st.session_state.node_to_delete:
        @st.dialog("Confirm Node Deletion")
        def show_confirm_node_delete():
            node_name = st.session_state.node_to_delete.name
            st.warning(f"Delete '{node_name}'? This will also delete all connected edges.")
            col1, col2 = st.columns(2)
            if col1.button("Confirm", use_container_width=True, type="primary"):
                command = DeleteNodeCommand(st.session_state.graph, st.session_state.node_to_delete.id)
                st.session_state.node_to_delete = None
                execute_command(command) # This will rerun
            if col2.button("Cancel", use_container_width=True):
                st.session_state.node_to_delete = None
                st.rerun()

        show_confirm_node_delete()

def render_delete_edge_workflow():
    st.subheader("Delete Edge")
    edge_options = {}
    for edge in st.session_state.graph.edges:
        source_node = st.session_state.graph.get_node(edge.source)
        target_node = st.session_state.graph.get_node(edge.target)
        if source_node and target_node:
            label = f"{source_node.name} → {target_node.name} ({edge.type})"
            edge_options[(edge.source, edge.target)] = label
    
    if not edge_options:
        st.caption("No edges to delete.")
        return
        
    edge_key = st.selectbox("Select Edge", list(edge_options.keys()), format_func=lambda x: edge_options.get(x, "Choose..."), index=None, placeholder="Choose an edge...")

    if st.button("Delete Edge", disabled=not edge_key):
        # Set expander state before executing command
        st.session_state.add_expander_state = False
        st.session_state.manage_expander_state = True
        source_id, target_id = edge_key
        command = DeleteEdgeCommand(st.session_state.graph, source_id, target_id)
        execute_command(command)

def render_analysis_controls():
    actor_options = {n.id: n.name for n in st.session_state.graph.nodes if n.type == 'Actor'}
    if not actor_options:
        st.caption("Add actors to run an analysis.")
        return

    attacker_id = st.selectbox("Attacker", actor_options.keys(), format_func=actor_options.get, index=None)
    if attacker_id and attacker_id != st.session_state.graph.attacker_id:
        execute_command(SetRoleCommand(st.session_state.graph, 'attacker', attacker_id))

    victim_id = st.selectbox("Victim", actor_options.keys(), format_func=actor_options.get, index=None)
    if victim_id and victim_id != st.session_state.graph.victim_id:
        execute_command(SetRoleCommand(st.session_state.graph, 'victim', victim_id))

    if st.button("Generate Attack Paths", type="primary", use_container_width=True, disabled=not(st.session_state.graph.attacker_id and st.session_state.graph.victim_id)):
        with st.spinner("Analyzing graph..."):
            paths = find_attack_paths_cached(st.session_state.graph, GreedyDFSStrategy())
            st.session_state.attack_paths = paths
            st.session_state.selected_path_index = None
            st.rerun()

def render_attack_path_results():
    if not st.session_state.attack_paths:
        st.info("No attack paths generated. Select an attacker and victim, then run the analysis.")
        return

    st.write(f"Found **{len(st.session_state.attack_paths)}** potential path(s).")
    for i, path in enumerate(st.session_state.attack_paths):
        path_str = " → ".join([st.session_state.graph.get_node(step.actor_id).name for step in path.steps if step.step_type == "trigger"])
        victim_node = st.session_state.graph.get_node(path.steps[-1].target_id)
        if victim_node:
            path_str += f" → **{victim_node.name}**"
        
        if st.button(f"Path {i+1}: {path_str}", key=f"path_{i}", use_container_width=True):
            st.session_state.selected_path_index = i
            st.rerun()