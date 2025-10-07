"""
The main entry point and presentation layer for the Streamlit application.

This module is responsible for the overall UI layout and for orchestrating
the user workflow. It imports from both `domain` and `logic` to tie the
system together.
"""
import streamlit as st
import uuid
from pydantic import ValidationError

# Import from our custom modules
from domain import (AddEdgeCommand, AddNodeCommand, CommandHistory,
                    SetRoleCommand)
from logic import (GreedyDFSStrategy, GraphAnalysis,
                   create_new_session, delete_current_session,
                   find_attack_paths_cached, get_all_sessions,
                   load_latest_session, load_session_by_id,
                   save_current_session)

# --- Page Configuration ---
st.set_page_config(
    page_title="AI Agent Red Team Workbench",
    layout="wide",
    initial_sidebar_state="expanded",
)

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
        sessions = get_all_sessions()
        session_names = {s_id: name for s_id, name in sessions.items()}
        selected_session = st.selectbox(
            "Load Graph", list(session_names.keys()),
            format_func=lambda s_id: session_names.get(s_id, "Unknown"),
            index=None, placeholder="Select a graph to load..."
        )
        if selected_session and selected_session != st.session_state.graph.id:
            load_session_by_id(selected_session)
            st.rerun()

        with st.form("new_session_form", clear_on_submit=True):
            new_graph_name = st.text_input("New Graph Name", placeholder="e.g., In-Car Agent System")
            if st.form_submit_button("Create New Graph"):
                if new_graph_name:
                    create_new_session(new_graph_name)
                    st.rerun()
                else:
                    st.warning("Please provide a name.")

        if st.session_state.graph.id and st.button("🗑️ Delete Current Graph", use_container_width=True):
            delete_current_session()
            st.rerun()

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

        with st.expander("➕ Add New Element", expanded=True):
            render_add_node_form()
            st.divider()
            render_add_edge_workflow()

        st.header("Analysis Controls")
        render_analysis_controls()

def render_add_node_form():
    node_type = st.radio("Node Type", ["Actor", "Datasource"], horizontal=True)
    node_name = st.text_input("Node Name", key="new_node_name")
    if st.button("Add Node"):
        if node_name:
            try:
                node_id = f"{node_name.replace(' ', '_')}_{str(uuid.uuid4())[:4]}"
                command = AddNodeCommand(st.session_state.graph, {"id": node_id, "name": node_name, "type": node_type})
                execute_command(command)
            except ValidationError as e:
                st.error(f"Validation Error: {e}")
        else:
            st.warning("Node name cannot be empty.")

def render_add_edge_workflow():
    node_options = {node.id: node.name for node in st.session_state.graph.nodes}
    if not node_options:
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
            edge_type = st.selectbox("Edge Type", ["read", "write", "communicate"])
            comm_props = {}
            if edge_type == "communicate":
                comm_props['response_only'] = st.checkbox("Response-only trigger?")
                comm_props['cardinality'] = st.radio("Cardinality", ["request-response", "streaming"], horizontal=True)

            if st.button("✓ Add Edge", type="primary"):
                try:
                    command = AddEdgeCommand(st.session_state.graph, {"source": source_node.id, "target": target_id, "type": edge_type, **comm_props})
                    execute_command(command)
                    st.session_state.edge_creation_source_id = None
                    st.rerun()
                except ValidationError as e:
                    st.error(f"Validation Error: {e}")
        if st.button("Cancel"):
            st.session_state.edge_creation_source_id = None
            st.rerun()

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

# --- Main Application Flow ---

def main():
    """Main function to run the Streamlit application."""
    if 'graph' not in st.session_state:
        load_latest_session()
    if 'history' not in st.session_state:
        st.session_state.history = CommandHistory()
    if 'attack_paths' not in st.session_state:
        st.session_state.attack_paths = []
    if 'selected_path_index' not in st.session_state:
        st.session_state.selected_path_index = None
    if 'edge_creation_source_id' not in st.session_state:
        st.session_state.edge_creation_source_id = None

    st.title("🛡️ AI Agent Red Team Workbench")
    if st.session_state.graph and st.session_state.graph.name:
        st.markdown(f"Currently working on: **{st.session_state.graph.name}**")
    else:
        st.markdown("No graph loaded. Create or select one from the sidebar.")

    render_sidebar()

    if st.session_state.graph and st.session_state.graph.id:
        col1, col2 = st.columns([3, 2], gap="large")
        with col1:
            st.subheader("System Architecture Graph")
            with st.container(height=800, border=False):
                highlight_path = None
                if st.session_state.selected_path_index is not None:
                    highlight_path = st.session_state.attack_paths[st.session_state.selected_path_index]
                
                analysis = GraphAnalysis(st.session_state.graph, GreedyDFSStrategy())
                analysis.render_mermaid(analysis.generate_mermaid_code(highlight_path))
        with col2:
            st.subheader("Generated Attack Paths")
            render_attack_path_results()
    else:
        st.info("Create a new graph or load one to get started.")

if __name__ == "__main__":
    main()