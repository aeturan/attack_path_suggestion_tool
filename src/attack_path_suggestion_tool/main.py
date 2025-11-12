"""
The main entry point and presentation layer for the Streamlit application.
"""
import streamlit as st

from domain import CommandHistory
from session_management import load_latest_session
from view.content import ABOUT_MODEL_TEXT, GRAPH_LEGEND_TEXT
from view.graph_renderer import GraphRenderer
from view.results_panel import render_attack_path_results
from view.sidebar import render_sidebar


def render_about_model():
    st.markdown(ABOUT_MODEL_TEXT)


def render_legend():
    with st.expander("Graph Legend"):
        st.markdown(GRAPH_LEGEND_TEXT)


def main():
    st.set_page_config(page_title="AI Agent Red Team Workbench", layout="wide", initial_sidebar_state="expanded")

    if "graph" not in st.session_state: load_latest_session()
    if "history" not in st.session_state: st.session_state.history = CommandHistory()
    if "attack_paths" not in st.session_state: st.session_state.attack_paths = []
    if "selected_path_index" not in st.session_state: st.session_state.selected_path_index = None

    st.title("🛡️ AI Agent Red Team Workbench")
    with st.expander("About the Attack Model"): render_about_model()

    if st.session_state.graph and st.session_state.graph.name:
        st.markdown(f"Currently working on: **{st.session_state.graph.name}**")
    else:
        st.markdown("No graph loaded. Create or select one from the sidebar.")

    render_sidebar()

    if st.session_state.graph and st.session_state.graph.id:
        col1, col2 = st.columns([3, 2], gap="large")
        with col1:
            st.subheader("System Architecture Graph")
            render_legend()
            with st.container(height=800, border=False):
                highlight_path = None
                if st.session_state.selected_path_index is not None:
                    highlight_path = st.session_state.attack_paths[st.session_state.selected_path_index]
                
                renderer = GraphRenderer(st.session_state.graph)
                mermaid_code = renderer.generate_mermaid_code(highlight_path)
                renderer.render_mermaid(mermaid_code)
        with col2:
            st.subheader("Generated Attack Plans")
            render_attack_path_results()
    else:
        st.info("Create a new graph or load one to get started.")

if __name__ == "__main__":
    main()