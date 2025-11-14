"""Shared UI helpers used by multiple Streamlit components."""

import streamlit as st

from attack_path_suggestion_tool.analysis.engine import clear_cached_data
from attack_path_suggestion_tool.session_management import save_current_session


def execute_command(command) -> None:
    """Execute a command, persist the graph, and refresh derived state."""

    st.session_state.history.execute(command)
    save_current_session()
    clear_cached_data()
    st.session_state.attack_paths = []
    st.session_state.selected_path_index = None
    st.toast(command.description, icon="✅")
    st.rerun()