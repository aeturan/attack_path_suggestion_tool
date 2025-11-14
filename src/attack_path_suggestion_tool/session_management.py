"""Helpers for persisting and restoring graph modeling sessions."""

import json

import streamlit as st

from attack_path_suggestion_tool.analysis.engine import clear_cached_data
from attack_path_suggestion_tool.config import APP_CONFIG
from attack_path_suggestion_tool.domain import CommandHistory, Graph

SESSIONS_DIR = APP_CONFIG.storage.sessions_dir

def get_all_sessions() -> dict[str, str]:
    """Return a mapping of saved session IDs to their display names."""

    SESSIONS_DIR.mkdir(exist_ok=True)
    sessions: dict[str, str] = {}
    for file_path in SESSIONS_DIR.glob("*.json"):
        try:
            with open(file_path, "r", encoding="utf-8") as file_handle:
                data = json.load(file_handle)
                sessions[data.get("id")] = data.get("name", "Unnamed Graph")
        except (json.JSONDecodeError, KeyError):
            continue
    return sessions


def save_current_session() -> None:
    """Serialize the in-memory graph to disk for persistence."""

    if st.session_state.graph and st.session_state.graph.id:
        SESSIONS_DIR.mkdir(exist_ok=True)
        file_path = SESSIONS_DIR / f"{st.session_state.graph.id}.json"
        with open(file_path, "w", encoding="utf-8") as file_handle:
            file_handle.write(st.session_state.graph.model_dump_json(indent=2))


def load_session_by_id(session_id: str) -> None:
    """Load a previously saved graph by ID and reset transient state."""

    clear_cached_data()
    file_path = SESSIONS_DIR / f"{session_id}.json"
    if file_path.exists():
        with open(file_path, "r", encoding="utf-8") as file_handle:
            data = json.load(file_handle)
        st.session_state.graph = Graph.model_validate(data)
        st.session_state.history = CommandHistory()
        st.session_state.attack_paths, st.session_state.selected_path_index = [], None


def load_latest_session() -> None:
    """Load the most recently modified session if one exists."""

    SESSIONS_DIR.mkdir(exist_ok=True)
    files = list(SESSIONS_DIR.glob("*.json"))
    if not files:
        create_new_session("My First Graph")
        return
    latest_file = max(files, key=lambda file_path: file_path.stat().st_mtime)
    load_session_by_id(latest_file.stem)


def create_new_session(name: str) -> None:
    """Start a brand-new graph with the provided display ``name``."""

    clear_cached_data()
    st.session_state.graph = Graph(name=name)
    st.session_state.history = CommandHistory()
    st.session_state.attack_paths, st.session_state.selected_path_index = [], None
    save_current_session()


def delete_current_session() -> None:
    """Delete the active session's JSON file then load the most recent one."""

    if st.session_state.graph and st.session_state.graph.id:
        file_path = SESSIONS_DIR / f"{st.session_state.graph.id}.json"
        if file_path.exists():
            file_path.unlink()
    load_latest_session()