import json
import streamlit as st
from attack_path_suggestion_tool.domain import CommandHistory, Graph
from attack_path_suggestion_tool.config import APP_CONFIG

SESSIONS_DIR = APP_CONFIG.storage.sessions_dir

def get_all_sessions() -> dict[str, str]:
    SESSIONS_DIR.mkdir(exist_ok=True)
    sessions = {}
    for file_path in SESSIONS_DIR.glob("*.json"):
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                sessions[data.get('id')] = data.get('name', 'Unnamed Graph')
        except (json.JSONDecodeError, KeyError): continue
    return sessions

def save_current_session():
    if st.session_state.graph and st.session_state.graph.id:
        SESSIONS_DIR.mkdir(exist_ok=True)
        file_path = SESSIONS_DIR / f"{st.session_state.graph.id}.json"
        with open(file_path, 'w') as f:
            f.write(st.session_state.graph.model_dump_json(indent=2))

def load_session_by_id(session_id: str):
    file_path = SESSIONS_DIR / f"{session_id}.json"
    if file_path.exists():
        with open(file_path, 'r') as f:
            data = json.load(f)
            st.session_state.graph = Graph.model_validate(data)
            st.session_state.history = CommandHistory()
            st.session_state.attack_paths, st.session_state.selected_path_index = [], None

def load_latest_session():
    SESSIONS_DIR.mkdir(exist_ok=True)
    files = list(SESSIONS_DIR.glob("*.json"))
    if not files:
        create_new_session("My First Graph")
        return
    latest_file = max(files, key=lambda f: f.stat().st_mtime)
    load_session_by_id(latest_file.stem)

def create_new_session(name: str):
    st.session_state.graph = Graph(name=name)
    st.session_state.history = CommandHistory()
    st.session_state.attack_paths, st.session_state.selected_path_index = [], None
    save_current_session()

def delete_current_session():
    if st.session_state.graph and st.session_state.graph.id:
        file_path = SESSIONS_DIR / f"{st.session_state.graph.id}.json"
        if file_path.exists(): file_path.unlink()
    load_latest_session()