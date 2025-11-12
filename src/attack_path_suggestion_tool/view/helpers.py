# view/helpers.py
import streamlit as st

from session_management import save_current_session

def execute_command(command):
    st.session_state.history.execute(command)
    save_current_session()
    st.toast(command.description, icon="✅")
    st.rerun()