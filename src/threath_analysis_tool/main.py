"""
The main entry point and presentation layer for the Streamlit application.

This module is responsible for the overall UI layout and for orchestrating
the user workflow. It imports from both `domain` and `logic` to tie the
system together.
"""
import streamlit as st

from domain import CommandHistory
from logic import GraphAnalysis, GreedyDFSStrategy
from session_management import load_latest_session

# Import from our custom modules
from ui_components import render_attack_path_results, render_sidebar

# --- Page Configuration ---
st.set_page_config(
    page_title="AI Agent Red Team Workbench",
    layout="wide",
    initial_sidebar_state="expanded",
)


# --- UI Rendering Functions ---
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


def render_legend():
    """Renders the legend and help text in a collapsible expander."""
    with st.expander("Graph Legend"):
        st.markdown(
            """
            * **Indicators (on Actors):**
                - `🔄` **Self-Trigger**: This actor can initiate actions on its own.
                - `🔔` **Datasource Trigger**: This actor is triggered when data is written to a datasource it "watches".
            * **Roles (Colors):**
                - **Red Fill**: The selected **Attacker**.
                - **Orange Fill**: The selected **Victim** and its compromised **Assets**.
                - **Green Highlight**: Part of a selected **Attack Path**.

            ---

            * **Arrow Styles:**
                - **Solid Line (`───>`)**: Represents a **unidirectional action** (`read`, `write`, or an initiating `comm` trigger).
                - **Dashed Line (`-·-·-·>`)**: Represents a **response-only** channel (`resp`).
            """
        )


def main():
    """Main function to run the Streamlit application."""
    if "graph" not in st.session_state:
        load_latest_session()
    if "history" not in st.session_state:
        st.session_state.history = CommandHistory()
    if "attack_paths" not in st.session_state:
        st.session_state.attack_paths = []
    if "selected_path_index" not in st.session_state:
        st.session_state.selected_path_index = None
    if "edge_creation_source_id" not in st.session_state:
        st.session_state.edge_creation_source_id = None

    st.title("🛡️ AI Agent Red Team Workbench")

    with st.expander("About the Attack Model"):
        render_about_model()

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
                    highlight_path = st.session_state.attack_paths[
                        st.session_state.selected_path_index
                    ]

                analysis = GraphAnalysis(st.session_state.graph, GreedyDFSStrategy())
                analysis.render_mermaid(
                    analysis.generate_mermaid_code(highlight_path)
                )
        with col2:
            st.subheader("Generated Attack Paths")
            render_attack_path_results()
    else:
        st.info("Create a new graph or load one to get started.")


if __name__ == "__main__":
    main()