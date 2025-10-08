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
def render_legend():
    """Renders the legend and help text in a collapsible expander."""
    with st.expander("Graph Legend & Help"):
        st.markdown(
            """
            #### Core Concepts
            - **Actor**: An active component that can perform actions and be triggered.
              - *Examples: Human Driver, AI Assistant, Email Tool, Map Tool.*
            - **Datasource`**: A passive component that stores or represents data.
              - *Examples: Long-Term Memory, Email Storage*
            
            ---
            
            #### Node Reference
            * **Indicators (on Actors):**
                - `🔄` **Self-Trigger**: This actor can initiate actions on its own.
                - `🔔` **Datasource Trigger**: This actor is triggered when data is written to a datasource it "watches".
            * **Roles (Colors):**
                - **Red Fill**: The selected **Attacker**.
                - **Orange Fill**: The selected **Victim**.
                - **Green Highlight**: Part of a selected **Attack Path**.

            ---

            #### Edge Reference
            * **Solid Line (`───>`)**: Represents a **unidirectional action** (`read`, `write`, or an initiating `comm` trigger). The source actively performs the action.
            * **Dashed Line (`- - ->`)**: Represents a **response-only** channel (`resp`). The source can only act after being contacted by the target.
            
            * **Edge Types:**
                - `read`: An Actor ingests or perceives data from a Datasource.
                - `write`: An Actor outputs or modifies data in a Datasource.
                - `comm`: An Actor initiates a trigger/command to another Actor.
                - `resp`: An Actor responds to a communication from another Actor.

            ---

            #### How to Use
            1.  **Build**: Use the sidebar menus to model your system's components and connections.
            2.  **Set Roles**: Use "Analysis Controls" to select an **Attacker** and a **Victim**.
            3.  **Generate**: Click "Generate Attack Paths" to run the analysis.
            4.  **Explore**: Click a path in the results list to highlight it on the graph.
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
    if st.session_state.graph and st.session_state.graph.name:
        st.markdown(f"Currently working on: **{st.session_state.graph.name}**")
    else:
        st.markdown("No graph loaded. Create or select one from the sidebar.")

    render_sidebar()

    if st.session_state.graph and st.session_state.graph.id:
        col1, col2 = st.columns([3, 2], gap="large")
        with col1:
            st.subheader("System Architecture Graph")

            # Render the legend above the graph
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