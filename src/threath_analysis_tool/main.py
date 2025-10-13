"""
The main entry point and presentation layer for the Streamlit application.
"""
import streamlit as st

from domain import CommandHistory, AttackPlan # Updated import
from logic import GraphAnalysis, StrategicPlannerStrategy # Updated import
from session_management import load_latest_session
from ui_components import render_attack_path_results, render_sidebar

# ... (render_about_model and render_legend are unchanged) ...

def render_about_model():
    st.markdown(
        """
        #### An Opinionated Framework for Modeling Attacks
        This tool provides a formal grammar for discovering complex attacks in Gen AI systems. We model attacks by deconstructing them into a few core primitives that follow a simple, powerful loop.

        ---

        ##### **1. The Primitives: Actors & Datasources**

        * **Actors `([ ])`**: The **"doers."** These are the only components that can perform actions.
            * *Think: The AI Assistant, a Human Driver, an API Tool.*
        
        * **Datasources `[( )]`**: The **"things."** These are passive containers of data or state that are acted upon.
            * *Think: A database, a driver's connected phone, GPS navigation data.*

        ---

        ##### **2. The Core Loop: Trigger → Action → Trigger**

        An attack propagates as a chain reaction. The fundamental cycle is: a **Trigger** makes an Actor active, and the **Action** it performs then causes the next Trigger.

        * **A Trigger Wakes the Actor:**
            A dormant Actor must be activated by a **Trigger**. There are three kinds of triggers:
            1.  **Self-Trigger `🔄`**: The Actor activates itself.
            2.  **Datasource Trigger `🔔`**: A `write` action to a Datasource the Actor is "watching" activates it.
            3.  **Communication Trigger**: A `comm` or `resp` action from another Actor activates it.

        * **An Active Actor Performs Actions:**
            Once active, an Actor can perform any of its defined **Actions** (represented by its outgoing edges):
            - `read`: Ingest data from a Datasource.
            - `write`: Modify data in a Datasource.
            - `comm` / `resp`: Send a message to another Actor.

        This cycle—where one Actor's `write` or `comm` action becomes the *trigger* for the next—is how the attack path extends across the system.

        ---

        ##### **3. Our Thesis: A Grammar for Attacks**

        We believe any complex attack can be described using this grammar. By finding "sentences" that start at the Attacker and end at the Victim's `Assets`, we can uncover surprising and non-obvious vulnerabilities.
        """
    )


def render_legend():
    with st.expander("Graph Legend"):
        st.markdown(
            """
            #### Node Reference
            * **Shapes:**
                - `([Actor])`: An **Actor** is an active component that performs actions.
                - `[(Datasource)]`: A **Datasource** is a passive component that stores data.
            * **Indicators (on Actors):**
                - `🔄` **Self-Trigger**: Actor can initiate actions on its own.
                - `🔔` **Datasource Trigger**: Actor is triggered by writes to a datasource it watches.
            * **Roles (Colors):**
                - **Red Fill**: The selected **Attacker**.
                - **Orange Fill**: The selected **Victim**.
                - **Green Highlight**: Part of a selected **Attack Path**.
            
            ---
            
            #### Edge Reference
            Edges represent actions. There are two fundamental types:
            * **Direct Actions (Solid Line `───>`)**: These are actions (`read`, `write`, `comm`) that an active actor can perform at will.
            * **Conditional Actions (Dashed Line `-·-·-·>`)**: This is a special action (`resp`) that can only be performed if a precondition (an inverse `communicate` edge) is met.

            ---

            #### Goal Indicators (Auto-Generated)
            These appear when a `Victim` is selected.
            * **`exploit` (Thick Red Arrow)**: Represents the final, critical action taken by the `Victim` that results in the compromise.
            * **`Assets (( ))`**: Represents the ultimate goal of the attack.
            """
        )


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
                
                analysis = GraphAnalysis(st.session_state.graph)
                analysis.render_mermaid(analysis.generate_mermaid_code(highlight_path))
        with col2:
            st.subheader("Generated Attack Plans")
            render_attack_path_results()
    else:
        st.info("Create a new graph or load one to get started.")

if __name__ == "__main__":
    main()