# Architecture Overview

The AI Agent Red Team Workbench is a Streamlit application that combines a rich client-side modeling experience with a cached attack-path analysis engine. This document describes the major building blocks, their responsibilities, and how data flows between them.

## High-Level Flow

1. **Streamlit UI (`main.py`, `view/*`)**
   - Renders the layout, sidebar, graph canvas, and results panes.
   - Receives user input (adding nodes/edges, setting attacker/victim roles, running the analysis).
2. **Command Layer (`ui_commands.py`)**
   - Every structural change is wrapped inside an undoable command.
   - Commands mutate the in-memory `Graph` model stored in `st.session_state`.
3. **Session Management (`session_management.py`)**
   - Serializes/deserializes graphs as JSON to the `sessions/` folder.
   - Ensures Streamlit state survives reloads and that caches are invalidated after edits.
4. **Analysis Core (`analysis/engine.py`, `analysis/pathfinding.py`)**
   - Builds helper graphs (trigger graph + poison graph) and heuristics.
   - Runs a pathfinding strategy to produce `AttackPlan` objects.
5. **Results View (`view/results_panel.py`, `view/graph_renderer.py`)**
   - Formats the returned plans as prose and highlights each hop on the Mermaid diagram.

## Domain Model

All shared data structures live in `domain.py` and are validated with Pydantic:

- **Graph**: Holds nodes, edges, attacker/victim IDs, and helper lookup methods.
- **Actor/Datasource**: Typed nodes. Actors carry trigger metadata (`SelfTrigger`, `DatasourceTrigger`, `CommunicationTrigger`).
- **Edge**: Directed relationship (read/write/communicate/respond).
- **AttackStep/TriggerChain/AttackPlan**: Analysis outputs that describe poison propagation along with prerequisite triggers.
- **CommandHistory & Commands**: Implements the undo/redo stack that the sidebar buttons manipulate.

## Analysis Engine

`analysis/engine.py` prepares the data structures the strategy needs:

- **Trigger Graph**: Maps actors to the actors they can activate based on triggers and datasource watches.
- **Poison Graph**: Captures how poisoned information can travel (write→read, communicate/respond).
- **Poison Heuristic**: Reverse-BFS distance from each actor to the synthetic `Assets` node, used as an admissible A* heuristic.

`analysis/pathfinding.py` defines the `PathfindingStrategy` interface plus `StrategicPlannerStrategy`, an A*-style search that:

1. Starts from the attacker, tracking compromised edges per actor.
2. Expands through the poison graph, paying extra cost whenever a `respond` edge needs activation or an actor (without a datasource watch) needs trigger to consume from a datasource.
3. Calls back into `GraphAnalysis.find_cheapest_trigger_chain` to synthesize trigger chains on demand.
4. Stops when `num_paths` valid `AttackPlan`s (cost ≤ `max_cost`) are discovered.

All heavy computations are wrapped by `@st.cache_data` so identical analyses across reruns are instant, and `clear_cached_data()` is invoked whenever the graph changes.

## UI Composition

- `view/sidebar.py` orchestrates session management, node/edge forms, undo/redo, and kicking off analyses.
- `view/graph_renderer.py` translates the graph + highlighted plan into Mermaid syntax and numbers each visible hop.
- `view/results_panel.py` recursively renders attack steps, surfacing the exact trigger/consumption requirements for each hop.
- `view/content.py` contains the long-form explanatory copy.

## Adding New Capabilities

1. **New node/edge types**: Extend the Pydantic models in `domain.py`, update the sidebar forms, and teach `graph_renderer.py` and `analysis/engine.py` how to interpret them.
2. **Alternate strategies**: Implement a new `PathfindingStrategy` subclass and expose it inside the sidebar's analysis controls.
3. **External storage**: Swap `session_management.py` to read/write from your datastore, keeping the same public helpers.

Keeping the responsibilities isolated this way allows you to iterate on the modeling experience, analysis heuristics, or persistence layer independently.
