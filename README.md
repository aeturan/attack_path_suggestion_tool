# 🛡️ AI Agent Red Team Workbench

**Check the paper:** [Agent2Agent Threats in Safety-Critical LLM Assistants: A Human-Centric Taxonomy](https://arxiv.org/abs/2602.05877)

The workbench is an interactive Streamlit application for reasoning about complex AI-agent ecosystems. Model your system as a graph, specify how components trigger each other, and let the analysis engine discover non-obvious attack paths from an attacker-controlled actor to the victim’s critical assets.

## Highlights

- **Visual graph builder** – Add actors/datasources, wire `read`/`write`/`communicate`/`respond` edges, and annotate triggers directly in the UI.
- **Formal path analysis** – The engine separates poison propagation from trigger activation, then merges them into readable attack plans.
- **Undo/redo everywhere** – Every edit is an undoable command, so you can explore “what-if” scenarios safely.
- **Session persistence** – Graphs are saved as JSON in `src/attack_path_suggestion_tool/sessions/`, making it easy to version or share them.
- **Documented architecture** – See `docs/architecture.md` for module responsibilities and data flow.

## Tech Stack

- Python 3.11+
- Streamlit for the UI
- Pydantic & `pydantic-settings` for data validation/config
- Custom A*-style planner for pathfinding

## Getting Started

### 1. Clone and install

```bash
git clone https://github.com/erkantare07/attack_path_suggestion_tool.git
cd attack_path_suggestion_tool
```

You can run the project with either [uv](https://github.com/astral-sh/uv) (recommended) or plain `pip`.

#### Option A – uv

```bash
uv venv
source .venv/bin/activate
uv pip install -e .
```

#### Option B – pip

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
```

### 2. Run the Streamlit app

```bash
streamlit run src/attack_path_suggestion_tool/main.py
```

If you prefer not to activate the virtual environment manually, you can also run `uv run streamlit run src/attack_path_suggestion_tool/main.py`.

The browser UI will open automatically. Use the sidebar to create or load a graph, add nodes/edges, set attacker + victim roles, and click **Generate Attack Plans**.

### 3. Run the tests

```bash
pytest
```

### 4. (Optional) Build and run with Docker

```bash
docker build -t attack-path-workbench .
docker run --rm -p 8501:8501 attack-path-workbench
```

Navigating to `http://localhost:8501` will show the same Streamlit UI.

## Project Layout

```
src/attack_path_suggestion_tool/
├── analysis/        # Graph analysis + pathfinding strategies
├── view/            # Streamlit UI components, content, and renderers
├── sessions/        # Auto-saved JSON graph sessions
├── domain.py        # Pydantic models shared across layers
├── ui_commands.py   # Undoable commands (Command pattern)
└── main.py          # Streamlit entry point
docs/architecture.md # Detailed architecture notes
tests/               # Unit tests for the domain and analysis layers
```

## Configuration

Application defaults live in `config.py` and can be overridden via environment variables thanks to `pydantic-settings`. Useful knobs include:

- `APP_CONFIG__ANALYSIS__NUM_PATHS_TO_FIND` – Default number of attack plans.
- `APP_CONFIG__ANALYSIS__MAX_ATTACK_COST` – Max allowed hop cost.
- `APP_CONFIG__STORAGE__SESSIONS_DIR` – Custom directory for session JSON files.

## Documentation

- `README.md` (this file) – quick start + ops notes.
- `docs/architecture.md` – system design, domain models, and extension guide.
- `src/attack_path_suggestion_tool/view/content.py` – in-app explanation of the attack grammar and legend.
