# 🛡️ AI Agent Red Team Workbench
An interactive Streamlit application for the structural vulnerability analysis of complex AI agent systems. This workbench provides a formal methodology and a visual tool for modeling system architectures, identifying unintended data and control flows, and discovering potential poison propagation paths.

It is designed for AI security researchers, red teams, and developers to reason about the architectural weaknesses of multi-component AI systems before they are exploited.

## Key Features
- Interactive Graph Builder: Visually construct system architectures using Actor and Datasource nodes and defining read, write, and communicate edges.

- Formal Attack Path Analysis: Implements a dual-path analysis algorithm to distinguish between "Poison Paths" (data flow) and "Trigger Paths" (control flow), revealing complex, multi-step vulnerabilities.

- Pluggable Analysis Engine: Uses the Strategy design pattern to allow for different pathfinding algorithms to be easily swapped and tested.

- Stateful Undo/Redo: A robust command history system (Command Pattern) allows for non-destructive, exploratory modeling with full undo/redo capabilities.

- Session Management: Automatically saves and loads graph models, allowing users to manage multiple analysis sessions.

- Configuration Driven: Application parameters are managed via a Pydantic settings model, allowing for easy tuning without code changes.

