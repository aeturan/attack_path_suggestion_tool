# view/graph_renderer.py
from collections import defaultdict

import streamlit.components.v1 as components

from attack_path_suggestion_tool.domain import (
    Actor,
    AttackPlan,
    AttackStep,
    DatasourceTrigger,
    Graph,
    SelfTrigger,
)


class GraphRenderer:
    """Handles the generation and rendering of Mermaid.js graphs."""
    ASSETS_NODE_ID = "assets_node"

    def __init__(self, graph: Graph):
        self.graph = graph

    def _find_datasource_bridge(self, writer_id: str, watcher_id: str) -> str | None:
        """Locate a datasource that connects a writer to a watcher via write/read edges."""
        write_targets = [e.target for e in self.graph.edges if e.source == writer_id and e.type == 'write']
        for ds_id in write_targets:
            read_edge = self.graph.get_edge(ds_id, watcher_id)
            if read_edge and read_edge.type == 'read':
                return ds_id
        return None

    @staticmethod
    def _append_highlight(edge_key: tuple[str, str], counter: int, edge_labels: dict, h_edges: set, ordered_edges: list[tuple[str, str]]) -> int:
        """Append numbering for a concrete edge unless it repeats the previous edge consecutively."""
        if ordered_edges and ordered_edges[-1] == edge_key:
            return counter
        edge_labels[edge_key].append(str(counter))
        h_edges.add(edge_key)
        ordered_edges.append(edge_key)
        return counter + 1

    def _traverse_and_number_steps(
        self,
        step: AttackStep,
        counter: int,
        edge_labels: dict,
        h_edges: set,
        ordered_edges: list[tuple[str, str]],
        victim_id: str | None = None,
        assets_node_id: str | None = None,
    ) -> int:
        """Recursively traverses an AttackStep tree in the correct order to assign numbers, skipping only invisible trigger events (not edges)."""
        # First, handle edge activation triggers (these may be invisible, e.g., datasource-watching)
        if step.edge_activation_trigger:
            for sub_step in step.edge_activation_trigger.steps:
                # Do NOT increment counter for invisible trigger events (i.e., not an edge)
                counter = self._traverse_and_number_steps(sub_step, counter, edge_labels, h_edges, ordered_edges, victim_id, assets_node_id)

        action = step.push_poison_action
        handled_datasource = False
        if action.edge_type == 'datasource':
            datasource_id = self._find_datasource_bridge(action.source_id, action.target_id)
            if datasource_id:
                write_key = (action.source_id, datasource_id)
                write_edge = self.graph.get_edge(*write_key)
                if write_edge:
                    counter = self._append_highlight(write_key, counter, edge_labels, h_edges, ordered_edges)
                read_key = (datasource_id, action.target_id)
                read_edge = self.graph.get_edge(*read_key)
                if read_edge:
                    counter = self._append_highlight(read_key, counter, edge_labels, h_edges, ordered_edges)
            handled_datasource = True
        # Only number and highlight edges that actually exist in the graph (visible edges).
        # This avoids numbering invisible trigger events (like datasource-watch activations) and self-triggers.
        if action.edge_type != 'self_trigger' and not handled_datasource:
            edge_key = (action.source_id, action.target_id)
            # Only label if the graph contains a corresponding edge
            if self.graph.get_edge(action.source_id, action.target_id) is not None:
                counter = self._append_highlight(edge_key, counter, edge_labels, h_edges, ordered_edges)

        # Special handling: if this is the final exploit step (victim -> assets), highlight and number it
        if victim_id and assets_node_id:
            if action.source_id == victim_id and action.target_id == assets_node_id:
                edge_key = (victim_id, assets_node_id)
                counter = self._append_highlight(edge_key, counter, edge_labels, h_edges, ordered_edges)

        # For consumption triggers, recurse as usual (do not increment counter for invisible triggers)
        if step.consumption_trigger:
            for sub_step in step.consumption_trigger.steps:
                counter = self._traverse_and_number_steps(sub_step, counter, edge_labels, h_edges, ordered_edges, victim_id, assets_node_id)
        
        return counter

    def _collect_highlight_metadata(self, highlight_path: AttackPlan | None = None) -> tuple[dict, set, int]:
        """Prepare edge labels, highlighted edges, and final counter for a path."""
        edge_labels: defaultdict[tuple[str, str], list[str]] = defaultdict(list)
        h_edges: set[tuple[str, str]] = set()
        ordered_edges: list[tuple[str, str]] = []
        counter = 1
        if highlight_path:
            victim_id = self.graph.victim_id
            assets_node_id = self.ASSETS_NODE_ID
            for step in highlight_path.steps:
                counter = self._traverse_and_number_steps(
                    step,
                    counter,
                    edge_labels,
                    h_edges,
                    ordered_edges,
                    victim_id,
                    assets_node_id,
                )
        return edge_labels, h_edges, counter

    def generate_mermaid_code(self, highlight_path: AttackPlan | None = None) -> str:
        lines = ["graph TD"]

        edge_labels, h_edges, _ = self._collect_highlight_metadata(highlight_path)

        for node in self.graph.nodes:
            shape, label = (("([", "])"), node.name) if isinstance(node, Actor) else (("[(", ")]"), node.name)
            if isinstance(node, Actor):
                inds = "".join(["🔄" if any(isinstance(t,SelfTrigger) for t in node.triggers) else "","🔔" if any(isinstance(t,DatasourceTrigger) for t in node.triggers) else ""])
                if inds: label = f"{node.name} {inds}"
            lines.append(f'    {node.id}{shape[0]}"{label}"{shape[1]}')
            if node.id == self.graph.attacker_id: lines.append(f"    style {node.id} fill:#ffadad,stroke:#ff5959,stroke-width:2px")
            elif node.id == self.graph.victim_id: lines.append(f"    style {node.id} fill:#ffd6a5,stroke:#ff9f43,stroke-width:2px")

        edge_display_text = {"write": "write","read": "read","communicate": "comm","respond": "resp"}
        arrow_templates = {
            "write": "-- {text} -->",
            "read": "-- {text} -->",
            "communicate": "-- {text} -->",
            "respond": "-. {text} .->"
        }

        for i, edge in enumerate(self.graph.edges):
            edge_key = (edge.source, edge.target)
            display_text = edge_display_text.get(edge.type, edge.type)
            template = arrow_templates.get(edge.type, "-- {text} -->")

            if edge_key in h_edges:
                label_text = ",".join(sorted(edge_labels[edge_key], key=int))
                full_label = f"{display_text} |{label_text}|"
                arrow = template.format(text=full_label)
                lines.append(f"    {edge.source} {arrow} {edge.target}")
                lines.append(f"    linkStyle {i} stroke:#80ed99,stroke-width:3px")
            else:
                arrow = template.format(text=display_text)
                lines.append(f"    {edge.source} {arrow} {edge.target}")
        
        if self.graph.victim_id:
            lines.append(f'    {self.ASSETS_NODE_ID}(("Assets"))')
            # Unconditionally style the Assets node orange whenever a victim is selected.
            lines.append(f"    style {self.ASSETS_NODE_ID} fill:#ffd6a5,stroke:#ff9f43,stroke-width:2px")
            
            exploit_edge_key = (self.graph.victim_id, self.ASSETS_NODE_ID)
            if exploit_edge_key in h_edges:
                label_text = ",".join(sorted(edge_labels[exploit_edge_key], key=int))
                arrow = f'-- exploit |{label_text}| -->'
                lines.append(f"    {self.graph.victim_id} {arrow} {self.ASSETS_NODE_ID}")
                lines.append(f"    linkStyle {len(self.graph.edges)} stroke:#80ed99,stroke-width:4px")
                # Thicken the border only when it's part of a highlighted path.
                lines.append(f"    style {self.ASSETS_NODE_ID} stroke-width:4px")
            else:
                lines.append(f"    {self.graph.victim_id} -- exploit --> {self.ASSETS_NODE_ID}")

        return "\n".join(lines)

    def calculate_visible_hops(self, highlight_path: AttackPlan | None = None) -> int:
        """Count the number of visible hops that receive numbering in the graph."""
        _, _, counter = self._collect_highlight_metadata(highlight_path)
        return max(0, counter - 1)

    def calculate_attacker_actions(self, highlight_path: AttackPlan | None = None, attacker_id: str | None = None) -> int:
        """Count how many numbered edges originate from the attacker in the highlighted path."""
        if not highlight_path or not attacker_id:
            return 0
        edge_labels, _, _ = self._collect_highlight_metadata(highlight_path)
        return sum(len(labels) for (source, _), labels in edge_labels.items() if source == attacker_id)

    def render_mermaid(self, mermaid_code: str):
        html_code = f"""
        <script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
        <script>
            mermaid.initialize({{
                'startOnLoad': true,
                'theme': 'base',
                'themeVariables': {{
                    'primaryColor': '#F0F2F6',
                    'primaryTextColor': '#262730'
                }}
            }});
        </script>
        <div class="mermaid">
        %%{{init: {{
        "flowchart": {{
            "defaultRenderer": "elk",
            "wrappingWidth": 100,
        }}
        }}}}%%
        {mermaid_code}
        </div>"""
        components.html(html_code, height=800, scrolling=True)

