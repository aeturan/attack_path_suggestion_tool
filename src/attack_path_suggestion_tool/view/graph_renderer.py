# view/graph_renderer.py
from collections import defaultdict
import streamlit.components.v1 as components

from attack_path_suggestion_tool.domain import Actor, AttackPlan, AttackStep, DatasourceTrigger, Graph, SelfTrigger


class GraphRenderer:
    """Handles the generation and rendering of Mermaid.js graphs."""
    ASSETS_NODE_ID = "assets_node"

    def __init__(self, graph: Graph):
        self.graph = graph

    def _traverse_and_number_steps(self, step: AttackStep, counter: int, edge_labels: dict, h_edges: set, victim_id: str | None = None, assets_node_id: str | None = None) -> int:
        """Recursively traverses an AttackStep tree in the correct order to assign numbers, skipping only invisible trigger events (not edges)."""
        # First, handle edge activation triggers (these may be invisible, e.g., datasource-watching)
        if step.edge_activation_trigger:
            for sub_step in step.edge_activation_trigger.steps:
                # Do NOT increment counter for invisible trigger events (i.e., not an edge)
                counter = self._traverse_and_number_steps(sub_step, counter, edge_labels, h_edges, victim_id, assets_node_id)

        action = step.push_poison_action
        # Only number and highlight edges that actually exist in the graph (visible edges).
        # This avoids numbering invisible trigger events (like datasource-watch activations) and self-triggers.
        if action.edge_type != 'self_trigger':
            edge_key = (action.source_id, action.target_id)
            # Only label if the graph contains a corresponding edge
            if self.graph.get_edge(action.source_id, action.target_id) is not None:
                edge_labels[edge_key].append(str(counter))
                h_edges.add(edge_key)
                counter += 1

        # Special handling: if this is the final exploit step (victim -> assets), highlight and number it
        if victim_id and assets_node_id:
            if action.source_id == victim_id and action.target_id == assets_node_id:
                edge_key = (victim_id, assets_node_id)
                edge_labels[edge_key].append(str(counter))
                h_edges.add(edge_key)
                counter += 1

        # For consumption triggers, recurse as usual (do not increment counter for invisible triggers)
        if step.consumption_trigger:
            for sub_step in step.consumption_trigger.steps:
                counter = self._traverse_and_number_steps(sub_step, counter, edge_labels, h_edges, victim_id, assets_node_id)
        
        return counter

    def generate_mermaid_code(self, highlight_path: AttackPlan | None = None) -> str:
        lines = ["graph TD"]
        
        edge_labels = defaultdict(list)
        h_edges = set()
        if highlight_path:
            execution_order = 1
            all_plan_steps = [step for attempt in highlight_path.attempts for step in attempt.steps]
            victim_id = self.graph.victim_id
            assets_node_id = self.ASSETS_NODE_ID
            for step in all_plan_steps:
                execution_order = self._traverse_and_number_steps(step, execution_order, edge_labels, h_edges, victim_id, assets_node_id)

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

