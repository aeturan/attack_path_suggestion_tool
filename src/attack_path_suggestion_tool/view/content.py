# view/content.py

ABOUT_MODEL_TEXT = """
#### Modeling How Agentic Attacks Actually Unfold

The workbench treats every attack as a repeatable story made of two nouns and one verb:
**Actors** perform **Actions** against **Datasources**, and each action can wake up the next actor.

---

##### 1. What Lives in the Graph?

| Concept | How to read it | Typical examples |
| --- | --- | --- |
| **Actors** | Active components that can send/receive data. | LLM agent, autonomous vehicle stack, human operator, API worker. |
| **Datasources** | Passive stores of state or content. | Vector DB, inbox queue, vehicle sensor buffer, system prompt vault. |
| **Edges** | Concrete ways actors move or observe data. | `write`, `read`, `communicate`, `respond`. |

Only actors can initiate actions, while datasources simply hold poison until another actor consumes it.

---

##### 2. The Trigger → Action → Trigger Loop

Attack propagation is modeled as repeating micro-loops:

1. **Trigger**: Something wakes an actor up. Triggers can be self-activation (`🔄`), a watched datasource being written (`🔔`), or a message (`communicate`/`respond`).
2. **Action**: Once active, the actor can follow any outgoing edge (read, write, communicate, respond).
3. **New Trigger**: That action creates the conditions for the next actor to wake up, and the chain continues.

Because the loop is explicit, the planner can reason about when a `respond` edge is usable, when a datasource watch fires automatically, and where the attacker must spend real effort.

---

##### 3. How to Capture a System

1. **Sketch the components**: Add every actor and datasource relevant to the scenario.
2. **Wire the flows**: Add `write`/`read` edges for data movement and `communicate`/`respond` edges for messaging contracts.
3. **Annotate triggers**: Mark self-triggers and datasource watches on each actor so the engine knows how it reactivates.
4. **Set roles**: Pick the attacker and victim, then let the planner search for paths that end in the synthetic `Assets` node.

The generated plans describe exactly which actions (and supporting triggers) an attacker must line up to reach the victim's critical assets.
"""

GRAPH_LEGEND_TEXT = """
#### Nodes

| Visual | Meaning |
| --- | --- |
| `Actor` | Active component (service, agent, person). Icons show triggers: `🔄` self-trigger, `🔔` watches a datasource. |
| `Datasource` | Passive datastore / queue / prompt state.
| **Color accents** | Red fill = attacker, orange = victim, green outline = currently highlighted plan.

#### Edges

| Rendering | Action semantics |
| --- | --- |
| Solid arrow `── write →` | Actor writes or sends poison downstream (`write`, `communicate`). |
| Solid arrow `── read →` | Actor consumes data directly from a datasource. |
| Dashed arrow `-·- respond ·->` | Conditional `respond` action. Requires the inverse `communicate` edge to be activated first. |

Highlighted edges are numbered in the order the analyzer expects them to occur.

#### Goal Marker

When a victim is selected, the tool creates a synthetic `Assets` node. Every successful plan must finish with the victim executing an `exploit` action toward that node.
"""