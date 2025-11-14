from attack_path_suggestion_tool.analysis.engine import GraphAnalysis
from attack_path_suggestion_tool.domain import (
    Action,
    Actor,
    AttackStep,
    Datasource,
    DatasourceTrigger,
    Edge,
    Graph,
    TriggerChain,
)


def test_trigger_chain_flattening():
    # Create nested trigger chains with AttackStep (no Attempt)
    action1 = Action(source_id="A", edge_type="write", target_id="B")
    step1 = AttackStep(
        push_poison_action=action1,
        target_actor_id="B",
        compromise_edge=("A", "B"),
        cost=1,
        summary="Step 1"
    )
    action2 = Action(source_id="B", edge_type="read", target_id="C")
    step2 = AttackStep(
        push_poison_action=action2,
        target_actor_id="C",
        compromise_edge=("B", "C"),
        cost=1,
        summary="Step 2"
    )
    chain = TriggerChain(steps=[step1, step2], cost=2)
    assert len(chain.steps) == 2
    assert chain.steps[0].summary == "Step 1"
    assert chain.steps[1].summary == "Step 2"

def test_datasource_trigger_chain_inferred():
    writer = Actor(id="writer", name="Writer")
    watcher = Actor(
        id="watcher",
        name="Watcher",
        triggers=[DatasourceTrigger(datasource_id="ds")],
    )
    datasource = Datasource(id="ds", name="Datasource")
    graph = Graph(
        nodes=[writer, watcher, datasource],
        edges=[
            Edge(source="writer", target="ds", type="write"),
            Edge(source="ds", target="watcher", type="read"),
        ],
    )
    analysis = GraphAnalysis(graph)

    chain = analysis.find_cheapest_trigger_chain({"writer"}, "watcher", set())
    assert chain is not None
    assert chain.cost == 1
    assert chain.steps[0].push_poison_action.edge_type == "datasource"
