from attack_path_suggestion_tool.domain import Action, AttackStep, AttackPlan

def test_attack_plan_structure():
    # Create a dummy AttackStep
    action = Action(source_id="A", edge_type="write", target_id="B")
    step = AttackStep(
        push_poison_action=action,
        target_actor_id="B",
        compromise_edge=("A", "B"),
        cost=1,
        summary="Test step"
    )
    # Create an AttackPlan with a flat list of steps (no Attempt)
    plan = AttackPlan(steps=[step], total_cost=1)
    assert isinstance(plan.steps, list)
    assert isinstance(plan.steps[0], AttackStep)
    assert plan.steps[0].cost == 1
    assert plan.steps[0].summary == "Test step"
from attack_path_suggestion_tool.domain import (
    Actor,
    Datasource,
    DatasourceTrigger,
    Edge,
    Graph,
    SelfTrigger,
)

def test_graph_get_node_and_edge():
    actor = Actor(id="actor_1", name="Actor 1")
    datasource = Datasource(id="ds_1", name="Datasource 1")
    edge = Edge(source="actor_1", target="ds_1", type="write")
    graph = Graph(nodes=[actor, datasource], edges=[edge])

    assert graph.get_node("actor_1") is actor
    assert graph.get_node("ds_1") is datasource
    assert graph.get_edge("actor_1", "ds_1") == edge
    assert graph.get_edge("ds_1", "actor_1") is None

def test_actor_triggers_preserved():
    ds_trigger = DatasourceTrigger(datasource_id="ds_1")
    actor = Actor(
        id="actor_triggers",
        name="Triggered Actor",
        triggers=[SelfTrigger(), ds_trigger],
    )

    trigger_types = {trigger.type for trigger in actor.triggers}
    assert "self" in trigger_types
    assert "datasource" in trigger_types
    assert actor.triggers[1].datasource_id == "ds_1"
