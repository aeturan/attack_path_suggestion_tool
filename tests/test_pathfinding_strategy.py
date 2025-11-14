from attack_path_suggestion_tool.analysis.engine import GraphAnalysis
from attack_path_suggestion_tool.analysis.pathfinding import StrategicPlannerStrategy
from attack_path_suggestion_tool.domain import (
    Actor,
    Datasource,
    DatasourceTrigger,
    Edge,
    Graph,
)


def test_write_to_read_chain_creates_consumption_trigger():
    attacker = Actor(id="attacker", name="Attacker")
    victim = Actor(
        id="victim",
        name="Victim",
        triggers=[DatasourceTrigger(datasource_id="shared_ds")],
    )
    datasource = Datasource(id="shared_ds", name="Shared DS")
    graph = Graph(
        nodes=[attacker, victim, datasource],
        edges=[
            Edge(source="attacker", target="shared_ds", type="write"),
            Edge(source="shared_ds", target="victim", type="read"),
        ],
        attacker_id="attacker",
        victim_id="victim",
    )

    analysis = GraphAnalysis(graph)
    strategy = StrategicPlannerStrategy()
    plan = analysis.find_attack_paths(strategy, num_paths=1, max_cost=10)[0]

    assert hasattr(plan, "steps")
    assert isinstance(plan.steps, list)
    step = plan.steps[0]
    assert step.push_poison_action.edge_type == "write"
    assert step.consumption_trigger is not None
    assert step.consumption_trigger.cost >= 1
    edge_types = [s.push_poison_action.edge_type for s in step.consumption_trigger.steps]
    assert "datasource" in edge_types
    assert "read" in edge_types


def test_respond_edge_requires_activation_chain_in_plan():
    attacker = Actor(id="attacker", name="Attacker")
    helper = Actor(id="helper", name="Helper")
    victim = Actor(
        id="victim",
        name="Victim",
        triggers=[DatasourceTrigger(datasource_id="trigger_ds")],
    )
    datasource = Datasource(id="trigger_ds", name="Trigger DS")

    edges = [
        Edge(source="attacker", target="helper", type="communicate"),
        Edge(source="helper", target="victim", type="respond"),
        Edge(source="victim", target="helper", type="communicate"),
        Edge(source="attacker", target="trigger_ds", type="write"),
        Edge(source="trigger_ds", target="victim", type="read"),
    ]

    graph = Graph(
        nodes=[attacker, helper, victim, datasource],
        edges=edges,
        attacker_id="attacker",
        victim_id="victim",
    )

    analysis = GraphAnalysis(graph)
    strategy = StrategicPlannerStrategy()
    plan = analysis.find_attack_paths(strategy, num_paths=5, max_cost=15)[1]

    print("plan:", plan)

    assert hasattr(plan, "steps")
    assert isinstance(plan.steps, list)

    respond_step = plan.steps[1]
    assert respond_step.push_poison_action.edge_type == "respond"
    assert respond_step.edge_activation_trigger is not None
    activation_types = [
        s.push_poison_action.edge_type
        for s in respond_step.edge_activation_trigger.steps
    ]
    assert "datasource" in activation_types
    assert "communicate" in activation_types
    assert ("helper", "victim") not in plan.active_channels
