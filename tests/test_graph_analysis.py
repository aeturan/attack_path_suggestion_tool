import pytest
from attack_path_suggestion_tool.analysis.engine import GraphAnalysis
from attack_path_suggestion_tool.domain import (
    Actor,
    CommunicationTrigger,
    Datasource,
    DatasourceTrigger,
    Edge,
    Graph,
    SelfTrigger,
)

@pytest.fixture
def setup_graph_analysis():
    writer = Actor(id="writer", name="Writer")
    communicator = Actor(
        id="communicator",
        name="Communicator",
        triggers=[CommunicationTrigger(source_actor_id="writer", edge_type="communicate")],
    )
    watcher = Actor(
        id="watcher",
        name="Watcher",
        triggers=[DatasourceTrigger(datasource_id="shared_ds")],
    )
    self_trigger = Actor(
        id="selfie",
        name="Selfie",
        triggers=[SelfTrigger()],
    )
    datasource = Datasource(id="shared_ds", name="Shared DS")

    edges = [
        Edge(source="writer", target="communicator", type="communicate"),
        Edge(source="writer", target="shared_ds", type="write"),
        Edge(source="shared_ds", target="watcher", type="read"),
    ]

    graph = Graph(
        nodes=[writer, communicator, watcher, self_trigger, datasource],
        edges=edges,
        victim_id="watcher",
    )
    analysis = GraphAnalysis(graph)
    return analysis

def test_trigger_graph_includes_all_trigger_types(setup_graph_analysis):
    trigger_graph = setup_graph_analysis.trigger_graph
    assert "communicator" in trigger_graph["writer"]
    assert "watcher" in trigger_graph["writer"]
    assert "selfie" in trigger_graph["selfie"]

def test_poison_graph_connects_writer_to_watcher(setup_graph_analysis):
    poison_graph = setup_graph_analysis.poison_graph
    assert "watcher" in poison_graph["writer"]

def test_poison_heuristic_counts_hops_to_assets(setup_graph_analysis):
    heuristic = setup_graph_analysis.poison_heuristic
    # Assets is cost 0, watcher is one hop, writer is two hops away
    assert heuristic[setup_graph_analysis.ASSETS_NODE_ID] == 0
    assert heuristic["watcher"] == 1
    assert heuristic["writer"] == 2
