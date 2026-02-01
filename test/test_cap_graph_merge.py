from analysis.cap_graph import (
    CapNode,
    CapEdge,
    _compute_edge_signature,
    _merge_equivalent_functions,
    _render_mermaid_node,
)


class TestCapGraphMerge:

    def test_identical_edges_merged(self):
        """Functions with identical edge patterns merge into one node."""
        funcs = [
            CapNode("function", "mod::foo", {"entry": True}),
            CapNode("function", "mod::bar", {"entry": True}),
        ]
        edges = [
            CapEdge("mutates", "mod::foo", "SharedObj", guard="role:Admin"),
            CapEdge("mutates", "mod::bar", "SharedObj", guard="role:Admin"),
            CapEdge("requires_proof", "mod::foo", "AdminCap"),
            CapEdge("requires_proof", "mod::bar", "AdminCap"),
        ]

        merged_funcs, merged_edges, mapping = _merge_equivalent_functions(funcs, edges)

        assert len(merged_funcs) == 1
        assert "_merged_names" in merged_funcs[0].properties
        assert set(merged_funcs[0].properties["_merged_names"]) == {"mod::foo", "mod::bar"}
        assert len(merged_edges) == 2

    def test_different_edges_not_merged(self):
        """Functions with different edge patterns stay separate."""
        funcs = [
            CapNode("function", "mod::foo", {}),
            CapNode("function", "mod::bar", {}),
        ]
        edges = [
            CapEdge("mutates", "mod::foo", "ObjA"),
            CapEdge("mutates", "mod::bar", "ObjB"),
        ]

        merged_funcs, merged_edges, mapping = _merge_equivalent_functions(funcs, edges)

        assert len(merged_funcs) == 2
        assert mapping["mod::foo"] == "mod::foo"
        assert mapping["mod::bar"] == "mod::bar"

    def test_partial_overlap_not_merged(self):
        """Functions with partially overlapping edges stay separate."""
        funcs = [
            CapNode("function", "mod::foo", {}),
            CapNode("function", "mod::bar", {}),
        ]
        edges = [
            CapEdge("mutates", "mod::foo", "SharedObj"),
            CapEdge("mutates", "mod::bar", "SharedObj"),
            CapEdge("requires_proof", "mod::foo", "AdminCap"),
        ]

        merged_funcs, merged_edges, mapping = _merge_equivalent_functions(funcs, edges)

        assert len(merged_funcs) == 2

    def test_incoming_edges_differ_not_merged(self):
        """Functions with same outgoing but different incoming edges stay separate."""
        funcs = [
            CapNode("function", "mod::foo", {}),
            CapNode("function", "mod::bar", {}),
        ]
        edges = [
            CapEdge("mutates", "mod::foo", "SharedObj"),
            CapEdge("mutates", "mod::bar", "SharedObj"),
            CapEdge("calls", "mod::entry", "mod::foo"),
        ]

        merged_funcs, merged_edges, mapping = _merge_equivalent_functions(funcs, edges)

        assert len(merged_funcs) == 2

    def test_three_funcs_two_merge(self):
        """Three functions, two with identical edges merge, one stays separate."""
        funcs = [
            CapNode("function", "mod::a", {}),
            CapNode("function", "mod::b", {}),
            CapNode("function", "mod::c", {}),
        ]
        edges = [
            CapEdge("mutates", "mod::a", "Obj"),
            CapEdge("mutates", "mod::b", "Obj"),
            CapEdge("mutates", "mod::c", "OtherObj"),
        ]

        merged_funcs, merged_edges, mapping = _merge_equivalent_functions(funcs, edges)

        assert len(merged_funcs) == 2
        merged_names = [f.properties.get("_merged_names") for f in merged_funcs if "_merged_names" in f.properties]
        assert len(merged_names) == 1
        assert set(merged_names[0]) == {"mod::a", "mod::b"}

    def test_edge_remapping(self):
        """Edges get remapped to merged node names."""
        funcs = [
            CapNode("function", "mod::foo", {}),
            CapNode("function", "mod::bar", {}),
        ]
        edges = [
            CapEdge("mutates", "mod::foo", "Obj"),
            CapEdge("mutates", "mod::bar", "Obj"),
        ]

        merged_funcs, merged_edges, mapping = _merge_equivalent_functions(funcs, edges)

        assert len(merged_edges) == 1
        assert merged_edges[0].source == merged_funcs[0].name

    def test_no_funcs_empty_result(self):
        """Empty input returns empty output."""
        merged_funcs, merged_edges, mapping = _merge_equivalent_functions([], [])

        assert merged_funcs == []
        assert merged_edges == []
        assert mapping == {}

    def test_single_func_no_merge(self):
        """Single function stays as-is."""
        funcs = [CapNode("function", "mod::only", {"entry": True})]
        edges = [CapEdge("mutates", "mod::only", "Obj")]

        merged_funcs, merged_edges, mapping = _merge_equivalent_functions(funcs, edges)

        assert len(merged_funcs) == 1
        assert "_merged_names" not in merged_funcs[0].properties
        assert mapping["mod::only"] == "mod::only"


class TestMermaidRendering:

    def test_merged_node_renders_with_function_symbol(self):
        """Merged node renders with ƒ prefix and <br/> separators."""
        node = CapNode("function", "pkg::mod::foo", {
            "_merged_names": ["pkg::mod::foo", "pkg::mod::bar", "pkg::mod::baz"]
        })

        result = _render_mermaid_node(node)

        assert "ƒ foo" in result
        assert "ƒ bar" in result
        assert "ƒ baz" in result
        assert "<br/>" in result

    def test_single_func_renders_with_function_symbol(self):
        """Single function node renders with ƒ prefix."""
        node = CapNode("function", "pkg::mod::my_func", {})

        result = _render_mermaid_node(node)

        assert "ƒ my_func" in result
        assert "<br/>" not in result

    def test_capability_no_function_symbol(self):
        """Capability nodes don't get ƒ symbol."""
        node = CapNode("capability", "pkg::mod::AdminCap", {})

        result = _render_mermaid_node(node)

        assert "ƒ" not in result
        assert "AdminCap" in result
