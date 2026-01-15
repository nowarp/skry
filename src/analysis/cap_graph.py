"""
Capability graph building and visualization.

Builds a graph representation of capability ownership and access control patterns
from facts. The graph can be rendered as ASCII for terminal display.

Graph structure:
- Nodes: Capabilities, Objects, Functions, Addresses
- Edges: Creates, Destroys, Reads, Mutates, Transfers, RequiresProof, etc.
"""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

from core.facts import Fact
from core.utils import get_simple_name, info
from move.types import strip_generics
from move.collectors import strip_ref_modifiers

if TYPE_CHECKING:
    from core.context import ProjectContext


@dataclass
class CapNode:
    """Node in capability graph."""

    kind: str  # "capability" | "object" | "function" | "address"
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CapEdge:
    """Edge in capability graph."""

    kind: str  # "creates" | "destroys" | "reads" | "mutates" | "transfers" | "requires_proof" | "calls"
    source: str  # Source node name
    target: str  # Target node name
    guard: Optional[str] = None  # Guard type if any
    address_class: Optional[str] = None  # For transfers: deployer, tx_sender, etc.
    details: Optional[str] = None  # Additional info


def build_cap_graph(ctx: "ProjectContext") -> Tuple[List[CapNode], List[CapEdge]]:
    """
    Build capability graph from facts.

    Returns:
        Tuple of (nodes, edges) for the capability graph.
    """
    nodes: Dict[str, CapNode] = {}  # name -> node
    edges: List[CapEdge] = []

    # Collect all facts across files
    all_facts: List[Fact] = []
    for file_ctx in ctx.source_files.values():
        all_facts.extend(file_ctx.facts)

    # Build index of roles, shared objects, etc.
    roles: Set[str] = set()
    shared_objects: Set[str] = set()
    privileged: Set[str] = set()
    configs: Set[str] = set()
    user_asset_containers: Set[str] = set()
    sensitive_fields: Dict[str, List[str]] = {}  # struct -> [fields]
    field_categories: Dict[Tuple[str, str], str] = {}  # (struct, field) -> category
    init_funcs: Set[str] = set()
    public_funcs: Set[str] = set()
    entry_funcs: Set[str] = set()

    for fact in all_facts:
        if fact.name == "IsCapability":
            roles.add(fact.args[0])
        elif fact.name == "IsSharedObject":
            shared_objects.add(fact.args[0])
        elif fact.name == "IsPrivileged":
            privileged.add(fact.args[0])
        elif fact.name == "IsConfig":
            configs.add(fact.args[0])
        elif fact.name == "IsUserAssetContainer":
            user_asset_containers.add(fact.args[0])
        elif fact.name == "FieldClassification" and len(fact.args) == 6 and not fact.args[3]:
            struct_name = fact.args[0]
            field_path = fact.args[1]
            category = fact.args[2]
            # Track all field categories
            field_categories[(struct_name, field_path)] = category
            # Also track sensitive fields separately for node properties
            if category == "sensitive":
                if struct_name not in sensitive_fields:
                    sensitive_fields[struct_name] = []
                sensitive_fields[struct_name].append(field_path)
        elif fact.name == "IsInit":
            init_funcs.add(fact.args[0])
        elif fact.name == "IsPublic":
            public_funcs.add(fact.args[0])
        elif fact.name == "IsEntry":
            entry_funcs.add(fact.args[0])

    # Add capability nodes
    for role in roles:
        props = {}
        if role in privileged:
            props["privileged"] = True
        nodes[role] = CapNode("capability", role, props)

    # Add object nodes (shared objects + configs)
    for obj in shared_objects | configs | user_asset_containers:
        if obj in roles:
            continue  # Skip if already a capability
        props = {}
        if obj in shared_objects:
            props["shared"] = True
        if obj in configs:
            props["config"] = True
        if obj in user_asset_containers:
            props["user_asset_container"] = True
        if obj in sensitive_fields:
            props["has_sensitive_fields"] = True
        nodes[obj] = CapNode("object", obj, props)

    # Track address classes for node creation
    has_tx_sender_transfers = False
    has_param_transfers = False

    # Add function nodes and edges
    for fact in all_facts:
        # CreatesCapability(func, cap_type)
        if fact.name == "CreatesCapability":
            func_name, cap_type = fact.args
            if func_name not in nodes:
                nodes[func_name] = _make_func_node(func_name, init_funcs, public_funcs, entry_funcs)

            # Determine address class for transfer
            addr_class = "deployer" if func_name in init_funcs else "tx_sender"
            if addr_class == "tx_sender":
                has_tx_sender_transfers = True
            edges.append(CapEdge("creates", func_name, cap_type, address_class=addr_class))

        # DestroysCapability(func, cap_type, stmt_id)
        elif fact.name == "DestroysCapability":
            func_name, cap_type, stmt_id = fact.args
            if func_name not in nodes:
                nodes[func_name] = _make_func_node(func_name, init_funcs, public_funcs, entry_funcs)

            # Check if guarded
            guard = _find_guard_for_function(func_name, all_facts)
            edges.append(CapEdge("destroys", func_name, cap_type, guard=guard))

        # TransfersToSender(func, struct_type)
        elif fact.name == "TransfersToSender":
            func_name, struct_type = fact.args
            if func_name not in nodes:
                nodes[func_name] = _make_func_node(func_name, init_funcs, public_funcs, entry_funcs)

            addr_class = "deployer" if func_name in init_funcs else "tx_sender"
            if addr_class == "tx_sender":
                has_tx_sender_transfers = True
            edges.append(CapEdge("transfers", func_name, struct_type, address_class=addr_class))

        # ChecksCapability(role_type, func)
        elif fact.name == "ChecksCapability":
            role_type, func_name = fact.args
            if func_name not in nodes:
                nodes[func_name] = _make_func_node(func_name, init_funcs, public_funcs, entry_funcs)
            edges.append(CapEdge("requires_proof", func_name, role_type))

        # WritesField(func, struct, field) - for shared objects
        elif fact.name == "WritesField":
            func_name, struct_type, field_path = fact.args
            if struct_type in shared_objects or struct_type in configs:
                if func_name not in nodes:
                    nodes[func_name] = _make_func_node(func_name, init_funcs, public_funcs, entry_funcs)
                guard = _find_guard_for_function(func_name, all_facts)
                # Include field category if available
                category = field_categories.get((struct_type, field_path), "")
                details = f"{field_path}[{category}]" if category else field_path
                edges.append(CapEdge("mutates", func_name, struct_type, guard=guard, details=details))

        # SharesObject(func, struct_type)
        elif fact.name == "SharesObject":
            func_name, struct_type = fact.args
            if func_name not in nodes:
                nodes[func_name] = _make_func_node(func_name, init_funcs, public_funcs, entry_funcs)
            edges.append(CapEdge("shares", func_name, struct_type))

    # Add address nodes from CapabilityOwner
    for fact in all_facts:
        if fact.name == "CapabilityOwner":
            cap_type, addr_class = fact.args
            addr_node_name = f"@{addr_class}"
            if addr_node_name not in nodes:
                nodes[addr_node_name] = CapNode("address", addr_node_name, {"class": addr_class})
            edges.append(CapEdge("owns", addr_node_name, cap_type))

    # Track transfers to tainted recipients (@param) from TaintedAtSink
    for fact in all_facts:
        if fact.name == "TaintedAtSink" and len(fact.args) >= 4:
            func_name, _source, _stmt_id, sink_type = fact.args[:4]
            if sink_type == "transfer_recipient":
                has_param_transfers = True
                if func_name not in nodes:
                    nodes[func_name] = _make_func_node(func_name, init_funcs, public_funcs, entry_funcs)
                guard = _find_guard_for_function(func_name, all_facts)
                edges.append(CapEdge("transfers", func_name, "@param", guard=guard, address_class="param"))

    # Add @tx_sender node if there are non-init transfers to sender
    if has_tx_sender_transfers:
        nodes["@tx_sender"] = CapNode("address", "@tx_sender", {"class": "tx_sender"})

    # Add @param node if there are transfers to tainted recipients
    if has_param_transfers:
        nodes["@param"] = CapNode("address", "@param", {"class": "param", "high_risk": True})

    # Add ALL public/entry functions (not just capability-related ones)
    for func_name in public_funcs | entry_funcs | init_funcs:
        if func_name not in nodes:
            nodes[func_name] = _make_func_node(func_name, init_funcs, public_funcs, entry_funcs)

    # Add Calls edges (function-to-function) - only between known functions
    for fact in all_facts:
        if fact.name == "Calls":
            caller, callee = fact.args
            if caller in nodes and callee in nodes:
                edges.append(CapEdge("calls", caller, callee))

    # Generate mutates edges from FormalArg for &mut shared object parameters
    for fact in all_facts:
        if fact.name == "FormalArg":
            func_name, _param_idx, _param_name, param_type = fact.args

            # Only &mut params (reads edges disabled - too noisy)
            if not param_type.startswith("&mut "):
                continue

            # Strip reference and extract base type
            base_type = strip_ref_modifiers(param_type)
            base_type = strip_generics(base_type)

            # Only create edge if param type is a shared object
            if base_type not in shared_objects:
                continue

            # Create node if needed
            if func_name not in nodes:
                nodes[func_name] = _make_func_node(func_name, init_funcs, public_funcs, entry_funcs)

            # Find guard for this function
            guard = _find_guard_for_function(func_name, all_facts)

            edges.append(CapEdge("mutates", func_name, base_type, guard=guard, details="&mut"))

    return list(nodes.values()), edges


def _make_func_node(
    func_name: str,
    init_funcs: Set[str],
    public_funcs: Set[str],
    entry_funcs: Set[str],
) -> CapNode:
    """Create a function node with appropriate properties."""
    props = {}
    if func_name in init_funcs:
        props["init"] = True
    if func_name in public_funcs:
        props["public"] = True
    if func_name in entry_funcs:
        props["entry"] = True
    return CapNode("function", func_name, props)


def _find_guard_for_function(func_name: str, facts: List[Fact]) -> Optional[str]:
    """Find the guard protecting a function (if any)."""
    for fact in facts:
        if fact.name == "ChecksCapability" and fact.args[1] == func_name:
            return f"role:{get_simple_name(fact.args[0])}"
        if fact.name == "HasSenderEqualityCheck" and fact.args[0] == func_name:
            return "sender"
        if fact.name == "ChecksPause" and fact.args[0] == func_name:
            return "pause"
        if fact.name == "HasVersionCheck" and fact.args[0] == func_name:
            return "version"
    return None


def _get_module(name: str) -> str:
    """Extract module from qualified name (pkg::module::item -> pkg::module)."""
    parts = name.split("::")
    if len(parts) >= 2:
        return f"{parts[0]}::{parts[1]}"
    return name


def _mermaid_node_id(name: str) -> str:
    """Convert FQN to valid Mermaid node ID."""
    return name.replace("::", "__").replace("@", "_at_").replace("-", "_")


def _render_mermaid_node(node: CapNode) -> str:
    """Render a node in Mermaid syntax with appropriate shape."""
    node_id = _mermaid_node_id(node.name)
    label = node.name.replace('"', r"\"")

    if node.kind == "capability":
        return f'        {node_id}[["{label}"]]'
    elif node.kind == "object":
        return f'        {node_id}(["{label}"])'
    elif node.kind == "address":
        return f'        {node_id}{{{{"{label}"}}}}'
    else:  # function
        return f'        {node_id}["{label}"]'


def _render_mermaid_edge(edge: CapEdge) -> str:
    """Render an edge in Mermaid syntax with appropriate style and label."""
    src_id = _mermaid_node_id(edge.source)
    tgt_id = _mermaid_node_id(edge.target)

    # Map internal kind to display label
    kind_label = {
        "requires_proof": "allows",
        "creates": "creates",
        "destroys": "destroys",
        "transfers": "transfers",
        "mutates": "mutates",
        "shares": "shares",
        "owns": "owns",
        "calls": "calls",
        "reads": "reads",
    }.get(edge.kind, edge.kind)

    # Build label
    label_parts = [kind_label]
    if edge.details:
        label_parts[0] = f"{kind_label} .{edge.details}"
    if edge.guard:
        label_parts.append(f"[{edge.guard}]")
    if edge.address_class:
        label_parts.append(f"-> {edge.address_class}")
    label = " ".join(label_parts)

    # Edge style based on type (swap src/tgt for requires_proof: cap --allows--> func)
    if edge.kind == "requires_proof":
        return f"    {tgt_id} -- {label} --> {src_id}"
    elif edge.kind == "destroys":
        return f"    {src_id} -. {label} .-> {tgt_id}"
    elif edge.kind == "mutates":
        return f"    {src_id} == {label} ==> {tgt_id}"
    elif edge.kind == "owns":
        return f"    {src_id} -. {label} .-> {tgt_id}"
    else:
        return f"    {src_id} -- {label} --> {tgt_id}"


def _mermaid_styles() -> str:
    """Return Mermaid classDef statements for node styling."""
    return """    classDef capability fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef object fill:#f3e5f5,stroke:#4a148c,stroke-width:1px
    classDef address fill:#fff3e0,stroke:#e65100,stroke-width:1px
    classDef addr_param fill:#ffebee,stroke:#c62828,stroke-width:2px
    classDef func_init fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px,stroke-dasharray:5
    classDef func_entry fill:#ffcdd2,stroke:#c62828,stroke-width:3px
    classDef func_public fill:#e3f2fd,stroke:#1565c0,stroke-width:1px"""


def dump_cap_graph_to_dir(ctx: "ProjectContext", output_dir: str) -> None:
    """
    Dump capability graph to directory as a single Mermaid diagram file.

    Creates capgraph.mmd containing all capabilities, objects, functions
    and their relationships across all modules.

    Args:
        ctx: Project context with analyzed source files
        output_dir: Directory to write Mermaid file to
    """
    import os

    os.makedirs(output_dir, exist_ok=True)

    nodes, edges = build_cap_graph(ctx)
    if not nodes:
        info("No capability graph data to dump")
        return

    # Group nodes by kind
    caps = [n for n in nodes if n.kind == "capability"]
    objs = [n for n in nodes if n.kind == "object"]
    init_funcs = [n for n in nodes if n.kind == "function" and n.properties.get("init")]
    funcs = [n for n in nodes if n.kind == "function" and not n.properties.get("init")]
    addrs = [n for n in nodes if n.kind == "address"]

    output_path = os.path.join(output_dir, "capgraph.mmd")
    lines = ["flowchart LR"]

    # Subgraph: Capabilities
    if caps:
        lines.append("    subgraph Capabilities")
        for cap in sorted(caps, key=lambda n: n.name):
            lines.append(_render_mermaid_node(cap))
        lines.append("    end")

    # Subgraph: Objects
    if objs:
        lines.append("    subgraph Objects")
        for obj in sorted(objs, key=lambda n: n.name):
            lines.append(_render_mermaid_node(obj))
        lines.append("    end")

    # Subgraph: Init Functions
    if init_funcs:
        lines.append("    subgraph Init")
        for func in sorted(init_funcs, key=lambda n: n.name):
            lines.append(_render_mermaid_node(func))
        lines.append("    end")

    # Subgraph: Functions
    if funcs:
        lines.append("    subgraph Functions")
        for func in sorted(funcs, key=lambda n: n.name):
            lines.append(_render_mermaid_node(func))
        lines.append("    end")

    # Subgraph: Addresses
    if addrs:
        lines.append("    subgraph Addresses")
        for addr in sorted(addrs, key=lambda n: n.name):
            lines.append(_render_mermaid_node(addr))
        lines.append("    end")

    # Edges (deduplicated, prefer edges with details over generic ones)
    lines.append("")

    # First pass: identify (kind, source, target) triplets that have edges with details
    triplets_with_details: Set[Tuple[str, str, str]] = set()
    for edge in edges:
        if edge.details:
            triplets_with_details.add((edge.kind, edge.source, edge.target))

    # Second pass: add edges, skipping generic ones when detailed edges exist
    # Track indices for linkStyle coloring
    seen_edges: Set[Tuple[str, str, str, Optional[str], Optional[str], Optional[str]]] = set()
    sensitive_edge_indices: List[int] = []
    config_edge_indices: List[int] = []
    edge_idx = 0
    for edge in edges:
        triplet = (edge.kind, edge.source, edge.target)
        # Skip generic edges when we have detailed edges for the same triplet
        if not edge.details and triplet in triplets_with_details:
            continue

        edge_key = (edge.source, edge.target, edge.kind, edge.details, edge.guard, edge.address_class)
        if edge_key not in seen_edges:
            seen_edges.add(edge_key)
            lines.append(_render_mermaid_edge(edge))
            # Track edge category for coloring
            if edge.details:
                if "[sensitive]" in edge.details:
                    sensitive_edge_indices.append(edge_idx)
                elif "[config_value]" in edge.details or "[mutable_config]" in edge.details:
                    config_edge_indices.append(edge_idx)
            edge_idx += 1

    # Styles
    lines.append("")
    lines.append(_mermaid_styles())

    # Class assignments
    for cap in caps:
        lines.append(f"    class {_mermaid_node_id(cap.name)} capability")
    for obj in objs:
        lines.append(f"    class {_mermaid_node_id(obj.name)} object")
    for func in init_funcs:
        lines.append(f"    class {_mermaid_node_id(func.name)} func_init")
    for func in funcs:
        if func.properties.get("entry"):
            lines.append(f"    class {_mermaid_node_id(func.name)} func_entry")
        else:
            lines.append(f"    class {_mermaid_node_id(func.name)} func_public")
    for addr in addrs:
        # Use high-risk style for @param
        if addr.properties.get("high_risk"):
            lines.append(f"    class {_mermaid_node_id(addr.name)} addr_param")
        else:
            lines.append(f"    class {_mermaid_node_id(addr.name)} address")

    # Edge coloring for sensitive/config fields
    if sensitive_edge_indices:
        indices = ",".join(str(i) for i in sensitive_edge_indices)
        lines.append(f"    linkStyle {indices} stroke:#c62828,stroke-width:2px")
    if config_edge_indices:
        indices = ",".join(str(i) for i in config_edge_indices)
        lines.append(f"    linkStyle {indices} stroke:#e65100,stroke-width:2px")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    info(f"Mermaid capability graph dumped to: {output_path}")
