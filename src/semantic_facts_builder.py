"""
Builds semantic facts using LLM reasoning (Pass 2).

This pass performs:
1. Project-level feature detection (versioning, etc.)
2. Unified struct + field classification (roles, privileged, user assets, config, field types)

Uses SourceFileContext populated by StructuralBuilder (Pass 1).
"""

from typing import List, Tuple, Set, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from analysis.function_index import FunctionIndex

from core.context import ProjectContext, SourceFileContext
from core.facts import Fact
from llm.client import call_llm_json
from core.utils import debug, get_simple_name
from move.extract import extract_function_signature, extract_function_source, extract_function_docstring
from move.sui_patterns import is_stdlib_type, is_stdlib_module
from move.types import extract_all_types
from move.imports import _replace_import_alias
from analysis.patterns import CreationSite, collect_creation_sites
from prompts import render as render_prompt


# Maximum functions to include in unified classification prompt
MAX_FUNCTIONS_IN_PROMPT = 8


def _truncate_preserving_transfers(func_source: str, max_lines: int = 50) -> str:
    """Truncate function source while preserving critical transfer/share/freeze calls.

    When a function exceeds max_lines, we truncate but add a summary of any
    critical lines (transfer, share, freeze calls) that would otherwise be hidden.
    This ensures the LLM can see the actual sharing status even for long functions.
    """
    lines = func_source.split("\n")
    if len(lines) <= max_lines:
        return func_source

    # Find critical lines beyond truncation point
    critical_patterns = ["transfer::", "share_object", "freeze_object", "public_transfer"]
    critical_lines = []
    for i, line in enumerate(lines):
        if i >= max_lines:  # Only look at truncated lines
            if any(p in line for p in critical_patterns):
                critical_lines.append((i + 1, line.strip()))  # 1-indexed line numbers

    # Build truncated output
    truncated = "\n".join(lines[:max_lines])
    if critical_lines:
        truncated += "\n  // ... truncated, but contains:\n"
        for line_no, content in critical_lines:
            truncated += f"  // Line {line_no}: {content}\n"
    else:
        truncated += "\n  // ... truncated"

    return truncated


def _struct_creates_target(func_source: str, struct_name: str) -> bool:
    """Check if function actually packs the target struct.

    Used to filter out creation sites that don't actually create the struct
    being classified (e.g., when simple name matching caused wrong attribution).
    """
    import re

    simple_name = get_simple_name(struct_name)
    # Look for pack expression: StructName { ... }
    pattern = rf"\b{re.escape(simple_name)}\s*\{{"
    return bool(re.search(pattern, func_source))


def _extract_struct_source(file_ctx: SourceFileContext, struct_name: str) -> str | None:
    """Extract struct source code from already-parsed file."""
    if file_ctx.source_code is None:
        return None
    source_code = file_ctx.source_code
    simple_name = get_simple_name(struct_name)

    def find_struct_def(node):
        if node.type == "struct_definition":
            for child in node.children:
                if child.type == "struct_identifier":
                    found_name = source_code[child.start_byte : child.end_byte]
                    if found_name == simple_name:
                        return node
        for child in node.children:
            result = find_struct_def(child)
            if result:
                return result
        return None

    struct_node = find_struct_def(file_ctx.root)
    if struct_node:
        return source_code[struct_node.start_byte : struct_node.end_byte]
    return None


class SemanticFactsBuilder:
    """
    Builds semantic facts using LLM reasoning.

    Performs two types of analysis:
    1. Project-level feature detection (versioning, ACL patterns, etc.)
    2. Unified struct + field classification (single LLM call per struct)
    """

    def __init__(self, required_features: Optional[set] = None):
        self.required_features = required_features or set()

    def build(self, ctx: ProjectContext, rules) -> None:
        """
        Build all semantic facts.

        Args:
            ctx: Project context with parsed source files
            rules: Hy rules to decide which facts to deduce
        """
        self._build_project_features(ctx)  # Project-level feature detection
        self._classify_struct_and_fields(ctx)  # Unified struct + field classification

    def _build_project_features(self, ctx: ProjectContext) -> None:
        """Detect project-level features (versioning, etc.)."""
        from features.runner import FeatureRunner

        source_files = list(ctx.source_files.keys())
        if not source_files:
            ctx.project_facts = []
            return

        if self.required_features:
            debug(f"Pass 2: Detecting project features: {self.required_features}")
            runner = FeatureRunner()
            ctx.project_facts = runner.detect_required(ctx, self.required_features)
            debug(f"Pass 2: Generated {len(ctx.project_facts)} project facts")
        else:
            debug("Pass 2: No features required, skipping detection")
            ctx.project_facts = []

    def _classify_struct_and_fields(self, ctx: ProjectContext) -> None:
        """
        Unified struct + field classification using single LLM call per struct.

        Classifies structs with `key` ability into:
        - IsCapability: capability/permission that gates access
        - IsPrivileged: admin/owner capability (controls critical operations)
        - IsUserAsset: user-owned valuable (receipt, ticket, position)
        - IsConfig: configuration parameters

        Also classifies fields:
        - IsConfigValueField: config values (fees, rates, limits)
        - IsPrivilegedAddressField: privileged addresses (admin, owner)
        - IsLockField: per-object lock control fields
        """
        # Collect candidates: structs with key ability not already classified
        candidates = self._collect_classification_candidates(ctx)
        if not candidates:
            debug("Pass 2: No internal struct candidates for classification")
        else:
            debug(f"Pass 2: Classifying {len(candidates)} structs (unified)...")

        # Collect creation sites and field accesses for all structs
        creation_sites = collect_creation_sites(ctx)
        field_accesses = self._collect_field_accesses(ctx)

        # Get function index from context (lazy-built, shared across passes)
        func_index = ctx.function_index

        # Collect struct field names for validation
        struct_fields = self._collect_struct_fields(ctx)

        # Fast-path: obvious roles
        fast_path_roles = []
        llm_candidates = []

        for struct_name, file_path in candidates:
            if self._is_obvious_role(struct_name, ctx, creation_sites, field_accesses):
                fast_path_roles.append((struct_name, file_path))
            else:
                llm_candidates.append((struct_name, file_path))

        new_struct_facts: List[Fact] = []
        new_field_facts: List[Fact] = []
        counts = {
            "IsCapability": 0,
            "IsPrivileged": 0,
            "IsUserAsset": 0,
            "IsConfig": 0,
            "IsStateContainer": 0,
            "config_fields": 0,
            "privileged_fields": 0,
            "lock_fields": 0,
            "state_fields": 0,
        }

        # Process fast-path roles (no LLM)
        for struct_name, file_path in fast_path_roles:
            file_ctx = ctx.source_files[file_path]
            role_fact = Fact("IsCapability", (struct_name,))
            priv_fact = Fact("IsPrivileged", (struct_name,))
            file_ctx.facts.append(role_fact)
            file_ctx.facts.append(priv_fact)
            new_struct_facts.append(role_fact)
            new_struct_facts.append(priv_fact)
            counts["IsCapability"] += 1
            counts["IsPrivileged"] += 1
            debug(f"  {struct_name} -> IsCapability+IsPrivileged (fast-path)")

        # Process LLM candidates
        for struct_name, file_path in llm_candidates:
            file_ctx = ctx.source_files[file_path]
            struct_source = _extract_struct_source(file_ctx, struct_name)
            if not struct_source:
                debug(f"  Could not extract source for {struct_name}")
                continue

            # Get struct comment if available
            struct_comment = self._get_struct_comment(file_ctx, struct_name)

            # Get creation sites for this struct
            struct_creation_sites = creation_sites.get(struct_name, [])

            # Get field accesses for this struct
            struct_field_accesses = field_accesses.get(struct_name, [])

            # Build unified function context
            func_context = self._build_unified_function_context(ctx, struct_name, struct_field_accesses, func_index)

            # Get valid field names for this struct (for validation)
            valid_fields = struct_fields.get(struct_name, set())

            # Classify via LLM (unified call)
            classification = self._classify_unified_llm(
                ctx,
                struct_name,
                struct_source,
                struct_comment,
                struct_creation_sites,
                func_context,
                func_index,
                valid_fields,
            )

            # Generate struct facts
            self._emit_struct_facts(ctx, file_ctx, struct_name, classification, new_struct_facts, counts)

            # Generate field facts (with validation)
            self._emit_field_facts(file_ctx, struct_name, classification, valid_fields, new_field_facts, counts)

        # Classify external types (from dependencies, no source code)
        external_counts = {"fast_path": 0, "llm": 0}
        external_candidates = self._collect_external_type_candidates(ctx)
        if external_candidates:
            debug(f"Pass 2: Classifying {len(external_candidates)} external types...")

            for type_fqn in external_candidates:
                usage_ctx = self._build_external_type_context(type_fqn, ctx)

                if self._is_obvious_external_role(usage_ctx):
                    # Fast-path: obvious role based on usage
                    self._emit_external_role_facts(type_fqn, ctx, is_role=True, is_privileged=True)
                    external_counts["fast_path"] += 1
                    counts["IsCapability"] += 1
                    counts["IsPrivileged"] += 1
                else:
                    # LLM classification with usage context
                    classification = self._classify_external_type_llm(type_fqn, usage_ctx)
                    self._emit_external_role_facts(
                        type_fqn,
                        ctx,
                        is_role=classification.get("is_role", False),
                        is_privileged=classification.get("is_privileged", False),
                    )
                    external_counts["llm"] += 1
                    if classification.get("is_role"):
                        counts["IsCapability"] += 1
                    if classification.get("is_privileged"):
                        counts["IsPrivileged"] += 1

            debug(
                f"Pass 2: External types - {external_counts['fast_path']} fast-path, "
                f"{external_counts['llm']} LLM-classified"
            )

        # Log summary
        if any(counts.values()):
            debug(
                f"Pass 2: Classified {counts['IsCapability']} roles, {counts['IsPrivileged']} privileged, "
                f"{counts['IsUserAsset']} user assets, {counts['IsConfig']} configs, "
                f"{counts['IsStateContainer']} state containers, "
                f"{counts['config_fields']} config fields, {counts['privileged_fields']} priv fields, "
                f"{counts['lock_fields']} lock fields, {counts['state_fields']} state fields"
            )

    def _collect_classification_candidates(self, ctx: ProjectContext) -> List[Tuple[str, str]]:
        """
        Collect structs that need LLM classification.

        Returns: List of (struct_name, file_path) tuples for structs with key ability
                 that aren't already classified structurally.
        """
        # Collect already-classified structs (FQNs only to avoid cross-module collision)
        classified_fqns: Set[str] = set()
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name in ("IsEvent", "IsPrivileged", "NotPrivileged"):
                    classified_fqns.add(fact.args[0])

        # Collect candidates: structs with HasKeyAbility not in classified
        candidates: List[Tuple[str, str]] = []
        for file_path, file_ctx in ctx.source_files.items():
            for fact in file_ctx.facts:
                if fact.name == "HasKeyAbility":
                    struct_name = fact.args[0]

                    # Skip stdlib types (use FQN prefix to avoid false positives)
                    if is_stdlib_type(struct_name):
                        continue

                    # Skip already classified (exact FQN match only)
                    if struct_name in classified_fqns:
                        continue

                    candidates.append((struct_name, file_path))

        # Sort for deterministic prompt generation (cache key stability)
        return sorted(candidates, key=lambda x: x[0])

    def _collect_field_accesses(self, ctx: ProjectContext) -> Dict[str, List[Tuple[str, str, str, int]]]:
        """
        Collect field accesses grouped by struct.

        Returns: Dict mapping struct_name to list of (func_name, field_path, snippet, line_num)
        """
        result: Dict[str, List[Tuple[str, str, str, int]]] = {}

        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "FieldAccess":
                    func_name, struct_type, field_path, snippet, line_num = fact.args
                    if struct_type not in result:
                        result[struct_type] = []
                    result[struct_type].append((func_name, field_path, snippet, line_num))

        return result

    def _collect_struct_fields(self, ctx: ProjectContext) -> Dict[str, Set[str]]:
        """
        Collect field names for each struct (for validation).

        Returns: Dict mapping struct_name to set of field names
        """
        result: Dict[str, Set[str]] = {}

        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "StructField":
                    struct_name = fact.args[0]
                    field_name = fact.args[2]
                    if struct_name not in result:
                        result[struct_name] = set()
                    result[struct_name].add(field_name)

        return result

    def _get_struct_comment(self, file_ctx: SourceFileContext, struct_name: str) -> Optional[str]:
        """Get struct comment from facts if available."""
        for fact in file_ctx.facts:
            if fact.name == "StructComment" and fact.args[0] == struct_name:
                return fact.args[1]
        return None

    def _build_unified_function_context(
        self,
        ctx: ProjectContext,
        struct_name: str,
        field_accesses: List[Tuple[str, str, str, int]],
        func_index: "FunctionIndex",
    ) -> str:
        """
        Build unified function context for classification prompt.

        Includes:
        - Functions with struct as owned param
        - Functions that access struct fields
        - Public/entry/friend functions with struct as ANY param (even without field access)
        - AC flags (checks sender, init) via FunctionIndex
        - Field access snippets

        Uses early termination: stops once MAX_FUNCTIONS_IN_PROMPT reached.
        """
        simple_name = get_simple_name(struct_name)

        # Collect functions from owned params
        funcs_with_owned_param: Set[str] = set()
        # Collect functions from any params (for public/entry/friend visibility check)
        funcs_with_any_param: Set[str] = set()
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "FormalArg":
                    func_name, _, _, param_type = fact.args
                    base_type = self._extract_base_type(param_type)
                    if base_type == simple_name:
                        funcs_with_any_param.add(func_name)
                        if not param_type.startswith("&"):
                            funcs_with_owned_param.add(func_name)

        # Collect functions from field accesses
        func_field_accesses: Dict[str, List[Tuple[str, str, int]]] = {}
        for func_name, field_path, snippet, line_num in field_accesses:
            if func_name not in func_field_accesses:
                func_field_accesses[func_name] = []
            func_field_accesses[func_name].append((field_path, snippet, line_num))

        # Combine all functions:
        # - Functions with owned params
        # - Functions with field accesses
        # - Public/entry/friend functions with any param (even without field access)
        all_funcs = funcs_with_owned_param | set(func_field_accesses.keys())

        # Add public/entry/friend functions that have struct as ANY param
        for func_name in funcs_with_any_param:
            priority = func_index.get(func_name).visibility_priority
            # Include if not private (priority 0-4: init/public entry/entry/public/friend)
            if priority < 5:
                all_funcs.add(func_name)

        if not all_funcs:
            return "(No functions use this struct)"

        # Build priority buckets for early termination
        # Priority: 0=init, 1=public entry, 2=entry, 3=public, 4=friend, 5=private
        buckets: List[List[str]] = [[] for _ in range(6)]

        for func_name in all_funcs:
            priority, _ = func_index.get_sort_key(func_name)
            buckets[priority].append(func_name)

        # Sort within each bucket by name for deterministic output
        for bucket in buckets:
            bucket.sort()

        # Build output with early termination by priority bucket
        lines: List[str] = []
        included_count = 0

        for priority, bucket in enumerate(buckets):
            if included_count >= MAX_FUNCTIONS_IN_PROMPT:
                break

            for func_name in bucket:
                if included_count >= MAX_FUNCTIONS_IN_PROMPT:
                    break

                # Skip private functions (priority 5) without field accesses
                # Public/entry/friend functions are included even without field accesses
                if priority == 5 and func_name not in func_field_accesses:
                    continue

                # Find function signature
                sig = None
                for file_ctx in ctx.source_files.values():
                    if file_ctx.source_code is None:
                        continue
                    sig = extract_function_signature(file_ctx.source_code, func_name, file_ctx.root)
                    if sig:
                        break

                if not sig:
                    continue

                # Get AC flags from index
                ac_flags = func_index.get_ac_flags(func_name)
                flags_str = " ".join(f"[{f}]" for f in ac_flags)

                # Format signature (compact)
                sig_lines = sig.strip().split("\n")
                compact_sig = " ".join("\n" + line.strip() if " fun " in line else line.strip() for line in sig_lines)

                # Build function entry
                header = f"{compact_sig} " + "{"
                if flags_str:
                    header += f" {flags_str}"
                lines.append(header)

                # Add field accesses or "doesn't access fields"
                if func_name in func_field_accesses:
                    lines.append("  // ...")
                    for field_path, snippet, line_num in func_field_accesses[func_name]:
                        lines.append(f"  {snippet}")
                    lines.append("  // ...\n" + "}")
                else:
                    lines.append(f"  // {simple_name}: no field access\n" + "}")

                lines.append("")
                included_count += 1

        return "\n".join(lines) if lines else "(No functions use this struct)"

    def _build_creation_sites_section(
        self,
        ctx: ProjectContext,
        creation_sites: List[CreationSite],
        func_index: "FunctionIndex",
        struct_name: Optional[str] = None,
    ) -> str:
        """Build creation sites section for prompt with full function source.

        If struct_name is provided, filters out creation sites where the function
        doesn't actually pack the target struct.
        """
        if not creation_sites:
            return ""

        # Filter creation sites to only include those that actually create the target struct
        relevant_sites = []
        for site in creation_sites:
            # Find function source to check if it creates the struct
            func_source = None
            for file_ctx in ctx.source_files.values():
                if file_ctx.source_code is None:
                    continue
                func_source = extract_function_source(file_ctx.source_code, site.func_name, file_ctx.root)
                if func_source:
                    break

            if func_source:
                # If struct_name provided, verify function actually creates this struct
                if struct_name is None or _struct_creates_target(func_source, struct_name):
                    relevant_sites.append((site, func_source))

        if not relevant_sites:
            return "## Creation Sites\n\nNo direct creation sites found for this struct.\n"

        lines = ["## Creation Sites"]
        for site, func_source in relevant_sites[:3]:  # Limit to 3 sites (with full source)
            func_simple = get_simple_name(site.func_name)

            # Build header with metadata
            ac_flags = func_index.get_ac_flags(site.func_name)
            flags_str = " ".join(f"[{f}]" for f in ac_flags)

            parts = [f"### `{func_simple}()`"]
            if flags_str:
                parts.append(flags_str)
            if site.called_from_init:
                parts.append(f"← called from `{get_simple_name(site.called_from_init)}`")
            elif site.is_init:
                parts.append("[init]")
            if site.transferred_to == "sender":
                parts.append("→ transferred to sender")
            elif site.transferred_to == "param":
                parts.append("→ transferred to param")
            if site.shared:
                parts.append("→ shared")
            if site.frozen:
                parts.append("→ frozen")
            if not site.transferred_to and not site.shared and not site.frozen:
                parts.append("→ returned")
            lines.append(" ".join(parts))

            # Find function docstring (func_source already fetched during filtering)
            func_docstring = None
            for file_ctx in ctx.source_files.values():
                if file_ctx.source_code is None:
                    continue
                func_docstring = extract_function_docstring(file_ctx.source_code, site.func_name, file_ctx.root)
                if func_docstring:
                    break

            # Truncate long functions while preserving critical transfer/share/freeze calls
            truncated_source = _truncate_preserving_transfers(func_source, max_lines=50)
            if func_docstring:
                lines.append(f"```move\n{func_docstring}\n{truncated_source}\n```")
            else:
                lines.append(f"```move\n{truncated_source}\n```")
            lines.append("")

        return "\n".join(lines)

    def _build_field_setters_section(
        self,
        ctx: ProjectContext,
        struct_name: str,
        struct_fields: Set[str],
    ) -> str:
        """Build field setters section for prompt.

        Shows which fields have setter functions and their access control.
        This helps LLM answer "does field X have an update function?" without guessing.
        """
        if not struct_fields:
            return ""

        # Collect WritesField facts for this struct: field -> list of setter functions
        field_setters: Dict[str, List[str]] = {}
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "WritesField" and fact.args[1] == struct_name:
                    func_name, _, field_path = fact.args
                    # Take only the first segment of field path (e.g., "config.fee" -> "fee")
                    field = field_path.split(".")[-1]
                    if field in struct_fields:
                        if field not in field_setters:
                            field_setters[field] = []
                        if func_name not in field_setters[field]:
                            field_setters[field].append(func_name)

        if not field_setters:
            # Show explicit message so LLM knows fields are immutable by design
            return "## Field Setters\n- No setters found (fields likely immutable after creation)"

        # Collect capability requirements for setter functions
        func_caps: Dict[str, str] = {}
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "FormalArg":
                    func_name, _, param_name, param_type = fact.args
                    # Check if param is a capability (first param, reference type with Cap suffix)
                    if param_name.startswith("_") and "Cap" in param_type:
                        # Extract capability name: &AdminCap -> AdminCap
                        cap_name = param_type.lstrip("&").lstrip("mut ").strip()
                        func_caps[func_name] = cap_name

        lines = ["## Field Setters"]

        # Fields with setters
        for field in sorted(field_setters.keys()):
            setters = field_setters[field]
            setter_strs = []
            for func in setters:
                func_simple = get_simple_name(func)
                if func in func_caps:
                    setter_strs.append(f"`{func_simple}()` [requires {func_caps[func]}]")
                else:
                    setter_strs.append(f"`{func_simple}()`")
            lines.append(f"- `{field}` ← {', '.join(setter_strs)}")

        # Fields without setters
        without_setters = sorted(f for f in struct_fields if f not in field_setters)
        if without_setters:
            lines.append(f"- No setter: {', '.join(f'`{f}`' for f in without_setters)}")

        return "\n".join(lines)

    def _classify_unified_llm(
        self,
        ctx: ProjectContext,
        struct_name: str,
        struct_source: str,
        struct_comment: Optional[str],
        creation_sites: List[CreationSite],
        func_context: str,
        func_index: "FunctionIndex",
        struct_fields: Optional[Set[str]] = None,
    ) -> dict:
        """
        Unified struct + field classification via single LLM call.

        Returns dict with keys:
        - is_role, is_privileged, is_user_asset, is_config, is_state_container (bool)
        - config_fields, privileged_fields, lock_fields, state_fields (list)
        """
        simple_name = get_simple_name(struct_name)

        # Build creation sites section (with filtering for the target struct)
        creation_section = self._build_creation_sites_section(ctx, creation_sites, func_index, struct_name)

        # Build field setters section (shows which fields have setter functions)
        setters_section = ""
        if struct_fields:
            setters_section = self._build_field_setters_section(ctx, struct_name, struct_fields)

        prompt = render_prompt(
            "classify/unified_struct.j2",
            simple_name=simple_name,
            struct_source=struct_source,
            struct_comment=struct_comment,
            creation_section=creation_section,
            setters_section=setters_section,
            func_context=func_context,
        )

        response = call_llm_json(
            prompt,
            {
                "is_role": bool,
                "is_privileged": bool,
                "is_user_asset": bool,
                "is_config": bool,
                "is_state_container": bool,
                "config_fields": list,
                "mutable_config_fields": list,
                "state_fields": list,
                "privileged_fields": list,
                "lock_fields": list,
                "protocol_invariant_fields": list,
            },
            context="UnifiedClassify",
        )

        if "error" in response:
            debug(f"  LLM error for {struct_name}: {response['error']}")
            return {
                "is_role": False,
                "is_privileged": False,
                "is_user_asset": False,
                "is_config": False,
                "is_state_container": False,
                "config_fields": [],
                "mutable_config_fields": [],
                "state_fields": [],
                "privileged_fields": [],
                "lock_fields": [],
                "protocol_invariant_fields": [],
            }

        return {
            "is_role": response.get("is_role", False),
            "is_privileged": response.get("is_privileged", False),
            "is_user_asset": response.get("is_user_asset", False),
            "is_config": response.get("is_config", False),
            "is_state_container": response.get("is_state_container", False),
            "config_fields": response.get("config_fields", []),
            "mutable_config_fields": response.get("mutable_config_fields", []),
            "state_fields": response.get("state_fields", []),
            "privileged_fields": response.get("privileged_fields", []),
            "lock_fields": response.get("lock_fields", []),
            "protocol_invariant_fields": response.get("protocol_invariant_fields", []),
        }

    def _emit_struct_facts(
        self,
        ctx: ProjectContext,
        file_ctx: SourceFileContext,
        struct_name: str,
        classification: dict,
        new_facts: List[Fact],
        counts: dict,
    ) -> None:
        """Emit struct classification facts based on LLM response."""
        if classification.get("is_role"):
            already_has = any(f.name == "IsCapability" and f.args[0] == struct_name for f in file_ctx.facts)
            if not already_has:
                fact = Fact("IsCapability", (struct_name,))
                file_ctx.facts.append(fact)
                new_facts.append(fact)
                counts["IsCapability"] += 1
                debug(f"  {struct_name} -> IsCapability")

        if classification.get("is_privileged"):
            fact = Fact("IsPrivileged", (struct_name,))
            # Skip if already exists (e.g., from structural detection)
            if fact not in file_ctx.facts:
                file_ctx.facts.append(fact)
                new_facts.append(fact)
                counts["IsPrivileged"] += 1
                debug(f"  {struct_name} -> IsPrivileged")
        else:
            # Only add NotPrivileged if no IsPrivileged exists
            priv_fact = Fact("IsPrivileged", (struct_name,))
            if priv_fact not in file_ctx.facts:
                fact = Fact("NotPrivileged", (struct_name,))
                file_ctx.facts.append(fact)
                new_facts.append(fact)

        if classification.get("is_user_asset"):
            fact = Fact("IsUserAsset", (struct_name, True))
            ctx.semantic_facts.append(fact)
            new_facts.append(fact)
            counts["IsUserAsset"] += 1
            debug(f"  {struct_name} -> IsUserAsset")
        else:
            fact = Fact("IsUserAsset", (struct_name, False))
            ctx.semantic_facts.append(fact)
            new_facts.append(fact)

        if classification.get("is_config"):
            fact = Fact("IsConfig", (struct_name,))
            file_ctx.facts.append(fact)
            new_facts.append(fact)
            counts["IsConfig"] += 1
            debug(f"  {struct_name} -> IsConfig")

        if classification.get("is_state_container"):
            fact = Fact("IsStateContainer", (struct_name,))
            file_ctx.facts.append(fact)
            new_facts.append(fact)
            counts["IsStateContainer"] += 1
            debug(f"  {struct_name} -> IsStateContainer")

    def _parse_field_entry(self, entry) -> tuple:
        """Parse field entry from LLM response. Returns (field_name, confidence)."""
        if isinstance(entry, dict):
            return entry.get("name", ""), entry.get("confidence", 1.0)
        # Backward compat: plain string
        return entry, 1.0

    def _emit_field_facts(
        self,
        file_ctx: SourceFileContext,
        struct_name: str,
        classification: dict,
        valid_fields: Set[str],
        new_facts: List[Fact],
        counts: dict,
    ) -> None:
        """Emit field classification facts based on LLM response, with validation."""
        for entry in classification.get("config_fields", []):
            field_name, confidence = self._parse_field_entry(entry)
            if field_name not in valid_fields:
                debug(f"  Skipping invalid config field: {struct_name}.{field_name}")
                continue
            fact = Fact("FieldClassification", (struct_name, field_name, "config_value", False, confidence, ""))
            file_ctx.facts.append(fact)
            new_facts.append(fact)
            counts["config_fields"] += 1
            debug(f"  {struct_name}.{field_name} -> FieldClassification(config_value) (conf={confidence:.2f})")

        for entry in classification.get("mutable_config_fields", []):
            field_name, confidence = self._parse_field_entry(entry)
            if field_name not in valid_fields:
                debug(f"  Skipping invalid mutable config field: {struct_name}.{field_name}")
                continue
            # Emit both mutable_config and config_value classifications
            fact1 = Fact("FieldClassification", (struct_name, field_name, "mutable_config", False, confidence, ""))
            fact2 = Fact("FieldClassification", (struct_name, field_name, "config_value", False, confidence, ""))
            file_ctx.facts.append(fact1)
            file_ctx.facts.append(fact2)
            new_facts.append(fact1)
            new_facts.append(fact2)
            counts["config_fields"] += 1
            if "mutable_config_fields" not in counts:
                counts["mutable_config_fields"] = 0
            counts["mutable_config_fields"] += 1
            debug(
                f"  {struct_name}.{field_name} -> FieldClassification(mutable_config + config_value) (conf={confidence:.2f})"
            )

        for entry in classification.get("state_fields", []):
            field_name, confidence = self._parse_field_entry(entry)
            if field_name not in valid_fields:
                debug(f"  Skipping invalid state field: {struct_name}.{field_name}")
                continue
            fact = Fact("FieldClassification", (struct_name, field_name, "state", False, confidence, ""))
            file_ctx.facts.append(fact)
            new_facts.append(fact)
            counts["state_fields"] += 1
            debug(f"  {struct_name}.{field_name} -> FieldClassification(state) (conf={confidence:.2f})")

        for entry in classification.get("privileged_fields", []):
            field_name, confidence = self._parse_field_entry(entry)
            if field_name not in valid_fields:
                debug(f"  Skipping invalid privileged field: {struct_name}.{field_name}")
                continue
            fact = Fact("FieldClassification", (struct_name, field_name, "privileged_address", False, confidence, ""))
            file_ctx.facts.append(fact)
            new_facts.append(fact)
            counts["privileged_fields"] += 1
            debug(f"  {struct_name}.{field_name} -> FieldClassification(privileged_address) (conf={confidence:.2f})")

        for entry in classification.get("lock_fields", []):
            field_name, confidence = self._parse_field_entry(entry)
            if field_name not in valid_fields:
                debug(f"  Skipping invalid lock field: {struct_name}.{field_name}")
                continue
            fact = Fact("FieldClassification", (struct_name, field_name, "lock", False, confidence, ""))
            file_ctx.facts.append(fact)
            new_facts.append(fact)
            counts["lock_fields"] += 1
            debug(f"  {struct_name}.{field_name} -> FieldClassification(lock) (conf={confidence:.2f})")

        for entry in classification.get("protocol_invariant_fields", []):
            field_name, confidence = self._parse_field_entry(entry)
            if field_name not in valid_fields:
                debug(f"  Skipping invalid protocol invariant field: {struct_name}.{field_name}")
                continue
            fact = Fact("FieldClassification", (struct_name, field_name, "protocol_invariant", False, confidence, ""))
            file_ctx.facts.append(fact)
            new_facts.append(fact)
            if "protocol_invariant_fields" not in counts:
                counts["protocol_invariant_fields"] = 0
            counts["protocol_invariant_fields"] += 1
            debug(f"  {struct_name}.{field_name} -> FieldClassification(protocol_invariant) (conf={confidence:.2f})")

    def _extract_base_type(self, param_type: str) -> str:
        """Extract base type name from param type (strip generics, vector, etc.)."""
        # Strip reference prefix (&, &mut)
        if param_type.startswith("&mut "):
            param_type = param_type[5:]
        elif param_type.startswith("&"):
            param_type = param_type[1:]

        # Strip vector<...>
        if param_type.startswith("vector<") and param_type.endswith(">"):
            param_type = param_type[7:-1]

        # Strip Option<...>
        if param_type.startswith("Option<") and param_type.endswith(">"):
            param_type = param_type[7:-1]

        # Strip generics: Type<T> -> Type
        if "<" in param_type:
            param_type = param_type[: param_type.index("<")]

        # Get simple name
        if "::" in param_type:
            param_type = get_simple_name(param_type)

        return param_type.strip()

    def _is_obvious_role(
        self,
        struct_name: str,
        ctx: ProjectContext,
        creation_sites: Dict[str, List[CreationSite]],
        field_accesses: Dict[str, List],
    ) -> bool:
        """
        Fast-path: detect obvious role without LLM query.

        Criteria (ALL must be true):
        1. Created ONCE in init() and transferred to sender (not shared, not to param)
        2. Exactly one field of type UID
        3. No field accesses in any function
        """
        # 1. Created exactly once in init, transferred to sender
        sites = creation_sites.get(struct_name, [])
        if len(sites) != 1:
            return False
        site = sites[0]
        if not site.is_init or site.transferred_to != "sender":
            return False
        if site.shared or site.frozen:
            return False

        # 2. Single UID field
        fields = []
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "StructField" and fact.args[0] == struct_name:
                    fields.append(fact.args[3])
        if len(fields) != 1 or fields[0] not in ("UID", "sui::object::UID"):
            return False

        # 3. No field accesses
        if struct_name in field_accesses and field_accesses[struct_name]:
            return False

        return True

    # -------------------------------------------------------------------------
    # External Type Classification
    # -------------------------------------------------------------------------

    def _strip_type_modifiers(self, type_str: str) -> str:
        """Strip reference prefixes and generics from type string."""
        result = type_str
        if result.startswith("&mut "):
            result = result[5:]
        elif result.startswith("&"):
            result = result[1:]
        if "<" in result:
            result = result[: result.index("<")]
        return result.strip()

    def _is_external_type(self, type_fqn: str, ctx: ProjectContext) -> bool:
        """Check if type is external (not defined in this project, not stdlib)."""
        if "::" not in type_fqn:
            return False

        clean_type = self._strip_type_modifiers(type_fqn)

        if is_stdlib_type(clean_type):
            return False

        parts = clean_type.split("::")
        if len(parts) < 2:
            return False
        type_module = "::".join(parts[:-1])

        # Collect project info
        project_modules = {file_ctx.module_path for file_ctx in ctx.source_files.values() if file_ctx.module_path}
        project_module_simple_names = {m.split("::")[-1] for m in project_modules if m}

        # Collect all struct FQNs defined in project
        project_types: Set[str] = set()
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "Struct":
                    project_types.add(fact.args[0])

        # If type_module is a full project module path, not external
        if type_module in project_modules:
            return False

        # For short-form types like `object::ID`, check if TYPE exists in project
        if len(parts) == 2 and parts[0] in project_module_simple_names:
            # Check if any project module with this simple name defines this type
            type_exists_in_project = False
            for pm in project_modules:
                if pm.endswith(f"::{parts[0]}"):
                    potential_fqn = f"{pm}::{parts[1]}"
                    if potential_fqn in project_types:
                        type_exists_in_project = True
                        break
            if type_exists_in_project:
                return False  # Type actually exists in project module

        # Fallback: check stdlib module names for unresolved imports
        if len(parts) == 2 and is_stdlib_module(parts[0]):
            return False

        return type_module not in project_modules

    def _collect_external_type_candidates(self, ctx: ProjectContext) -> List[str]:
        """Collect external types that need classification."""
        classified_fqns: Set[str] = set()
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name in ("IsCapability", "IsPrivileged", "NotPrivileged"):
                    classified_fqns.add(fact.args[0])

        # Build global import map from all files. This allows resolving types
        # even when the current file doesn't have an explicit import but another
        # file does (e.g., `object::ID` resolves via any file importing sui::object).
        global_import_map: Dict[str, str] = {}
        for file_ctx in ctx.source_files.values():
            for alias, fqn in file_ctx.import_map.items():
                # Only add if it resolves to stdlib (avoid project-specific aliases)
                if is_stdlib_type(fqn):
                    if alias not in global_import_map:
                        global_import_map[alias] = fqn
                    # Also extract module alias from type FQN
                    # e.g., 'ID': 'sui::object::ID' -> 'object': 'sui::object'
                    parts = fqn.split("::")
                    if len(parts) >= 3:  # e.g., sui::object::ID
                        module_alias = parts[-2]  # 'object'
                        module_fqn = "::".join(parts[:-1])  # 'sui::object'
                        if module_alias not in global_import_map:
                            global_import_map[module_alias] = module_fqn

        external_types: Set[str] = set()

        for file_ctx in ctx.source_files.values():
            # Merge file-specific imports with global stdlib imports
            import_map = {**global_import_map, **file_ctx.import_map}

            for fact in file_ctx.facts:
                type_to_check = None

                if fact.name == "FormalArg":
                    type_to_check = fact.args[3]
                elif fact.name == "StructField":
                    type_to_check = fact.args[3]
                elif fact.name == "FunReturnType":
                    type_to_check = fact.args[1]

                if type_to_check:
                    # Extract all types (tuples, generics, nested)
                    for individual_type in extract_all_types(type_to_check):
                        # Resolve import aliases to FQN
                        resolved_type = _replace_import_alias(individual_type, import_map)
                        if self._is_external_type(resolved_type, ctx):
                            clean_type = self._strip_type_modifiers(resolved_type)
                            if clean_type not in classified_fqns:
                                external_types.add(clean_type)

        return sorted(external_types)

    def _build_external_type_context(self, type_fqn: str, ctx: ProjectContext) -> dict:
        """Build usage-based context for external type classification."""
        functions_using = []
        stored_in = []
        getters = []

        privileged_types: Set[str] = set()
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "IsPrivileged":
                    privileged_types.add(fact.args[0])

        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "FormalArg":
                    param_type = fact.args[3]
                    clean_param = self._strip_type_modifiers(param_type)

                    if clean_param == type_fqn:
                        func_name = fact.args[0]
                        param_pos = fact.args[1]
                        functions_using.append(
                            {
                                "name": func_name,
                                "param_position": param_pos,
                                "visibility": self._get_func_visibility(func_name, ctx),
                                "checks_other_cap": self._func_checks_other_capability(func_name, type_fqn, ctx),
                            }
                        )

                elif fact.name == "StructField":
                    field_type = fact.args[3]
                    clean_field = self._strip_type_modifiers(field_type)
                    if clean_field == type_fqn:
                        struct_name = fact.args[0]
                        field_name = fact.args[2]
                        co_located = self._get_co_located_privileged(struct_name, privileged_types, ctx)
                        stored_in.append(
                            {
                                "struct": struct_name,
                                "field": field_name,
                                "co_located_caps": co_located,
                            }
                        )

                elif fact.name == "FunReturnType":
                    return_type = fact.args[1]
                    clean_return = self._strip_type_modifiers(return_type)
                    if clean_return == type_fqn:
                        func_name = fact.args[0]
                        getters.append(
                            {
                                "name": func_name,
                                "visibility": self._get_func_visibility(func_name, ctx),
                                "returns_ref": return_type.startswith("&"),
                            }
                        )

        return {
            "type_fqn": type_fqn,
            "functions_using": functions_using,
            "stored_in": stored_in,
            "getters": getters,
        }

    def _get_func_visibility(self, func_name: str, ctx: ProjectContext) -> str:
        """Get function visibility."""
        is_public = False
        is_entry = False
        is_friend = False

        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.args[0] == func_name:
                    if fact.name == "IsPublic":
                        is_public = True
                    elif fact.name == "IsEntry":
                        is_entry = True
                    elif fact.name == "IsFriend":
                        is_friend = True

        if is_friend:
            return "public(package)"
        if is_entry:
            return "entry"
        if is_public:
            return "public"
        return "private"

    def _func_checks_other_capability(self, func_name: str, exclude_type: str, ctx: ProjectContext) -> bool:
        """Check if function checks a capability other than exclude_type."""
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "ChecksCapability" and fact.args[1] == func_name:
                    cap_type = fact.args[0]
                    clean_cap = self._strip_type_modifiers(cap_type)
                    if clean_cap != exclude_type:
                        return True
        return False

    def _get_co_located_privileged(
        self, struct_name: str, privileged_types: Set[str], ctx: ProjectContext
    ) -> List[str]:
        """Get privileged types stored in the same struct."""
        co_located = []
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "StructField" and fact.args[0] == struct_name:
                    field_type = fact.args[3]
                    clean_field = self._strip_type_modifiers(field_type)
                    for priv_type in privileged_types:
                        if clean_field == priv_type:
                            co_located.append(get_simple_name(priv_type))
        return co_located

    def _is_obvious_external_role(self, usage_ctx: dict) -> bool:
        """Fast-path: detect obvious external roles without LLM."""
        # Signal 1: Co-located with known privileged types
        for struct_info in usage_ctx["stored_in"]:
            if struct_info["co_located_caps"]:
                return True

        # Signal 2: Has restricted getter
        for getter in usage_ctx["getters"]:
            if getter["visibility"] in ("public(package)", "public(friend)"):
                return True

        return False

    def _classify_external_type_llm(self, type_fqn: str, usage_ctx: dict) -> dict:
        """Classify external type via LLM using usage context."""
        simple_name = get_simple_name(type_fqn)

        prompt = render_prompt(
            "classify/external_struct.j2",
            type_fqn=type_fqn,
            simple_name=simple_name,
            stored_in=usage_ctx["stored_in"],
            functions_using=usage_ctx["functions_using"],
            getters=usage_ctx["getters"],
        )

        response = call_llm_json(
            prompt,
            {"is_role": bool, "is_privileged": bool},
            context="ExternalTypeClassify",
        )

        if "error" in response:
            debug(f"  LLM error for external {type_fqn}: {response['error']}")
            return {"is_role": False, "is_privileged": False}

        return {
            "is_role": response.get("is_role", False),
            "is_privileged": response.get("is_privileged", False),
        }

    def _emit_external_role_facts(self, type_fqn: str, ctx: ProjectContext, is_role: bool, is_privileged: bool) -> None:
        """Emit facts for external type classification."""
        # Find a file to attach the facts to (first file that uses this type)
        target_file = None
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "StructField" and self._strip_type_modifiers(fact.args[3]) == type_fqn:
                    target_file = file_ctx
                    break
            if target_file:
                break

        if not target_file:
            for file_ctx in ctx.source_files.values():
                target_file = file_ctx
                break

        if not target_file:
            return

        # Emit IsExternal
        external_fact = Fact("IsExternal", (type_fqn,))
        if external_fact not in target_file.facts:
            target_file.facts.append(external_fact)
            debug(f"  {type_fqn} -> IsExternal")

        if is_role:
            role_fact = Fact("IsCapability", (type_fqn,))
            if role_fact not in target_file.facts:
                target_file.facts.append(role_fact)
                debug(f"  {type_fqn} -> IsCapability (external)")

        if is_privileged:
            priv_fact = Fact("IsPrivileged", (type_fqn,))
            if priv_fact not in target_file.facts:
                target_file.facts.append(priv_fact)
                debug(f"  {type_fqn} -> IsPrivileged (external)")
