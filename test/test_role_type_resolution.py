"""Tests for module-aware role type resolution in ChecksCapability generation.

Ensures that same-named types in different modules are not confused.
E.g., module_a::ManagerCap vs module_b::ManagerCap should be distinct.
"""

from core.context import ProjectContext
from core.facts import Fact
from analysis.access_control import generate_checks_role_facts, _resolve_type_to_fqn


class TestResolveTypeToFqn:
    """Unit tests for _resolve_type_to_fqn helper."""

    def test_already_qualified_unchanged(self):
        """Fully qualified types pass through unchanged."""
        result = _resolve_type_to_fqn(
            "module_a::ManagerCap",
            import_map={},
            module_path="module_b",
            local_structs=set(),
        )
        assert result == "module_a::ManagerCap"

    def test_import_alias_resolved(self):
        """Types in import_map are resolved to full path."""
        result = _resolve_type_to_fqn(
            "ManagerCap",
            import_map={"ManagerCap": "typus_nft::typus_nft::ManagerCap"},
            module_path="typus_nft::discount_mint",
            local_structs=set(),
        )
        assert result == "typus_nft::typus_nft::ManagerCap"

    def test_local_struct_qualified(self):
        """Local struct types are qualified with module_path."""
        result = _resolve_type_to_fqn(
            "ManagerCap",
            import_map={},
            module_path="typus_nft::staking",
            local_structs={"typus_nft::staking::ManagerCap"},
        )
        assert result == "typus_nft::staking::ManagerCap"

    def test_import_takes_precedence_over_local(self):
        """Import alias takes precedence over local struct matching."""
        result = _resolve_type_to_fqn(
            "ManagerCap",
            import_map={"ManagerCap": "external::module::ManagerCap"},
            module_path="my::module",
            local_structs={"my::module::ManagerCap"},
        )
        assert result == "external::module::ManagerCap"

    def test_ref_modifiers_stripped(self):
        """Reference modifiers are stripped before resolution."""
        result = _resolve_type_to_fqn(
            "&ManagerCap",
            import_map={"ManagerCap": "typus_nft::typus_nft::ManagerCap"},
            module_path="typus_nft::discount_mint",
            local_structs=set(),
        )
        assert result == "typus_nft::typus_nft::ManagerCap"

    def test_mut_ref_modifiers_stripped(self):
        """Mutable reference modifiers are stripped before resolution."""
        result = _resolve_type_to_fqn(
            "&mut ManagerCap",
            import_map={"ManagerCap": "typus_nft::typus_nft::ManagerCap"},
            module_path="typus_nft::discount_mint",
            local_structs=set(),
        )
        assert result == "typus_nft::typus_nft::ManagerCap"

    def test_partially_qualified_with_alias(self):
        """Partially qualified types with import alias prefix are resolved."""
        result = _resolve_type_to_fqn(
            "typus_nft::ManagerCap",
            import_map={"typus_nft": "typus_nft::typus_nft"},
            module_path="other::module",
            local_structs=set(),
        )
        assert result == "typus_nft::typus_nft::ManagerCap"

    def test_unresolved_returns_as_is(self):
        """Unresolved types are returned as-is."""
        result = _resolve_type_to_fqn(
            "UnknownType",
            import_map={},
            module_path="my::module",
            local_structs=set(),
        )
        assert result == "UnknownType"


class TestChecksCapabilityTypeResolution:
    """Integration tests for generate_checks_role_facts with type resolution."""

    def _make_ctx_with_files(self, file_specs: dict) -> ProjectContext:
        """
        Create ProjectContext with multiple files.

        file_specs: {
            "path.move": {
                "facts": [...],
                "import_map": {...},
                "module_path": "...",
            }
        }
        """
        ctx = ProjectContext(list(file_specs.keys()))
        for file_path, spec in file_specs.items():
            ctx.source_files[file_path].facts = spec.get("facts", [])
            ctx.source_files[file_path].import_map = spec.get("import_map", {})
            ctx.source_files[file_path].module_path = spec.get("module_path")

        # Build global_facts_index
        for file_path, file_ctx in ctx.source_files.items():
            for fact in file_ctx.facts:
                if fact.name == "Fun":
                    func_name = fact.args[0]
                    if func_name not in ctx.global_facts_index:
                        ctx.global_facts_index[func_name] = {}
                    ctx.global_facts_index[func_name][file_path] = [fact]
                elif fact.name == "FormalArg":
                    func_name = fact.args[0]
                    if func_name in ctx.global_facts_index and file_path in ctx.global_facts_index[func_name]:
                        ctx.global_facts_index[func_name][file_path].append(fact)
        return ctx

    def test_same_name_different_modules_no_confusion(self):
        """
        Two modules define ManagerCap. Each function should only match its own module's role.

        module_a::func_a(&module_a::ManagerCap) -> ChecksCapability(module_a::ManagerCap, func_a)
        module_b::func_b(&module_b::ManagerCap) -> ChecksCapability(module_b::ManagerCap, func_b)

        NOT: ChecksCapability(module_a::ManagerCap, func_b) or vice versa
        """
        ctx = self._make_ctx_with_files({
            "module_a.move": {
                "facts": [
                    Fact("Struct", ("module_a::ManagerCap",)),
                    Fact("IsCapability", ("module_a::ManagerCap",)),
                    Fact("Fun", ("module_a::func_a",)),
                    Fact("FormalArg", ("module_a::func_a", 0, "cap", "ManagerCap")),
                ],
                "import_map": {},
                "module_path": "module_a",
            },
            "module_b.move": {
                "facts": [
                    Fact("Struct", ("module_b::ManagerCap",)),
                    Fact("IsCapability", ("module_b::ManagerCap",)),
                    Fact("Fun", ("module_b::func_b",)),
                    Fact("FormalArg", ("module_b::func_b", 0, "cap", "ManagerCap")),
                ],
                "import_map": {},
                "module_path": "module_b",
            },
        })

        generate_checks_role_facts(ctx)

        # Collect all ChecksCapability facts
        checks_role_facts = []
        for file_ctx in ctx.source_files.values():
            checks_role_facts.extend([f for f in file_ctx.facts if f.name == "ChecksCapability"])
        for func_facts in ctx.global_facts_index.values():
            for facts in func_facts.values():
                checks_role_facts.extend([f for f in facts if f.name == "ChecksCapability"])

        # Remove duplicates
        checks_role_facts = list(set((f.args[0], f.args[1]) for f in checks_role_facts))

        # func_a should only have module_a::ManagerCap
        func_a_roles = [role for role, func in checks_role_facts if func == "module_a::func_a"]
        assert func_a_roles == ["module_a::ManagerCap"], f"func_a roles: {func_a_roles}"

        # func_b should only have module_b::ManagerCap
        func_b_roles = [role for role, func in checks_role_facts if func == "module_b::func_b"]
        assert func_b_roles == ["module_b::ManagerCap"], f"func_b roles: {func_b_roles}"

    def test_imported_role_resolved_correctly(self):
        """
        A function imports a role from another module and uses it.

        use module_a::ManagerCap;
        fun func(&ManagerCap) -> ChecksCapability(module_a::ManagerCap, func)
        """
        ctx = self._make_ctx_with_files({
            "module_a.move": {
                "facts": [
                    Fact("Struct", ("module_a::ManagerCap",)),
                    Fact("IsCapability", ("module_a::ManagerCap",)),
                ],
                "import_map": {},
                "module_path": "module_a",
            },
            "module_b.move": {
                "facts": [
                    Fact("Fun", ("module_b::protected_func",)),
                    Fact("FormalArg", ("module_b::protected_func", 0, "cap", "ManagerCap")),
                ],
                # Imports ManagerCap from module_a
                "import_map": {"ManagerCap": "module_a::ManagerCap"},
                "module_path": "module_b",
            },
        })

        generate_checks_role_facts(ctx)

        # Collect ChecksCapability facts for protected_func
        checks_role_facts = []
        for func_facts in ctx.global_facts_index.get("module_b::protected_func", {}).values():
            checks_role_facts.extend([f for f in func_facts if f.name == "ChecksCapability"])

        assert len(checks_role_facts) == 1
        assert checks_role_facts[0].args[0] == "module_a::ManagerCap"
        assert checks_role_facts[0].args[1] == "module_b::protected_func"

    def test_aliased_import_resolved(self):
        """
        A function imports a role with an alias.

        use module_a::ManagerCap as AdminCap;
        fun func(&AdminCap) -> ChecksCapability(module_a::ManagerCap, func)
        """
        ctx = self._make_ctx_with_files({
            "module_a.move": {
                "facts": [
                    Fact("Struct", ("module_a::ManagerCap",)),
                    Fact("IsCapability", ("module_a::ManagerCap",)),
                ],
                "import_map": {},
                "module_path": "module_a",
            },
            "module_b.move": {
                "facts": [
                    Fact("Fun", ("module_b::protected_func",)),
                    Fact("FormalArg", ("module_b::protected_func", 0, "cap", "AdminCap")),
                ],
                # Imports ManagerCap as AdminCap
                "import_map": {"AdminCap": "module_a::ManagerCap"},
                "module_path": "module_b",
            },
        })

        generate_checks_role_facts(ctx)

        checks_role_facts = []
        for func_facts in ctx.global_facts_index.get("module_b::protected_func", {}).values():
            checks_role_facts.extend([f for f in func_facts if f.name == "ChecksCapability"])

        assert len(checks_role_facts) == 1
        assert checks_role_facts[0].args[0] == "module_a::ManagerCap"

    def test_no_match_for_non_role_type(self):
        """
        A type with same name as a role in another module but not imported should NOT match.
        """
        ctx = self._make_ctx_with_files({
            "module_a.move": {
                "facts": [
                    Fact("Struct", ("module_a::ManagerCap",)),
                    Fact("IsCapability", ("module_a::ManagerCap",)),
                ],
                "import_map": {},
                "module_path": "module_a",
            },
            "module_b.move": {
                "facts": [
                    # Has a local struct with same name but NOT a role
                    Fact("Struct", ("module_b::ManagerCap",)),
                    # No IsCapability for module_b::ManagerCap
                    Fact("Fun", ("module_b::func",)),
                    Fact("FormalArg", ("module_b::func", 0, "cap", "ManagerCap")),
                ],
                "import_map": {},  # No import - uses local ManagerCap
                "module_path": "module_b",
            },
        })

        generate_checks_role_facts(ctx)

        checks_role_facts = []
        for func_facts in ctx.global_facts_index.get("module_b::func", {}).values():
            checks_role_facts.extend([f for f in func_facts if f.name == "ChecksCapability"])

        # Should NOT match module_a::ManagerCap because we're using local (unimported) ManagerCap
        assert len(checks_role_facts) == 0, f"Unexpected ChecksCapability: {checks_role_facts}"

    def test_fully_qualified_param_type(self):
        """
        Fully qualified parameter types should match directly when imported.
        Cross-module roles require explicit import for security.
        """
        ctx = self._make_ctx_with_files({
            "module_a.move": {
                "facts": [
                    Fact("Struct", ("module_a::ManagerCap",)),
                    Fact("IsCapability", ("module_a::ManagerCap",)),
                ],
                "import_map": {},
                "module_path": "module_a",
            },
            "module_b.move": {
                "facts": [
                    Fact("Fun", ("module_b::func",)),
                    # Fully qualified type in param
                    Fact("FormalArg", ("module_b::func", 0, "cap", "module_a::ManagerCap")),
                ],
                # Must import the module to use cross-module role
                "import_map": {"module_a": "module_a"},
                "module_path": "module_b",
            },
        })

        generate_checks_role_facts(ctx)

        checks_role_facts = []
        for func_facts in ctx.global_facts_index.get("module_b::func", {}).values():
            checks_role_facts.extend([f for f in func_facts if f.name == "ChecksCapability"])

        assert len(checks_role_facts) == 1
        assert checks_role_facts[0].args[0] == "module_a::ManagerCap"

    def test_cross_module_fqn_without_import_rejected(self):
        """
        Cross-module FQN without import should NOT generate ChecksCapability.
        This prevents FQN collision attacks where wrong-module caps provide false protection.
        """
        ctx = self._make_ctx_with_files({
            "module_a.move": {
                "facts": [
                    Fact("Struct", ("module_a::ManagerCap",)),
                    Fact("IsCapability", ("module_a::ManagerCap",)),
                ],
                "import_map": {},
                "module_path": "module_a",
            },
            "module_b.move": {
                "facts": [
                    Fact("Fun", ("module_b::func",)),
                    # FQN type but NO import - should be rejected
                    Fact("FormalArg", ("module_b::func", 0, "cap", "module_a::ManagerCap")),
                ],
                "import_map": {},  # No import!
                "module_path": "module_b",
            },
        })

        generate_checks_role_facts(ctx)

        checks_role_facts = []
        for func_facts in ctx.global_facts_index.get("module_b::func", {}).values():
            checks_role_facts.extend([f for f in func_facts if f.name == "ChecksCapability"])

        # Should NOT generate ChecksCapability - cross-module FQN without import is rejected
        assert len(checks_role_facts) == 0
