"""Tests for semantic facts builder (Pass 2)."""
from unittest.mock import patch

from core.facts import Fact
from core.context import ProjectContext
from semantic_facts_builder import SemanticFactsBuilder


class TestCollectClassificationCandidates:
    """Test _collect_classification_candidates helper."""

    def _make_ctx(self, facts_by_file: dict) -> ProjectContext:
        """Create ProjectContext with given facts."""
        ctx = ProjectContext(list(facts_by_file.keys()))
        for file_path, facts in facts_by_file.items():
            ctx.source_files[file_path].facts = facts
        return ctx

    def test_finds_candidates_with_key_ability(self):
        """Finds structs with HasKeyAbility fact."""
        ctx = self._make_ctx({
            "receipt.move": [
                Fact("HasKeyAbility", ("mod::Receipt",)),
            ],
        })

        builder = SemanticFactsBuilder()
        candidates = builder._collect_classification_candidates(ctx)

        assert ("mod::Receipt", "receipt.move") in candidates

    def test_role_still_candidate_for_privileged(self):
        """Structs with IsCapability are still candidates for IsPrivileged classification."""
        ctx = self._make_ctx({
            "cap.move": [
                Fact("HasKeyAbility", ("mod::AdminCap",)),
                Fact("IsCapability", ("mod::AdminCap",)),  # Has role, but no privileged classification yet
            ],
        })

        builder = SemanticFactsBuilder()
        candidates = builder._collect_classification_candidates(ctx)

        # Should still be candidate - needs IsPrivileged classification
        assert any(c[0] == "mod::AdminCap" for c in candidates)

    def test_includes_shared_objects(self):
        """Shared objects should be included - they can be config/admin-controlled."""
        ctx = self._make_ctx({
            "pool.move": [
                Fact("HasKeyAbility", ("mod::Pool",)),
                Fact("IsSharedObject", ("mod::Pool",)),
            ],
        })

        builder = SemanticFactsBuilder()
        candidates = builder._collect_classification_candidates(ctx)

        # Shared objects need classification (can be config, admin-controlled, etc.)
        assert any(c[0] == "mod::Pool" for c in candidates)

    def test_skips_events(self):
        """Skips structs marked as IsEvent."""
        ctx = self._make_ctx({
            "events.move": [
                Fact("HasKeyAbility", ("mod::TransferEvent",)),
                Fact("IsEvent", ("mod::TransferEvent",)),
            ],
        })

        builder = SemanticFactsBuilder()
        candidates = builder._collect_classification_candidates(ctx)

        assert not any(c[0] == "mod::TransferEvent" for c in candidates)

    def test_skips_privileged_roles(self):
        """Skips structs already marked as IsPrivileged."""
        ctx = self._make_ctx({
            "cap.move": [
                Fact("HasKeyAbility", ("mod::OwnerCap",)),
                Fact("IsPrivileged", ("mod::OwnerCap",)),
            ],
        })

        builder = SemanticFactsBuilder()
        candidates = builder._collect_classification_candidates(ctx)

        assert not any(c[0] == "mod::OwnerCap" for c in candidates)

    def test_skips_stdlib_types(self):
        """Skips stdlib types like Coin, Balance."""
        ctx = self._make_ctx({
            "coin.move": [
                Fact("HasKeyAbility", ("sui::coin::Coin",)),
            ],
        })

        builder = SemanticFactsBuilder()
        candidates = builder._collect_classification_candidates(ctx)

        # Coin should be skipped as stdlib type
        assert not any("Coin" in c[0] for c in candidates)

    def test_user_defined_stdlib_name_not_skipped(self):
        """User-defined struct with stdlib name (e.g., Coin) should NOT be skipped.

        This tests that FQN-prefix check is used, not simple name matching.
        A user can define their own Coin struct in their module.
        """
        ctx = self._make_ctx({
            "custom_coin.move": [
                Fact("HasKeyAbility", ("myprotocol::custom::Coin",)),  # User's Coin, NOT stdlib
            ],
        })

        builder = SemanticFactsBuilder()
        candidates = builder._collect_classification_candidates(ctx)

        # User's Coin should be a candidate (NOT skipped)
        assert any(c[0] == "myprotocol::custom::Coin" for c in candidates)

    def test_cross_module_same_name_not_skipped(self):
        """Two modules with same-named struct should both be candidates when only one is fully classified."""
        ctx = self._make_ctx({
            "alpha.move": [
                Fact("HasKeyAbility", ("alpha::pool::Pool",)),
                Fact("IsCapability", ("alpha::pool::Pool",)),
                Fact("IsPrivileged", ("alpha::pool::Pool",)),  # Fully classified
            ],
            "beta.move": [
                Fact("HasKeyAbility", ("beta::pool::Pool",)),
                # NOT classified yet - should be candidate
            ],
        })

        builder = SemanticFactsBuilder()
        candidates = builder._collect_classification_candidates(ctx)

        # beta::pool::Pool should be candidate even though alpha::pool::Pool is classified
        assert any(c[0] == "beta::pool::Pool" for c in candidates)
        # alpha::pool::Pool should NOT be candidate (already has IsPrivileged)
        assert not any(c[0] == "alpha::pool::Pool" for c in candidates)


class TestExtractBaseType:
    """Test _extract_base_type helper in SemanticFactsBuilder."""

    def test_strips_vector(self):
        builder = SemanticFactsBuilder()
        assert builder._extract_base_type("vector<Receipt>") == "Receipt"

    def test_strips_option(self):
        builder = SemanticFactsBuilder()
        assert builder._extract_base_type("Option<Receipt>") == "Receipt"

    def test_strips_generics(self):
        builder = SemanticFactsBuilder()
        assert builder._extract_base_type("Pool<SUI>") == "Pool"

    def test_strips_module_path(self):
        builder = SemanticFactsBuilder()
        assert builder._extract_base_type("my_module::inner::Receipt") == "Receipt"

    def test_strips_reference(self):
        builder = SemanticFactsBuilder()
        assert builder._extract_base_type("&Receipt") == "Receipt"

    def test_strips_mutable_reference(self):
        builder = SemanticFactsBuilder()
        assert builder._extract_base_type("&mut Receipt") == "Receipt"

    def test_strips_reference_with_module(self):
        builder = SemanticFactsBuilder()
        assert builder._extract_base_type("&my_module::Receipt") == "Receipt"


class TestBuildUnifiedFunctionContext:
    """Test _build_unified_function_context method."""

    def _make_ctx(self, facts_by_file: dict) -> ProjectContext:
        """Create ProjectContext with given facts and source code."""
        ctx = ProjectContext(list(facts_by_file.keys()))
        for file_path, (facts, source_code) in facts_by_file.items():
            file_ctx = ctx.source_files[file_path]
            file_ctx.facts = facts
            # Always set dummy source_code so extract_function_signature is attempted
            # (We'll mock it in tests)
            file_ctx.source_code = source_code if source_code else "dummy source"
            file_ctx.root = None  # Will be mocked in tests
        return ctx

    def test_includes_public_function_without_field_access(self):
        """Public functions with struct param should be included even without field access."""
        facts = [
            Fact("Fun", ("mod::process_receipt",)),
            Fact("IsPublic", ("mod::process_receipt",)),
            Fact("FormalArg", ("mod::process_receipt", 0, "receipt", "Receipt")),
            # No FieldAccess facts - function doesn't access receipt's fields
        ]

        ctx = self._make_ctx({"test.move": (facts, None)})
        builder = SemanticFactsBuilder()

        # Mock function index
        from analysis.function_index import FunctionIndex
        func_index = FunctionIndex(ctx)

        # Mock extract_function_signature to return a dummy signature
        with patch("semantic_facts_builder.extract_function_signature") as mock_extract:
            mock_extract.return_value = "public fun process_receipt(receipt: Receipt)"

            result = builder._build_unified_function_context(
                ctx, "mod::Receipt", [], func_index
            )

        # Should include the public function even without field access
        assert "process_receipt" in result or "does not access fields" in result

    def test_includes_entry_function_without_field_access(self):
        """Entry functions with struct param should be included even without field access."""
        facts = [
            Fact("Fun", ("mod::redeem",)),
            Fact("IsEntry", ("mod::redeem",)),
            Fact("FormalArg", ("mod::redeem", 0, "receipt", "Receipt")),
            # No FieldAccess facts
        ]

        ctx = self._make_ctx({"test.move": (facts, None)})
        builder = SemanticFactsBuilder()

        from analysis.function_index import FunctionIndex
        func_index = FunctionIndex(ctx)

        with patch("semantic_facts_builder.extract_function_signature") as mock_extract:
            mock_extract.return_value = "entry fun redeem(receipt: Receipt)"

            result = builder._build_unified_function_context(
                ctx, "mod::Receipt", [], func_index
            )

        # Should include the entry function even without field access
        assert result != "(No functions use this struct)"

    def test_includes_public_entry_function_without_field_access(self):
        """Public entry functions with struct param should be included even without field access."""
        facts = [
            Fact("Fun", ("mod::claim",)),
            Fact("IsPublic", ("mod::claim",)),
            Fact("IsEntry", ("mod::claim",)),
            Fact("FormalArg", ("mod::claim", 0, "receipt", "Receipt")),
        ]

        ctx = self._make_ctx({"test.move": (facts, None)})
        builder = SemanticFactsBuilder()

        from analysis.function_index import FunctionIndex
        func_index = FunctionIndex(ctx)

        with patch("semantic_facts_builder.extract_function_signature") as mock_extract:
            mock_extract.return_value = "public entry fun claim(receipt: Receipt)"

            result = builder._build_unified_function_context(
                ctx, "mod::Receipt", [], func_index
            )

        assert result != "(No functions use this struct)"

    def test_excludes_private_function_without_field_access(self):
        """Private functions without field access should still be excluded."""
        facts = [
            Fact("Fun", ("mod::helper",)),
            # No IsPublic/IsEntry - private function
            Fact("FormalArg", ("mod::helper", 0, "receipt", "Receipt")),
        ]

        ctx = self._make_ctx({"test.move": (facts, None)})
        builder = SemanticFactsBuilder()

        from analysis.function_index import FunctionIndex
        func_index = FunctionIndex(ctx)

        result = builder._build_unified_function_context(
            ctx, "mod::Receipt", [], func_index
        )

        # Private function without field access should be excluded
        assert result == "(No functions use this struct)"

    def test_includes_private_function_with_field_access(self):
        """Private functions WITH field access should be included."""
        field_accesses = [
            ("mod::helper", "amount", "let x = receipt.amount;", 10),
        ]
        facts = [
            Fact("Fun", ("mod::helper",)),
            # No IsPublic/IsEntry - private function
            Fact("FormalArg", ("mod::helper", 0, "receipt", "Receipt")),
            Fact("FieldAccess", ("mod::helper", "mod::Receipt", "amount", "let x = receipt.amount;", 10)),
        ]

        ctx = self._make_ctx({"test.move": (facts, None)})
        builder = SemanticFactsBuilder()

        from analysis.function_index import FunctionIndex
        func_index = FunctionIndex(ctx)

        with patch("semantic_facts_builder.extract_function_signature") as mock_extract:
            mock_extract.return_value = "fun helper(receipt: Receipt)"

            result = builder._build_unified_function_context(
                ctx, "mod::Receipt", field_accesses, func_index
            )

        # Private function WITH field access should be included
        assert result != "(No functions use this struct)"

    def test_includes_public_function_with_reference_param(self):
        """Public functions with &Receipt param should be included."""
        facts = [
            Fact("Fun", ("mod::check_receipt",)),
            Fact("IsPublic", ("mod::check_receipt",)),
            Fact("FormalArg", ("mod::check_receipt", 0, "receipt", "&Receipt")),
        ]

        ctx = self._make_ctx({"test.move": (facts, None)})
        builder = SemanticFactsBuilder()

        from analysis.function_index import FunctionIndex
        func_index = FunctionIndex(ctx)

        with patch("semantic_facts_builder.extract_function_signature") as mock_extract:
            mock_extract.return_value = "public fun check_receipt(receipt: &Receipt)"

            result = builder._build_unified_function_context(
                ctx, "mod::Receipt", [], func_index
            )

        # Public function with reference param should be included
        assert result != "(No functions use this struct)"


class TestClassifyStructsIntegration:
    """Integration tests for struct classification."""

    def _make_ctx(self, facts_by_file: dict) -> ProjectContext:
        """Create ProjectContext with given facts."""
        ctx = ProjectContext(list(facts_by_file.keys()))
        for file_path, facts in facts_by_file.items():
            ctx.source_files[file_path].facts = facts
        return ctx

    def test_no_candidates_when_all_classified(self):
        """No candidates when all structs are already fully classified (has IsPrivileged/NotPrivileged)."""
        ctx = self._make_ctx({
            "mod.move": [
                Fact("HasKeyAbility", ("mod::AdminCap",)),
                Fact("IsCapability", ("mod::AdminCap",)),
                Fact("IsPrivileged", ("mod::AdminCap",)),  # Fully classified
            ],
        })
        ctx.project_facts = []

        builder = SemanticFactsBuilder()
        candidates = builder._collect_classification_candidates(ctx)

        assert len(candidates) == 0

    def test_shared_object_not_skipped_from_classification(self):
        """Shared objects should still be candidates for classification.

        IsSharedObject is orthogonal to struct classification - a shared object
        can still be a config struct or admin-controlled. Previously, shared
        objects were incorrectly skipped from LLM classification.
        """
        ctx = self._make_ctx({
            "game.move": [
                Fact("HasKeyAbility", ("game::GameState",)),
                Fact("IsSharedObject", ("game::GameState",)),  # Shared but needs classification
                Fact("StructField", ("game::GameState", 0, "admin", "address")),
            ],
        })
        ctx.project_facts = []

        builder = SemanticFactsBuilder()
        candidates = builder._collect_classification_candidates(ctx)

        # GameState should be a candidate despite being IsSharedObject
        assert len(candidates) == 1
        assert candidates[0][0] == "game::GameState"

    def test_event_skipped_from_classification(self):
        """Events should be skipped from classification - they don't need role/config facts."""
        ctx = self._make_ctx({
            "events.move": [
                Fact("HasKeyAbility", ("events::TransferEvent",)),
                Fact("IsEvent", ("events::TransferEvent",)),
            ],
        })
        ctx.project_facts = []

        builder = SemanticFactsBuilder()
        candidates = builder._collect_classification_candidates(ctx)

        assert len(candidates) == 0


class TestTransfersUserAssetEndToEnd:
    """End-to-end tests for TransfersUserAsset derived fact."""

    def _make_ctx_with_semantic(self, facts_by_file: dict, semantic_facts: list) -> ProjectContext:
        """Create ProjectContext with facts and semantic facts."""
        ctx = ProjectContext(list(facts_by_file.keys()))
        for file_path, facts in facts_by_file.items():
            ctx.source_files[file_path].facts = facts
        ctx.semantic_facts = semantic_facts
        return ctx

    def test_transfers_user_asset_generated(self):
        """TransfersUserAsset is generated when IsUserAsset exists."""
        from analysis.derived_facts import compute_derived_facts

        ctx = self._make_ctx_with_semantic(
            {
                "receipt.move": [
                    Fact("FormalArg", ("redeem", 0, "receipt", "Receipt")),
                    Fact("TaintedAtSink", ("redeem", "receipt", "stmt1", "transfer_value", "")),
                ],
            },
            [Fact("IsUserAsset", ("Receipt", True))],
        )

        compute_derived_facts(ctx)

        facts = ctx.source_files["receipt.move"].facts
        transfers_user_asset = [f for f in facts if f.name == "TransfersUserAsset"]
        assert len(transfers_user_asset) == 1
        assert transfers_user_asset[0].args == ("redeem", "Receipt")

    def test_no_transfers_user_asset_when_not_user_asset(self):
        """No TransfersUserAsset when IsUserAsset is False."""
        from analysis.derived_facts import compute_derived_facts

        ctx = self._make_ctx_with_semantic(
            {
                "treasury.move": [
                    Fact("FormalArg", ("withdraw", 0, "treasury", "Treasury")),
                    Fact("TaintedAtSink", ("withdraw", "treasury", "stmt1", "transfer_value", "")),
                ],
            },
            [Fact("IsUserAsset", ("Treasury", False))],  # NOT user asset
        )

        compute_derived_facts(ctx)

        facts = ctx.source_files["treasury.move"].facts
        transfers_user_asset = [f for f in facts if f.name == "TransfersUserAsset"]
        assert len(transfers_user_asset) == 0


class TestObviousRoleFastPath:
    """Test _is_obvious_role fast-path detection."""

    def _make_ctx_with_struct(self, struct_name: str, fields: list, creation_sites: list) -> ProjectContext:
        """Create ProjectContext with struct and facts."""
        from analysis.patterns import CreationSite

        ctx = ProjectContext(["test.move"])
        file_ctx = ctx.source_files["test.move"]

        # Add struct facts
        file_ctx.facts.append(Fact("HasKeyAbility", (struct_name,)))
        for idx, (field_name, field_type) in enumerate(fields):
            file_ctx.facts.append(Fact("StructField", (struct_name, idx, field_name, field_type)))

        # Convert dicts to CreationSite objects
        creation_site_objs = []
        for site_dict in creation_sites:
            creation_site_objs.append(
                CreationSite(
                    func_name=site_dict["func_name"],
                    is_init=site_dict.get("is_init", False),
                    transferred_to=site_dict.get("transferred_to"),
                    shared=site_dict.get("shared", False),
                    frozen=site_dict.get("frozen", False),
                )
            )

        return ctx, {"test::AdminCap": creation_site_objs}

    def test_obvious_role_skips_llm(self):
        """Created once in init, transferred to sender, single UID, unused -> fast-path."""
        ctx, creation_sites = self._make_ctx_with_struct(
            "test::AdminCap",
            [("id", "UID")],
            [{"func_name": "test::init", "is_init": True, "transferred_to": "sender"}],
        )

        builder = SemanticFactsBuilder()
        field_accesses = {}

        result = builder._is_obvious_role("test::AdminCap", ctx, creation_sites, field_accesses)
        assert result is True

    def test_multiple_creation_sites_requires_llm(self):
        """Created in multiple places -> LLM required."""
        ctx, creation_sites = self._make_ctx_with_struct(
            "test::AdminCap",
            [("id", "UID")],
            [
                {"func_name": "test::init", "is_init": True, "transferred_to": "sender"},
                {"func_name": "test::create", "is_init": False, "transferred_to": "sender"},
            ],
        )

        builder = SemanticFactsBuilder()
        field_accesses = {}

        result = builder._is_obvious_role("test::AdminCap", ctx, creation_sites, field_accesses)
        assert result is False

    def test_not_init_requires_llm(self):
        """Created outside init -> LLM required."""
        ctx, creation_sites = self._make_ctx_with_struct(
            "test::Badge",
            [("id", "UID")],
            [{"func_name": "test::mint_badge", "is_init": False, "transferred_to": "sender"}],
        )

        builder = SemanticFactsBuilder()
        field_accesses = {}

        result = builder._is_obvious_role("test::Badge", ctx, creation_sites, field_accesses)
        assert result is False

    def test_shared_requires_llm(self):
        """Shared struct -> LLM required."""
        ctx, creation_sites = self._make_ctx_with_struct(
            "test::Registry",
            [("id", "UID")],
            [{"func_name": "test::init", "is_init": True, "shared": True}],
        )

        builder = SemanticFactsBuilder()
        field_accesses = {}

        result = builder._is_obvious_role("test::Registry", ctx, creation_sites, field_accesses)
        assert result is False

    def test_transferred_to_param_requires_llm(self):
        """Transferred to param (not sender) -> LLM required."""
        ctx, creation_sites = self._make_ctx_with_struct(
            "test::Ticket",
            [("id", "UID")],
            [{"func_name": "test::init", "is_init": True, "transferred_to": "param"}],
        )

        builder = SemanticFactsBuilder()
        field_accesses = {}

        result = builder._is_obvious_role("test::Ticket", ctx, creation_sites, field_accesses)
        assert result is False

    def test_multiple_fields_requires_llm(self):
        """Multiple fields -> LLM required."""
        ctx, creation_sites = self._make_ctx_with_struct(
            "test::Config",
            [("id", "UID"), ("fee_rate", "u64")],
            [{"func_name": "test::init", "is_init": True, "transferred_to": "sender"}],
        )

        builder = SemanticFactsBuilder()
        field_accesses = {}

        result = builder._is_obvious_role("test::Config", ctx, creation_sites, field_accesses)
        assert result is False

    def test_field_accessed_requires_llm(self):
        """Field accessed -> LLM required."""
        ctx, creation_sites = self._make_ctx_with_struct(
            "test::AdminCap",
            [("id", "UID")],
            [{"func_name": "test::init", "is_init": True, "transferred_to": "sender"}],
        )

        builder = SemanticFactsBuilder()
        field_accesses = {"test::AdminCap": [("test::verify", "id", "cap.id", 42)]}

        result = builder._is_obvious_role("test::AdminCap", ctx, creation_sites, field_accesses)
        assert result is False


class TestBuildCreationSitesSection:
    """Test _build_creation_sites_section includes full function source."""

    def test_includes_function_source(self):
        """Creation site section includes full function source code."""
        from analysis.patterns import CreationSite
        from move.parse import parse_move_source

        source_code = """
module test::rewards {
    /// Creates a new rewards pool with exchange rate
    public fun new(rate_num: u64, rate_denom: u64): RewardsPool {
        RewardsPool {
            exchange_rate_numerator: rate_num,
            exchange_rate_denominator: rate_denom,
        }
    }
}
"""
        root = parse_move_source(source_code)
        ctx = ProjectContext(["test.move"])
        ctx.source_files["test.move"].source_code = source_code
        ctx.source_files["test.move"].root = root

        sites = [
            CreationSite(
                func_name="test::rewards::new",
                is_init=False,
                transferred_to="sender",
                shared=False,
                frozen=False,
                called_from_init=None,
            )
        ]

        # Mock function index
        class MockFuncIndex:
            def get_ac_flags(self, _):
                return []

        builder = SemanticFactsBuilder()
        result = builder._build_creation_sites_section(ctx, sites, MockFuncIndex())

        assert "## Creation Sites" in result
        assert "### `new()`" in result
        assert "public fun new" in result
        assert "rate_num: u64" in result
        assert "exchange_rate_numerator" in result

    def test_shows_init_caller_chain(self):
        """Shows which init function calls the creation site transitively."""
        from analysis.patterns import CreationSite
        from move.parse import parse_move_source

        source_code = """
module test::cap {
    fun create_cap(): AdminCap {
        AdminCap { id: object::new(ctx) }
    }
}
"""
        root = parse_move_source(source_code)
        ctx = ProjectContext(["test.move"])
        ctx.source_files["test.move"].source_code = source_code
        ctx.source_files["test.move"].root = root

        sites = [
            CreationSite(
                func_name="test::cap::create_cap",
                is_init=True,
                transferred_to="sender",
                shared=False,
                frozen=False,
                called_from_init="test::cap::init",
            )
        ]

        class MockFuncIndex:
            def get_ac_flags(self, _):
                return []

        builder = SemanticFactsBuilder()
        result = builder._build_creation_sites_section(ctx, sites, MockFuncIndex())

        assert "← called from `init`" in result

    def test_shows_init_marker_for_direct_init(self):
        """Shows [init] marker when function IS init."""
        from analysis.patterns import CreationSite
        from move.parse import parse_move_source

        source_code = """
module test::cap {
    fun init(ctx: &mut TxContext) {
        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }
}
"""
        root = parse_move_source(source_code)
        ctx = ProjectContext(["test.move"])
        ctx.source_files["test.move"].source_code = source_code
        ctx.source_files["test.move"].root = root

        sites = [
            CreationSite(
                func_name="test::cap::init",
                is_init=True,
                transferred_to="sender",
                shared=False,
                frozen=False,
                called_from_init=None,  # It IS init, not called from init
            )
        ]

        class MockFuncIndex:
            def get_ac_flags(self, _):
                return []

        builder = SemanticFactsBuilder()
        result = builder._build_creation_sites_section(ctx, sites, MockFuncIndex())

        assert "[init]" in result
        assert "← called from" not in result

    def test_truncation_preserves_transfer_calls(self):
        """When function is truncated, critical transfer/share/freeze calls should be preserved.

        This is the core bug: Hard 50-line truncation hides share_object() calls,
        so LLM can't see the actual sharing status.
        """
        from analysis.patterns import CreationSite
        from move.parse import parse_move_source

        # Create a long function (>50 lines) with share_object at the end
        # Lines 1-5: function signature and setup
        # Lines 6-55: filler code (50 lines)
        # Line 56+: share_object call - this gets truncated!
        filler_lines = "\n".join([f"        let x{i} = {i};" for i in range(50)])
        source_code = f"""
module test::long_init {{
    public struct Config has key {{ id: UID, value: u64 }}

    fun init(ctx: &mut TxContext) {{
        let config = Config {{ id: object::new(ctx), value: 0 }};
{filler_lines}
        transfer::share_object(config);
    }}
}}
"""
        root = parse_move_source(source_code)
        ctx = ProjectContext(["test.move"])
        ctx.source_files["test.move"].source_code = source_code
        ctx.source_files["test.move"].root = root

        sites = [
            CreationSite(
                func_name="test::long_init::init",
                is_init=True,
                transferred_to="none",
                shared=True,
                frozen=False,
                called_from_init=None,
            )
        ]

        class MockFuncIndex:
            def get_ac_flags(self, _):
                return []

        builder = SemanticFactsBuilder()
        result = builder._build_creation_sites_section(ctx, sites, MockFuncIndex())

        # The share_object call should be visible even after truncation
        assert "share_object" in result, (
            "BUG: share_object call is hidden by truncation - LLM can't see sharing status"
        )

    def test_truncation_preserves_multiple_transfer_calls(self):
        """Multiple transfer/share/freeze calls should all be preserved."""
        from analysis.patterns import CreationSite
        from move.parse import parse_move_source

        filler_lines = "\n".join([f"        let x{i} = {i};" for i in range(50)])
        source_code = f"""
module test::multi {{
    public struct A has key {{ id: UID }}
    public struct B has key {{ id: UID }}

    fun init(ctx: &mut TxContext) {{
        let a = A {{ id: object::new(ctx) }};
        let b = B {{ id: object::new(ctx) }};
{filler_lines}
        transfer::share_object(a);
        transfer::transfer(b, tx_context::sender(ctx));
    }}
}}
"""
        root = parse_move_source(source_code)
        ctx = ProjectContext(["test.move"])
        ctx.source_files["test.move"].source_code = source_code
        ctx.source_files["test.move"].root = root

        sites = [
            CreationSite(
                func_name="test::multi::init",
                is_init=True,
                transferred_to="sender",
                shared=True,
                frozen=False,
                called_from_init=None,
            )
        ]

        class MockFuncIndex:
            def get_ac_flags(self, _):
                return []

        builder = SemanticFactsBuilder()
        result = builder._build_creation_sites_section(ctx, sites, MockFuncIndex())

        # Both transfer calls should be visible
        assert "share_object" in result, "share_object should be preserved"
        assert "transfer::transfer" in result or "transfer(b" in result, (
            "transfer call should be preserved"
        )

    def test_creation_sites_filters_irrelevant_functions(self):
        """
        When a creation site function doesn't actually pack the target struct,
        it should be filtered out from the creation sites section.

        This is Fix 5: Filter Module init() to Relevant Structs Only.
        """
        from analysis.patterns import CreationSite
        from move.parse import parse_move_source

        # init() creates AdminCap only, not Registry
        source_code = """
module test::multi {
    public struct AdminCap has key { id: UID }
    public struct Registry has key { id: UID }

    fun init(ctx: &mut TxContext) {
        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    fun create_registry(ctx: &mut TxContext) {
        let reg = Registry { id: object::new(ctx) };
        transfer::share_object(reg);
    }
}
"""
        root = parse_move_source(source_code)
        ctx = ProjectContext(["test.move"])
        ctx.source_files["test.move"].source_code = source_code
        ctx.source_files["test.move"].root = root

        # Incorrectly associated creation site - init() doesn't create Registry!
        # This simulates what could happen with buggy creation site collection.
        sites = [
            CreationSite(
                func_name="test::multi::init",  # This function creates AdminCap, not Registry
                is_init=True,
                transferred_to="sender",
                shared=False,
                frozen=False,
                called_from_init=None,
            )
        ]

        class MockFuncIndex:
            def get_ac_flags(self, _):
                return []

        builder = SemanticFactsBuilder()
        # We're building section for Registry, but passing init() which creates AdminCap
        result = builder._build_creation_sites_section(
            ctx, sites, MockFuncIndex(), struct_name="test::multi::Registry"
        )

        # The init() function should NOT be shown because it doesn't create Registry
        # It should say "No direct creation sites" instead
        assert "No direct creation sites" in result, (
            "BUG: init() shown for Registry even though it creates AdminCap, not Registry. "
            f"Got: {result[:200]}"
        )

    def test_creation_sites_keeps_relevant_functions(self):
        """
        When a creation site function actually packs the target struct,
        it should be included in the creation sites section.
        """
        from analysis.patterns import CreationSite
        from move.parse import parse_move_source

        source_code = """
module test::correct {
    public struct Config has key { id: UID }

    fun init(ctx: &mut TxContext) {
        let config = Config { id: object::new(ctx) };
        transfer::share_object(config);
    }
}
"""
        root = parse_move_source(source_code)
        ctx = ProjectContext(["test.move"])
        ctx.source_files["test.move"].source_code = source_code
        ctx.source_files["test.move"].root = root

        sites = [
            CreationSite(
                func_name="test::correct::init",
                is_init=True,
                transferred_to="none",
                shared=True,
                frozen=False,
                called_from_init=None,
            )
        ]

        class MockFuncIndex:
            def get_ac_flags(self, _):
                return []

        builder = SemanticFactsBuilder()
        result = builder._build_creation_sites_section(
            ctx, sites, MockFuncIndex(), struct_name="test::correct::Config"
        )

        # The init() function SHOULD be shown because it creates Config
        assert "init()" in result, "init() should be shown for Config"
        assert "Config {" in result, "Config pack expression should be visible"

    def test_shows_returned_when_no_transfer(self):
        """
        When object is returned (not transferred/shared/frozen), show '→ returned'.

        This clarifies that the caller decides disposition, helping LLM understand
        the flow when helpers create objects for callers like init().
        """
        from analysis.patterns import CreationSite
        from move.parse import parse_move_source

        source_code = """
module test::factory {
    public struct Cap has key { id: UID }

    public fun create_cap(ctx: &mut TxContext): Cap {
        Cap { id: object::new(ctx) }
    }
}
"""
        root = parse_move_source(source_code)
        ctx = ProjectContext(["test.move"])
        ctx.source_files["test.move"].source_code = source_code
        ctx.source_files["test.move"].root = root

        # Creation site with no transfer - object is returned
        sites = [
            CreationSite(
                func_name="test::factory::create_cap",
                is_init=False,
                transferred_to=None,  # Not transferred
                shared=False,         # Not shared
                frozen=False,         # Not frozen
                called_from_init="test::factory::init",  # Called from init
            )
        ]

        class MockFuncIndex:
            def get_ac_flags(self, _):
                return []

        builder = SemanticFactsBuilder()
        result = builder._build_creation_sites_section(ctx, sites, MockFuncIndex())

        # Should show "→ returned" to indicate object is returned to caller
        assert "returned" in result.lower(), (
            "BUG: When object is returned (not transferred/shared/frozen), "
            "should show '→ returned' to clarify disposition. "
            f"Got: {result}"
        )


class TestFieldSettersSection:
    """Test _build_field_setters_section for semantic context.

    LLM often asks "does field X have an update function?" but this info
    exists in WritesField facts. This section shows it explicitly.
    """

    def _make_ctx_with_facts(self, facts_by_file: dict) -> ProjectContext:
        """Create ProjectContext with given facts."""
        ctx = ProjectContext(list(facts_by_file.keys()))
        for file_path, facts in facts_by_file.items():
            ctx.source_files[file_path].facts = facts
        return ctx

    def test_shows_fields_with_setters(self):
        """Fields with WritesField facts should be shown as having setters."""
        ctx = self._make_ctx_with_facts({
            "config.move": [
                Fact("StructField", ("mod::Config", 0, "fee_rate", "u64")),
                Fact("StructField", ("mod::Config", 1, "admin", "address")),
                Fact("StructField", ("mod::Config", 2, "name", "String")),
                # update_fee writes to fee_rate
                Fact("WritesField", ("mod::update_fee", "mod::Config", "fee_rate")),
                # update_admin writes to admin
                Fact("WritesField", ("mod::update_admin", "mod::Config", "admin")),
                # name has no setter (immutable)
            ],
        })

        builder = SemanticFactsBuilder()
        struct_fields = {"fee_rate", "admin", "name"}

        result = builder._build_field_setters_section(ctx, "mod::Config", struct_fields)

        # Should show fields with setters
        assert "fee_rate" in result, "fee_rate should be shown"
        assert "update_fee" in result, "setter function should be shown"
        assert "admin" in result, "admin should be shown"
        assert "update_admin" in result, "setter function should be shown"
        # Should show field without setter
        assert "name" in result, "name should be shown"
        assert "no setter" in result.lower(), "Should indicate name has no setter"

    def test_shows_access_control_requirements(self):
        """Setter functions requiring capability should show access control."""
        ctx = self._make_ctx_with_facts({
            "config.move": [
                Fact("StructField", ("mod::Config", 0, "fee_rate", "u64")),
                # update_fee writes to fee_rate and requires AdminCap
                Fact("WritesField", ("mod::update_fee", "mod::Config", "fee_rate")),
                Fact("FormalArg", ("mod::update_fee", 0, "_cap", "&AdminCap")),
                Fact("FormalArg", ("mod::update_fee", 1, "config", "&mut Config")),
            ],
        })

        builder = SemanticFactsBuilder()
        struct_fields = {"fee_rate"}

        result = builder._build_field_setters_section(ctx, "mod::Config", struct_fields)

        # Should show access control requirement
        assert "AdminCap" in result, "Should show AdminCap requirement"

    def test_empty_when_no_fields(self):
        """Returns empty string when struct has no fields."""
        ctx = self._make_ctx_with_facts({"empty.move": []})

        builder = SemanticFactsBuilder()
        result = builder._build_field_setters_section(ctx, "mod::Empty", set())

        assert result == "", "Should return empty string for struct with no fields"

    def test_shows_no_setters_message_when_fields_but_no_setters(self):
        """
        When struct has fields but no WritesField facts, show explicit message.

        This helps LLM understand the fields are immutable by design,
        rather than wondering if setters exist elsewhere.
        """
        ctx = self._make_ctx_with_facts({
            "config.move": [
                Fact("StructField", ("mod::Config", 0, "name", "String")),
                Fact("StructField", ("mod::Config", 1, "version", "u64")),
                # No WritesField facts - these fields have no setters
            ],
        })

        builder = SemanticFactsBuilder()
        struct_fields = {"name", "version"}

        result = builder._build_field_setters_section(ctx, "mod::Config", struct_fields)

        # Should show explicit message about no setters, not empty string
        assert "no setter" in result.lower(), (
            "BUG: When struct has fields but no setters, should show explicit message. "
            f"Got empty or: {result[:100]}"
        )

    def test_finds_cross_module_setters(self):
        """
        WritesField facts from other modules should be discovered.

        If struct is defined in module A but setter is in module B,
        the Field Setters section should still show the setter.
        """
        ctx = self._make_ctx_with_facts({
            # Module A defines the struct
            "types.move": [
                Fact("StructField", ("pkg::types::Config", 0, "fee_rate", "u64")),
            ],
            # Module B has a setter for it
            "admin.move": [
                Fact("WritesField", ("pkg::admin::update_fee", "pkg::types::Config", "fee_rate")),
            ],
        })

        builder = SemanticFactsBuilder()
        struct_fields = {"fee_rate"}

        result = builder._build_field_setters_section(ctx, "pkg::types::Config", struct_fields)

        # Should find the setter from admin module
        assert "fee_rate" in result, "Should show fee_rate field"
        assert "update_fee" in result, (
            "BUG: Setter from different module not found. "
            f"Got: {result}"
        )


class TestExternalTypeClassification:
    """Test external type candidate collection handles tuple types.

    Move supports tuple return types: `fun foo(): (Type1, Type2)`
    Tuples can appear in FunReturnType and potentially other places.
    """

    def _make_ctx(self, facts_by_file: dict) -> ProjectContext:
        ctx = ProjectContext(list(facts_by_file.keys()))
        for file_path, facts in facts_by_file.items():
            ctx.source_files[file_path].facts = facts
            ctx.source_files[file_path].module_path = "test::module"
        return ctx

    def test_tuple_return_types_not_passed_as_partial(self):
        """Tuple return types should extract individual types, not pass partial tuple."""
        ctx = self._make_ctx({
            "test.move": [
                # Valid Move: fun get_info(): (ascii::String, string::String, option::Option<u64>)
                Fact("FunReturnType", ("test::module::get_info",
                     "(ascii::String, string::String, option::Option<u64>)")),
            ],
        })

        builder = SemanticFactsBuilder()
        candidates = builder._collect_external_type_candidates(ctx)

        # Should NOT contain partial tuple like "(ascii::String..."
        for c in candidates:
            assert not c.startswith("("), f"Malformed tuple type collected: {c}"

    def test_tuple_return_with_external_type_extracts_it(self):
        """External types inside tuple returns should be extracted and collected."""
        ctx = self._make_ctx({
            "test.move": [
                # Valid Move: fun get_pair(): (u64, external::mod::Type)
                Fact("FunReturnType", ("test::module::get_pair",
                     "(u64, external::mod::Type)")),
            ],
        })

        builder = SemanticFactsBuilder()
        candidates = builder._collect_external_type_candidates(ctx)

        # Should extract external::mod::Type
        assert "external::mod::Type" in candidates, (
            f"External type from tuple not extracted. Got: {candidates}"
        )

    def test_nested_generic_in_tuple_extracted(self):
        """Nested generic types within tuples should be handled."""
        ctx = self._make_ctx({
            "test.move": [
                # Valid Move: fun get_items(): (vector<external::mod::Item>, u64)
                Fact("FunReturnType", ("test::module::get_items",
                     "(vector<external::mod::Item>, u64)")),
            ],
        })

        builder = SemanticFactsBuilder()
        candidates = builder._collect_external_type_candidates(ctx)

        # Should extract external::mod::Item (after stripping vector<>)
        assert "external::mod::Item" in candidates, (
            f"Nested external type not extracted. Got: {candidates}"
        )

    def test_generic_param_type_extracted(self):
        """Generic type arguments in function params should be extracted."""
        ctx = self._make_ctx({
            "test.move": [
                # Function param with generic containing external type
                Fact("FormalArg", ("test::module::process", 0, "items",
                     "vector<external::mod::Item>")),
            ],
        })

        builder = SemanticFactsBuilder()
        candidates = builder._collect_external_type_candidates(ctx)

        # Should extract external::mod::Item
        assert "external::mod::Item" in candidates, (
            f"External type from generic param not extracted. Got: {candidates}"
        )

    def test_stdlib_types_resolved_via_import(self):
        """Types like balance::Balance should resolve to sui::balance::Balance via imports."""
        ctx = self._make_ctx({
            "test.move": [
                Fact("StructField", ("test::module::Pool", 0, "balance", "balance::Balance")),
            ],
        })
        # Simulate import: use sui::balance::{Self, Balance}
        ctx.source_files["test.move"].import_map = {
            "balance": "sui::balance",
            "Balance": "sui::balance::Balance",
        }

        builder = SemanticFactsBuilder()
        candidates = builder._collect_external_type_candidates(ctx)

        # balance::Balance should resolve to sui::balance::Balance (stdlib - not external)
        assert "balance::Balance" not in candidates, (
            f"Stdlib type not filtered after import resolution. Got: {candidates}"
        )
        assert len(candidates) == 0, f"Expected no external types, got: {candidates}"

    def test_coin_type_resolved_via_import(self):
        """coin::Coin should resolve to sui::coin::Coin via imports."""
        ctx = self._make_ctx({
            "test.move": [
                Fact("FormalArg", ("test::module::deposit", 0, "payment", "coin::Coin<SUI>")),
            ],
        })
        # Simulate import: use sui::coin::{Self, Coin}
        ctx.source_files["test.move"].import_map = {
            "coin": "sui::coin",
            "Coin": "sui::coin::Coin",
        }

        builder = SemanticFactsBuilder()
        candidates = builder._collect_external_type_candidates(ctx)

        # coin::Coin should resolve to sui::coin::Coin (stdlib - not external)
        assert "coin::Coin" not in candidates, (
            f"Stdlib coin type not filtered. Got: {candidates}"
        )
        assert len(candidates) == 0, f"Expected no external types, got: {candidates}"

    def test_stdlib_resolved_via_global_import_map(self):
        """Types should resolve via imports from OTHER files in the project.

        If file A imports sui::object::{Self, ID} and file B uses object::ID
        without explicit import, B should still resolve it as stdlib.
        """
        ctx = ProjectContext(["file_a.move", "file_b.move"])

        # File A has explicit import
        ctx.source_files["file_a.move"].facts = []
        ctx.source_files["file_a.move"].module_path = "test::a"
        ctx.source_files["file_a.move"].import_map = {
            "object": "sui::object",
            "ID": "sui::object::ID",
        }

        # File B uses object::ID but only imports ID directly (not Self)
        ctx.source_files["file_b.move"].facts = [
            Fact("StructField", ("test::b::Pool", 0, "owner_id", "object::ID")),
        ]
        ctx.source_files["file_b.move"].module_path = "test::b"
        ctx.source_files["file_b.move"].import_map = {
            "ID": "sui::object::ID",  # Only ID imported, not module alias
        }

        builder = SemanticFactsBuilder()
        candidates = builder._collect_external_type_candidates(ctx)

        # object::ID should resolve via global import_map from file A
        assert "object::ID" not in candidates, (
            f"Stdlib type not resolved via global import map. Got: {candidates}"
        )
        assert len(candidates) == 0, f"Expected no external types, got: {candidates}"

    def test_module_alias_derived_from_type_import(self):
        """Module alias should be derived from type imports.

        If all files only import `use sui::object::ID;` (without Self),
        we should still be able to resolve `object::ID` by deriving
        `object` -> `sui::object` from the type import.
        """
        ctx = ProjectContext(["test.move"])

        # File only imports ID, not the module alias
        ctx.source_files["test.move"].facts = [
            Fact("StructField", ("test::Pool", 0, "owner_id", "object::ID")),
        ]
        ctx.source_files["test.move"].module_path = "test"
        ctx.source_files["test.move"].import_map = {
            "ID": "sui::object::ID",  # Only type imported, no Self
        }

        builder = SemanticFactsBuilder()
        candidates = builder._collect_external_type_candidates(ctx)

        # object::ID should resolve because we derive object -> sui::object
        # from the ID -> sui::object::ID mapping
        assert "object::ID" not in candidates, (
            f"Module alias not derived from type import. Got: {candidates}"
        )
        assert len(candidates) == 0, f"Expected no external types, got: {candidates}"

    def test_stdlib_module_fallback_no_imports(self):
        """Stdlib modules should be recognized even with empty import_map.

        If a file uses `object::ID` but has no imports (edge case),
        we should still recognize `object` as a stdlib module.
        """
        ctx = ProjectContext(["test.move"])

        ctx.source_files["test.move"].facts = [
            Fact("StructField", ("test::Pool", 0, "owner_id", "object::ID")),
            Fact("FormalArg", ("test::deposit", 0, "payment", "coin::Coin<SUI>")),
            Fact("StructField", ("test::Pool", 1, "bal", "balance::Balance<SUI>")),
        ]
        ctx.source_files["test.move"].module_path = "test"
        ctx.source_files["test.move"].import_map = {}  # Empty!

        builder = SemanticFactsBuilder()
        candidates = builder._collect_external_type_candidates(ctx)

        # All should be recognized as stdlib via module name fallback
        assert "object::ID" not in candidates, f"object::ID not recognized. Got: {candidates}"
        assert "coin::Coin" not in candidates, f"coin::Coin not recognized. Got: {candidates}"
        assert "balance::Balance" not in candidates, f"balance::Balance not recognized. Got: {candidates}"
        assert len(candidates) == 0, f"Expected no external types, got: {candidates}"

    def test_user_module_shadows_stdlib_when_type_exists(self):
        """User module named 'object' shadows stdlib ONLY if type is defined there.

        If project defines myproject::object::MyType, then object::MyType
        should be recognized as project type, not stdlib.
        """
        ctx = ProjectContext(["myproject/object.move"])

        ctx.source_files["myproject/object.move"].facts = [
            Fact("Struct", ("myproject::object::MyType",)),  # Type is defined
            Fact("StructField", ("myproject::object::Pool", 0, "data", "object::MyType")),
        ]
        ctx.source_files["myproject/object.move"].module_path = "myproject::object"
        ctx.source_files["myproject/object.move"].import_map = {}

        builder = SemanticFactsBuilder()
        candidates = builder._collect_external_type_candidates(ctx)

        # object::MyType exists in project -> not external
        assert "object::MyType" not in candidates, (
            f"Project type incorrectly treated as external. Got: {candidates}"
        )

    def test_stdlib_not_shadowed_by_module_name_only(self):
        """Stdlib type should NOT be shadowed if only module name matches.

        If project has myproject::object but doesn't define ID,
        then object::ID should still resolve to sui::object::ID (stdlib).
        """
        ctx = ProjectContext(["myproject/object.move"])

        ctx.source_files["myproject/object.move"].facts = [
            Fact("Struct", ("myproject::object::UserData",)),  # Defines UserData, NOT ID
            Fact("StructField", ("myproject::object::Pool", 0, "owner", "object::ID")),
        ]
        ctx.source_files["myproject/object.move"].module_path = "myproject::object"
        ctx.source_files["myproject/object.move"].import_map = {}

        builder = SemanticFactsBuilder()
        candidates = builder._collect_external_type_candidates(ctx)

        # object::ID should be recognized as stdlib (not external)
        # because myproject::object::ID doesn't exist
        assert "object::ID" not in candidates, (
            f"stdlib object::ID incorrectly shadowed. Got: {candidates}"
        )
