"""Tests for derived facts computation (Pass 2.5)."""

from core.facts import Fact
from core.context import ProjectContext
from analysis.derived_facts import (
    compute_derived_facts,
    _collect_shared_types,
    _collect_user_asset_types,
    _compute_shared_object_facts,
    _compute_user_provided_value_facts,
    _compute_user_asset_transfer_facts,
    _compute_transfers_from_shared_object_facts,
)
from move.types import extract_base_type


class TestExtractBaseType:
    """Test extract_base_type helper."""

    def test_simple_type(self):
        assert extract_base_type("Pool") == "Pool"

    def test_ref_type(self):
        assert extract_base_type("&Pool") == "Pool"

    def test_mut_ref_type(self):
        assert extract_base_type("&mut Pool") == "Pool"

    def test_generic_type(self):
        assert extract_base_type("Pool<SUI>") == "Pool"

    def test_mut_ref_generic(self):
        assert extract_base_type("&mut Pool<SUI>") == "Pool"

    def test_qualified_name(self):
        assert extract_base_type("test::module::Pool") == "Pool"

    def test_qualified_with_generic(self):
        assert extract_base_type("test::module::Pool<T>") == "Pool"


class TestCollectSharedTypes:
    """Test _collect_shared_types function."""

    def test_collects_from_all_files(self):
        """Collects IsSharedObject types from multiple files (FQNs only)."""
        ctx = ProjectContext(["file1.move", "file2.move"])
        ctx.source_files["file1.move"].facts = [
            Fact("IsSharedObject", ("test::Pool",)),
        ]
        ctx.source_files["file2.move"].facts = [
            Fact("IsSharedObject", ("other::Registry",)),
        ]

        shared = _collect_shared_types(ctx)

        # Only FQNs, no simple names (to avoid cross-module collision)
        assert shared == {"test::Pool", "other::Registry"}

    def test_empty_when_no_shared(self):
        """Returns empty set when no IsSharedObject facts."""
        ctx = ProjectContext(["file.move"])
        ctx.source_files["file.move"].facts = []

        shared = _collect_shared_types(ctx)

        assert len(shared) == 0


class TestCollectUserAssetTypes:
    """Test _collect_user_asset_types function."""

    def test_collects_from_semantic_facts(self):
        """Collects IsUserAsset types from semantic facts."""
        ctx = ProjectContext([])
        ctx.semantic_facts = [
            Fact("IsUserAsset", ("Receipt", True)),
            Fact("IsUserAsset", ("Treasury", False)),  # NOT user asset
        ]

        user_assets = _collect_user_asset_types(ctx)

        assert "Receipt" in user_assets
        assert "Treasury" not in user_assets

    def test_empty_when_no_semantic_facts(self):
        """Returns empty when no semantic_facts attribute."""
        ctx = ProjectContext([])

        user_assets = _collect_user_asset_types(ctx)

        assert len(user_assets) == 0


class TestComputeSharedObjectFacts:
    """Test _compute_shared_object_facts function."""

    def test_creates_operates_on_shared_fact(self):
        """Creates OperatesOnSharedObject when func has &mut to shared type."""
        facts = [
            Fact("FormalArg", ("withdraw", 0, "pool", "&mut Pool")),
        ]
        # Now only FQNs - matching uses simple name extraction
        shared_types = {"test::Pool"}

        shared_facts, owned_facts = _compute_shared_object_facts(facts, shared_types)

        assert len(shared_facts) == 1
        assert shared_facts[0].name == "OperatesOnSharedObject"
        assert shared_facts[0].args == ("withdraw",)
        assert len(owned_facts) == 0

    def test_creates_operates_on_owned_fact(self):
        """Creates OperatesOnOwnedOnly when func has &mut to non-shared type."""
        facts = [
            Fact("FormalArg", ("use_cap", 0, "cap", "&mut AdminCap")),
        ]
        shared_types = {"Pool"}  # AdminCap NOT shared

        shared_facts, owned_facts = _compute_shared_object_facts(facts, shared_types)

        assert len(shared_facts) == 0
        assert len(owned_facts) == 1
        assert owned_facts[0].name == "OperatesOnOwnedOnly"
        assert owned_facts[0].args == ("use_cap",)

    def test_no_facts_for_non_mut_params(self):
        """No facts when function has no &mut params."""
        facts = [
            Fact("FormalArg", ("view", 0, "pool", "&Pool")),  # Not &mut
        ]
        shared_types = {"Pool"}

        shared_facts, owned_facts = _compute_shared_object_facts(facts, shared_types)

        assert len(shared_facts) == 0
        assert len(owned_facts) == 0

    def test_handles_generic_types(self):
        """Handles generic types like Pool<T>."""
        facts = [
            Fact("FormalArg", ("withdraw", 0, "pool", "&mut Pool<SUI>")),
        ]
        shared_types = {"test::Pool"}  # FQN only

        shared_facts, _ = _compute_shared_object_facts(facts, shared_types)

        assert len(shared_facts) == 1
        assert shared_facts[0].args == ("withdraw",)

    def test_multiple_mut_params(self):
        """Handles function with multiple &mut params - any shared = shared."""
        facts = [
            Fact("FormalArg", ("func", 0, "cap", "&mut AdminCap")),  # Not shared
            Fact("FormalArg", ("func", 1, "pool", "&mut Pool")),  # Shared
        ]
        shared_types = {"test::Pool"}  # FQN only

        shared_facts, owned_facts = _compute_shared_object_facts(facts, shared_types)

        assert len(shared_facts) == 1
        assert len(owned_facts) == 0

    def test_cross_module_same_name_both_match(self):
        """Two modules with same-named shared Pool - both match &mut Pool param."""
        facts = [
            Fact("FormalArg", ("func", 0, "pool", "&mut Pool")),
        ]
        # Both alpha and beta have shared Pool - &mut Pool matches either
        shared_types = {"alpha::Pool", "beta::Pool"}

        shared_facts, _ = _compute_shared_object_facts(facts, shared_types)

        # Should match because simple name "Pool" is in shared_simple_names
        assert len(shared_facts) == 1

    def test_cross_module_different_name_no_collision(self):
        """Different-named shared objects don't collide."""
        facts = [
            Fact("FormalArg", ("func", 0, "registry", "&mut Registry")),
        ]
        # Only Pool is shared, not Registry
        shared_types = {"alpha::Pool", "beta::Pool"}

        shared_facts, owned_facts = _compute_shared_object_facts(facts, shared_types)

        # Registry is not shared, so OperatesOnOwnedOnly
        assert len(shared_facts) == 0
        assert len(owned_facts) == 1


class TestComputeUserProvidedValueFacts:
    """Test _compute_user_provided_value_facts function."""

    def test_creates_fact_for_coin_param(self):
        """Creates TransfersUserProvidedValue when transfer uses Coin param."""
        facts = [
            Fact("FormalArg", ("deposit", 0, "coin", "Coin<SUI>")),
            Fact("TaintedAtSink", ("deposit", "coin", "stmt1", "transfer_value", "")),
        ]

        result = _compute_user_provided_value_facts(facts)

        assert len(result) == 1
        assert result[0].name == "TransfersUserProvidedValue"
        assert result[0].args == ("deposit",)

    def test_creates_fact_for_balance_param(self):
        """Creates TransfersUserProvidedValue when transfer uses Balance param."""
        facts = [
            Fact("FormalArg", ("deposit", 0, "balance", "Balance<SUI>")),
            Fact("TaintedAtSink", ("deposit", "balance", "stmt1", "transfer_value", "")),
        ]

        result = _compute_user_provided_value_facts(facts)

        assert len(result) == 1
        assert result[0].args == ("deposit",)

    def test_no_fact_for_borrowed_param(self):
        """No fact when transfer source is borrowed."""
        facts = [
            Fact("FormalArg", ("withdraw", 0, "pool", "&mut Pool")),
            Fact("TaintedAtSink", ("withdraw", "pool", "stmt1", "transfer_value", "")),
        ]

        result = _compute_user_provided_value_facts(facts)

        assert len(result) == 0

    def test_no_fact_for_non_value_type(self):
        """No fact when transfer source is not Coin/Balance."""
        facts = [
            Fact("FormalArg", ("transfer_nft", 0, "nft", "NFT")),
            Fact("TaintedAtSink", ("transfer_nft", "nft", "stmt1", "transfer_value", "")),
        ]

        result = _compute_user_provided_value_facts(facts)

        assert len(result) == 0

    def test_all_sources_must_be_value_type(self):
        """All transfer sources must be Coin/Balance."""
        facts = [
            Fact("FormalArg", ("mixed", 0, "coin", "Coin<SUI>")),
            Fact("FormalArg", ("mixed", 1, "other", "SomeType")),
            Fact("TaintedAtSink", ("mixed", "coin", "stmt1", "transfer_value", "")),
            Fact("TaintedAtSink", ("mixed", "other", "stmt2", "transfer_value", "")),
        ]

        result = _compute_user_provided_value_facts(facts)

        # other is not Coin/Balance, so no fact
        assert len(result) == 0


class TestComputeUserAssetTransferFacts:
    """Test _compute_user_asset_transfer_facts function."""

    def test_creates_fact_for_user_asset(self):
        """Creates TransfersUserAsset when transfer uses user asset type."""
        facts = [
            Fact("FormalArg", ("redeem", 0, "receipt", "Receipt")),
            Fact("TaintedAtSink", ("redeem", "receipt", "stmt1", "transfer_value", "")),
        ]
        user_asset_types = {"Receipt"}

        result = _compute_user_asset_transfer_facts(facts, user_asset_types)

        assert len(result) == 1
        assert result[0].name == "TransfersUserAsset"
        assert result[0].args == ("redeem", "Receipt")

    def test_no_fact_for_non_user_asset(self):
        """No fact when transfer type is not user asset."""
        facts = [
            Fact("FormalArg", ("withdraw", 0, "treasury", "Treasury")),
            Fact("TaintedAtSink", ("withdraw", "treasury", "stmt1", "transfer_value", "")),
        ]
        user_asset_types = {"Receipt"}  # Treasury NOT user asset

        result = _compute_user_asset_transfer_facts(facts, user_asset_types)

        assert len(result) == 0

    def test_no_fact_for_borrowed_param(self):
        """No fact when param is borrowed."""
        facts = [
            Fact("FormalArg", ("use_receipt", 0, "receipt", "&Receipt")),
            Fact("TaintedAtSink", ("use_receipt", "receipt", "stmt1", "transfer_value", "")),
        ]
        user_asset_types = {"Receipt"}

        result = _compute_user_asset_transfer_facts(facts, user_asset_types)

        assert len(result) == 0

    def test_empty_user_assets(self):
        """Returns empty when no user asset types."""
        facts = [
            Fact("FormalArg", ("func", 0, "x", "SomeType")),
            Fact("TaintedAtSink", ("func", "x", "stmt1", "transfer_value", "")),
        ]

        result = _compute_user_asset_transfer_facts(facts, set())

        assert len(result) == 0


class TestComputeTransfersFromSharedObjectFacts:
    """Test _compute_transfers_from_shared_object_facts function."""

    def test_creates_fact_for_shared_object_extraction(self):
        """Creates TransfersFromSharedObject when extracting from shared object."""
        facts = [
            Fact("FormalArg", ("drain", 0, "pool", "&mut Pool")),
            Fact("TaintedAtSink", ("drain", "pool", "stmt1", "transfer_value", "")),
            Fact("HasValueExtraction", ("drain", True)),
        ]
        shared_types = {"Pool"}

        result = _compute_transfers_from_shared_object_facts(facts, shared_types)

        assert len(result) == 1
        assert result[0].name == "TransfersFromSharedObject"
        assert result[0].args == ("drain", "pool", "Pool")

    def test_no_fact_for_non_shared_type(self):
        """No fact when source type is not shared."""
        facts = [
            Fact("FormalArg", ("withdraw", 0, "vault", "&mut Vault")),
            Fact("TaintedAtSink", ("withdraw", "vault", "stmt1", "transfer_value", "")),
        ]
        shared_types = {"Pool"}  # Vault NOT shared

        result = _compute_transfers_from_shared_object_facts(facts, shared_types)

        assert len(result) == 0

    def test_no_fact_for_owned_param(self):
        """No fact when param is owned (not &mut)."""
        facts = [
            Fact("FormalArg", ("transfer", 0, "pool", "Pool")),  # Owned, not &mut
            Fact("TaintedAtSink", ("transfer", "pool", "stmt1", "transfer_value", "")),
        ]
        shared_types = {"Pool"}

        result = _compute_transfers_from_shared_object_facts(facts, shared_types)

        assert len(result) == 0

    def test_no_fact_for_immutable_ref(self):
        """No fact when param is immutable ref (&)."""
        facts = [
            Fact("FormalArg", ("view", 0, "pool", "&Pool")),  # Immutable ref
            Fact("TaintedAtSink", ("view", "pool", "stmt1", "transfer_value", "")),
        ]
        shared_types = {"Pool"}

        result = _compute_transfers_from_shared_object_facts(facts, shared_types)

        assert len(result) == 0

    def test_handles_generic_types(self):
        """Handles generic types like Pool<SUI>."""
        facts = [
            Fact("FormalArg", ("drain", 0, "pool", "&mut Pool<SUI>")),
            Fact("TaintedAtSink", ("drain", "pool", "stmt1", "transfer_value", "")),
            Fact("HasValueExtraction", ("drain", True)),
        ]
        shared_types = {"Pool"}

        result = _compute_transfers_from_shared_object_facts(facts, shared_types)

        assert len(result) == 1
        assert result[0].args == ("drain", "pool", "Pool")

    def test_deduplicates_facts(self):
        """Deduplicates facts for same func/param/type combination."""
        facts = [
            Fact("FormalArg", ("drain", 0, "pool", "&mut Pool")),
            Fact("TaintedAtSink", ("drain", "pool", "stmt1", "transfer_value", "")),
            Fact("TaintedAtSink", ("drain", "pool", "stmt2", "transfer_value", "")),  # Same source
            Fact("HasValueExtraction", ("drain", True)),
        ]
        shared_types = {"Pool"}

        result = _compute_transfers_from_shared_object_facts(facts, shared_types)

        assert len(result) == 1  # Only one fact despite two TaintedTransferValue


class TestComputeDerivedFactsIntegration:
    """Integration tests for compute_derived_facts."""

    def _make_ctx(self, facts_by_file: dict) -> ProjectContext:
        """Create ProjectContext with given facts."""
        ctx = ProjectContext(list(facts_by_file.keys()))
        for file_path, facts in facts_by_file.items():
            ctx.source_files[file_path].facts = facts
        return ctx

    def test_full_pipeline(self):
        """Test full derived facts computation."""
        ctx = self._make_ctx({
            "pool.move": [
                Fact("IsSharedObject", ("Pool",)),
                Fact("FormalArg", ("withdraw", 0, "pool", "&mut Pool")),
            ],
            "deposit.move": [
                Fact("FormalArg", ("deposit", 0, "coin", "Coin<SUI>")),
                Fact("TaintedAtSink", ("deposit", "coin", "stmt1", "transfer_value", "")),
            ],
        })

        compute_derived_facts(ctx)

        # Check pool.move has OperatesOnSharedObject
        pool_facts = ctx.source_files["pool.move"].facts
        assert any(f.name == "OperatesOnSharedObject" and f.args == ("withdraw",) for f in pool_facts)

        # Check deposit.move has TransfersUserProvidedValue
        deposit_facts = ctx.source_files["deposit.move"].facts
        assert any(f.name == "TransfersUserProvidedValue" and f.args == ("deposit",) for f in deposit_facts)

    def test_with_user_asset_semantic_facts(self):
        """Test with IsUserAsset semantic facts."""
        ctx = self._make_ctx({
            "receipt.move": [
                Fact("FormalArg", ("redeem", 0, "receipt", "Receipt")),
                Fact("TaintedAtSink", ("redeem", "receipt", "stmt1", "transfer_value", "")),
            ],
        })
        ctx.semantic_facts = [
            Fact("IsUserAsset", ("Receipt", True)),
        ]

        compute_derived_facts(ctx)

        # Check TransfersUserAsset fact created
        facts = ctx.source_files["receipt.move"].facts
        assert any(
            f.name == "TransfersUserAsset" and f.args == ("redeem", "Receipt")
            for f in facts
        )
