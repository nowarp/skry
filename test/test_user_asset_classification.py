"""Tests for IsUserAsset LLM classification."""

from core.facts import Fact
from semantic_facts_builder import SemanticFactsBuilder


class TestIsUserAssetFactSchema:
    """Test IsUserAsset fact schema."""

    def test_fact_creation_true(self):
        """IsUserAsset fact can be created with True."""
        fact = Fact("IsUserAsset", ("TypusBidReceipt", True))
        assert fact.name == "IsUserAsset"
        assert fact.args == ("TypusBidReceipt", True)

    def test_fact_creation_false(self):
        """IsUserAsset fact can be created with False."""
        fact = Fact("IsUserAsset", ("Treasury", False))
        assert fact.name == "IsUserAsset"
        assert fact.args == ("Treasury", False)


class TestSemanticFactsBuilderExtractBaseType:
    """Test SemanticFactsBuilder._extract_base_type method."""

    def test_extract_from_vector(self):
        """Extracts type from vector<T>."""
        builder = SemanticFactsBuilder()
        assert builder._extract_base_type("vector<Receipt>") == "Receipt"

    def test_extract_from_option(self):
        """Extracts type from Option<T>."""
        builder = SemanticFactsBuilder()
        assert builder._extract_base_type("Option<Receipt>") == "Receipt"

    def test_extract_strips_generics(self):
        """Strips generic parameters."""
        builder = SemanticFactsBuilder()
        assert builder._extract_base_type("Pool<SUI, USDC>") == "Pool"

    def test_extract_simple_name(self):
        """Gets simple name from qualified."""
        builder = SemanticFactsBuilder()
        assert builder._extract_base_type("test::module::Receipt") == "Receipt"
