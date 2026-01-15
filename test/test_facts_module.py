"""Tests for facts.py module."""
import pytest
from core.facts import (
    Fact,
    names_match,
    has_fact_for_name,
    fact_exists,
    get_fact_boolean,
    add_fact,
    get_caps,
    get_all_structs,
    UnregisteredFactError,
    get_all_fact_schemas,
    get_facts_by_scope,
)
from test_utils import make_facts


class TestNamesMatch:
    def test_exact_match(self):
        assert names_match("foo", "foo")
        assert names_match("mod::func", "mod::func")

    def test_simple_name_match(self):
        assert names_match("AdminCap", "ac1::config::AdminCap")
        assert names_match("ac1::config::AdminCap", "AdminCap")

    def test_different_modules_same_name(self):
        # Simple names match even if modules differ
        assert names_match("mod1::Foo", "mod2::Foo")

    def test_no_match(self):
        assert not names_match("Foo", "Bar")
        assert not names_match("mod::Foo", "mod::Bar")


class TestHasFactForName:
    def test_exact_match(self):
        facts = make_facts(
            ("IsCapability", "ac1::config::AdminCap"),
            ("Struct", "ac1::config::Treasury"),
        )
        assert has_fact_for_name(facts, "IsCapability", "ac1::config::AdminCap")

    def test_simple_name_match(self):
        facts = make_facts(("IsCapability", "ac1::config::AdminCap"),)
        assert has_fact_for_name(facts, "IsCapability", "AdminCap")

    def test_qualified_to_simple(self):
        facts = make_facts(("IsCapability", "AdminCap"),)
        assert has_fact_for_name(facts, "IsCapability", "other::module::AdminCap")

    def test_no_match(self):
        facts = make_facts(("IsCapability", "AdminCap"),)
        assert not has_fact_for_name(facts, "IsCapability", "Treasury")
        assert not has_fact_for_name(facts, "IsAsset", "AdminCap")

    def test_empty_facts(self):
        assert not has_fact_for_name([], "IsCapability", "AdminCap")


class TestFactExists:
    def test_simple_fact(self):
        facts = make_facts(("Fun", "mod::f"),)
        assert fact_exists(facts, "Fun", ("mod::f",))

    def test_fact_with_boolean(self):
        facts = [Fact("Transfers", ("mod::f", True))]
        assert fact_exists(facts, "Transfers", ("mod::f",))

    def test_no_match(self):
        facts = make_facts(("Fun", "mod::f"),)
        assert not fact_exists(facts, "Fun", ("mod::g",))
        assert not fact_exists(facts, "IsPublic", ("mod::f",))


class TestGetFactBoolean:
    def test_true_value(self):
        facts = [Fact("Transfers", ("mod::f", True))]
        assert get_fact_boolean(facts, "Transfers", ("mod::f",)) is True

    def test_false_value(self):
        facts = [Fact("Transfers", ("mod::f", False))]
        assert get_fact_boolean(facts, "Transfers", ("mod::f",)) is False

    def test_no_boolean(self):
        facts = make_facts(("Fun", "mod::f"),)
        # Non-boolean fact returns True when matched
        assert get_fact_boolean(facts, "Fun", ("mod::f",)) is True

    def test_not_found(self):
        facts = make_facts(("Fun", "mod::f"),)
        assert get_fact_boolean(facts, "Transfers", ("mod::f",)) is None


class TestAddFact:
    def test_add_simple(self):
        facts = []
        add_fact(facts, "Fun", ("mod::f",))
        assert len(facts) == 1
        assert facts[0].name == "Fun"
        assert facts[0].args == ("mod::f",)

    def test_add_with_description(self):
        facts = []
        # Use a registered fact with custom description
        add_fact(facts, "Fun", ("mod::f",), description="custom desc")
        assert facts[0].description == "custom desc"

    def test_description_from_schema(self):
        """Fact.get_description() returns schema description when no explicit desc."""
        facts = []
        add_fact(facts, "Transfers", ("mod::f", True))
        # description field is None, but get_description() returns schema desc
        assert facts[0].description is None
        assert facts[0].get_description() == "Function performs transfer (including via callees)"


class TestFactRegistry:
    """Tests for the fact registry and validation."""

    def test_unregistered_fact_raises_error(self):
        """Creating a Fact with unregistered name must raise UnregisteredFactError."""
        with pytest.raises(UnregisteredFactError) as exc_info:
            Fact("CompletelyMadeUpFactName", ("arg",))
        assert "CompletelyMadeUpFactName" in str(exc_info.value)
        assert "not registered" in str(exc_info.value)

    def test_registered_fact_succeeds(self):
        """Creating a Fact with registered name should work."""
        fact = Fact("IsPublic", ("mod::func",))
        assert fact.name == "IsPublic"
        assert fact.args == ("mod::func",)

    def test_feature_facts_are_registered(self):
        """Project-scope feature facts are properly registered."""
        # FeatureVersion is a registered fact (not dynamic)
        fact = Fact("FeatureVersion", (True,))
        assert fact.name == "FeatureVersion"
        assert fact.args == (True,)
        assert fact.schema is not None
        assert fact.schema.scope == "project"

    def test_registry_has_all_facts(self):
        """Registry should have a reasonable number of facts defined."""
        schemas = get_all_fact_schemas()
        assert len(schemas) > 50  # We have ~85 facts

    def test_facts_by_scope(self):
        """Can filter facts by scope."""
        struct_facts = get_facts_by_scope("struct")
        func_facts = get_facts_by_scope("function")
        stmt_facts = get_facts_by_scope("statement")

        assert any(s.name == "IsCapability" for s in struct_facts)
        assert any(s.name == "Fun" for s in func_facts)
        assert any(s.name == "Tainted" for s in stmt_facts)

    def test_fact_schema_property(self):
        """Fact.schema returns the FactSchema."""
        fact = Fact("IsPublic", ("mod::func",))
        schema = fact.schema
        assert schema is not None
        assert schema.name == "IsPublic"
        assert schema.description == "Function is public"


class TestFactGetters:
    def test_get_all_structs(self):
        facts = make_facts(
            ("Struct", "mod::Foo"),
            ("Struct", "mod::Bar"),
            ("Fun", "mod::f"),
        )
        structs = get_all_structs(facts)
        assert set(structs) == {"mod::Foo", "mod::Bar"}

    def test_get_caps(self):
        # IsCapability facts have single arg: (role_name,)
        # Role detection is based on struct having single UID field
        facts = [
            Fact("IsCapability", ("mod::AdminCap",)),
            Fact("IsCapability", ("mod::UserCap",)),
            Fact("Struct", ("mod::Treasury",)),
        ]
        roles = get_caps(facts)
        assert set(roles) == {"mod::AdminCap", "mod::UserCap"}

