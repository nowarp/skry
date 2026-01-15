"""Tests for LLM-based sensitive field classification."""

from core.facts import Fact
from llm.sensitivity import (
    FieldInfo,
    StructInfo,
    collect_structs_for_analysis,
    build_sensitivity_prompt_for_batch,
    _collect_role_sensitive_facts,
    _collect_emitted_struct_names,
    MAX_FIELDS_PER_QUERY,
)


class TestCollectStructsForAnalysis:
    """Tests for collect_structs_for_analysis function."""

    def test_basic_struct_collection(self):
        """Test collecting a simple struct with fields (only_emitted=False)."""
        facts = [
            Fact("Struct", ("test::MyStruct",)),
            Fact("StructField", ("test::MyStruct", 0, "balance", "u64")),
            Fact("StructField", ("test::MyStruct", 1, "owner", "address")),
        ]
        # Use only_emitted=False for basic unit test
        structs = collect_structs_for_analysis(facts, only_emitted=False)
        assert len(structs) == 1
        assert structs[0].name == "test::MyStruct"
        assert len(structs[0].fields) == 2

    def test_only_emitted_filters_to_event_sinks(self):
        """With only_emitted=True, only structs in EventEmitSink are included."""
        facts = [
            # Two structs
            Fact("Struct", ("test::EmittedEvent",)),
            Fact("StructField", ("test::EmittedEvent", 0, "data", "u64")),
            Fact("StructField", ("test::EmittedEvent", 1, "sender", "address")),
            Fact("Struct", ("test::NotEmitted",)),
            Fact("StructField", ("test::NotEmitted", 0, "foo", "u64")),
            Fact("StructField", ("test::NotEmitted", 1, "bar", "String")),
            # Only EmittedEvent is actually emitted
            Fact("EventEmitSink", ("some_func", "stmt_1", "test::EmittedEvent")),
        ]
        structs = collect_structs_for_analysis(facts, only_emitted=True)
        assert len(structs) == 1
        assert structs[0].name == "test::EmittedEvent"

    def test_no_event_emissions_returns_empty(self):
        """With only_emitted=True and no EventEmitSink, return empty."""
        facts = [
            Fact("Struct", ("test::SomeStruct",)),
            Fact("StructField", ("test::SomeStruct", 0, "data", "u64")),
            # No EventEmitSink facts!
        ]
        structs = collect_structs_for_analysis(facts, only_emitted=True)
        assert len(structs) == 0

    def test_skips_role_structs(self):
        """Role/capability structs should be excluded from LLM analysis."""
        facts = [
            Fact("Struct", ("test::AdminCap",)),
            Fact("StructField", ("test::AdminCap", 0, "id", "UID")),
            Fact("IsCapability", ("test::AdminCap",)),
        ]
        structs = collect_structs_for_analysis(facts, only_emitted=False)
        assert len(structs) == 0

    def test_role_structs_auto_marked_sensitive(self):
        """Role/capability struct fields are auto-marked sensitive without LLM."""
        facts = [
            Fact("Struct", ("test::AdminCap",)),
            Fact("StructField", ("test::AdminCap", 0, "id", "UID")),
            Fact("StructField", ("test::AdminCap", 1, "admin_address", "address")),
            Fact("IsCapability", ("test::AdminCap",)),
        ]
        sensitive_facts = _collect_role_sensitive_facts(facts)
        # 2 fields, 1 FieldClassification fact each
        assert len(sensitive_facts) == 2
        # Check FieldClassification facts
        sensitive_field_facts = [f for f in sensitive_facts if f.name == "FieldClassification"]
        assert len(sensitive_field_facts) == 2
        field_names = {f.args[1] for f in sensitive_field_facts}
        assert "id" in field_names
        assert "admin_address" in field_names
        # All should be positive sensitive classifications with reason='trust'
        for fact in sensitive_field_facts:
            assert len(fact.args) == 6
            assert fact.args[2] == "sensitive"  # category
            assert fact.args[3] is False  # negative=False (positive classification)
            assert fact.args[4] == 1.0  # confidence
            assert fact.args[5] == "trust"  # reason

    def test_non_role_structs_not_auto_marked(self):
        """Non-role structs should NOT be auto-marked sensitive."""
        facts = [
            Fact("Struct", ("test::UserData",)),
            Fact("StructField", ("test::UserData", 0, "balance", "u64")),
            Fact("StructField", ("test::UserData", 1, "owner", "address")),
            # No IsCapability fact!
        ]
        sensitive_facts = _collect_role_sensitive_facts(facts)
        assert len(sensitive_facts) == 0

    def test_skips_uid_only_structs(self):
        """Structs with only UID field should be excluded."""
        facts = [
            Fact("Struct", ("test::SingleUID",)),
            Fact("StructField", ("test::SingleUID", 0, "id", "UID")),
        ]
        structs = collect_structs_for_analysis(facts, only_emitted=False)
        assert len(structs) == 0

    def test_includes_struct_comment(self):
        """Struct-level comments should be included."""
        facts = [
            Fact("Struct", ("test::User",)),
            Fact("StructField", ("test::User", 0, "name", "String")),
            Fact("StructField", ("test::User", 1, "email", "String")),
            Fact("StructComment", ("test::User", "User profile with sensitive data")),
        ]
        structs = collect_structs_for_analysis(facts, only_emitted=False)
        assert len(structs) == 1
        assert structs[0].struct_comment == "User profile with sensitive data"

    def test_includes_field_comments(self):
        """Field-level comments should be included."""
        facts = [
            Fact("Struct", ("test::Wallet",)),
            Fact("StructField", ("test::Wallet", 0, "balance", "u64")),
            Fact("StructField", ("test::Wallet", 1, "secret_key", "vector<u8>")),
            Fact("FieldComment", ("test::Wallet", "secret_key", "Private key - DO NOT EXPOSE")),
        ]
        structs = collect_structs_for_analysis(facts, only_emitted=False)
        assert len(structs) == 1
        assert len(structs[0].fields) == 2
        # Find the secret_key field
        secret_field = next(f for f in structs[0].fields if f.field_name == "secret_key")
        assert secret_field.field_comment == "Private key - DO NOT EXPOSE"
        # balance should have no comment
        balance_field = next(f for f in structs[0].fields if f.field_name == "balance")
        assert balance_field.field_comment is None


class TestCollectEmittedStructNames:
    """Tests for _collect_emitted_struct_names function."""

    def test_collects_from_event_emit_sink(self):
        """Should collect struct names from EventEmitSink facts."""
        facts = [
            Fact("EventEmitSink", ("func1", "stmt_1", "module::Event1")),
            Fact("EventEmitSink", ("func2", "stmt_2", "module::Event2")),
            Fact("EventEmitSink", ("func3", "stmt_3", "module::Event1")),  # duplicate
        ]
        emitted = _collect_emitted_struct_names(facts)
        assert emitted == {"module::Event1", "module::Event2"}

    def test_empty_when_no_events(self):
        """Should return empty set when no EventEmitSink facts."""
        facts = [
            Fact("Struct", ("test::Foo",)),
            Fact("StructField", ("test::Foo", 0, "x", "u64")),
        ]
        emitted = _collect_emitted_struct_names(facts)
        assert emitted == set()


class TestBuildSensitivityPrompt:
    """Tests for prompt building with comments."""

    def test_prompt_includes_struct_comment(self):
        """Struct-level comments should appear in prompt."""
        struct = StructInfo(
            name="test::SecretVault",
            struct_comment="Contains highly sensitive cryptographic material",
            fields=[
                FieldInfo("test::SecretVault", 0, "master_key", "vector<u8>"),
                FieldInfo("test::SecretVault", 1, "salt", "vector<u8>"),
            ],
        )
        prompt, field_keys = build_sensitivity_prompt_for_batch(struct.fields, [struct])

        assert "// Contains highly sensitive cryptographic material" in prompt
        assert "test::SecretVault" in prompt
        assert len(field_keys) == 2

    def test_prompt_includes_field_comment(self):
        """Field-level comments should appear in prompt."""
        struct = StructInfo(
            name="test::User",
            fields=[
                FieldInfo("test::User", 0, "public_id", "u64", field_comment="User ID - public"),
                FieldInfo("test::User", 1, "password_hash", "vector<u8>", field_comment="Hashed password - NEVER expose"),
            ],
        )
        prompt, field_keys = build_sensitivity_prompt_for_batch(struct.fields, [struct])

        assert "// User ID - public" in prompt
        assert "// Hashed password - NEVER expose" in prompt
        assert "public_id: u64" in prompt
        assert "password_hash: vector<u8>" in prompt

    def test_prompt_uses_array_format(self):
        """Prompt should request JSON array of sensitive fields with reason/confidence."""
        struct = StructInfo(
            name="test::Data",
            fields=[
                FieldInfo("test::Data", 0, "field1", "u64"),
                FieldInfo("test::Data", 1, "field2", "String"),
            ],
        )
        prompt, field_keys = build_sensitivity_prompt_for_batch(struct.fields, [struct])

        # Should ask for JSON array with reason and confidence
        assert "JSON array" in prompt
        # Should show example format with field, reason, confidence
        assert '"field":' in prompt
        assert '"reason":' in prompt
        assert '"confidence":' in prompt

    def test_batching_respects_max_fields(self):
        """Verify MAX_FIELDS_PER_QUERY constant is reasonable."""
        # This is a sanity check that we don't query too many fields at once
        assert MAX_FIELDS_PER_QUERY == 15


class TestSensitiveFieldBoolean:
    """Tests for SensitiveField(struct, field, is_sensitive) boolean format."""

    def test_sensitive_field_has_boolean_arg(self):
        """SensitiveField facts should have 3 args: struct, field, is_sensitive."""
        facts = [
            Fact("Struct", ("test::AdminCap",)),
            Fact("StructField", ("test::AdminCap", 0, "id", "UID")),
            Fact("IsCapability", ("test::AdminCap",)),
        ]
        sensitive_facts = _collect_role_sensitive_facts(facts)
        # 1 field, 1 FieldClassification fact
        assert len(sensitive_facts) == 1
        # Check FieldClassification fact
        sensitive_field_facts = [f for f in sensitive_facts if f.name == "FieldClassification"]
        assert len(sensitive_field_facts) == 1
        fact = sensitive_field_facts[0]
        assert len(fact.args) == 6
        assert fact.args[0] == "test::AdminCap"
        assert fact.args[1] == "id"
        assert fact.args[2] == "sensitive"  # category
        assert fact.args[3] is False  # negative=False (positive classification)
        assert fact.args[4] == 1.0  # confidence
        assert fact.args[5] == "trust"  # reason


class TestStructFieldCommentParsing:
    """Tests that verify struct/field comments are properly parsed from source."""

    def test_struct_comment_extraction(self):
        """Test that struct comments are extracted and passed to sensitivity analysis."""
        from move.parse import parse_move_source, build_code_facts

        source = '''
module test::sensitive {
    use sui::object::UID;

    /// User credentials storage
    /// Contains highly sensitive authentication data
    struct UserCredentials has key {
        id: UID,
        username: String,
        password_hash: vector<u8>,
    }
}
'''
        root = parse_move_source(source)
        facts, _ = build_code_facts(source, root, filename="test.move")

        # Check StructComment fact was generated
        struct_comments = [f for f in facts if f.name == "StructComment"]
        assert len(struct_comments) == 1
        assert struct_comments[0].args[0] == "test::sensitive::UserCredentials"
        assert "sensitive authentication data" in struct_comments[0].args[1]

    def test_field_comment_extraction(self):
        """Test that field comments are extracted and passed to sensitivity analysis."""
        from move.parse import parse_move_source, build_code_facts

        source = '''
module test::wallet {
    use sui::object::UID;

    struct Wallet has key {
        id: UID,
        // Public balance visible on-chain
        balance: u64,
        // SECRET: Private key material - never expose!
        secret_seed: vector<u8>,
    }
}
'''
        root = parse_move_source(source)
        facts, _ = build_code_facts(source, root, filename="test.move")

        # Check FieldComment facts were generated
        field_comments = [f for f in facts if f.name == "FieldComment"]
        assert len(field_comments) >= 2

        # Find the secret_seed comment
        secret_comment = next(
            (f for f in field_comments if f.args[1] == "secret_seed"),
            None
        )
        assert secret_comment is not None
        assert "never expose" in secret_comment.args[2].lower()

    def test_comments_included_in_prompt(self):
        """End-to-end test: comments from parse -> sensitivity prompt."""
        from move.parse import parse_move_source, build_code_facts

        source = '''
module test::secret {
    use sui::object::UID;

    /// Internal admin configuration
    struct AdminConfig has key {
        id: UID,
        // Admin-only secret token
        auth_token: vector<u8>,
        public_name: String,
    }
}
'''
        root = parse_move_source(source)
        facts, _ = build_code_facts(source, root, filename="test.move")

        # Collect structs for analysis (only_emitted=False for unit test)
        structs = collect_structs_for_analysis(facts, only_emitted=False)
        assert len(structs) == 1

        # Build prompt
        prompt, field_keys = build_sensitivity_prompt_for_batch(structs[0].fields, structs)

        # Verify struct comment is in prompt
        assert "// Internal admin configuration" in prompt

        # Verify field comment is in prompt
        assert "// Admin-only secret token" in prompt

        # Verify fields are listed
        assert "auth_token: vector<u8>" in prompt
        assert "public_name: String" in prompt

    def test_no_comment_struct_works(self):
        """Structs without comments should still work."""
        from move.parse import parse_move_source, build_code_facts

        source = '''
module test::nocomment {
    use sui::object::UID;

    struct PlainStruct has key {
        id: UID,
        field1: u64,
        field2: String,
    }
}
'''
        root = parse_move_source(source)
        facts, _ = build_code_facts(source, root, filename="test.move")

        structs = collect_structs_for_analysis(facts, only_emitted=False)
        assert len(structs) == 1
        assert structs[0].struct_comment is None
        assert all(f.field_comment is None for f in structs[0].fields)

        # Should still build valid prompt
        prompt, field_keys = build_sensitivity_prompt_for_batch(structs[0].fields, structs)
        assert "field1: u64" in prompt
        # 3 fields: id, field1, field2 (but id is UID so struct has 3)
        assert len(field_keys) == 3
