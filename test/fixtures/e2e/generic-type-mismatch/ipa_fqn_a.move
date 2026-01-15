/// IPA FQN collision test: module_a has validate<T> that DOES validate
module test::ipa_fqn_a {
    use std::type_name;

    /// Validates generic type T with assertion
    public fun validate<T>(expected_type: std::string::String) {
        assert!(type_name::into_string(type_name::get<T>()) == expected_type, 1);
    }
}
