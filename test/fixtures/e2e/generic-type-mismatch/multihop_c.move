/// Multi-hop test: module_c validates T via type_name::get<T>() with assertion
module test::multihop_c {
    use std::type_name;

    /// Validates generic type T - the actual validation happens here
    public fun validate<T>(expected_type: std::string::String) {
        assert!(type_name::into_string(type_name::get<T>()) == expected_type, 1);
    }
}
