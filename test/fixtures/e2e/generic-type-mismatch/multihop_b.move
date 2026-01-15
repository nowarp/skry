/// Multi-hop test: module_b is intermediate - calls multihop_c::validate
module test::multihop_b {
    use test::multihop_c;

    /// Intermediate helper - delegates validation to module_c
    public fun validate_via_c<T>(expected_type: std::string::String) {
        multihop_c::validate<T>(expected_type);
    }

    /// Helper that does NOT validate - VULNERABLE
    // @false-negative: generic-type-mismatch
    public fun no_validate<T>() {
        // Does nothing - no validation
    }
}
