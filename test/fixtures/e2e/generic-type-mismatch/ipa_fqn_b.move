/// IPA FQN collision test: module_b has validate<T> that does NOT validate
module test::ipa_fqn_b {
    /// Same simple name as module_a::validate, but does NOT validate.
    /// VULNERABLE: Has validation responsibility but doesn't validate
    // @false-negative: generic-type-mismatch
    public fun validate<T>() {
        // No type_name::get - does not validate!
    }
}
