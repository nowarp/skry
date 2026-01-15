module test::hop_a {
    use test::hop_b;
    use test::hop_c::AdminCap;

    /// Entry point: calls hop_b which calls hop_c which does the transfer
    // @expect: single-step-ownership
    public entry fun transfer_via_hops(cap: AdminCap, recipient: address) {
        hop_b::forward(cap, recipient);
    }
}
