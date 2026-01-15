module test::hop_b {
    use test::hop_c::{Self, AdminCap};

    /// Middle hop - forwards cap to hop_c
    // @expect: single-step-ownership
    public fun forward(cap: AdminCap, addr: address) {
        hop_c::sink(cap, addr);
    }
}
