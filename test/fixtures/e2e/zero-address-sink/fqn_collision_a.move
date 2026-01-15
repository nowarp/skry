/// FQN collision test - module A
module test::fqn_collision_a {
    use sui::coin::Coin;
    use sui::sui::SUI;
    use sui::transfer;

    public struct Treasury has drop {
        addr: address
    }

    /// VULNERABLE: Transfers to zero address
    // @expect: zero-address-sink
    public fun burn(treasury: Treasury, coin: Coin<SUI>) {
        transfer::public_transfer(coin, @0x0);  // Lost
    }
}
