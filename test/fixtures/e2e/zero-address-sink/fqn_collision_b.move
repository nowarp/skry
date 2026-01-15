/// FQN collision test - module B
module test::fqn_collision_b {
    use sui::coin::Coin;
    use sui::sui::SUI;
    use sui::transfer;

    public struct Treasury has drop {
        addr: address
    }

    const VALID_ADDR: address = @0x456;

    /// SAFE: Transfers to valid address
    public fun send(treasury: Treasury, coin: Coin<SUI>) {
        transfer::public_transfer(coin, VALID_ADDR);
    }
}
