/// Test cases for zero-address-sink rule.
/// Value transferred to zero address is permanently lost
module test::zero_address_sink {
    use sui::coin::Coin;
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::TxContext;

    const ZERO_ADDR: address = @0x0;
    const BURN_ADDRESS: address = @0x0;

    /// VULNERABLE: Transfer to zero address
    // @expect: zero-address-sink
    public entry fun burn_fees(coin: Coin<SUI>) {
        transfer::public_transfer(coin, ZERO_ADDR);  // Lost forever!
    }

    /// VULNERABLE: Transfer to constant zero address
    // @expect: zero-address-sink
    public entry fun send_to_void(coin: Coin<SUI>) {
        transfer::public_transfer(coin, @0x0);  // Directly to zero
    }

    /// VULNERABLE: Transfer using named constant
    // @expect: zero-address-sink
    public entry fun burn_using_const(coin: Coin<SUI>) {
        transfer::public_transfer(coin, BURN_ADDRESS);  // Still zero
    }

    /// SAFE: Transfer to valid recipient
    public entry fun send_fees(coin: Coin<SUI>, recipient: address) {
        transfer::public_transfer(coin, recipient);
    }

    /// SAFE: Proper burn via TreasuryCap
    public entry fun proper_burn(
        treasury: &mut sui::coin::TreasuryCap<SUI>,
        coin: Coin<SUI>
    ) {
        sui::coin::burn(treasury, coin);
    }

    /// SAFE: Transfer to sender
    public entry fun refund(coin: Coin<SUI>, ctx: &TxContext) {
        transfer::public_transfer(coin, sui::tx_context::sender(ctx));
    }
}
