/// Safe test cases - no zero address transfers
module test::zero_address_safe {
    use sui::coin::{Self, Coin, TreasuryCap};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    const TREASURY_ADDR: address = @0x123;

    /// Transfer to valid address
    public entry fun send_to_treasury(coin: Coin<SUI>) {
        transfer::public_transfer(coin, TREASURY_ADDR);
    }

    /// Transfer to parameter address
    public entry fun send_to_recipient(coin: Coin<SUI>, recipient: address) {
        assert!(recipient != @0x0, 0);  // Check non-zero
        transfer::public_transfer(coin, recipient);
    }

    /// Proper burn mechanism
    public entry fun burn_coins<T>(treasury: &mut TreasuryCap<T>, coin: Coin<T>) {
        coin::burn(treasury, coin);
    }

    /// Transfer to sender
    public entry fun return_to_sender(coin: Coin<SUI>, ctx: &TxContext) {
        transfer::public_transfer(coin, tx_context::sender(ctx));
    }
}
