module test::coin_vuln {
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::coin::{Self as coin, TreasuryCap, CoinMetadata};

    public struct COIN_VULN has drop {}

    public struct Treasury has key, store {
        id: UID,
        cap: TreasuryCap<COIN_VULN>,
        metadata: CoinMetadata<COIN_VULN>,
    }

    #[allow(lint(share_owned))]
    fun init(witness: COIN_VULN, ctx: &mut TxContext) {
        let (treasury_cap, metadata) = coin::create_currency(
            witness,
            9,
            b"VCOIN",
            b"VulnerableCoin",
            b"",
            option::none(),
            ctx,
        );
        let treasury = Treasury {
            id: object::new(ctx),
            cap: treasury_cap,
            metadata,
        };

        transfer::share_object(treasury);
    }

    public entry fun unprotected_send(
        treasury: &mut Treasury,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext,
    ) {
        // Bad: anyone can mint arbitrary `amount` to arbitrary `recipient`.
        coin::mint_and_transfer(&mut treasury.cap, amount, recipient, ctx);
    }
}
