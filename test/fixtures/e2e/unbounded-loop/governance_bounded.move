/// Test case: Loops bounded by governance participant counts (naturally small)
/// From: Legend-of-Arcadia Multisig - loops over user-provided vectors for governance changes
module test::governance_bounded {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::vec_map::{Self, VecMap};

    public struct MultiSig has key {
        id: UID,
        participants: VecMap<address, u64>,
        threshold: u64,
    }

    fun init(ctx: &mut TxContext) {
        let mut participants = vec_map::empty();
        vec_map::insert(&mut participants, tx_context::sender(ctx), 1);
        let ms = MultiSig {
            id: object::new(ctx),
            participants,
            threshold: 1,
        };
        sui::transfer::share_object(ms);
    }

    // Loop over user-provided removal list for governance update proposal
    // In real governance, this is naturally bounded (typically 5-20 signers)
    // Gas costs prevent adding too many participants
    // @false-positive: unbounded-loop (governance participant count is naturally bounded)
    public entry fun propose_remove_participants(
        _ms: &mut MultiSig,
        participants_to_remove: vector<address>,
    ) {
        let len = vector::length(&participants_to_remove);
        let mut i = 0;
        while (i < len) {
            let _addr = vector::borrow(&participants_to_remove, i);
            // Check participant exists in ms.participants
            i = i + 1;
        };
    }
}
