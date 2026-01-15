module test::iterator {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;
    use sui::transfer;
    use sui::event::emit;

    const ErrorNotOneTimeWitness: u64 = 0;

    public struct ITERATOR has drop {}

    public struct IteratorCreatorCap has key, store {
        id: UID,
    }

    /// IteratorCap is a capability that allows iterate phases of the lottery system.
    public struct IteratorCap has key, store {
        id: UID,
    }

    public struct IteratorCapCreated has copy, drop {
        cap_id: object::ID,
    }

    /// Initializes the iterator creator capability.
    fun init(witness: ITERATOR, ctx: &mut TxContext) {
        assert!(sui::types::is_one_time_witness(&witness), ErrorNotOneTimeWitness);

        let authority = ctx.sender();

        let iterator_creator_cap = IteratorCreatorCap {
            id: object::new(ctx),
        };

        create_iterator_cap(&iterator_creator_cap, authority, ctx);

        transfer::public_transfer(iterator_creator_cap, authority);
    }

    /// Creates an iterator capability.
    public fun create_iterator_cap(
        _self: &IteratorCreatorCap,
        recipient: address,
        ctx: &mut TxContext,
    ) {
        let iterator_cap = IteratorCap {
            id: object::new(ctx),
        };

        emit(IteratorCapCreated { cap_id: object::id(&iterator_cap) });

        transfer::public_transfer(iterator_cap, recipient);
    }
}
