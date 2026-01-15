/// Test case: Config field modified via governance/proposal mechanism, not direct setter
/// From: Legend-of-Arcadia Multisig - threshold modified in multisig_setting_execute
module test::governance_setter {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;
    use sui::vec_map::{Self, VecMap};

    public struct Proposal has store {
        new_threshold: u64,
        approved_weight: u64,
    }

    // Threshold IS modified, but via governance flow, not direct setter
    // @false-positive: missing-mutable-config-setter (modified via governance in execute_proposal)
    public struct MultiSig has key {
        id: UID,
        threshold: u64,
        participants: VecMap<address, u64>,
        pending_proposal: Option<Proposal>,
    }

    fun init(ctx: &mut TxContext) {
        let ms = MultiSig {
            id: object::new(ctx),
            threshold: 1,
            participants: vec_map::empty(),
            pending_proposal: option::none(),
        };
        sui::transfer::share_object(ms);
    }

    /// Create proposal to change threshold
    public fun propose_threshold(ms: &mut MultiSig, new_threshold: u64) {
        ms.pending_proposal = option::some(Proposal {
            new_threshold,
            approved_weight: 0,
        });
    }

    /// Vote on proposal
    public fun vote(ms: &mut MultiSig, voter: address) {
        let proposal = option::borrow_mut(&mut ms.pending_proposal);
        let weight = *vec_map::get(&ms.participants, &voter);
        proposal.approved_weight = proposal.approved_weight + weight;
    }

    /// Execute approved proposal - THIS is where threshold gets modified
    public fun execute_proposal(ms: &mut MultiSig) {
        let proposal = option::extract(&mut ms.pending_proposal);
        assert!(proposal.approved_weight >= ms.threshold, 0);
        // Threshold IS being set here via governance mechanism
        ms.threshold = proposal.new_threshold;
    }
}
