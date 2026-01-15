/// Test case: DTO/proposal object pattern - struct is a proposal payload, not a mutable config
/// From: Legend-of-Arcadia Multisig - MultiSignatureSetting is proposal data, not persistent config
module test::proposal_dto {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;
    use sui::vec_map::{Self, VecMap};

    // Proposal settings - created once, consumed by governance, never mutated
    // @false-positive: missing-mutable-config-setter (DTO/proposal object, not mutable config)
    public struct ProposalSettings has store, key {
        id: UID,
        new_threshold: u64,
        participants_to_add: VecMap<address, u64>,
        participants_to_remove: vector<address>,
    }

    /// The actual governance object that IS mutable
    public struct Governance has key {
        id: UID,
        threshold: u64,
        participants: VecMap<address, u64>,
        pending_proposals: VecMap<u256, ProposalSettings>,
    }

    public struct AdminCap has key, store { id: UID }

    fun init(ctx: &mut TxContext) {
        let gov = Governance {
            id: object::new(ctx),
            threshold: 1,
            participants: vec_map::empty(),
            pending_proposals: vec_map::empty(),
        };
        sui::transfer::share_object(gov);

        let admin = AdminCap { id: object::new(ctx) };
        sui::transfer::transfer(admin, sui::tx_context::sender(ctx));
    }

    /// Create proposal - ProposalSettings is immutable after creation
    public fun create_proposal(
        gov: &mut Governance,
        new_threshold: u64,
        participants_to_add: VecMap<address, u64>,
        participants_to_remove: vector<address>,
        ctx: &mut TxContext,
    ) {
        let settings = ProposalSettings {
            id: object::new(ctx),
            new_threshold,
            participants_to_add,
            participants_to_remove,
        };
        vec_map::insert(&mut gov.pending_proposals, 0, settings);
    }

    /// Execute proposal - applies settings to Governance, then discards ProposalSettings
    public fun execute_proposal(gov: &mut Governance, proposal_id: u256) {
        let (_, settings) = vec_map::remove(&mut gov.pending_proposals, &proposal_id);
        gov.threshold = settings.new_threshold;
        // Apply other settings...
        let ProposalSettings { id, new_threshold: _, participants_to_add: _, participants_to_remove: _ } = settings;
        object::delete(id);
    }
}
