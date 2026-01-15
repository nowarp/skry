/// Test cases for tainted-state-modification rule.
/// User-controlled data written to state through function calls.
module test::state_mod {
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID, ID};
    use sui::dynamic_field;
    use sui::table::{Self, Table};

    /// Shared protocol storage (has multiple fields to avoid role misclassification)
    public struct Storage has key {
        id: UID,
        version: u64,
    }

    /// Admin capability (single UID field - correctly classified as role)
    public struct AdminCap has key, store {
        id: UID,
    }

    /// Config struct with vector fields (protocol configuration)
    public struct Config has key {
        id: UID,
        allowed_tokens: vector<address>,
        fee_tiers: vector<u64>,
    }

    /// Registry shared object for user assets
    public struct AssetRegistry has key {
        id: UID,
        assets: Table<ID, u64>,
    }

    /// User-creatable asset (anyone can mint)
    public struct UserAsset has key, store {
        id: UID,
        creator: address,
        data: u64,
    }

    /// PrivConfig struct with privileged admin field (for create-and-corrupt test)
    public struct PrivConfig has key {
        id: UID,
        admin: address,
    }

    /// VULNERABLE: Direct tainted state write via dynamic_field
    /// User controls value written to shared Storage
    // @expect: tainted-state-modification
    public entry fun set_value_unsafe(
        storage: &mut Storage,
        key: vector<u8>,
        value: u64,
        _ctx: &mut TxContext
    ) {
        dynamic_field::add(&mut storage.id, key, value);
    }

    /// VULNERABLE: Tainted key and value
    // @expect: tainted-state-modification
    public entry fun set_data_unsafe(
        storage: &mut Storage,
        key: vector<u8>,
        data: vector<u8>,
        _ctx: &mut TxContext
    ) {
        dynamic_field::add(&mut storage.id, key, data);
    }

    /// VULNERABLE: IPA - entry calls helper that writes state
    // @expect: tainted-state-modification
    public entry fun set_value_via_helper(
        storage: &mut Storage,
        key: vector<u8>,
        value: u64,
        ctx: &mut TxContext
    ) {
        do_set_value(storage, key, value);
    }

    /// Helper that writes to state
    fun do_set_value(storage: &mut Storage, key: vector<u8>, value: u64) {
        dynamic_field::add(&mut storage.id, key, value);
    }

    /// SAFE: Has sender check
    public entry fun set_value_with_sender(
        storage: &mut Storage,
        key: vector<u8>,
        value: u64,
        ctx: &mut TxContext
    ) {
        // Check sender is authorized (comparing against dummy address for test)
        assert!(tx_context::sender(ctx) == @0x1, 0);
        dynamic_field::add(&mut storage.id, key, value);
    }

    /// SAFE: Has role check
    public entry fun set_value_with_role(
        storage: &mut Storage,
        key: vector<u8>,
        value: u64,
        _cap: &AdminCap,
        _ctx: &mut TxContext
    ) {
        dynamic_field::add(&mut storage.id, key, value);
    }

    /// SAFE: IPA - callee checks sender (guard propagates)
    public entry fun set_value_via_guarded_helper(
        storage: &mut Storage,
        key: vector<u8>,
        value: u64,
        ctx: &mut TxContext
    ) {
        do_set_value_checked(storage, key, value, ctx);
    }

    /// Helper with sender check
    fun do_set_value_checked(
        storage: &mut Storage,
        key: vector<u8>,
        value: u64,
        ctx: &mut TxContext
    ) {
        // Check sender is authorized (comparing against dummy address for test)
        assert!(tx_context::sender(ctx) == @0x1, 0);
        dynamic_field::add(&mut storage.id, key, value);
    }

    /// VULNERABLE: Store tainted vector in config via swap
    /// Anyone can overwrite protocol's allowed tokens list
    // @expect: tainted-state-modification
    public entry fun set_allowed_tokens(
        config: &mut Config,
        tokens: vector<address>,
        _ctx: &mut TxContext
    ) {
        // Build new list from tainted input
        let mut new_tokens = vector::empty<address>();
        let mut i = 0;
        while (i < vector::length(&tokens)) {
            vector::push_back(&mut new_tokens, *vector::borrow(&tokens, i));
            i = i + 1;
        };
        // Swap into config (clears old, sets new)
        vector::swap(&mut config.allowed_tokens, &mut new_tokens);
    }

    /// VULNERABLE: Vector built via push_back then assigned to shared state
    /// Taint flows: param -> vector::borrow -> push_back -> struct field
    // @expect: tainted-state-modification
    public entry fun set_fee_tiers(
        config: &mut Config,
        tiers: vector<u64>,
        _ctx: &mut TxContext
    ) {
        let mut new_tiers = vector::empty<u64>();
        let mut i = 0;
        while (i < vector::length(&tiers)) {
            vector::push_back(&mut new_tiers, *vector::borrow(&tiers, i));
            i = i + 1;
        };
        config.fee_tiers = new_tiers;
    }

    /// VULNERABLE: Populate storage from tainted vectors
    /// Iterating tainted vector and writing each element to shared state
    // @expect: tainted-state-modification
    public entry fun populate_registry(
        storage: &mut Storage,
        keys: vector<vector<u8>>,
        values: vector<u64>,
        _ctx: &mut TxContext
    ) {
        let mut i = 0;
        while (i < vector::length(&keys)) {
            let key = *vector::borrow(&keys, i);
            let value = *vector::borrow(&values, i);
            dynamic_field::add(&mut storage.id, key, value);
            i = i + 1;
        };
    }

    /// SAFE (no marker): Creates user asset and registers in shared registry
    /// Writing to registry is safe - just self-registration of caller's own asset
    public entry fun create_and_register_asset(
        registry: &mut AssetRegistry,
        data: u64,
        ctx: &mut TxContext
    ) {
        // Inline sender call (matches create_medal pattern)
        let asset = UserAsset {
            id: object::new(ctx),
            creator: tx_context::sender(ctx),
            data,
        };
        table::add(&mut registry.assets, object::uid_to_inner(&asset.id), data);
        transfer::share_object(asset);
    }

    /// Detected: Creates user asset BUT ALSO corrupts config (no value extraction)
    /// The filter now detects writes to privileged fields even when creating user-creatable
    // @expect: tainted-state-modification
    public entry fun create_and_corrupt(
        registry: &mut AssetRegistry,
        config: &mut PrivConfig,
        data: u64,
        ctx: &mut TxContext
    ) {
        // Create user asset (triggers creates-user-creatable? = true)
        let asset = UserAsset {
            id: object::new(ctx),
            creator: tx_context::sender(ctx),
            data,
        };
        table::add(&mut registry.assets, object::uid_to_inner(&asset.id), data);
        transfer::share_object(asset);

        // BUT ALSO corrupt config admin - this is NOT value extraction!
        // The filter misses this because has-value-extraction? = false
        config.admin = tx_context::sender(ctx);
    }

    /// VULNERABLE: State write via let binding (table::borrow_mut in LetStmt)
    /// Tests StateWriteSink generation for LetStmt (not just ExprStmt)
    // @expect: tainted-state-modification
    public entry fun modify_registry_unsafe(
        registry: &mut AssetRegistry,
        asset_id: ID,
        new_value: u64,
        _ctx: &mut TxContext
    ) {
        // State write via let binding - must generate StateWriteSink
        let value_ref = table::borrow_mut(&mut registry.assets, asset_id);
        *value_ref = new_value;
    }

    fun init(ctx: &mut TxContext) {
        let storage = Storage {
            id: object::new(ctx),
            version: 0,
        };
        transfer::share_object(storage);

        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));

        // Share AssetRegistry for FP test case
        let registry = AssetRegistry {
            id: object::new(ctx),
            assets: table::new(ctx),
        };
        transfer::share_object(registry);

        // Share PrivConfig for create-and-corrupt FN test
        let priv_config = PrivConfig {
            id: object::new(ctx),
            admin: tx_context::sender(ctx),
        };
        transfer::share_object(priv_config);
    }
}
