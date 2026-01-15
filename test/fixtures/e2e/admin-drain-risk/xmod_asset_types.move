/// Cross-module user asset test: Asset type definitions
/// UserVault defined here, used by another module
module test::xmod_asset_types {
    use sui::balance::Balance;
    use sui::sui::SUI;
    use sui::object::{Self, UID};

    /// User asset defined in this module
    public struct UserVault has key, store {
        id: UID,
        owner: address,
        balance: Balance<SUI>,
    }

    /// Admin cap for this module
    public struct AdminCap has key, store {
        id: UID,
    }

    /// Accessor for balance
    public fun balance_mut(vault: &mut UserVault): &mut Balance<SUI> {
        &mut vault.balance
    }

    public fun owner(vault: &UserVault): address {
        vault.owner
    }
}
