/// Safe test cases - no sensitive data in events
module test::sensitive_event_safe {
    use sui::event;
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};
    use std::string::String;

    public struct Account has key {
        id: UID,
        owner: address,
        secret_key: vector<u8>,  // Sensitive, not leaked
    }

    public struct AccountCreated has copy, drop {
        account_id: address,
        owner: address,
    }

    public struct AccountUpdated has copy, drop {
        account_id: address,
    }

    /// Safe: Event doesn't include secret_key
    public entry fun create_account(account: &Account) {
        event::emit(AccountCreated {
            account_id: sui::object::uid_to_address(&account.id),
            owner: account.owner,
        });
    }

    /// Safe: Minimal information
    public entry fun update_account(account: &Account) {
        event::emit(AccountUpdated {
            account_id: sui::object::uid_to_address(&account.id),
        });
    }
}
