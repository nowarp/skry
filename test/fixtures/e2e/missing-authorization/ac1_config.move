module test::ac1_config;

use sui::transfer;
use sui::object::{Self as object, UID};
use sui::tx_context::{Self as tx_context, TxContext};

public struct AdminCap has key, store {
    id: UID,
}

fun init(ctx: &mut TxContext) {
    let admin_cap = AdminCap { id: object::new(ctx) };
    let sender = tx_context::sender(ctx);
    transfer::transfer(admin_cap, sender);
}
