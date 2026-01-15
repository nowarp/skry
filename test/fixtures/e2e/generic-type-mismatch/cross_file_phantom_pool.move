/// Test: Pool module with phantom type parameter.
/// Used by cross_file_phantom_interface.move to test cross-file phantom binding.
module pool_module::pool {
    use sui::object::UID;

    /// Pool with phantom LP type - constrains L to specific pool
    public struct Pool<phantom L> has key, store {
        id: UID,
        balance: u64,
    }
}
