#![cfg_attr(not(feature = "std"), no_std)]

// no_std CStr/CString support stabilized in Rust 1.64.0
extern crate alloc;

// Expose error types
mod errors;
pub use errors::KeyError;

// Primary keyctl interface
mod keyctl;
pub use keyctl::KeyCtl;

// Internal FFI for raw syscalls
mod ffi;

// Expose KeyPermissions API
mod permissions;
pub use permissions::KeyPermissions;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let id = add_key(
            KeyType::User,
            KeyringIdentifier::UserSession,
            "my-super-secret-test-key",
            "Test Data".as_bytes(),
        )
        .unwrap();

        let keyctl = KeyCtl::from_id(id);
        //keyctl.set_perm(0x3f3f0000).unwrap();
        //keyctl.read().unwrap();
        keyctl.clear().unwrap()
    }
}
