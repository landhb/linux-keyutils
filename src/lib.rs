//! Rust interface to the Linux key-management facility.
//! Provides a safe interface around the raw system calls allowing
//! user-space programs to perform key manipulation.
//!
//! Example usage:
//!
//! ```
//! use linux_keyutils::{Key, KeyRing, KeyError, KeyRingIdentifier};
//! use linux_keyutils::{KeyPermissionsBuilder, Permission};
//!
//! fn main() -> Result<(), KeyError> {
//!     // Obtain the default session keyring for the current process
//!     // See [KeyRingIdentifier] and `man 2 keyctl` for more information on default
//!     // keyrings for processes.
//!     let ring = KeyRing::from_special_id(KeyRingIdentifier::Session, false)?;
//!
//!     // Insert a new key
//!     let key = ring.add_key("my-new-key", b"secret")?;
//!
//!     // Utiltiies to create proper permissions
//!     let perms = KeyPermissionsBuilder::builder()
//!         .posessor(Permission::ALL)
//!         .user(Permission::ALL)
//!         .group(Permission::VIEW | Permission::READ)
//!         .build();
//!
//!     // Perform manipulations on the key such as setting permissions
//!     key.set_perm(perms)?;
//!
//!     // Or invalidating (removing) the key
//!     key.invalidate()?;
//!     Ok(())
//! }
//! ```
//!
//! To look for an existing key you can use the [KeyRing::search] method. Usage:
//!
//! ```
//! use linux_keyutils::{Key, KeyRing, KeyError, KeyRingIdentifier};
//! use linux_keyutils::{KeyPermissionsBuilder, Permission};
//!
//! fn get_key(description: &str) -> Result<Key, KeyError> {
//!     // Obtain the default session keyring for the current process
//!     // See `KeyRingIdentifier` and `man 7 keyrings` for more information on default
//!     // keyrings for processes and users.
//!     let ring = KeyRing::from_special_id(KeyRingIdentifier::Session, false)?;
//!
//!     // Lookup an existing key
//!     let key = ring.search(description)?;
//!     Ok(key)
//! }
//! ```
#![cfg_attr(not(feature = "std"), no_std)]
//#![deny(warnings)]

// no_std CStr/CString support stabilized in Rust 1.64.0
// CString requires alloc however
extern crate alloc;

// Internal FFI for raw syscalls
mod ffi;

// Export certain FFI types
pub use ffi::{KeyRingIdentifier, KeySerialId, KeyType};

// Expose error types
mod errors;
pub use errors::KeyError;

// Primary keyring interface
mod keyring;
pub use keyring::KeyRing;

// Primary key interface
mod key;
pub use key::Key;

// Expose KeyPermissions API
mod permissions;
pub use permissions::{KeyPermissions, KeyPermissionsBuilder, Permission};
