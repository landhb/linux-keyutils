//! Rust interface to the Linux key-management facility.
//! Provides a safe interface around the raw system calls allowing
//! user-space programs to perform key manipulation.
//!
//! Example usage:
//!
//! ```
//! use linux_keyutils::{Key, KeyRing, KeyError, KeyRingIdentifier};
//!
//! fn example() -> Result<KeyRing, KeyError> {
//!     // Obtain the default User keyring for the current UID/user
//!     // See [KeyRingIdentifier] and `man 2 ctl` for more information on default
//!     // keyrings for processes.
//!     let ring = KeyRing::from_special_id(KeyRingIdentifier::User, false)?;
//!
//!     // Insert
//!     Ok(ring)
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
