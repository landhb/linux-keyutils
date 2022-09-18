#![cfg_attr(not(feature = "std"), no_std)]

// no_std CStr/CString support stabilized in Rust 1.64.0
// CString requires alloc however
extern crate alloc;

// Internal FFI for raw syscalls
mod ffi;

// Expose error types
mod errors;
pub use errors::KeyError;

// Primary keyctl interface
mod keyctl;
pub use keyctl::KeyCtl;

// Expose KeyPermissions API
mod permissions;
pub use permissions::KeyPermissions;
