#![cfg_attr(not(feature = "std"), no_std)]

mod ffi;

extern crate alloc;

use alloc::ffi::CString;
use core::ffi::CStr;

mod errors;
pub use errors::LinuxError;

// Expose types
mod types;
pub use types::*;

// Expose KeyPermissions API
mod permissions;
pub use permissions::KeyPermissions;

/// Serial Number for a Key
///
/// Returned by the kernel.
struct KeySerialId(i32);

/// The key type is a string that specifies the key's type. Internally, the kernel
/// defines a number of key types that are available in the core key management code.
/// Among the types that are available for user-space use and can be specified as the
/// type argument to add_key() are the following:
pub enum KeyType {
    /// Keyrings  are  special  key  types that may contain links to sequences of other
    /// keys of any type.  If this interface is used to create a keyring, then payload
    /// should be NULL and plen should be zero.
    KeyRing,
    /// This is a general purpose key type whose payload may be read and updated by
    /// user-space  applications. The  key is kept entirely within kernel memory.
    /// The payload for keys of this type is a blob of arbitrary data of up to 32,767 bytes.
    User,
    /// This key type is essentially the same as "user", but it does not permit the key
    /// to read. This is suitable for storing payloads that you do not want to be
    /// readable from user space.
    Logon,
    /// This key type is similar to "user", but may hold a payload of up to 1 MiB.
    /// If the key payload is large  enough, then it may be stored encrypted in
    /// tmpfs (which can be swapped out) rather than kernel memory.
    BigKey,
}

/// Perform the conversion here so that alternative cstrings cannot be used.
/// Using Rust's type system to ensure only valid key types are used.
impl From<KeyType> for &'static CStr {
    fn from(t: KeyType) -> &'static CStr {
        unsafe {
            match t {
                KeyType::KeyRing => CStr::from_bytes_with_nul_unchecked(b"keyring\0"),
                KeyType::User => CStr::from_bytes_with_nul_unchecked(b"user\0"),
                KeyType::Logon => CStr::from_bytes_with_nul_unchecked(b"logon\0"),
                KeyType::BigKey => CStr::from_bytes_with_nul_unchecked(b"big_key\0"),
            }
        }
    }
}

/// add_key() creates or updates a key of the given type and description, instantiates
/// it with the payload of length plen, attaches it to the nominated keyring, and
/// returns the key's serial number.
///
/// The key may be rejected if the provided data is in the wrong format or it is invalid
/// in some other way. If the destination keyring already contains a key that matches the
/// specified type and description, then, if the key type supports it, that key will be
/// updated rather than a new key being created; if not, a new key (with a different ID)
/// will be created and it will displace the link to the extant key from the keyring.
///
/// The destination keyring serial number may be that of a valid keyring for which the
/// caller has write  permission.  Alternatively, it may be one of the following special
/// keyring IDs:
fn add_key(
    ktype: KeyType,
    description: &str,
    payload: &[u8],
    keyring: KeyringIdentifier,
) -> Result<KeySerialId, LinuxError> {
    // Perform conversion into a c string
    let description = CString::new(description).or(Err(LinuxError::InvalidDescription))?;

    // Perform the actual system call
    let res = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            Into::<&'static CStr>::into(ktype).as_ptr(),
            description.as_ptr(),
            payload.as_ptr(),
            payload.len() as libc::size_t,
            keyring as i32,
        )
    };

    // Return the underlying error
    if res < 0 {
        return Err(crate::errors::get_libc_error());
    }

    // Otherwise return the ID
    Ok(KeySerialId(
        res.try_into().or(Err(LinuxError::InvalidIdentifier))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        add_key(
            KeyType::User,
            "Test Key",
            "Test Data".as_bytes(),
            KeyringIdentifier::UserSession,
        )
        .unwrap();
    }
}
