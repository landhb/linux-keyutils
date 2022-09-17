mod ffi;

// Expose types
mod types;
pub use types::*;

// Expose KeyPermissions API
mod permissions;
pub use permissions::KeyPermissions;

/// Serial Number for a Key
///
/// Returned by the kernel.
type KeySerialId = i32;

/// The key type is a string that specifies the key's type. Internally, the kernel
/// defines a number of key types that are available in the core key management code.
/// Among the types that are available for user-space use and can be specified as the
/// type argument to add_key() are the following:
pub enum KeyTypes {
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

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
