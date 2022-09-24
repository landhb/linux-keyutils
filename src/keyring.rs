use crate::ffi::{self, KeyCtlOperation};
use crate::{Key, KeyError, KeyRingIdentifier, KeySerialId, KeyType};

/// Rust Interface for KeyRing operations using the kernel
/// provided keyrings. Used to locate, create, search, add,
/// and remove keys to & from keyrings.
#[derive(Copy, Clone)]
pub struct KeyRing {
    id: KeySerialId,
}

impl KeyRing {
    /// Obtain a KeyRing directly from its ID
    pub const fn from_id(id: KeySerialId) -> Self {
        Self { id }
    }

    /// Obtain a KeyRing from its special identifier.
    ///
    /// If the create argument is true, then this method will
    /// attempt to create the keyring. Otherwise it will only
    /// succeed if the keyring already exists and is valid.
    ///
    /// Internally this uses KEYCTL_GET_KEYRING_ID to resolve
    /// a keyrings real ID from the special identifier.
    pub fn from_special_id(id: KeyRingIdentifier, create: bool) -> Result<Self, KeyError> {
        let id: i32 = ffi::keyctl!(
            KeyCtlOperation::GetKeyRingId,
            id as libc::c_ulong,
            if create { 1 } else { 0 }
        )?
        .try_into()
        .or(Err(KeyError::KeyringDoesNotExist))?;
        Ok(Self {
            id: KeySerialId(id),
        })
    }

    /// Creates or updates a key of the given type and description, instantiates
    /// it with the payload of length plen, attaches it to the User keyring.
    ///
    /// If the destination keyring already contains a key that matches
    /// the specified type and description, then, if the key type supports
    /// it, that key will be updated rather than a new key being created;
    /// if not, a new key (with a different ID) will be created and it will
    /// displace the link to the extant key from the keyring.
    pub fn create<D: AsRef<str> + ?Sized, S: AsRef<[u8]> + ?Sized>(
        &self,
        description: &D,
        secret: &S,
    ) -> Result<Key, KeyError> {
        let id = ffi::add_key(
            KeyType::User,
            self.id.as_raw_id() as libc::c_ulong,
            description.as_ref(),
            secret.as_ref(),
        )?;
        Ok(Key::from_id(id))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_from_special_id() {
        // Test that a keyring that normally doesn't exist by default is
        // created when called.
        let ring = KeyRing::from_special_id(KeyRingIdentifier::Thread, true).unwrap();
        assert!(ring.id.as_raw_id() > 0);

        // Test that a keyring that should already exist is returned
        let ring = KeyRing::from_special_id(KeyRingIdentifier::User, false).unwrap();
        assert!(ring.id.as_raw_id() > 0);
    }
}
