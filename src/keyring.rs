use crate::ffi::{self, KeyCtlOperation};
use crate::{Key, KeyError, KeyRingIdentifier, KeySerialId, KeyType};
use alloc::ffi::CString;
use core::convert::TryInto;
use core::ffi::CStr;

/// Rust Interface for KeyRing operations using the kernel
/// provided keyrings. Used to locate, create, search, add,
/// and remove keys to & from keyrings.
#[derive(Debug, Copy, Clone)]
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
        let id: KeySerialId = ffi::keyctl!(
            KeyCtlOperation::GetKeyRingId,
            id as libc::c_ulong,
            if create { 1 } else { 0 }
        )?
        .try_into()
        .or(Err(KeyError::InvalidIdentifier))?;
        Ok(Self { id })
    }

    /// Creates or updates a key of the given type and description, instantiates
    /// it with the payload of length plen, attaches it to the User keyring.
    ///
    /// If the destination keyring already contains a key that matches
    /// the specified type and description, then, if the key type supports
    /// it, that key will be updated rather than a new key being created;
    /// if not, a new key (with a different ID) will be created and it will
    /// displace the link to the extant key from the keyring.
    pub fn add_key<D: AsRef<str> + ?Sized, S: AsRef<[u8]> + ?Sized>(
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

    /// Search for a key in a keyring tree, returning its ID and optionally linking
    /// it to a specified keyring.
    ///
    /// The tree to be searched is specified by passing the ID of the head keyring
    /// in arg2 (cast to key_serial_t). The search is performed breadth-first and
    /// recursively.
    ///
    /// The source keyring must grant search permission to the caller. When
    /// performing the recursive search, only keyrings that grant the caller search
    /// permission will be searched. Only keys with for which the caller has
    /// search permission can be found.
    ///
    /// If the key is found, its ID is returned as the function result.
    pub fn search<D: AsRef<str> + ?Sized>(&self, description: &D) -> Result<Key, KeyError> {
        // The provided description must be properly null terminated for the kernel
        let description =
            CString::new(description.as_ref()).or(Err(KeyError::InvalidDescription))?;

        // Perform the raw syscall and validate that the result is a valid ID
        let id: KeySerialId = ffi::keyctl!(
            KeyCtlOperation::Search,
            self.id.as_raw_id() as libc::c_ulong,
            Into::<&'static CStr>::into(KeyType::User).as_ptr() as _,
            description.as_ptr() as _,
            0
        )?
        .try_into()
        .or(Err(KeyError::InvalidIdentifier))?;

        // Construct a key object from the ID
        Ok(Key::from_id(id))
    }

    /// Create a link from a keyring to a key.
    ///
    /// If a key with the same type and description is already linked in the keyring,
    /// then that key is displaced from the keyring.
    ///
    /// Before  creating  the  link,  the  kernel  checks the nesting of the keyrings
    /// and returns appropriate errors if the link would produce a cycle or if the
    /// nesting of keyrings would be too deep (The limit on the nesting of keyrings is
    /// determined by the kernel constant KEYRING_SEARCH_MAX_DEPTH, defined with the
    /// value 6, and is necessary to prevent overflows on the kernel stack when
    /// recursively searching keyrings).
    ///
    /// The caller must have link permission on the key being added and write
    /// permission on the keyring.
    pub fn link_key() {}

    /// Unlink a key from a keyring.
    ///
    /// If the key is not currently linked into the keyring, an error results. If the
    /// last link to a key is removed, then that key will be scheduled for destruction.
    ///
    /// The caller must have write permission on the keyring from which the key is being
    /// removed.
    pub fn unlink_key() {}

    /// Clear the contents of (i.e., unlink all keys from) this keyring.
    ///
    /// The caller must have write permission on the keyring.
    pub fn clear(&self) {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{KeyPermissionsBuilder, Permission};

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

    #[test]
    fn test_search_existing_key() {
        // Test that a keyring that normally doesn't exist by default is
        // created when called.
        let ring = KeyRing::from_special_id(KeyRingIdentifier::Session, false).unwrap();
        let key = ring.add_key("test_search", b"data").unwrap();

        // Ensure we have search permission on the key
        let perms = KeyPermissionsBuilder::builder()
            .posessor(Permission::ALL)
            .user(Permission::ALL)
            .build();

        // Enforce perms
        key.set_perm(perms).unwrap();

        // Search should succeed
        let result = ring.search("test_search").unwrap();

        // Assert that the ID is the same
        assert_eq!(key.get_id(), result.get_id());

        // Invalidate the key
        key.invalidate().unwrap();
    }

    #[test]
    fn test_search_non_existing_key() {
        // Test that a keyring that normally doesn't exist by default is
        // created when called.
        let ring = KeyRing::from_special_id(KeyRingIdentifier::Session, false).unwrap();

        // Search should succeed
        let result = ring.search("test_search_no_exist");

        // Assert that the ID is the same
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), KeyError::KeyDoesNotExist);
    }
}
