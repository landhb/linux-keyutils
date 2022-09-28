use crate::ffi::{self, KeyCtlOperation, KeySerialId};
use crate::utils::String;
use crate::{KeyError, KeyPermissions, KeyType};
use core::fmt;

/// A key corresponding to a specific real ID.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Key(KeySerialId);

/// An entry description
#[derive(Debug, Clone)]
pub struct Description {
    ktype: KeyType,
    uid: u16,
    gid: u16,
    perm: KeyPermissions,
    description: String,
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let description = self.description().map_err(|_| fmt::Error::default())?;
        write!(f, "Key({})", description.description)
    }
}

impl Key {
    /// Initialize a new [Key] object from the provided ID
    pub fn from_id(id: KeySerialId) -> Self {
        Self(id)
    }

    /// Obtain a copy of the ID of this key
    pub fn get_id(&self) -> KeySerialId {
        self.0
    }

    /// Obtain a string describing the attributes of a specified key.
    ///
    /// The key must grant the caller view permission.
    ///
    /// The returned string contains the following information about
    /// the key:
    ///
    /// `type;uid;gid;perm;description`
    ///
    /// In the above, type and description are strings, uid and gid are
    /// decimal strings, and perm is a hexadecimal permissions mask.
    pub fn description(&self) -> Result<Description, KeyError> {
        let mut result = alloc::vec![0u8; 512];

        // Obtain the description from the kernel
        let len = ffi::keyctl!(
            KeyCtlOperation::Describe,
            self.0.as_raw_id() as libc::c_ulong,
            result.as_mut_ptr() as _,
            result.len() as _
        )? as usize;

        // Construct the string from the resulting data ensuring utf8 compat
        let s = core::str::from_utf8(&result[..len]).or(Err(KeyError::InvalidDescription))?;
        println!("{:?}", s);
        // Begin parsing
        let mut iter = s.split(';');

        // Create the description
        Ok(Description {
            ktype: iter
                .next()
                .and_then(|v| v.try_into().ok())
                .ok_or(KeyError::InvalidDescription)?,
            uid: iter
                .next()
                .and_then(|v| v.parse().ok())
                .ok_or(KeyError::InvalidDescription)?,
            gid: iter
                .next()
                .and_then(|v| v.parse().ok())
                .ok_or(KeyError::InvalidDescription)?,
            perm: KeyPermissions::from_u32(
                iter.next()
                    .and_then(|v| u32::from_str_radix(v, 16).ok())
                    .ok_or(KeyError::InvalidDescription)?,
            ),
            description: iter.next().ok_or(KeyError::InvalidDescription)?.to_string(),
        })
    }

    /// Read the payload data of a key.
    ///
    /// The key must either grant the caller read permission, or grant
    /// the caller search permission when searched for from the process
    /// keyrings (i.e., the key is possessed).
    pub fn read<T: AsMut<[u8]>>(&self, buffer: &mut T) -> Result<usize, KeyError> {
        // TODO: alternate key types? Currenlty we don't support KeyType::BigKey
        let len = ffi::keyctl!(
            KeyCtlOperation::Read,
            self.0.as_raw_id() as libc::c_ulong,
            buffer.as_mut().as_mut_ptr() as _,
            buffer.as_mut().len() as _
        )? as usize;
        Ok(len)
    }

    /// Update a key's data payload.
    ///
    /// The caller must have write permission on the key specified and the key
    /// type must support updating.
    ///
    /// A negatively instantiated key (see the description of [Key::reject])
    /// can be positively instantiated with this operation.
    pub fn update<T: AsRef<[u8]>>(&self, update: &T) -> Result<(), KeyError> {
        _ = ffi::keyctl!(
            KeyCtlOperation::Update,
            self.0.as_raw_id() as libc::c_ulong,
            update.as_ref().as_ptr() as _,
            update.as_ref().len() as _
        )?;
        Ok(())
    }

    /// Change the permissions of the key with the ID provided
    ///
    /// If the caller doesn't have the CAP_SYS_ADMIN capability, it can change
    /// permissions only only for the keys it owns. (More precisely: the caller's
    /// filesystem UID must match the UID of the key.)
    pub fn set_perm(&self, perm: KeyPermissions) -> Result<(), KeyError> {
        _ = ffi::keyctl!(
            KeyCtlOperation::SetPerm,
            self.0.as_raw_id() as libc::c_ulong,
            perm.bits() as _
        )?;
        Ok(())
    }

    /// Change the ownership (user and group ID) of a key.
    ///
    /// For the UID to be changed, or for the GID to be changed to a group
    /// the caller is not a member of, the caller must have the CAP_SYS_ADMIN
    /// capability (see capabilities(7)).
    ///
    /// If the UID is to be changed, the new user must have sufficient quota
    /// to accept the key. The quota deduction will be removed from the old
    /// user to the new user should the UID be changed.
    pub fn chown(&self, uid: Option<u32>, gid: Option<u32>) -> Result<(), KeyError> {
        let uid_opt = uid.unwrap_or(u32::MAX);
        let gid_opt = gid.unwrap_or(u32::MAX);
        _ = ffi::keyctl!(
            KeyCtlOperation::Chown,
            self.0.as_raw_id() as libc::c_ulong,
            uid_opt as _,
            gid_opt as _
        )?;
        Ok(())
    }

    /// Set a timeout on a key.
    ///
    /// Specifying the timeout value as 0 clears any existing timeout on the key.
    ///
    /// The `/proc/keys` file displays the remaining time until each key will expire.
    /// (This is the only method of discovering the timeout on a key.)
    ///
    /// The caller must either have the setattr permission on the key or hold an
    /// instantiation authorization token for the key.
    ///
    /// The key and any links to the key will be automatically garbage collected
    /// after the  timeout  expires. Subsequent attempts to access the key will
    /// then fail with the error EKEYEXPIRED.
    ///
    /// This operation cannot be used to set timeouts on revoked, expired, or
    /// negatively instantiated keys.
    pub fn set_timeout(&self, seconds: usize) -> Result<(), KeyError> {
        _ = ffi::keyctl!(
            KeyCtlOperation::SetTimeout,
            self.0.as_raw_id() as libc::c_ulong,
            seconds as _
        )?;
        Ok(())
    }

    /// Revoke this key. Similar to [Key::reject] just without the timeout.
    ///
    /// The key is scheduled for garbage collection; it will no longer be findable,
    /// and will be unavailable for further operations. Further attempts to use the
    /// key will fail with the error `EKEYREVOKED`.
    ///
    /// The caller must have write or setattr permission on the key.
    pub fn revoke(&self) -> Result<(), KeyError> {
        _ = ffi::keyctl!(KeyCtlOperation::Revoke, self.0.as_raw_id() as libc::c_ulong)?;
        Ok(())
    }

    /// Mark a key as negatively instantiated and set an expiration timer on the key.
    ///
    /// This will prevent others from retrieving the key in further searches. And they
    /// will receive a `EKEYREJECTED` error when performing the search.
    ///
    /// Similar to [Key::revoke] but with a timeout.
    pub fn reject(&self, seconds: usize) -> Result<(), KeyError> {
        _ = ffi::keyctl!(
            KeyCtlOperation::Reject,
            self.0.as_raw_id() as libc::c_ulong,
            seconds as _,
            libc::EKEYREJECTED as _
        )?;
        Ok(())
    }

    /// Mark a key as invalid.
    ///
    /// To invalidate a key, the caller must have search permission on the
    /// key.
    ///
    /// This operation marks the key as invalid and schedules immediate
    /// garbage collection. The garbage collector removes the invali‐
    /// dated key from all keyrings and deletes the key when  its  refer‐
    /// ence count reaches zero. After this operation, the key will be
    /// ignored by all searches, even if it is not yet deleted.
    ///
    /// Keys that are marked invalid become invisible to normal key oper‐
    /// ations  immediately,  though they are still visible in `/proc/keys`
    /// (marked with an 'i' flag) until they are actually removed.
    pub fn invalidate(&self) -> Result<(), KeyError> {
        ffi::keyctl!(
            KeyCtlOperation::Invalidate,
            self.0.as_raw_id() as libc::c_ulong
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyRing, KeyRingIdentifier, Permission};
    use zeroize::Zeroizing;

    #[test]
    fn test_user_keyring_add_key() {
        let secret = "Test Data";

        // Obtain the default User keyring
        let ring = KeyRing::from_special_id(KeyRingIdentifier::Session, false).unwrap();

        // Create the key
        let key = ring.add_key("my-super-secret-test-key", secret).unwrap();

        // A buffer that is ensured to be zeroed when
        // out of scope
        let mut buf = Zeroizing::new([0u8; 4096]);

        // Allow P/U/G full permissions
        let mut perms = KeyPermissions::new();
        perms.set_posessor_perms(Permission::ALL);
        perms.set_user_perms(Permission::ALL);
        perms.set_group_perms(Permission::ALL);

        // Set the permissions
        key.set_perm(perms).unwrap();

        // Read the secret and verify it matches
        let len = key.read(&mut buf).unwrap();
        assert_eq!(secret.as_bytes(), &buf[..len]);

        // Update it
        key.update(&"wow".as_bytes()).unwrap();

        // Verify it matches the new content
        let len = key.read(&mut buf).unwrap();
        assert_eq!("wow".as_bytes(), &buf[..len]);
        key.invalidate().unwrap()
    }
}
