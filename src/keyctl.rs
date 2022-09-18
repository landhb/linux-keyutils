use crate::ffi::{keyctl_impl, KeyCtlOperation, KeySerialId};
use crate::keyctl;
use crate::KeyError;
use core::ffi::CStr;
use core::fmt;

/// Rust Interface for KeyCtl operations using the kernel
/// provided keyrings. Each method is implemented to leverage
/// Rust strict typing.
pub struct KeyCtl(KeySerialId);

impl fmt::Display for KeyCtl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let description = self.description().or(Err(fmt::Error::default()))?;
        write!(f, "KeyCtl({})", description)
    }
}

impl KeyCtl {
    /// Initialize a new `KeyCtl` object from the provided ID
    pub fn from_id(id: KeySerialId) -> Self {
        Self(id)
    }

    /// Obtain a string describing the attributes of a specified key.
    ///
    /// The key must grant the caller view permission.
    ///
    /// The returned string is null-terminated and contains the following
    /// information about the key:
    ///
    /// type;uid;gid;perm;description
    ///
    /// In the above, type and description are strings, uid and gid are
    /// decimal strings, and perm is a hexadecimal permissions mask.
    pub fn description(&self) -> Result<String, KeyError> {
        let mut result = vec![0u8; 512];

        // Obtain the description from the kernel
        let len = keyctl!(
            KeyCtlOperation::Describe,
            self.0.as_raw_id() as libc::c_ulong,
            result.as_mut_ptr() as _,
            result.len() as _
        )?;

        // Construct the string from the resulting data ensuring utf8 compat
        Ok(String::from_utf8(result).or(Err(KeyError::InvalidDescription))?)
    }

    /// Read the payload data of a key.
    pub fn read(&self, buffer: &mut [u8]) -> Result<usize, KeyError> {
        let len = keyctl!(
            KeyCtlOperation::Read,
            self.0.as_raw_id() as libc::c_ulong,
            buffer.as_mut_ptr() as _,
            buffer.len() as _
        )? as usize;
        Ok(len)
    }

    /// Update a key's data payload.
    ///
    /// The caller must have write permission on the key specified and the key
    /// type must support updating.
    ///
    /// A  negatively  instantiated key (see the description of `KeyCtl::reject`)
    /// can be positively instantiated with this operation.
    pub fn update(&self) -> Result<(), KeyError> {
        Ok(())
    }

    /// Change the permissions of the key with the ID provided
    ///
    /// If the caller doesn't have the CAP_SYS_ADMIN capability, it can change
    /// permissions only only for the keys it owns. (More precisely: the caller's
    /// filesystem UID must match the UID of the key.)
    pub fn set_perm(&self, perm: u32) -> Result<(), KeyError> {
        _ = keyctl!(
            KeyCtlOperation::SetPerm,
            self.0.as_raw_id() as libc::c_ulong,
            perm as _
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
    pub fn chown(&self, uid: i32, gid: i32) -> Result<(), KeyError> {
        //_ = keyctl!(KeyCtlOperation::Chown, self.0.as_raw_id() as libc::c_ulong)?;
        Ok(())
    }

    /*pub fn clear_keyring(&self) -> Result<(), KeyError> {
        keyctl!(KeyCtlOperation::Clear, self.0.as_raw_id() as libc::c_ulong)?;
        Ok(())
    }*/

    /// Mark a key as invalid.
    ///
    /// To invalidate a key, the caller must have search permission on the
    /// key.
    ///
    /// This operation marks the key as invalid and  schedules  immediate
    /// garbage  collection.   The  garbage collector removes the invali‐
    /// dated key from all keyrings and deletes the key when  its  refer‐
    /// ence  count  reaches zero.  After this operation, the key will be
    /// ignored by all searches, even if it is not yet deleted.
    ///
    /// Keys that are marked invalid become invisible to normal key oper‐
    /// ations  immediately,  though they are still visible in /proc/keys
    /// (marked with an 'i' flag) until they are actually removed.
    pub fn invalidate(&self) -> Result<(), KeyError> {
        keyctl!(
            KeyCtlOperation::Invalidate,
            self.0.as_raw_id() as libc::c_ulong
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::{self, KeyType, KeyringIdentifier};

    #[test]
    fn test_user_keyring_add_key() {
        let secret = "Test Data";
        let id = ffi::add_key(
            KeyType::User,
            KeyringIdentifier::User,
            "my-super-secret-test-key",
            secret.as_bytes(),
        )
        .unwrap();
        let mut buf = [0u8; 4096];

        let keyctl = KeyCtl::from_id(id);
        println!("{}", keyctl);
        keyctl.set_perm(0x3f3f0000).unwrap();
        let len = keyctl.read(&mut buf).unwrap();
        assert_eq!(secret.as_bytes(), &buf[..len]);
        keyctl.invalidate().unwrap()
    }
}
