use crate::ffi::{keyctl_impl, KeyCtlOperation, KeySerialId};
use crate::keyctl;
use crate::KeyError;

/// Rust Interface for KeyCtl operations using the kernel
/// provided keyrings. Each method is implemented to leverage
/// Rust strict typing.
pub struct KeyCtl(KeySerialId);

impl KeyCtl {
    /// Initialize a new `KeyCtl` object from the provided ID
    pub fn from_id(id: KeySerialId) -> Self {
        Self(id)
    }

    /// Read the payload data of a key.
    pub fn read(&self) -> Result<(), KeyError> {
        let mut buf = [0u8; 2048];
        let len = keyctl!(
            KeyCtlOperation::Read,
            self.0.as_raw_id() as libc::c_ulong,
            buf.as_mut_ptr() as _,
            buf.len() as _
        )? as usize;
        println!("{:?}", &buf[..len]);
        Ok(())
    }

    pub fn set_perm(&self, perm: u32) -> Result<(), KeyError> {
        let len = keyctl!(
            KeyCtlOperation::SetPerm,
            self.0.as_raw_id() as libc::c_ulong,
            perm as _
        )? as usize;
        Ok(())
    }

    pub fn clear(&self) -> Result<(), KeyError> {
        keyctl!(KeyCtlOperation::Clear, self.0.as_raw_id() as libc::c_ulong)?;
        Ok(())
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::{self, KeyType, KeyringIdentifier};

    #[test]
    fn it_works() {
        let id = ffi::add_key(
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
