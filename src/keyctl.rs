use crate::{KeyError, KeySerialId};

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
    pub fn read() -> Result<(), KeyError> {
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
