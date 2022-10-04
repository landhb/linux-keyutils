use crate::{Key, KeyError, KeyRing, KeySerialId, KeyType, Metadata};
use core::cmp::PartialEq;

/// An item/node linked to a ring. Both keys and other keyrings
/// can be linked to a particular keyring.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum LinkNode {
    KeyRing(KeyRing),
    Key(Key),
}

impl LinkNode {
    pub(crate) fn from_id(id: KeySerialId) -> Result<Self, KeyError> {
        let metadata = Metadata::from_id(id)?;
        let node = match metadata.get_type() {
            KeyType::KeyRing => Self::KeyRing(KeyRing::from_id(id)),
            KeyType::User => Self::Key(Key::from_id(id)),
            _ => return Err(KeyError::OperationNotSupported),
        };
        Ok(node)
    }
}

impl PartialEq<Key> for LinkNode {
    fn eq(&self, other: &Key) -> bool {
        matches!(self, LinkNode::Key(x) if x == other)
    }
}

impl PartialEq<Key> for &LinkNode {
    fn eq(&self, other: &Key) -> bool {
        matches!(self, LinkNode::Key(x) if x == other)
    }
}

impl PartialEq<KeyRing> for LinkNode {
    fn eq(&self, other: &KeyRing) -> bool {
        matches!(self, LinkNode::KeyRing(x) if x == other)
    }
}

impl PartialEq<KeyRing> for &LinkNode {
    fn eq(&self, other: &KeyRing) -> bool {
        matches!(self, LinkNode::KeyRing(x) if x == other)
    }
}
