//! Definitions ported from the C keyutils library
//!
#[allow(dead_code)]
pub enum KeyringIdentifier {
    /// Key ID for thread-specific keyring
    Thread = -1,
    /// Key ID for process-specific keyring
    Process = -2,
    /// Key ID for session-specific keyring
    Session = -3,
    /// Key ID for UID-specific keyring
    User = -4,
    /// Key ID for UID-session keyring
    UserSession = -5,
    /// Key ID for GID-specific keyring
    Group = -6,
    /// Key ID for assumed request_key auth key
    ReqKeyAuthKey = -7,
}

#[allow(dead_code)]
pub enum DefaultKeyring {
    NoChange = -1,
    Default = 0,
    Thread = 1,
    Process = 2,
    Session = 3,
    User = 4,
    UserSession = 5,
    Group = 6,
}

#[allow(dead_code)]
#[repr(u32)]
pub enum KeyCtlOperation {
    /// Ask for a keyring's ID
    GetKeyRingId = libc::KEYCTL_GET_KEYRING_ID,
    /// Join or start named session keyring
    JoinSessionKeyRing = libc::KEYCTL_JOIN_SESSION_KEYRING,
    /// Update a key
    Update = libc::KEYCTL_UPDATE,
    /// Revoke a key
    Revoke = libc::KEYCTL_REVOKE,
    /// Set ownership of a key
    Chown = libc::KEYCTL_CHOWN,
    /// Set permissions of a key
    SetPerm = libc::KEYCTL_SETPERM,
    /// Describe a key
    Describe = libc::KEYCTL_DESCRIBE,
    /// Clear contents of a keyring
    Clear = libc::KEYCTL_CLEAR,
    /// Link a key into a keyring
    Link = libc::KEYCTL_LINK,
    /// Unlink a key from a keyring
    Unlink = libc::KEYCTL_UNLINK,
    /// Search for a key in a keyring
    Search = libc::KEYCTL_SEARCH,
    /// Read a key or keyring's contents
    Read = libc::KEYCTL_READ,
    /// Instantiate a partially constructed key
    Instantiate = libc::KEYCTL_INSTANTIATE,
    /// Negate a partially constructed key
    Negate = libc::KEYCTL_NEGATE,
    /// Set default request-key keyring
    SetRequestKeyKeyring = libc::KEYCTL_SET_REQKEY_KEYRING,
    /// Set timeout on a key
    SetTimeout = libc::KEYCTL_SET_TIMEOUT,
    /// Assume authority to instantiate key
    AssumeAuthority = libc::KEYCTL_ASSUME_AUTHORITY,
    /// Get key security label
    GetSecurityLabel = libc::KEYCTL_GET_SECURITY,
    /// Set my session keyring on my parent process
    SessionToParent = libc::KEYCTL_SESSION_TO_PARENT,
    /// Reject a partially constructed key
    Reject = libc::KEYCTL_REJECT,
    /// Instantiate a partially constructed key
    InstantiageIov = libc::KEYCTL_INSTANTIATE_IOV,
    /// Invalidate a key
    Invalidate = libc::KEYCTL_INVALIDATE,
    /// Get a user's persistent keyring
    GetPersistent = libc::KEYCTL_GET_PERSISTENT,
    /// Compute Diffie-Hellman values
    DiffieHellmanCompute = libc::KEYCTL_DH_COMPUTE,
    /// Query public key parameters
    PubkeyQuery = libc::KEYCTL_PKEY_QUERY,
    /// Encrypt a blob using a public key
    PubkeyEncrypt = libc::KEYCTL_PKEY_ENCRYPT,
    /// Decrypt a blob using a public key
    PubkeyDecrypt = libc::KEYCTL_PKEY_DECRYPT,
    /// Create a public key signature
    PubkeySign = libc::KEYCTL_PKEY_SIGN,
    /// Verify a public key signature
    PubkeyVerify = libc::KEYCTL_PKEY_VERIFY,
    /// Restrict keys allowed to link to a keyring
    RestrictKeyring = libc::KEYCTL_RESTRICT_KEYRING,
    /// Move keys between keyrings
    Move = libc::KEYCTL_MOVE,
    /// Find capabilities of keyrings subsystem
    Capabilities = libc::KEYCTL_CAPABILITIES,
    /// Watch a key or ring of keys for changes
    WatchKey = 32,
}
