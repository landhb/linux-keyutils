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
pub enum CommandOptions {
    /// Ask for a keyring's ID
    GetKeyRingId = 0,
    /// Join or start named session keyring
    JoinSessionKeyRing = 1,
    /// Update a key
    Update = 2,
    /// Revoke a key
    Revoke = 3,
    /// Set ownership of a key
    Chown = 4,
    /// Set permissions of a key
    SetPerm = 5,
    /// Describe a key
    Describe = 6,
    /// Clear contents of a keyring
    Clear = 7,
    /// Link a key into a keyring
    Link = 8,
    /// Unlink a key from a keyring
    Unlink = 9,
    /// Search for a key in a keyring
    Search = 10,
    /// Read a key or keyring's contents
    Read = 11,
    /// Instantiate a partially constructed key
    Instantiate = 12,
    /// Negate a partially constructed key
    Negate = 13,
    /// Set default request-key keyring
    SetRequestKeyKeyring = 14,
    /// Set timeout on a key
    SetTimeout = 15,
    /// Assume authority to instantiate key
    AssumeAuthority = 16,
    /// Get key security label
    GetSecurityLabel = 17,
    /// Set my session keyring on my parent process
    SessionToParent = 18,
    /// Reject a partially constructed key
    Reject = 19,
    /// Instantiate a partially constructed key
    InstantiageIov = 20,
    /// Invalidate a key
    Invalidate = 21,
    /// Get a user's persistent keyring
    GetPersistent = 22,
    /// Compute Diffie-Hellman values
    DiffieHellmanCompute = 23,
    /// Query public key parameters
    PubkeyQuery = 24,
    /// Encrypt a blob using a public key
    PubkeyEncrypt = 25,
    /// Decrypt a blob using a public key
    PubkeyDecrypt = 26,
    /// Create a public key signature
    PubkeySign = 27,
    /// Verify a public key signature
    PubkeyVerify = 28,
    /// Restrict keys allowed to link to a keyring
    RestrictKeyring = 29,
    /// Move keys between keyrings
    Move = 30,
    /// Find capabilities of keyrings subsystem
    Capabilities = 31,
    /// Watch a key or ring of keys for changes
    WatchKey = 32,
}
