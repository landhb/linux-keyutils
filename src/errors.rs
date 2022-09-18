use core::fmt::Debug;
use core::fmt::Display;
use core::fmt::Formatter;
use core::fmt::Result;

#[cfg(feature = "std")]
use std::error::Error;

/// Read errno
macro_rules! errno {
    () => {
        unsafe { *libc::__errno_location() }
    };
}

#[allow(dead_code)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LinuxError {
    /// The keyring wasn't available for modification by the user.
    AccessDenied,

    /// The key quota for this user would be exceeded by creating
    /// this key or linking it to the keyring.
    QuotaExceeded,

    /// One or more of type, description, and payload points outside
    /// process's accessible address space.
    BadAddress,

    /// Provided bad arguments
    InvalidArguments,

    /// The keyring has expired.
    KeyExpired,

    /// The keyring has been revoked.
    KeyRevoked,

    /// The attempt to generate a new key was rejected.
    KeyRejected,

    /// The keyring doesn't exist.
    KeyringDoesNotExist,

    /// Insufficient memory to create a key.
    OutOfMemory,

    /// Invalid Description
    InvalidDescription,

    /// An invalid identifier was returned
    InvalidIdentifier,

    /// Unknown - catch all, return this instead of panicing
    Unknown(i32),
}

impl Display for LinuxError {
    #[inline(always)]
    fn fmt(&self, f: &mut Formatter) -> Result {
        <LinuxError as Debug>::fmt(self, f)
    }
}

#[cfg(feature = "std")]
impl Error for LinuxError {}

#[cfg(feature = "std")]
pub fn get_libc_error() -> LinuxError {
    match errno!() {
        // Create Errors
        libc::EACCES => LinuxError::AccessDenied,
        libc::EDQUOT => LinuxError::QuotaExceeded,
        libc::EFAULT => LinuxError::BadAddress,
        libc::EINVAL => LinuxError::InvalidArguments,
        libc::EKEYEXPIRED => LinuxError::KeyExpired,
        libc::EKEYREVOKED => LinuxError::KeyRevoked,
        libc::EKEYREJECTED => LinuxError::KeyRejected,
        libc::ENOMEM => LinuxError::OutOfMemory,

        // Unknown, provide error code for debugging
        x => LinuxError::Unknown(x),
    }
}
