//! Create a more rust-like permissions construct, ported from the unix
//! permissions defined in keyutils.h

/// Key Handle Permissions Mask
///
/// Returned by the kernel.
pub struct KeyPermissions(u32);

/// Builder for permissions
pub struct KeyPermissionsBuilder;

impl KeyPermissions {
    pub fn new() -> Self {
        Self(0)
    }
}
