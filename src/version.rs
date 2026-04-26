use crate::signature::Signature;

/// The version of the ticket format.
///
/// It's either:
/// - 0x2100 for Version 2.0
/// - 0x2101 for Version 2.1
/// - 0x3100 for Version 3.0
/// - 0x4100 for Version 4.0
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// Version 2.0
    V2 = 0x2100,

    /// Version 2.1
    V2_1 = 0x2101,

    /// Version 3.0
    V3 = 0x3100,

    /// Version 4.0
    V4 = 0x4100,
}

impl Version {
    /// Get the version from a u16.
    pub const fn from_u16(version: u16) -> Option<Self> {
        match version {
            0x2100 => Some(Self::V2),
            0x2101 => Some(Self::V2_1),
            0x3100 => Some(Self::V3),
            0x4100 => Some(Self::V4),
            _ => None,
        }
    }

    /// Get the expected length of the ticket for this version.
    pub const fn ticket_length(self) -> usize {
        match self {
            Self::V2 | Self::V2_1 => 212,
            Self::V3 => 220,
            Self::V4 => 320,
        }
    }

    /// Length of the signature.
    pub fn signature_length(self, signature: &Signature) -> usize {
        match signature {
            // PS3 uses SHA-1 for V2 to V3, and SHA-256 for V4.
            Signature::Console(_) => match self {
                Self::V2 | Self::V2_1 | Self::V3 => 16,
                Self::V4 => 32,
            },

            Signature::Emulator(_) => unimplemented!(),
        }
    }
}
