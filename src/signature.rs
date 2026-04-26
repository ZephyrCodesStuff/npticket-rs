use crate::version::Version;

/// The signature ID of the ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    /// ``PlayStation Network``, real PS3
    Console(Vec<u8>),

    /// ``RPCN``, RPCS3 emulator
    Emulator(Vec<u8>),
}

impl Default for Signature {
    fn default() -> Self {
        Self::Emulator(Vec::new())
    }
}

impl Signature {
    /// Get the data.
    pub fn signed_data(&self) -> &[u8] {
        match self {
            Self::Console(data) | Self::Emulator(data) => data,
        }
    }

    /// Length of the data to verify the signature against.
    pub fn signed_data_length(&self, ticket_version: Version) -> usize {
        match self {
            Self::Console(_) => {
                ticket_version.ticket_length() - (ticket_version.signature_length(self) + 16)
            }

            // The emulator only signs from 0x08 to 0xB0, skipping the first 8 bytes.
            // This is the entirety of the `user_data` section.
            Self::Emulator(_) => unimplemented!(),
        }
    }

    /// Deserialize a signature from a byte slice.
    ///
    /// `RPCN` signatures have the ID `RPCN`.
    /// All other signatures are considered `PSN` signatures.
    pub fn from_bytes(id: [u8; 4], data: &[u8]) -> Self {
        match &id {
            b"RPCN" => Self::Emulator(data.to_vec()),
            _ => Self::Console(data.to_vec()),
        }
    }
}
