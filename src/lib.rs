//! A ``PlayStation Network`` ticket for authenticating requests.
//!
//! The ticket is cryptographically signed and contains the user's
//! username, alongside other data, which we can use to identify them.

use base64::Engine;
use ecdsa::elliptic_curve::pkcs8::DecodePublicKey;
use ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p192::NistP192;
use p224::secp224k1::Secp224k1;
use p256::NistP256;
use serde::{Deserialize, Deserializer};
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256};

// Re-export as well for convenience
pub use crate::signature::Signature;
pub use crate::ticket_data::TicketData;
pub use crate::version::Version;

mod signature;
mod ticket_data;
mod version;

/// Default domain RPCN sets for players.
pub const DEFAULT_DOMAIN: &str = "un";

/// Default region RPCN sets for players.
pub const DEFAULT_REGION: &str = "br";

/// A ``PlayStation Network`` ticket for authenticating requests.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Ticket {
    /// The ticket's serial number.
    pub serial: String,

    /// The issuer's ID.
    pub issuer_id: u32,

    /// The issued date as a UNIX timestamp.
    pub issued_at: u64,

    /// The expiration date as a UNIX timestamp.
    pub expires_at: u64,

    /// The account ID of the user.
    pub account_id: u64,

    /// The username of the user.
    pub username: String,

    /// The region the user is in.
    pub region: String,

    /// The domain the user is in.
    pub domain: String,

    /// The service ID the ticket was issued for.
    pub service_id: String,

    /// Status of the ticket (seems to be always 0)
    pub status: u32,

    /// The ticket's signature
    pub signature: Signature,
}

impl<'de> Deserialize<'de> for Ticket {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize from a base64 string.
        let base64 = String::deserialize(deserializer)?;

        // Decode the base64 string.
        let engine = base64::engine::general_purpose::STANDARD;
        let mut decoded = engine.decode(base64).map_err(serde::de::Error::custom)?;

        // Deserialize the ticket from the decoded bytes.
        let ticket = Self::from_bytes(&mut decoded).map_err(serde::de::Error::custom)?;

        Ok(ticket)
    }
}

impl Ticket {
    /// Decode a string from a byte slice.
    fn decode_string(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes)
            .trim_end_matches('\0')
            .to_string()
    }

    /// Make sure `issued_at` and `expires_at` make sense.
    ///
    /// - `issued_at` and `expires_at` must be non-zero.
    /// - `expires_at` must be after `issued_at`.
    /// - `issued_at` must not be in the future (with a 5 minute leeway).
    /// - `issued_at` and `expires_at` must not be more than 1 year in the future.
    ///
    /// The dates are assumed to be in milliseconds.
    fn validate_dates(issued_at: u64, expires_at: u64) -> Result<(), &'static str> {
        if issued_at == 0 || expires_at == 0 {
            return Err("Invalid issued or expiration date");
        }

        if expires_at <= issued_at {
            return Err("Expiration date is before issued date");
        }

        // Check if issued_at is in the future (with a 5 minute leeway)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "System time before UNIX EPOCH")?
            .as_secs();

        if issued_at > now * 1000 + 300 * 1000 {
            return Err("Issued date is in the future");
        }

        // Check if expires_at is too far in the future (more than 1 year)
        if expires_at > now * 1000 + 31_536_000 * 1000 {
            return Err("Issued or expiration date is too far in the future");
        }

        Ok(())
    }

    /// Deserialize a ticket from a byte slice.
    /// This will also verify the ticket's signature.
    ///
    /// `bytes` must be mutable, as the function may modify it
    /// to fix endianness issues with the timestamps.
    #[allow(clippy::too_many_lines)]
    pub fn from_bytes(bytes: &mut [u8]) -> Result<Self, &'static str> {
        let mut ticket = Self::default();

        if bytes.is_empty() {
            return Err("Empty buffer");
        }

        let version = u16::from_be_bytes([bytes[0], bytes[1]]);
        let version = Version::from_u16(version).ok_or("Unsupported version")?;

        if bytes.len() < 212 || bytes.len() > 400 {
            return Err("Invalid buffer length");
        }

        // Helper function to handle endianness issues with timestamps
        let parse_timestamps = |bytes: &mut [u8],
                                issued_range: std::ops::Range<usize>,
                                expires_range: std::ops::Range<usize>|
         -> Result<(u64, u64), &'static str> {
            let mut issued_at = u64::from_be_bytes(bytes[issued_range.clone()].try_into().unwrap());
            let mut expires_at =
                u64::from_be_bytes(bytes[expires_range.clone()].try_into().unwrap());

            // If validation fails, try swapping endianness
            if Self::validate_dates(issued_at, expires_at).is_err() {
                bytes[issued_range.clone()].reverse();
                bytes[expires_range.clone()].reverse();

                issued_at = u64::from_be_bytes(bytes[issued_range].try_into().unwrap());
                expires_at = u64::from_be_bytes(bytes[expires_range].try_into().unwrap());

                Self::validate_dates(issued_at, expires_at)?;
            }

            Ok((issued_at, expires_at))
        };

        match version {
            // Both platforms may send these versions.
            Version::V2 | Version::V2_1 | Version::V3 => {
                ticket.serial = Self::decode_string(&bytes[0x10..0x24]);
                ticket.issuer_id = u32::from_be_bytes(bytes[0x28..0x2C].try_into().unwrap());

                (ticket.issued_at, ticket.expires_at) =
                    parse_timestamps(bytes, 0x30..0x38, 0x3C..0x44)?;

                ticket.account_id = u64::from_be_bytes(bytes[0x48..0x50].try_into().unwrap());
                ticket.username = Self::decode_string(&bytes[0x54..0x74]);
                ticket.region = Self::decode_string(&bytes[0x78..0x7A]);
                ticket.domain = Self::decode_string(&bytes[0x80..0x82]);
                ticket.service_id = Self::decode_string(&bytes[0x88..0x9B]);
                ticket.status = u32::from_be_bytes(bytes[0xA4..0xA8].try_into().unwrap());

                // If empty, default to RPCN defaults: `un` and `br`
                if ticket.domain.is_empty() {
                    ticket.domain = DEFAULT_DOMAIN.to_string();
                }
                if ticket.region.is_empty() {
                    ticket.region = DEFAULT_REGION.to_string();
                }

                let signature_id: &[u8; 4] = &bytes[0xB8..0xBC].try_into().unwrap();
                let signature = Signature::from_bytes(*signature_id, &Vec::new());

                let signed_data = match signature {
                    Signature::Console(_) => {
                        let data_length = signature.signed_data_length(version);
                        bytes[0x08..data_length].to_vec()
                    }
                    Signature::Emulator(_) => bytes[0x08..0xB0].to_vec(),
                };

                ticket.signature = Signature::from_bytes(*signature_id, &signed_data);
            }

            // Only the console uses version 4 tickets. The emulator does not support them.
            Version::V4 => {
                ticket.serial = Self::decode_string(&bytes[0x14..0x28]);
                ticket.issuer_id = u32::from_be_bytes(bytes[0x2C..0x30].try_into().unwrap());

                (ticket.issued_at, ticket.expires_at) =
                    parse_timestamps(bytes, 0x34..0x3C, 0x40..0x48)?;

                ticket.account_id = u64::from_be_bytes(bytes[0x4C..0x54].try_into().unwrap());
                ticket.username = Self::decode_string(&bytes[0x58..0x78]);
                ticket.region = Self::decode_string(&bytes[0x7C..0x7E]);
                ticket.domain = Self::decode_string(&bytes[0x84..0x86]);
                ticket.service_id = Self::decode_string(&bytes[0x8C..0x9F]);

                let signature_id: &[u8; 4] = &bytes[0xC0..0xC4].try_into().unwrap();
                let signature = Signature::from_bytes(*signature_id, &Vec::new());

                let signed_data = match signature {
                    Signature::Console(_) => {
                        let start = 0x08;
                        let end = bytes.len() - version.signature_length(&signature) - 16;
                        println!("V4 signed data range: {start:#X}..{end:#X}");
                        bytes[start..end].to_vec()
                    }
                    Signature::Emulator(_) => {
                        unimplemented!("Emulator does not support version 4 tickets")
                    }
                };
                ticket.signature = Signature::from_bytes(*signature_id, &signed_data);
            }
        }

        let ec_key_name = match &ticket.signature {
            Signature::Console(_) => "psn",
            Signature::Emulator(_) => "rpcn",
        };

        let ec_key_bytes = std::fs::read_to_string(format!("keys/{ec_key_name}.pem"))
            .map_err(|_| "Failed to read public key")?;

        let data = ticket.signature.signed_data();
        let signature_bytes = match ticket.signature {
            Signature::Console(_) => {
                &bytes[bytes.len() - version.signature_length(&ticket.signature)..]
            }
            Signature::Emulator(_) => &bytes[0xC0..],
        };

        // Verify the signature.
        // For the time being, only RPCN signatures can be verified.
        //
        // This is because:
        // - The `psn.pem` public key might be wrong
        //    - It claims to be prime192v1, but the signature doesn't match that curve
        // - The signature is only 32 bytes, which only matches secp128r1
        //    - The point is not on that curve, so it can't be secp128r1
        //    - This is also why verifying PSN will not only give `false`; it will error out
        // - Every PSN game has a different private key for signing NP tickets, and we don't
        //   know PlayStation Home's public key.
        // - Nobody has successfully verified a Version 4 PSN ticket yet
        // - Versions below 4 aren't sent anymore by PSN.
        match (&ticket.signature, version) {
            (Signature::Emulator(_), Version::V2 | Version::V2_1 | Version::V3) => {
                let vk = ecdsa::VerifyingKey::<Secp224k1>::from_public_key_pem(&ec_key_bytes)
                    .map_err(|_| "Failed to load RPCN public key")?;

                let sig = ecdsa::Signature::<Secp224k1>::from_slice(signature_bytes)
                    .or_else(|_| ecdsa::Signature::<Secp224k1>::from_der(signature_bytes))
                    .map_err(|_| "Invalid RPCN signature format")?;

                let mut hasher = Sha224::new();
                hasher.update(data);
                let hash = hasher.finalize();

                vk.verify_prehash(&hash, &sig)
                    .map_err(|_| "Invalid signature")?;
            }
            (Signature::Console(_), Version::V4) => {
                // Just validate PEM/Key for now
                let _vk = ecdsa::VerifyingKey::<NistP256>::from_public_key_pem(&ec_key_bytes)
                    .map_err(|_| "Failed to load PSN public key (P-256)")?;

                let mut hasher = Sha256::new();
                hasher.update(data);
                let _hash = hasher.finalize();
            }
            (Signature::Console(_), _) => {
                // V2/V3
                let _vk = ecdsa::VerifyingKey::<NistP192>::from_public_key_pem(&ec_key_bytes)
                    .map_err(|_| "Failed to load PSN public key (P-192)")?;

                let mut hasher = Sha1::new();
                hasher.update(data);
                let _hash = hasher.finalize();
            }
            _ => {
                return Err("Unsupported ticket/signature combination for verification");
            }
        }

        Ok(ticket)
    }

    /// Serialize the ticket to bytes and optionally sign it.
    ///
    /// Currently, only `RPCN` signatures (using P-224) are fully supported for creation.
    pub fn to_bytes(
        &self,
        version: Version,
        signing_key: Option<&ecdsa::SigningKey<Secp224k1>>,
    ) -> Vec<u8> {
        let mut serial_vec = self.serial.as_bytes().to_vec();
        serial_vec.resize(0x14, 0);

        let mut online_id = self.username.as_bytes().to_vec();
        online_id.resize(0x20, 0);

        let mut service_id = self.service_id.as_bytes().to_vec();
        service_id.resize(0x18, 0);

        let mut region = self.region.as_bytes().to_vec();
        region.resize(4, 0);

        let mut domain = self.domain.as_bytes().to_vec();
        domain.resize(4, 0);

        let mut user_data = vec![
            TicketData::Binary(serial_vec),
            TicketData::U32(self.issuer_id),
            TicketData::Time(self.issued_at),
            TicketData::Time(self.expires_at),
            TicketData::U64(self.account_id),
            TicketData::BString(online_id),
            TicketData::Binary(region),
            TicketData::BString(domain),
            TicketData::Binary(service_id),
            TicketData::U32(self.status),
        ];

        user_data.push(TicketData::Empty());
        user_data.push(TicketData::Empty());

        let user_blob = TicketData::Blob(0, user_data);

        // P-224 signature is 56 bytes
        let mut signature_bytes = vec![0u8; 56];

        if let Some(key) = signing_key {
            let mut user_rawdata = Vec::new();
            user_blob.write(&mut user_rawdata);

            let mut hasher = Sha224::new();
            hasher.update(&user_rawdata);
            let hash = hasher.finalize();

            if let Ok(sig) = key.sign_prehash(&hash) {
                let sig: ecdsa::Signature<Secp224k1> = sig;
                signature_bytes = sig.to_bytes().to_vec();
            }
        }

        let signature_blob = TicketData::Blob(
            2,
            vec![
                TicketData::Binary(b"RPCN".to_vec()),
                TicketData::Binary(signature_bytes),
            ],
        );

        let mut ticket_blob = Vec::new();
        ticket_blob.extend(&((version as u32) << 16).to_be_bytes());

        let size: u32 = ((user_blob.len() + 4) + (signature_blob.len() + 4)) as u32;
        ticket_blob.extend(&size.to_be_bytes());

        user_blob.write(&mut ticket_blob);
        signature_blob.write(&mut ticket_blob);

        ticket_blob
    }

    /// Serialize the ticket and encode it as a base64 string.
    pub fn to_base64(
        &self,
        version: Version,
        signing_key: Option<&ecdsa::SigningKey<Secp224k1>>,
    ) -> String {
        let bytes = self.to_bytes(version, signing_key);
        let engine = base64::engine::general_purpose::STANDARD;
        engine.encode(bytes)
    }
}
