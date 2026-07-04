//! A ``PlayStation Network`` ticket for authenticating requests.
//!
//! The ticket is cryptographically signed and contains the user's
//! username, alongside other data, which we can use to identify them.

use base64::Engine;
use openssl::bn::BigNum;
use openssl::ec::EcKey;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::{PKey, Private};
use openssl::sign::Verifier;
use serde::{Deserialize, Deserializer};

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

        // NOTE: from_bytes does NOT verify the signature; the caller is responsible
        // for verification via from_bytes_with_key.
        let ticket = Self::from_bytes(&mut decoded).map_err(serde::de::Error::custom)?;

        Ok(ticket)
    }
}

/// Helper: compute a SHA-224 digest of `data` using OpenSSL.
fn sha224(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut h = Hasher::new(MessageDigest::sha224()).map_err(|_| "Failed to init SHA-224")?;
    h.update(data).map_err(|_| "Failed to hash data")?;
    Ok(h.finish().map_err(|_| "Failed to finalize hash")?.to_vec())
}

/// Helper: convert a raw fixed-size `r || s` signature (or DER) into an [`EcdsaSig`].
///
/// If the input is valid DER it is used directly; otherwise we split at the midpoint
/// and build the signature from the raw `r` and `s` components.
fn parse_ecdsa_sig(bytes: &[u8]) -> Result<EcdsaSig, &'static str> {
    if let Ok(sig) = EcdsaSig::from_der(bytes) {
        return Ok(sig);
    }
    if bytes.len() % 2 != 0 || bytes.is_empty() {
        return Err("Invalid signature format: odd or zero length");
    }
    let half = bytes.len() / 2;
    let r = BigNum::from_slice(&bytes[..half]).map_err(|_| "Failed to parse r component")?;
    let s = BigNum::from_slice(&bytes[half..]).map_err(|_| "Failed to parse s component")?;
    EcdsaSig::from_private_components(r, s)
        .map_err(|_| "Failed to construct ECDSA signature from r||s")
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

    /// Parse the raw fields from `bytes` into a [`Ticket`] **without** verifying
    /// the signature.
    ///
    /// Prefer [`Self::from_bytes_with_key`] to also verify the signature.
    ///
    /// `bytes` must be mutable because the function may swap byte order to fix
    /// endianness issues with the timestamps.
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

        // Helper to handle endianness issues with timestamps
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

        Ok(ticket)
    }

    /// Parse and **verify** a ticket using the supplied PEM-encoded public key.
    ///
    /// Verification uses OpenSSL and supports:
    /// - **RPCN (secp224k1, SHA-224)** — fully verified.
    /// - **PSN V4 (P-256 / prime256v1, SHA-256)** — verified when a key is provided.
    /// - **PSN V2/V3 (P-192 / prime192v1, SHA-1)** — verified when a key is provided.
    ///
    /// The raw signature is expected to be in `r || s` (fixed-size) format; DER is
    /// also accepted as a fallback.
    pub fn from_bytes_with_key(bytes: &mut [u8], pub_key_pem: &str) -> Result<Self, &'static str> {
        // 1. Parse all fields (no crypto yet)
        let ticket = Self::from_bytes(bytes)?;

        // 2. Re-derive version (already validated)
        let version = Version::from_u16(u16::from_be_bytes([bytes[0], bytes[1]]))
            .ok_or("Unsupported version")?;

        // 3. Locate the raw signature bytes
        let signature_bytes: &[u8] = match &ticket.signature {
            Signature::Console(_) => {
                let sig_len = version.signature_length(&ticket.signature);
                &bytes[bytes.len() - sig_len..]
            }
            Signature::Emulator(_) => &bytes[0xC0..],
        };

        // 4. Load public key via OpenSSL
        let pkey = PKey::public_key_from_pem(pub_key_pem.as_bytes())
            .map_err(|_| "Failed to load public key from PEM")?;

        // 5. Choose hash algorithm:
        //    RPCN (secp224k1)    → SHA-224
        //    PSN V4 (P-256)      → SHA-256
        //    PSN V2/V3 (P-192)  → SHA-1
        let digest = match (&ticket.signature, version) {
            (Signature::Emulator(_), _) => MessageDigest::sha224(),
            (Signature::Console(_), Version::V4) => MessageDigest::sha256(),
            (Signature::Console(_), _) => MessageDigest::sha1(),
        };

        // 6. Convert raw r||s → DER (or pass DER through as-is)
        let ecdsa_sig = parse_ecdsa_sig(signature_bytes)?;
        let der_sig = ecdsa_sig
            .to_der()
            .map_err(|_| "Failed to DER-encode ECDSA signature")?;

        // 7. Verify using OpenSSL Verifier (handles hashing internally)
        let mut verifier =
            Verifier::new(digest, &pkey).map_err(|_| "Failed to create OpenSSL verifier")?;
        verifier
            .update(ticket.signature.signed_data())
            .map_err(|_| "Failed to feed data to verifier")?;
        let valid = verifier
            .verify(&der_sig)
            .map_err(|_| "Signature verification error")?;

        if !valid {
            return Err("Invalid signature");
        }

        Ok(ticket)
    }

    /// Serialize the ticket to bytes and **sign** it using an OpenSSL private key.
    ///
    /// `signing_key` is a PEM-encoded PKCS#8 or SEC1 EC private key for the
    /// RPCN curve (secp224k1). Pass `None` to produce an unsigned (zero-filled)
    /// signature blob for testing.
    ///
    /// The produced signature is in raw `r || s` format (28 bytes each, 56 bytes
    /// total) to match what RPCS3 / RPCN expect.
    pub fn to_bytes(&self, version: Version, signing_key_pem: Option<&str>) -> Vec<u8> {
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

        // secp224k1 signature: 28 bytes per component = 56 bytes total (raw r||s)
        let mut signature_bytes = vec![0u8; 56];

        if let Some(pem) = signing_key_pem {
            // Try to sign; on any error we fall back to the zero-filled placeholder
            if let Some(sig) = Self::sign_user_blob(&user_blob, pem) {
                signature_bytes = sig;
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

    /// Internal: serialise `user_blob`, SHA-224 hash it, sign with OpenSSL, and
    /// return the raw `r || s` bytes (56 bytes for secp224k1).
    fn sign_user_blob(user_blob: &TicketData, private_key_pem: &str) -> Option<Vec<u8>> {
        // Serialise the blob to bytes
        let mut user_rawdata = Vec::new();
        user_blob.write(&mut user_rawdata);

        // Compute SHA-224 digest
        let digest = sha224(&user_rawdata).ok()?;

        // Load the private key
        let pkey = PKey::private_key_from_pem(private_key_pem.as_bytes()).ok()?;
        let ec_key: EcKey<Private> = pkey.ec_key().ok()?;

        // Sign the digest using OpenSSL's low-level EcdsaSig::sign
        let sig = EcdsaSig::sign(&digest, &ec_key).ok()?;

        // Convert to fixed-size r || s (28 bytes each for secp224k1 / P-224)
        let r = sig.r().to_vec();
        let s = sig.s().to_vec();

        // Zero-pad each component to exactly 28 bytes
        let mut raw = vec![0u8; 56];
        let r_start = 28usize.saturating_sub(r.len());
        let s_start = 28usize.saturating_sub(s.len());
        raw[r_start..28].copy_from_slice(&r[r.len().saturating_sub(28)..]);
        raw[28 + s_start..].copy_from_slice(&s[s.len().saturating_sub(28)..]);

        Some(raw)
    }

    /// Serialize the ticket and encode it as a base64 string.
    pub fn to_base64(&self, version: Version, signing_key_pem: Option<&str>) -> String {
        let bytes = self.to_bytes(version, signing_key_pem);
        let engine = base64::engine::general_purpose::STANDARD;
        engine.encode(bytes)
    }
}
