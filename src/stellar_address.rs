//! Conversion between a raw ed25519 public key, as carried on every
//! `TransactionEnvelope.origin_pubkey`, and its Stellar StrKey (SEP-0023)
//! account address representation (`G...`).
//!
//! This is new, reusable infrastructure: nothing in this crate or in
//! `stellarconduit-core` previously needed to render a raw pubkey as a
//! Stellar address. It exists because the `dispute-resolver` Soroban
//! contract's `raise_dispute` entry point takes `initiator`/`respondent` as
//! Soroban `Address` values, which off-chain are represented as `G...`/`M...`
//! StrKey strings — see `crate::conflict::escalation`.

/// Encode `pubkey` as a Stellar `G...` account StrKey.
///
/// Delegates entirely to the `stellar-strkey` crate (official Stellar
/// tooling) for the actual version-byte + base32 + CRC16-XModem encoding —
/// this function is just plumbing, not a reimplementation of SEP-0023.
pub fn pubkey_to_stellar_address(pubkey: &[u8; 32]) -> String {
    stellar_strkey::ed25519::PublicKey(*pubkey)
        .to_string()
        .as_str()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-good (pubkey, StrKey) pairs taken directly from
    /// `stellar/rs-stellar-strkey`'s own `test_valid_public_keys` test
    /// vectors (https://github.com/stellar/rs-stellar-strkey/blob/main/tests/tests.rs) —
    /// i.e. externally verified values, not a round-trip against our own
    /// encoder.
    #[test]
    fn test_pubkey_to_address_matches_known_vector() {
        let pubkey_1: [u8; 32] = [
            0x36, 0x3e, 0xaa, 0x38, 0x67, 0x84, 0x1f, 0xba, 0xd0, 0xf4, 0xed, 0x88, 0xc7, 0x79,
            0xe4, 0xfe, 0x66, 0xe5, 0x6a, 0x24, 0x70, 0xdc, 0x98, 0xc0, 0xec, 0x9c, 0x07, 0x3d,
            0x05, 0xc7, 0xb1, 0x03,
        ];
        assert_eq!(
            pubkey_to_stellar_address(&pubkey_1),
            "GA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQHES5"
        );

        let pubkey_2: [u8; 32] = [
            0x3f, 0x0c, 0x34, 0xbf, 0x93, 0xad, 0x0d, 0x99, 0x71, 0xd0, 0x4c, 0xcc, 0x90, 0xf7,
            0x05, 0x51, 0x1c, 0x83, 0x8a, 0xad, 0x97, 0x34, 0xa4, 0xa2, 0xfb, 0x0d, 0x7a, 0x03,
            0xfc, 0x7f, 0xe8, 0x9a,
        ];
        assert_eq!(
            pubkey_to_stellar_address(&pubkey_2),
            "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"
        );
    }

    #[test]
    fn test_pubkey_to_address_is_deterministic() {
        let pubkey = [7u8; 32];
        assert_eq!(
            pubkey_to_stellar_address(&pubkey),
            pubkey_to_stellar_address(&pubkey)
        );
    }

    #[test]
    fn test_pubkey_to_address_has_g_prefix_and_expected_length() {
        let pubkey = [42u8; 32];
        let address = pubkey_to_stellar_address(&pubkey);
        assert!(address.starts_with('G'));
        assert_eq!(address.len(), 56);
    }

    #[test]
    fn test_different_pubkeys_yield_different_addresses() {
        assert_ne!(
            pubkey_to_stellar_address(&[1u8; 32]),
            pubkey_to_stellar_address(&[2u8; 32])
        );
    }
}
