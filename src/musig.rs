use anyhow::{bail, Result};
use bitcoin::secp256k1::PublicKey;
use musig2::KeyAggContext;

/// BIP-327 key aggregation for n-of-n MuSig2.
///
/// Takes 2–16 compressed 33-byte secp256k1 public keys and returns
/// the aggregate public key. This aggregate is used as the Taproot
/// internal key — `Address::p2tr` applies the BIP-341 tweak.
///
/// Unlike the previous hand-rolled implementation, this uses the
/// battle-tested `musig2` crate which correctly implements the
/// `GetSecondKey` optimization (second unique key gets coefficient 1)
/// required by the BIP-327 spec.
pub fn musig_aggregate(pubkeys: &[PublicKey]) -> Result<PublicKey> {
    if pubkeys.len() < 2 {
        bail!("MUSIG2 REQUIRES AT LEAST 2 KEYS");
    }
    if pubkeys.len() > 16 {
        bail!("MUSIG2 SUPPORTS UP TO 16 KEYS");
    }

    // Sort keys lexicographically for canonical BIP-327 ordering.
    // Callers provide keys in arbitrary order; sorting ensures the same
    // aggregate regardless of input order, consistent with the convention
    // used by BIP-327-compliant wallets.
    let mut sorted = pubkeys.to_vec();
    sorted.sort_by_key(|pk| pk.serialize());

    let ctx = KeyAggContext::new(sorted.iter().copied())
        .map_err(|e| anyhow::anyhow!("KEY AGGREGATION FAILED: {}", e))?;

    // aggregated_pubkey() returns the full 33-byte compressed PublicKey
    // (with parity), which we pass as the Taproot internal key.
    Ok(ctx.aggregated_pubkey())
}

/// Parse a hex-encoded 33-byte compressed pubkey into a secp256k1::PublicKey.
pub fn parse_pubkey_hex(hex_str: &str) -> Result<PublicKey> {
    let trimmed = hex_str.trim();
    if trimmed.len() != 66 {
        bail!("PUBKEY MUST BE 66 HEX CHARS (33-BYTE COMPRESSED)");
    }
    let bytes = hex::decode(trimmed)
        .map_err(|_| anyhow::anyhow!("INVALID HEX IN PUBKEY"))?;
    if bytes[0] != 0x02 && bytes[0] != 0x03 {
        bail!("PUBKEY MUST START WITH 02 OR 03 (COMPRESSED)");
    }
    PublicKey::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("INVALID SECP256K1 POINT: {}", e))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn make_pk(secret_bytes: &[u8; 32]) -> PublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(secret_bytes).unwrap();
        sk.public_key(&secp)
    }

    #[test]
    fn two_key_aggregation_is_deterministic() {
        let pk1 = make_pk(&[1u8; 32]);
        let pk2 = make_pk(&[2u8; 32]);
        let agg1 = musig_aggregate(&[pk1, pk2]).unwrap();
        let agg2 = musig_aggregate(&[pk1, pk2]).unwrap();
        assert_eq!(agg1, agg2);
    }

    #[test]
    fn key_order_produces_same_aggregate() {
        // BIP-327 sorts keys internally, so order shouldn't matter
        let pk1 = make_pk(&[1u8; 32]);
        let pk2 = make_pk(&[2u8; 32]);
        let agg_fwd = musig_aggregate(&[pk1, pk2]).unwrap();
        let agg_rev = musig_aggregate(&[pk2, pk1]).unwrap();
        assert_eq!(agg_fwd, agg_rev, "BIP-327 aggregate must be order-independent");
    }

    #[test]
    fn three_key_aggregation_works() {
        let pk1 = make_pk(&[1u8; 32]);
        let pk2 = make_pk(&[2u8; 32]);
        let pk3 = make_pk(&[3u8; 32]);
        let agg = musig_aggregate(&[pk1, pk2, pk3]);
        assert!(agg.is_ok(), "3-of-3 aggregation should succeed");
    }

    #[test]
    fn single_key_rejected() {
        let pk1 = make_pk(&[1u8; 32]);
        assert!(musig_aggregate(&[pk1]).is_err());
    }

    #[test]
    fn too_many_keys_rejected() {
        let pks: Vec<PublicKey> = (1u8..=17).map(|i| make_pk(&[i; 32])).collect();
        assert!(musig_aggregate(&pks).is_err());
    }

    #[test]
    fn parse_pubkey_hex_valid() {
        let pk = make_pk(&[5u8; 32]);
        let hex = hex::encode(pk.serialize());
        let parsed = parse_pubkey_hex(&hex).unwrap();
        assert_eq!(pk, parsed);
    }

    #[test]
    fn parse_pubkey_hex_rejects_uncompressed() {
        // 65-byte uncompressed key starts with 04
        let bad = "04".to_owned() + &"aa".repeat(64);
        // Too long (130 chars), will fail on length check
        assert!(parse_pubkey_hex(&bad).is_err());
    }
}
