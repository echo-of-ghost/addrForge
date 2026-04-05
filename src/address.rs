use anyhow::{bail, Result};
use bitcoin::{
    key::UntweakedPublicKey,
    secp256k1::{SecretKey, SECP256K1},
    Address, CompressedPublicKey, Network,
};
use bip39::Mnemonic;

// NUMS point: BIP-341 standard provably-unspendable internal key.
// Any address using this as the internal key can only be spent via script path.
const NUMS_X: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

// ── Result types ──────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct FoundAddr {
    pub address:           String,
    pub pubkey:            String,   // x-only for Taproot, compressed for others
    pub compressed_pubkey: String,   // always the 33-byte compressed key (02/03 prefix)
    pub wif:               String,
    pub mnemonic:          String,   // BIP-39 24-word mnemonic (English)
}

#[derive(Clone)]
pub struct InspectorResult {
    pub address:      String,
    pub addr_type:    String,
    pub network:      String,
    pub encoding:     String,
    pub pubkey_hex:   String,
    pub spend_type:   Option<String>,
    pub hash_type:    String,
    pub entropy_bits: f64,
    pub payload_bits: f64,
    pub is_nums:      bool,
}

// ── Address generation ────────────────────────────────────────────────────────

pub fn generate_address(secret: &SecretKey, addr_type: crate::types::AddrType, network: Network) -> String {
    use crate::types::AddrType;
    let (xonly, _) = secret.x_only_public_key(SECP256K1);
    let cpk = CompressedPublicKey(secret.public_key(SECP256K1));
    match addr_type {
        AddrType::Legacy       => Address::p2pkh(&cpk, network).to_string(),
        AddrType::NestedSegWit => Address::p2shwpkh(&cpk, network).to_string(),
        AddrType::NativeSegWit => Address::p2wpkh(&cpk, network).to_string(),
        AddrType::Taproot      =>
            Address::p2tr(SECP256K1, UntweakedPublicKey::from(xonly), None, network).to_string(),
    }
}

pub fn generate_address_merkle(
    secret: &SecretKey,
    merkle: Option<bitcoin::taproot::TapNodeHash>,
    network: Network,
) -> String {
    let (xonly, _) = secret.x_only_public_key(SECP256K1);
    Address::p2tr(SECP256K1, UntweakedPublicKey::from(xonly), merkle, network).to_string()
}

/// Build a FoundAddr from a discovered secret key + address string.
pub fn build_found_addr(
    secret: &SecretKey,
    address: String,
    addr_type: crate::types::AddrType,
    network: Network,
) -> FoundAddr {
    use crate::types::AddrType;
    let (xonly, _) = secret.x_only_public_key(SECP256K1);
    let cpk = CompressedPublicKey(secret.public_key(SECP256K1));
    let compressed = cpk.to_string();
    let pubkey = match addr_type {
        AddrType::Taproot => xonly.to_string(),
        _                 => compressed.clone(),
    };
    let wif = bitcoin::PrivateKey::new(*secret, network).to_wif();
    let mnemonic = secret_to_mnemonic(secret);

    FoundAddr { address, pubkey, compressed_pubkey: compressed, wif, mnemonic }
}

/// Convert a 32-byte secret key to a BIP-39 24-word English mnemonic.
pub fn secret_to_mnemonic(secret: &SecretKey) -> String {
    let bytes = secret.secret_bytes();
    Mnemonic::from_entropy(&bytes)
        .map(|m| m.to_string())
        .unwrap_or_default()
}

// ── Address inspection ────────────────────────────────────────────────────────

pub fn inspect_address(addr_str: &str) -> Result<InspectorResult> {
    let addr: Address<bitcoin::address::NetworkUnchecked> = addr_str
        .parse()
        .map_err(|_| anyhow::anyhow!("CANNOT PARSE ADDRESS"))?;
    let addr = addr.assume_checked();

    let lc = addr_str.to_lowercase();
    let network = detect_network(&lc);
    let script = addr.script_pubkey();
    let raw = script.as_bytes();

    if script.is_p2pkh() {
        // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let hash_bytes = &raw[3..23];
        let hex = hex::encode(hash_bytes).to_uppercase();
        Ok(InspectorResult {
            address:      addr_str.to_string(),
            addr_type:    "LEGACY (P2PKH)".into(),
            network:      network.into(),
            encoding:     "BASE58CHECK".into(),
            pubkey_hex:   hex.clone(),
            spend_type:   Some("SINGLE KEY (ECDSA SECP256K1)".into()),
            hash_type:    format!("HASH160: {}...", &hex[..16]),
            entropy_bits: 160.0,
            payload_bits: lc.len().saturating_sub(1) as f64 * 5.7,
            is_nums:      false,
        })
    } else if script.is_p2sh() {
        // OP_HASH160 <20 bytes> OP_EQUAL
        let hash_bytes = &raw[2..22];
        let hex = hex::encode(hash_bytes).to_uppercase();
        Ok(InspectorResult {
            address:      addr_str.to_string(),
            addr_type:    "NESTED SEGWIT (P2SH-P2WPKH)".into(),
            network:      network.into(),
            encoding:     "BASE58CHECK".into(),
            pubkey_hex:   hex.clone(),
            spend_type:   Some("SCRIPT HASH (LIKELY P2SH-P2WPKH)".into()),
            hash_type:    format!("HASH160: {}...", &hex[..16]),
            entropy_bits: 160.0,
            payload_bits: lc.len().saturating_sub(1) as f64 * 5.7,
            is_nums:      false,
        })
    } else if script.is_p2wpkh() {
        // OP_0 <20 bytes>
        let hash_bytes = &raw[2..22];
        let hex = hex::encode(hash_bytes).to_uppercase();
        Ok(InspectorResult {
            address:      addr_str.to_string(),
            addr_type:    "NATIVE SEGWIT (P2WPKH)".into(),
            network:      network.into(),
            encoding:     "BECH32".into(),
            pubkey_hex:   hex.clone(),
            spend_type:   Some("SINGLE KEY (ECDSA SECP256K1, SEGWIT V0)".into()),
            hash_type:    format!("HASH160: {}...", &hex[..16]),
            entropy_bits: 160.0,
            payload_bits: lc.len().saturating_sub(4) as f64 * 5.0,
            is_nums:      false,
        })
    } else if script.is_p2tr() {
        // OP_1 <32 bytes>
        if raw.len() < 34 { bail!("MALFORMED TAPROOT ADDRESS"); }
        let key_bytes = &raw[2..34];
        let hex = hex::encode(key_bytes).to_uppercase();
        let is_nums = hex.to_lowercase() == NUMS_X;
        let spend_type = if is_nums {
            Some("PROVABLY UNSPENDABLE (NUMS POINT) -- SCRIPT-PATH ONLY".into())
        } else {
            None
        };
        Ok(InspectorResult {
            address:      addr_str.to_string(),
            addr_type:    "TAPROOT (P2TR)".into(),
            network:      network.into(),
            encoding:     "BECH32M".into(),
            pubkey_hex:   hex.clone(),
            spend_type,
            hash_type:    format!("X-ONLY PUBKEY: {}...", &hex[..16]),
            entropy_bits: 256.0,
            payload_bits: lc.len().saturating_sub(4) as f64 * 5.0,
            is_nums,
        })
    } else {
        bail!("UNRECOGNISED ADDRESS FORMAT")
    }
}

fn detect_network(lc: &str) -> &'static str {
    if lc.starts_with("bcrt1") { "REGTEST" }
    else if lc.starts_with("bc1") || lc.starts_with('1') || lc.starts_with('3') { "MAINNET" }
    else if lc.starts_with("tb1") || lc.starts_with('m') || lc.starts_with('n') || lc.starts_with('2') { "TESTNET / SIGNET" }
    else { "UNKNOWN" }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::SecretKey;
    use crate::types::AddrType;

    fn test_secret() -> SecretKey {
        SecretKey::from_slice(&[0x42u8; 32]).unwrap()
    }

    #[test]
    fn generate_legacy_mainnet_starts_with_1() {
        let addr = generate_address(&test_secret(), AddrType::Legacy, Network::Bitcoin);
        assert!(addr.starts_with('1'), "Legacy mainnet must start with '1', got: {addr}");
    }

    #[test]
    fn generate_nested_mainnet_starts_with_3() {
        let addr = generate_address(&test_secret(), AddrType::NestedSegWit, Network::Bitcoin);
        assert!(addr.starts_with('3'), "Nested SegWit mainnet must start with '3', got: {addr}");
    }

    #[test]
    fn generate_native_mainnet_starts_with_bc1q() {
        let addr = generate_address(&test_secret(), AddrType::NativeSegWit, Network::Bitcoin);
        assert!(addr.starts_with("bc1q"), "Native SegWit mainnet must start with 'bc1q', got: {addr}");
    }

    #[test]
    fn generate_taproot_mainnet_starts_with_bc1p() {
        let addr = generate_address(&test_secret(), AddrType::Taproot, Network::Bitcoin);
        assert!(addr.starts_with("bc1p"), "Taproot mainnet must start with 'bc1p', got: {addr}");
    }

    #[test]
    fn generate_legacy_testnet_starts_with_m_or_n() {
        let addr = generate_address(&test_secret(), AddrType::Legacy, Network::Testnet);
        assert!(
            addr.starts_with('m') || addr.starts_with('n'),
            "Legacy testnet must start with 'm' or 'n', got: {addr}"
        );
    }

    #[test]
    fn generate_taproot_testnet_starts_with_tb1p() {
        let addr = generate_address(&test_secret(), AddrType::Taproot, Network::Testnet);
        assert!(addr.starts_with("tb1p"), "Taproot testnet must start with 'tb1p', got: {addr}");
    }

    #[test]
    fn generate_taproot_regtest_starts_with_bcrt1p() {
        let addr = generate_address(&test_secret(), AddrType::Taproot, Network::Regtest);
        assert!(addr.starts_with("bcrt1p"), "Taproot regtest must start with 'bcrt1p', got: {addr}");
    }

    #[test]
    fn secret_to_mnemonic_produces_24_words() {
        let mnemonic = secret_to_mnemonic(&test_secret());
        assert!(!mnemonic.is_empty());
        let word_count = mnemonic.split_whitespace().count();
        assert_eq!(word_count, 24, "32-byte entropy should yield 24 words, got: {word_count}");
    }

    #[test]
    fn secret_to_mnemonic_is_deterministic() {
        let s = test_secret();
        assert_eq!(secret_to_mnemonic(&s), secret_to_mnemonic(&s));
    }

    #[test]
    fn inspect_taproot_address() {
        let addr = generate_address(&test_secret(), AddrType::Taproot, Network::Bitcoin);
        let result = inspect_address(&addr).unwrap();
        assert_eq!(result.addr_type, "TAPROOT (P2TR)");
        assert_eq!(result.network, "MAINNET");
        assert_eq!(result.encoding, "BECH32M");
    }

    #[test]
    fn inspect_legacy_address() {
        let addr = generate_address(&test_secret(), AddrType::Legacy, Network::Bitcoin);
        let result = inspect_address(&addr).unwrap();
        assert_eq!(result.addr_type, "LEGACY (P2PKH)");
    }

    #[test]
    fn inspect_testnet_taproot() {
        let addr = generate_address(&test_secret(), AddrType::Taproot, Network::Testnet);
        let result = inspect_address(&addr).unwrap();
        assert_eq!(result.addr_type, "TAPROOT (P2TR)");
        assert_eq!(result.network, "TESTNET / SIGNET");
    }

    #[test]
    fn build_found_addr_fields_are_correct() {
        let secret = test_secret();
        let addr = generate_address(&secret, AddrType::Taproot, Network::Bitcoin);
        let found = build_found_addr(&secret, addr.clone(), AddrType::Taproot, Network::Bitcoin);
        assert_eq!(found.address, addr);
        assert!(!found.wif.is_empty());
        assert_eq!(found.mnemonic.split_whitespace().count(), 24);
    }
}
