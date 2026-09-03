use bitcoin::Network;
use crate::types::{AddrType, BASE58_CHARSET};

// Base58check model: the 25-byte payload (version ++ hash160 ++ checksum) is
// encoded as one '1' per leading zero byte, followed by the base58 digits of
// the remaining bytes read as one big integer. Only version 0x00 produces
// leading zero bytes (the version byte itself, plus any leading zero bytes of
// the hash160 — each extra zero byte is a 1-in-256 event adding another '1').
// Non-zero versions encode the full 25-byte integer directly, so the first
// character is determined by the version's numeric range ('m'/'n' for 0x6f,
// '3' for 0x05, '2' for 0xc4) and never contains padding '1's.
//
// Computations use f64: interval widths dwarf rounding error for any pattern
// short enough to ever be found, and difficulty output is an estimate.

// ── Public API ────────────────────────────────────────────────────────────────

/// Expected attempts to find a prefix match.
/// For bech32: uniform 32^extra_chars.
/// For base58: exact fraction under the model above.
pub fn difficulty_for_prefix(prefix: &str, addr_type: AddrType, network: Network) -> f64 {
    match addr_type {
        AddrType::Taproot | AddrType::NativeSegWit => {
            let extra = prefix.len().saturating_sub(addr_type.fixed_prefix_len(network));
            addr_type.charset_size().powi(extra as i32)
        }
        AddrType::Legacy | AddrType::NestedSegWit => {
            let version = addr_type.version_byte(network).unwrap_or(0x00);
            base58_prefix_difficulty(prefix, version)
        }
    }
}

/// Expected attempts to find a suffix match.
/// Trailing base58 / bech32 characters are uniformly distributed.
pub fn difficulty_for_suffix(suffix_len: usize, addr_type: AddrType) -> f64 {
    addr_type.charset_size().powi(suffix_len as i32)
}

/// Check whether a base58check prefix is reachable for a given version byte.
pub fn is_base58_prefix_reachable(prefix: &str, version: u8) -> bool {
    base58_prefix_difficulty(prefix, version).is_finite()
}

/// Returns true if a prefix only matches a rare address form (e.g. extra
/// leading '1's requiring leading zero hash bytes), so searches will be much
/// slower than the per-character estimate suggests.
pub fn base58_prefix_is_rare(prefix: &str, version: u8) -> bool {
    let d = base58_prefix_difficulty(prefix, version);
    let naive = 58.0_f64.powi(prefix.len().saturating_sub(1) as i32);
    d.is_finite() && d > naive * 3.0
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn pow256(n: i32) -> f64 { 256.0_f64.powi(n) }
fn pow58(n: i32) -> f64 { 58.0_f64.powi(n) }

/// Numeric value of a base58 digit string, or None on an invalid character.
fn base58_value(s: &str) -> Option<f64> {
    let mut v = 0.0_f64;
    for ch in s.chars() {
        v = v * 58.0 + BASE58_CHARSET.find(ch)? as f64;
    }
    Some(v)
}

/// How many integers in [lo, hi) have base58 digits starting with `digits`.
/// Sums over every possible total digit count.
fn matched_in_range(digits: &str, lo: f64, hi: f64) -> f64 {
    let Some(val) = base58_value(digits) else { return 0.0 };
    let len = digits.len() as i32;
    let mut matched = 0.0_f64;
    for d in len..=40 {
        let d_lo = if d == 1 { 0.0 } else { pow58(d - 1) };
        let d_hi = pow58(d);
        if d_hi <= lo { continue; }
        if d_lo >= hi { break; }
        let r_lo = val * pow58(d - len);
        let r_hi = (val + 1.0) * pow58(d - len);
        let w = r_hi.min(d_hi).min(hi) - r_lo.max(d_lo).max(lo);
        if w > 0.0 { matched += w; }
    }
    matched
}

/// Expected attempts for a base58check prefix under version byte `version`.
fn base58_prefix_difficulty(prefix: &str, version: u8) -> f64 {
    if prefix.is_empty() { return 1.0; }
    if base58_value(prefix).is_none() { return f64::INFINITY; }
    if version == 0x00 {
        // Leading '1's: one from the version byte, each further '1' demands a
        // leading zero byte of hash160 (1/256 each).
        if !prefix.starts_with('1') { return f64::INFINITY; }
        let ones = prefix.chars().take_while(|c| *c == '1').count();
        let k = (ones - 1) as i32; // required leading zero bytes of hash160
        if k > 20 { return f64::INFINITY; }
        let rest = &prefix[ones..];
        if rest.is_empty() {
            // Any address with at least k leading zero hash bytes matches.
            return pow256(k);
        }
        // Exactly k zero bytes, then the digits of the remaining integer M
        // (top byte non-zero) must start with `rest`.
        let bytes = 24 - k;
        let m_lo = pow256(bytes - 1);
        let m_hi = pow256(bytes);
        let matched = matched_in_range(rest, m_lo, m_hi);
        if matched <= 0.0 { return f64::INFINITY; }
        // P = P(k zero bytes) * P(M in matched set), M uniform over [0, 256^bytes)
        pow256(k) * pow256(bytes) / matched
    } else {
        // Full 25-byte integer N in [version * 256^24, (version+1) * 256^24).
        let lo = version as f64 * pow256(24);
        let hi = (version as f64 + 1.0) * pow256(24);
        let matched = matched_in_range(prefix, lo, hi);
        if matched <= 0.0 { return f64::INFINITY; }
        (hi - lo) / matched
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bech32_difficulty_scales_geometrically() {
        let d4 = difficulty_for_prefix("bc1pface", AddrType::Taproot, Network::Bitcoin);
        let d5 = difficulty_for_prefix("bc1pfaced", AddrType::Taproot, Network::Bitcoin);
        let ratio = d5 / d4;
        assert!((ratio - 32.0).abs() < 0.001, "ratio was {ratio}");
    }

    #[test]
    fn legacy_prefix_1_has_difficulty_1() {
        let d = difficulty_for_prefix("1", AddrType::Legacy, Network::Bitcoin);
        assert_eq!(d, 1.0);
    }

    #[test]
    fn repeated_ones_prefixes_are_reachable() {
        // Addresses like 11..., 111... exist (leading zero hash bytes);
        // each extra '1' costs a factor of 256.
        assert!(is_base58_prefix_reachable("11", 0x00));
        assert!(is_base58_prefix_reachable("111", 0x00));
        assert!(is_base58_prefix_reachable("1111", 0x00));
        assert_eq!(base58_prefix_difficulty("11", 0x00), 256.0);
        assert_eq!(base58_prefix_difficulty("111", 0x00), 65536.0);
        // '1' + zero byte + digits is also reachable
        assert!(is_base58_prefix_reachable("11a", 0x00));
    }

    #[test]
    fn repeated_ones_flagged_rare() {
        assert!(base58_prefix_is_rare("11", 0x00));
        assert!(!base58_prefix_is_rare("1A", 0x00));
    }

    #[test]
    fn every_second_char_reachable_for_mainnet_legacy() {
        for ch in BASE58_CHARSET.chars() {
            let p = format!("1{ch}");
            assert!(is_base58_prefix_reachable(&p, 0x00), "1{ch} should be reachable");
        }
    }

    #[test]
    fn nested_segwit_prefix_reachable() {
        assert!(is_base58_prefix_reachable("3A", 0x05));
        // Mainnet P2SH always starts with '3'
        assert!(!is_base58_prefix_reachable("2A", 0x05));
    }

    #[test]
    fn testnet_legacy_m_and_n_both_reachable() {
        assert!(is_base58_prefix_reachable("m", 0x6f));
        assert!(is_base58_prefix_reachable("n", 0x6f));
        assert!(is_base58_prefix_reachable("n4", 0x6f));
        assert!(!is_base58_prefix_reachable("p", 0x6f));
        // 'm' covers most testnet legacy addresses; difficulty near 1
        let dm = base58_prefix_difficulty("m", 0x6f);
        assert!(dm > 1.0 && dm < 1.5, "difficulty('m') was {dm}");
        let dn = base58_prefix_difficulty("n", 0x6f);
        assert!(dn > 2.0, "difficulty('n') was {dn}");
    }

    #[test]
    fn testnet_nested_prefix_reachable() {
        // Testnet P2SH (0xc4) addresses are 35 chars starting with '2'
        assert!(is_base58_prefix_reachable("2N", 0xc4));
        assert!(is_base58_prefix_reachable("2M", 0xc4));
        assert!(!is_base58_prefix_reachable("3N", 0xc4));
    }

    #[test]
    fn invalid_char_unreachable() {
        assert!(!is_base58_prefix_reachable("1O", 0x00));
        assert!(!is_base58_prefix_reachable("1l", 0x00));
    }

    #[test]
    fn suffix_difficulty_scales_geometrically() {
        let d1 = difficulty_for_suffix(1, AddrType::Taproot);
        let d2 = difficulty_for_suffix(2, AddrType::Taproot);
        assert!((d2 / d1 - 32.0).abs() < 0.001);
    }
}
