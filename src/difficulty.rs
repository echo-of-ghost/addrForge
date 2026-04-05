use bitcoin::Network;
use crate::types::{AddrType, BASE58_CHARSET};

// ── Public API ────────────────────────────────────────────────────────────────

/// Expected attempts to find a prefix match.
/// For bech32: uniform 32^extra_chars.
/// For base58: exact fraction accounting for the version-byte constraint.
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
    !reachable_lengths(prefix, version).is_empty()
}

/// Return which address lengths a base58check prefix can appear in.
pub fn reachable_lengths(prefix: &str, version: u8) -> Vec<usize> {
    let possible_lengths: &[usize] = if version == 0x00 || version == 0x6f { &[33, 34] } else { &[34] };
    let mut out = Vec::new();

    for &addr_len in possible_lengths {
        if prefix.len() > addr_len { continue; }

        if version == 0x00 || version == 0x6f {
            let digits = addr_len - 1;
            let first_char = if version == 0x00 { '1' } else { 'm' };
            if !prefix.starts_with(first_char) && prefix.len() >= 1 { continue; }
            let prefix_after_first = if prefix.len() >= 1 { &prefix[1..] } else { prefix };

            if prefix_after_first.is_empty() {
                out.push(addr_len);
                continue;
            }

            let (p_min, p_max) = base58_prefix_to_range(prefix_after_first, digits);
            let digit_min = base58_pow(digits - 1);
            let digit_max = base58_pow(digits) - 1.0;
            let data_max: f64 = 2.0_f64.powi(192) - 1.0;
            let range_min = digit_min;
            let range_max = if digit_max > data_max { data_max } else { digit_max };

            if p_max >= range_min && p_min <= range_max {
                out.push(addr_len);
            }
        } else {
            let range_min = (version as f64) * 256.0_f64.powi(24);
            let range_max = ((version as f64) + 1.0) * 256.0_f64.powi(24) - 1.0;
            let (p_min, p_max) = base58_prefix_to_range(prefix, addr_len);
            if p_max >= range_min && p_min <= range_max {
                out.push(addr_len);
            }
        }
    }
    out
}

/// Returns true if a Legacy/Testnet prefix is only reachable in the rare 33-char format.
pub fn base58_prefix_is_rare(prefix: &str, version: u8) -> bool {
    let lens = reachable_lengths(prefix, version);
    !lens.is_empty() && !lens.contains(&34)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Compute expected attempts to find a base58check address starting with `prefix`.
fn base58_prefix_difficulty(prefix: &str, version: u8) -> f64 {
    if version == 0x00 || version == 0x6f {
        let first_char = if version == 0x00 { '1' } else { 'm' };
        if prefix.len() < 1 || !prefix.starts_with(first_char) { return 1.0; }
        let suffix = &prefix[1..];
        if suffix.is_empty() { return 1.0; }

        let mut matching: f64 = 0.0;
        for n_digits in [32_usize, 33] {
            let digit_lo: f64 = if n_digits <= 1 { 0.0 } else { 58.0_f64.powi((n_digits - 1) as i32) };
            let digit_hi: f64 = 58.0_f64.powi(n_digits as i32) - 1.0;
            let data_max: f64 = 256.0_f64.powi(24) - 1.0;
            let digit_hi = if digit_hi > data_max { data_max } else { digit_hi };
            if digit_lo > digit_hi { continue; }
            if suffix.len() > n_digits { continue; }
            let remaining = n_digits - suffix.len();
            let (p_lo, p_hi) = base58_prefix_numeric_range(suffix, remaining);
            let lo = if p_lo > digit_lo { p_lo } else { digit_lo };
            let hi = if p_hi < digit_hi { p_hi } else { digit_hi };
            if lo <= hi { matching += hi - lo + 1.0; }
        }
        if matching <= 0.0 { return f64::INFINITY; }
        256.0_f64.powi(24) / matching
    } else {
        let addr_lo: f64 = (version as f64) * 256.0_f64.powi(24);
        let addr_hi: f64 = ((version as f64) + 1.0) * 256.0_f64.powi(24) - 1.0;
        let n_digits: usize = 34;
        if prefix.len() > n_digits { return f64::INFINITY; }
        let remaining = n_digits - prefix.len();
        let (p_lo, p_hi) = base58_prefix_numeric_range(prefix, remaining);
        let lo = if p_lo > addr_lo { p_lo } else { addr_lo };
        let hi = if p_hi < addr_hi { p_hi } else { addr_hi };
        if lo > hi { return f64::INFINITY; }
        let matching = hi - lo + 1.0;
        let total_for_version = addr_hi - addr_lo + 1.0;
        total_for_version / matching
    }
}

fn base58_prefix_to_range(prefix: &str, total_digits: usize) -> (f64, f64) {
    let remaining = total_digits - prefix.len();
    let mut min_val: f64 = 0.0;
    let mut max_val: f64 = 0.0;
    for ch in prefix.chars() {
        let idx = BASE58_CHARSET.find(ch).unwrap_or(0) as f64;
        min_val = min_val * 58.0 + idx;
        max_val = max_val * 58.0 + idx;
    }
    min_val *= base58_pow(remaining);
    max_val = max_val * base58_pow(remaining) + (base58_pow(remaining) - 1.0);
    (min_val, max_val)
}

fn base58_prefix_numeric_range(prefix: &str, remaining: usize) -> (f64, f64) {
    let mut lo: f64 = 0.0;
    let mut hi: f64 = 0.0;
    for ch in prefix.chars() {
        let idx = BASE58_CHARSET.find(ch).unwrap_or(0) as f64;
        lo = lo * 58.0 + idx;
        hi = hi * 58.0 + idx;
    }
    let pow = 58.0_f64.powi(remaining as i32);
    lo *= pow;
    hi = hi * pow + (pow - 1.0);
    (lo, hi)
}

pub fn base58_pow(n: usize) -> f64 {
    58.0_f64.powi(n as i32)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bech32_difficulty_scales_geometrically() {
        let d4 = difficulty_for_prefix("bc1pface", AddrType::Taproot, Network::Bitcoin);
        let d5 = difficulty_for_prefix("bc1pfaced", AddrType::Taproot, Network::Bitcoin);
        // Each extra char multiplies difficulty by 32
        let ratio = d5 / d4;
        assert!((ratio - 32.0).abs() < 0.001, "ratio was {ratio}");
    }

    #[test]
    fn legacy_prefix_1_has_difficulty_1() {
        // "1" matches every Legacy address
        let d = difficulty_for_prefix("1", AddrType::Legacy, Network::Bitcoin);
        assert_eq!(d, 1.0);
    }

    #[test]
    fn nested_segwit_prefix_reachable() {
        // All 3... addresses are reachable for P2SH on mainnet
        assert!(is_base58_prefix_reachable("3A", 0x05));
    }

    #[test]
    fn suffix_difficulty_scales_geometrically() {
        let d1 = difficulty_for_suffix(1, AddrType::Taproot);
        let d2 = difficulty_for_suffix(2, AddrType::Taproot);
        assert!((d2 / d1 - 32.0).abs() < 0.001);
    }

    #[test]
    fn testnet_legacy_difficulty() {
        // Testnet legacy addresses start with 'm' (version 0x6f)
        let d = difficulty_for_prefix("m", AddrType::Legacy, Network::Testnet);
        assert_eq!(d, 1.0);
    }

    #[test]
    fn base58_prefix_is_rare_detects_33char_only() {
        // '1' prefix is NOT rare for mainnet (version 0x00) — it covers both 33 and 34 char addresses
        assert!(!base58_prefix_is_rare("1", 0x00));
    }
}
