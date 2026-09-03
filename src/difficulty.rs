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
// The interval arithmetic runs on exact 256-bit integers, not f64. Endpoints
// reach ~2^198 while the band a prefix matches is 58^(34-len) wide, so from
// about 10 prefix characters the band drops below one f64 ULP at that
// magnitude: the subtraction cancels to zero, and a perfectly findable prefix
// reads as unreachable with infinite difficulty. Only the final ratio is
// converted to f64, where relative error is irrelevant for an estimate.

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

// ── Fixed-width big integer ───────────────────────────────────────────────────

/// Unsigned 256-bit integer, little-endian limbs. Large enough for every value
/// in play here: the biggest is 58^40 (~2^234), and payload ranges top out at
/// 2^200. Products are bounded by construction, so overflow is unreachable.
#[derive(Clone, Copy, PartialEq, Eq)]
struct U256([u64; 4]);

impl U256 {
    const ZERO: U256 = U256([0; 4]);
    const ONE:  U256 = U256([1, 0, 0, 0]);

    /// 2^bits, for bits < 256.
    fn pow2(bits: u32) -> U256 {
        let mut l = [0u64; 4];
        l[(bits / 64) as usize] = 1u64 << (bits % 64);
        U256(l)
    }

    fn mul_small(self, m: u64) -> U256 {
        let mut out = [0u64; 4];
        let mut carry: u128 = 0;
        for i in 0..4 {
            let p = self.0[i] as u128 * m as u128 + carry;
            out[i] = p as u64;
            carry = p >> 64;
        }
        U256(out)
    }

    fn add_small(self, a: u64) -> U256 {
        let mut out = self.0;
        let mut carry = a as u128;
        for limb in out.iter_mut() {
            if carry == 0 { break; }
            let s = *limb as u128 + carry;
            *limb = s as u64;
            carry = s >> 64;
        }
        U256(out)
    }

    fn mul(self, other: U256) -> U256 {
        let mut out = [0u64; 4];
        for i in 0..4 {
            if self.0[i] == 0 { continue; }
            let mut carry: u128 = 0;
            for j in 0..(4 - i) {
                let idx = i + j;
                let cur = out[idx] as u128 + self.0[i] as u128 * other.0[j] as u128 + carry;
                out[idx] = cur as u64;
                carry = cur >> 64;
            }
        }
        U256(out)
    }

    /// Saturating difference, so callers never need to pre-check ordering.
    fn sub(self, other: U256) -> U256 {
        if self <= other { return U256::ZERO; }
        let mut out = [0u64; 4];
        let mut borrow: i128 = 0;
        for i in 0..4 {
            let d = self.0[i] as i128 - other.0[i] as i128 - borrow;
            if d < 0 {
                out[i] = (d + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                out[i] = d as u64;
                borrow = 0;
            }
        }
        U256(out)
    }

    fn to_f64(self) -> f64 {
        let mut v = 0.0_f64;
        for i in (0..4).rev() {
            v = v * 18446744073709551616.0 + self.0[i] as f64;
        }
        v
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Most significant limb first — the derived ordering would compare
        // the least significant limb and be wrong.
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                std::cmp::Ordering::Equal => continue,
                o => return o,
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(other)) }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn pow58(n: u32) -> U256 {
    let mut v = U256::ONE;
    for _ in 0..n { v = v.mul_small(58); }
    v
}

/// Numeric value of a base58 digit string, or None on an invalid character.
fn base58_value(s: &str) -> Option<U256> {
    let mut v = U256::ZERO;
    for ch in s.chars() {
        v = v.mul_small(58).add_small(BASE58_CHARSET.find(ch)? as u64);
    }
    Some(v)
}

/// How many integers in [lo, hi) have base58 digits starting with `digits`.
/// Sums over every possible total digit count.
fn matched_in_range(digits: &str, lo: U256, hi: U256) -> f64 {
    let Some(val) = base58_value(digits) else { return 0.0 };
    let len = digits.len() as u32;
    let mut matched = 0.0_f64;
    for d in len.max(1)..=40 {
        let d_lo = pow58(d - 1);
        let d_hi = pow58(d);
        if d_hi <= lo { continue; }
        if d_lo >= hi { break; }
        let p = pow58(d - len);
        let start = val.mul(p).max(d_lo).max(lo);
        let end   = val.add_small(1).mul(p).min(d_hi).min(hi);
        if end > start { matched += end.sub(start).to_f64(); }
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
        let k = (ones - 1) as u32; // required leading zero bytes of hash160
        if k > 20 { return f64::INFINITY; }
        let rest = &prefix[ones..];
        if rest.is_empty() {
            // Any address with at least k leading zero hash bytes matches.
            return U256::pow2(8 * k).to_f64();
        }
        // Exactly k zero bytes, then the digits of the remaining integer M
        // (top byte non-zero) must start with `rest`.
        let bytes = 24 - k;
        let m_lo = U256::pow2(8 * (bytes - 1));
        let m_hi = U256::pow2(8 * bytes);
        let matched = matched_in_range(rest, m_lo, m_hi);
        if matched <= 0.0 { return f64::INFINITY; }
        // P = P(k zero bytes) * P(M in matched set); the 24 bytes after the
        // version are modelled as uniform, so k + bytes = 24 collapses to 2^192.
        U256::pow2(192).to_f64() / matched
    } else {
        // Full 25-byte integer N in [version * 2^192, (version+1) * 2^192).
        let lo = U256::pow2(192).mul_small(version as u64);
        let hi = U256::pow2(192).mul_small(version as u64 + 1);
        let matched = matched_in_range(prefix, lo, hi);
        if matched <= 0.0 { return f64::INFINITY; }
        U256::pow2(192).to_f64() / matched
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

    /// Long prefixes used to collapse: the matched band fell below one f64 ULP
    /// at the payload's magnitude, so the interval subtraction cancelled to
    /// zero and a findable prefix reported infinite difficulty.
    #[test]
    fn long_prefixes_stay_reachable() {
        for p in ["moZzoqEgcz", "moZzoqEgczS", "moZzoqEgczSa", "moZzoqEgczSab"] {
            assert!(is_base58_prefix_reachable(p, 0x6f), "{p} should be reachable");
            assert!(base58_prefix_difficulty(p, 0x6f).is_finite(), "{p} difficulty must be finite");
        }
        for p in ["1BitcoinEat", "1BitcoinEatx"] {
            assert!(is_base58_prefix_reachable(p, 0x00), "{p} should be reachable");
        }
        for p in ["3Nested123AB", "3Nested123ABc"] {
            assert!(is_base58_prefix_reachable(p, 0x05), "{p} should be reachable");
        }
        for p in ["2N4qbie4V3rm", "2N4qbie4V3rmL"] {
            assert!(is_base58_prefix_reachable(p, 0xc4), "{p} should be reachable");
        }
    }

    /// A prefix band sitting wholly inside the version's numeric range has a
    /// closed form: 2^192 / 58^(34 - len). Anything off by more than rounding
    /// means the interval arithmetic lost precision again.
    #[test]
    fn difficulty_matches_closed_form() {
        let p = "moZzoqEgczSab";
        for k in 2..=p.len() {
            let got = base58_prefix_difficulty(&p[..k], 0x6f);
            let want = 2.0_f64.powi(192) / 58.0_f64.powi(34 - k as i32);
            let rel = (got - want).abs() / want;
            assert!(rel < 1e-9, "len {k}: got {got:e}, want {want:e}, rel err {rel:e}");
        }
    }

    /// Every legal prefix length must produce a usable estimate — no infinities
    /// leaking into the UI for patterns the search would actually find.
    #[test]
    fn no_spurious_infinities_at_max_length() {
        for (p, v) in [("moZzoqEgczSab", 0x6fu8), ("1BitcoinEatWo", 0x00),
                       ("3Nested123ABc", 0x05), ("2N4qbie4V3rmL", 0xc4)] {
            let d = base58_prefix_difficulty(p, v);
            assert!(d.is_finite() && d > 0.0, "{p} gave {d}");
        }
    }

    #[test]
    fn testnet_m_covers_most_addresses() {
        // 'm' and 'n' partition testnet legacy; 'm' takes the larger share.
        let dm = base58_prefix_difficulty("m", 0x6f);
        let dn = base58_prefix_difficulty("n", 0x6f);
        assert!((1.0 / dm + 1.0 / dn - 1.0).abs() < 1e-6, "shares must sum to 1");
        assert!(dm < dn, "'m' should be the more common prefix");
    }

    #[test]
    fn suffix_difficulty_scales_geometrically() {
        let d1 = difficulty_for_suffix(1, AddrType::Taproot);
        let d2 = difficulty_for_suffix(2, AddrType::Taproot);
        assert!((d2 / d1 - 32.0).abs() < 0.001);
    }
}



