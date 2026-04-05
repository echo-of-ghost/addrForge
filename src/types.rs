use bitcoin::Network;

pub const BECH32_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
pub const BASE58_CHARSET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// ── Address type ──────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Copy, Debug)]
pub enum AddrType { Legacy, NestedSegWit, NativeSegWit, Taproot }

impl AddrType {
    pub fn all() -> &'static [AddrType] {
        &[AddrType::Taproot, AddrType::NativeSegWit, AddrType::NestedSegWit, AddrType::Legacy]
    }

    pub fn label(&self) -> &'static str {
        match self {
            AddrType::Legacy       => "LEGACY        P2PKH        1...",
            AddrType::NestedSegWit => "NESTED SEGWIT P2SH-P2WPKH  3...",
            AddrType::NativeSegWit => "NATIVE SEGWIT P2WPKH       bc1q...",
            AddrType::Taproot      => "TAPROOT       P2TR          bc1p...",
        }
    }

    pub fn short(&self) -> &'static str {
        match self {
            AddrType::Legacy       => "LEGACY (P2PKH)",
            AddrType::NestedSegWit => "NESTED SEGWIT (P2SH-P2WPKH)",
            AddrType::NativeSegWit => "NATIVE SEGWIT (P2WPKH)",
            AddrType::Taproot      => "TAPROOT (P2TR)",
        }
    }

    /// The fixed prefix that all valid addresses of this type on the given network start with.
    pub fn default_prefix(&self, network: Network) -> &'static str {
        match (self, network) {
            (AddrType::Legacy,       Network::Bitcoin)  => "1",
            (AddrType::Legacy,       _)                 => "m",
            (AddrType::NestedSegWit, Network::Bitcoin)  => "3",
            (AddrType::NestedSegWit, _)                 => "2",
            (AddrType::NativeSegWit, Network::Bitcoin)  => "bc1q",
            (AddrType::NativeSegWit, Network::Regtest)  => "bcrt1q",
            (AddrType::NativeSegWit, _)                 => "tb1q",
            (AddrType::Taproot,      Network::Bitcoin)  => "bc1p",
            (AddrType::Taproot,      Network::Regtest)  => "bcrt1p",
            (AddrType::Taproot,      _)                 => "tb1p",
        }
    }

    /// Length of the fixed non-variable prefix (e.g. "bc1p" = 4, "bcrt1p" = 6, "1" = 1).
    pub fn fixed_prefix_len(&self, network: Network) -> usize {
        self.default_prefix(network).len()
    }

    pub fn charset(&self) -> &'static str {
        match self {
            AddrType::Legacy | AddrType::NestedSegWit   => BASE58_CHARSET,
            AddrType::NativeSegWit | AddrType::Taproot   => BECH32_CHARSET,
        }
    }

    pub fn charset_size(&self) -> f64 {
        match self {
            AddrType::Legacy | AddrType::NestedSegWit   => 58.0,
            AddrType::NativeSegWit | AddrType::Taproot   => 32.0,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            AddrType::Legacy =>
                "P2PKH. BASE58CHECK (NO 0, O, I, L). MIXED CASE.\n  HASH160 OF COMPRESSED PUBKEY.\n  DERIVATION: m/44'/0'/0'",
            AddrType::NestedSegWit =>
                "P2SH-P2WPKH. BASE58CHECK. MIXED CASE.\n  SEGWIT WRAPPED IN SCRIPT HASH.\n  DERIVATION: m/49'/0'/0'",
            AddrType::NativeSegWit =>
                "P2WPKH. BECH32. LOWERCASE ONLY.\n  WITNESS V0. ERROR DETECTION BUILT IN.\n  DERIVATION: m/84'/0'/0'",
            AddrType::Taproot =>
                "P2TR. BECH32M. LOWERCASE ONLY.\n  WITNESS V1. SCHNORR SIGS. MUSIG2 SUPPORTED.\n  DERIVATION: m/86'/0'/0'",
        }
    }

    pub fn supports_merkle(&self) -> bool { *self == AddrType::Taproot }

    /// Version byte for base58check encoding (mainnet / testnet).
    /// Returns None for bech32 address types.
    pub fn version_byte(&self, network: Network) -> Option<u8> {
        match (self, network) {
            (AddrType::Legacy,       Network::Bitcoin)  => Some(0x00),
            (AddrType::Legacy,       _)                 => Some(0x6f),
            (AddrType::NestedSegWit, Network::Bitcoin)  => Some(0x05),
            (AddrType::NestedSegWit, _)                 => Some(0xc4),
            _                                           => None,
        }
    }
}

impl std::str::FromStr for AddrType {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "legacy"  => Ok(Self::Legacy),
            "nested"  => Ok(Self::NestedSegWit),
            "native"  => Ok(Self::NativeSegWit),
            "taproot" => Ok(Self::Taproot),
            _ => Err(format!("Unknown address type: '{}'. Use legacy, nested, native, or taproot.", s)),
        }
    }
}

// ── Address mode ──────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Copy)]
pub enum AddrMode { SingleSig, MuSig2 }

impl AddrMode {
    pub fn label(&self) -> &'static str {
        match self {
            AddrMode::SingleSig => "SINGLESIG  -- ONE KEY, ONE OWNER",
            AddrMode::MuSig2    => "MUSIG2     -- AGGREGATE N KEYS (BIP-327)",
        }
    }
    pub fn description(&self) -> &'static str {
        match self {
            AddrMode::SingleSig =>
                "STANDARD SINGLE-KEY ADDRESS.\n  YOU HOLD THE PRIVATE KEY AND SIGN ALONE.\n  COMPATIBLE WITH ALL BITCOIN ADDRESS TYPES.",
            AddrMode::MuSig2 =>
                "N-OF-N MULTISIG VIA KEY AGGREGATION (BIP-327).\n  ENTER 2 TO 16 PUBKEYS TO DERIVE THE AGGREGATE\n  TAPROOT ADDRESS. ALL PARTIES MUST CO-SIGN.\n  INDISTINGUISHABLE FROM SINGLESIG ON-CHAIN.",
        }
    }
}

// ── Search mode ───────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
pub enum Mode { Prefix, Suffix, Regex }

impl Mode {
    pub fn label(&self) -> &'static str {
        match self {
            Mode::Prefix => "PREFIX",
            Mode::Suffix => "SUFFIX",
            Mode::Regex  => "REGEX ",
        }
    }
    pub fn all() -> &'static [Mode] {
        &[Mode::Prefix, Mode::Suffix, Mode::Regex]
    }
}

// ── Network display helper ────────────────────────────────────────────────────

pub fn network_label(n: Network) -> &'static str {
    match n {
        Network::Bitcoin => "MAINNET",
        Network::Testnet => "TESTNET",
        Network::Signet  => "SIGNET",
        Network::Regtest => "REGTEST",
        _                => "UNKNOWN",
    }
}

pub fn network_all() -> &'static [Network] {
    &[Network::Bitcoin, Network::Testnet, Network::Signet, Network::Regtest]
}

impl std::str::FromStr for AddrMode {
    type Err = ();
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s { "musig2" => Ok(AddrMode::MuSig2), _ => Ok(AddrMode::SingleSig) }
    }
}
