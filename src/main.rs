use anyhow::{bail, Result};
use bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    key::UntweakedPublicKey,
    network::constants::Network,
    secp256k1::{rand::thread_rng, PublicKey as Secp256k1PubKey, SecretKey, SECP256K1},
    Address, PublicKey,
};
use clap::Parser;
use crossbeam_channel::bounded;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyModifiers},
    execute, queue,
    style::{Color, Print, SetForegroundColor},
    terminal::{self, ClearType},
};
use regex::Regex;
use std::{
    io::{self, Write},
    fs,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

// ── Palette ───────────────────────────────────────────────────────────────────

const GREEN:  Color = Color::Rgb { r: 36,  g: 255, b: 82  };
const DIM:    Color = Color::Rgb { r: 18,  g: 100, b: 32  };
const BRIGHT: Color = Color::Rgb { r: 180, g: 255, b: 200 };
const BLACK:  Color = Color::Rgb { r: 0,   g: 0,   b: 0   };
const WARN:   Color = Color::Rgb { r: 255, g: 180, b: 40  };

// ── Constants ─────────────────────────────────────────────────────────────────

const BECH32_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BASE58_CHARSET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const TICK_MS:        u64  = 100;
const SEP:            &str = "------------------------------------------------------------";
const VERSION: &str = concat!("V", env!("CARGO_PKG_VERSION"));

// NUMS point: the standard provably-unspendable internal key for Taproot.
// Defined in BIP-341 as lift_x(sha256("BIP0340/challenge"||"BIP0340/challenge")).
// Any address using this as the internal key can only be spent via script path.
const NUMS_X: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "addrforge", about = "Bitcoin address forge", version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    /// Run without TUI — print results to stdout
    #[arg(long)]
    no_tui: bool,

    /// Address type: legacy, nested, native, taproot [default: taproot]
    #[arg(long, default_value = "taproot")]
    addr_type: String,

    /// Search mode: prefix, suffix, regex [default: prefix]
    #[arg(long, default_value = "prefix")]
    mode: String,

    /// Pattern to search for
    #[arg(long)]
    pattern: Option<String>,

    /// Number of matches to find [default: 1]
    #[arg(long, default_value = "1")]
    count: usize,

    /// Number of threads [default: all CPUs]
    #[arg(long)]
    threads: Option<usize>,

    /// Benchmark address generation speed and print estimates, then exit
    #[arg(long)]
    bench: bool,

    /// Directory to save result files [default: current directory]
    #[arg(long, default_value = ".")]
    output_dir: String,
}

// ── Address type ──────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Copy)]
enum AddrType { Legacy, NestedSegWit, NativeSegWit, Taproot }

impl AddrType {
    fn all() -> &'static [AddrType] {
        &[AddrType::Taproot, AddrType::NativeSegWit, AddrType::NestedSegWit, AddrType::Legacy]
    }
    fn label(&self) -> &'static str {
        match self {
            AddrType::Legacy       => "LEGACY        P2PKH        1...",
            AddrType::NestedSegWit => "NESTED SEGWIT P2SH-P2WPKH  3...",
            AddrType::NativeSegWit => "NATIVE SEGWIT P2WPKH       bc1q...",
            AddrType::Taproot      => "TAPROOT       P2TR          bc1p...",
        }
    }
    fn short(&self) -> &'static str {
        match self {
            AddrType::Legacy       => "LEGACY (P2PKH)",
            AddrType::NestedSegWit => "NESTED SEGWIT (P2SH-P2WPKH)",
            AddrType::NativeSegWit => "NATIVE SEGWIT (P2WPKH)",
            AddrType::Taproot      => "TAPROOT (P2TR)",
        }
    }
    fn default_prefix(&self) -> &'static str {
        match self {
            AddrType::Legacy       => "1",
            AddrType::NestedSegWit => "3",
            AddrType::NativeSegWit => "bc1q",
            AddrType::Taproot      => "bc1p",
        }
    }
    fn charset(&self) -> &'static str {
        match self {
            AddrType::Legacy | AddrType::NestedSegWit => BASE58_CHARSET,
            AddrType::NativeSegWit | AddrType::Taproot => BECH32_CHARSET,
        }
    }
    fn charset_size(&self) -> f64 {
        match self {
            AddrType::Legacy | AddrType::NestedSegWit => 58.0,
            AddrType::NativeSegWit | AddrType::Taproot => 32.0,
        }
    }
    fn fixed_prefix_len(&self) -> usize {
        match self {
            AddrType::Legacy | AddrType::NestedSegWit => 1,
            AddrType::NativeSegWit | AddrType::Taproot => 4,
        }
    }
    fn description(&self) -> &'static str {
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
    fn supports_merkle(&self) -> bool { *self == AddrType::Taproot }
}

impl std::str::FromStr for AddrType {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "legacy"   => Ok(Self::Legacy),
            "nested"   => Ok(Self::NestedSegWit),
            "native"   => Ok(Self::NativeSegWit),
            "taproot"  => Ok(Self::Taproot),
            _ => Err(format!("Unknown address type: '{}'. Use legacy, nested, native, or taproot.", s)),
        }
    }
}

// ── Signing mode ──────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq, Copy)]
enum SigningMode { SingleSig, MuSig2 }

impl SigningMode {
    fn label(&self) -> &'static str {
        match self {
            SigningMode::SingleSig => "SINGLESIG  -- ONE KEY, ONE SIGNER",
            SigningMode::MuSig2    => "MUSIG2     -- AGGREGATE TWO KEYS",
        }
    }
    fn description(&self) -> &'static str {
        match self {
            SigningMode::SingleSig =>
                "STANDARD SINGLE-KEY ADDRESS.\n  YOU HOLD THE PRIVATE KEY AND SIGN ALONE.\n  COMPATIBLE WITH ALL BITCOIN ADDRESS TYPES.",
            SigningMode::MuSig2 =>
                "TWO-OF-TWO MULTISIG VIA KEY AGGREGATION (BIP-327).\n  ENTER TWO PUBKEYS TO DERIVE THE AGGREGATE\n  TAPROOT ADDRESS. BOTH PARTIES MUST CO-SIGN.\n  INDISTINGUISHABLE FROM SINGLESIG ON-CHAIN.",
        }
    }
}

// ── Search mode ───────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Mode { Prefix, Suffix, Regex }

impl Mode {
    fn label(&self) -> &'static str {
        match self {
            Mode::Prefix => "PREFIX",
            Mode::Suffix => "SUFFIX",
            Mode::Regex  => "REGEX ",
        }
    }
    fn all() -> &'static [Mode] {
        &[Mode::Prefix, Mode::Suffix, Mode::Regex]
    }
}

// ── MuSig2 key aggregation (BIP-327 simplified) ───────────────────────────────
// We implement the key aggregation step: given two compressed pubkeys,
// produce the aggregate x-only pubkey used as the Taproot internal key.

fn musig2_aggregate(pk1_hex: &str, pk2_hex: &str) -> Result<Secp256k1PubKey> {
    let pk1_bytes = hex::decode(pk1_hex.trim())
        .map_err(|_| anyhow::anyhow!("INVALID HEX FOR KEY 1"))?;
    let pk2_bytes = hex::decode(pk2_hex.trim())
        .map_err(|_| anyhow::anyhow!("INVALID HEX FOR KEY 2"))?;

    if pk1_bytes.len() != 33 { bail!("KEY 1 MUST BE 33-BYTE COMPRESSED PUBKEY (66 HEX CHARS)"); }
    if pk2_bytes.len() != 33 { bail!("KEY 2 MUST BE 33-BYTE COMPRESSED PUBKEY (66 HEX CHARS)"); }

    let pk1 = Secp256k1PubKey::from_slice(&pk1_bytes)
        .map_err(|_| anyhow::anyhow!("INVALID SECP256K1 POINT FOR KEY 1"))?;
    let pk2 = Secp256k1PubKey::from_slice(&pk2_bytes)
        .map_err(|_| anyhow::anyhow!("INVALID SECP256K1 POINT FOR KEY 2"))?;

    // BIP-327 key aggregation:
    // 1. Sort keys lexicographically (canonical ordering)
    // 2. Compute L = H_agg(pk1 || pk2) — the "key list hash"
    // 3. a_i = H_agg(L || pk_i) for each key
    // 4. Q = a_1 * P_1 + a_2 * P_2

    let mut keys = [pk1_bytes.as_slice(), pk2_bytes.as_slice()];
    keys.sort(); // lexicographic sort for canonical order

    // L = SHA256("KeyAgg list" || pk1_sorted || pk2_sorted)
    let mut engine = sha256::Hash::engine();
    let tag = sha256::Hash::hash(b"KeyAgg list");
    engine.input(tag.as_byte_array());
    engine.input(tag.as_byte_array());
    engine.input(keys[0]);
    engine.input(keys[1]);
    let l_hash = sha256::Hash::from_engine(engine);

    // a_i = SHA256("KeyAgg coefficient" || L || pk_i) for each
    let coeff_tag = sha256::Hash::hash(b"KeyAgg coefficient");

    let compute_coeff = |pk_bytes: &[u8]| -> Result<bitcoin::secp256k1::Scalar> {
        let mut eng = sha256::Hash::engine();
        eng.input(coeff_tag.as_byte_array());
        eng.input(coeff_tag.as_byte_array());
        eng.input(l_hash.as_byte_array());
        eng.input(pk_bytes);
        let h = sha256::Hash::from_engine(eng);
        // Convert hash to scalar — truncate to 32 bytes
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(h.as_byte_array());
        bitcoin::secp256k1::Scalar::from_be_bytes(bytes)
            .map_err(|_| anyhow::anyhow!("COEFFICIENT HASH EXCEEDS CURVE ORDER"))
    };

    let a1 = compute_coeff(keys[0])?;
    let a2 = compute_coeff(keys[1])?;

    // Q = a1*P1 + a2*P2
    let pk_a = if keys[0] == pk1_bytes.as_slice() { pk1 } else { pk2 };
    let pk_b = if keys[0] == pk1_bytes.as_slice() { pk2 } else { pk1 };

    let p1_tweaked = pk_a.mul_tweak(SECP256K1, &a1)
        .map_err(|e| anyhow::anyhow!("KEY AGGREGATION FAILED: {}", e))?;
    let p2_tweaked = pk_b.mul_tweak(SECP256K1, &a2)
        .map_err(|e| anyhow::anyhow!("KEY AGGREGATION FAILED: {}", e))?;

    p1_tweaked.combine(&p2_tweaked)
        .map_err(|e| anyhow::anyhow!("KEY COMBINATION FAILED: {}", e))
}

// ── Screens / Fields ──────────────────────────────────────────────────────────

#[derive(PartialEq, Clone, Copy)]
enum Screen { SigningPicker, TypePicker, MuSig2Setup, MuSig2Result, Setup, Running, Results, Inspector }

#[derive(Clone, Copy, PartialEq)]
enum Field { Mode, Pattern, Threads, Count, Merkle }

#[derive(Clone, Copy, PartialEq)]
enum MuSig2Field { Key1, Key2 }

// ── Domain types ──────────────────────────────────────────────────────────────

#[derive(Clone)]
struct FoundAddr {
    address:           String,
    pubkey:            String,   // x-only for Taproot, compressed for others
    compressed_pubkey: String,   // always the 33-byte compressed key (02/03 prefix)
    wif:               String,
}

// ── Session ───────────────────────────────────────────────────────────────────

struct Session {
    total_attempts: u64,
    total_elapsed:  f64,
}

impl Session {
    fn new() -> Self { Self { total_attempts: 0, total_elapsed: 0.0 } }
    fn record_run(&mut self, attempts: u64, elapsed: f64) {
        self.total_attempts += attempts;
        self.total_elapsed  += elapsed;
    }
}

// ── App ───────────────────────────────────────────────────────────────────────

struct App {
    screen:          Screen,
    prev_screen:     Screen,

    // signing picker
    signing_sel:     usize,

    // type picker
    addr_type:       AddrType,
    picker_sel:      usize,


    // setup
    field:           Field,
    mode:            Mode,
    pattern_input:   String,
    threads_input:   String,
    count_input:     String,
    merkle_input:    String,
    error:           Option<String>,
    input_warn:      Option<String>,   // transient flash warning for rejected keystrokes

    // musig2 setup
    musig2_field:    MuSig2Field,
    musig2_key1:     String,
    musig2_key2:     String,
    musig2_agg_key:  Option<String>,   // hex of aggregate x-only pubkey
    musig2_address:  Option<String>,   // derived Taproot address

    // runtime
    start:           Option<Instant>,
    finish:          Option<Instant>,
    attempts:        Arc<AtomicU64>,
    found_count:     Arc<AtomicU64>,
    done:            Arc<AtomicBool>,
    results:         Arc<Mutex<Vec<FoundAddr>>>,
    rx:              Option<crossbeam_channel::Receiver<FoundAddr>>,

    // run snapshot
    run_addr_type:   AddrType,
    run_pattern:     String,
    run_mode:        Mode,
    run_count:       usize,
    run_threads:     usize,

    // results
    selected:        usize,
    saved:           Option<String>,

    // inspector
    inspector_input:  String,
    inspector_result: Option<InspectorResult>,

    // config
    output_dir:      String,

    // session
    session:         Session,
}

impl App {
    fn new() -> Self {
        Self {
            screen:          Screen::SigningPicker,
            prev_screen:     Screen::SigningPicker,
            signing_sel:     0,
            addr_type:       AddrType::Taproot,
            picker_sel:      0,
            field:           Field::Mode,
            mode:            Mode::Prefix,
            pattern_input:   "bc1p".into(),
            threads_input:   num_cpus().to_string(),
            count_input:     "1".into(),
            merkle_input:    String::new(),
            error:           None,
            input_warn:      None,
            musig2_field:    MuSig2Field::Key1,
            musig2_key1:     String::new(),
            musig2_key2:     String::new(),
            musig2_agg_key:  None,
            musig2_address:  None,
            start:           None,
            finish:          None,
            attempts:        Arc::new(AtomicU64::new(0)),
            found_count:     Arc::new(AtomicU64::new(0)),
            done:            Arc::new(AtomicBool::new(false)),
            results:         Arc::new(Mutex::new(Vec::new())),
            rx:              None,
            run_addr_type:   AddrType::Taproot,
            run_pattern:     String::new(),
            run_mode:        Mode::Prefix,
            run_count:       0,
            run_threads:     0,
            selected:        0,
            saved:           None,
            inspector_input:  String::new(),
            inspector_result: None,
            output_dir:      ".".into(),
            session:         Session::new(),
        }
    }

    fn new_with_config(output_dir: String, session: Session) -> Self {
        let mut a = Self::new();
        a.output_dir = output_dir;
        a.session    = session;
        a
    }

    fn select_addr_type(&mut self, t: AddrType) {
        self.addr_type     = t;
        self.screen        = Screen::Setup;
        self.field         = Field::Mode;
        self.mode          = Mode::Prefix;
        self.pattern_input = t.default_prefix().to_string();
        self.merkle_input  = String::new();
        self.error         = None;
        self.input_warn    = None;
    }

    // ── address generation ────────────────────────────────────────────────────

    fn generate_address(secret: &SecretKey, addr_type: AddrType) -> String {
        let (xonly, _) = secret.x_only_public_key(SECP256K1);
        let pubkey = PublicKey::new(secret.public_key(SECP256K1));
        match addr_type {
            AddrType::Legacy =>
                Address::p2pkh(&pubkey, Network::Bitcoin).to_string(),
            AddrType::NestedSegWit =>
                Address::p2shwpkh(&pubkey, Network::Bitcoin)
                    .unwrap_or_else(|_| Address::p2pkh(&pubkey, Network::Bitcoin))
                    .to_string(),
            AddrType::NativeSegWit =>
                Address::p2wpkh(&pubkey, Network::Bitcoin)
                    .unwrap_or_else(|_| Address::p2pkh(&pubkey, Network::Bitcoin))
                    .to_string(),
            AddrType::Taproot =>
                Address::p2tr(SECP256K1, UntweakedPublicKey::from(xonly), None, Network::Bitcoin)
                    .to_string(),
        }
    }

    fn generate_address_merkle(secret: &SecretKey, merkle: Option<bitcoin::taproot::TapNodeHash>) -> String {
        let (xonly, _) = secret.x_only_public_key(SECP256K1);
        Address::p2tr(SECP256K1, UntweakedPublicKey::from(xonly), merkle, Network::Bitcoin).to_string()
    }

    // ── MuSig2 derive (instant — no search) ──────────────────────────────────

    fn derive_musig2(&mut self) -> Result<()> {
        let agg = musig2_aggregate(&self.musig2_key1, &self.musig2_key2)?;
        let (xonly, _) = agg.x_only_public_key();
        self.musig2_agg_key = Some(xonly.to_string().to_uppercase());
        self.musig2_address = Some(
            Address::p2tr(SECP256K1, UntweakedPublicKey::from(xonly), None, Network::Bitcoin)
                .to_string()
        );
        self.screen = Screen::MuSig2Result;
        Ok(())
    }

    // ── SingleSig search ─────────────────────────────────────────────────────

    fn start_search(&mut self) -> Result<()> {
        if self.threads_input.trim().is_empty() { bail!("THREADS CANNOT BE EMPTY"); }
        if self.count_input.trim().is_empty()   { bail!("COUNT CANNOT BE EMPTY"); }
        let threads: usize = self.threads_input.trim().parse()
            .map_err(|_| anyhow::anyhow!("THREADS MUST BE A NUMBER"))?;
        if threads == 0 { bail!("THREADS MUST BE >= 1"); }
        if threads > 256 { bail!("THREADS CAPPED AT 256"); }
        let count: usize = self.count_input.trim().parse()
            .map_err(|_| anyhow::anyhow!("COUNT MUST BE A NUMBER"))?;
        if count == 0 { bail!("COUNT MUST BE >= 1"); }
        if count > 1000 { bail!("COUNT CAPPED AT 1000"); }

        let merkle = if self.merkle_input.trim().is_empty() {
            None
        } else {
            Some(parse_merkle(self.merkle_input.trim())?)
        };
        let merkle_root = merkle.map(bitcoin::taproot::TapNodeHash::assume_hidden);

        let addr_type  = self.addr_type;
        let is_bech32  = matches!(addr_type, AddrType::Taproot | AddrType::NativeSegWit);
        // Bech32 addresses are lowercase-only by spec. Base58 is case-sensitive.
        let match_pat  = if is_bech32 { self.pattern_input.to_lowercase() } else { self.pattern_input.clone() };

        type Matcher = Arc<dyn Fn(&str) -> bool + Send + Sync>;
        let matcher: Matcher = match &self.mode {
            Mode::Prefix => {
                validate_prefix(&match_pat, addr_type)?;
                let p = match_pat.clone();
                Arc::new(move |addr: &str| addr.starts_with(&p))
            }
            Mode::Suffix => {
                validate_suffix_chars(&match_pat, addr_type)?;
                let p = match_pat.clone();
                Arc::new(move |addr: &str| addr.ends_with(&p))
            }
            Mode::Regex => {
                let re = build_regex(&self.pattern_input)?;
                Arc::new(move |addr: &str| re.is_match(addr))
            }
        };

        let attempts    = Arc::new(AtomicU64::new(0));
        let found_count = Arc::new(AtomicU64::new(0));
        let done        = Arc::new(AtomicBool::new(false));
        let results     = Arc::new(Mutex::new(Vec::<FoundAddr>::new()));
        let (tx, rx)    = bounded::<FoundAddr>(128);

        spawn_workers(
            threads, addr_type, merkle_root, matcher, count,
            Arc::clone(&attempts), Arc::clone(&found_count), Arc::clone(&done), tx,
        );

        self.run_pattern   = self.pattern_input.clone();
        self.run_mode      = self.mode;
        self.run_count     = count;
        self.run_threads   = threads;
        self.run_addr_type = addr_type;
        self.start         = Some(Instant::now());
        self.finish        = None;
        self.attempts      = attempts;
        self.found_count   = found_count;
        self.done          = done;
        self.results       = results;
        self.rx            = Some(rx);
        self.selected      = 0;
        self.saved         = None;
        self.screen        = Screen::Running;
        Ok(())
    }

    // ── save musig2 result ────────────────────────────────────────────────────

    fn save_musig2_result(&mut self) {
        let (Some(addr), Some(agg)) = (&self.musig2_address, &self.musig2_agg_key) else { return; };
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_millis();
        let filename = format!("addrforge-musig2-{}.txt", ts);
        let filepath = std::path::Path::new(&self.output_dir).join(&filename);
        let mut out = String::new();
        out.push_str(&format!("ADDRFORGE {} -- MUSIG2 DERIVATION\n\n", VERSION));
        out.push_str(&format!("ADDRESS        : {}\n", addr));
        out.push_str(&format!("AGG OUTPUT KEY : {}\n", agg));
        out.push_str(&format!("PUBKEY 1       : {}\n", self.musig2_key1));
        out.push_str(&format!("PUBKEY 2       : {}\n", self.musig2_key2));
        match fs::write(&filepath, &out) {
            Ok(_)  => self.saved = Some(filepath.to_string_lossy().into_owned()),
            Err(e) => self.error = Some(format!("SAVE FAILED: {}", e)),
        }
    }

    // ── save results ──────────────────────────────────────────────────────────

    fn save_results(&mut self) {
        let results = self.results.lock().unwrap_or_else(|e| e.into_inner());
        if results.is_empty() { return; }
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_millis();
        let filename = format!("addrforge-{}.txt", ts);
        let filepath = std::path::Path::new(&self.output_dir).join(&filename);
        let mut out = String::new();
        out.push_str(&format!("ADDRFORGE {} -- RESULTS\n", VERSION));
        out.push_str(&format!("TYPE    : {}\n", self.run_addr_type.short()));
        out.push_str(&format!("MODE    : {}\n", self.run_mode.label()));
        out.push_str(&format!("PATTERN : {}\n", self.run_pattern));
        out.push_str(&format!("THREADS : {}  COUNT : {}\n", self.run_threads, self.run_count));
        out.push_str(&format!("ELAPSED : {}  ATTEMPTS : {}\n\n",
            fmt_dur(self.elapsed()), fmt_num(self.attempts.load(Ordering::Relaxed))));
        for (i, m) in results.iter().enumerate() {
            out.push_str(&format!("MATCH {}\n", i + 1));
            out.push_str(&format!("  ADDRESS    : {}\n", m.address));
            out.push_str(&format!("  PUBKEY     : {}\n", m.pubkey));
            if self.run_addr_type == AddrType::Taproot {
                out.push_str(&format!("  COMPRESSED : {}\n", m.compressed_pubkey));
            }
            out.push_str(&format!("  WIF KEY    : {}\n", m.wif));
            out.push('\n');
        }
        match fs::write(&filepath, &out) {
            Ok(_)  => self.saved = Some(filepath.to_string_lossy().into_owned()),
            Err(e) => self.error = Some(format!("SAVE FAILED: {}", e)),
        }
    }

    // ── tick ──────────────────────────────────────────────────────────────────

    fn tick(&mut self) {
        if let Some(rx) = &self.rx {
            while let Ok(m) = rx.try_recv() {
                self.results.lock().unwrap_or_else(|e| e.into_inner()).push(m);
            }
        }
        match self.screen {
            Screen::Running => {
                if self.done.load(Ordering::Relaxed) {
                    if self.finish.is_none() {
                        self.finish = Some(Instant::now());
                        if let Some(rx) = &self.rx {
                            while let Ok(m) = rx.try_recv() {
                                self.results.lock().unwrap_or_else(|e| e.into_inner()).push(m);
                            }
                        }
                        self.session.record_run(
                            self.attempts.load(Ordering::Relaxed),
                            self.elapsed(),
                        );
                    }
                    self.screen = Screen::Results;
                }
            }
            _ => {}
        }
    }

    fn elapsed(&self) -> f64 {
        match (self.start, self.finish) {
            (Some(s), Some(f)) => (f - s).as_secs_f64(),
            (Some(s), None)    => s.elapsed().as_secs_f64(),
            _                  => 0.0,
        }
    }
    fn rate(&self) -> f64 {
        let e = self.elapsed();
        if e > 0.5 { self.attempts.load(Ordering::Relaxed) as f64 / e } else { 0.0 }
    }
}

// ── Inspector ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct InspectorResult {
    address:      String,
    addr_type:    String,
    network:      String,
    encoding:     String,
    pubkey_hex:   String,
    spend_type:   Option<String>,
    hash_type:    String,
    entropy_bits: f64,
    payload_bits: f64,
    is_nums:      bool,
}

fn inspect_address(addr_str: &str) -> Result<InspectorResult> {
    use bitcoin::address::Payload;

    let addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
        addr_str.parse().map_err(|_| anyhow::anyhow!("CANNOT PARSE ADDRESS"))?;
    let addr = addr.assume_checked();
    let lc   = addr_str.to_lowercase();

    let network = if lc.starts_with("bcrt1") {
        "REGTEST"
    } else if lc.starts_with("bc1") || lc.starts_with('1') || lc.starts_with('3') {
        "MAINNET"
    } else if lc.starts_with("tb1") || lc.starts_with('m') || lc.starts_with('n') || lc.starts_with('2') {
        "TESTNET / SIGNET"
    } else {
        "UNKNOWN"
    };

    match &addr.payload {
        Payload::PubkeyHash(pkh) => {
            let hex = hex::encode(pkh.as_byte_array());
            Ok(InspectorResult {
                address:      addr_str.to_string(),
                addr_type:    "LEGACY (P2PKH)".into(),
                network:      network.into(),
                encoding:     "BASE58CHECK".into(),
                pubkey_hex:   hex.clone().to_uppercase(),
                spend_type:   Some("SINGLE KEY (ECDSA SECP256K1)".into()),
                hash_type:    format!("HASH160: {}...", &hex[..16].to_uppercase()),
                entropy_bits: 160.0,
                payload_bits: lc.len().saturating_sub(1) as f64 * 5.7,
                is_nums:      false,
            })
        }
        Payload::ScriptHash(sh) => {
            let hex = hex::encode(sh.as_byte_array());
            Ok(InspectorResult {
                address:      addr_str.to_string(),
                addr_type:    "NESTED SEGWIT (P2SH-P2WPKH)".into(),
                network:      network.into(),
                encoding:     "BASE58CHECK".into(),
                pubkey_hex:   hex.clone().to_uppercase(),
                spend_type:   Some("SCRIPT HASH (LIKELY P2SH-P2WPKH)".into()),
                hash_type:    format!("HASH160: {}...", &hex[..16].to_uppercase()),
                entropy_bits: 160.0,
                payload_bits: lc.len().saturating_sub(1) as f64 * 5.7,
                is_nums:      false,
            })
        }
        Payload::WitnessProgram(wp) => {
            let version = wp.version().to_num();
            let program = wp.program().as_bytes();
            let hex     = hex::encode(program);

            if version == 1 && program.len() != 32 {
                bail!("MALFORMED TAPROOT ADDRESS");
            }

            // NUMS detection: check if output key matches the BIP-341 standard NUMS point
            let is_nums = version == 1 && hex == NUMS_X;

            let spend_type = if version == 1 {
                if is_nums {
                    Some("PROVABLY UNSPENDABLE (NUMS POINT) -- SCRIPT-PATH ONLY".into())
                } else {
                    None
                }
            } else if version == 0 {
                Some("SINGLE KEY (ECDSA SECP256K1, SEGWIT V0)".into())
            } else {
                Some("UNKNOWN".into())
            };

            let (addr_type_str, entropy) = match version {
                0 => ("NATIVE SEGWIT (P2WPKH)", 160.0_f64),
                1 => ("TAPROOT (P2TR)", 256.0_f64),
                v => (if v < 17 { "UNKNOWN SEGWIT" } else { "INVALID" }, program.len() as f64 * 8.0),
            };

            let encoding = if version == 0 { "BECH32" } else { "BECH32M" };

            let hash      = sha256::Hash::hash(program);
            let hash_disp = format!("SHA256: {}...", &hex::encode(hash.as_byte_array())[..16].to_uppercase());
            let payload_bits = lc.len().saturating_sub(4) as f64 * 5.0;

            Ok(InspectorResult {
                address:      addr_str.to_string(),
                addr_type:    addr_type_str.into(),
                network:      network.into(),
                encoding:     encoding.into(),
                pubkey_hex:   hex.to_uppercase(),
                spend_type:   spend_type,
                hash_type:    hash_disp,
                entropy_bits: entropy,
                payload_bits,
                is_nums,
            })
        }
        _ => bail!("UNRECOGNISED ADDRESS FORMAT"),
    }
}

// ── Shared worker spawner ────────────────────────────────────────────────────

/// Batch size for thread-local attempt counting before flushing to the shared atomic.
/// Reduces cache-line contention across cores.
const ATTEMPT_BATCH: u64 = 4096;

fn spawn_workers(
    threads:    usize,
    addr_type:  AddrType,
    merkle_root: Option<bitcoin::taproot::TapNodeHash>,
    matcher:    Arc<dyn Fn(&str) -> bool + Send + Sync>,
    count:      usize,
    attempts:   Arc<AtomicU64>,
    found_count: Arc<AtomicU64>,
    done:       Arc<AtomicBool>,
    tx:         crossbeam_channel::Sender<FoundAddr>,
) {
    let use_merkle = addr_type == AddrType::Taproot && merkle_root.is_some();

    for _ in 0..threads {
        let matcher     = Arc::clone(&matcher);
        let attempts    = Arc::clone(&attempts);
        let found_count = Arc::clone(&found_count);
        let done        = Arc::clone(&done);
        let tx          = tx.clone();
        let need        = count;

        thread::spawn(move || {
            let mut rng = thread_rng();
            let mut local_count: u64 = 0;
            while !done.load(Ordering::Relaxed) {
                let secret = SecretKey::new(&mut rng);
                let addr_raw = if use_merkle {
                    App::generate_address_merkle(&secret, merkle_root)
                } else {
                    App::generate_address(&secret, addr_type)
                };
                // Bech32 addresses are already lowercase from to_string().
                // Base58 addresses are case-sensitive — compare as-is.
                let addr_match: &str = &addr_raw;
                local_count += 1;
                if local_count % ATTEMPT_BATCH == 0 {
                    attempts.fetch_add(ATTEMPT_BATCH, Ordering::Relaxed);
                }
                if matcher(addr_match) {
                    let prev = found_count.fetch_add(1, Ordering::SeqCst);
                    if prev < need as u64 {
                        let compressed = PublicKey::new(secret.public_key(SECP256K1)).to_string();
                        let pubkey = match addr_type {
                            AddrType::Taproot => {
                                let (xonly, _) = secret.x_only_public_key(SECP256K1);
                                xonly.to_string()
                            }
                            _ => compressed.clone(),
                        };
                        let _ = tx.send(FoundAddr {
                            address:           addr_raw,
                            pubkey,
                            compressed_pubkey: compressed,
                            wif:               bitcoin::PrivateKey::new(secret, Network::Bitcoin).to_wif(),
                        });
                        if prev + 1 >= need as u64 {
                            done.store(true, Ordering::Relaxed);
                        }
                    }
                }
            }
            // Flush remaining local count
            attempts.fetch_add(local_count % ATTEMPT_BATCH, Ordering::Relaxed);
        });
    }
}

// ── Validation / helpers ──────────────────────────────────────────────────────

fn validate_prefix(s: &str, addr_type: AddrType) -> Result<String> {
    let fixed    = addr_type.fixed_prefix_len();
    let expected = addr_type.default_prefix().to_lowercase();
    if s.len() <= fixed { bail!("PREFIX TOO SHORT"); }
    if !s.starts_with(&expected) {
        bail!("PREFIX MUST START WITH {}", expected.to_uppercase());
    }
    let charset = addr_type.charset();
    for ch in s[fixed..].chars() {
        if !charset.contains(ch) {
            bail!("INVALID CHAR '{}' FOR {} ADDRESSES", ch, addr_type.short());
        }
    }
    // For base58 types, check if the prefix is actually reachable given the version byte.
    // The version byte constrains which character combinations are possible in early positions.
    if matches!(addr_type, AddrType::Legacy | AddrType::NestedSegWit) {
        let version = match addr_type {
            AddrType::Legacy       => 0x00u8,
            AddrType::NestedSegWit => 0x05u8,
            _ => unreachable!(),
        };
        if !is_base58_prefix_reachable(s, version) {
            bail!("PREFIX '{}' IS UNREACHABLE FOR {} ADDRESSES", s, addr_type.short());
        }
    }
    Ok(s.to_string())
}

/// Check whether a base58check prefix is reachable for a given version byte.
///
/// Base58check encodes [version_byte || 20-byte-hash || 4-byte-checksum] (25 bytes).
/// The version byte constrains which characters can appear in each position.
/// For version 0x00 (Legacy), addresses can be 33 or 34 characters (leading '1' from zero byte).
/// For version 0x05 (Nested SegWit), addresses are always 34 characters.
fn is_base58_prefix_reachable(prefix: &str, version: u8) -> bool {
    !reachable_lengths(prefix, version).is_empty()
}

/// Return which address lengths a base58check prefix can appear in.
fn reachable_lengths(prefix: &str, version: u8) -> Vec<usize> {
    let possible_lengths: &[usize] = if version == 0x00 { &[33, 34] } else { &[34] };
    let mut out = Vec::new();

    for &addr_len in possible_lengths {
        if prefix.len() > addr_len {
            continue;
        }
        if version == 0x00 {
            // Version 0x00: the leading '1' comes from the zero version byte.
            // The remaining (addr_len - 1) chars encode the numeric value of the
            // remaining 24 bytes (hash + checksum) as a base58 number.
            // For an (addr_len-1)-digit base58 number, the range is
            // [58^(digits-1), 58^digits - 1] (for digits >= 2).
            // The numeric value is also bounded by the 24-byte data range: [0, 2^192 - 1].
            let digits = addr_len - 1; // number of base58 digits after the leading '1'
            let prefix_after_1 = &prefix[1..]; // skip the leading '1'

            if prefix_after_1.is_empty() {
                out.push(addr_len);
                continue;
            }

            // Convert prefix chars after '1' to a numeric range
            let (p_min, p_max) = base58_prefix_to_range(prefix_after_1, digits);

            // Range of valid values: must have exactly `digits` base58 digits
            // and must not exceed 2^192 - 1 (24 bytes max)
            let digit_min = base58_pow(digits - 1); // 58^(digits-1)
            let digit_max = base58_pow(digits) - 1.0; // 58^digits - 1
            // Data range: 24 bytes = 192 bits. We use [u128; 2] style math.
            // 2^192 - 1 as (hi, lo): hi = 2^64 - 1, lo = u128::MAX... actually let's simplify.
            // 58^33 > 2^192, so for digits=33, digit_max may exceed the data range.
            // 58^32 ≈ 1.16e56, 2^192 ≈ 6.28e57. So 58^32 < 2^192 < 58^33.
            // For 33-char addresses (digits=32): digit_max = 58^32 - 1 < 2^192, so data range not limiting.
            // For 34-char addresses (digits=33): digit_max = 58^33 - 1 > 2^192, so cap at 2^192 - 1.
            // We'll use f64 for the overlap check since we only need approximate bounds.
            let data_max: f64 = 2.0_f64.powi(192) - 1.0;
            let range_min = digit_min;
            let range_max = if digit_max > data_max { data_max } else { digit_max };

            if p_max >= range_min && p_min <= range_max {
                out.push(addr_len);
            }
        } else {
            // Non-zero version byte: the full 25 bytes are encoded as one base58 number.
            // Range: [version * 256^24, (version+1) * 256^24 - 1]
            let range_min = (version as f64) * 256.0_f64.powi(24);
            let range_max = ((version as f64) + 1.0) * 256.0_f64.powi(24) - 1.0;

            // Convert prefix to a numeric range at the full address length
            let (p_min, p_max) = base58_prefix_to_range(prefix, addr_len);

            if p_max >= range_min && p_min <= range_max {
                out.push(addr_len);
            }
        }
    }
    out
}

/// Returns true if a Legacy prefix is only reachable in the rare 33-char
/// address format (~4% of all Legacy addresses), which makes it much slower.
fn legacy_prefix_is_rare(prefix: &str) -> bool {
    let lens = reachable_lengths(prefix, 0x00);
    !lens.is_empty() && !lens.contains(&34)
}

/// Convert a base58 prefix string to its numeric min/max range,
/// assuming it will be padded to `total_digits` characters.
/// Returns (min_value, max_value) as f64 (sufficient precision for range checks).
fn base58_prefix_to_range(prefix: &str, total_digits: usize) -> (f64, f64) {
    let remaining = total_digits - prefix.len();
    let mut min_val: f64 = 0.0;
    let mut max_val: f64 = 0.0;
    for ch in prefix.chars() {
        let idx = BASE58_CHARSET.find(ch).unwrap_or(0) as f64;
        min_val = min_val * 58.0 + idx;
        max_val = max_val * 58.0 + idx;
    }
    // Pad min with '1' (index 0) and max with 'z' (index 57)
    min_val *= base58_pow(remaining);
    max_val = max_val * base58_pow(remaining) + (base58_pow(remaining) - 1.0);
    (min_val, max_val)
}

/// 58^n as f64.
fn base58_pow(n: usize) -> f64 {
    58.0_f64.powi(n as i32)
}

fn validate_suffix_chars(s: &str, addr_type: AddrType) -> Result<String> {
    if s.is_empty() { bail!("SUFFIX CANNOT BE EMPTY"); }
    let charset = addr_type.charset();
    for ch in s.chars() {
        if !charset.contains(ch) {
            bail!("INVALID CHAR '{}' FOR {} ADDRESSES", ch, addr_type.short());
        }
    }
    Ok(s.to_string())
}

fn build_regex(pattern: &str) -> Result<Regex> {
    Regex::new(pattern).map_err(|e| anyhow::anyhow!("BAD REGEX: {}", e))
}

fn parse_merkle(s: &str) -> Result<[u8; 32]> {
    let b = hex::decode(s.to_lowercase())?;
    if b.len() != 32 { bail!("MERKLE ROOT MUST BE 32 BYTES (64 HEX CHARS)"); }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&b);
    Ok(arr)
}

/// Estimate the average number of attempts to find an address matching the given prefix.
/// For bech32 (Taproot, Native SegWit): uniform distribution, 32^extra_chars.
/// For base58 (Legacy, Nested SegWit): computes the exact fraction of the address space
/// that matches the prefix, accounting for the version byte's constraint on character
/// distribution in early positions.
fn difficulty_for_prefix(prefix: &str, addr_type: AddrType) -> f64 {
    match addr_type {
        AddrType::Taproot | AddrType::NativeSegWit => {
            // Bech32: uniform character distribution, simple calculation
            let extra = prefix.len().saturating_sub(addr_type.fixed_prefix_len());
            addr_type.charset_size().powi(extra as i32)
        }
        AddrType::Legacy | AddrType::NestedSegWit => {
            let version: u8 = match addr_type {
                AddrType::Legacy       => 0x00,
                AddrType::NestedSegWit => 0x05,
                _ => unreachable!(),
            };
            base58_prefix_difficulty(prefix, version)
        }
    }
}

/// For suffix mode, the simple estimate is fine — trailing characters in base58
/// addresses are uniformly distributed regardless of version byte.
fn difficulty_for_suffix(suffix_len: usize, addr_type: AddrType) -> f64 {
    addr_type.charset_size().powi(suffix_len as i32)
}

/// Compute the expected number of key generations to find a base58check address
/// starting with `prefix` for a given version byte.
///
/// This works by computing what fraction of the 256^20 possible hash values
/// produce an address whose base58check encoding starts with `prefix`.
fn base58_prefix_difficulty(prefix: &str, version: u8) -> f64 {
    if version == 0x00 {
        // Version 0x00: leading '1' from zero byte, remaining 24 bytes (hash + checksum)
        // are encoded as a base58 integer of 32 or 33 digits.
        let suffix = &prefix[1..]; // strip the leading '1'
        if suffix.is_empty() {
            return 1.0; // '1' matches all Legacy addresses
        }

        let mut matching: f64 = 0.0;
        for n_digits in [32_usize, 33] {
            // Numeric range for exactly n_digits base58 digits
            let digit_lo: f64 = if n_digits <= 1 { 0.0 } else { 58.0_f64.powi((n_digits - 1) as i32) };
            let digit_hi: f64 = 58.0_f64.powi(n_digits as i32) - 1.0;
            // Cap by actual 24-byte data range
            let data_max: f64 = 256.0_f64.powi(24) - 1.0;
            let digit_hi = if digit_hi > data_max { data_max } else { digit_hi };
            if digit_lo > digit_hi { continue; }
            if suffix.len() > n_digits { continue; }

            let remaining = n_digits - suffix.len();
            let (p_lo, p_hi) = base58_prefix_numeric_range(suffix, remaining);

            // Intersect prefix range with digit range
            let lo = if p_lo > digit_lo { p_lo } else { digit_lo };
            let hi = if p_hi < digit_hi { p_hi } else { digit_hi };
            if lo <= hi {
                matching += hi - lo + 1.0;
            }
        }

        if matching <= 0.0 { return f64::INFINITY; }
        // matching is the count of 24-byte numeric values that match.
        // But we generate 20-byte hashes (the checksum is fixed per hash).
        // Each hash produces exactly one 24-byte value, so the probability
        // is matching / 256^24, and difficulty is 256^20 * (256^24 / matching) / 256^4.
        // Simplifies to: 256^24 / matching (since each of 256^20 hashes maps to
        // one of 256^24 values, but only 1/256^4 of the 24-byte space is reachable
        // for each specific hash due to the deterministic checksum).
        // Actually: total valid 24-byte values = 256^20 (one per hash, each with unique checksum).
        // Fraction matching = matching / 256^24.
        // Difficulty = 1 / fraction = 256^24 / matching.
        256.0_f64.powi(24) / matching
    } else {
        // Non-zero version byte: full 25 bytes encoded as one base58 number.
        // Address is always 34 characters.
        // Numeric range: [version * 256^24, (version+1) * 256^24 - 1]
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
        // Difficulty = total addresses / matching addresses
        // Total addresses for this version = 256^20 (one per hash)
        // matching fraction = matching / (256^24) (the full numeric range of 25 bytes)
        // But only 256^20 of those 25-byte values are valid (deterministic checksum).
        // So: fraction = matching / 256^24, and since we try 256^20 total,
        // expected hits = 256^20 * matching / 256^24 = matching / 256^4.
        // Difficulty = 1 / (matching / 256^4 / 256^20) ... let me simplify.
        // P(match) = matching / (addr_hi - addr_lo + 1)
        // Difficulty = 1 / P(match) = (addr_hi - addr_lo + 1) / matching
        let total_for_version = addr_hi - addr_lo + 1.0;
        total_for_version / matching
    }
}

/// Convert a base58 prefix string into its numeric [lo, hi] range,
/// assuming it will be padded to (prefix.len() + remaining) total digits.
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

fn num_cpus() -> usize {
    thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

fn fmt_dur(s: f64) -> String {
    if s.is_infinite() || s.is_nan() { return "...".into(); }
    if s < 60.0        { format!("{:.1}S", s) }
    else if s < 3600.0 { format!("{:.1}M", s / 60.0) }
    else               { format!("{:.1}H", s / 3600.0) }
}

fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { out.push(','); }
        out.push(ch);
    }
    out.chars().rev().collect()
}

fn fmt_rate(r: f64) -> String {
    if r >= 1_000_000.0 { format!("{:.2}M/SEC", r / 1_000_000.0) }
    else if r >= 1_000.0 { format!("{:.0}K/SEC", r / 1_000.0) }
    else                  { format!("{:.0}/SEC", r) }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max { return s; }
    // Find the largest char boundary <= max to avoid panics on multi-byte chars
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) { end -= 1; }
    &s[..end]
}

// Render a footer hint bar. Each entry is ("KEY", "action") — key in bright green, action in dim.
fn hint_bar(out: &mut impl Write, hints: &[(&str, &str)]) -> Result<()> {
    for (i, (key, action)) in hints.iter().enumerate() {
        if i > 0 {
            queue!(out, SetForegroundColor(DIM), Print("   "))?;
        }
        queue!(out, SetForegroundColor(GREEN), Print(key))?;
        if !action.is_empty() {
            queue!(out, SetForegroundColor(DIM), Print(" "), Print(action))?;
        }
    }
    Ok(())
}

// ── Macros ────────────────────────────────────────────────────────────────────

macro_rules! w       { ($out:expr, $($a:tt)*) => { queue!($out, Print(format!($($a)*)))? }; }
macro_rules! green   { ($o:expr) => { queue!($o, SetForegroundColor(GREEN))?  }; }
macro_rules! dim     { ($o:expr) => { queue!($o, SetForegroundColor(DIM))?    }; }
macro_rules! bright  { ($o:expr) => { queue!($o, SetForegroundColor(BRIGHT))? }; }
macro_rules! warn    { ($o:expr) => { queue!($o, SetForegroundColor(WARN))?   }; }
macro_rules! inv_on  { ($o:expr) => { queue!($o, crossterm::style::SetBackgroundColor(GREEN), SetForegroundColor(BLACK))? }; }
macro_rules! inv_off { ($o:expr) => { queue!($o, crossterm::style::SetBackgroundColor(BLACK), SetForegroundColor(GREEN))? }; }
macro_rules! cl  { ($o:expr, $row:expr) => {
    queue!($o, cursor::MoveTo(0, $row), terminal::Clear(ClearType::CurrentLine))?
}; }
macro_rules! clear_body { ($o:expr) => { for r in 2..32 { cl!($o, r); } }; }

// ── Draw ──────────────────────────────────────────────────────────────────────

fn draw(out: &mut impl Write, app: &App) -> Result<()> {
    // Guard: require at least 72 cols × 24 rows
    if let Ok((cols, rows)) = terminal::size() {
        if cols < 72 || rows < 24 {
            queue!(out, cursor::MoveTo(0, 0), terminal::Clear(ClearType::All))?;
            dim!(out);
            w!(out, "  TERMINAL TOO SMALL");
            queue!(out, cursor::MoveTo(0, 1))?;
            w!(out, "  NEED 72x24  GOT {}x{}", cols, rows);
            out.flush()?;
            return Ok(());
        }
    }

    let nav = match app.screen {
        Screen::SigningPicker | Screen::TypePicker |
        Screen::Setup | Screen::MuSig2Setup | Screen::Results => "F2 INSPECT",
        _ => "",
    };
    cl!(out, 0);
    dim!(out); w!(out, "-- ");
    warn!(out); w!(out, "ADDRFORGE");
    dim!(out); w!(out, " {} ", VERSION);
    if nav.is_empty() {
        w!(out, "{}", "-".repeat(56));
    } else {
        dim!(out); w!(out, "{} ", "-".repeat(56usize.saturating_sub(nav.len() + 1)));
        green!(out); w!(out, "F2"); dim!(out); w!(out, " INSPECT");
    }
    cl!(out, 1);

    match app.screen {
        Screen::SigningPicker => draw_signing_picker(out, app)?,
        Screen::TypePicker    => draw_type_picker(out, app)?,
        Screen::MuSig2Setup   => draw_musig2_setup(out, app)?,
        Screen::MuSig2Result  => draw_musig2_result(out, app)?,
        Screen::Setup         => draw_setup(out, app)?,
        Screen::Running       => draw_running(out, app)?,
        Screen::Results       => draw_results(out, app)?,
        Screen::Inspector     => draw_inspector(out, app)?,
    }

    out.flush()?;
    Ok(())
}

// ── Signing picker ────────────────────────────────────────────────────────────

fn draw_signing_picker(out: &mut impl Write, app: &App) -> Result<()> {
    clear_body!(out);
    cl!(out, 2); bright!(out); w!(out, "  SIGNING MODE");
    cl!(out, 3);
    for (i, mode) in [SigningMode::SingleSig, SigningMode::MuSig2].iter().enumerate() {
        cl!(out, 4 + i as u16);
        if i == app.signing_sel {
            green!(out); w!(out, "  ");
            inv_on!(out); w!(out, " {} ", mode.label()); inv_off!(out);
        } else {
            dim!(out); w!(out, "    {} ", mode.label());
        }
    }
    cl!(out, 6);
    cl!(out, 7); dim!(out); w!(out, "  {}", SEP);
    cl!(out, 8);
    let sel = if app.signing_sel == 0 { SigningMode::SingleSig } else { SigningMode::MuSig2 };
    warn!(out);
    match sel { SigningMode::SingleSig => { w!(out, "  SINGLESIG"); } SigningMode::MuSig2 => { w!(out, "  MUSIG2"); } }
    cl!(out, 9);
    let desc_lines: Vec<&str> = sel.description().split('\n').collect();
    for (i, line) in desc_lines.iter().enumerate() {
        cl!(out, 10 + i as u16); dim!(out); w!(out, "  {}", line);
    }
    let after = 10 + desc_lines.len() as u16 + 1;
    cl!(out, after);
    cl!(out, after + 1); dim!(out); w!(out, "  {}", SEP);
    cl!(out, after + 2); w!(out, "  ");
    hint_bar(out, &[("↑↓", "SELECT"), ("RETURN", "CONFIRM"), ("ESC", "QUIT")])?;
    for r in (after + 3)..24 { cl!(out, r); }
    Ok(())
}

// ── Type picker ───────────────────────────────────────────────────────────────

fn draw_type_picker(out: &mut impl Write, app: &App) -> Result<()> {
    clear_body!(out);
    cl!(out, 2); bright!(out); w!(out, "  ADDRESS TYPE");
    cl!(out, 3);
    for (i, t) in AddrType::all().iter().enumerate() {
        cl!(out, 4 + i as u16);
        if i == app.picker_sel {
            green!(out); w!(out, "  ");
            inv_on!(out); w!(out, " {} ", t.label()); inv_off!(out);
        } else {
            dim!(out); w!(out, "    {} ", t.label());
        }
    }
    cl!(out, 8);
    cl!(out, 9); dim!(out); w!(out, "  {}", SEP);
    cl!(out, 10);
    let sel = AddrType::all()[app.picker_sel];
    cl!(out, 11); warn!(out); w!(out, "  {}", sel.short());
    cl!(out, 12);
    let desc_lines: Vec<&str> = sel.description().split('\n').collect();
    for (i, line) in desc_lines.iter().enumerate() {
        cl!(out, 13 + i as u16); dim!(out); w!(out, "  {}", line);
    }
    let after = 13 + desc_lines.len() as u16;
    cl!(out, after);
    cl!(out, after + 1); dim!(out);
    w!(out, "  CHARSET ");
    green!(out); w!(out, "{:.0} chars", sel.charset_size());
    dim!(out); w!(out, "  /  KEY SPACE ");
    green!(out); w!(out, "{}", match sel { AddrType::Taproot => "256 bits", _ => "160 bits" });
    dim!(out); w!(out, "  /  BITS/CHAR ");
    green!(out); w!(out, "{:.2}", sel.charset_size().log2());
    cl!(out, after + 2);
    cl!(out, after + 3); w!(out, "  ");
    hint_bar(out, &[("↑↓", "SELECT"), ("RETURN", "CONFIRM"), ("ESC", "BACK")])?;
    for r in (after + 3)..24 { cl!(out, r); }
    Ok(())
}

// ── MuSig2 setup ─────────────────────────────────────────────────────────────

fn draw_musig2_setup(out: &mut impl Write, app: &App) -> Result<()> {
    clear_body!(out);
    let focused = |f: MuSig2Field| app.musig2_field == f;

    cl!(out, 2); warn!(out); w!(out, "  MUSIG2");
    dim!(out); w!(out, "  /  TWO-OF-TWO TAPROOT KEY AGGREGATION (BIP-327)");
    cl!(out, 3); dim!(out); w!(out, "  COMPRESSED PUBKEYS REQUIRED  --  02... OR 03... PREFIX  --  66 HEX CHARS");
    cl!(out, 4);

    cl!(out, 5);
    if focused(MuSig2Field::Key1) { green!(out); w!(out, "] "); } else { dim!(out); w!(out, "  "); }
    dim!(out); w!(out, "PUBKEY 1 : ");
    green!(out); w!(out, "{}", truncate(&app.musig2_key1, 66));
    if focused(MuSig2Field::Key1) { inv_on!(out); w!(out, " "); inv_off!(out); }

    cl!(out, 6);
    if focused(MuSig2Field::Key2) { green!(out); w!(out, "] "); } else { dim!(out); w!(out, "  "); }
    dim!(out); w!(out, "PUBKEY 2 : ");
    green!(out); w!(out, "{}", truncate(&app.musig2_key2, 66));
    if focused(MuSig2Field::Key2) { inv_on!(out); w!(out, " "); inv_off!(out); }

    cl!(out, 7);
    cl!(out, 8);
    if let Some(err) = &app.error {
        warn!(out); w!(out, "  ? {}", err);
    } else {
        let k1_ok = app.musig2_key1.len() == 66;
        let k2_ok = app.musig2_key2.len() == 66;
        match (k1_ok, k2_ok) {
            (false, _) => { dim!(out); w!(out, "  KEY 1: {}/66 CHARS", app.musig2_key1.len()); }
            (true, false) => { dim!(out); w!(out, "  KEY 2: {}/66 CHARS", app.musig2_key2.len()); }
            (true, true)  => { green!(out); w!(out, "  READY -- PRESS RETURN TO DERIVE ADDRESS"); }
        }
    }

    cl!(out, 9);
    cl!(out, 10); dim!(out); w!(out, "  {}", SEP);
    cl!(out, 11); w!(out, "  ");
    hint_bar(out, &[("RETURN", "DERIVE"), ("TAB", "NEXT FIELD"), ("ESC", "BACK")])?;
    for r in 12..30 { cl!(out, r); }
    Ok(())
}

// ── MuSig2 result ─────────────────────────────────────────────────────────────

fn draw_musig2_result(out: &mut impl Write, app: &App) -> Result<()> {
    clear_body!(out);
    cl!(out, 2); warn!(out); w!(out, "  MUSIG2");
    dim!(out); w!(out, "  /  AGGREGATE ADDRESS DERIVED");
    cl!(out, 3); dim!(out); w!(out, "  BOTH PARTIES MUST CO-SIGN TO SPEND. INDISTINGUISHABLE FROM SINGLESIG ON-CHAIN.");
    cl!(out, 4); dim!(out); w!(out, "  {}", SEP);
    cl!(out, 5);

    cl!(out, 6); bright!(out); w!(out, "  TAPROOT ADDRESS");
    cl!(out, 7); green!(out);
    w!(out, "   {}", app.musig2_address.as_deref().unwrap_or(""));
    cl!(out, 8);
    cl!(out, 9); bright!(out); w!(out, "  AGGREGATE OUTPUT KEY (X-ONLY)");
    cl!(out, 10); green!(out);
    w!(out, "   {}", app.musig2_agg_key.as_deref().unwrap_or(""));
    cl!(out, 11);
    cl!(out, 12); dim!(out); w!(out, "  PUBKEY 1 : ");
    green!(out); w!(out, "{}", truncate(&app.musig2_key1, 66));
    cl!(out, 13); dim!(out); w!(out, "  PUBKEY 2 : ");
    green!(out); w!(out, "{}", truncate(&app.musig2_key2, 66));
    cl!(out, 14);
    if let Some(path) = &app.saved { cl!(out, 14); green!(out); w!(out, "  SAVED: {}  ", path); warn!(out); w!(out, "KEEP THIS FILE SECURE"); }
    else if let Some(err) = &app.error { cl!(out, 14); warn!(out); w!(out, "  ! {}", err); }
    cl!(out, 15); dim!(out); w!(out, "  {}", SEP);
    cl!(out, 16); w!(out, "  ");
    hint_bar(out, &[("S", "SAVE"), ("ESC", "NEW DERIVATION")])?;
    for r in 17..30 { cl!(out, r); }
    Ok(())
}

// ── Setup ─────────────────────────────────────────────────────────────────────

fn draw_setup(out: &mut impl Write, app: &App) -> Result<()> {
    clear_body!(out);
    let focused = |f: Field| app.field == f;

    cl!(out, 2);
    warn!(out); w!(out, "  {}", app.addr_type.short());
    dim!(out); w!(out, "  /  ESC CHANGE TYPE");
    cl!(out, 3);

    cl!(out, 5);
    if focused(Field::Mode) { green!(out); w!(out, "] "); } else { dim!(out); w!(out, "  "); }
    dim!(out); w!(out, "MODE    : ");
    for m in Mode::all() {
        if *m == app.mode {
            inv_on!(out); w!(out, " {} ", m.label()); inv_off!(out);
        } else {
            dim!(out); w!(out, " {} ", m.label());
        }
        green!(out);
    }
    cl!(out, 6);
    cl!(out, 7);

    let mut row: u16 = 8;
    {
        let label = match &app.mode {
            Mode::Prefix => "PREFIX  : ",
            Mode::Suffix => "SUFFIX  : ",
            Mode::Regex  => "REGEX   : ",
        };
        cl!(out, row);
        if focused(Field::Pattern) { green!(out); w!(out, "] "); } else { dim!(out); w!(out, "  "); }
        dim!(out); w!(out, "{}", label);
        green!(out); w!(out, "{}", app.pattern_input);
        if focused(Field::Pattern) { inv_on!(out); w!(out, " "); inv_off!(out); }
        row += 1;
    }

    cl!(out, row); row += 1;
    cl!(out, row);
    if focused(Field::Threads) { green!(out); w!(out, "] "); } else { dim!(out); w!(out, "  "); }
    dim!(out); w!(out, "THREADS : "); green!(out); w!(out, "{}", app.threads_input);
    if focused(Field::Threads) { inv_on!(out); w!(out, " "); inv_off!(out); }
    dim!(out); w!(out, "  1-256");
    row += 1;

    cl!(out, row);
    if focused(Field::Count) { green!(out); w!(out, "] "); } else { dim!(out); w!(out, "  "); }
    dim!(out); w!(out, "FIND    : "); green!(out); w!(out, "{}", app.count_input);
    if focused(Field::Count) { inv_on!(out); w!(out, " "); inv_off!(out); }
    dim!(out); w!(out, "  1-1000");
    row += 1;

    if app.addr_type.supports_merkle() && matches!(app.mode, Mode::Prefix | Mode::Suffix) {
        cl!(out, row);
        if focused(Field::Merkle) { green!(out); w!(out, "] "); } else { dim!(out); w!(out, "  "); }
        dim!(out); w!(out, "MERKLE  : ");
        if app.merkle_input.is_empty() { dim!(out); w!(out, "(NONE)"); }
        else { green!(out); w!(out, "{}", truncate(&app.merkle_input, 48)); }
        if focused(Field::Merkle) { inv_on!(out); w!(out, " "); inv_off!(out); }
        row += 1;
    }

    cl!(out, row); row += 1;
    cl!(out, row);
    match &app.mode {
        Mode::Prefix => {
            let diff = difficulty_for_prefix(&app.pattern_input, app.addr_type);
            dim!(out); w!(out, "  DIFFICULTY  : ~{} ATTEMPTS", fmt_num(diff as u64));
            if matches!(app.addr_type, AddrType::Legacy | AddrType::NestedSegWit) {
                w!(out, "  (CASE-SENSITIVE)");
            }
            if matches!(app.addr_type, AddrType::Legacy)
                && app.pattern_input.len() > 1
                && legacy_prefix_is_rare(&app.pattern_input)
            {
                row += 1;
                cl!(out, row);
                warn!(out); w!(out, "  ! ONLY ~4% OF LEGACY ADDRESSES CAN MATCH — EXPECT SLOWER RESULTS");
            }
        }
        Mode::Suffix => {
            let diff = difficulty_for_suffix(app.pattern_input.len(), app.addr_type);
            dim!(out); w!(out, "  DIFFICULTY  : ~{} ATTEMPTS", fmt_num(diff as u64));
        }
        Mode::Regex => { dim!(out); w!(out, "  DIFFICULTY  : VARIES (REGEX)"); }
    }
    row += 1;

    cl!(out, row); row += 1;
    if let Some(err) = &app.error {
        cl!(out, row); warn!(out); w!(out, "  ? {}", err);
        row += 1;
    } else if let Some(w) = &app.input_warn {
        cl!(out, row); warn!(out); w!(out, "  {}", w);
        row += 1;
    } else {
        cl!(out, row); row += 1;
    }
    cl!(out, row); row += 1;
    cl!(out, row); dim!(out); w!(out, "  {}", SEP); row += 1;
    cl!(out, row); w!(out, "  ");
    hint_bar(out, &[("RETURN", "START"), ("TAB", "NEXT"), ("SPACE", "CYCLE MODE"), ("ESC", "CHANGE TYPE")])?;
    row += 1;
    for r in row..32 { cl!(out, r); }
    Ok(())
}

// ── Running ───────────────────────────────────────────────────────────────────

fn draw_running(out: &mut impl Write, app: &App) -> Result<()> {
    clear_body!(out);
    let mode_label = app.run_mode.label();
    cl!(out, 2); dim!(out);
    w!(out, "  {} / {} / ", app.run_addr_type.short(), mode_label);
    warn!(out); w!(out, "{}", app.run_pattern);
    cl!(out, 3);
    cl!(out, 4);
    dim!(out); w!(out, "  ATTEMPTS ");
    bright!(out); w!(out, "{}", fmt_num(app.attempts.load(Ordering::Relaxed)));
    dim!(out); w!(out, "   RATE ");
    bright!(out); w!(out, "{}", fmt_rate(app.rate()));
    dim!(out); w!(out, "   ELAPSED ");
    bright!(out); w!(out, "{}", fmt_dur(app.elapsed()));
    cl!(out, 5);
    cl!(out, 6); dim!(out); w!(out, "  {}", SEP);
    cl!(out, 7);

    let found = app.found_count.load(Ordering::Relaxed);
    cl!(out, 8);
    let dots = match (app.elapsed() * 3.0) as u64 % 4 { 0 => ".", 1 => "..", 2 => "...", _ => "" };
    warn!(out);
    if found == 0 {
        w!(out, "  SEARCHING{}", dots);
    } else {
        w!(out, "  {} OF {} FOUND", found, app.run_count);
    }

    let results = app.results.lock().unwrap_or_else(|e| e.into_inner());
    let recent: Vec<_> = results.iter().rev().take(3).collect();
    for (i, m) in recent.iter().enumerate() {
        cl!(out, 9 + i as u16);
        dim!(out); w!(out, "  + "); green!(out); w!(out, "{}", truncate(&m.address, 58));
    }
    for i in recent.len()..3 { cl!(out, 9 + i as u16); }

    cl!(out, 14); dim!(out); w!(out, "  {}", SEP);
    cl!(out, 15); w!(out, "  ");
    hint_bar(out, &[("ESC", "ABORT")])?;
    Ok(())
}

// ── Results ───────────────────────────────────────────────────────────────────

fn draw_results(out: &mut impl Write, app: &App) -> Result<()> {
    clear_body!(out);
    let results = app.results.lock().unwrap_or_else(|e| e.into_inner());

    cl!(out, 2); dim!(out);
    w!(out, "  {} / {} / {} / {}",
        app.run_addr_type.short(),
        fmt_dur(app.elapsed()),
        fmt_num(app.attempts.load(Ordering::Relaxed)),
        if results.len() == 1 { "1 MATCH".to_string() } else { format!("{} MATCHES", results.len()) });
    cl!(out, 3);
    cl!(out, 4); dim!(out); w!(out, "  {}", SEP);
    cl!(out, 5);

    let mut row: u16 = 6;
    if results.is_empty() {
        cl!(out, row); green!(out); w!(out, "  NO RESULTS."); row += 1;
    } else {
        if results.len() > 1 {
            cl!(out, row);
            for (i, _) in results.iter().enumerate() {
                if i == app.selected { inv_on!(out); w!(out, " {:>2} ", i + 1); inv_off!(out); }
                else { dim!(out); w!(out, " {:>2} ", i + 1); }
            }
            row += 2;
        }
        if let Some(m) = results.get(app.selected) {
            cl!(out, row); bright!(out); w!(out, "  ADDRESS");
            row += 1;
            cl!(out, row); green!(out); w!(out, "   {}", m.address);
            row += 2;

            let pubkey_label = match app.run_addr_type {
                AddrType::Taproot => "  OUTPUT KEY (TWEAKED X-ONLY PUBKEY)",
                _                 => "  COMPRESSED PUBLIC KEY",
            };
            cl!(out, row); bright!(out); w!(out, "{}", pubkey_label);
            row += 1;
            cl!(out, row); green!(out); w!(out, "   {}", truncate(&m.pubkey, 66));
            row += 1;
            if app.run_addr_type == AddrType::Taproot {
                cl!(out, row); dim!(out); w!(out, "  COMPRESSED PUBKEY (USE FOR MUSIG2)");
                row += 1;
                cl!(out, row); green!(out); w!(out, "   {}", truncate(&m.compressed_pubkey, 68));
                row += 1;
            }
            row += 1;
            cl!(out, row); bright!(out); w!(out, "  WIF (PRIVATE KEY) ");
            warn!(out); w!(out, "(KEEP SECRET)");
            row += 1;
            cl!(out, row); bright!(out); w!(out, "   {}", m.wif);
            row += 2;
        }
    }

    cl!(out, row); row += 1;
    cl!(out, row); dim!(out); w!(out, "{}", SEP); row += 1;
    cl!(out, row);
    if let Some(path) = &app.saved { green!(out); w!(out, "  SAVED: {}  ", path); warn!(out); w!(out, "KEEP THIS FILE SECURE"); row += 1; cl!(out, row); }
    else { dim!(out); w!(out, "  SAVES TO: {}", app.output_dir); row += 1; cl!(out, row); }
    if let Some(err)  = &app.error { warn!(out); w!(out, "  ! {}", err); row += 1; cl!(out, row); }
    dim!(out);
    let mut hints: Vec<(&str, &str)> = vec![];
    if results.len() > 1 { hints.push(("↑↓", "SELECT")); }
    if !results.is_empty() { hints.push(("S", "SAVE")); }
    hints.push(("I", "INSPECT"));
    hints.push(("N", "NEW"));
    hints.push(("ESC", "BACK"));
    w!(out, "  ");
    hint_bar(out, &hints)?;
    // clear any stale rows from previous longer renders
    for r in (row + 1)..30 { cl!(out, r); }
    Ok(())
}

// ── Inspector ─────────────────────────────────────────────────────────────────

fn draw_inspector(out: &mut impl Write, app: &App) -> Result<()> {
    clear_body!(out);
    let mut row: u16 = 2;
    cl!(out, row); dim!(out); w!(out, "{}", SEP); row += 1;
    cl!(out, row); warn!(out); w!(out, "  ADDRESS INSPECTOR"); row += 2;
    cl!(out, row); dim!(out); w!(out, "  PASTE ANY BITCOIN ADDRESS:"); row += 1;
    cl!(out, row); green!(out); w!(out, "  > {}", app.inspector_input);
    inv_on!(out); w!(out, " "); inv_off!(out);
    row += 2;

    if let Some(r) = &app.inspector_result {
        cl!(out, row); dim!(out); w!(out, "{}", SEP); row += 1;
        cl!(out, row); dim!(out); w!(out, "  TYPE           : "); warn!(out); w!(out, "{}", r.addr_type); row += 1;
        cl!(out, row); dim!(out); w!(out, "  NETWORK        : "); green!(out); w!(out, "{}", r.network); row += 1;
        cl!(out, row); dim!(out); w!(out, "  ENCODING       : "); green!(out); w!(out, "{}", r.encoding); row += 1;
        cl!(out, row); dim!(out); w!(out, "  ADDRESS        : "); green!(out); w!(out, "{}", truncate(&r.address, 62)); row += 1;
        cl!(out, row); dim!(out); w!(out, "  KEY / HASH     : "); green!(out); w!(out, "{}", truncate(&r.pubkey_hex, 64)); row += 2;
        if let Some(st) = &r.spend_type {
            if r.is_nums {
                cl!(out, row); warn!(out); w!(out, "  SPEND TYPE     : {}", st); row += 2;
            } else {
                cl!(out, row); dim!(out); w!(out, "  SPEND TYPE     : "); warn!(out); w!(out, "{}", st); row += 2;
            }
        }
        cl!(out, row); dim!(out); w!(out, "  FINGERPRINT    : "); green!(out); w!(out, "{}", r.hash_type); row += 1;
        cl!(out, row); dim!(out); w!(out, "  KEY SPACE      : "); green!(out); w!(out, "{:.0} BITS", r.entropy_bits); row += 1;
        cl!(out, row); dim!(out); w!(out, "  PAYLOAD ENCODES: "); green!(out); w!(out, "{:.1} BITS", r.payload_bits); row += 1;
    } else if let Some(err) = &app.error {
        cl!(out, row); warn!(out); w!(out, "  ? {}", err); row += 1;
    } else {
        cl!(out, row); row += 1;
    }

    cl!(out, row);
    cl!(out, row + 1); dim!(out); w!(out, "  {}", SEP);
    cl!(out, row + 2); w!(out, "  ");
    hint_bar(out, &[("TYPE", "ADDRESS"), ("RETURN", "INSPECT"), ("ESC", "BACK")])?;
    Ok(())
}

// ── CLI (no-TUI) mode ─────────────────────────────────────────────────────────

fn run_cli(cli: &Cli) -> Result<()> {
    let addr_type: AddrType = cli.addr_type.parse()
        .map_err(|e: String| anyhow::anyhow!("{}", e))?;
    let threads = cli.threads.unwrap_or_else(num_cpus);
    let count   = cli.count;

    let pattern = cli.pattern.clone()
        .ok_or_else(|| anyhow::anyhow!("--pattern is required in --no-tui mode"))?;
    let is_bech32 = matches!(addr_type, AddrType::Taproot | AddrType::NativeSegWit);
    // Bech32 addresses are lowercase-only by spec. Base58 is case-sensitive.
    let match_pat = if is_bech32 { pattern.to_lowercase() } else { pattern.clone() };
    let mode_str  = cli.mode.clone();

    type Matcher = Arc<dyn Fn(&str) -> bool + Send + Sync>;
    let matcher: Matcher = match mode_str.as_str() {
        "prefix" => {
            validate_prefix(&match_pat, addr_type)?;
            let p = match_pat.clone();
            Arc::new(move |addr: &str| addr.starts_with(&p))
        }
        "suffix" => {
            validate_suffix_chars(&match_pat, addr_type)?;
            let p = match_pat.clone();
            Arc::new(move |addr: &str| addr.ends_with(&p))
        }
        "regex" => {
            let re = build_regex(&pattern)?;
            Arc::new(move |addr: &str| re.is_match(addr))
        }
        _ => bail!("Unknown mode: {}. Use prefix, suffix, or regex.", mode_str),
    };

    let attempts    = Arc::new(AtomicU64::new(0));
    let found_count = Arc::new(AtomicU64::new(0));
    let done        = Arc::new(AtomicBool::new(false));
    let (tx, rx)    = bounded::<FoundAddr>(64);
    let start       = Instant::now();

    let case_note = if !is_bech32 && mode_str != "regex"
        { " (case-sensitive)" } else { "" };
    eprintln!("Searching for {} {} address matching {}{}{}...",
        addr_type.short(), mode_str, pattern, case_note,
        if count > 1 { format!(" ({} matches)", count) } else { String::new() });

    spawn_workers(
        threads, addr_type, None, matcher, count,
        Arc::clone(&attempts), Arc::clone(&found_count), Arc::clone(&done), tx,
    );

    let mut found = 0;
    for m in rx {
        found += 1;
        println!("--- match {} ---", found);
        println!("address    : {}", m.address);
        println!("pubkey     : {}", m.pubkey);
        if m.pubkey != m.compressed_pubkey {
            println!("compressed : {}", m.compressed_pubkey);
        }
        println!("wif        : {}", m.wif);
    }

    let elapsed = start.elapsed().as_secs_f64();
    let total   = attempts.load(Ordering::Relaxed);
    eprintln!("Done. {} match(es) in {:.1}s — {} attempts — {}", found, elapsed, fmt_num(total), fmt_rate(total as f64 / elapsed));
    Ok(())
}

fn run_bench(cli: &Cli) -> Result<()> {
    let addr_type: AddrType = cli.addr_type.parse()
        .map_err(|e: String| anyhow::anyhow!("{}", e))?;
    let threads = cli.threads.unwrap_or_else(num_cpus);
    let bench_secs = 5.0_f64;

    eprintln!("Benchmarking {} address generation on {} threads for {:.0}s...",
        addr_type.short(), threads, bench_secs);

    let attempts = Arc::new(AtomicU64::new(0));
    let done     = Arc::new(AtomicBool::new(false));

    for _ in 0..threads {
        let attempts = Arc::clone(&attempts);
        let done     = Arc::clone(&done);
        thread::spawn(move || {
            let mut rng = thread_rng();
            let mut local_count: u64 = 0;
            while !done.load(Ordering::Relaxed) {
                let secret = SecretKey::new(&mut rng);
                let _ = App::generate_address(&secret, addr_type);
                local_count += 1;
                if local_count % ATTEMPT_BATCH == 0 {
                    attempts.fetch_add(ATTEMPT_BATCH, Ordering::Relaxed);
                }
            }
            attempts.fetch_add(local_count % ATTEMPT_BATCH, Ordering::Relaxed);
        });
    }

    let start = Instant::now();
    thread::sleep(Duration::from_secs_f64(bench_secs));
    done.store(true, Ordering::Relaxed);

    let total   = attempts.load(Ordering::Relaxed);
    let elapsed = start.elapsed().as_secs_f64();
    let rate    = total as f64 / elapsed;

    println!("Result : {}", fmt_rate(rate));
    println!("Threads: {}", threads);
    println!("Type   : {}", addr_type.short());
    println!();

    let cs  = addr_type.charset_size();
    let pfx = addr_type.default_prefix();
    println!("Estimates at this rate (avg attempts for N vanity chars):");
    for extra in 1..=8u32 {
        let diff = cs.powi(extra as i32);
        println!("  {}+{} : avg {}", pfx, extra, fmt_dur(diff / rate));
    }
    if matches!(addr_type, AddrType::Legacy | AddrType::NestedSegWit) {
        println!();
        println!("Note: base58 estimates assume uniform character distribution.");
        println!("Actual difficulty varies by character — rare prefixes may take longer.");
    }
    Ok(())
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.bench {
        return run_bench(&cli);
    }

    if cli.no_tui {
        return run_cli(&cli);
    }

    // Install panic hook to restore terminal on crash
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            terminal::LeaveAlternateScreen,
            cursor::Show,
            SetForegroundColor(Color::Reset),
            crossterm::style::SetBackgroundColor(Color::Reset)
        );
        original_hook(info);
    }));

    let mut stdout = io::stdout();
    terminal::enable_raw_mode()?;
    execute!(
        stdout,
        terminal::EnterAlternateScreen,
        cursor::Hide,
        crossterm::style::SetBackgroundColor(BLACK),
        SetForegroundColor(GREEN),
        terminal::Clear(ClearType::All),
        terminal::SetTitle("ADDRFORGE")
    )?;

    let mut app = App::new();
    app.output_dir = cli.output_dir.clone();

    loop {
        draw(&mut stdout, &app)?;

        if event::poll(Duration::from_millis(TICK_MS))? {
            match event::read()? {
                Event::Resize(_, _) => {
                    execute!(
                        stdout,
                        terminal::Clear(ClearType::All),
                        crossterm::style::SetBackgroundColor(BLACK),
                        SetForegroundColor(GREEN),
                        cursor::Hide,
                    )?;
                    continue;
                }
                Event::Key(k) => {
                if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
                    break;
                }

                if k.code == KeyCode::F(2)
                    && matches!(app.screen, Screen::Setup | Screen::Results |
                                Screen::TypePicker | Screen::SigningPicker | Screen::MuSig2Setup)
                {
                    app.prev_screen = app.screen;
                    app.screen = Screen::Inspector;
                    continue;
                }

                if k.code == KeyCode::Esc {
                    match app.screen {
                        Screen::SigningPicker => break,
                        Screen::TypePicker    => { app.screen = Screen::SigningPicker; }
                        Screen::MuSig2Setup   => { app.screen = Screen::SigningPicker; app.error = None; }
                        Screen::MuSig2Result  => {
                            app.screen = Screen::MuSig2Setup;
                            app.musig2_agg_key = None;
                            app.musig2_address = None;
                            app.saved = None;
                            queue!(stdout, terminal::Clear(ClearType::All))?;
                        }
                        Screen::Setup => { app.screen = Screen::TypePicker; app.input_warn = None; }
                        Screen::Running => {
                            app.done.store(true, Ordering::Relaxed);
                            let session    = std::mem::replace(&mut app.session, Session::new());
                            let output_dir = app.output_dir.clone();
                            app = App::new_with_config(output_dir, session);
                            queue!(stdout, terminal::Clear(ClearType::All))?;
                        }
                        Screen::Results => {
                            // ESC goes back to Setup — keep addr type, network, mode, pattern
                            // so the user can tweak and search again immediately.
                            // N) NEW resets all the way to SigningPicker.
                            app.screen = Screen::Setup;
                            app.error  = None;
                            app.saved  = None;
                            queue!(stdout, terminal::Clear(ClearType::All))?;
                        }
                        Screen::Inspector => { app.screen = app.prev_screen; }
                    }
                    continue;
                }

                match app.screen {
                    Screen::SigningPicker => on_signing_picker_key(&mut app, k.code),
                    Screen::TypePicker    => on_picker_key(&mut app, k.code),
                    Screen::MuSig2Setup   => on_musig2_setup_key(&mut app, k.code),
                    Screen::MuSig2Result  => on_musig2_result_key(&mut app, k.code),
                    Screen::Setup         => on_setup_key(&mut app, k.code),
                    Screen::Running       => {}
                    Screen::Results       => on_results_key(&mut app, k.code),
                    Screen::Inspector     => on_inspector_key(&mut app, k.code),
                }
                } // end Event::Key
                _ => {}
            } // end match event
        }

        app.tick();
    }

    app.done.store(true, Ordering::Relaxed);
    terminal::disable_raw_mode()?;
    execute!(
        stdout,
        terminal::LeaveAlternateScreen,
        cursor::Show,
        SetForegroundColor(Color::Reset),
        crossterm::style::SetBackgroundColor(Color::Reset)
    )?;
    Ok(())
}

// ── Key handlers ─────────────────────────────────────────────────────────────

fn on_signing_picker_key(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Up   | KeyCode::Char('k') => { app.signing_sel = app.signing_sel.saturating_sub(1); }
        KeyCode::Down | KeyCode::Char('j') => { app.signing_sel = (app.signing_sel + 1).min(1); }
        KeyCode::Enter => {
            if app.signing_sel == 0 {
                app.screen       = Screen::TypePicker;
            } else {
                app.screen       = Screen::MuSig2Setup;
                app.error        = None;
            }
        }
        _ => {}
    }
}

fn on_picker_key(app: &mut App, key: KeyCode) {
    let n = AddrType::all().len();
    match key {
        KeyCode::Up   | KeyCode::Char('k') => { app.picker_sel = app.picker_sel.saturating_sub(1); }
        KeyCode::Down | KeyCode::Char('j') => { app.picker_sel = (app.picker_sel + 1).min(n - 1); }
        KeyCode::Enter => {
            let t = AddrType::all()[app.picker_sel];
            app.select_addr_type(t);

        }
        _ => {}
    }
}

fn on_musig2_setup_key(app: &mut App, key: KeyCode) {
    app.error = None;
    let fields = [MuSig2Field::Key1, MuSig2Field::Key2];
    match key {
        KeyCode::Tab | KeyCode::Down => {
            let pos = fields.iter().position(|f| *f == app.musig2_field).unwrap_or(0);
            app.musig2_field = fields[(pos + 1) % fields.len()];
        }
        KeyCode::BackTab | KeyCode::Up => {
            let pos = fields.iter().position(|f| *f == app.musig2_field).unwrap_or(0);
            app.musig2_field = fields[(pos + fields.len() - 1) % fields.len()];
        }
        KeyCode::Enter => {
            if let Err(e) = app.derive_musig2() {
                app.error = Some(e.to_string());
            }
        }
        KeyCode::Backspace => {
            match app.musig2_field {
                MuSig2Field::Key1 => { app.musig2_key1.pop(); app.musig2_agg_key = None; app.musig2_address = None; }
                MuSig2Field::Key2 => { app.musig2_key2.pop(); app.musig2_agg_key = None; app.musig2_address = None; }
            }
        }
        KeyCode::Char(c) => {
            if c.is_ascii_hexdigit() {
                let lc = c.to_ascii_lowercase();
                match app.musig2_field {
                    MuSig2Field::Key1 => { if app.musig2_key1.len() < 66 { app.musig2_key1.push(lc); } }
                    MuSig2Field::Key2 => { if app.musig2_key2.len() < 66 { app.musig2_key2.push(lc); } }
                }
                app.musig2_agg_key = None;
                app.musig2_address = None;
            }
        }
        _ => {}
    }
}

fn on_musig2_result_key(app: &mut App, key: KeyCode) {
    if let KeyCode::Char('s') | KeyCode::Char('S') = key {
        app.save_musig2_result();
    }
}

fn setup_fields(mode: &Mode, addr_type: AddrType) -> Vec<Field> {
    let mut f = vec![Field::Mode];
    f.extend([Field::Pattern, Field::Threads, Field::Count]);
    if addr_type.supports_merkle() && matches!(mode, Mode::Prefix | Mode::Suffix) {
        f.push(Field::Merkle);
    }
    f
}

fn on_setup_key(app: &mut App, key: KeyCode) {
    app.error = None;
    app.input_warn = None;
    match key {
        KeyCode::Tab | KeyCode::Down => {
            let fields = setup_fields(&app.mode, app.addr_type);
            let pos = fields.iter().position(|f| *f == app.field).unwrap_or(0);
            app.field = fields[(pos + 1) % fields.len()];
        }
        KeyCode::BackTab | KeyCode::Up => {
            let fields = setup_fields(&app.mode, app.addr_type);
            let pos = fields.iter().position(|f| *f == app.field).unwrap_or(0);
            app.field = fields[(pos + fields.len() - 1) % fields.len()];
        }
        KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right => {
            match app.field {
                Field::Mode => {
                    let all = Mode::all();
                    let pos = all.iter().position(|m| *m == app.mode).unwrap_or(0);
                    app.mode = all[(pos + 1) % all.len()];
                    let def = app.addr_type.default_prefix().to_string();
                    match &app.mode {
                        Mode::Prefix => app.pattern_input = def.clone(),
                        Mode::Suffix | Mode::Regex => {
                            if app.pattern_input.to_lowercase() == def || app.pattern_input.to_lowercase().starts_with(&def) {
                                app.pattern_input = String::new();
                            }
                        }
                    }
                }

                _ => {}
            }
        }
        KeyCode::Enter => {
            if let Err(e) = app.start_search() {
                app.error = Some(e.to_string());
            }
        }
        KeyCode::Backspace => {
            match app.field {
                Field::Pattern => {
                    let min = if app.mode == Mode::Prefix {
                        app.addr_type.fixed_prefix_len()
                    } else { 0 };
                    if app.pattern_input.len() > min { app.pattern_input.pop(); }
                }
                Field::Threads => { app.threads_input.pop(); }
                Field::Count   => { app.count_input.pop(); }
                Field::Merkle  => { app.merkle_input.pop(); }
                Field::Mode => {}
            }
        }
        KeyCode::Char(c) => {
            match app.field {
                Field::Mode => {}
                Field::Pattern => {
                    let charset   = app.addr_type.charset();
                    let fixed     = app.addr_type.fixed_prefix_len();
                    let is_base58 = matches!(app.addr_type, AddrType::Legacy | AddrType::NestedSegWit);
                    let normalise = |ch: char| if is_base58 { ch } else { ch.to_ascii_lowercase() };
                    let char_allowed = |ch: char| -> bool {
                        if is_base58 { charset.contains(ch) }
                        else { charset.contains(ch.to_ascii_lowercase()) }
                    };
                    match &app.mode {
                        Mode::Prefix => {
                            if app.pattern_input.len() < fixed {
                                // Still in the fixed prefix portion — accept any char
                                app.pattern_input.push(normalise(c));
                            } else if app.pattern_input.len() >= fixed + 12 {
                                app.input_warn = Some("MAX LENGTH REACHED".into());
                            } else if !char_allowed(c) {
                                app.input_warn = Some(format!(
                                    "'{}' NOT IN {} CHARSET", c, app.addr_type.short()));
                            } else {
                                // Tentatively add the character, then check reachability
                                app.pattern_input.push(normalise(c));
                                if is_base58 {
                                    let version = match app.addr_type {
                                        AddrType::Legacy       => 0x00u8,
                                        AddrType::NestedSegWit => 0x05u8,
                                        _ => unreachable!(),
                                    };
                                    if !is_base58_prefix_reachable(&app.pattern_input, version) {
                                        app.pattern_input.pop(); // undo
                                        app.input_warn = Some(format!(
                                            "PREFIX '{}{}' IS UNREACHABLE FOR {}",
                                            app.pattern_input, normalise(c), app.addr_type.short()));
                                    }
                                }
                            }
                        }
                        Mode::Suffix => {
                            if app.pattern_input.len() >= 12 {
                                app.input_warn = Some("MAX LENGTH REACHED".into());
                            } else if !char_allowed(c) {
                                app.input_warn = Some(format!(
                                    "'{}' NOT IN {} CHARSET", c, app.addr_type.short()));
                            } else {
                                app.pattern_input.push(normalise(c));
                            }
                        }
                        Mode::Regex => { app.pattern_input.push(c); }
                    }
                }
                Field::Threads => { if c.is_ascii_digit() { app.threads_input.push(c); } }
                Field::Count   => { if c.is_ascii_digit() { app.count_input.push(c); } }
                Field::Merkle  => { if c.is_ascii_hexdigit() { app.merkle_input.push(c.to_ascii_uppercase()); } }
            }
        }
        _ => {}
    }
}

fn on_results_key(app: &mut App, key: KeyCode) {
    let n = app.results.lock().unwrap_or_else(|e| e.into_inner()).len();
    match key {
        KeyCode::Up   | KeyCode::Char('k') | KeyCode::Char('K') => {
            app.selected = app.selected.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') | KeyCode::Char('J') => {
            if n > 0 { app.selected = (app.selected + 1).min(n - 1); }
        }
        KeyCode::Char('s') | KeyCode::Char('S') => { app.save_results(); }
        KeyCode::Char('i') | KeyCode::Char('I') => {
            if let Some(m) = app.results.lock().unwrap_or_else(|e| e.into_inner()).get(app.selected).cloned() {
                app.inspector_input  = m.address.clone();
                app.inspector_result = inspect_address(&m.address).ok();
            }
            app.prev_screen = Screen::Results;
            app.screen      = Screen::Inspector;
        }
        KeyCode::Char('n') | KeyCode::Char('N') => {
            let session    = std::mem::replace(&mut app.session, Session::new());
            let output_dir = app.output_dir.clone();
            *app = App::new_with_config(output_dir, session);
        }
        _ => {}
    }
}

fn on_inspector_key(app: &mut App, key: KeyCode) {
    app.error = None;
    match key {
        KeyCode::Backspace => { app.inspector_input.pop(); app.inspector_result = None; }
        KeyCode::Enter => {
            match inspect_address(&app.inspector_input) {
                Ok(r)  => { app.inspector_result = Some(r); }
                Err(e) => { app.error = Some(e.to_string()); app.inspector_result = None; }
            }
        }
        KeyCode::Char(c) => {
            // Accept alphanumeric as-is (Base58 is case-sensitive, bech32 is lowercase)
            if c.is_ascii_alphanumeric() && app.inspector_input.len() < 100 {
                app.inspector_input.push(c);
                app.inspector_result = None;
            }
        }
        _ => {}
    }
}