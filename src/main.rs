mod address;
mod config;
mod difficulty;
mod musig;
mod search;
mod types;
mod ui;

use anyhow::{bail, Result};
use bitcoin::{secp256k1::rand::thread_rng, Network};
use clap::Parser;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal,
};
use ratatui::{backend::CrosstermBackend, Terminal};
use regex::Regex;
use std::{
    fs,
    io::{self},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use address::{generate_address, inspect_address, FoundAddr, InspectorResult};
use difficulty::is_base58_prefix_reachable;
use musig::{musig_aggregate, parse_pubkey_hex};
use search::{make_channel, spawn_workers, Session};
use types::{AddrType, Mode, network_all, network_label};

// ── Constants (pub so ui.rs can read them) ────────────────────────────────────

pub const VERSION: &str = concat!("V", env!("CARGO_PKG_VERSION"));
const TICK_MS: u64 = 100;

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

    /// Network: mainnet, testnet, signet, regtest [default: mainnet]
    #[arg(long, default_value = "mainnet")]
    network: String,
}

pub fn parse_network(s: &str) -> Result<Network> {
    match s.to_lowercase().as_str() {
        "mainnet" | "bitcoin" | "main" => Ok(Network::Bitcoin),
        "testnet" | "test"             => Ok(Network::Testnet),
        "signet"  | "sig"              => Ok(Network::Signet),
        "regtest" | "reg"              => Ok(Network::Regtest),
        _ => bail!("Unknown network '{}'. Use mainnet, testnet, signet, or regtest.", s),
    }
}

fn network_to_str(n: Network) -> &'static str {
    match n {
        Network::Bitcoin => "mainnet",
        Network::Testnet => "testnet",
        Network::Signet  => "signet",
        Network::Regtest => "regtest",
        _                => "mainnet",
    }
}

fn addr_type_to_str(t: AddrType) -> &'static str {
    match t {
        AddrType::Legacy       => "legacy",
        AddrType::NestedSegWit => "nested",
        AddrType::NativeSegWit => "native",
        AddrType::Taproot      => "taproot",
    }
}

fn mode_to_str(m: Mode) -> &'static str {
    match m { Mode::Prefix => "prefix", Mode::Suffix => "suffix", Mode::Regex => "regex" }
}

// ── TUI Screens / Fields ──────────────────────────────────────────────────────

#[derive(PartialEq, Clone, Copy)]
pub enum Screen {
    ModePicker, TypePicker, MuSig2Setup, MuSig2Result,
    Setup, Running, Results, Inspector,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Field { Network, Mode, Pattern, Threads, Count, Merkle }

// ── App ───────────────────────────────────────────────────────────────────────

pub struct App {
    pub screen:      Screen,
    pub prev_screen: Screen,

    // mode picker
    pub mode_sel: usize,

    // type picker
    pub addr_type:  AddrType,
    pub picker_sel: usize,

    // setup
    pub network:       Network,
    pub field:         Field,
    pub mode:          Mode,
    pub pattern_input: String,
    pub threads_input: String,
    pub count_input:   String,
    pub merkle_input:  String,
    pub error:         Option<String>,
    pub input_warn:    Option<String>,

    // musig2 setup (n-of-m)
    pub musig2_keys:    Vec<String>,
    pub musig2_input:   String,
    pub musig2_agg_key: Option<String>,
    pub musig2_address: Option<String>,

    // runtime
    pub start:       Option<Instant>,
    pub finish:      Option<Instant>,
    pub attempts:    Arc<AtomicU64>,
    pub found_count: Arc<AtomicU64>,
    pub done:        Arc<AtomicBool>,
    pub results:     Arc<Mutex<Vec<FoundAddr>>>,
    pub rx:          Option<crossbeam_channel::Receiver<FoundAddr>>,

    // run snapshot
    pub run_addr_type: AddrType,
    pub run_pattern:   String,
    pub run_mode:      Mode,
    pub run_count:     usize,
    pub run_threads:   usize,
    pub run_network:   Network,

    // results
    pub selected: usize,
    pub saved:    Option<String>,

    // inspector
    pub inspector_input:  String,
    pub inspector_result: Option<InspectorResult>,

    // config
    pub output_dir: String,

    // session
    pub session: Session,
}

impl App {
    fn new() -> Self {
        Self {
            screen:          Screen::ModePicker,
            prev_screen:     Screen::ModePicker,
            mode_sel:        0,
            addr_type:       AddrType::Taproot,
            picker_sel:      0,
            network:         Network::Bitcoin,
            field:           Field::Mode,
            mode:            Mode::Prefix,
            pattern_input:   "bc1p".into(),
            threads_input:   num_cpus().to_string(),
            count_input:     "1".into(),
            merkle_input:    String::new(),
            error:           None,
            input_warn:      None,
            musig2_keys:     Vec::new(),
            musig2_input:    String::new(),
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
            run_network:     Network::Bitcoin,
            selected:        0,
            saved:           None,
            inspector_input:  String::new(),
            inspector_result: None,
            output_dir:       ".".into(),
            session:          Session::new(),
        }
    }

    fn new_with_config(output_dir: String, session: Session, network: Network) -> Self {
        let mut a = Self::new();
        a.output_dir = output_dir;
        a.session    = session;
        a.network    = network;
        a
    }

    fn apply_config(&mut self, cfg: &config::Config) {
        if let Some(at) = &cfg.addr_type {
            if let Ok(t) = at.parse::<AddrType>() { self.addr_type = t; }
        }
        if let Some(net) = &cfg.network {
            if let Ok(n) = parse_network(net) { self.network = n; }
        }
        if let Some(m) = &cfg.mode {
            self.mode = match m.as_str() { "suffix" => Mode::Suffix, "regex" => Mode::Regex, _ => Mode::Prefix };
        }
        if let Some(t) = cfg.threads { self.threads_input = t.to_string(); }
        if let Some(od) = &cfg.output_dir { self.output_dir = od.clone(); }
        // Refresh pattern for resolved addr_type + network
        if self.mode == Mode::Prefix {
            self.pattern_input = self.addr_type.default_prefix(self.network).to_string();
        }
    }

    fn to_config(&self) -> config::Config {
        config::Config {
            addr_type:  Some(addr_type_to_str(self.addr_type).to_string()),
            network:    Some(network_to_str(self.network).to_string()),
            mode:       Some(mode_to_str(self.mode).to_string()),
            threads:    self.threads_input.parse().ok(),
            output_dir: if self.output_dir != "." { Some(self.output_dir.clone()) } else { None },
        }
    }

    fn select_addr_type(&mut self, t: AddrType) {
        self.addr_type     = t;
        self.screen        = Screen::Setup;
        self.field         = Field::Mode;
        self.mode          = Mode::Prefix;
        self.pattern_input = t.default_prefix(self.network).to_string();
        self.merkle_input  = String::new();
        self.error         = None;
        self.input_warn    = None;
    }

    // ── MuSig2 derive ─────────────────────────────────────────────────────────

    fn derive_musig2(&mut self) -> Result<()> {
        if self.musig2_keys.len() < 2 { bail!("ADD AT LEAST 2 KEYS BEFORE DERIVING"); }
        let pubkeys: Vec<bitcoin::secp256k1::PublicKey> = self.musig2_keys
            .iter().map(|h| parse_pubkey_hex(h)).collect::<Result<_>>()?;

        let agg    = musig_aggregate(&pubkeys)?;
        let (xonly, _) = agg.x_only_public_key();
        self.musig2_agg_key = Some(hex::encode(xonly.serialize()).to_uppercase());
        self.musig2_address = Some(
            bitcoin::Address::p2tr(
                bitcoin::secp256k1::SECP256K1,
                bitcoin::key::UntweakedPublicKey::from(xonly),
                None,
                self.network,
            ).to_string()
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
        if threads == 0  { bail!("THREADS MUST BE >= 1"); }
        if threads > 256 { bail!("THREADS CAPPED AT 256"); }
        let count: usize = self.count_input.trim().parse()
            .map_err(|_| anyhow::anyhow!("COUNT MUST BE A NUMBER"))?;
        if count == 0    { bail!("COUNT MUST BE >= 1"); }
        if count > 1000  { bail!("COUNT CAPPED AT 1000"); }

        let merkle = if self.merkle_input.trim().is_empty() {
            None
        } else {
            Some(parse_merkle(self.merkle_input.trim())?)
        };
        let merkle_root = merkle.map(bitcoin::taproot::TapNodeHash::assume_hidden);

        let addr_type = self.addr_type;
        let network   = self.network;
        let is_bech32 = matches!(addr_type, AddrType::Taproot | AddrType::NativeSegWit);
        let match_pat = if is_bech32 { self.pattern_input.to_lowercase() } else { self.pattern_input.clone() };

        type Matcher = Arc<dyn Fn(&str) -> bool + Send + Sync>;
        let matcher: Matcher = match &self.mode {
            Mode::Prefix => {
                validate_prefix(&match_pat, addr_type, network)?;
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
        let (tx, rx)    = make_channel(128);

        spawn_workers(
            threads, addr_type, network, merkle_root, matcher, count,
            Arc::clone(&attempts), Arc::clone(&found_count), Arc::clone(&done), tx,
        );

        self.run_pattern   = self.pattern_input.clone();
        self.run_mode      = self.mode;
        self.run_count     = count;
        self.run_threads   = threads;
        self.run_addr_type = addr_type;
        self.run_network   = network;
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

    // ── Save ──────────────────────────────────────────────────────────────────

    fn save_musig2_result(&mut self) {
        let (Some(addr), Some(agg)) = (&self.musig2_address, &self.musig2_agg_key) else { return; };
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis();
        let filename = format!("addrforge-musig2-{}.txt", ts);
        let filepath = std::path::Path::new(&self.output_dir).join(&filename);
        let mut out = format!("ADDRFORGE {} -- MUSIG2 DERIVATION\n\n", VERSION);
        out.push_str(&format!("NETWORK        : {}\nADDRESS        : {}\nAGG OUTPUT KEY : {}\nKEY COUNT      : {}\n\n",
            network_label(self.network), addr, agg, self.musig2_keys.len()));
        for (i, k) in self.musig2_keys.iter().enumerate() {
            out.push_str(&format!("PUBKEY {:>2}       : {}\n", i + 1, k));
        }
        match fs::write(&filepath, &out) {
            Ok(_)  => self.saved = Some(filepath.to_string_lossy().into_owned()),
            Err(e) => self.error = Some(format!("SAVE FAILED: {}", e)),
        }
    }

    fn save_results(&mut self) {
        let results = self.results.lock().unwrap_or_else(|e| e.into_inner());
        if results.is_empty() { return; }
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis();
        let filename = format!("addrforge-{}.txt", ts);
        let filepath = std::path::Path::new(&self.output_dir).join(&filename);
        let mut out = format!("ADDRFORGE {} -- RESULTS\n", VERSION);
        out.push_str(&format!("TYPE    : {}\nNETWORK : {}\nMODE    : {}\nPATTERN : {}\nTHREADS : {}  COUNT : {}\nELAPSED : {}  ATTEMPTS : {}\n\n",
            self.run_addr_type.short(), network_label(self.run_network), self.run_mode.label(),
            self.run_pattern, self.run_threads, self.run_count,
            fmt_dur(self.elapsed()), fmt_num(self.attempts.load(Ordering::Relaxed))));
        for (i, m) in results.iter().enumerate() {
            out.push_str(&format!("MATCH {}\n  ADDRESS    : {}\n  PUBKEY     : {}\n", i + 1, m.address, m.pubkey));
            if self.run_addr_type == AddrType::Taproot {
                out.push_str(&format!("  COMPRESSED : {}\n", m.compressed_pubkey));
            }
            out.push_str(&format!("  WIF KEY    : {}\n  MNEMONIC   : {}\n\n", m.wif, m.mnemonic));
        }
        match fs::write(&filepath, &out) {
            Ok(_)  => self.saved = Some(filepath.to_string_lossy().into_owned()),
            Err(e) => self.error = Some(format!("SAVE FAILED: {}", e)),
        }
    }

    // ── Tick ─────────────────────────────────────────────────────────────────

    pub fn tick(&mut self) {
        if let Some(rx) = &self.rx {
            while let Ok(m) = rx.try_recv() {
                self.results.lock().unwrap_or_else(|e| e.into_inner()).push(m);
            }
        }
        if let Screen::Running = self.screen {
            if self.done.load(Ordering::Relaxed) && self.finish.is_none() {
                self.finish = Some(Instant::now());
                if let Some(rx) = &self.rx {
                    while let Ok(m) = rx.try_recv() {
                        self.results.lock().unwrap_or_else(|e| e.into_inner()).push(m);
                    }
                }
                self.session.record_run(self.attempts.load(Ordering::Relaxed), self.elapsed());
                self.screen = Screen::Results;
            }
        }
    }

    pub fn elapsed(&self) -> f64 {
        match (self.start, self.finish) {
            (Some(s), Some(f)) => (f - s).as_secs_f64(),
            (Some(s), None)    => s.elapsed().as_secs_f64(),
            _                  => 0.0,
        }
    }

    pub fn rate(&self) -> f64 {
        let e = self.elapsed();
        if e > 0.5 { self.attempts.load(Ordering::Relaxed) as f64 / e } else { 0.0 }
    }
}

// ── Validation / helpers ──────────────────────────────────────────────────────

fn validate_prefix(s: &str, addr_type: AddrType, network: Network) -> Result<String> {
    let fixed    = addr_type.fixed_prefix_len(network);
    let expected = addr_type.default_prefix(network).to_lowercase();
    if s.len() <= fixed { bail!("PREFIX TOO SHORT"); }
    if !s.starts_with(&expected) { bail!("PREFIX MUST START WITH {}", expected.to_uppercase()); }
    let charset = addr_type.charset();
    for ch in s[fixed..].chars() {
        if !charset.contains(ch) {
            bail!("INVALID CHAR '{}' FOR {} ADDRESSES", ch, addr_type.short());
        }
    }
    if matches!(addr_type, AddrType::Legacy | AddrType::NestedSegWit) {
        let version = addr_type.version_byte(network).unwrap_or(0x00);
        if !is_base58_prefix_reachable(s, version) {
            bail!("PREFIX '{}' IS UNREACHABLE FOR {} ADDRESSES", s, addr_type.short());
        }
    }
    Ok(s.to_string())
}

fn validate_suffix_chars(s: &str, addr_type: AddrType) -> Result<String> {
    if s.is_empty() { bail!("SUFFIX CANNOT BE EMPTY"); }
    for ch in s.chars() {
        if !addr_type.charset().contains(ch) {
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

fn num_cpus() -> usize {
    thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

pub fn fmt_dur(s: f64) -> String {
    if s.is_infinite() || s.is_nan() { return "...".into(); }
    if s < 60.0        { format!("{:.1}S", s) }
    else if s < 3600.0 { format!("{:.1}M", s / 60.0) }
    else               { format!("{:.1}H", s / 3600.0) }
}

pub fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { out.push(','); }
        out.push(ch);
    }
    out.chars().rev().collect()
}

pub fn fmt_rate(r: f64) -> String {
    if r >= 1_000_000.0 { format!("{:.2}M/SEC", r / 1_000_000.0) }
    else if r >= 1_000.0 { format!("{:.0}K/SEC", r / 1_000.0) }
    else                  { format!("{:.0}/SEC", r) }
}

pub fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max { return s; }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) { end -= 1; }
    &s[..end]
}

// ── Terminal setup/teardown ───────────────────────────────────────────────────

fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    let mut stdout = io::stdout();
    terminal::enable_raw_mode()?;
    execute!(stdout, terminal::EnterAlternateScreen, cursor::Hide, terminal::SetTitle("ADDRFORGE"))?;
    let backend = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;
    term.clear()?;
    Ok(term)
}

fn restore_terminal(term: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    terminal::disable_raw_mode()?;
    execute!(term.backend_mut(), terminal::LeaveAlternateScreen, cursor::Show)?;
    term.show_cursor()?;
    Ok(())
}

// ── CLI (no-TUI) mode ─────────────────────────────────────────────────────────

fn run_cli(cli: &Cli) -> Result<()> {
    let addr_type: AddrType = cli.addr_type.parse().map_err(|e: String| anyhow::anyhow!("{}", e))?;
    let network = parse_network(&cli.network)?;
    let threads = cli.threads.unwrap_or_else(num_cpus);
    let pattern = cli.pattern.clone().ok_or_else(|| anyhow::anyhow!("--pattern is required in --no-tui mode"))?;
    let is_bech32 = matches!(addr_type, AddrType::Taproot | AddrType::NativeSegWit);
    let match_pat = if is_bech32 { pattern.to_lowercase() } else { pattern.clone() };

    type Matcher = Arc<dyn Fn(&str) -> bool + Send + Sync>;
    let matcher: Matcher = match cli.mode.as_str() {
        "prefix" => { validate_prefix(&match_pat, addr_type, network)?; let p = match_pat.clone(); Arc::new(move |a: &str| a.starts_with(&p)) }
        "suffix" => { validate_suffix_chars(&match_pat, addr_type)?;    let p = match_pat.clone(); Arc::new(move |a: &str| a.ends_with(&p)) }
        "regex"  => { let re = build_regex(&pattern)?; Arc::new(move |a: &str| re.is_match(a)) }
        _        => bail!("Unknown mode: {}. Use prefix, suffix, or regex.", cli.mode),
    };

    let attempts    = Arc::new(AtomicU64::new(0));
    let found_count = Arc::new(AtomicU64::new(0));
    let done        = Arc::new(AtomicBool::new(false));
    let (tx, rx)    = make_channel(64);
    let start       = Instant::now();

    eprintln!("Searching for {} {} {} address matching {}...",
        network_label(network), addr_type.short(), cli.mode, pattern);
    spawn_workers(threads, addr_type, network, None, matcher, cli.count,
        Arc::clone(&attempts), Arc::clone(&found_count), Arc::clone(&done), tx);

    let mut found = 0;
    for m in rx {
        found += 1;
        println!("--- match {} ---\naddress  : {}\npubkey   : {}", found, m.address, m.pubkey);
        if m.pubkey != m.compressed_pubkey { println!("compressed: {}", m.compressed_pubkey); }
        println!("wif      : {}\nmnemonic : {}", m.wif, m.mnemonic);
    }

    let elapsed = start.elapsed().as_secs_f64();
    let total   = attempts.load(Ordering::Relaxed);
    eprintln!("Done. {} match(es) in {:.1}s — {} attempts — {}",
        found, elapsed, fmt_num(total), fmt_rate(total as f64 / elapsed));
    Ok(())
}

fn run_bench(cli: &Cli) -> Result<()> {
    let addr_type: AddrType = cli.addr_type.parse().map_err(|e: String| anyhow::anyhow!("{}", e))?;
    let network  = parse_network(&cli.network)?;
    let threads  = cli.threads.unwrap_or_else(num_cpus);
    const BATCH: u64 = 4096;

    eprintln!("Benchmarking {} {} generation on {} threads for 5s...",
        network_label(network), addr_type.short(), threads);

    let attempts = Arc::new(AtomicU64::new(0));
    let done     = Arc::new(AtomicBool::new(false));
    for _ in 0..threads {
        let (a, d) = (Arc::clone(&attempts), Arc::clone(&done));
        thread::spawn(move || {
            let mut rng   = thread_rng();
            let mut local = 0u64;
            while !d.load(Ordering::Relaxed) {
                let _ = generate_address(&bitcoin::secp256k1::SecretKey::new(&mut rng), addr_type, network);
                local += 1;
                if local % BATCH == 0 { a.fetch_add(BATCH, Ordering::Relaxed); }
            }
            a.fetch_add(local % BATCH, Ordering::Relaxed);
        });
    }
    let start = Instant::now();
    thread::sleep(Duration::from_secs(5));
    done.store(true, Ordering::Relaxed);
    let rate = attempts.load(Ordering::Relaxed) as f64 / start.elapsed().as_secs_f64();
    println!("Result : {}\nThreads: {}\nType   : {}\nNetwork: {}\n",
        fmt_rate(rate), threads, addr_type.short(), network_label(network));
    let pfx = addr_type.default_prefix(network);
    for extra in 1..=8u32 {
        let diff = addr_type.charset_size().powi(extra as i32);
        println!("  {}+{} : avg {}", pfx, extra, fmt_dur(diff / rate));
    }
    Ok(())
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.bench   { return run_bench(&cli); }
    if cli.no_tui  { return run_cli(&cli); }

    // Load persisted settings
    let cfg = config::load();

    // Install panic hook to restore terminal on crash
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(io::stdout(), terminal::LeaveAlternateScreen, cursor::Show);
        original_hook(info);
    }));

    let mut term = setup_terminal()?;

    let mut app = App::new();
    app.output_dir = cli.output_dir.clone();
    if let Ok(n) = parse_network(&cli.network) { app.network = n; }
    app.apply_config(&cfg);

    loop {
        term.draw(|f| ui::draw(f, &app))?;

        if event::poll(Duration::from_millis(TICK_MS))? {
            match event::read()? {
                // ratatui auto-resizes on the next draw(); no manual Clear needed
                Event::Resize(_, _) => {}
                Event::Key(k) => {
                    if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
                        break;
                    }

                    if k.code == KeyCode::F(2)
                        && matches!(app.screen, Screen::Setup | Screen::Results |
                                    Screen::TypePicker | Screen::ModePicker | Screen::MuSig2Setup)
                    {
                        app.prev_screen = app.screen;
                        app.screen = Screen::Inspector;
                        continue;
                    }

                    if k.code == KeyCode::Esc {
                        match app.screen {
                            Screen::ModePicker   => break,
                            Screen::TypePicker   => { app.screen = Screen::ModePicker; }
                            Screen::MuSig2Setup  => { app.screen = Screen::ModePicker; app.error = None; }
                            Screen::MuSig2Result => {
                                app.screen = Screen::MuSig2Setup;
                                app.musig2_agg_key = None;
                                app.musig2_address = None;
                                app.saved = None;
                            }
                            Screen::Setup   => { app.screen = Screen::TypePicker; app.input_warn = None; }
                            Screen::Running => {
                                app.done.store(true, Ordering::Relaxed);
                                let session    = std::mem::replace(&mut app.session, Session::new());
                                let output_dir = app.output_dir.clone();
                                let network    = app.network;
                                app = App::new_with_config(output_dir, session, network);
                            }
                            Screen::Results => {
                                app.screen = Screen::Setup;
                                app.error  = None;
                                app.saved  = None;
                            }
                            Screen::Inspector => { app.screen = app.prev_screen; }
                        }
                        continue;
                    }

                    match app.screen {
                        Screen::ModePicker   => on_mode_picker_key(&mut app, k.code),
                        Screen::TypePicker   => on_picker_key(&mut app, k.code),
                        Screen::MuSig2Setup  => on_musig2_setup_key(&mut app, k.code),
                        Screen::MuSig2Result => on_musig2_result_key(&mut app, k.code),
                        Screen::Setup        => on_setup_key(&mut app, k.code),
                        Screen::Running      => {}
                        Screen::Results      => on_results_key(&mut app, k.code),
                        Screen::Inspector    => on_inspector_key(&mut app, k.code),
                    }
                }
                _ => {}
            }
        }

        app.tick();
    }

    app.done.store(true, Ordering::Relaxed);

    // Persist settings on clean exit
    let _ = config::save(&app.to_config());

    restore_terminal(&mut term)?;
    Ok(())
}

// ── Key handlers ─────────────────────────────────────────────────────────────

fn on_mode_picker_key(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Up   | KeyCode::Char('k') => { app.mode_sel = app.mode_sel.saturating_sub(1); }
        KeyCode::Down | KeyCode::Char('j') => { app.mode_sel = (app.mode_sel + 1).min(1); }
        KeyCode::Enter => {
            if app.mode_sel == 0 { app.screen = Screen::TypePicker; }
            else                  { app.screen = Screen::MuSig2Setup; app.error = None; }
        }
        _ => {}
    }
}

fn on_picker_key(app: &mut App, key: KeyCode) {
    let n = AddrType::all().len();
    match key {
        KeyCode::Up   | KeyCode::Char('k') => { app.picker_sel = app.picker_sel.saturating_sub(1); }
        KeyCode::Down | KeyCode::Char('j') => { app.picker_sel = (app.picker_sel + 1).min(n - 1); }
        KeyCode::Enter => { let t = AddrType::all()[app.picker_sel]; app.select_addr_type(t); }
        _ => {}
    }
}

fn on_musig2_setup_key(app: &mut App, key: KeyCode) {
    app.error = None;
    match key {
        KeyCode::Enter => {
            if !app.musig2_input.is_empty() {
                match parse_pubkey_hex(&app.musig2_input) {
                    Ok(_) => { app.musig2_keys.push(app.musig2_input.clone()); app.musig2_input.clear(); }
                    Err(e) => { app.error = Some(e.to_string()); }
                }
            } else if app.musig2_keys.len() >= 2 {
                if let Err(e) = app.derive_musig2() { app.error = Some(e.to_string()); }
            } else {
                app.error = Some("ADD AT LEAST 2 KEYS".into());
            }
        }
        KeyCode::Backspace => {
            if app.musig2_input.is_empty() { app.musig2_keys.pop(); }
            else { app.musig2_input.pop(); }
        }
        KeyCode::Char(c) => {
            if c.is_ascii_hexdigit() && app.musig2_input.len() < 66 {
                app.musig2_input.push(c.to_ascii_lowercase());
            }
        }
        _ => {}
    }
}

fn on_musig2_result_key(app: &mut App, key: KeyCode) {
    if let KeyCode::Char('s') | KeyCode::Char('S') = key { app.save_musig2_result(); }
}

fn setup_fields(mode: &Mode, addr_type: AddrType) -> Vec<Field> {
    let mut f = vec![Field::Network, Field::Mode, Field::Pattern, Field::Threads, Field::Count];
    if addr_type.supports_merkle() && matches!(mode, Mode::Prefix | Mode::Suffix) { f.push(Field::Merkle); }
    f
}

fn on_setup_key(app: &mut App, key: KeyCode) {
    app.error     = None;
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
                Field::Network => {
                    let all = network_all();
                    let pos = all.iter().position(|n| *n == app.network).unwrap_or(0);
                    app.network = all[(pos + 1) % all.len()];
                    if app.mode == Mode::Prefix {
                        app.pattern_input = app.addr_type.default_prefix(app.network).to_string();
                    }
                }
                Field::Mode => {
                    let all = Mode::all();
                    let pos = all.iter().position(|m| *m == app.mode).unwrap_or(0);
                    app.mode = all[(pos + 1) % all.len()];
                    let def = app.addr_type.default_prefix(app.network).to_string();
                    match app.mode {
                        Mode::Prefix => app.pattern_input = def,
                        Mode::Suffix | Mode::Regex => {
                            if app.pattern_input.to_lowercase().starts_with(app.addr_type.default_prefix(app.network)) {
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
            } else {
                // Persist settings after each successful search start
                let _ = config::save(&app.to_config());
            }
        }
        KeyCode::Backspace => {
            match app.field {
                Field::Pattern => {
                    let min = if app.mode == Mode::Prefix { app.addr_type.fixed_prefix_len(app.network) } else { 0 };
                    if app.pattern_input.len() > min { app.pattern_input.pop(); }
                }
                Field::Threads => { app.threads_input.pop(); }
                Field::Count   => { app.count_input.pop(); }
                Field::Merkle  => { app.merkle_input.pop(); }
                Field::Network | Field::Mode => {}
            }
        }
        KeyCode::Char(c) => {
            match app.field {
                Field::Network | Field::Mode => {}
                Field::Pattern => {
                    let charset   = app.addr_type.charset();
                    let fixed     = app.addr_type.fixed_prefix_len(app.network);
                    let is_base58 = matches!(app.addr_type, AddrType::Legacy | AddrType::NestedSegWit);
                    let normalise = |ch: char| if is_base58 { ch } else { ch.to_ascii_lowercase() };
                    let allowed   = |ch: char| if is_base58 { charset.contains(ch) } else { charset.contains(ch.to_ascii_lowercase()) };

                    match app.mode {
                        Mode::Prefix => {
                            if app.pattern_input.len() < fixed {
                                app.pattern_input.push(normalise(c));
                            } else if app.pattern_input.len() >= fixed + 12 {
                                app.input_warn = Some("MAX LENGTH REACHED".into());
                            } else if !allowed(c) {
                                app.input_warn = Some(format!("'{}' NOT IN {} CHARSET", c, app.addr_type.short()));
                            } else {
                                app.pattern_input.push(normalise(c));
                                if is_base58 {
                                    let version = app.addr_type.version_byte(app.network).unwrap_or(0x00);
                                    if !is_base58_prefix_reachable(&app.pattern_input, version) {
                                        app.pattern_input.pop();
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
                            } else if !allowed(c) {
                                app.input_warn = Some(format!("'{}' NOT IN {} CHARSET", c, app.addr_type.short()));
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
            let network    = app.network;
            *app = App::new_with_config(output_dir, session, network);
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
                Ok(r)  => { app.inspector_result = Some(r); app.error = None; }
                Err(e) => { app.error = Some(e.to_string()); app.inspector_result = None; }
            }
        }
        KeyCode::Char(c) => {
            if c.is_ascii_alphanumeric() && app.inspector_input.len() < 100 {
                app.inspector_input.push(c);
                app.inspector_result = None;
            }
        }
        _ => {}
    }
}
