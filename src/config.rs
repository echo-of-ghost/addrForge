use std::path::PathBuf;

/// Persisted settings stored in `~/.config/addrforge/config.toml`.
/// Hand-rolled key = value parser (no external toml dep needed).
#[derive(Default, Debug)]
pub struct Config {
    pub addr_type:  Option<String>,  // "taproot" | "native" | "nested" | "legacy"
    pub network:    Option<String>,  // "mainnet" | "testnet" | "signet" | "regtest"
    pub mode:       Option<String>,  // "prefix" | "suffix" | "regex"
    pub threads:    Option<usize>,
    pub output_dir: Option<String>,
}

fn config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("addrforge").join("config.toml"))
}

pub fn load() -> Config {
    let Some(path) = config_path() else { return Config::default() };
    let Ok(text) = std::fs::read_to_string(&path) else { return Config::default() };
    parse(&text)
}

pub fn save(config: &Config) -> std::io::Result<()> {
    let Some(path) = config_path() else { return Ok(()) };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serialise(config))
}

// ── Minimal key = value serialiser / parser ───────────────────────────────────

fn serialise(c: &Config) -> String {
    let mut out = String::from("# addrforge settings\n");
    if let Some(v) = &c.addr_type  { out.push_str(&format!("addr_type = {}\n", v)); }
    if let Some(v) = &c.network    { out.push_str(&format!("network = {}\n", v)); }
    if let Some(v) = &c.mode       { out.push_str(&format!("mode = {}\n", v)); }
    if let Some(v) =  c.threads    { out.push_str(&format!("threads = {}\n", v)); }
    if let Some(v) = &c.output_dir { out.push_str(&format!("output_dir = {}\n", v)); }
    out
}

fn parse(text: &str) -> Config {
    let mut cfg = Config::default();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() { continue; }
        let Some((k, v)) = line.split_once('=') else { continue };
        let k = k.trim();
        let v = v.trim().to_string();
        match k {
            "addr_type"  => cfg.addr_type  = Some(v),
            "network"    => cfg.network    = Some(v),
            "mode"       => cfg.mode       = Some(v),
            "threads"    => cfg.threads    = v.parse().ok(),
            "output_dir" => cfg.output_dir = Some(v),
            _ => {}
        }
    }
    cfg
}
