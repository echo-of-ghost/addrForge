use std::sync::atomic::Ordering;

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::{
    address::InspectorResult,
    difficulty::{base58_prefix_is_rare, difficulty_for_prefix, difficulty_for_suffix},
    fmt_dur, fmt_num, fmt_rate, truncate,
    types::{AddrMode, AddrType, Mode, network_all, network_label},
    App, Field, Screen,
};

// ── Palette ───────────────────────────────────────────────────────────────────

const GREEN:  Color = Color::Rgb(85,  158, 101); // --grn   #559e65
const DIM:    Color = Color::Rgb(58,  138, 74);  // --grn2  #3a8a4a
const BRIGHT: Color = Color::Rgb(232, 232, 232); // --t1    #e8e8e8
const BLACK:  Color = Color::Rgb(14,  14,  14);  // --ink   #0e0e0e
const WARN:   Color = Color::Rgb(240, 112, 32);  // --orange #f07020

const SEP: &str     = "------------------------------------------------------------";
const VERSION: &str = concat!("V", env!("CARGO_PKG_VERSION"));

// ── Style helpers ─────────────────────────────────────────────────────────────

fn sg() -> Style { Style::default().fg(GREEN) }
fn sd() -> Style { Style::default().fg(DIM) }
fn sb() -> Style { Style::default().fg(BRIGHT) }
fn sw() -> Style { Style::default().fg(WARN) }
fn si() -> Style { Style::default().fg(BLACK).bg(GREEN) } // inverse video
fn base() -> Style { Style::default().bg(BLACK) }

// ── Span / Line helpers ───────────────────────────────────────────────────────

fn s(text: impl Into<String>, style: Style) -> Span<'static> {
    Span::styled(text.into(), style)
}

fn sep_line() -> Line<'static> {
    Line::from(s(SEP, sd()))
}

fn blank() -> Line<'static> {
    Line::from("")
}

/// Build the hint bar at the bottom of each screen.
fn hints(pairs: &[(&str, &str)]) -> Line<'static> {
    let mut spans = Vec::new();
    for (i, (key, action)) in pairs.iter().enumerate() {
        if i > 0 { spans.push(s("   ", sd())); }
        spans.push(s(*key, sg()));
        if !action.is_empty() {
            spans.push(s(format!(" {}", action), sd()));
        }
    }
    Line::from(spans)
}

/// Focus indicator: `] ` (green) if focused, `  ` otherwise.
fn focus_prefix(focused: bool) -> Span<'static> {
    if focused { s("] ", sg()) } else { s("  ", sd()) }
}

/// Cursor block appended to focused input fields.
fn cursor() -> Span<'static> {
    s(" ", si())
}

// ── Layout helpers ────────────────────────────────────────────────────────────

/// Split an area into [content, sep, hints] vertically.
fn body_layout(area: Rect) -> [Rect; 3] {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1), Constraint::Length(1)])
        .split(area);
    [chunks[0], chunks[1], chunks[2]]
}

fn render_bg(f: &mut Frame, area: Rect) {
    f.render_widget(Block::default().style(base()), area);
}

fn render_paragraph(f: &mut Frame, lines: Vec<Line<'static>>, area: Rect) {
    f.render_widget(Paragraph::new(lines).style(base()), area);
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.size();

    // Black background across the whole frame
    render_bg(f, area);

    // Minimum terminal size: show a graceful overlay instead of broken rendering
    if area.width < 72 || area.height < 24 {
        let msg = vec![
            blank(),
            blank(),
            Line::from(s("  TERMINAL TOO SMALL", sd())),
            Line::from(s(format!("  NEED 72x24  GOT {}x{}", area.width, area.height), sd())),
            blank(),
            Line::from(s("  PLEASE RESIZE TO CONTINUE", sw())),
        ];
        f.render_widget(Paragraph::new(msg).style(base()), area);
        return;
    }

    draw_header(f, area, app);

    // Body: everything below the 1-line header, leaving room for top blank line
    let body = Rect {
        x: 0, y: 2,
        width: area.width,
        height: area.height.saturating_sub(2),
    };

    match app.screen {
        Screen::ModePicker   => draw_mode_picker(f, body, app),
        Screen::TypePicker   => draw_type_picker(f, body, app),
        Screen::MuSig2Setup  => draw_musig2_setup(f, body, app),
        Screen::MuSig2Result => draw_musig2_result(f, body, app),
        Screen::Setup        => draw_setup(f, body, app),
        Screen::Running      => draw_running(f, body, app),
        Screen::Results      => draw_results(f, body, app),
        Screen::Inspector    => draw_inspector(f, body, app),
    }
}

// ── Header (row 0) ─────────────────────────────────────────────────────────

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let has_nav = matches!(
        app.screen,
        Screen::ModePicker | Screen::TypePicker | Screen::Setup |
        Screen::MuSig2Setup | Screen::Results
    );
    let prefix = format!("-- ADDRFORGE {} ", VERSION);
    let nav    = if has_nav { "F2 INSPECT" } else { "" };
    let dashes = area.width
        .saturating_sub(prefix.len() as u16 + nav.len() as u16 + if has_nav { 1 } else { 0 })
        as usize;

    let mut spans = vec![s(prefix, sd()), s("-".repeat(dashes), sd())];
    if has_nav {
        spans.push(s("F2", sg()));
        spans.push(s(" INSPECT", sd()));
    }

    f.render_widget(
        Paragraph::new(Line::from(spans)).style(base()),
        Rect { x: 0, y: 0, width: area.width, height: 1 },
    );
}

// ── Mode picker ─────────────────────────────────────────────────────────────

fn draw_mode_picker(f: &mut Frame, body: Rect, app: &App) {
    let [content, sep_area, hint_area] = body_layout(body);

    let modes = [AddrMode::SingleSig, AddrMode::MuSig2];
    let sel   = modes[app.mode_sel];

    let mut lines: Vec<Line> = vec![
        Line::from(s("  ADDRESS MODE", sb())),
        blank(),
    ];

    for (i, mode) in modes.iter().enumerate() {
        if i == app.mode_sel {
            lines.push(Line::from(vec![s("  ", sg()), s(format!(" {} ", mode.label()), si())]));
        } else {
            lines.push(Line::from(s(format!("    {} ", mode.label()), sd())));
        }
    }

    lines.extend([blank(), sep_line(), blank()]);
    lines.push(Line::from(s(format!("  {}", match sel { AddrMode::SingleSig => "SINGLESIG", AddrMode::MuSig2 => "MUSIG2" }), sw())));
    lines.push(blank());

    for desc_line in sel.description().split('\n') {
        lines.push(Line::from(s(format!("  {}", desc_line), sd())));
    }

    render_paragraph(f, lines, content);
    render_paragraph(f, vec![sep_line()], sep_area);
    render_paragraph(f, vec![hints(&[("↑↓", "SELECT"), ("RETURN", "CONFIRM"), ("ESC", "QUIT")])], hint_area);
}

// ── Type picker ─────────────────────────────────────────────────────────────

fn draw_type_picker(f: &mut Frame, body: Rect, app: &App) {
    let [content, sep_area, hint_area] = body_layout(body);

    let mut lines: Vec<Line> = vec![
        Line::from(s("  ADDRESS TYPE", sb())),
        blank(),
    ];

    for (i, t) in AddrType::all().iter().enumerate() {
        if i == app.picker_sel {
            lines.push(Line::from(vec![s("  ", sg()), s(format!(" {} ", t.label()), si())]));
        } else {
            lines.push(Line::from(s(format!("    {} ", t.label()), sd())));
        }
    }

    let sel = AddrType::all()[app.picker_sel];
    lines.extend([blank(), sep_line(), blank()]);
    lines.push(Line::from(s(format!("  {}", sel.short()), sw())));
    lines.push(blank());
    for dl in sel.description().split('\n') {
        lines.push(Line::from(s(format!("  {}", dl), sd())));
    }
    lines.push(blank());
    lines.push(Line::from(vec![
        s("  CHARSET ", sd()),
        s(format!("{:.0} chars", sel.charset_size()), sg()),
        s("  /  KEY SPACE ", sd()),
        s(match sel { AddrType::Taproot => "256 bits".to_string(), _ => "160 bits".to_string() }, sg()),
        s("  /  BITS/CHAR ", sd()),
        s(format!("{:.2}", sel.charset_size().log2()), sg()),
    ]));

    render_paragraph(f, lines, content);
    render_paragraph(f, vec![sep_line()], sep_area);
    render_paragraph(f, vec![hints(&[("↑↓", "SELECT"), ("RETURN", "CONFIRM"), ("ESC", "BACK")])], hint_area);
}

// ── MuSig2 setup ─────────────────────────────────────────────────────────────

fn draw_musig2_setup(f: &mut Frame, body: Rect, app: &App) {
    let [content, sep_area, hint_area] = body_layout(body);

    let mut lines: Vec<Line> = vec![
        Line::from(vec![s("  MUSIG2", sw()), s("  /  N-OF-N TAPROOT KEY AGGREGATION (BIP-327)", sd())]),
        Line::from(s("  ENTER COMPRESSED PUBKEYS (66 HEX CHARS). ENTER TO ADD.", sd())),
        blank(),
    ];

    for (i, k) in app.musig2_keys.iter().enumerate() {
        lines.push(Line::from(vec![
            s(format!("  KEY {:>2} : ", i + 1), sd()),
            s(truncate(k, 66).to_string(), sg()),
        ]));
    }

    // Current input line
    lines.push(Line::from(vec![
        s("] ", sg()),
        s(format!("KEY {:>2} : ", app.musig2_keys.len() + 1), sd()),
        s(truncate(&app.musig2_input, 60).to_string(), sg()),
        cursor(),
    ]));
    lines.push(blank());

    if let Some(err) = &app.error {
        lines.push(Line::from(s(format!("  ? {}", err), sw())));
    } else {
        let input_len = app.musig2_input.len();
        let status = match app.musig2_keys.len() {
            0 | 1 => Line::from(s(format!("  {}/66 CHARS -- ADD AT LEAST 2 KEYS", input_len), sd())),
            _ if input_len > 0 => Line::from(s(format!("  {}/66 CHARS -- ENTER TO ADD", input_len), sd())),
            _ => Line::from(s(format!("  {} KEYS READY -- RETURN TO DERIVE ADDRESS", app.musig2_keys.len()), sg())),
        };
        lines.push(status);
    }

    render_paragraph(f, lines, content);
    render_paragraph(f, vec![sep_line()], sep_area);
    render_paragraph(f, vec![hints(&[("RETURN", "ADD / DERIVE"), ("BACKSPACE", "REMOVE LAST"), ("ESC", "BACK")])], hint_area);
}

// ── MuSig2 result ─────────────────────────────────────────────────────────────

fn draw_musig2_result(f: &mut Frame, body: Rect, app: &App) {
    let [content, sep_area, hint_area] = body_layout(body);

    let mut lines: Vec<Line> = vec![
        Line::from(vec![
            s("  MUSIG2", sw()),
            s(format!("  /  AGGREGATE ADDRESS DERIVED ({} KEYS)", app.musig2_keys.len()), sd()),
        ]),
        Line::from(s("  ALL PARTIES MUST CO-SIGN. INDISTINGUISHABLE FROM SINGLESIG ON-CHAIN.", sd())),
        Line::from(sep_line()),
        blank(),
        Line::from(s("  TAPROOT ADDRESS", sb())),
        Line::from(s(format!("   {}", app.musig2_address.as_deref().unwrap_or("")), sg())),
        blank(),
        Line::from(s("  AGGREGATE OUTPUT KEY (X-ONLY)", sb())),
        Line::from(s(format!("   {}", app.musig2_agg_key.as_deref().unwrap_or("")), sg())),
        blank(),
    ];

    for (i, k) in app.musig2_keys.iter().enumerate().take(8) {
        lines.push(Line::from(vec![
            s(format!("  PUBKEY {:>2} : ", i + 1), sd()),
            s(truncate(k, 58).to_string(), sg()),
        ]));
    }
    if app.musig2_keys.len() > 8 {
        lines.push(Line::from(s(format!("  ... AND {} MORE KEYS", app.musig2_keys.len() - 8), sd())));
    }
    lines.push(blank());

    if let Some(path) = &app.saved {
        lines.push(Line::from(vec![
            s(format!("  SAVED: {}  ", truncate(path, 50)), sg()),
            s("KEEP SECURE", sw()),
        ]));
    } else if let Some(err) = &app.error {
        lines.push(Line::from(s(format!("  ! {}", err), sw())));
    }

    render_paragraph(f, lines, content);
    render_paragraph(f, vec![sep_line()], sep_area);
    render_paragraph(f, vec![hints(&[("S", "SAVE"), ("ESC", "NEW DERIVATION")])], hint_area);
}

// ── Setup ─────────────────────────────────────────────────────────────────────

fn draw_setup(f: &mut Frame, body: Rect, app: &App) {
    let [content, sep_area, hint_area] = body_layout(body);

    let focused = |f: Field| app.field == f;

    let mut lines: Vec<Line> = vec![
        Line::from(vec![s(format!("  {}", app.addr_type.short()), sw()), s("  /  ESC CHANGE TYPE", sd())]),
        blank(),
    ];

    // Network row
    {
        let mut spans = vec![focus_prefix(focused(Field::Network)), s("NETWORK : ", sd())];
        for n in network_all() {
            if *n == app.network {
                spans.push(s(format!(" {} ", network_label(*n)), si()));
            } else {
                spans.push(s(format!(" {} ", network_label(*n)), sd()));
            }
        }
        lines.push(Line::from(spans));
    }

    // Mode row
    {
        let mut spans = vec![focus_prefix(focused(Field::Mode)), s("MODE    : ", sd())];
        for m in Mode::all() {
            if *m == app.mode {
                spans.push(s(format!(" {} ", m.label()), si()));
            } else {
                spans.push(s(format!(" {} ", m.label()), sd()));
            }
        }
        lines.push(Line::from(spans));
    }

    lines.push(blank());

    // Pattern row
    {
        let label = match app.mode { Mode::Prefix => "PREFIX  : ", Mode::Suffix => "SUFFIX  : ", Mode::Regex => "REGEX   : " };
        let mut spans = vec![focus_prefix(focused(Field::Pattern)), s(label, sd()), s(app.pattern_input.clone(), sg())];
        if focused(Field::Pattern) { spans.push(cursor()); }
        lines.push(Line::from(spans));
    }

    lines.push(blank());

    // Threads row
    {
        let mut spans = vec![focus_prefix(focused(Field::Threads)), s("THREADS : ", sd()), s(app.threads_input.clone(), sg())];
        if focused(Field::Threads) { spans.push(cursor()); }
        spans.push(s("  1-256", sd()));
        lines.push(Line::from(spans));
    }

    // Count row
    {
        let mut spans = vec![focus_prefix(focused(Field::Count)), s("FIND    : ", sd()), s(app.count_input.clone(), sg())];
        if focused(Field::Count) { spans.push(cursor()); }
        spans.push(s("  1-1000", sd()));
        lines.push(Line::from(spans));
    }

    // Merkle row (Taproot only, prefix/suffix only)
    if app.addr_type.supports_merkle() && matches!(app.mode, Mode::Prefix | Mode::Suffix) {
        let val = if app.merkle_input.is_empty() {
            s("(NONE)", sd())
        } else {
            s(truncate(&app.merkle_input, 48).to_string(), sg())
        };
        let mut spans = vec![focus_prefix(focused(Field::Merkle)), s("MERKLE  : ", sd()), val];
        if focused(Field::Merkle) { spans.push(cursor()); }
        lines.push(Line::from(spans));
    }

    lines.push(blank());

    // Difficulty estimate
    match &app.mode {
        Mode::Prefix => {
            let diff = difficulty_for_prefix(&app.pattern_input, app.addr_type, app.network);
            let mut diff_spans = vec![
                s("  DIFFICULTY  : ", sd()),
                s(format!("~{} ATTEMPTS", fmt_num(diff as u64)), sg()),
            ];
            if matches!(app.addr_type, AddrType::Legacy | AddrType::NestedSegWit) {
                diff_spans.push(s("  (CASE-SENSITIVE)", sd()));
            }
            lines.push(Line::from(diff_spans));

            if matches!(app.addr_type, AddrType::Legacy) && app.pattern_input.len() > 1 {
                let version = app.addr_type.version_byte(app.network).unwrap_or(0x00);
                if base58_prefix_is_rare(&app.pattern_input, version) {
                    lines.push(Line::from(s("  ! ONLY ~4% OF LEGACY ADDRESSES CAN MATCH — EXPECT SLOWER RESULTS", sw())));
                }
            }
        }
        Mode::Suffix => {
            let diff = difficulty_for_suffix(app.pattern_input.len(), app.addr_type);
            lines.push(Line::from(vec![
                s("  DIFFICULTY  : ", sd()),
                s(format!("~{} ATTEMPTS", fmt_num(diff as u64)), sg()),
            ]));
        }
        Mode::Regex => {
            lines.push(Line::from(s("  DIFFICULTY  : VARIES (REGEX)", sd())));
        }
    }

    lines.push(blank());

    // Validation error or transient warn
    if let Some(err) = &app.error {
        lines.push(Line::from(s(format!("  ? {}", err), sw())));
    } else if let Some(w) = &app.input_warn {
        lines.push(Line::from(s(format!("  {}", w), sw())));
    }

    render_paragraph(f, lines, content);
    render_paragraph(f, vec![sep_line()], sep_area);
    render_paragraph(f, vec![hints(&[("RETURN", "START"), ("TAB", "NEXT"), ("SPACE", "CYCLE"), ("ESC", "CHANGE TYPE")])], hint_area);
}

// ── Running ───────────────────────────────────────────────────────────────────

fn draw_running(f: &mut Frame, body: Rect, app: &App) {
    let [content, sep_area, hint_area] = body_layout(body);

    let attempts = app.attempts.load(Ordering::Relaxed);
    let found    = app.found_count.load(Ordering::Relaxed);
    let dots     = match (app.elapsed() * 3.0) as u64 % 4 { 0 => ".", 1 => "..", 2 => "...", _ => "" };

    let mut lines: Vec<Line> = vec![
        // Title line
        Line::from(vec![
            s(format!("  {} / {} / ", app.run_addr_type.short(), network_label(app.run_network)), sd()),
            s(app.run_mode.label().to_string(), sd()),
            s(" / ", sd()),
            s(app.run_pattern.clone(), sw()),
        ]),
        blank(),
        // Stats
        Line::from(vec![
            s("  ATTEMPTS ", sd()),
            s(fmt_num(attempts), sb()),
            s("   RATE ", sd()),
            s(fmt_rate(app.rate()), sb()),
            s("   ELAPSED ", sd()),
            s(fmt_dur(app.elapsed()), sb()),
        ]),
        blank(),
        sep_line(),
        blank(),
        // Search status
        if found == 0 {
            Line::from(s(format!("  SEARCHING{}", dots), sw()))
        } else {
            Line::from(s(format!("  {} OF {} FOUND", found, app.run_count), sw()))
        },
        blank(),
    ];

    // Up to 3 most-recently-found addresses
    let results = app.results.lock().unwrap_or_else(|e| e.into_inner());
    for m in results.iter().rev().take(3) {
        lines.push(Line::from(vec![
            s("  + ", sd()),
            s(truncate(&m.address, 60).to_string(), sg()),
        ]));
    }

    render_paragraph(f, lines, content);
    render_paragraph(f, vec![sep_line()], sep_area);
    render_paragraph(f, vec![hints(&[("ESC", "ABORT")])], hint_area);
}

// ── Results ───────────────────────────────────────────────────────────────────

pub fn draw_results(f: &mut Frame, body: Rect, app: &App) {
    let results = app.results.lock().unwrap_or_else(|e| e.into_inner());
    let n       = results.len();

    // Layout: when multiple results, split body into [list | detail | sep | hints]
    // When single result: [detail | sep | hints]
    let list_height: u16 = if n > 1 { (n as u16 + 2).min(8) } else { 0 };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),            // stats + sep
            Constraint::Length(list_height),   // scrollable list (0 if single)
            Constraint::Min(8),                // detail panel
            Constraint::Length(1),             // save status / error
            Constraint::Length(1),             // sep
            Constraint::Length(1),             // hints
        ])
        .split(body);

    // Stats
    let stats_line = Line::from(vec![
        s(format!("  {} / {} / {} / ",
            app.run_addr_type.short(),
            fmt_dur(app.elapsed()),
            fmt_num(app.attempts.load(Ordering::Relaxed))), sd()),
        s(if n == 1 { "1 MATCH".to_string() } else { format!("{} MATCHES", n) }, sg()),
    ]);
    render_paragraph(f, vec![stats_line, sep_line()], chunks[0]);

    // Scrollable address list (only when multiple results)
    if n > 1 {
        let items: Vec<ListItem> = results.iter().enumerate().map(|(i, m)| {
            let addr = truncate(&m.address, (chunks[1].width as usize).saturating_sub(7));
            ListItem::new(Line::from(vec![
                s(format!(" {:>3}  ", i + 1), sd()),
                s(addr.to_string(), if i == app.selected { sb() } else { sg() }),
            ]))
        }).collect();

        let list = List::new(items)
            .highlight_style(si())
            .highlight_symbol(">");

        let mut state = ListState::default();
        state.select(Some(app.selected));

        f.render_widget(Block::default().style(base()), chunks[1]);
        f.render_stateful_widget(list, chunks[1], &mut state);
    }

    // Detail panel for selected result
    let mut detail: Vec<Line> = vec![blank()];
    if let Some(m) = results.get(app.selected) {
        detail.push(Line::from(s("  ADDRESS", sb())));
        detail.push(Line::from(vec![s("   ", sd()), s(m.address.clone(), sg())]));
        detail.push(blank());

        let pk_label = match app.run_addr_type {
            AddrType::Taproot => "  OUTPUT KEY (TWEAKED X-ONLY PUBKEY)",
            _                 => "  COMPRESSED PUBLIC KEY",
        };
        detail.push(Line::from(s(pk_label, sb())));
        detail.push(Line::from(vec![s("   ", sd()), s(truncate(&m.pubkey, 68).to_string(), sg())]));

        if app.run_addr_type == AddrType::Taproot {
            detail.push(Line::from(s("  COMPRESSED PUBKEY (USE FOR MUSIG2)", sd())));
            detail.push(Line::from(vec![s("   ", sd()), s(truncate(&m.compressed_pubkey, 68).to_string(), sg())]));
        }

        detail.push(blank());
        detail.push(Line::from(vec![s("  WIF (PRIVATE KEY)  ", sb()), s("(KEEP SECRET)", sw())]));
        detail.push(Line::from(vec![s("   ", sd()), s(m.wif.clone(), sg())]));

        detail.push(Line::from(vec![s("  BIP-39 MNEMONIC    ", sb()), s("(KEEP SECRET)", sw())]));
        // Split 24 words across two lines (12+12)
        let words: Vec<&str> = m.mnemonic.split_whitespace().collect();
        if words.len() == 24 {
            detail.push(Line::from(vec![s("   ", sd()), s(words[..12].join(" "), sd())]));
            detail.push(Line::from(vec![s("   ", sd()), s(words[12..].join(" "), sd())]));
        } else {
            detail.push(Line::from(vec![s("   ", sd()), s(truncate(&m.mnemonic, 70).to_string(), sd())]));
        }
    } else if n == 0 {
        detail.push(Line::from(s("  NO RESULTS", sg())));
    }

    render_paragraph(f, detail, chunks[2]);

    // Save status / error line
    let status = if let Some(path) = &app.saved {
        Line::from(vec![
            s(format!("  SAVED: {}  ", truncate(path, 48)), sg()),
            s("KEEP THIS FILE SECURE", sw()),
        ])
    } else if let Some(err) = &app.error {
        Line::from(s(format!("  ! {}", err), sw()))
    } else {
        Line::from(s(format!("  SAVES TO: {}", app.output_dir), sd()))
    };
    render_paragraph(f, vec![status], chunks[3]);

    render_paragraph(f, vec![sep_line()], chunks[4]);

    // Hints
    let mut hint_list: Vec<(&str, &str)> = vec![];
    if n > 1    { hint_list.push(("↑↓ / jk", "SCROLL")); }
    if n > 0    { hint_list.push(("S", "SAVE")); }
    hint_list.push(("I", "INSPECT"));
    hint_list.push(("N", "NEW"));
    hint_list.push(("ESC", "BACK"));
    render_paragraph(f, vec![hints(&hint_list)], chunks[5]);
}

// ── Inspector ─────────────────────────────────────────────────────────────────

fn draw_inspector(f: &mut Frame, body: Rect, app: &App) {
    let [content, sep_area, hint_area] = body_layout(body);

    let mut lines: Vec<Line> = vec![
        sep_line(),
        Line::from(s("  ADDRESS INSPECTOR", sw())),
        blank(),
        Line::from(s("  PASTE ANY BITCOIN ADDRESS:", sd())),
        Line::from(vec![
            s("  > ", sg()),
            s(app.inspector_input.clone(), sg()),
            cursor(),
        ]),
        blank(),
    ];

    if let Some(r) = &app.inspector_result {
        lines.extend(inspector_result_lines(r));
    } else if let Some(err) = &app.error {
        lines.push(Line::from(s(format!("  ? {}", err), sw())));
    }

    render_paragraph(f, lines, content);
    render_paragraph(f, vec![sep_line()], sep_area);
    render_paragraph(f, vec![hints(&[("TYPE", "ADDRESS"), ("RETURN", "INSPECT"), ("ESC", "BACK")])], hint_area);
}

fn inspector_result_lines(r: &InspectorResult) -> Vec<Line<'static>> {
    let mut lines = vec![sep_line()];
    let row = |label: &str, val: &str| -> Line<'static> {
        Line::from(vec![
            s(format!("  {:<15} : ", label), sd()),
            s(val.to_string(), sg()),
        ])
    };
    lines.push(Line::from(vec![s("  TYPE            : ".to_string(), sd()), s(r.addr_type.clone(), sw())]));
    lines.push(row("NETWORK", &r.network));
    lines.push(row("ENCODING", &r.encoding));
    lines.push(row("ADDRESS", truncate(&r.address, 62)));
    lines.push(row("KEY / HASH", truncate(&r.pubkey_hex, 64)));
    lines.push(blank());
    if let Some(st) = &r.spend_type {
        if r.is_nums {
            lines.push(Line::from(s(format!("  SPEND TYPE      : {}", st), sw())));
        } else {
            lines.push(Line::from(vec![
                s("  SPEND TYPE      : ", sd()),
                s(st.clone(), sw()),
            ]));
        }
        lines.push(blank());
    }
    lines.push(row("FINGERPRINT", &r.hash_type));
    lines.push(Line::from(vec![
        s("  KEY SPACE       : ", sd()),
        s(format!("{:.0} BITS", r.entropy_bits), sg()),
    ]));
    lines.push(Line::from(vec![
        s("  PAYLOAD ENCODES : ", sd()),
        s(format!("{:.1} BITS", r.payload_bits), sg()),
    ]));
    lines
}
