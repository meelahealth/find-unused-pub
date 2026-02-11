#![deny(unused)]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{mpsc, OnceLock};
use std::io::IsTerminal;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDate, Utc};
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use grep_regex::RegexMatcherBuilder;
use grep_searcher::sinks::UTF8;
use grep_searcher::Searcher;
use ignore::WalkBuilder;
use owo_colors::OwoColorize;
use ratatui::layout::{Alignment, Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Terminal;
use rusqlite::Connection;

// ---------------------------------------------------------------------------
// Theme — semantic color layer
// ---------------------------------------------------------------------------

/// Palette index: cycles through all available themes.
static PALETTE_IDX: AtomicU8 = AtomicU8::new(3);
static THEMES: OnceLock<Vec<ThemeColors>> = OnceLock::new();
static ACTIVE_FILTER_NAMES: OnceLock<Vec<&'static str>> = OnceLock::new();
static DISABLED_FILTER_NAMES: OnceLock<Vec<String>> = OnceLock::new();
static ENABLED_FILTER_NAMES: OnceLock<Vec<String>> = OnceLock::new();
static IGNORED_PATHS: OnceLock<Vec<String>> = OnceLock::new();

const PALETTE_COUNT: u8 = 5;

#[derive(Debug)]
struct ThemeColors {
    name: &'static str,

    // Surfaces
    surface: Color,
    // Text hierarchy
    on_surface: Color,
    on_surface_variant: Color,
    dim: Color,
    dim_accent: Color,
    // Borders
    outline: Color,
    // Semantic accents
    primary: Color,
    secondary: Color,
    tertiary: Color,
    accent: Color,
    info: Color,
    // Status
    error: Color,
    warning: Color,
    success: Color,
    // Filter label colors (orm, graphql, builder, cynic)
    filter_colors: [Color; 4],
    // Swatch for palette preview
    swatch: Vec<Color>,
}

/// Convert a catppuccin color to ratatui Color.
fn ctp(c: catppuccin::Color) -> Color {
    c.into()
}

fn theme_from_catppuccin(name: &'static str, f: &catppuccin::FlavorColors) -> ThemeColors {
    ThemeColors {
        name,
        surface: ctp(f.base),
        on_surface: ctp(f.text),
        on_surface_variant: ctp(f.subtext0),
        dim: ctp(f.overlay0),
        dim_accent: ctp(f.overlay1),
        outline: ctp(f.surface2),
        primary: ctp(f.lavender),
        secondary: ctp(f.sapphire),
        tertiary: ctp(f.peach),
        accent: ctp(f.mauve),
        info: ctp(f.sky),
        error: ctp(f.red),
        warning: ctp(f.yellow),
        success: ctp(f.green),
        filter_colors: [ctp(f.teal), ctp(f.mauve), ctp(f.peach), ctp(f.sky)],
        swatch: vec![
            ctp(f.rosewater), ctp(f.flamingo), ctp(f.pink), ctp(f.mauve),
            ctp(f.red), ctp(f.maroon), ctp(f.peach), ctp(f.yellow),
            ctp(f.green), ctp(f.teal), ctp(f.sky), ctp(f.sapphire),
            ctp(f.blue), ctp(f.lavender),
        ],
    }
}

fn eldritch_theme() -> ThemeColors {
    let bg       = Color::Rgb(0x21, 0x23, 0x37); // Sunken Depths Grey
    let cur_line = Color::Rgb(0x32, 0x34, 0x49); // Shallow Depths Grey
    let fg       = Color::Rgb(0xeb, 0xfa, 0xfa); // Lighthouse White
    let comment  = Color::Rgb(0x70, 0x81, 0xd0); // The Old One Purple
    let cyan     = Color::Rgb(0x04, 0xd1, 0xf9); // Watery Tomb Blue
    let green    = Color::Rgb(0x37, 0xf4, 0x99); // Great Old One Green
    let orange   = Color::Rgb(0xf7, 0xc6, 0x7f); // Dreaming Orange
    let pink     = Color::Rgb(0xf2, 0x65, 0xb5); // Pustule Pink
    let purple   = Color::Rgb(0xa4, 0x8c, 0xf2); // Lovecraft Purple
    let red      = Color::Rgb(0xf1, 0x6c, 0x75); // R'lyeh Red
    let yellow   = Color::Rgb(0xf1, 0xfc, 0x79); // Gold of Yuggoth
    // Derived dim variants (blend comment toward bg)
    let dim_acc  = Color::Rgb(0x58, 0x5a, 0x80);

    ThemeColors {
        name: "eldritch",
        surface: bg,
        on_surface: fg,
        on_surface_variant: comment,
        dim: Color::Rgb(0x50, 0x52, 0x70),
        dim_accent: dim_acc,
        outline: cur_line,
        primary: purple,
        secondary: cyan,
        tertiary: orange,
        accent: pink,
        info: cyan,
        error: red,
        warning: yellow,
        success: green,
        filter_colors: [green, purple, orange, cyan],
        swatch: vec![fg, comment, cyan, green, orange, pink, purple, red, yellow, cur_line, dim_acc],
    }
}

fn build_all_themes() -> Vec<ThemeColors> {
    let p = &catppuccin::PALETTE;
    vec![
        theme_from_catppuccin("latte", &p.latte.colors),
        theme_from_catppuccin("frappe", &p.frappe.colors),
        theme_from_catppuccin("macchiato", &p.macchiato.colors),
        theme_from_catppuccin("mocha", &p.mocha.colors),
        eldritch_theme(),
    ]
}

/// Get the active theme (resolved live from PALETTE_IDX).
fn theme() -> &'static ThemeColors {
    let themes = THEMES.get().expect("themes not initialized");
    let idx = PALETTE_IDX.load(Ordering::Relaxed) as usize;
    &themes[idx.min(themes.len() - 1)]
}

/// Build a palette swatch line: colored blocks for each theme color + name.
fn palette_swatch<'a>() -> Line<'a> {
    let t = theme();
    let mut spans: Vec<Span<'a>> = vec![Span::raw(" ")];
    for &c in &t.swatch {
        spans.push(Span::styled("█", Style::default().fg(c)));
    }
    spans.push(Span::styled(
        format!(" {} ", t.name),
        Style::default().fg(t.on_surface_variant),
    ));
    Line::from(spans).alignment(Alignment::Right)
}

/// Cycle to the next palette and return its name.
fn cycle_palette() -> &'static str {
    let next = (PALETTE_IDX.load(Ordering::Relaxed) + 1) % PALETTE_COUNT;
    PALETTE_IDX.store(next, Ordering::Relaxed);
    theme().name
}

/// Get the list of active filter names for TUI display.
fn active_filter_names() -> &'static [&'static str] {
    ACTIVE_FILTER_NAMES.get().map_or(&[], |v| v.as_slice())
}

/// Get the list of disabled filter names for TUI display.
fn disabled_filter_names() -> &'static [String] {
    DISABLED_FILTER_NAMES.get().map_or(&[], |v| v.as_slice())
}

/// Get the list of explicitly enabled opt-in filter names for TUI display.
fn enabled_filter_names() -> &'static [String] {
    ENABLED_FILTER_NAMES.get().map_or(&[], |v| v.as_slice())
}

/// Get the list of ignored paths for TUI display.
fn ignored_paths() -> &'static [String] {
    IGNORED_PATHS.get().map_or(&[], |v| v.as_slice())
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum Palette {
    Latte,
    Frappe,
    Macchiato,
    Mocha,
    Eldritch,
}

impl Palette {
    fn to_index(self) -> u8 {
        match self {
            Palette::Latte => 0,
            Palette::Frappe => 1,
            Palette::Macchiato => 2,
            Palette::Mocha => 3,
            Palette::Eldritch => 4,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "find-unused-pub",
    about = "Find pub items that are unused or only used within their crate",
    version
)]
struct Args {
    /// Color palette (latte, frappe, macchiato, mocha, eldritch)
    #[arg(long, value_enum, default_value = "mocha", env = "FIND_UNUSED_PUB_PALETTE")]
    palette: Palette,
    /// Crate paths to scan (defaults to all crates/*)
    crate_paths: Vec<PathBuf>,

    /// Auto-fix crate-internal items → pub(crate)
    #[arg(long)]
    fix_crate_internal: bool,

    /// Auto-fix unused items → remove pub (lets rustc warn dead_code)
    #[arg(long)]
    fix_unused: bool,

    /// Alias for --fix-crate-internal
    #[arg(long)]
    fix: bool,

    /// Clear the allowlist database
    #[arg(long)]
    nuke_allowlist: bool,

    /// Ignore crate paths (relative to workspace root, repeatable)
    #[arg(long, env = "FIND_UNUSED_PUB_IGNORE", value_delimiter = ',')]
    ignore: Vec<PathBuf>,

    /// Disable a filter plugin by name (repeatable, e.g. --disable-filter graphql)
    #[arg(long, env = "FIND_UNUSED_PUB_DISABLE_FILTER", value_delimiter = ',')]
    disable_filter: Vec<String>,

    /// Enable an opt-in filter plugin by name (repeatable, e.g. --enable-filter cynic)
    #[arg(long, env = "FIND_UNUSED_PUB_ENABLE_FILTER", value_delimiter = ',')]
    enable_filter: Vec<String>,

    /// Resume from cached scan results instead of re-scanning
    #[arg(long)]
    resume: bool,
}

impl Args {
    fn should_fix_crate_internal(&self) -> bool {
        self.fix_crate_internal || self.fix
    }
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PubSymbol {
    name: String,
    file: PathBuf,
    line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum SymbolKind {
    UnusedAnywhere,
    CrateInternalOnly { refs: usize },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct UnusedSymbol {
    symbol: PubSymbol,
    kind: SymbolKind,
    crate_name: String,
    /// Reference locations for crate-internal items (excludes definition line).
    internal_refs: Vec<(PathBuf, usize)>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum SkipReason {
    Graphql(String),
    Cynic(String),
    Orm,
}

impl SkipReason {
    /// Display label for the TUI, e.g. "[graphql:SimpleObject]" or "[orm]".
    fn label(&self) -> String {
        match self {
            SkipReason::Graphql(attr) => format!(" [graphql:{attr}]"),
            SkipReason::Cynic(attr) => format!(" [cynic:{attr}]"),
            SkipReason::Orm => " [orm]".to_string(),
        }
    }

    /// Resolve the label color by looking up the corresponding filter plugin.
    fn label_color(&self) -> Color {
        let filter_name = match self {
            SkipReason::Graphql(_) => "graphql",
            SkipReason::Cynic(_) => "cynic",
            SkipReason::Orm => "orm",
        };
        // Find the matching filter to get its configured color
        for f in all_filters() {
            if f.name() == filter_name {
                return f.label_color();
            }
        }
        theme().dim
    }
}

// ---------------------------------------------------------------------------
// Filter plugin system
// ---------------------------------------------------------------------------

/// A named, toggleable plugin that participates in crate analysis.
///
/// Plugins can do two things (both optional, override as needed):
/// - **Filter**: partition symbols into kept vs skipped (ORM, GraphQL).
/// - **Alias**: provide alternative search names (derive_builder).
trait SymbolFilter: Send + Sync {
    /// Short lowercase name shown in CLI / TUI (e.g. "graphql", "orm").
    fn name(&self) -> &'static str;

    /// Color used for the `[name]` label in the TUI.
    fn label_color(&self) -> Color;

    /// Whether this filter is enabled by default.
    /// Opt-in filters (like cynic) return `false` here.
    fn default_enabled(&self) -> bool {
        true
    }

    /// Partition `symbols` into (kept, skipped).
    /// Called once per crate after `collect_pub_symbols`.
    /// Default: keep everything.
    fn filter(&self, symbols: Vec<PubSymbol>) -> (Vec<PubSymbol>, Vec<(PubSymbol, SkipReason)>) {
        (symbols, vec![])
    }

    /// Provide additional search aliases for symbols.
    /// Returns a map of original_name → alias_name.
    /// Default: no aliases.
    fn aliases(&self, _symbols: &[PubSymbol]) -> HashMap<String, String> {
        HashMap::new()
    }
}

/// ORM filter — skips well-known sea-orm derive names (Model, Entity, …).
struct OrmFilter;

impl SymbolFilter for OrmFilter {
    fn name(&self) -> &'static str {
        "orm"
    }

    fn label_color(&self) -> Color {
        theme().filter_colors[0]
    }

    fn filter(&self, symbols: Vec<PubSymbol>) -> (Vec<PubSymbol>, Vec<(PubSymbol, SkipReason)>) {
        let mut kept = vec![];
        let mut skipped = vec![];
        for sym in symbols {
            if SKIP_SYMBOLS.contains(&sym.name.as_str()) {
                skipped.push((sym, SkipReason::Orm));
            } else {
                kept.push(sym);
            }
        }
        // Deduplicate skipped names
        let mut seen = HashSet::new();
        skipped.retain(|(sym, _)| seen.insert(sym.name.clone()));
        (kept, skipped)
    }
}

/// GraphQL filter — skips items decorated with async-graphql attributes.
struct GraphqlFilter;

impl SymbolFilter for GraphqlFilter {
    fn name(&self) -> &'static str {
        "graphql"
    }

    fn label_color(&self) -> Color {
        theme().filter_colors[1]
    }

    fn filter(&self, symbols: Vec<PubSymbol>) -> (Vec<PubSymbol>, Vec<(PubSymbol, SkipReason)>) {
        filter_graphql_exempt(symbols)
    }
}

/// Builder filter — detects #[derive(Builder)] and adds {Name}Builder aliases.
struct BuilderFilter;

impl SymbolFilter for BuilderFilter {
    fn name(&self) -> &'static str {
        "builder"
    }

    fn label_color(&self) -> Color {
        theme().filter_colors[2]
    }

    fn aliases(&self, symbols: &[PubSymbol]) -> HashMap<String, String> {
        detect_builder_aliases(symbols)
    }
}

/// Cynic filter — skips items decorated with cynic derive attributes.
/// Off by default — enable with `--enable-filter cynic`.
struct CynicFilter;

impl SymbolFilter for CynicFilter {
    fn name(&self) -> &'static str {
        "cynic"
    }

    fn label_color(&self) -> Color {
        theme().filter_colors[3]
    }

    fn default_enabled(&self) -> bool {
        false
    }

    fn filter(&self, symbols: Vec<PubSymbol>) -> (Vec<PubSymbol>, Vec<(PubSymbol, SkipReason)>) {
        filter_cynic_exempt(symbols)
    }
}

/// All available filters, in the order they run.
fn all_filters() -> Vec<Box<dyn SymbolFilter>> {
    vec![
        Box::new(OrmFilter),
        Box::new(GraphqlFilter),
        Box::new(BuilderFilter),
        Box::new(CynicFilter),
    ]
}

/// Build the active filter list: default-on filters minus `disabled`, plus
/// default-off filters that appear in `enabled`.
fn active_filters(disabled: &[String], enabled: &[String]) -> Vec<Box<dyn SymbolFilter>> {
    all_filters()
        .into_iter()
        .filter(|f| {
            let explicitly_disabled = disabled.iter().any(|d| d.eq_ignore_ascii_case(f.name()));
            let explicitly_enabled = enabled.iter().any(|e| e.eq_ignore_ascii_case(f.name()));
            if explicitly_disabled {
                return false;
            }
            f.default_enabled() || explicitly_enabled
        })
        .collect()
}

/// Names of all known filters (for help text / validation).
fn all_filter_names() -> Vec<&'static str> {
    vec!["orm", "graphql", "builder", "cynic"]
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct CrateResult {
    crate_name: String,
    items_found: usize,
    unused: Vec<UnusedSymbol>,
    /// Symbols skipped with the reason they were skipped.
    skipped: Vec<(PubSymbol, SkipReason)>,
}

enum ScanMessage {
    Stage(String),
    Done(CrateResult),
}

#[derive(Debug, Clone)]
struct GitBlameInfo {
    short_hash: String,
    author: String,
    date: String,
    age: String,
    summary: String,
}

#[derive(Debug, Clone)]
struct GitLogEntry {
    short_hash: String,
    author: String,
    date: String,
    age: String,
    subject: String,
    patch: String,
    /// All +/- lines from the full diff that mention the symbol.
    diff_matches: Vec<String>,
    /// True if the symbol only appears in definition-like lines (fn, struct, etc.),
    /// never in usage context.
    definition_only: bool,
}

#[derive(Debug, Clone)]
struct GitInfo {
    blame: Option<GitBlameInfo>,
    log_entry: Option<GitLogEntry>,
}

#[derive(Clone)]
enum GitLoadState {
    Pending,
    RunningBlame,
    RunningLogS,
    Done(GitInfo),
}

#[derive(Clone)]
enum ReviewAction {
    Fix,
    Allowlist,
    Skip,
}

/// Tracks background scan progress when the TUI starts before scanning completes.
struct ScanState {
    crate_names: Vec<String>,
    /// Current stage description per crate (shown while scanning).
    stages: Vec<String>,
    /// Indexed by crate order; `None` means still scanning.
    completed: Vec<Option<CrateResult>>,
    rx: mpsc::Receiver<(usize, ScanMessage)>,
    start: Instant,
}

// ---------------------------------------------------------------------------
// Git info
// ---------------------------------------------------------------------------

fn git_blame(file: &Path, line: usize, workspace_root: &Path) -> Option<GitBlameInfo> {
    let output = Command::new("git")
        .args(["blame", &format!("-L{line},{line}"), "--porcelain"])
        .arg(file)
        .current_dir(workspace_root)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut hash = None;
    let mut author = None;
    let mut epoch = None;
    let mut summary = None;
    for blame_line in stdout.lines() {
        if hash.is_none() {
            // First line: "hash orig_line final_line num_lines"
            hash = blame_line.split_whitespace().next().map(|h| {
                if h.len() >= 7 { h[..7].to_string() } else { h.to_string() }
            });
        } else if let Some(a) = blame_line.strip_prefix("author ") {
            author = Some(a.to_string());
        } else if let Some(t) = blame_line.strip_prefix("author-time ") {
            epoch = t.trim().parse::<i64>().ok();
        } else if let Some(s) = blame_line.strip_prefix("summary ") {
            summary = Some(s.to_string());
        }
    }
    let dt = DateTime::from_timestamp(epoch?, 0)?;
    let date = dt.format("%Y-%m-%d").to_string();
    let age = relative_age(dt);
    Some(GitBlameInfo {
        short_hash: hash?,
        author: author.unwrap_or_default(),
        date,
        age,
        summary: summary.unwrap_or_default(),
    })
}

fn relative_age(dt: DateTime<Utc>) -> String {
    let days = (Utc::now() - dt).num_days();
    if days < 1 {
        "today".to_string()
    } else if days == 1 {
        "yesterday".to_string()
    } else if days < 30 {
        format!("{days} days ago")
    } else if days < 365 {
        let months = days / 30;
        if months == 1 { "1 month ago".to_string() } else { format!("{months} months ago") }
    } else {
        let years = days / 365;
        if years == 1 { "1 year ago".to_string() } else { format!("{years} years ago") }
    }
}

fn git_log_s(symbol: &str, workspace_root: &Path) -> Option<GitLogEntry> {
    let output = Command::new("git")
        .args([
            "log",
            "-1",
            "-S",
            symbol,
            "--format=%h|%an|%ad|%s",
            "--date=short",
            "--patch",
            "--",
            "**/*.rs",
        ])
        .current_dir(workspace_root)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();
    let header = lines.next()?;
    if header.is_empty() {
        return None;
    }
    let parts: Vec<&str> = header.splitn(4, '|').collect();
    if parts.len() < 4 {
        return None;
    }
    let raw_patch: String = lines.collect::<Vec<_>>().join("\n");
    let patch = filter_patch_for_symbol(&raw_patch, symbol);

    // Grep the full diff for the symbol — like `rg "symbol" diff_output`
    let diff_matches: Vec<String> = raw_patch
        .lines()
        .filter(|l| {
            (l.starts_with('+') || l.starts_with('-'))
                && !l.starts_with("+++")
                && !l.starts_with("---")
                && l.contains(symbol)
        })
        .map(|l| l.to_string())
        .collect();

    let definition_only = !diff_matches.is_empty()
        && diff_matches.iter().all(|l| is_definition_line(l, symbol));

    let date_str = parts[2].to_string();
    let age = NaiveDate::parse_from_str(&date_str, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|dt| relative_age(dt.and_utc()))
        .unwrap_or_default();
    Some(GitLogEntry {
        short_hash: parts[0].to_string(),
        author: parts[1].to_string(),
        date: date_str,
        age,
        subject: parts[3].to_string(),
        patch,
        diff_matches,
        definition_only,
    })
}

/// Filter a full commit patch down to only hunks where a +/- line contains the symbol.
fn filter_patch_for_symbol(patch: &str, symbol: &str) -> String {
    let mut result = Vec::new();
    let mut current_file_header: Vec<&str> = Vec::new();
    let mut current_hunk: Vec<&str> = Vec::new();
    let mut hunk_matches = false;
    let mut file_header_emitted = false;

    for line in patch.lines() {
        if line.starts_with("diff --git ") {
            // Flush previous hunk
            if hunk_matches && !current_hunk.is_empty() {
                if !file_header_emitted {
                    result.extend_from_slice(&current_file_header);
                }
                result.extend_from_slice(&current_hunk);
            }
            // Start new file section
            current_file_header = vec![line];
            current_hunk.clear();
            hunk_matches = false;
            file_header_emitted = false;
        } else if line.starts_with("--- ") || line.starts_with("+++ ") || line.starts_with("index ") {
            current_file_header.push(line);
        } else if line.starts_with("@@") {
            // Flush previous hunk
            if hunk_matches && !current_hunk.is_empty() {
                if !file_header_emitted {
                    result.extend_from_slice(&current_file_header);
                    file_header_emitted = true;
                }
                result.extend_from_slice(&current_hunk);
            }
            // Start new hunk
            current_hunk = vec![line];
            hunk_matches = false;
        } else {
            current_hunk.push(line);
            if !hunk_matches
                && (line.starts_with('+') || line.starts_with('-'))
                && line.contains(symbol)
            {
                hunk_matches = true;
            }
        }
    }
    // Flush final hunk
    if hunk_matches && !current_hunk.is_empty() {
        if !file_header_emitted {
            result.extend_from_slice(&current_file_header);
        }
        result.extend_from_slice(&current_hunk);
    }
    result.join("\n")
}

/// Check if a diff line mentions the symbol only in a definition context
/// (fn, struct, enum, type, const, static, trait, mod).
fn is_definition_line(line: &str, symbol: &str) -> bool {
    let content = line.trim_start_matches(['+', '-']);
    // Everything before the symbol name tells us if it's a definition
    let before = content.split(symbol).next().unwrap_or("");
    before.contains("fn ")
        || before.contains("struct ")
        || before.contains("enum ")
        || before.contains("type ")
        || before.contains("const ")
        || before.contains("static ")
        || before.contains("trait ")
        || before.contains("mod ")
}

fn spawn_prefetcher(
    items: Vec<(usize, String, PathBuf, usize)>,
    workspace_root: PathBuf,
    tx: mpsc::Sender<(usize, GitLoadState)>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        for (idx, name, file, line) in items {
            // Signal: running blame
            if tx.send((idx, GitLoadState::RunningBlame)).is_err() {
                break;
            }
            let blame = git_blame(&file, line, &workspace_root);

            // Signal: running log -S
            if tx.send((idx, GitLoadState::RunningLogS)).is_err() {
                break;
            }
            let log_entry = git_log_s(&name, &workspace_root);

            let info = GitInfo { blame, log_entry };
            if tx.send((idx, GitLoadState::Done(info))).is_err() {
                break;
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Symbol collection
// ---------------------------------------------------------------------------

/// Skipped ORM-derived symbols that are always used implicitly.
const SKIP_SYMBOLS: &[&str] = &[
    "ActiveModel",
    "Model",
    "Relation",
    "Entity",
    "Column",
    "ActiveModelBehavior",
];

/// async-graphql attributes that mark items as framework-used.
/// Ordered longest-first so that `contains("Object")` doesn't shadow `SimpleObject`.
const GRAPHQL_ATTRS: &[&str] = &[
    "SimpleObject",
    "MergedObject",
    "InputObject",
    "Subscription",
    "Interface",
    "Mutation",
    "Object",
    "Union",
];

fn collect_pub_symbols(crate_path: &Path) -> Result<Vec<PubSymbol>> {
    let src = crate_path.join("src");
    if !src.is_dir() {
        return Ok(vec![]);
    }

    let pattern = r"^\s*pub\s+(?:async\s+)?(?:fn|struct|enum|trait|type|const|static)\s+([A-Za-z_][A-Za-z0-9_]*)";
    let matcher = RegexMatcherBuilder::new()
        .build(pattern)
        .context("building pub-definition regex")?;

    let extract_re =
        regex::Regex::new(r"^\s*pub\s+(?:async\s+)?(?:fn|struct|enum|trait|type|const|static)\s+([A-Za-z_][A-Za-z0-9_]*)")
            .unwrap();

    let mut results: Vec<PubSymbol> = vec![];
    let mut searcher = Searcher::new();

    for entry in WalkBuilder::new(&src)
        .types(
            ignore::types::TypesBuilder::new()
                .add_defaults()
                .select("rust")
                .build()
                .unwrap(),
        )
        .build()
        .flatten()
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        // Skip generated files
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .map_or(false, |n| n.contains(".generated."))
        {
            continue;
        }

        searcher.search_path(
            &matcher,
            path,
            UTF8(|line_num, line| {
                // Filter out pub(crate), pub(super), pub(in ...)
                let trimmed = line.trim_start();
                if trimmed.starts_with("pub(crate)")
                    || trimmed.starts_with("pub(super)")
                    || trimmed.starts_with("pub(in ")
                {
                    return Ok(true);
                }

                if let Some(caps) = extract_re.captures(line) {
                    let name = caps[1].to_string();
                    if name.len() >= 2 {
                        results.push(PubSymbol {
                            name,
                            file: path.to_path_buf(),
                            line: line_num as usize,
                        });
                    }
                }
                Ok(true)
            }),
        )?;
    }

    // Deduplicate by name, keeping first occurrence
    let mut seen = HashSet::new();
    let mut deduped = vec![];
    for sym in results {
        if seen.insert(sym.name.clone()) {
            deduped.push(sym);
        }
    }

    Ok(deduped)
}

// ---------------------------------------------------------------------------
// Symbol searching
// ---------------------------------------------------------------------------

/// Count occurrences of each symbol name in the given directories.
/// Returns a map of symbol_name → hit count.
fn count_symbol_hits(
    symbol_names: &[String],
    search_dirs: &[PathBuf],
) -> Result<HashMap<String, usize>> {
    if symbol_names.is_empty() || search_dirs.is_empty() {
        return Ok(HashMap::new());
    }

    // Build a word-bounded alternation: \b(sym1|sym2|...)\b
    let alt = symbol_names.join("|");
    let pattern = format!(r"\b({})\b", alt);

    let matcher = RegexMatcherBuilder::new()
        .build(&pattern)
        .context("building symbol search regex")?;

    let word_re = regex::Regex::new(&pattern).unwrap();
    let mut counts: HashMap<String, usize> = HashMap::new();

    let mut walker = WalkBuilder::new(&search_dirs[0]);
    for dir in &search_dirs[1..] {
        walker.add(dir);
    }
    let walker = walker
        .types(
            ignore::types::TypesBuilder::new()
                .add_defaults()
                .select("rust")
                .build()
                .unwrap(),
        )
        .build();

    let mut searcher = Searcher::new();

    for entry in walker.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        searcher.search_path(
            &matcher,
            path,
            UTF8(|_line_num, line| {
                // Skip comment-only lines (commented-out code shouldn't count)
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    return Ok(true);
                }
                for m in word_re.find_iter(line) {
                    let sym = m.as_str().to_string();
                    *counts.entry(sym).or_insert(0) += 1;
                }
                Ok(true)
            }),
        )?;
    }

    Ok(counts)
}

/// Find all (file, line) locations where any of the given symbol names appear.
fn find_symbol_locations(
    names: &[&str],
    search_dirs: &[PathBuf],
) -> Result<Vec<(PathBuf, usize)>> {
    if names.is_empty() || search_dirs.is_empty() {
        return Ok(vec![]);
    }

    let alt = names
        .iter()
        .map(|n| regex::escape(n))
        .collect::<Vec<_>>()
        .join("|");
    let pattern = format!(r"\b({})\b", alt);

    let matcher = RegexMatcherBuilder::new()
        .build(&pattern)
        .context("building location search regex")?;

    let mut locations = vec![];
    let mut searcher = Searcher::new();

    let mut walker = WalkBuilder::new(&search_dirs[0]);
    for dir in &search_dirs[1..] {
        walker.add(dir);
    }
    let walker = walker
        .types(
            ignore::types::TypesBuilder::new()
                .add_defaults()
                .select("rust")
                .build()
                .unwrap(),
        )
        .build();

    for entry in walker.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        searcher.search_path(
            &matcher,
            path,
            UTF8(|line_num, line| {
                // Skip comment-only lines (commented-out code shouldn't count)
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    return Ok(true);
                }
                locations.push((path.to_path_buf(), line_num as usize));
                Ok(true)
            }),
        )?;
    }

    Ok(locations)
}

// ---------------------------------------------------------------------------
// Crate analysis
// ---------------------------------------------------------------------------

fn analyze_crate(
    crate_path: &Path,
    all_crate_dirs: &[PathBuf],
    allowlist: &HashSet<(String, String)>,
    filters: &[Box<dyn SymbolFilter>],
    on_progress: &dyn Fn(&str),
) -> Result<CrateResult> {
    let crate_name = crate_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    on_progress("collecting pub symbols…");
    let all_symbols = collect_pub_symbols(crate_path)?;
    let items_found = all_symbols.len();

    // Run each active filter plugin in sequence
    let mut symbols = all_symbols;
    let mut skipped: Vec<(PubSymbol, SkipReason)> = vec![];
    for filter in filters.iter() {
        on_progress(&format!("filtering [{}]…", filter.name()));
        let (kept, filter_skipped) = filter.filter(symbols);
        symbols = kept;
        skipped.extend(filter_skipped);
    }

    if symbols.is_empty() {
        return Ok(CrateResult {
            crate_name,
            items_found: 0,
            unused: vec![],
            skipped,
        });
    }

    // External search: all other crate dirs (includes tests/, benches/)
    let external_dirs: Vec<PathBuf> = all_crate_dirs
        .iter()
        .filter(|d| d.as_path() != crate_path)
        .cloned()
        .collect();

    let symbol_names: Vec<String> = symbols.iter().map(|s| s.name.clone()).collect();

    // Collect aliases from all active plugins (e.g. Builder → {Name}Builder)
    let mut all_aliases = HashMap::new();
    for filter in filters.iter() {
        all_aliases.extend(filter.aliases(&symbols));
    }
    let mut ext_search: Vec<String> = symbol_names.clone();
    for alias in all_aliases.values() {
        ext_search.push(alias.clone());
    }

    on_progress(&format!("searching {} symbols externally…", ext_search.len()));
    let mut external_counts = count_symbol_hits(&ext_search, &external_dirs)?;
    // Merge alias hits back to the original symbol
    for (origin, alias) in &all_aliases {
        if let Some(&count) = external_counts.get(alias) {
            *external_counts.entry(origin.clone()).or_insert(0) += count;
        }
    }

    // Find symbols with zero external hits
    let no_external: Vec<&PubSymbol> = symbols
        .iter()
        .filter(|s| external_counts.get(&s.name).copied().unwrap_or(0) == 0)
        .collect();

    // Internal search for those symbols (including builder aliases)
    let mut internal_search: Vec<String> = no_external.iter().map(|s| s.name.clone()).collect();
    for sym in &no_external {
        if let Some(alias) = all_aliases.get(&sym.name) {
            internal_search.push(alias.clone());
        }
    }
    on_progress(&format!("searching {} symbols internally…", internal_search.len()));
    let mut internal_counts = count_symbol_hits(&internal_search, &[crate_path.to_path_buf()])?;
    for (origin, alias) in &all_aliases {
        if let Some(&count) = internal_counts.get(alias) {
            *internal_counts.entry(origin.clone()).or_insert(0) += count;
        }
    }

    // Classify
    let mut unused = vec![];
    for sym in no_external {
        // Check allowlist
        if allowlist.contains(&(sym.name.clone(), crate_name.clone())) {
            continue;
        }

        let internal_hits = internal_counts.get(&sym.name).copied().unwrap_or(0);
        let kind = if internal_hits <= 1 {
            SymbolKind::UnusedAnywhere
        } else {
            SymbolKind::CrateInternalOnly {
                refs: internal_hits,
            }
        };

        unused.push(UnusedSymbol {
            symbol: sym.clone(),
            kind,
            crate_name: crate_name.clone(),
            internal_refs: vec![],
        });
    }

    // For crate-internal items, find where the references are
    for item in &mut unused {
        if let SymbolKind::CrateInternalOnly { .. } = item.kind {
            let mut search_names: Vec<&str> = vec![&item.symbol.name];
            let alias;
            if let Some(a) = all_aliases.get(&item.symbol.name) {
                alias = a.clone();
                search_names.push(&alias);
            }
            let mut refs =
                find_symbol_locations(&search_names, &[crate_path.to_path_buf()])?;
            // Remove the definition line itself
            refs.retain(|(f, l)| !(*f == item.symbol.file && *l == item.symbol.line));
            item.internal_refs = refs;
        }
    }

    on_progress(&format!("done — {} issues found", unused.len()));
    Ok(CrateResult {
        crate_name,
        items_found,
        unused,
        skipped,
    })
}

// ---------------------------------------------------------------------------
// Allowlist DB
// ---------------------------------------------------------------------------

fn open_db(workspace_root: &Path) -> Result<Connection> {
    let path = workspace_root.join(".find-unused-pub.db");
    let conn = Connection::open(&path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS allowlist (
            symbol TEXT NOT NULL,
            crate_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            reason TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (symbol, crate_name)
        );
        CREATE TABLE IF NOT EXISTS scan_cache (
            crate_name TEXT PRIMARY KEY,
            content_hash TEXT NOT NULL,
            results_json TEXT NOT NULL,
            scanned_at TEXT DEFAULT CURRENT_TIMESTAMP
        );",
    )?;
    Ok(conn)
}

fn load_allowlist(conn: &Connection) -> Result<HashSet<(String, String)>> {
    let mut stmt = conn.prepare("SELECT symbol, crate_name FROM allowlist")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut set = HashSet::new();
    for row in rows {
        set.insert(row?);
    }
    Ok(set)
}

fn add_to_allowlist(
    conn: &Connection,
    symbol: &str,
    crate_name: &str,
    file_path: &str,
    reason: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO allowlist (symbol, crate_name, file_path, reason) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![symbol, crate_name, file_path, reason],
    )?;
    Ok(())
}

fn nuke_allowlist(conn: &Connection) -> Result<()> {
    conn.execute_batch("DROP TABLE IF EXISTS allowlist;")?;
    conn.execute_batch(
        "CREATE TABLE allowlist (
            symbol TEXT NOT NULL,
            crate_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            reason TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (symbol, crate_name)
        );",
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Scan cache
// ---------------------------------------------------------------------------

/// Compute a content hash for a crate's src/ directory.
/// Uses file paths + modification times as a cheap fingerprint.
fn crate_content_hash(crate_path: &Path) -> String {
    use std::fmt::Write;
    let src_dir = crate_path.join("src");
    let mut entries: Vec<(String, u64)> = vec![];
    if let Ok(walker) = fs::read_dir(&src_dir) {
        collect_rs_mtimes(&src_dir, &mut entries);
        let _ = walker; // consumed above
    }
    entries.sort();
    let mut hasher = String::new();
    for (path, mtime) in &entries {
        let _ = write!(hasher, "{path}:{mtime};");
    }
    format!("{:x}", simple_hash(hasher.as_bytes()))
}

/// Recursively collect .rs files and their modification times.
fn collect_rs_mtimes(dir: &Path, out: &mut Vec<(String, u64)>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_mtimes(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let mtime = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            out.push((path.to_string_lossy().to_string(), mtime));
        }
    }
}

/// Simple non-cryptographic hash (FNV-1a).
fn simple_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Try to load a cached scan result for a crate.
/// Returns `None` on cache miss, hash mismatch, or deserialization failure
/// (e.g. if the shape of CrateResult changed since the entry was written).
fn load_cached_result(conn: &Connection, crate_name: &str, expected_hash: &str) -> Option<CrateResult> {
    let mut stmt = conn
        .prepare("SELECT content_hash, results_json FROM scan_cache WHERE crate_name = ?1")
        .ok()?;
    let (hash, json): (String, String) = stmt
        .query_row(rusqlite::params![crate_name], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .ok()?;
    if hash != expected_hash {
        return None;
    }
    serde_json::from_str(&json).ok()
}

/// Save a scan result to the cache.
fn save_cached_result(conn: &Connection, crate_name: &str, content_hash: &str, result: &CrateResult) {
    let json = match serde_json::to_string(result) {
        Ok(j) => j,
        Err(_) => return,
    };
    let _ = conn.execute(
        "INSERT OR REPLACE INTO scan_cache (crate_name, content_hash, results_json) VALUES (?1, ?2, ?3)",
        rusqlite::params![crate_name, content_hash, json],
    );
}

// ---------------------------------------------------------------------------
// Fixing
// ---------------------------------------------------------------------------

fn apply_fix_crate_internal(symbol: &UnusedSymbol) -> Result<()> {
    let content = fs::read_to_string(&symbol.symbol.file)?;
    let lines: Vec<&str> = content.lines().collect();
    let line_idx = symbol.symbol.line - 1;

    if line_idx >= lines.len() {
        anyhow::bail!(
            "line {} out of range in {}",
            symbol.symbol.line,
            symbol.symbol.file.display()
        );
    }

    let new_line = lines[line_idx].replacen("pub ", "pub(crate) ", 1);
    let mut new_lines: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
    new_lines[line_idx] = new_line;

    let mut result = new_lines.join("\n");
    if content.ends_with('\n') {
        result.push('\n');
    }
    fs::write(&symbol.symbol.file, result)?;
    Ok(())
}

/// Find the full span of a Rust item starting at `start_line` (0-indexed).
/// Returns (inclusive_start, exclusive_end) line indices.
/// Uses tree-sitter for accurate parsing with fallback to brace-counting.
fn find_item_span(source: &str, start_line: usize) -> (usize, usize) {
    if let Some(span) = find_item_span_ts(source, start_line) {
        return span;
    }
    find_item_span_fallback(source, start_line)
}

const ITEM_KINDS: &[&str] = &[
    "function_item",
    "struct_item",
    "enum_item",
    "trait_item",
    "type_item",
    "const_item",
    "static_item",
];

fn find_item_span_ts(source: &str, start_line: usize) -> Option<(usize, usize)> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(source, None)?;
    let root = tree.root_node();
    let item = find_item_at_line(root, start_line)?;

    // Attributes are children of the item in tree-sitter-rust,
    // so start_position() already includes them.
    let mut first_line = item.start_position().row;
    let last_line = item.end_position().row;

    // Doc comments and attributes are separate sibling nodes — walk back to include them.
    let mut prev = item.prev_sibling();
    while let Some(sibling) = prev {
        match sibling.kind() {
            "line_comment" | "block_comment" => {
                let text = &source[sibling.start_byte()..sibling.end_byte()];
                if text.starts_with("///") || text.starts_with("//!") || text.starts_with("/**") {
                    first_line = sibling.start_position().row;
                    prev = sibling.prev_sibling();
                } else {
                    break;
                }
            }
            "attribute_item" => {
                first_line = sibling.start_position().row;
                prev = sibling.prev_sibling();
            }
            _ => break,
        }
    }

    let mut end = last_line + 1;
    let lines: Vec<&str> = source.lines().collect();
    if end < lines.len() && lines[end].trim().is_empty() {
        end += 1;
    }

    Some((first_line, end))
}

fn find_item_at_line<'a>(
    node: tree_sitter::Node<'a>,
    line: usize,
) -> Option<tree_sitter::Node<'a>> {
    if ITEM_KINDS.contains(&node.kind()) {
        let start = node.start_position().row;
        let end = node.end_position().row;
        if line >= start && line <= end {
            return Some(node);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = find_item_at_line(child, line) {
            return Some(found);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// GraphQL attribute detection (tree-sitter)
// ---------------------------------------------------------------------------

/// Check if a pub symbol at `line` (0-indexed) is exempt from unused detection
/// because it has async-graphql attributes (directly or via parent impl block).
fn is_graphql_exempt(source: &str, line: usize) -> Option<String> {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .is_err()
    {
        return None;
    }
    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return None,
    };
    let root = tree.root_node();

    let item = match find_item_at_line(root, line) {
        Some(i) => i,
        None => return None,
    };

    // Check direct attributes on the item (e.g. #[derive(SimpleObject)])
    if let Some(attr) = node_has_graphql_attr(item, source) {
        return Some(attr);
    }

    // If inside an impl block, check the impl block's attributes (e.g. #[Object])
    let mut parent = item.parent();
    while let Some(p) = parent {
        if p.kind() == "impl_item" {
            return node_has_graphql_attr(p, source);
        }
        parent = p.parent();
    }

    None
}

/// Check if a node's preceding sibling attributes contain any GRAPHQL_ATTRS.
fn node_has_graphql_attr(node: tree_sitter::Node, source: &str) -> Option<String> {
    let mut sibling = node.prev_sibling();
    while let Some(s) = sibling {
        match s.kind() {
            "attribute_item" => {
                let text = &source[s.start_byte()..s.end_byte()];
                for attr in GRAPHQL_ATTRS {
                    if text.contains(attr) {
                        return Some(attr.to_string());
                    }
                }
            }
            "line_comment" | "block_comment" => {}
            _ => break,
        }
        sibling = s.prev_sibling();
    }
    None
}

/// Filter out symbols that are exempt due to async-graphql attributes.
/// Returns (kept symbols, names of skipped symbols).
fn filter_graphql_exempt(symbols: Vec<PubSymbol>) -> (Vec<PubSymbol>, Vec<(PubSymbol, SkipReason)>) {
    let mut kept = vec![];
    let mut skipped = vec![];
    for sym in symbols {
        let source = match fs::read_to_string(&sym.file) {
            Ok(s) => s,
            Err(_) => {
                kept.push(sym);
                continue;
            }
        };
        if let Some(attr) = is_graphql_exempt(&source, sym.line - 1) {
            skipped.push((sym, SkipReason::Graphql(attr)));
        } else {
            kept.push(sym);
        }
    }
    (kept, skipped)
}

// ---------------------------------------------------------------------------
// cynic attribute detection
// ---------------------------------------------------------------------------

/// cynic derive macro names that mark items as framework-used.
const CYNIC_ATTRS: &[&str] = &[
    "QueryFragment",
    "QueryVariables",
    "InputObject",
    "Enum",
    "Scalar",
    "InlineFragments",
];

/// Check if a symbol at `line` (0-indexed) has a cynic derive attribute.
fn is_cynic_exempt(source: &str, line: usize) -> Option<String> {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .is_err()
    {
        return None;
    }
    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return None,
    };
    let root = tree.root_node();

    let item = match find_item_at_line(root, line) {
        Some(i) => i,
        None => return None,
    };

    node_has_cynic_attr(item, source)
}

/// Check if a node's preceding sibling attributes contain any CYNIC_ATTRS.
fn node_has_cynic_attr(node: tree_sitter::Node, source: &str) -> Option<String> {
    let mut sibling = node.prev_sibling();
    while let Some(s) = sibling {
        match s.kind() {
            "attribute_item" => {
                let text = &source[s.start_byte()..s.end_byte()];
                if text.contains("cynic") {
                    for attr in CYNIC_ATTRS {
                        if text.contains(attr) {
                            return Some(attr.to_string());
                        }
                    }
                }
            }
            "line_comment" | "block_comment" => {}
            _ => break,
        }
        sibling = s.prev_sibling();
    }
    None
}

/// Filter out symbols that are exempt due to cynic derive attributes.
fn filter_cynic_exempt(symbols: Vec<PubSymbol>) -> (Vec<PubSymbol>, Vec<(PubSymbol, SkipReason)>) {
    let mut kept = vec![];
    let mut skipped = vec![];
    for sym in symbols {
        let source = match fs::read_to_string(&sym.file) {
            Ok(s) => s,
            Err(_) => {
                kept.push(sym);
                continue;
            }
        };
        if let Some(attr) = is_cynic_exempt(&source, sym.line - 1) {
            skipped.push((sym, SkipReason::Cynic(attr)));
        } else {
            kept.push(sym);
        }
    }
    (kept, skipped)
}

// ---------------------------------------------------------------------------
// derive_builder alias detection (tree-sitter)
// ---------------------------------------------------------------------------

/// Detect symbols with #[derive(Builder)] and return a map of name → ["{name}Builder"].
/// These aliases should also be searched when counting references.
fn detect_builder_aliases(symbols: &[PubSymbol]) -> HashMap<String, String> {
    let mut aliases = HashMap::new();
    for sym in symbols {
        let source = match fs::read_to_string(&sym.file) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if has_derive_builder(&source, sym.line - 1) {
            aliases.insert(sym.name.clone(), format!("{}Builder", sym.name));
        }
    }
    aliases
}

/// Check if a symbol at `line` (0-indexed) has #[derive(Builder)].
fn has_derive_builder(source: &str, line: usize) -> bool {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .is_err()
    {
        return false;
    }
    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return false,
    };
    let root = tree.root_node();
    let item = match find_item_at_line(root, line) {
        Some(i) => i,
        None => return false,
    };
    let mut sibling = item.prev_sibling();
    while let Some(s) = sibling {
        match s.kind() {
            "attribute_item" => {
                let text = &source[s.start_byte()..s.end_byte()];
                if text.contains("derive") && text.contains("Builder") {
                    return true;
                }
            }
            "line_comment" | "block_comment" => {}
            _ => break,
        }
        sibling = s.prev_sibling();
    }
    false
}

/// Fallback: brace-counting heuristic when tree-sitter fails to parse.
fn find_item_span_fallback(source: &str, start_line: usize) -> (usize, usize) {
    let lines: Vec<&str> = source.lines().collect();
    let mut first = start_line;
    while first > 0 {
        let prev = lines[first - 1].trim();
        if prev.starts_with('#')
            || prev.starts_with("///")
            || prev.starts_with("//!")
            || prev.is_empty()
        {
            first -= 1;
        } else {
            break;
        }
    }
    while first < start_line && lines[first].trim().is_empty() {
        first += 1;
    }

    let def_line = lines[start_line];
    let is_semicolon_item = {
        let trimmed = def_line.trim_start();
        trimmed.starts_with("pub const ")
            || trimmed.starts_with("pub static ")
            || trimmed.starts_with("pub type ")
            || trimmed.starts_with("const ")
            || trimmed.starts_with("static ")
            || trimmed.starts_with("type ")
    };

    let mut end = start_line;
    if is_semicolon_item {
        while end < lines.len() {
            if lines[end].contains(';') {
                end += 1;
                break;
            }
            end += 1;
        }
    } else {
        let mut depth: i32 = 0;
        let mut found_open = false;
        while end < lines.len() {
            for ch in lines[end].chars() {
                if ch == '{' {
                    depth += 1;
                    found_open = true;
                } else if ch == '}' {
                    depth -= 1;
                }
            }
            end += 1;
            if found_open && depth <= 0 {
                break;
            }
        }
    }

    if end < lines.len() && lines[end].trim().is_empty() {
        end += 1;
    }

    (first, end)
}

fn apply_fix_unused(symbol: &UnusedSymbol) -> Result<String> {
    let content = fs::read_to_string(&symbol.symbol.file)?;
    let lines: Vec<&str> = content.lines().collect();
    let line_idx = symbol.symbol.line - 1;

    if line_idx >= lines.len() {
        anyhow::bail!(
            "line {} out of range in {}",
            symbol.symbol.line,
            symbol.symbol.file.display()
        );
    }

    let (span_start, span_end) = find_item_span(&content, line_idx);

    // Build the removed text for display
    let removed: Vec<&str> = lines[span_start..span_end].to_vec();
    let preview = if removed.len() <= 3 {
        removed.join("\n")
    } else {
        format!(
            "{}\n  ... ({} more lines)\n{}",
            removed[0],
            removed.len() - 2,
            removed.last().unwrap()
        )
    };

    let mut new_lines: Vec<&str> = Vec::with_capacity(lines.len());
    new_lines.extend_from_slice(&lines[..span_start]);
    new_lines.extend_from_slice(&lines[span_end..]);

    let mut result = new_lines.join("\n");
    if content.ends_with('\n') && !result.ends_with('\n') {
        result.push('\n');
    }
    fs::write(&symbol.symbol.file, result)?;

    Ok(preview)
}

// ---------------------------------------------------------------------------
// TUI
// ---------------------------------------------------------------------------

/// What the TUI is currently showing.
enum TuiPhase {
    /// Crates are being scanned in the background; show progress.
    Scanning,
    Summary,
    Review,
}

/// Summary screen sub-views.
enum SummaryView {
    /// Compact table: one row per crate.
    Table,
    /// Detailed: per-symbol listing with refs.
    Detail,
    /// Skipped: graphql-exempt symbols that were excluded from analysis.
    Skipped,
}

/// Top-level app state for the unified TUI.
struct App {
    phase: TuiPhase,
    results: Vec<CrateResult>,
    all_unused: Vec<UnusedSymbol>,
    workspace_root: PathBuf,
    conn: Connection,
    elapsed: Duration,
    /// Currently highlighted menu item in the summary screen.
    summary_selected: usize,
    /// Which sub-view of the summary is active.
    summary_view: SummaryView,
    /// Scroll offset (used in table/detail/scanning views).
    detail_scroll: u16,
    /// Review sub-state (created when entering review phase).
    review: Option<ReviewApp>,
    /// Scan-in-progress state (present during Scanning phase).
    scan: Option<ScanState>,
    /// Which crates are expanded in the detail view.
    detail_expanded: HashSet<String>,
    /// Cursor position in the detail view (index among crates with unused items).
    detail_cursor: usize,
    /// Which crates are expanded in the skipped view.
    skipped_expanded: HashSet<String>,
    /// Cursor position in the skipped view (index among crates with skipped items).
    skipped_cursor: usize,
}

struct ReviewApp {
    items: Vec<UnusedSymbol>,
    workspace_root: PathBuf,
    current: usize,
    git_states: Vec<GitLoadState>,
    git_rx: mpsc::Receiver<(usize, GitLoadState)>,
    selected_action: usize,
    actions: Vec<Option<ReviewAction>>,
    scroll_offset: u16,
}

/// Actions available from the summary menu.
#[derive(Clone, Copy, PartialEq)]
enum SummaryAction {
    ReviewUnused,
    ReviewCrateInternal,
    FixAllUnused,
    FixAllCrateInternal,
    Quit,
}

fn summary_menu_items(app: &App) -> Vec<(SummaryAction, String)> {
    let n_unused = app
        .all_unused
        .iter()
        .filter(|u| u.kind == SymbolKind::UnusedAnywhere)
        .count();
    let n_internal = app
        .all_unused
        .iter()
        .filter(|u| matches!(u.kind, SymbolKind::CrateInternalOnly { .. }))
        .count();

    let mut items = vec![];
    if n_unused > 0 {
        items.push((
            SummaryAction::ReviewUnused,
            format!("👀 (r) Review unused everywhere ({n_unused}) ← recommended"),
        ));
    }
    if n_internal > 0 {
        items.push((
            SummaryAction::ReviewCrateInternal,
            format!("👀 (i) Review crate-internal ({n_internal})"),
        ));
    }
    if n_unused > 0 {
        items.push((
            SummaryAction::FixAllUnused,
            format!("⚠️  (u) Fix all unused (delete {n_unused})"),
        ));
    }
    if n_internal > 0 {
        items.push((
            SummaryAction::FixAllCrateInternal,
            format!("🔧 (c) Fix all crate-internal → pub(crate) ({n_internal}) ← recommended"),
        ));
    }
    items.push((SummaryAction::Quit, "🚪 (q) Quit".to_string()));
    items
}

fn run_tui(
    results: Vec<CrateResult>,
    scan: Option<ScanState>,
    workspace_root: &Path,
    conn: Connection,
    elapsed: Duration,
) -> Result<()> {
    let (phase, all_unused) = if scan.is_some() {
        (TuiPhase::Scanning, vec![])
    } else {
        let all_unused = results.iter().flat_map(|r| r.unused.clone()).collect();
        (TuiPhase::Summary, all_unused)
    };

    let mut app = App {
        phase,
        results,
        all_unused,
        workspace_root: workspace_root.to_path_buf(),
        conn,
        elapsed,
        summary_selected: 0,
        summary_view: SummaryView::Table,
        detail_scroll: 0,
        review: None,
        scan,
        detail_expanded: HashSet::new(),
        detail_cursor: 0,
        skipped_expanded: HashSet::new(),
        skipped_cursor: 0,
    };

    // Enter alternate screen
    let mut stdout = std::io::stdout();
    terminal::enable_raw_mode()?;
    stdout.execute(EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_tui_main_loop(&mut terminal, &mut app);

    // Restore terminal
    terminal::disable_raw_mode()?;
    terminal.backend_mut().execute(LeaveAlternateScreen)?;

    result
}

fn is_quit_key(key: &event::KeyEvent) -> bool {
    match key.code {
        KeyCode::Char('q') => true,
        KeyCode::Char('c') | KeyCode::Char('d')
            if key.modifiers.contains(event::KeyModifiers::CONTROL) =>
        {
            true
        }
        _ => false,
    }
}

fn run_tui_main_loop(
    terminal: &mut Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    loop {
        match app.phase {
            TuiPhase::Scanning => {
                // Drain messages from the scan channel
                if let Some(ref mut scan) = app.scan {
                    while let Ok((idx, msg)) = scan.rx.try_recv() {
                        match msg {
                            ScanMessage::Stage(desc) => {
                                scan.stages[idx] = desc;
                            }
                            ScanMessage::Done(result) => {
                                scan.completed[idx] = Some(result);
                            }
                        }
                    }
                }

                terminal.draw(|frame| draw_scanning(frame, app))?;

                // Check if all crates finished
                if let Some(ref scan) = app.scan {
                    if scan.completed.iter().all(|c| c.is_some()) {
                        let scan = app.scan.take().unwrap();
                        app.elapsed = scan.start.elapsed();
                        app.results = scan.completed.into_iter().flatten().collect();
                        app.results
                            .sort_by(|a, b| a.crate_name.cmp(&b.crate_name));
                        app.all_unused = app
                            .results
                            .iter()
                            .flat_map(|r| r.unused.clone())
                            .collect();
                        app.phase = TuiPhase::Summary;
                        continue;
                    }
                }

                if event::poll(Duration::from_millis(100))? {
                    if let Event::Key(key) = event::read()? {
                        if key.kind != KeyEventKind::Press {
                            continue;
                        }
                        if is_quit_key(&key) {
                            return Ok(());
                        }
                        match key.code {
                            KeyCode::PageDown => {
                                app.detail_scroll = app.detail_scroll.saturating_add(1);
                            }
                            KeyCode::PageUp => {
                                app.detail_scroll = app.detail_scroll.saturating_sub(1);
                            }
                            KeyCode::Char('p') => {
                                cycle_palette();
                            }
                            _ => {}
                        }
                    }
                }
            }
            TuiPhase::Summary => {
                terminal.draw(|frame| draw_summary(frame, app))?;

                if event::poll(Duration::from_millis(100))? {
                    if let Event::Key(key) = event::read()? {
                        if key.kind != KeyEventKind::Press {
                            continue;
                        }
                        if is_quit_key(&key) {
                            return Ok(());
                        }
                        let menu = summary_menu_items(app);
                        match key.code {
                            KeyCode::Tab => {
                                app.summary_view = match app.summary_view {
                                    SummaryView::Table => SummaryView::Detail,
                                    SummaryView::Detail => SummaryView::Skipped,
                                    SummaryView::Skipped => SummaryView::Table,
                                };
                                app.detail_scroll = 0;
                            }
                            KeyCode::Char('j') => {
                                match app.summary_view {
                                    SummaryView::Detail => {
                                        let max = app.results.iter().filter(|r| !r.unused.is_empty()).count();
                                        if app.detail_cursor < max.saturating_sub(1) {
                                            app.detail_cursor += 1;
                                            app.detail_scroll = 0;
                                        }
                                    }
                                    SummaryView::Skipped => {
                                        let max = app.results.iter().filter(|r| !r.skipped.is_empty()).count();
                                        if app.skipped_cursor < max.saturating_sub(1) {
                                            app.skipped_cursor += 1;
                                            app.detail_scroll = 0;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            KeyCode::Char('k') => {
                                match app.summary_view {
                                    SummaryView::Detail => {
                                        if app.detail_cursor > 0 {
                                            app.detail_cursor -= 1;
                                            app.detail_scroll = 0;
                                        }
                                    }
                                    SummaryView::Skipped => {
                                        if app.skipped_cursor > 0 {
                                            app.skipped_cursor -= 1;
                                            app.detail_scroll = 0;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            KeyCode::Char(' ') => {
                                match app.summary_view {
                                    SummaryView::Detail => {
                                        let crate_name: Option<String> = app.results.iter()
                                            .filter(|r| !r.unused.is_empty())
                                            .nth(app.detail_cursor)
                                            .map(|r| r.crate_name.clone());
                                        if let Some(name) = crate_name {
                                            if !app.detail_expanded.remove(&name) {
                                                app.detail_expanded.insert(name);
                                            }
                                        }
                                    }
                                    SummaryView::Skipped => {
                                        let crate_name: Option<String> = app.results.iter()
                                            .filter(|r| !r.skipped.is_empty())
                                            .nth(app.skipped_cursor)
                                            .map(|r| r.crate_name.clone());
                                        if let Some(name) = crate_name {
                                            if !app.skipped_expanded.remove(&name) {
                                                app.skipped_expanded.insert(name);
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            KeyCode::Up => {
                                if app.summary_selected > 0 {
                                    app.summary_selected -= 1;
                                }
                            }
                            KeyCode::Down => {
                                if app.summary_selected < menu.len().saturating_sub(1) {
                                    app.summary_selected += 1;
                                }
                            }
                            KeyCode::PageDown => {
                                app.detail_scroll = app.detail_scroll.saturating_add(1);
                            }
                            KeyCode::PageUp => {
                                app.detail_scroll = app.detail_scroll.saturating_sub(1);
                            }
                            KeyCode::Enter => {
                                if let Some((action, _)) = menu.get(app.summary_selected) {
                                    handle_summary_action(*action, app)?;
                                }
                            }
                            // Hotkeys
                            KeyCode::Char('r') => {
                                if menu.iter().any(|(a, _)| *a == SummaryAction::ReviewUnused) {
                                    handle_summary_action(SummaryAction::ReviewUnused, app)?;
                                }
                            }
                            KeyCode::Char('i') => {
                                if menu.iter().any(|(a, _)| *a == SummaryAction::ReviewCrateInternal) {
                                    handle_summary_action(SummaryAction::ReviewCrateInternal, app)?;
                                }
                            }
                            KeyCode::Char('u') => {
                                if menu.iter().any(|(a, _)| *a == SummaryAction::FixAllUnused) {
                                    handle_summary_action(SummaryAction::FixAllUnused, app)?;
                                }
                            }
                            KeyCode::Char('c') => {
                                if menu.iter().any(|(a, _)| *a == SummaryAction::FixAllCrateInternal) {
                                    handle_summary_action(SummaryAction::FixAllCrateInternal, app)?;
                                }
                            }
                            KeyCode::Char('p') => {
                                cycle_palette();
                            }
                            _ => {}
                        }
                    }
                }
            }
            TuiPhase::Review => {
                if let Some(ref mut review) = app.review {
                    // Drain git prefetch
                    while let Ok((idx, state)) = review.git_rx.try_recv() {
                        if idx == review.current {
                            if let GitLoadState::Done(ref info) = state {
                                if let Some(ref entry) = info.log_entry {
                                    let symbol = &review.items[review.current].symbol.name;
                                    review.scroll_offset = entry
                                        .patch
                                        .lines()
                                        .position(|l| {
                                            (l.starts_with('+') || l.starts_with('-'))
                                                && l.contains(symbol.as_str())
                                        })
                                        .unwrap_or(0)
                                        as u16;
                                    if entry.definition_only {
                                        review.selected_action = 0;
                                    }
                                }
                            }
                        }
                        review.git_states[idx] = state;
                    }

                    terminal.draw(|frame| draw_review(frame, review))?;

                    if event::poll(Duration::from_millis(100))? {
                        if let Event::Key(key) = event::read()? {
                            if key.kind != KeyEventKind::Press {
                                continue;
                            }
                            if is_quit_key(&key) {
                                // Apply any actions taken so far, then exit
                                finish_review(app)?;
                                return Ok(());
                            }
                            match key.code {
                                KeyCode::Up => {
                                    if review.selected_action > 0 {
                                        review.selected_action -= 1;
                                    }
                                }
                                KeyCode::Down => {
                                    if review.selected_action < 2 {
                                        review.selected_action += 1;
                                    }
                                }
                                KeyCode::PageDown => {
                                    review.scroll_offset =
                                        review.scroll_offset.saturating_add(1);
                                }
                                KeyCode::PageUp => {
                                    review.scroll_offset =
                                        review.scroll_offset.saturating_sub(1);
                                }
                                KeyCode::Enter
                                | KeyCode::Char('f')
                                | KeyCode::Char('a')
                                | KeyCode::Char('s') => {
                                    let action = match key.code {
                                        KeyCode::Char('f') => ReviewAction::Fix,
                                        KeyCode::Char('a') => ReviewAction::Allowlist,
                                        KeyCode::Char('s') => ReviewAction::Skip,
                                        _ => match review.selected_action {
                                            0 => ReviewAction::Fix,
                                            1 => ReviewAction::Allowlist,
                                            _ => ReviewAction::Skip,
                                        },
                                    };
                                    review.actions[review.current] = Some(action);
                                    review.current += 1;
                                    review.selected_action = 2;
                                    review.scroll_offset = 0;
                                    if review.current >= review.items.len() {
                                        finish_review(app)?;
                                    }
                                }
                                KeyCode::Esc => {
                                    // Back to summary (apply actions taken so far)
                                    finish_review(app)?;
                                }
                                KeyCode::Char('p') => {
                                    cycle_palette();
                                }
                                _ => {}
                            }
                        }
                    }
                } else {
                    app.phase = TuiPhase::Summary;
                }
            }
        }
    }
}

fn handle_summary_action(action: SummaryAction, app: &mut App) -> Result<()> {
    match action {
        SummaryAction::ReviewUnused => {
            let items: Vec<UnusedSymbol> = app
                .all_unused
                .iter()
                .filter(|u| u.kind == SymbolKind::UnusedAnywhere)
                .cloned()
                .collect();
            start_review(app, items);
        }
        SummaryAction::ReviewCrateInternal => {
            let items: Vec<UnusedSymbol> = app
                .all_unused
                .iter()
                .filter(|u| matches!(u.kind, SymbolKind::CrateInternalOnly { .. }))
                .cloned()
                .collect();
            start_review(app, items);
        }
        SummaryAction::FixAllUnused => {
            let to_fix: Vec<UnusedSymbol> = app
                .all_unused
                .iter()
                .filter(|u| u.kind == SymbolKind::UnusedAnywhere)
                .cloned()
                .collect();
            for item in &to_fix {
                let _ = apply_fix_unused(item);
            }
            // Remove fixed items from all_unused
            app.all_unused
                .retain(|u| u.kind != SymbolKind::UnusedAnywhere);
            // Update results
            for r in &mut app.results {
                r.unused.retain(|u| u.kind != SymbolKind::UnusedAnywhere);
            }
        }
        SummaryAction::FixAllCrateInternal => {
            let to_fix: Vec<UnusedSymbol> = app
                .all_unused
                .iter()
                .filter(|u| matches!(u.kind, SymbolKind::CrateInternalOnly { .. }))
                .cloned()
                .collect();
            for item in &to_fix {
                let _ = apply_fix_crate_internal(item);
            }
            app.all_unused
                .retain(|u| !matches!(u.kind, SymbolKind::CrateInternalOnly { .. }));
            for r in &mut app.results {
                r.unused
                    .retain(|u| !matches!(u.kind, SymbolKind::CrateInternalOnly { .. }));
            }
        }
        SummaryAction::Quit => {
            // Signal exit — caller checks this won't happen since we handle 'q' separately
        }
    }
    Ok(())
}

fn start_review(app: &mut App, items: Vec<UnusedSymbol>) {
    if items.is_empty() {
        return;
    }
    let (tx, rx) = mpsc::channel();
    let prefetch_items: Vec<(usize, String, PathBuf, usize)> = items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            (
                i,
                item.symbol.name.clone(),
                item.symbol.file.clone(),
                item.symbol.line,
            )
        })
        .collect();
    let prefetch_root = app.workspace_root.clone();
    let _handle = spawn_prefetcher(prefetch_items, prefetch_root, tx);

    let count = items.len();
    app.review = Some(ReviewApp {
        items,
        workspace_root: app.workspace_root.clone(),
        current: 0,
        git_states: vec![GitLoadState::Pending; count],
        git_rx: rx,
        selected_action: 2,
        actions: vec![None; count],
        scroll_offset: 0,
    });
    app.phase = TuiPhase::Review;
}

fn finish_review(app: &mut App) -> Result<()> {
    if let Some(review) = app.review.take() {
        for (item, action) in review.items.iter().zip(review.actions.iter()) {
            let action = match action {
                Some(a) => a,
                None => continue,
            };
            match action {
                ReviewAction::Fix => match item.kind {
                    SymbolKind::CrateInternalOnly { .. } => {
                        apply_fix_crate_internal(item)?;
                    }
                    SymbolKind::UnusedAnywhere => {
                        let _ = apply_fix_unused(item)?;
                    }
                },
                ReviewAction::Allowlist => {
                    add_to_allowlist(
                        &app.conn,
                        &item.symbol.name,
                        &item.crate_name,
                        &item.symbol.file.to_string_lossy(),
                        None,
                    )?;
                }
                ReviewAction::Skip => {}
            }
            // Remove acted-upon items from all_unused
            let name = &item.symbol.name;
            let crate_name = &item.crate_name;
            if !matches!(action, ReviewAction::Skip) {
                app.all_unused
                    .retain(|u| !(u.symbol.name == *name && u.crate_name == *crate_name));
                for r in &mut app.results {
                    r.unused
                        .retain(|u| !(u.symbol.name == *name && u.crate_name == *crate_name));
                }
            }
        }
    }
    app.phase = TuiPhase::Summary;
    app.summary_selected = 0;
    Ok(())
}

/// Build status lines showing active config (filters, ignored paths, disabled filters).
/// Shown at the top of scanning/summary views so the TUI is self-documenting.
fn config_status_lines(dim: Style) -> Vec<Line<'static>> {
    let mut lines = vec![];

    let filters = active_filter_names();
    let disabled = disabled_filter_names();
    let enabled = enabled_filter_names();
    let ignored = ignored_paths();

    // Only show config block if there's something non-default to report
    let has_disabled = !disabled.is_empty();
    let has_enabled = !enabled.is_empty();
    let has_ignored = !ignored.is_empty();

    if has_disabled || has_enabled || has_ignored {
        let mut spans: Vec<Span> = vec![
            Span::styled("  config ", Style::default().fg(theme().on_surface_variant).add_modifier(Modifier::BOLD)),
        ];

        // Active filters
        spans.push(Span::styled("filters: ", dim));
        if filters.is_empty() {
            spans.push(Span::styled("none", Style::default().fg(theme().error)));
        } else {
            spans.push(Span::styled(
                filters.join(", "),
                Style::default().fg(theme().success),
            ));
        }

        // Disabled filters (only show if any)
        if has_disabled {
            spans.push(Span::styled("  disabled: ", dim));
            spans.push(Span::styled(
                disabled.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
                Style::default().fg(theme().error),
            ));
        }

        // Enabled opt-in filters (only show if any)
        if has_enabled {
            spans.push(Span::styled("  opt-in: ", dim));
            spans.push(Span::styled(
                enabled.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
                Style::default().fg(theme().info),
            ));
        }

        // Ignored paths (only show if any)
        if has_ignored {
            spans.push(Span::styled("  ignoring: ", dim));
            spans.push(Span::styled(
                ignored.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
                Style::default().fg(theme().tertiary),
            ));
        }

        lines.push(Line::from(spans));
        lines.push(Line::raw(""));
    }

    lines
}

fn draw_scanning(frame: &mut ratatui::Frame, app: &App) {
    let dim = Style::default().fg(theme().dim);
    let scan = app.scan.as_ref().unwrap();

    let done_count = scan.completed.iter().filter(|c| c.is_some()).count();
    let total = scan.crate_names.len();
    let elapsed = scan.start.elapsed();

    let max_name_len = scan
        .crate_names
        .iter()
        .map(|n| n.len())
        .max()
        .unwrap_or(10);

    let title = format!(
        " 🔍 find-unused-pub — scanning ({}/{} crates, {:.1}s) [{}] ",
        done_count,
        total,
        elapsed.as_secs_f64(),
        theme().name,
    );

    let mut lines: Vec<Line> = vec![];
    lines.extend(config_status_lines(dim));

    for (idx, name) in scan.crate_names.iter().enumerate() {
        let name_padded = format!("{:<width$}", name, width = max_name_len);
        if let Some(ref result) = scan.completed[idx] {
            let n_unused = result
                .unused
                .iter()
                .filter(|u| u.kind == SymbolKind::UnusedAnywhere)
                .count();
            let n_internal = result
                .unused
                .iter()
                .filter(|u| matches!(u.kind, SymbolKind::CrateInternalOnly { .. }))
                .count();

            let mut spans = vec![
                Span::styled("  ✅ ", Style::default().fg(theme().success)),
                Span::styled(name_padded, Style::default().fg(theme().secondary)),
                Span::raw("  "),
                Span::styled(format!("{:>3} found", result.items_found), dim),
            ];

            if n_unused > 0 {
                spans.push(Span::raw("  "));
                spans.push(Span::styled(
                    format!("❗ {n_unused} unused"),
                    Style::default().fg(theme().error),
                ));
            }
            if n_internal > 0 {
                spans.push(Span::raw("  "));
                spans.push(Span::styled(
                    format!("🔧 {n_internal} internal"),
                    Style::default().fg(theme().warning),
                ));
            }
            if n_unused == 0 && n_internal == 0 {
                spans.push(Span::raw("  "));
                spans.push(Span::styled("✨ clean", Style::default().fg(theme().success)));
            }

            lines.push(Line::from(spans));
        } else {
            let stage = &scan.stages[idx];
            let stage_span = if stage.is_empty() {
                Span::styled("waiting…", dim)
            } else {
                Span::styled(stage.as_str(), Style::default().fg(theme().tertiary))
            };
            lines.push(Line::from(vec![
                Span::styled("  ⏳ ", Style::default().fg(theme().tertiary)),
                Span::styled(name_padded, Style::default().fg(theme().on_surface_variant)),
                Span::raw("  "),
                stage_span,
            ]));
        }
    }

    let rows = Layout::vertical([
        Constraint::Min(5),    // content
        Constraint::Length(3), // actions bar
    ])
    .split(frame.area());

    let widget = Paragraph::new(Text::from(lines))
        .scroll((app.detail_scroll, 0))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme().outline))
                .title(title)
                .title_style(Style::default().fg(theme().primary).add_modifier(Modifier::BOLD)),
        );
    frame.render_widget(widget, rows[0]);

    let bar = Paragraph::new(Line::from(vec![
        Span::styled(" p", Style::default().fg(theme().tertiary).add_modifier(Modifier::BOLD)),
        Span::styled(": palette  ", dim),
        Span::styled("PgUp/PgDn", Style::default().fg(theme().tertiary).add_modifier(Modifier::BOLD)),
        Span::styled(": scroll  ", dim),
        Span::styled("q", Style::default().fg(theme().tertiary).add_modifier(Modifier::BOLD)),
        Span::styled(": quit", dim),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme().outline))
            .title_bottom(palette_swatch()),
    );
    frame.render_widget(bar, rows[1]);
}

fn draw_summary(frame: &mut ratatui::Frame, app: &App) {
    let dim = Style::default().fg(theme().dim);

    // Layout: content area + menu at bottom
    let rows = Layout::vertical([
        Constraint::Min(10),   // content
        Constraint::Length(8), // menu
    ])
    .split(frame.area());

    let view_label = match app.summary_view {
        SummaryView::Table => "📊 summary",
        SummaryView::Detail => "📋 detail",
        SummaryView::Skipped => "🛡️ skipped",
    };
    let title = format!(
        " 📦 find-unused-pub — {} crates in {:.1}s ({}) [{}] ",
        app.results.len(),
        app.elapsed.as_secs_f64(),
        view_label,
        theme().name,
    );

    match app.summary_view {
        SummaryView::Table => draw_summary_table(frame, app, rows[0], &title, dim),
        SummaryView::Detail => draw_summary_detail(frame, app, rows[0], &title, dim),
        SummaryView::Skipped => draw_summary_skipped(frame, app, rows[0], &title, dim),
    }

    // -- Menu (shared by all views) --
    let menu = summary_menu_items(app);
    let menu_items: Vec<ListItem> = menu
        .iter()
        .enumerate()
        .map(|(i, (action, label))| {
            let style = if i == app.summary_selected {
                Style::default()
                    .fg(theme().surface)
                    .bg(theme().primary)
                    .add_modifier(Modifier::BOLD)
            } else {
                match action {
                    SummaryAction::ReviewUnused => Style::default().fg(theme().success),
                    SummaryAction::ReviewCrateInternal => Style::default().fg(theme().secondary),
                    SummaryAction::FixAllUnused => Style::default().fg(theme().error),
                    SummaryAction::FixAllCrateInternal => Style::default().fg(theme().success),
                    SummaryAction::Quit => Style::default().fg(theme().on_surface),
                }
            };
            ListItem::new(label.as_str()).style(style)
        })
        .collect();
    let mut list_state = ListState::default().with_selected(Some(app.summary_selected));
    let menu_widget = List::new(menu_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme().outline))
                .title(" ⚡ Actions (↑↓+Enter or hotkey, Tab: swap view, PgUp/PgDn: scroll, p: palette, q: quit) ")
                .title_style(Style::default().fg(theme().tertiary))
                .title_bottom(palette_swatch()),
        )
        .highlight_symbol("▸ ");
    frame.render_stateful_widget(menu_widget, rows[1], &mut list_state);
}

fn draw_summary_table(
    frame: &mut ratatui::Frame,
    app: &App,
    area: ratatui::layout::Rect,
    title: &str,
    dim: Style,
) {
    let max_name_len = app
        .results
        .iter()
        .map(|r| r.crate_name.len())
        .max()
        .unwrap_or(10);

    let mut table_lines: Vec<Line> = vec![];
    table_lines.extend(config_status_lines(dim));

    for result in &app.results {
        let n_unused = result
            .unused
            .iter()
            .filter(|u| u.kind == SymbolKind::UnusedAnywhere)
            .count();
        let n_internal = result
            .unused
            .iter()
            .filter(|u| matches!(u.kind, SymbolKind::CrateInternalOnly { .. }))
            .count();

        let name_padded = format!("{:<width$}", result.crate_name, width = max_name_len);
        let found_str = format!("{:>3} found", result.items_found);

        let mut spans = vec![
            Span::styled(name_padded, Style::default().fg(theme().secondary)),
            Span::raw("  "),
            Span::styled(found_str, dim),
        ];

        if n_unused > 0 {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(
                format!("❗ {n_unused} unused"),
                Style::default().fg(theme().error),
            ));
        }
        if n_internal > 0 {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(
                format!("🔧 {n_internal} internal"),
                Style::default().fg(theme().warning),
            ));
        }
        if n_unused == 0 && n_internal == 0 {
            spans.push(Span::raw("  "));
            spans.push(Span::styled("✨ clean", Style::default().fg(theme().success)));
        }

        table_lines.push(Line::from(spans));
    }

    // Totals
    let total_unused: usize = app
        .all_unused
        .iter()
        .filter(|u| u.kind == SymbolKind::UnusedAnywhere)
        .count();
    let total_internal: usize = app
        .all_unused
        .iter()
        .filter(|u| matches!(u.kind, SymbolKind::CrateInternalOnly { .. }))
        .count();
    let total_found: usize = app.results.iter().map(|r| r.items_found).sum();
    table_lines.push(Line::raw(""));
    let mut total_spans = vec![
        Span::styled(
            format!("{:<width$}", "TOTAL", width = max_name_len),
            Style::default().fg(theme().on_surface).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(format!("{:>3} found", total_found), dim),
    ];
    if total_unused > 0 {
        total_spans.push(Span::raw("  "));
        total_spans.push(Span::styled(
            format!("❗ {total_unused} unused"),
            Style::default().fg(theme().error).add_modifier(Modifier::BOLD),
        ));
    }
    if total_internal > 0 {
        total_spans.push(Span::raw("  "));
        total_spans.push(Span::styled(
            format!("🔧 {total_internal} internal"),
            Style::default()
                .fg(theme().warning)
                .add_modifier(Modifier::BOLD),
        ));
    }
    if total_unused == 0 && total_internal == 0 {
        total_spans.push(Span::raw("  "));
        total_spans.push(Span::styled(
            "✨ all clean!",
            Style::default()
                .fg(theme().success)
                .add_modifier(Modifier::BOLD),
        ));
    }
    table_lines.push(Line::from(total_spans));

    let table_widget = Paragraph::new(Text::from(table_lines))
        .scroll((app.detail_scroll, 0))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme().outline))
                .title(title.to_string())
                .title_style(Style::default().fg(theme().primary).add_modifier(Modifier::BOLD)),
        );
    frame.render_widget(table_widget, area);
}

fn draw_summary_detail(
    frame: &mut ratatui::Frame,
    app: &App,
    area: ratatui::layout::Rect,
    title: &str,
    dim: Style,
) {
    let total_unused: usize = app.all_unused.len();
    let mut lines: Vec<Line> = vec![];

    lines.push(Line::from(vec![
        Span::styled(
            format!("📋 {total_unused} issues"),
            Style::default().fg(theme().on_surface).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled("j/k: navigate crates, PgUp/PgDn: scroll, Space: expand/collapse", dim),
    ]));
    lines.push(Line::raw(""));

    let mut crate_idx = 0usize;
    for result in &app.results {
        if result.unused.is_empty() {
            continue;
        }

        let is_focused = crate_idx == app.detail_cursor;
        let is_expanded = app.detail_expanded.contains(&result.crate_name);
        let arrow = if is_expanded { "▼" } else { "▶" };
        let cursor_indicator = if is_focused { "▸ " } else { "  " };

        let n_unused = result.unused.iter().filter(|u| u.kind == SymbolKind::UnusedAnywhere).count();
        let n_internal = result.unused.iter().filter(|u| matches!(u.kind, SymbolKind::CrateInternalOnly { .. })).count();

        let name_style = if is_focused {
            Style::default()
                .fg(theme().secondary)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            Style::default()
                .fg(theme().secondary)
                .add_modifier(Modifier::BOLD)
        };

        let mut header_spans = vec![
            Span::styled(cursor_indicator, Style::default().fg(theme().primary)),
            Span::styled(format!("{arrow} "), Style::default().fg(theme().dim_accent)),
            Span::styled(&result.crate_name, name_style),
            Span::raw(" "),
            Span::styled(
                format!("({}/{})", result.unused.len(), result.items_found),
                dim,
            ),
        ];
        if n_unused > 0 {
            header_spans.push(Span::raw("  "));
            header_spans.push(Span::styled(
                format!("❗ {n_unused}"),
                Style::default().fg(theme().error),
            ));
        }
        if n_internal > 0 {
            header_spans.push(Span::raw("  "));
            header_spans.push(Span::styled(
                format!("🔧 {n_internal}"),
                Style::default().fg(theme().warning),
            ));
        }
        lines.push(Line::from(header_spans));

        if is_expanded {
            for item in &result.unused {
                match item.kind {
                    SymbolKind::UnusedAnywhere => {
                        lines.push(Line::from(vec![
                            Span::raw("      "),
                            Span::styled(
                                format!("❗ {}", item.symbol.name),
                                Style::default().fg(theme().error),
                            ),
                            Span::raw(" "),
                            Span::styled("unused everywhere", dim),
                        ]));
                    }
                    SymbolKind::CrateInternalOnly { refs } => {
                        lines.push(Line::from(vec![
                            Span::raw("      "),
                            Span::styled(
                                format!("🔧 {}", item.symbol.name),
                                Style::default().fg(theme().warning),
                            ),
                            Span::raw(" "),
                            Span::styled(
                                format!("crate-internal only ({refs} refs)"),
                                dim,
                            ),
                        ]));
                    }
                }
                let rel_path = item
                    .symbol
                    .file
                    .strip_prefix(&app.workspace_root)
                    .unwrap_or(&item.symbol.file);
                lines.push(Line::from(Span::styled(
                    format!("        {}:{}", rel_path.display(), item.symbol.line),
                    Style::default().fg(theme().on_surface_variant),
                )));
                for (ref_file, ref_line) in &item.internal_refs {
                    let rel = ref_file
                        .strip_prefix(&app.workspace_root)
                        .unwrap_or(ref_file);
                    lines.push(Line::from(Span::styled(
                        format!("          ↳ {}:{}", rel.display(), ref_line),
                        Style::default().fg(theme().dim_accent),
                    )));
                }
            }
        }

        crate_idx += 1;
    }

    if total_unused == 0 {
        lines.push(Line::from(Span::styled("No issues found.", dim)));
    }

    let detail_widget = Paragraph::new(Text::from(lines))
        .scroll((app.detail_scroll, 0))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme().outline))
                .title(title.to_string())
                .title_style(Style::default().fg(theme().primary).add_modifier(Modifier::BOLD)),
        );
    frame.render_widget(detail_widget, area);
}

fn draw_summary_skipped(
    frame: &mut ratatui::Frame,
    app: &App,
    area: ratatui::layout::Rect,
    title: &str,
    dim: Style,
) {
    let mut lines: Vec<Line> = vec![];

    let total_skipped: usize = app.results.iter().map(|r| r.skipped.len()).sum();
    lines.push(Line::from(vec![
        Span::styled(
            format!("🛡️  {total_skipped} symbols skipped"),
            Style::default().fg(theme().on_surface).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(format!("({})", active_filter_names().join(", ")), dim),
    ]));
    lines.push(Line::from(Span::styled(
        "j/k: navigate crates, PgUp/PgDn: scroll, Space: expand/collapse",
        dim,
    )));
    lines.push(Line::raw(""));

    let mut crate_idx = 0usize;
    for result in &app.results {
        if result.skipped.is_empty() {
            continue;
        }

        let is_focused = crate_idx == app.skipped_cursor;
        let is_expanded = app.skipped_expanded.contains(&result.crate_name);
        let arrow = if is_expanded { "▼" } else { "▶" };
        let cursor_indicator = if is_focused { "▸ " } else { "  " };

        let name_style = if is_focused {
            Style::default()
                .fg(theme().secondary)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            Style::default()
                .fg(theme().secondary)
                .add_modifier(Modifier::BOLD)
        };

        lines.push(Line::from(vec![
            Span::styled(cursor_indicator, Style::default().fg(theme().primary)),
            Span::styled(format!("{arrow} "), Style::default().fg(theme().dim_accent)),
            Span::styled(&result.crate_name, name_style),
            Span::raw(" "),
            Span::styled(
                format!("({} skipped)", result.skipped.len()),
                dim,
            ),
        ]));

        if is_expanded {
            for (sym, reason) in &result.skipped {
                let rel = sym
                    .file
                    .strip_prefix(&app.workspace_root)
                    .unwrap_or(&sym.file);
                lines.push(Line::from(vec![
                    Span::raw("      "),
                    Span::styled(&sym.name, Style::default().fg(theme().on_surface_variant)),
                    Span::styled(reason.label(), Style::default().fg(reason.label_color())),
                    Span::raw("  "),
                    Span::styled(
                        format!("{}:{}", rel.display(), sym.line),
                        Style::default().fg(theme().dim),
                    ),
                ]));
            }
        }

        crate_idx += 1;
    }

    if total_skipped == 0 {
        lines.push(Line::from(Span::styled("No symbols were skipped.", dim)));
    }

    let widget = Paragraph::new(Text::from(lines))
        .scroll((app.detail_scroll, 0))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme().outline))
                .title(title.to_string())
                .title_style(Style::default().fg(theme().primary).add_modifier(Modifier::BOLD)),
        );
    frame.render_widget(widget, area);
}

fn draw_review(frame: &mut ratatui::Frame, app: &ReviewApp) {
    let item = &app.items[app.current];
    let total = app.items.len();

    let rel_path = item
        .symbol
        .file
        .strip_prefix(&app.workspace_root)
        .unwrap_or(&item.symbol.file);
    let dim = Style::default().fg(theme().dim);
    let label_style = Style::default().fg(theme().tertiary);

    let is_definition_only = matches!(
        &app.git_states[app.current],
        GitLoadState::Done(info) if info.log_entry.as_ref().is_some_and(|e| e.definition_only)
    );

    // Top-level: main content area + action bar at bottom
    let rows = Layout::vertical([
        Constraint::Min(8),     // main content
        Constraint::Length(5),  // actions
    ])
    .split(frame.area());

    // Main content: left info column | right patch column
    let cols = Layout::horizontal([
        Constraint::Percentage(40), // info side
        Constraint::Percentage(60), // patch side
    ])
    .split(rows[0]);

    // Left column: symbol info + git context stacked
    let left_rows = Layout::vertical([
        Constraint::Length(4),  // symbol info
        Constraint::Min(4),    // git context
    ])
    .split(cols[0]);

    // -- Symbol info (top-left) --
    let kind_label = match item.kind {
        SymbolKind::UnusedAnywhere => Span::styled("❗ unused everywhere", Style::default().fg(theme().error)),
        SymbolKind::CrateInternalOnly { refs } => Span::styled(
            format!("🔧 crate-internal only ({refs} refs)"),
            Style::default().fg(theme().warning),
        ),
    };
    let symbol_text = Text::from(vec![
        Line::from(vec![
            Span::styled(
                &item.symbol.name,
                Style::default().fg(theme().on_surface).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            kind_label,
        ]),
        Line::from(Span::styled(
            format!("{}:{}", rel_path.display(), item.symbol.line),
            Style::default().fg(theme().on_surface_variant),
        )),
    ]);
    let review_title = if is_definition_only {
        format!(" 🧹 Review ({}/{}) — ✅ SAFE DELETE ", app.current + 1, total)
    } else {
        format!(" 🔍 Review ({}/{}) ", app.current + 1, total)
    };
    let symbol_border_style = if is_definition_only {
        Style::default().fg(theme().success)
    } else {
        Style::default().fg(theme().outline)
    };
    let symbol_block = Paragraph::new(symbol_text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(symbol_border_style)
            .title(review_title)
            .title_style(Style::default().fg(theme().primary).add_modifier(Modifier::BOLD)),
    );
    frame.render_widget(symbol_block, left_rows[0]);

    // -- Git context (bottom-left) --
    let git_text = match &app.git_states[app.current] {
        GitLoadState::Pending => {
            Text::from(Span::styled("⏳ waiting...", dim))
        }
        GitLoadState::RunningBlame => {
            Text::from(Span::styled(
                format!("⏳ $ git blame -L{0},{0} --porcelain {1}", item.symbol.line, rel_path.display()),
                dim,
            ))
        }
        GitLoadState::RunningLogS => {
            Text::from(Span::styled(
                format!("⏳ $ git log -1 -S '{}' --patch -- '**/*.rs'", item.symbol.name),
                dim,
            ))
        }
        GitLoadState::Done(info) => {
            let mut lines = vec![];

            if let Some(blame) = &info.blame {
                lines.push(Line::from(vec![
                    Span::styled("📝 Line last modified ", label_style),
                    Span::styled(&blame.age, Style::default().fg(theme().accent)),
                ]));
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  ({}) by {}", blame.date, blame.author),
                        dim,
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(&blame.short_hash, Style::default().fg(theme().secondary)),
                    Span::raw(" "),
                    Span::styled(&blame.summary, Style::default().fg(theme().on_surface)),
                ]));
                lines.push(Line::from(Span::styled(
                    format!("  $ git show {}", blame.short_hash),
                    dim,
                )));
            }

            if let Some(entry) = &info.log_entry {
                if !lines.is_empty() {
                    lines.push(Line::raw(""));
                }
                lines.push(Line::from(vec![
                    Span::styled("🔎 Symbol last added/removed ", label_style),
                    Span::styled(&entry.age, Style::default().fg(theme().accent)),
                ]));
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  ({}) by {}", entry.date, entry.author),
                        dim,
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(&entry.short_hash, Style::default().fg(theme().secondary)),
                    Span::raw(" "),
                    Span::styled(&entry.subject, Style::default().fg(theme().on_surface)),
                ]));
                lines.push(Line::from(Span::styled(
                    format!("  $ git show {}", entry.short_hash),
                    dim,
                )));
                lines.push(Line::from(Span::styled(
                    format!("  $ git log -S '{}' -- '**/*.rs'", item.symbol.name),
                    dim,
                )));
            }

            if lines.is_empty() {
                lines.push(Line::from(Span::styled("no git history found", dim)));
            }
            Text::from(lines)
        }
    };
    let git_block = Paragraph::new(git_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme().outline))
                .title(" 🕰️  Git context ")
                .title_style(Style::default().fg(theme().tertiary)),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(git_block, left_rows[1]);

    // -- Patch diff (right column, full height) --
    let mut patch_lines: Vec<Line> = vec![];
    let mut patch_title = String::from(" Patch ");
    if let GitLoadState::Done(info) = &app.git_states[app.current] {
        if let Some(entry) = &info.log_entry {
            patch_title = format!(" 📄 $ git show {} ", entry.short_hash);
            // Show grep-like matches first
            if !entry.diff_matches.is_empty() {
                patch_lines.push(Line::from(Span::styled(
                    format!("All occurrences in diff ({}):", entry.diff_matches.len()),
                    label_style,
                )));
                for m in &entry.diff_matches {
                    let style = if m.starts_with('+') {
                        Style::default().fg(theme().success)
                    } else {
                        Style::default().fg(theme().error)
                    };
                    patch_lines.push(Line::from(Span::styled(m.as_str(), style)));
                }
                patch_lines.push(Line::raw(""));
            }
            for patch_line in entry.patch.lines().skip(app.scroll_offset as usize) {
                let style = if patch_line.starts_with('+') && !patch_line.starts_with("+++") {
                    Style::default().fg(theme().success)
                } else if patch_line.starts_with('-') && !patch_line.starts_with("---") {
                    Style::default().fg(theme().error)
                } else if patch_line.starts_with("@@") {
                    Style::default().fg(theme().info)
                } else {
                    Style::default().fg(theme().dim)
                };
                patch_lines.push(Line::from(Span::styled(patch_line, style)));
            }
        }
    }
    if patch_lines.is_empty() {
        match &app.git_states[app.current] {
            GitLoadState::Pending | GitLoadState::RunningBlame | GitLoadState::RunningLogS => {
                patch_lines.push(Line::from(Span::styled("⏳ loading...", dim)));
            }
            GitLoadState::Done(_) => {
                patch_lines.push(Line::from(Span::styled("no patch available", dim)));
            }
        }
    }
    let patch_block = Paragraph::new(Text::from(patch_lines))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme().outline))
                .title(patch_title)
                .title_style(Style::default().fg(theme().tertiary)),
        );
    frame.render_widget(patch_block, cols[1]);

    // -- Action selector (bottom, full width) --
    let fix_label = if is_definition_only {
        match item.kind {
            SymbolKind::UnusedAnywhere => "🗑️  (f) Fix (delete) ← recommended",
            SymbolKind::CrateInternalOnly { .. } => "🔧 (f) Fix (pub(crate)) ← recommended",
        }
    } else {
        match item.kind {
            SymbolKind::UnusedAnywhere => "🗑️  (f) Fix (delete item)",
            SymbolKind::CrateInternalOnly { .. } => "🔧 (f) Fix (pub(crate))",
        }
    };
    let action_labels = [fix_label, "📋 (a) Allowlist", "⏭️  (s) Skip"];
    let action_items: Vec<ListItem> = action_labels
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let style = if i == app.selected_action {
                Style::default()
                    .fg(theme().surface)
                    .bg(theme().primary)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme().on_surface)
            };
            ListItem::new(*label).style(style)
        })
        .collect();
    let mut list_state = ListState::default().with_selected(Some(app.selected_action));
    let action_list = List::new(action_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme().outline))
                .title(" ⚡ Action (f/a/s or ↑↓+Enter, PgUp/PgDn: scroll, p: palette, q: quit) ")
                .title_style(Style::default().fg(theme().tertiary))
                .title_bottom(palette_swatch()),
        )
        .highlight_symbol("▸ ");
    frame.render_stateful_widget(action_list, rows[1], &mut list_state);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    THEMES.set(build_all_themes()).expect("themes already set");
    PALETTE_IDX.store(args.palette.to_index(), Ordering::Relaxed);

    // Validate --disable-filter and --enable-filter values
    let known = all_filter_names();
    for name in args.disable_filter.iter().chain(args.enable_filter.iter()) {
        if !known.iter().any(|k| k.eq_ignore_ascii_case(name)) {
            anyhow::bail!(
                "unknown filter '{}'. Available filters: {}",
                name,
                known.join(", "),
            );
        }
    }

    // Build active filter list & store names for TUI
    let filters = active_filters(&args.disable_filter, &args.enable_filter);
    let filter_names: Vec<&'static str> = filters.iter().map(|f| f.name()).collect();
    ACTIVE_FILTER_NAMES.set(filter_names).expect("filter names already set");
    DISABLED_FILTER_NAMES
        .set(args.disable_filter.clone())
        .expect("disabled filter names already set");
    ENABLED_FILTER_NAMES
        .set(args.enable_filter.clone())
        .expect("enabled filter names already set");

    // Store ignored paths for TUI display
    let ignore_display: Vec<String> = args.ignore.iter().map(|p| p.display().to_string()).collect();
    IGNORED_PATHS.set(ignore_display).expect("ignored paths already set");

    let start = Instant::now();

    // Find workspace root (look for root Cargo.toml with [workspace])
    let workspace_root = find_workspace_root()?;
    let crates_dir = workspace_root.join("crates");

    // Handle --nuke-allowlist
    let conn = open_db(&workspace_root)?;
    if args.nuke_allowlist {
        nuke_allowlist(&conn)?;
        eprintln!("{}", "Allowlist cleared.".green());
        if args.crate_paths.is_empty()
            && !args.should_fix_crate_internal()
            && !args.fix_unused
        {
            return Ok(());
        }
    }

    let allowlist = load_allowlist(&conn)?;

    // Resolve crate paths
    let mut target_crates: Vec<PathBuf> = if args.crate_paths.is_empty() {
        let mut crates = vec![];
        for entry in fs::read_dir(&crates_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                crates.push(entry.path());
            }
        }
        crates.sort();
        crates
    } else {
        args.crate_paths
            .iter()
            .map(|p| {
                if p.is_absolute() {
                    p.clone()
                } else {
                    workspace_root.join(p)
                }
            })
            .collect()
    };

    // Apply --ignore: remove crates whose path matches any ignore entry
    if !args.ignore.is_empty() {
        let ignore_abs: Vec<PathBuf> = args
            .ignore
            .iter()
            .map(|ig| {
                if ig.is_absolute() {
                    ig.clone()
                } else {
                    workspace_root.join(ig)
                }
            })
            .collect();
        target_crates.retain(|p| !ignore_abs.iter().any(|ig| p == ig));
    }

    // Build list of all crate dirs (includes src/, tests/, benches/ for searching)
    let all_crate_dirs: Vec<PathBuf> = fs::read_dir(&crates_dir)?
        .flatten()
        .filter(|e| e.file_type().map_or(false, |t| t.is_dir()))
        .map(|e| e.path())
        .collect();

    // Wrap filters in Arc for sharing across spawn_blocking tasks
    let filters: std::sync::Arc<Vec<Box<dyn SymbolFilter>>> = std::sync::Arc::new(filters);
    let use_cache = args.resume;

    // Precompute content hashes for cache invalidation
    let crate_hashes: Vec<String> = target_crates
        .iter()
        .map(|p| crate_content_hash(p))
        .collect();

    // Non-interactive batch fix: must await all results first
    if args.should_fix_crate_internal() || args.fix_unused {
        let mut results = vec![];
        for (i, crate_path) in target_crates.iter().enumerate() {
            let crate_name = crate_path.file_name().unwrap().to_str().unwrap();
            if use_cache {
                if let Some(cached) = load_cached_result(&conn, crate_name, &crate_hashes[i]) {
                    results.push(cached);
                    continue;
                }
            }
            let cp = crate_path.clone();
            let ad = all_crate_dirs.clone();
            let wl = allowlist.clone();
            let f = filters.clone();
            let result = tokio::task::spawn_blocking(move || {
                analyze_crate(&cp, &ad, &wl, &f, &|_| {})
            }).await??;
            save_cached_result(&conn, crate_name, &crate_hashes[i], &result);
            results.push(result);
        }
        let all_unused: Vec<UnusedSymbol> = results
            .iter()
            .flat_map(|r| r.unused.clone())
            .collect();
        let mut fixed = 0;
        for item in &all_unused {
            let should_fix = match item.kind {
                SymbolKind::CrateInternalOnly { .. } => args.should_fix_crate_internal(),
                SymbolKind::UnusedAnywhere => args.fix_unused,
            };
            if should_fix {
                let label = match item.kind {
                    SymbolKind::CrateInternalOnly { .. } => {
                        apply_fix_crate_internal(item)?;
                        "-> pub(crate)"
                    }
                    SymbolKind::UnusedAnywhere => {
                        let _preview = apply_fix_unused(item)?;
                        "-> deleted"
                    }
                };
                eprintln!(
                    "  {} {} {}",
                    "fixed".green(),
                    item.symbol.name.bold(),
                    label.dimmed(),
                );
                fixed += 1;
            }
        }
        if fixed > 0 {
            eprintln!("{}", format!("Fixed {fixed} items").bold().green());
        }
        return Ok(());
    }

    // Non-interactive pipe output: when stdout is not a TTY, print plain text
    if !std::io::stdout().is_terminal() {
        let mut results = vec![];
        for (i, crate_path) in target_crates.iter().enumerate() {
            let crate_name = crate_path.file_name().unwrap().to_str().unwrap();
            if use_cache {
                if let Some(cached) = load_cached_result(&conn, crate_name, &crate_hashes[i]) {
                    results.push(cached);
                    continue;
                }
            }
            let cp = crate_path.clone();
            let ad = all_crate_dirs.clone();
            let wl = allowlist.clone();
            let f = filters.clone();
            let result = tokio::task::spawn_blocking(move || {
                analyze_crate(&cp, &ad, &wl, &f, &|_| {})
            }).await??;
            save_cached_result(&conn, crate_name, &crate_hashes[i], &result);
            results.push(result);
        }
        let elapsed = start.elapsed();

        let total_unused: usize = results.iter().map(|r| r.unused.len()).sum();
        let total_skipped: usize = results.iter().map(|r| r.skipped.len()).sum();
        let total_items: usize = results.iter().map(|r| r.items_found).sum();
        println!("find-unused-pub  ({:.1}s)  {} items scanned, {} unused, {} skipped",
            elapsed.as_secs_f64(), total_items, total_unused, total_skipped);
        println!();

        for result in &results {
            if result.unused.is_empty() && result.skipped.is_empty() {
                continue;
            }
            println!("# {}", result.crate_name);
            for item in &result.unused {
                let rel = item.symbol.file.strip_prefix(&workspace_root).unwrap_or(&item.symbol.file);
                let kind = match item.kind {
                    SymbolKind::UnusedAnywhere => "unused",
                    SymbolKind::CrateInternalOnly { refs } => {
                        // Leak a formatted string — acceptable for one-shot CLI output
                        Box::leak(format!("crate-internal ({refs} refs)").into_boxed_str())
                    }
                };
                println!("  {} {}:{} [{}]", item.symbol.name, rel.display(), item.symbol.line, kind);
            }
            for (sym, reason) in &result.skipped {
                let rel = sym.file.strip_prefix(&workspace_root).unwrap_or(&sym.file);
                println!("  {} {}:{} {}", sym.name, rel.display(), sym.line, reason.label());
            }
            println!();
        }
        return Ok(());
    }

    // Streaming TUI: start immediately, show scan progress
    let crate_names: Vec<String> = target_crates
        .iter()
        .map(|p| {
            p.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        })
        .collect();
    let n_crates = crate_names.len();
    let (scan_tx, scan_rx) = mpsc::channel();
    for (idx, crate_path) in target_crates.iter().enumerate() {
        let crate_name = crate_path.file_name().unwrap().to_str().unwrap().to_string();
        // Check cache first when --resume is set
        if use_cache {
            if let Some(cached) = load_cached_result(&conn, &crate_name, &crate_hashes[idx]) {
                let _ = scan_tx.send((idx, ScanMessage::Stage("cached".to_string())));
                let _ = scan_tx.send((idx, ScanMessage::Done(cached)));
                continue;
            }
        }
        let crate_path = crate_path.clone();
        let all_dirs = all_crate_dirs.clone();
        let wl = allowlist.clone();
        let tx = scan_tx.clone();
        let f = filters.clone();
        let hash = crate_hashes[idx].clone();
        let db_path = workspace_root.clone();
        tokio::task::spawn_blocking(move || {
            let progress_tx = tx.clone();
            let progress_idx = idx;
            let on_progress = move |msg: &str| {
                let _ = progress_tx.send((progress_idx, ScanMessage::Stage(msg.to_string())));
            };
            let result = analyze_crate(&crate_path, &all_dirs, &wl, &f, &on_progress)
                .unwrap_or_else(|_| {
                    CrateResult {
                        crate_name: crate_path
                            .file_name()
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_string(),
                        items_found: 0,
                        unused: vec![],
                        skipped: vec![],
                    }
                });
            // Save to cache for next --resume
            if let Ok(save_conn) = open_db(&db_path) {
                save_cached_result(&save_conn, &result.crate_name, &hash, &result);
            }
            let _ = tx.send((idx, ScanMessage::Done(result)));
        });
    }
    drop(scan_tx);

    let scan_state = ScanState {
        crate_names,
        stages: (0..n_crates).map(|_| String::new()).collect(),
        completed: (0..n_crates).map(|_| None).collect(),
        rx: scan_rx,
        start,
    };
    run_tui(vec![], Some(scan_state), &workspace_root, conn, Duration::ZERO)?;

    Ok(())
}

fn find_workspace_root() -> Result<PathBuf> {
    let mut dir = std::env::current_dir()?;
    loop {
        let cargo_toml = dir.join("Cargo.toml");
        if cargo_toml.exists() {
            let content = fs::read_to_string(&cargo_toml)?;
            if content.contains("[workspace]") {
                return Ok(dir);
            }
        }
        if !dir.pop() {
            anyhow::bail!("Could not find workspace root (no Cargo.toml with [workspace] found)");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Create a mini workspace under a temp dir.
    /// `crates` is a slice of (crate_name, &[(filename, source_content)]).
    fn create_workspace(crates: &[(&str, &[(&str, &str)])]) -> TempDir {
        let tmp = TempDir::new().unwrap();
        let crates_dir = tmp.path().join("crates");
        fs::create_dir_all(&crates_dir).unwrap();
        for (name, files) in crates {
            let src_dir = crates_dir.join(name).join("src");
            fs::create_dir_all(&src_dir).unwrap();
            for (filename, content) in *files {
                fs::write(src_dir.join(filename), content).unwrap();
            }
        }
        tmp
    }

    fn crate_dirs(tmp: &TempDir) -> Vec<PathBuf> {
        let crates_dir = tmp.path().join("crates");
        fs::read_dir(&crates_dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_type().map_or(false, |t| t.is_dir()))
            .map(|e| e.path())
            .collect()
    }

    // -- find_item_span (tree-sitter) ----------------------------------------

    #[test]
    fn item_span_ts_function() {
        let source = "\
fn private() {}

pub fn hello() {
    println!(\"hello\");
}

fn other() {}
";
        // pub fn hello is on line 2 (0-indexed)
        // lines 2-4, plus trailing blank → end = 6
        let span = find_item_span_ts(source, 2);
        assert_eq!(span, Some((2, 6)));
    }

    #[test]
    fn item_span_ts_with_doc_comment() {
        let source = "\
/// Does something
/// cool
pub fn documented() {
    todo!()
}
";
        // pub fn is on line 2, doc comments on lines 0-1
        let span = find_item_span_ts(source, 2);
        assert_eq!(span, Some((0, 5)));
    }

    #[test]
    fn item_span_ts_with_attribute() {
        let source = "\
#[derive(Debug)]
pub struct Foo {
    bar: i32,
}
";
        // attribute is sibling, struct_item starts at line 1
        let span = find_item_span_ts(source, 1);
        assert_eq!(span, Some((0, 4)));
    }

    #[test]
    fn item_span_ts_const() {
        let source = "\
pub const MAX: usize = 100;

pub fn other() {}
";
        // const on line 0, trailing blank on line 1 → end = 2
        let span = find_item_span_ts(source, 0);
        assert_eq!(span, Some((0, 2)));
    }

    #[test]
    fn item_span_ts_struct_with_doc_and_attr() {
        let source = "\
use std::fmt;

/// A point in 2D space
#[derive(Debug, Clone)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

pub fn other() {}
";
        // pub struct Point on line 4, doc on line 2, attr on line 3
        let span = find_item_span_ts(source, 4);
        assert_eq!(span, Some((2, 9)));
    }

    // -- collect_pub_symbols -------------------------------------------------

    #[test]
    fn collect_finds_pub_items() {
        let ws = create_workspace(&[(
            "alpha",
            &[(
                "lib.rs",
                "pub fn foo() {}\npub struct Bar {}\nfn private() {}\npub(crate) fn scoped() {}\n",
            )],
        )]);
        let symbols = collect_pub_symbols(&ws.path().join("crates/alpha")).unwrap();
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"foo"));
        assert!(names.contains(&"Bar"));
        assert!(!names.contains(&"private"));
        assert!(!names.contains(&"scoped"));
    }

    #[test]
    fn orm_filter_skips_orm_symbols() {
        let ws = create_workspace(&[(
            "alpha",
            &[(
                "lib.rs",
                "pub struct Model {}\npub struct Entity {}\npub fn real_thing() {}\n",
            )],
        )]);
        let symbols = collect_pub_symbols(&ws.path().join("crates/alpha")).unwrap();
        let filter = OrmFilter;
        let (kept, skipped) = filter.filter(symbols);
        let kept_names: Vec<&str> = kept.iter().map(|s| s.name.as_str()).collect();
        assert!(!kept_names.contains(&"Model"));
        assert!(!kept_names.contains(&"Entity"));
        assert!(kept_names.contains(&"real_thing"));
        assert!(skipped.iter().any(|(sym, r)| sym.name == "Model" && *r == SkipReason::Orm));
        assert!(skipped.iter().any(|(sym, r)| sym.name == "Entity" && *r == SkipReason::Orm));
    }

    // -- count_symbol_hits ---------------------------------------------------

    #[test]
    fn count_hits_correctly() {
        let ws = create_workspace(&[
            ("alpha", &[("lib.rs", "pub fn shared() {}\npub fn lonely() {}\n")]),
            (
                "beta",
                &[("lib.rs", "fn consumer() {\n    shared();\n    shared();\n}\n")],
            ),
        ]);
        let beta_src = ws.path().join("crates/beta/src");
        let names = vec!["shared".to_string(), "lonely".to_string()];
        let counts = count_symbol_hits(&names, &[beta_src]).unwrap();
        assert_eq!(counts.get("shared").copied().unwrap_or(0), 2);
        assert_eq!(counts.get("lonely").copied().unwrap_or(0), 0);
    }

    // -- analyze_crate -------------------------------------------------------

    #[test]
    fn analyze_classifies_unused_and_internal() {
        let ws = create_workspace(&[
            (
                "alpha",
                &[(
                    "lib.rs",
                    concat!(
                        "pub fn used_externally() {}\n",
                        "pub fn used_internally() { used_internally_helper(); }\n",
                        "fn used_internally_helper() { used_internally(); }\n",
                        "pub fn dead_code() {}\n",
                    ),
                )],
            ),
            (
                "beta",
                &[("lib.rs", "fn consumer() { used_externally(); }\n")],
            ),
        ]);
        let crate_path = ws.path().join("crates/alpha");
        let src_dirs = crate_dirs(&ws);
        let allowlist = HashSet::new();
        let result = analyze_crate(&crate_path, &src_dirs, &allowlist, &all_filters(), &|_| {}).unwrap();

        let find = |name: &str| result.unused.iter().find(|u| u.symbol.name == name);

        // used_externally: has external hits → not reported
        assert!(find("used_externally").is_none());

        // dead_code: no refs anywhere → UnusedAnywhere
        let dead = find("dead_code").unwrap();
        assert_eq!(dead.kind, SymbolKind::UnusedAnywhere);

        // used_internally: internal refs only → CrateInternalOnly
        let internal = find("used_internally").unwrap();
        assert!(matches!(internal.kind, SymbolKind::CrateInternalOnly { .. }));
    }

    #[test]
    fn analyze_respects_allowlist() {
        let ws = create_workspace(&[(
            "alpha",
            &[("lib.rs", "pub fn allowlisted_fn() {}\n")],
        )]);
        let src_dirs = crate_dirs(&ws);
        let mut allowlist = HashSet::new();
        allowlist.insert(("allowlisted_fn".to_string(), "alpha".to_string()));

        let result =
            analyze_crate(&ws.path().join("crates/alpha"), &src_dirs, &allowlist, &all_filters(), &|_| {}).unwrap();
        assert!(result.unused.is_empty());
    }

    // -- apply_fix_crate_internal --------------------------------------------

    #[test]
    fn fix_crate_internal_changes_pub_to_pub_crate() {
        let ws = create_workspace(&[(
            "alpha",
            &[("lib.rs", "pub fn internal_only() {\n    todo!()\n}\n")],
        )]);
        let file = ws.path().join("crates/alpha/src/lib.rs");
        let sym = UnusedSymbol {
            symbol: PubSymbol {
                name: "internal_only".to_string(),
                file: file.clone(),
                line: 1,
            },
            kind: SymbolKind::CrateInternalOnly { refs: 3 },
            crate_name: "alpha".to_string(),
            internal_refs: vec![],
        };
        apply_fix_crate_internal(&sym).unwrap();

        let result = fs::read_to_string(&file).unwrap();
        assert!(result.contains("pub(crate) fn internal_only()"));
        assert!(!result.starts_with("pub fn"));
    }

    // -- apply_fix_unused ----------------------------------------------------

    #[test]
    fn fix_unused_deletes_entire_function() {
        let source = "\
pub fn keep_me() {}

pub fn delete_me() {
    println!(\"bye\");
}

pub fn also_keep() {}
";
        let ws = create_workspace(&[("alpha", &[("lib.rs", source)])]);
        let file = ws.path().join("crates/alpha/src/lib.rs");
        let sym = UnusedSymbol {
            symbol: PubSymbol {
                name: "delete_me".to_string(),
                file: file.clone(),
                line: 3, // 1-indexed
            },
            kind: SymbolKind::UnusedAnywhere,
            crate_name: "alpha".to_string(),
            internal_refs: vec![],
        };

        let _preview = apply_fix_unused(&sym).unwrap();
        let result = fs::read_to_string(&file).unwrap();
        assert!(result.contains("keep_me"));
        assert!(!result.contains("delete_me"));
        assert!(result.contains("also_keep"));
    }

    #[test]
    fn fix_unused_deletes_struct_with_doc_and_attr() {
        let source = "\
pub fn keep() {}

/// Old struct
#[derive(Debug)]
pub struct Dead {
    field: i32,
}

pub fn also_keep() {}
";
        let ws = create_workspace(&[("alpha", &[("lib.rs", source)])]);
        let file = ws.path().join("crates/alpha/src/lib.rs");
        let sym = UnusedSymbol {
            symbol: PubSymbol {
                name: "Dead".to_string(),
                file: file.clone(),
                line: 5, // 1-indexed: the `pub struct Dead` line
            },
            kind: SymbolKind::UnusedAnywhere,
            crate_name: "alpha".to_string(),
            internal_refs: vec![],
        };

        let _preview = apply_fix_unused(&sym).unwrap();
        let result = fs::read_to_string(&file).unwrap();
        assert!(result.contains("keep"));
        assert!(!result.contains("Dead"));
        assert!(!result.contains("Old struct")); // doc comment deleted too
        assert!(result.contains("also_keep"));
    }

    #[test]
    fn fix_unused_deletes_const() {
        let source = "\
pub const UNUSED_CONST: &str = \"hello\";

pub fn keep() {}
";
        let ws = create_workspace(&[("alpha", &[("lib.rs", source)])]);
        let file = ws.path().join("crates/alpha/src/lib.rs");
        let sym = UnusedSymbol {
            symbol: PubSymbol {
                name: "UNUSED_CONST".to_string(),
                file: file.clone(),
                line: 1,
            },
            kind: SymbolKind::UnusedAnywhere,
            crate_name: "alpha".to_string(),
            internal_refs: vec![],
        };

        let _preview = apply_fix_unused(&sym).unwrap();
        let result = fs::read_to_string(&file).unwrap();
        assert!(!result.contains("UNUSED_CONST"));
        assert!(result.contains("keep"));
    }

    // -- graphql exemption ---------------------------------------------------

    #[test]
    fn graphql_object_impl_methods_exempt() {
        let source = "\
#[Object]
impl MyQuery {
    pub async fn resolver(&self) -> String {
        todo!()
    }
}
";
        // pub async fn resolver is on line 2 (0-indexed)
        assert_eq!(is_graphql_exempt(source, 2), Some("Object".to_string()));
    }

    #[test]
    fn graphql_derive_simple_object_exempt() {
        let source = "\
#[derive(SimpleObject)]
pub struct Output {
    pub name: String,
}
";
        // pub struct Output is on line 1 (0-indexed)
        assert_eq!(is_graphql_exempt(source, 1), Some("SimpleObject".to_string()));
    }

    #[test]
    fn non_graphql_items_not_exempt() {
        let source = "\
#[derive(Debug)]
pub struct Regular {
    pub field: i32,
}
";
        assert_eq!(is_graphql_exempt(source, 1), None);
    }

    #[test]
    fn graphql_mutation_impl_methods_exempt() {
        let source = "\
#[Mutation]
impl MyMutation {
    pub async fn create_thing(&self) -> bool {
        true
    }
}
";
        assert_eq!(is_graphql_exempt(source, 2), Some("Mutation".to_string()));
    }

    #[test]
    fn collect_skips_graphql_items() {
        let ws = create_workspace(&[(
            "alpha",
            &[(
                "lib.rs",
                concat!(
                    "#[derive(SimpleObject)]\n",
                    "pub struct GqlOutput {\n",
                    "    pub name: String,\n",
                    "}\n",
                    "\n",
                    "pub fn regular_fn() {}\n",
                ),
            )],
        )]);
        let symbols = collect_pub_symbols(&ws.path().join("crates/alpha")).unwrap();
        let filter = GraphqlFilter;
        let (kept, skipped) = filter.filter(symbols);
        let kept_names: Vec<&str> = kept.iter().map(|s| s.name.as_str()).collect();
        assert!(kept_names.contains(&"regular_fn"));
        assert!(!kept_names.contains(&"GqlOutput"));
        assert!(skipped.iter().any(|(sym, reason)| sym.name == "GqlOutput" && *reason == SkipReason::Graphql("SimpleObject".to_string())));
    }

    // -- derive_builder aliases ----------------------------------------------

    #[test]
    fn detect_builder_alias() {
        let source = "\
#[derive(Builder, Debug)]
#[builder(pattern = \"owned\")]
pub struct MyConfig {
    pub name: String,
}
";
        assert!(has_derive_builder(source, 2)); // pub struct line, 0-indexed
    }

    #[test]
    fn no_builder_no_alias() {
        let source = "\
#[derive(Debug)]
pub struct Plain {
    pub field: i32,
}
";
        assert!(!has_derive_builder(source, 1));
    }

    #[test]
    fn builder_used_externally_via_alias() {
        // alpha defines a struct with derive(Builder)
        // beta uses MyConfigBuilder (the generated builder type)
        // → alpha::MyConfig should NOT be reported as unused
        let ws = create_workspace(&[
            (
                "alpha",
                &[(
                    "lib.rs",
                    "#[derive(Builder)]\npub struct MyConfig {\n    pub name: String,\n}\n",
                )],
            ),
            (
                "beta",
                &[(
                    "lib.rs",
                    "fn consumer() {\n    let _b = MyConfigBuilder::default();\n}\n",
                )],
            ),
        ]);
        let src_dirs = crate_dirs(&ws);
        let allowlist = HashSet::new();
        let result =
            analyze_crate(&ws.path().join("crates/alpha"), &src_dirs, &allowlist, &all_filters(), &|_| {}).unwrap();

        let find = |name: &str| result.unused.iter().find(|u| u.symbol.name == name);
        // MyConfig should not be unused because MyConfigBuilder is referenced externally
        assert!(find("MyConfig").is_none());
    }

    #[test]
    fn builder_unused_everywhere_still_reported() {
        // alpha defines a struct with derive(Builder)
        // nobody uses MyConfig or MyConfigBuilder
        let ws = create_workspace(&[
            (
                "alpha",
                &[(
                    "lib.rs",
                    "#[derive(Builder)]\npub struct MyConfig {\n    pub name: String,\n}\n",
                )],
            ),
            ("beta", &[("lib.rs", "fn consumer() {}\n")]),
        ]);
        let src_dirs = crate_dirs(&ws);
        let allowlist = HashSet::new();
        let result =
            analyze_crate(&ws.path().join("crates/alpha"), &src_dirs, &allowlist, &all_filters(), &|_| {}).unwrap();

        let find = |name: &str| result.unused.iter().find(|u| u.symbol.name == name);
        // MyConfig should be reported as unused since neither it nor MyConfigBuilder is used
        assert!(find("MyConfig").is_some());
    }

    // -- tests/ directory search coverage ------------------------------------

    /// Helper: add a tests/ file to a crate in a workspace
    fn add_test_file(tmp: &TempDir, crate_name: &str, filename: &str, content: &str) {
        let tests_dir = tmp.path().join("crates").join(crate_name).join("tests");
        fs::create_dir_all(&tests_dir).unwrap();
        fs::write(tests_dir.join(filename), content).unwrap();
    }

    #[test]
    fn symbol_used_in_tests_dir_not_unused() {
        // alpha defines a pub fn, beta's tests/ dir uses it
        let ws = create_workspace(&[
            ("alpha", &[("lib.rs", "pub fn test_helper() {}\n")]),
            ("beta", &[("lib.rs", "// nothing here\n")]),
        ]);
        add_test_file(&ws, "beta", "integration.rs", "fn it_works() { test_helper(); }\n");

        let dirs = crate_dirs(&ws);
        let allowlist = HashSet::new();
        let result =
            analyze_crate(&ws.path().join("crates/alpha"), &dirs, &allowlist, &all_filters(), &|_| {}).unwrap();

        let find = |name: &str| result.unused.iter().find(|u| u.symbol.name == name);
        // test_helper is used in beta's tests/ → should NOT be reported
        assert!(find("test_helper").is_none());
    }

    #[test]
    fn internal_refs_populated_for_crate_internal() {
        let ws = create_workspace(&[(
            "alpha",
            &[(
                "lib.rs",
                concat!(
                    "pub fn used_internally() { used_internally_helper(); }\n",
                    "fn used_internally_helper() { used_internally(); }\n",
                ),
            )],
        )]);
        let dirs = crate_dirs(&ws);
        let allowlist = HashSet::new();
        let result =
            analyze_crate(&ws.path().join("crates/alpha"), &dirs, &allowlist, &all_filters(), &|_| {}).unwrap();

        let item = result
            .unused
            .iter()
            .find(|u| u.symbol.name == "used_internally")
            .expect("should be crate-internal");
        assert!(matches!(item.kind, SymbolKind::CrateInternalOnly { .. }));
        // Should have internal_refs (the non-definition usage sites)
        assert!(!item.internal_refs.is_empty());
    }

    // -- plugin system -------------------------------------------------------

    #[test]
    fn disable_filter_skips_graphql_exemption() {
        // With graphql filter disabled, a #[derive(SimpleObject)] struct should
        // be reported as unused (not skipped).
        let ws = create_workspace(&[(
            "alpha",
            &[(
                "lib.rs",
                concat!(
                    "#[derive(SimpleObject)]\n",
                    "pub struct GqlOutput {\n",
                    "    pub name: String,\n",
                    "}\n",
                ),
            )],
        )]);
        let dirs = crate_dirs(&ws);
        let allowlist = HashSet::new();
        let no_graphql = active_filters(&["graphql".to_string()], &[]);
        let result = analyze_crate(
            &ws.path().join("crates/alpha"),
            &dirs,
            &allowlist,
            &no_graphql,
            &|_| {},
        )
        .unwrap();
        // GqlOutput should NOT be in skipped (graphql filter is off)
        assert!(!result.skipped.iter().any(|(sym, _)| sym.name == "GqlOutput"));
        // GqlOutput should be in unused
        assert!(result.unused.iter().any(|u| u.symbol.name == "GqlOutput"));
    }

    #[test]
    fn disable_filter_skips_orm_exemption() {
        // With ORM filter disabled, Model/Entity should be reported as unused.
        let ws = create_workspace(&[(
            "alpha",
            &[("lib.rs", "pub struct Model {}\npub struct Entity {}\n")],
        )]);
        let dirs = crate_dirs(&ws);
        let allowlist = HashSet::new();
        let no_orm = active_filters(&["orm".to_string()], &[]);
        let result = analyze_crate(
            &ws.path().join("crates/alpha"),
            &dirs,
            &allowlist,
            &no_orm,
            &|_| {},
        )
        .unwrap();
        assert!(!result.skipped.iter().any(|(sym, _)| sym.name == "Model"));
        assert!(result.unused.iter().any(|u| u.symbol.name == "Model"));
        assert!(result.unused.iter().any(|u| u.symbol.name == "Entity"));
    }

    #[test]
    fn all_filter_names_matches_all_filters() {
        let filters = all_filters();
        let names = all_filter_names();
        assert_eq!(filters.len(), names.len());
        for (f, n) in filters.iter().zip(names.iter()) {
            assert_eq!(f.name(), *n);
        }
    }

    // -- comment line skipping -----------------------------------------------

    #[test]
    fn commented_reference_not_counted() {
        // alpha defines pub fn foo, beta only "references" it in a comment
        // → foo should be reported as UnusedAnywhere
        let ws = create_workspace(&[
            ("alpha", &[("lib.rs", "pub fn foo() {}\n")]),
            ("beta", &[("lib.rs", "// foo()\n")]),
        ]);
        let dirs = crate_dirs(&ws);
        let allowlist = HashSet::new();
        let result = analyze_crate(
            &ws.path().join("crates/alpha"),
            &dirs,
            &allowlist,
            &all_filters(),
            &|_| {},
        )
        .unwrap();
        let item = result
            .unused
            .iter()
            .find(|u| u.symbol.name == "foo")
            .expect("foo should be reported as unused");
        assert_eq!(item.kind, SymbolKind::UnusedAnywhere);
    }

    #[test]
    fn real_reference_with_trailing_comment_still_counts() {
        // alpha defines pub fn bar, beta calls it with a trailing comment
        // → bar should NOT be reported as unused
        let ws = create_workspace(&[
            ("alpha", &[("lib.rs", "pub fn bar() {}\n")]),
            ("beta", &[("lib.rs", "fn use_it() { bar(); } // call bar\n")]),
        ]);
        let dirs = crate_dirs(&ws);
        let allowlist = HashSet::new();
        let result = analyze_crate(
            &ws.path().join("crates/alpha"),
            &dirs,
            &allowlist,
            &all_filters(),
            &|_| {},
        )
        .unwrap();
        assert!(
            result.unused.iter().all(|u| u.symbol.name != "bar"),
            "bar has a real call site and should not be unused"
        );
    }

    // -- insta snapshot: scan results ----------------------------------------

    #[test]
    fn snapshot_scan_results() {
        let ws = create_workspace(&[
            (
                "alpha",
                &[(
                    "lib.rs",
                    concat!(
                        "pub fn used_externally() {}\n",
                        "pub fn used_internally() { used_internally_helper(); }\n",
                        "fn used_internally_helper() { used_internally(); }\n",
                        "pub fn dead_code() {}\n",
                    ),
                )],
            ),
            (
                "beta",
                &[("lib.rs", "fn consumer() { used_externally(); }\n")],
            ),
        ]);
        let crate_path = ws.path().join("crates/alpha");
        let src_dirs = crate_dirs(&ws);
        let allowlist = HashSet::new();
        let result =
            analyze_crate(&crate_path, &src_dirs, &allowlist, &all_filters(), &|_| {}).unwrap();

        // Redact the temp dir paths so snapshots are stable
        let json = serde_json::to_value(&result).unwrap();
        let stable = redact_paths(json, ws.path());
        insta::assert_json_snapshot!("scan_results", stable);
    }

    /// Replace absolute temp-dir paths with `<WORKSPACE>` so snapshots are deterministic.
    fn redact_paths(value: serde_json::Value, ws_root: &Path) -> serde_json::Value {
        let prefix = ws_root.to_string_lossy();
        match value {
            serde_json::Value::String(s) => {
                serde_json::Value::String(s.replace(prefix.as_ref(), "<WORKSPACE>"))
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.into_iter().map(|v| redact_paths(v, ws_root)).collect())
            }
            serde_json::Value::Object(map) => {
                serde_json::Value::Object(
                    map.into_iter()
                        .map(|(k, v)| (k, redact_paths(v, ws_root)))
                        .collect(),
                )
            }
            other => other,
        }
    }
}
