# find-unused-pub

Find `pub` items in a Rust workspace that are either unused entirely or only used within their own crate. Ships with a full TUI (ratatui) for browsing results, reviewing items interactively, and applying fixes. Includes catppuccin and [eldritch](https://github.com/eldritch-theme/eldritch) color themes.

## Install

```bash
cargo install --git https://github.com/Bolognafingers/find-unused-pub
```

Or build from source:

```bash
cargo build --release
```

## Usage

Run from anywhere inside a Rust workspace (it walks up to find the root `Cargo.toml` with `[workspace]`):

```bash
# Scan all crates — launches the TUI
find-unused-pub

# Scan specific crates
find-unused-pub crates/auth crates/core

# Ignore a crate
find-unused-pub --ignore crates/app

# Disable the graphql filter (faster if you don't use async-graphql)
find-unused-pub --disable-filter graphql

# Enable an opt-in filter (e.g. cynic for cynic-rs projects)
find-unused-pub --enable-filter cynic

# Use a different palette
find-unused-pub --palette latte
find-unused-pub --palette eldritch

# Auto-fix crate-internal items → pub(crate)
find-unused-pub --fix crates/auth

# Auto-fix unused items (deletes the entire item)
find-unused-pub --fix-unused

# Force a fresh scan, ignoring the cache
find-unused-pub --no-cache

# Clear the allowlist database
find-unused-pub --nuke-allowlist
```

## Flags

| Flag | Description |
|------|-------------|
| `--palette <name>` | Color theme: `latte`, `frappe`, `macchiato`, `mocha` (default), `eldritch` |
| `--ignore <path>` | Skip a crate path (repeatable, relative to workspace root) |
| `--disable-filter <name>` | Turn off a filter plugin (repeatable, see [Filters](#filters)) |
| `--enable-filter <name>` | Turn on an opt-in filter plugin (repeatable, see [Filters](#filters)) |
| `--no-cache` | Ignore cached results and rescan all crates from scratch |
| `--fix` | Alias for `--fix-crate-internal` |
| `--fix-crate-internal` | Auto-fix crate-internal items to `pub(crate)` |
| `--fix-unused` | Auto-fix unused items by deleting them entirely |
| `--nuke-allowlist` | Clear the SQLite allowlist database |

Flags compose: `--fix --fix-unused` fixes both categories.

## Environment variables

Set these in your `.envrc` or shell profile to avoid repeating flags:

| Variable | Example | Description |
|----------|---------|-------------|
| `FIND_UNUSED_PUB_PALETTE` | `latte` | Initial color palette |
| `FIND_UNUSED_PUB_IGNORE` | `crates/app,crates/cli` | Comma-separated crate paths to skip |
| `FIND_UNUSED_PUB_DISABLE_FILTER` | `graphql` | Comma-separated filter names to disable |
| `FIND_UNUSED_PUB_ENABLE_FILTER` | `cynic` | Comma-separated opt-in filter names to enable |

CLI flags override environment variables when both are set.

## TUI

The default mode launches an interactive TUI with three phases:

1. **Scanning** — streams results as each crate is analyzed, showing live progress
2. **Summary** — three views (Tab to switch): table overview, per-crate detail (collapsible), and skipped symbols (collapsible)
3. **Review** — step through each item with git blame/log context, choose fix / allowlist / skip

### Keybindings

| Key | Action |
|-----|--------|
| `Tab` | Cycle summary views (table / detail / skipped) |
| `j` / `k` | Navigate crates (detail/skipped views) |
| `PgUp` / `PgDn` | Scroll content |
| `Space` | Expand/collapse a crate in detail/skipped view |
| `p` | Cycle palette live |
| `q` | Quit |
| `r` | Review unused items |
| `i` | Review crate-internal items |
| `f` / `a` / `s` | Fix / Allowlist / Skip (in review) |

The TUI title bar and config block show the active palette, enabled filters, disabled filters, and ignored paths — always self-documenting.

## Filters

Filters are modular plugins that exempt symbols from analysis. Most ship enabled by default (batteries included). Disable any with `--disable-filter <name>`. Opt-in filters must be explicitly enabled with `--enable-filter <name>`.

### Default-on

| Filter | What it does |
|--------|--------------|
| `orm` | Skips sea-orm derive names: `Model`, `Entity`, `Column`, `Relation`, `ActiveModel`, `ActiveModelBehavior` |
| `graphql` | Skips items with async-graphql attributes: `#[Object]`, `#[derive(SimpleObject)]`, `#[Mutation]`, etc. Shows the specific attribute in the TUI (e.g. `[graphql:SimpleObject]`) |
| `builder` | Detects `#[derive(Builder)]` and searches for `{Name}Builder` aliases so builder-pattern structs aren't falsely reported |

### Opt-in

| Filter  | What it does                                                                                                                                                                      |
|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `cynic` | Skips items with cynic derive attributes: `#[derive(cynic::QueryFragment)]`, `#[derive(cynic::InputObject)]`, etc. Shows the specific attribute (e.g. `[cynic:QueryFragment]`) |

## How it works

1. Scans each crate's `src/` for `pub fn|struct|enum|trait|type|const|static` definitions
2. Runs active filter plugins to exempt framework-used symbols
3. Batch-searches all other crates for word-bounded matches (ripgrep as a library)
4. For symbols with zero external hits, checks internal usage within the same crate
5. Classifies each symbol:
   - **unused anywhere** — no references beyond the definition itself
   - **crate-internal only** — used inside the crate but never externally
6. Comment-only lines (`// ...`) are ignored during reference counting

Uses [tree-sitter-rust](https://github.com/tree-sitter/tree-sitter-rust) for accurate item span detection when deleting items (includes doc comments, attributes, and the full item body).

## Allowlist

False positives can be allowlisted during review mode. The allowlist is stored in a SQLite database at `.find-unused-pub.db` in the workspace root (gitignored).

## Caveats

- Text-based search: will miss re-exports, derive macros generating references, etc.
- May false-positive on items used only via trait impls or proc macros
- Skips `pub(crate)`, `pub(super)`, and `pub(in ...)` (already scoped)
- Skips `pub mod` (modules are structural)
- Block comments (`/* */`) are not skipped during reference counting (only `//` lines)

## Tests

```bash
cargo nextest run
```
