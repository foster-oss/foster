# Changelog

## Unreleased

- Fix: `foster-oss guard "npm install x"` (the whole command as one quoted argument) now checks the
  install instead of reporting "no package installs". `guard -- npm install x` was not affected.
- CI runs the GitHub Action itself on a fixture, using the released package.

## 0.5.0

- `scan --since <git-ref>`: only check dependencies added or changed since a ref, by comparing each
  lockfile with its content at that ref (works with `--recursive`; a lockfile that did not exist then
  counts as all new; an unknown ref falls back to a full scan with a warning).
- GitHub Action: on pull requests, checks only what the PR adds or changes (`only-new: true`, default),
  fetching the base commit in shallow clones; `since` input to compare with any ref.
- README: guard demo from real output.

## 0.4.0

- Guard catches **look-alike names** of popular packages in all six ecosystems (`lodahs` → `lodash`,
  `expresss` → `express`, `reqeusts` → `requests`), using the critical-package list shipped as
  `data/popular.json` (rebuilt weekly with the Orphan Index). Widely used neighbours such as
  `preact`/`react` or `ulid`/`uuid` are not flagged.
- Before calling a name hallucinated, guard confirms with the real registry (npm, PyPI, crates.io, the Go
  proxy, RubyGems, Packagist); brand-new packages no index knows yet get **ask**, not deny.
- Unknown names come with "did you mean …?".
- README: setup for Codex, Cursor, Gemini CLI and Copilot through AGENTS.md-style rules.

## 0.3.0

- **`foster-oss guard`**: checks every package a shell command would install, before it runs.
  Blocks names that do not exist on the registry (hallucinated or typo'd names, the "slopsquatting"
  risk) and packages with vulnerabilities no release fixes; asks about unmaintained packages and
  vulnerable versions that a newer release fixes, with maintained alternatives.
  Understands npm, pnpm, yarn, bun, npx/dlx, pip, uv, poetry, pipx, cargo, go, gem, bundle and composer.
- `guard --hook claude`: drop-in Claude Code PreToolUse hook (JSON decisions, fails open).
- MCP tool `foster_check_install_command` for agents without hooks.

## 0.2.1

- Listed in the official MCP Registry as `io.github.foster-oss/foster` (`server.json`, `mcpName`).
- Releases publish to the MCP Registry automatically after npm.

## 0.2.0 (2026-11-27)

First release on npm: `npx foster-oss`.


- Six ecosystems: Cargo (`Cargo.lock`), Go (`go.mod`), RubyGems (`Gemfile.lock`) and Packagist
  (`composer.lock`) join npm and PyPI; Python also gains `poetry.lock` and `Pipfile.lock`.
- The Orphan Index now covers 5,797 critical packages across all six ecosystems, with a
  per-ecosystem breakdown on the site.
- Replacement suggestions (`consider: …`): e18e module-replacements for npm, plus Foster's reviewed
  `registry/alternatives.json` for all ecosystems.
- `scan --recursive`: monorepos with lockfiles in subfolders (the GitHub Action does this by default).
- `scan --sbom <file>`: scan CycloneDX or SPDX JSON SBOMs (purls for all six ecosystems).
- SARIF 2.1.0 output (`--sarif`) and an Action option to upload findings to GitHub code scanning.
- Fix suggestions pick the nearest fixed release on the installed release line.
- Registry lists drop-in patches from any provider (12 from Keep LTS).

## 0.1.0

First version.

- `foster-oss scan`: reads npm, pnpm, yarn (classic and berry), uv and pinned pip lockfiles; reports
  Foster patches, orphaned + vulnerable, unfixed, upgradable and quietly orphaned dependencies.
  Text, JSON and Markdown output, `--fail-on` for CI, `--offline` mode.
- `foster-oss fix`: points npm/pnpm/yarn projects at Foster patches through npm aliases.
- `foster-oss check`: one-package lookup.
- `foster-oss mcp`: MCP server with `foster_check_package`, `foster_scan_project`, `foster_list_patches`.
- Orphan Index builder, static site and weekly workflow.
- Patch registry listing drop-in patches from any provider (12 from Keep LTS).
- Patch Lab with build-and-verify script for gaps no one has patched; the `ip` patch is retired in favour of `@keep-lts/ip`.
- GitHub Action, agent skill, governance and AI policy.
