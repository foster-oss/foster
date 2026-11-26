# Changelog

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
