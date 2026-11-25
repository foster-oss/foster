# Changelog

## 0.1.0 (unreleased)

First version.

- `foster-oss scan`: reads npm, pnpm, yarn (classic and berry), uv and pinned pip lockfiles; reports
  Foster patches, orphaned + vulnerable, unfixed, upgradable and quietly orphaned dependencies.
  Text, JSON and Markdown output, `--fail-on` for CI, `--offline` mode.
- `foster-oss fix`: points npm/pnpm/yarn projects at Foster patches through npm aliases.
- `foster-oss check`: one-package lookup.
- `foster-oss mcp`: MCP server with `foster_check_package`, `foster_scan_project`, `foster_list_patches`.
- Orphan Index builder, static site and weekly workflow.
- Patch Lab with build-and-verify script; first patch: `ip` (GHSA-2p57-rm9w-gvfp), staged.
- GitHub Action, agent skill, governance and AI policy.
