# Changelog

## 0.8.1

Three more ways past `guard`, from a second outside review, and one false positive it uncovered.

- **Global options before the subcommand** are read: `npm --prefix apps/a ci`, `npm -C apps/a ci`,
  `npm --prefix=apps/a ci`, `pnpm -C dir install`, `yarn --cwd dir`, `pip -q install x`. Before, these looked
  like no install at all.
- **Installs with no lockfile** (`npm install`, `pnpm install`, `yarn`, `bun install` in a fresh clone, or with
  only `bun.lockb`) check the packages in `package.json`, as if they were named on the command line:
  malware, names that do not exist, look-alikes, install scripts. Local folders and workspaces are skipped.
- **Lockfile installs check names, not only advisories.** Locked packages whose names look like a popular
  package are looked up (at most 20 per lockfile, everything else stays offline): a name that does not
  exist on the registry is a deny (`colourama==1.0.0` in requirements.txt), a little-used look-alike an ask
  (`expres` in package-lock.json).
- **No more look-alike warnings for huge new packages.** `call-bound`, `get-proto`, `es-errors` and `obug`
  have a billion downloads a month but "0 dependent repos" in ecosyste.ms; a look-alike name with 100k+
  downloads a month is now trusted, on the command line and in lockfiles.

## 0.8.0

Closes four ways past `guard` found in an outside review of 0.7.0, and brings guard to the shell.

- **Lockfile installs are checked.** `npm ci`, `npm install` with no package names, `pnpm install`, `yarn`,
  `bun install`, `pip install -r`, `uv sync`, `uv pip sync`, `poetry install`, `pipenv sync`, `bundle install`,
  `composer install` and `cargo fetch`/`build` used to pass unchecked. Guard now reads the lockfile the
  command would use (following `cd dir &&`, `--prefix`, `--dir`, `--cwd`) and denies the install when any
  locked package is known malware: one OSV batch query for the whole lockfile. The Claude Code hook uses
  the session's working directory.
- **npm aliases** (`tc@npm:@ctrl/tinycolor@4.1.1`) are checked as the real package.
- **npm registry tarball URLs** are checked as the package and version they name. Other URLs and git
  sources (`https://…/x.tgz`, `github:a/b`, `git+https://…`, `pkg @ https://…`) are an **ask**: no registry
  or advisory database covers them.
- **Ranges and dist-tags** (`x@^4.1.0`, `x@~1.2`, `x@next`) are resolved to the version npm would install;
  before, guard checked the latest release whatever the range said.
- **`guard` exit codes**: 0 allow, 1 deny, **10 ask** (was 0), so `foster-oss guard -- <cmd> && <cmd>`
  stops on an ask too, and a wrapper can tell the cases apart. `--strict` still turns ask into 1; new
  `--quiet` prints nothing when the install is allowed.
- **`foster-oss shell-init bash|zsh|powershell`** prints functions that guard the installs you type: npm,
  npx, pnpm, yarn, bun, pip, uv, poetry, pipx, pipenv, cargo, go, gem, bundle and composer. Deny cancels,
  ask prompts `Install anyway? [y/N]` (cancelled without a terminal), and a guard that cannot run never
  blocks. `command npm …` skips the check once.
- The command parser keeps backslashes in Windows paths (`cd "C:\Users\me\app"`), and inside double
  quotes only treats a backslash before `$`, a backtick, `"` or another backslash as an escape, as
  POSIX shells do.

## 0.7.0

- **Guard blocks known malware.** Every install is checked against OSV, which includes the OpenSSF
  malicious-packages database and GitHub's malware advisories: `npm i @ctrl/tinycolor@4.1.1`
  (Shai-Hulud, 2025), `npm i crossenv` and `npm i ua-parser-js@0.7.29` are now denied.
- **Guard asks about install scripts in a suspicious context (npm).** A package first published in the
  last 30 days that runs `preinstall`/`install`/`postinstall`, or a fresh release that adds an install
  script the previous release did not have, is an **ask**, showing the script and the previous version.
  One small request per package; nothing is fetched beyond that unless a script is present.
- **`scan` reports malware** instead of skipping it: a `MALWARE` finding (SARIF `error`) for a known
  malicious package or hijacked release in your lockfile, with what to do (remove, rotate credentials).
  `--fail-on` has a new level, `malicious`, which is now the CLI default: known malware exits 1 at every
  level except `none`.
- Advisories whose titles merely mention similar words ("session hijacking") are no longer mistaken for
  malware: malware is recognised by OSV `MAL-` ids and the titles GitHub and OpenSSF use for it.
- **`fund` helps without money too.** For at-risk packages with no funding link it now lists each one with
  a concrete next step: the issue tracker to offer co-maintenance or send fixes, a note when the
  repository is archived (fork it together, or replace it), and maintained alternatives when known.
- Guard checks the packages of one command in parallel: five packages take under two seconds instead of five.

## 0.6.1

- The CLI no longer lets a stale copy of the Orphan Index from the GitHub CDN replace the newer data
  bundled in the release (it compares `generatedAt` and keeps the newest), so `fund` shows funding
  links right after a release.

## 0.6.0

- **`foster-oss fund`**: the dependencies you rely on that are unmaintained or at risk, ranked by how much
  the ecosystem relies on them, with their maintainers' sponsorship links, and the few people whose
  sponsorship covers most of them. Also as the MCP tool `foster_fund_project`.
- `scan` shows a `fund:` line for orphaned findings; the README lists what to do in order: upstream
  first, fund the maintainers, move to a maintained alternative, and use a drop-in patch only as a stopgap.
- The Orphan Index records funding links (2,459 of 5,797 critical packages) and the site has a
  "Fund what everyone depends on" section.

- **Direct or transitive, and through what.** Foster now reads the dependency graph from the lockfile
  (package-lock v2/v3, pnpm v5/v6/v9, yarn classic and berry, uv, Poetry, Cargo, Gemfile.lock,
  composer.lock) and from CycloneDX/SPDX SBOMs that record it. Every transitive finding names the direct
  dependency that brings it in: `devalue@5.9.2 (transitive, via astro)`.
- The summary counts direct findings (`10 upgrade (4 direct)`), and the quiet orphan line splits what you
  depend on directly from what comes in through other packages, with the parents responsible for most of
  them (`mostly via request (34), express (17)`). Findings in direct dependencies sort first.
- When a vulnerable package comes in only through a direct dependency that nobody maintains, Foster says
  that it will never move to the fix (replace the parent, or force the fix with an override) instead of
  "upgrade normally".
- Direct dependencies are now exact where the lockfile lists the project's own dependencies (npm, pnpm,
  yarn, uv, Cargo, SBOMs): a second, nested copy of a direct package is reported as transitive, and an npm
  alias (`"ip": "npm:@keep-lts/ip@2.0.2"`) counts as direct.
- Python direct dependencies are read from `pyproject.toml` (PEP 621, PEP 735 dependency groups,
  `[tool.uv]`, Poetry tables) and `Pipfile`, for `poetry.lock`, `uv.lock` and `Pipfile.lock`.
- JSON output: `dependency.via` and a `summary` (`{ kind: { total, direct } }`); SARIF results carry
  `direct` and `via`.

## 0.5.1

- Fix: `foster-oss guard "npm install x"` (the whole command as one quoted argument) now checks the
  install instead of reporting "no package installs". `guard -- npm install x` was not affected.
- **Fix: the GitHub Action did not load** (`action.yml` had a YAML error since 0.2, in the `comment` and
  `sarif` input descriptions). CI now runs the Action itself on a fixture, and a test parses every YAML
  file in the repository.

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
