# Changelog

## 0.9.0

Foster as an Agent Skill, for every coding agent.

- **`foster-oss skill install`** adds the Foster skill (the open [Agent Skills](https://agentskills.io) format)
  to a project: `.agents/skills`, read by Codex, Cursor, Gemini CLI, GitHub Copilot, OpenCode, Amp, Cline,
  Zed, Warp and others, and `.claude/skills` for Claude Code, plus any other agent folder already in the
  project. `--global` installs it for every agent on the machine, `--agent <id>` for one, and
  `foster-oss skill print` prints it. `npx skills add foster-oss/foster` works too.
- **The skill is rewritten around the pre-install check**: run `foster-oss guard` on the exact command,
  act on exit 0 / 1 / 10, guard the scaffolding command and the first install of a new project, check
  names before writing them into a manifest, and never work around a block. Finding details moved to
  `references/findings.md`.
- **Claude Code plugin** in the same repository: `/plugin install foster --marketplace foster-oss/foster`
  installs the PreToolUse hook, the skill and the MCP server in one step.
- **Project scaffolders are checked**: `npm create`, `npm init <initializer>`, `pnpm create`, `yarn create`
  and `bun create` run a `create-*` package from the registry, which guard now checks the way npm maps it
  (`vite` → `create-vite`, `@scope` → `@scope/create`). `npm create vitee@latest` is denied: no such package.

## 0.8.7

No change in behaviour: Foster now says what it does.

- `foster-oss --help` leads with guard and shows examples; the npm description, the MCP Registry
  description and the GitHub Action description mention malware and the pre-install check.
- The README leads with guard (what it decides, what it reads, how to set it up, how it is tested), with
  demos regenerated from real output; SECURITY.md says how to report a way past guard.
- The Orphan Index site has a "Before your agent installs anything" section.

## 0.8.6

- **Peer dependencies are checked.** npm 7+ and pnpm 8+ install `peerDependencies` automatically, so a
  package.json with `"peerDependencies": {"crossenv": "0.0.2-security"}` put malware on disk while guard saw
  nothing. They are now checked like the other dependency fields; peers that `peerDependenciesMeta` marks
  `optional` are skipped, because npm does not install those. Found by the seventh outside review, which
  also confirmed overrides, corepack, `npm-shrinkwrap.json` and manifest aliases are covered.

## 0.8.5

The two gaps from the sixth outside review, and a hole in the live CI check itself.

- **Overrides are checked.** npm `overrides`, yarn `resolutions` and `pnpm.overrides` replace what a dependency
  installs: `"overrides": {"ms": "npm:crossenv@0.0.2-security"}` makes `npm install` put crossenv on disk under
  the name `ms`, and guard saw only the direct dependencies. Every override target (nested npm overrides,
  yarn path keys like `**/ms`, pnpm `a>b` keys) is now checked like a dependency; `$ref` values and pnpm's
  `-` removals are skipped. Lockfiles were already safe: they record the real package behind an alias.
- **corepack** is understood: `corepack pnpm install`, `corepack yarn@4.1.0 add x`, `corepack npm …`, and `pnpx`.
  `shell-init` wraps `corepack` and `pnpx` too.
- The `guard-live` CI job did not fail when a check inside a subshell failed (the workspace cases); it does now,
  and it also covers overrides, resolutions and corepack.

## 0.8.4

Fixes a regression in 0.8.3 found by the fifth outside review, and the last two gaps it found.

- **Regression: known malware was an ask, not a deny, when its name also looks like a popular package.**
  0.8.3 stopped asking OSV a second time per package (the version check already reports malware), but the
  decision looked at look-alike names before that malware finding. `crossenv` (malware, and one letter
  from `cross-env`) became an ask on `npm i`, `npx`, `pnpm dlx`, `yarn dlx`, `bunx`, `npm exec` and installs
  from package.json. Malware now outranks every other rule again.
- **A new CI job runs guard against real malware** on the live registries and OSV, with no stubs: `crossenv`,
  `@ctrl/tinycolor@4.1.1`, an alias of it, `ua-parser-js@0.7.29`, a workspace install, and clean packages.
  The unit tests stub the network, so a change in how the pieces fit together only shows there.
- **`npm install <name>`** (and `pnpm add`, `yarn add`, `bun add`) in a project also checks what package.json
  brings along that the lockfile does not have: npm installs the whole project, not only `<name>`. Global
  installs (`-g`) are left alone.
- **Stale lockfiles are compared by version too**, not only by name: a dependency whose pinned version or
  range no locked copy satisfies (lockfile has `ms@2.1.3`, package.json wants `^3`) is checked.

## 0.8.3

From a fourth outside review: the last way past guard it found, and speed on big monorepos.

- **Stale lockfiles.** A monorepo whose root lockfile predates a dependency added in a workspace (a merge,
  a new workspace) passed `npm install`, `pnpm install`, `yarn install` and `bun install`, which rewrite the
  lockfile from package.json and install the new dependency. Guard now also checks every dependency in the
  root and workspace package.json files that the lockfile does not have yet. `npm ci`, `--frozen-lockfile`
  and `--immutable` still trust the lockfile, since they install it as it is.
- **Faster.** A root install of 60 workspaces and 120 packages with no lockfile went from 7.4 s to 2.5 s:
  all versions are resolved first and sent to OSV in one request instead of 240, the Orphan Index and patch
  registry are loaded once per run instead of once per package, and package records are cached.
- **Less noise from package.json installs.** A fixable vulnerability in a dependency your own package.json
  already pins is a note instead of an ask on every install (typed on the command line, it is still an ask).
  More than five notes are summarised.
- An existing lockfile with no external packages (a workspace-only monorepo) is trusted as a lockfile, not
  mistaken for a missing one.

## 0.8.2

From a third outside review: two monorepo paths, `npm exec`, and noise that could stop CI.

- **Monorepo roots without a lockfile** check every workspace: `npm install`, `pnpm install`, `yarn install`
  and `npm i --workspace a` in a root whose `package.json` has `workspaces` (or that has a
  `pnpm-workspace.yaml`) now read each workspace's `package.json`. Globs (`apps/*`, `packages/**`) and
  exclusions (`!apps/old`) are understood; dependencies on other workspaces are skipped.
- **`npm exec` and `npm x`** are checked like `npx`.
- **Unmaintained packages no longer stop installs.** A dead or dormant package with no known vulnerability
  (for example `cross-env`, whose repository is archived) is allowed with a "Note (not blocking)" line and
  maintained alternatives, instead of an ask that a non-interactive shell or CI would cancel. Vulnerable or
  malicious packages are unchanged.
- The look-alike check in lockfiles looks up to 60 names (was 20), and says so when a lockfile has more.

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
