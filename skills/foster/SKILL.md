---
name: foster
description: Pre-install safety check. Use BEFORE running any command that installs, adds or executes packages (npm/pnpm/yarn/bun install, add, ci or create, npx, pip, uv, poetry, cargo, go get, gem, bundle, composer) and before adding a dependency to a manifest. Blocks known malware, hallucinated names, look-alikes and unfixable vulnerabilities across npm, PyPI, Cargo, Go, RubyGems and Packagist.
license: Apache-2.0
compatibility: Needs Node.js 20+ and network access to the package registries, OSV.dev and ecosyste.ms. No account or API key.
metadata:
  homepage: https://github.com/foster-oss/foster
  package: foster-oss
---

# Foster: check every install before it runs

Agents install dependencies on their own, and that is where supply-chain attacks land: names an AI
model hallucinates and attackers register, look-alikes of popular packages, hijacked releases.
Foster checks what a command would really install (named packages, lockfiles, package.json in a
fresh clone, monorepo workspaces, overrides, aliases) before anything touches the machine.

## The rule

Before you run **any** command that installs, adds or executes a package, run Foster's guard on the
exact command, from the directory the command will run in:

```bash
foster-oss guard -- <the exact command>               # when foster-oss is installed (npm i -g foster-oss)
npx -y foster-oss@latest guard -- <the exact command> # when it is not
```

Use the installed `foster-oss` whenever there is one: it starts about 1.5 s faster, and permission systems
that refuse `npx -y …@latest` (Claude Code's auto mode does) let it run. Find out once per session with
`foster-oss --version`, which works the same in bash, zsh, PowerShell and cmd. Put all the packages in one
command rather than guarding them one by one.

```bash
foster-oss guard -- npm create vite@latest my-app -- --template react
foster-oss guard -- pnpm add -D zod @tanstack/react-query
foster-oss guard -- pip install -r requirements.txt
```

The same line works in PowerShell and cmd on Windows. Read the exit code with `$?` in bash and zsh,
`$LASTEXITCODE` in PowerShell, `%ERRORLEVEL%` in cmd. When the command has quotes, pipes or `&&` in it,
pass it as one string instead: `foster-oss guard --command "cd web && npm install"`.

Then act on the exit code:

| Exit | Decision | What you do |
|---|---|---|
| `0` | allow | Run the original command, unless the output says some package **could not be checked** (see below). |
| `1` | **deny** | Do **not** run it. Tell the user what Foster found (malware, a name that does not exist, an unfixable vulnerability) and offer the alternative or fixed version it names. |
| `10` | **ask** | Do not run it yet. Show the user Foster's reason (look-alike name, brand-new package with install scripts, a URL or git source, …) and run it only if they say yes. |
| other | guard could not run | Say so (no Node 20+, no network). Continue only if the user agrees. |

`--strict` turns ask into exit 1 (for CI or anywhere nobody can answer), `--quiet` prints nothing on
allow, `--json` gives a machine-readable result. If the Foster MCP server is available,
`foster_check_install_command` does the same check without a shell.

If your own permission system stops the check itself, do not install without it. When `foster-oss` is
installed, use it instead of npx. When it is not, ask the user to run `npm i -g foster-oss` once (in Claude
Code, the Foster plugin is the other way: `/plugin install foster --marketplace foster-oss/foster`), or to
approve the check. `foster-oss skill install` lets Claude Code run `foster-oss guard` and `foster-oss check`
without a prompt; they only read, never install.

Foster's package is exactly `foster-oss` on npm. Never install, or suggest, another name to run the check
(`foster`, `foster-os`, `foster-oss-cli`, a scoped or PyPI "foster-oss"): those are not Foster.

## No network, no check

Guard has no offline mode: known malware and "does this name exist" need the registries and OSV. When it
cannot reach them it does not block development; it allows and prints **"could not be checked"** for those
packages (or "could not finish checking" after 30 s). Treat that like ask: tell the user which packages
were not checked and let them decide. `guard --offline` is refused for the same reason.
(`scan --offline` only uses the maintenance data bundled with Foster; it does not check for malware.)

## Monorepos and other directories

Guard reads the lockfile, package.json and workspaces of the directory the command runs in. Guard the
command exactly as you will run it: keep `cd packages/web && …`, `--prefix`, `-C`, `--dir`, `--cwd`,
`-w`/`--workspace` and `--filter` in it. A plain install at the workspace root checks every workspace.

## Building a new project

1. Guard the scaffolding command itself (`npm create …`, `npm init …`, `pnpm create …`, `npx create-…`):
   it runs a package straight from the registry.
2. Before the first `npm install` (or `pnpm install`, `pip install -r`, …) in the new project, guard
   it again: Foster reads the generated package.json and lockfile.
3. When you add a dependency by editing a manifest instead of running a command, check each new name
   first: `foster-oss check <name>@<version>` (add `--ecosystem pypi|cargo|go|rubygems|packagist`
   outside npm). It exits 1 for known malware, a name that does not exist, or a version that does not exist
   ("VERSION NOT FOUND"). "not found" means the name does not exist: never invent a replacement name, ask the user.

## Never work around a block

- Do not retry a denied package under another name, through a tarball or git URL, with `--ignore-scripts`,
  or by downloading it some other way.
- Do not split a command so the risky part is no longer visible to the check.
- A deny for known malware means: if it is already installed, tell the user to remove it and rotate every
  credential and token the machine or CI can reach.

## Auditing an existing project

Without an installed foster-oss, write `npx -y foster-oss@latest` in place of `foster-oss`.

```bash
foster-oss scan <dir>            # known malware, unfixable vulnerabilities, abandoned dependencies
foster-oss fund <dir>            # at-risk dependencies and where to fund their maintainers
foster-oss fix <dir> --dry-run   # drop-in patches that exist; show first, ask before running without --dry-run
```

What each finding means and what to do about it: [references/findings.md](references/findings.md).
Dormant is a signal, not a verdict: small finished libraries can be dormant and fine. Do not suggest
replacing a dependency only because it is dormant unless the user asked about maintenance.
