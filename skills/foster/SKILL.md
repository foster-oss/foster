---
name: foster
description: Pre-install safety check for dependencies. Use BEFORE running any command that installs or adds packages (npm/pnpm/yarn/bun install or add, npm ci, npx, pnpm dlx, bunx, npm create or npm init scaffolders, pip/uv/poetry/pipx/pipenv install, cargo add or install, go get or install, gem/bundle install, composer require) and before writing a new dependency into package.json, requirements.txt, pyproject.toml, Cargo.toml, go.mod, Gemfile or composer.json. Blocks known malware, hallucinated package names that do not exist, look-alike names and vulnerabilities no release fixes, across npm, PyPI, Cargo, Go, RubyGems and Packagist. Also use when asked whether a package is safe, maintained or abandoned, or to audit a project's dependencies.
license: Apache-2.0
compatibility: Needs Node.js 20+ and network access to the npm registry, OSV.dev and ecosyste.ms. No account or API key.
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
exact command, from the same working directory:

```bash
npx -y foster-oss@latest guard -- <the exact command>
```

Examples:

```bash
npx -y foster-oss@latest guard -- npm create vite@latest my-app -- --template react
npx -y foster-oss@latest guard -- npm install
npx -y foster-oss@latest guard -- pnpm add zod @tanstack/react-query
npx -y foster-oss@latest guard -- pip install -r requirements.txt
npx -y foster-oss@latest guard -- cargo add serde
```

Then act on the exit code:

| Exit | Decision | What you do |
|---|---|---|
| `0` | allow | Run the original command. |
| `1` | **deny** | Do **not** run it. Tell the user what Foster found (malware, a name that does not exist, an unfixable vulnerability) and offer the alternative or fixed version it names. |
| `10` | **ask** | Do not run it yet. Show the user Foster's reason (look-alike name, brand-new package with install scripts, a URL or git source, …) and run it only if they say yes. |
| other | guard could not run | Say so (no Node 20+, no network). Continue only if the user agrees. |

If the Foster MCP server is available, `foster_check_install_command` does the same check without a
shell.

## Building a new project

1. Guard the scaffolding command itself (`npm create …`, `npm init …`, `pnpm create …`, `npx create-…`):
   it runs a package straight from the registry.
2. Before the first `npm install` (or `pnpm install`, `pip install -r`, …) in the new project, guard
   it again: Foster reads the generated package.json and lockfile.
3. When you add a dependency by editing a manifest instead of running a command, check each new name
   first: `npx -y foster-oss@latest check <name>@<version>` (add `--ecosystem pypi|cargo|go|rubygems|packagist`
   outside npm). "not found" means the name does not exist: never invent a replacement name, ask the user.

## Never work around a block

- Do not retry a denied package under another name, through a tarball or git URL, with `--ignore-scripts`,
  or by downloading it some other way.
- Do not split a command so the risky part is no longer visible to the check.
- A deny for known malware means: if it is already installed, tell the user to remove it and rotate every
  credential and token the machine or CI can reach.

## Auditing an existing project

```bash
npx -y foster-oss@latest scan <dir>        # known malware, unfixable vulnerabilities, abandoned dependencies
npx -y foster-oss@latest fund <dir>        # at-risk dependencies and where to fund their maintainers
npx -y foster-oss@latest fix <dir> --dry-run   # drop-in patches that exist; show first, then ask before running without --dry-run
```

What each finding means and what to do about it: [references/findings.md](references/findings.md).
Dormant is a signal, not a verdict: small finished libraries can be dormant and fine. Do not suggest
replacing a dependency only because it is dormant unless the user asked about maintenance.
