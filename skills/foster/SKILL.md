---
name: foster
description: Check whether a dependency is still maintained and whether it has security holes nobody can fix, before adding it or when auditing a project. Use when adding, upgrading or reviewing dependencies (npm, PyPI, Cargo, Go, RubyGems, Packagist), when a user asks "is this package safe / maintained / abandoned", when a security scan reports a vulnerability with no fixed version, or when auditing a lockfile for supply-chain risk.
---

# Foster: orphaned dependency check

Foster finds dependencies that nobody maintains anymore, tells apart "just upgrade" from
"no fix exists anywhere", and can switch a project to published drop-in security patches (from Foster or providers such as Keep LTS)
without changing any import.

## When to use it

- **Before adding a dependency** you have not used before: check it.
- **When an audit says "no fix available"**: Foster may have a patch, or the package may be abandoned.
- **When reviewing a project's health**: scan the lockfile.

## Commands

Run them with `npx` (no install needed). Node 20+.

```bash
# One package, optionally a specific version
npx -y foster-oss check <name>[@<version>]            # npm
npx -y foster-oss check <name>@<version> --ecosystem pypi

# A whole project: package-lock.json, pnpm-lock.yaml, yarn.lock, uv.lock, poetry.lock,
# Pipfile.lock, requirements.txt, Cargo.lock, go.mod, Gemfile.lock, composer.lock
npx -y foster-oss scan <dir>
npx -y foster-oss scan <dir> --json        # for further processing
npx -y foster-oss scan <dir> --all         # also list quiet orphans

# Switch to published drop-in patches (edits package.json, then reinstall)
npx -y foster-oss fix <dir> --dry-run      # show first
npx -y foster-oss fix <dir>
```

If the MCP server is configured (`npx -y foster-oss mcp`), prefer its tools:
`foster_check_package`, `foster_scan_project`, `foster_list_patches`.

## How to read the results

| Finding | Meaning | What to do |
|---|---|---|
| `PATCH READY` | A published drop-in patch exists for this exact version | Show the user, then `foster-oss fix` (ask before editing package.json) |
| `ORPHANED+VULN` | Known vulnerability, no fix anywhere, package dead or dormant | Prefer a maintained alternative; otherwise tell the user it can be nominated for adoption |
| `NO FIX YET` | Known vulnerability, no fix released, but the package seems maintained | Watch for a release; consider mitigations |
| `UPGRADE` | Fixed upstream | Upgrade normally; Foster is not needed |
| `ORPHANED` | Widely used, unmaintained, no known vulnerability | Informational. Avoid for *new* code; a `consider:` line names maintained replacements when known |
| "not found" | The name does not exist on the registry | Likely a typo or hallucinated package: do **not** install it |

## Before running an install command

Run `npx -y foster-oss guard -- <the exact command>` (or the MCP tool `foster_check_install_command`).
If it says **deny**, do not run the command: tell the user why and offer the suggested alternative or a
fixed version. If it says **ask**, show the user the reason and let them decide.

## Rules

- Never run `foster-oss fix` without telling the user what will change; run `--dry-run` first.
- After `fix`, run the project's install command and its tests.
- "Dormant" is a signal, not a verdict: small finished libraries can be dormant and fine. Only
  call something risky when it is dormant **and** vulnerable, or when the user is choosing a new dependency.
- Do not suggest replacing a dependency just because it is dormant unless the user asked about maintenance.
