# Foster

**A foster home for open source packages nobody maintains anymore.**

Foster finds the dependencies in your project that have been abandoned, tells you which of them
have security holes that *no release fixes*, and lets you swap in a reviewed, minimal Foster patch
with one command, without changing a single import and without taking anyone's package name.

```bash
npx foster-oss scan        # what in my lockfile is orphaned, or vulnerable with no fix?
npx foster-oss fix         # switch to reviewed Foster patches (edits package.json)
npx foster-oss check ip@2.0.1
```

## Why

We classified the **2,817 most depended-on packages** on npm and PyPI (the
[ecosyste.ms](https://ecosyste.ms) critical set) in November 2026:

- **28% are unmaintained**: 229 dead and 561 dormant ([methodology](METHODOLOGY.md)).
- Those unmaintained packages are downloaded **~190 billion times a month** and back
  **~885 million** dependent repositories.
- **497** of them can only be published by a single account.
- **4 of them have security advisories that no release fixes**, together downloaded ~270 million times a month:

| Package | Downloads / month | Advisory with no fix | Status |
|---|---|---|---|
| `extract-zip` | 113M | 2 × HIGH: symlink path traversal / arbitrary file write | dormant |
| `elliptic` | 74M | LOW: risky cryptographic primitive | dormant |
| `aws-sdk` (v2) | 48M | LOW: region parameter validation | dead (end of life) |
| `ip` | 38M | HIGH: SSRF, `isPublic()` misclassifies `127.1`, `::fFFf:127.0.0.1`, … | dormant, **Foster patch ready** |

Detection tools already exist. Upgrade bots (Dependabot, Renovate) can't help when no fixed version
exists. Registries' abandonment policies are about *taking over names*, when what people need is
*one fixed release*. And Jazzband, the best-known cooperative for adopting orphaned Python
projects, wound down in 2026. Foster is the missing piece: **a public, auditable way to patch →
review → release → deliver fixes for critical packages nobody maintains.**

The full numbers are in the [Orphan Index](site/index.html) ([JSON](data/orphans.json),
[CSV](data/orphans.csv)), rebuilt weekly.

## How it works

```
Orphan Index ──► Patch Lab ──► upstream PR first ──► @foster-oss/<name> ──► foster-oss fix
(public data)    (minimal fix,   (6-week window;        (provenance,           (npm alias override,
                  2 reviewers)    released only if       reproducible from      imports unchanged)
                                  nobody answers)        upstream + patch)
```

1. **Orphan Index.** Every week, Foster classifies the critical package set as active / dormant /
   dead from public signals, and lists advisories that no release fixes.
2. **Patch Lab.** A patch is the smallest diff that fixes the advisory, nothing else. Its tests must
   *fail on the original release* and pass on the patch, and the upstream test suite must still pass.
   AI may draft it; two human reviewers from different organisations approve it.
3. **Upstream first.** The patch is offered to the original repository. Foster only releases its
   own package if upstream has not responded after six weeks, and steps back the moment upstream ships a fix.
4. **Release.** `@foster-oss/<name>` is rebuilt in CI from the upstream registry tarball plus the
   public `fix.patch`, and published with npm provenance. No upstream install scripts are kept.
5. **Delivery.** `foster-oss fix` points your project at the patch through an npm alias
   (`"ip": "npm:@foster-oss/ip@2.0.1-foster.1"`), so `require("ip")` keeps working.

## Usage

### CLI

Node 20+. Reads `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`
(classic and berry), `uv.lock` and pinned `requirements.txt`.

| Command | What it does |
|---|---|
| `foster-oss scan [dir]` | Report orphaned and unpatched dependencies. `--json`, `--markdown`, `--all`, `--fail-on <level>`, `--offline` |
| `foster-oss fix [dir]` | Point dependencies at released Foster patches. `--dry-run`, `--force` |
| `foster-oss check <name[@version]>` | Maintenance status, reach, unfixed advisories and patches for one package. `--ecosystem pypi` |
| `foster-oss mcp` | Start the MCP server for AI agents |

What the findings mean:

| Finding | Meaning |
|---|---|
| `FOSTER PATCH` | A reviewed Foster patch exists for this exact version. Run `foster-oss fix`. |
| `ORPHANED+VULN` | Known vulnerability, no fix anywhere, package dead or dormant. Prefer an alternative, or [nominate it](https://github.com/foster-oss/foster/issues/new?template=adopt.yml). |
| `NO FIX YET` | Known vulnerability with no release yet, but the package looks maintained. |
| `UPGRADE` | Fixed upstream. Just upgrade; Foster is not needed. |
| `ORPHANED` | Widely used and unmaintained, no known vulnerability. Shown with `--all`. |

`fix` is npm-ecosystem only for now (npm, pnpm, yarn). Python projects get findings and manual instructions.

### GitHub Action

```yaml
- uses: foster-oss/foster@v0
  with:
    fail-on: orphaned-vulnerable   # none | patch-available | orphaned-vulnerable | unpatched | any
    comment: true                  # optional PR comment; needs pull-requests: write
```

The report is also written to the job summary.

### AI agents

**MCP** (Claude Code, Codex, Cursor, …):

```json
{ "mcpServers": { "foster": { "command": "npx", "args": ["-y", "foster-oss", "mcp"] } } }
```

Tools: `foster_check_package` (call it before adding a dependency; it also catches names that
don't exist, a common sign of a hallucinated package), `foster_scan_project`, `foster_list_patches`.

**Skill**: copy [`skills/foster`](skills/foster/SKILL.md) into your agent's skills folder
(e.g. `.claude/skills/foster/`).

### Library

```ts
import { scanProject, checkPackage } from "foster-oss";
const result = await scanProject("./my-app");
```

## Patches

| Package | Replaces | Fixes | Status |
|---|---|---|---|
| [`@foster-oss/ip`](patches/npm/ip/ADOPTION.md) | `ip` ≤ 2.0.1 | GHSA-2p57-rm9w-gvfp (HIGH, SSRF) | staged: verified, waiting for upstream window and reviewers |

Next in the queue: `extract-zip` (2 × HIGH). See [patches/README.md](patches/README.md).

## Contributing

Foster needs reviewers more than anything: people who can read a small security diff and say
"yes, this is correct and minimal". Also wanted: patch authors, adapters for more ecosystems,
and corrections to the index. Start with [CONTRIBUTING.md](CONTRIBUTING.md).

Foster's rules are in [GOVERNANCE.md](GOVERNANCE.md), its stance on AI-written code in
[AI_POLICY.md](AI_POLICY.md), and how to report a problem in Foster itself in [SECURITY.md](SECURITY.md).

## Data and credits

Maintenance and reach data: [ecosyste.ms](https://ecosyste.ms) (CC BY-SA 4.0). Vulnerabilities:
[OSV.dev](https://osv.dev) and the GitHub Advisory Database. The dead/dormant buckets follow
Andrew Nesbitt's [“Weekend at Bernie's”](https://nesbitt.io/2026/05/08/weekend-at-bernies) analysis.

Code: [Apache-2.0](LICENSE). Each patched package keeps its original license.
