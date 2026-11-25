# Patch Lab

Foster's first job is to **connect** orphaned, vulnerable dependencies to fixes that already exist
(see `registry/patches.json`). The Patch Lab is the last resort, for packages that are orphaned,
vulnerable and have **no published patch anywhere**. Before starting one, check the registry,
[Keep LTS](https://keep-lts.com), the upstream issue tracker (open PRs often contain a fix) and
maintained forks. Duplicating an existing patch helps nobody.

Each folder is one adoption: `patches/<ecosystem>/<name>/`. See CONTRIBUTING.md for the layout and
GOVERNANCE.md for the rules. Verify any patch yourself:

```bash
node scripts/build-patch.mjs npm/ip          # rebuild from upstream, apply, test
node scripts/build-patch.mjs npm/ip --pack   # also produce the tarball in dist/
```

## Status

| Package | Advisory | Status | Record |
|---|---|---|---|
| npm `ip` 2.0.1 | GHSA-2p57-rm9w-gvfp, CVE-2025-59436 | retired: superseded by `@keep-lts/ip@2.0.2` | [ADOPTION.md](npm/ip/ADOPTION.md) |

## Open gaps (orphaned, vulnerable, no patch anywhere)

From the Orphan Index (November 2026):

| Package | Downloads / month | Advisories | Notes |
|---|---|---|---|
| npm `elliptic` 6.6.1 | 74M | [GHSA-848j-6mx2-7j84](https://github.com/advisories/GHSA-848j-6mx2-7j84) (LOW) | Cryptography: needs a reviewer with crypto expertise; may be better solved by migration guidance. |
| npm `request` 2.88.2 | (not in critical set) | [GHSA-p8p7-x288-28g6](https://github.com/advisories/GHSA-p8p7-x288-28g6) (MODERATE) | Deprecated since 2020; SSRF via cross-protocol redirects. Large long tail of users. |
| npm `aws-sdk` 2.x | 48M | [GHSA-j965-2qgj-vjmq](https://github.com/advisories/GHSA-j965-2qgj-vjmq) (LOW) | End of life by AWS; the right answer is migrating to v3, not a patch. |

Already covered elsewhere: `extract-zip` and `ip` (Keep LTS).
