# Patch Lab

Each folder is one adoption: `patches/<ecosystem>/<name>/`. See CONTRIBUTING.md for the layout and
GOVERNANCE.md for the rules. Verify any patch yourself:

```bash
node scripts/build-patch.mjs npm/ip          # rebuild from upstream, apply, test
node scripts/build-patch.mjs npm/ip --pack   # also produce the tarball in dist/
```

## Status

| Package | Advisory | Status | Record |
|---|---|---|---|
| npm `ip` 2.0.1 | GHSA-2p57-rm9w-gvfp (HIGH) | staged | [ADOPTION.md](npm/ip/ADOPTION.md) |

## Adoption queue

From the Orphan Index (November 2026): packages in the critical set, unmaintained, with advisories
that no release fixes. Pick one, open an issue saying you are working on it, then a PR.

| Package | Downloads / month | Advisories | Notes |
|---|---|---|---|
| npm `extract-zip` 2.0.1 | 113M | [GHSA-7pqw-9j4j-h8q3](https://github.com/advisories/GHSA-7pqw-9j4j-h8q3), [GHSA-jmr9-qjv8-65gv](https://github.com/advisories/GHSA-jmr9-qjv8-65gv) (HIGH) | Symlink entries allow writes outside the target directory. Highest-impact candidate. |
| npm `elliptic` 6.6.1 | 74M | [GHSA-848j-6mx2-7j84](https://github.com/advisories/GHSA-848j-6mx2-7j84) (LOW) | Cryptography: needs a reviewer with crypto expertise; may be better solved by migration guidance. |
| npm `aws-sdk` 2.x | 48M | [GHSA-j965-2qgj-vjmq](https://github.com/advisories/GHSA-j965-2qgj-vjmq) (LOW) | v2 is end-of-life by AWS; the right answer is migrating to v3. Probably *not* a Foster adoption. |
| npm `request` 2.88.2 | (not in critical set) | [GHSA-p8p7-x288-28g6](https://github.com/advisories/GHSA-p8p7-x288-28g6) (MODERATE) | Deprecated since 2020; SSRF via cross-protocol redirects. Large long tail of users. |

Not everything unmaintained should be adopted: deprecated-by-design packages with a maintained
successor (like `aws-sdk` v2) are better served by migration docs.
