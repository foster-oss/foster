# Adoption record: `ip` (npm)

| | |
|---|---|
| Upstream | [`ip`](https://www.npmjs.com/package/ip) · [indutny/node-ip](https://github.com/indutny/node-ip) |
| Upstream version patched | 2.0.1 (latest, released 2024-02-19) |
| Replacement | `@foster-oss/ip@2.0.1-foster.1` |
| Advisory | [GHSA-2p57-rm9w-gvfp](https://github.com/advisories/GHSA-2p57-rm9w-gvfp) / CVE-2024-29415, severity HIGH |
| Status | **staged**: patch written and verified, waiting for upstream contact window and two reviewers |
| Reach (ecosyste.ms, Nov 2026) | ~38M downloads/month · ~2.9M dependent repos · ~4.2K dependent packages |
| Maintenance (Orphan Index) | dormant: no release for 2.8 years, no push for 2.3 years |

## The problem

`ip.isPublic()` and `ip.isPrivate()` decide whether an address is internal by matching
regular expressions against the *string*. The same address can be written many ways, and
HTTP clients (anything following the WHATWG URL standard, including Node's `fetch`) accept them all:

| Input | What `fetch` connects to | `ip@2.0.1` `isPublic()` |
|---|---|---|
| `127.1` | 127.0.0.1 | `true` ❌ |
| `012.1.2.3` | 10.1.2.3 | `true` ❌ |
| `01200034567` | 10.0.57.119 | `true` ❌ |
| `000:0:0000::01` | ::1 | `true` ❌ |
| `::fFFf:127.0.0.1` | ::ffff:127.0.0.1 | `true` ❌ |
| `0.0.0.0` | the local host | `true` ❌ |

Code that uses `isPublic()` as an SSRF guard ("only fetch public URLs") can therefore be
pointed at loopback, private networks, or cloud metadata endpoints. This was an incomplete
fix of CVE-2023-42282. No fixed version of `ip` exists.

A second root cause: `isV6Format()` matches any string of hex digits, so a bare number like
`01200034567` was treated as IPv6 and skipped the IPv4 normalisation entirely.

## The fix

`lib/ip.js` only, see [`fix.patch`](fix.patch). `isPrivate`, `isPublic` and `isLoopback` now:

1. parse the address into a number first: IPv4 with the library's own `normalizeToLong`
   (decimal, octal, hex and shorthand forms), IPv6 through Node's WHATWG URL parser, so the
   library sees exactly what an HTTP client would connect to;
2. pick IPv4 vs IPv6 by the presence of `:` instead of `isV6Format()`;
3. unwrap IPv4 embedded in IPv6 (mapped `::ffff:0:0/96`, compatible `::/96`, NAT64 `64:ff9b::/96`);
4. check ranges numerically.

Deliberate behaviour changes, all in the direction of "not public":

- `0.0.0.0/8` is now private (on Linux, connecting to 0.0.0.0 reaches the local host).
- `fe80::/10` is private as a whole, not only addresses starting with the text `fe80:`.
- IPv4 addresses inside NAT64 / IPv4-compatible IPv6 are classified by their IPv4 part.

Unchanged: the same private ranges as before, `isPrivate()` still throws on invalid input,
`isLoopback()` still returns `true` for `::` and `fe80::1` (as 2.0.1 did), every other function is untouched.

## Verification

`node scripts/build-patch.mjs npm/ip` (runs in CI):

- Foster advisory tests: 7/7 pass on the patch, and **fail on the original 2.0.1** (proves they test the bug).
- Upstream test suite (`test/api-test.js` from the repository): 90/91 pass, identical to the
  unpatched release. The one failure, `address('private', 'ipv6')`, depends on the machine's
  network interfaces and fails the same way on 2.0.1 when the host has a public IPv6 address.
- End-to-end: in a project depending on `socks@2.7.1` (which depends on `ip`), an npm
  `overrides` entry made `socks` load the patched code, with `isPublic('127.1') === false`.

## Upstream contact log

Foster's rule (GOVERNANCE.md): a patch is only released after upstream has had 6 weeks to respond.

| Date | Action | Result |
|---|---|---|
| _pending_ | Comment on the advisory discussion / open a PR at indutny/node-ip with this patch | |
| _pending_ | Email the maintainer listed on npm | |
| _pending + 6 weeks_ | Decide: release `@foster-oss/ip` or close if upstream released a fix | |

Note for reviewers: the maintainer has publicly disputed parts of the earlier CVE. Keep the
contact respectful, credit the original work, and offer the patch as a PR first. If upstream
ships a fix, this adoption is closed and `foster-oss fix` will point people at the upstream release instead.

## Reviews

Two approvals from reviewers in different organisations are required before release.

| Reviewer | Organisation | Date | Verdict |
|---|---|---|---|
| | | | |
| | | | |
