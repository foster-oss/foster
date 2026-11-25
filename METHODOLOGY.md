# Methodology

How the Orphan Index and `foster-oss scan` decide what is "dead", "dormant" and "unpatched".
The code is in [`src/lib/classify.ts`](src/lib/classify.ts) and [`src/lib/scan.ts`](src/lib/scan.ts);
this document must change whenever that code does.

## Which packages

The index covers the **ecosyste.ms critical set** for npm, PyPI, crates.io (Cargo), the Go module proxy, RubyGems and Packagist: the top packages per registry
by a blend of downloads and dependent repositories (2,295 npm + 522 PyPI packages in November 2026).
`foster-oss scan` also looks up, live, any package in your lockfile that has a vulnerability with no
fixed version, even if it is not in the critical set.

## Maintenance status

Inputs, all public, from `packages.ecosyste.ms`: registry status, latest release date, source
repository (archived flag, last push), and issue/PR counts for the past year.

Rules, applied in order:

| Status | Rule |
|---|---|
| **dead** | The registry marks the package deprecated or removed. |
| **dead** | The source repository is archived. |
| **dead** | Issues or PRs were opened in the past year, **none** were closed or merged, and there was no push and no release in the past year. |
| **dormant** | No release and no push in the past year. (Also: no linked repository and no release for 2+ years.) |
| **unknown** | No linked repository and a release within 2 years, or no activity data at all. |
| **active** | Everything else. |

Differences from Andrew Nesbitt's buckets: his "dead" uses *no response from someone with write
access*; ecosyste.ms does not expose who responded, so Foster uses *no closes and no merges* as the
proxy and additionally requires no push and no release, to avoid calling a quiet-but-alive project dead.

**These are signals, not verdicts.** A tiny library can be *finished* rather than abandoned. Foster
only proposes action when a package is unmaintained **and** has a real problem nobody can fix.

## "Advisory with no fix"

An advisory counts as unfixed for a package only when all of these hold:

1. it is not withdrawn;
2. it is not a malware or hijacked-release report (GitHub classification `MALWARE`, or a title
   mentioning malware, compromise, hijack, protestware, sabotage). Those need "avoid that
   version", not a patch, and are already flagged by `npm audit`;
3. no patched version is published for it;
4. **the latest release is still inside the vulnerable range**. If a newer release escapes the range,
   upgrading fixes it, even when the advisory database never recorded a "patched version".

Rules 2 and 4 matter: with only rules 1 and 3, 46 advisories in the November 2026 snapshot looked
unfixed (most were hijacked-release reports or old ranges that newer releases escape); with all four, 5
remain, all in unmaintained packages.

In `scan`, the same logic runs on [OSV](https://osv.dev) data for your exact installed versions:
an OSV `fixed` event means "upgrade"; a `last_affected` bound below the newest release also means
"upgrade"; anything else is "no fix".

## Priority score

Used to order the index (higher = more people exposed to an unmaintained, vulnerable package):

```
reach    = log10(1 + dependentRepos + 10 × dependentPackages + downloadsPerMonth / 1000)
priority = reach × statusWeight × advisoryWeight
statusWeight:   dead 3 · dormant 2 · unknown 1 · active 0
advisoryWeight: most severe unfixed advisory: critical 10 · high 7 · moderate 4 · low 1 · none 1
```

Active packages always score 0: Foster is not for packages that have a maintainer.

## Headline numbers

`data/stats.json` sums, over dead + dormant packages, the downloads in the last month and the
dependent repositories reported by ecosyste.ms. Downloads include CI and mirrors and are not
unique users. Dependent repository counts come from ecosyste.ms' repository dependency graph and
overlap between packages (one repository depending on 50 orphaned packages counts 50 times).

## Known limitations

- Six ecosystems so far (npm, PyPI, Cargo, Go, RubyGems, Packagist); Maven, NuGet and others are not covered yet.
- Only the critical set is classified in bulk; long-tail packages are looked up on demand.
- Issue activity is a proxy; a maintainer who reads everything but closes nothing looks "dead".
- Advisory ranges that cannot be parsed are kept (counted as unfixed) to err on the side of caution.
- PyPI version comparison is numeric, not full PEP 440.

## Replacement suggestions

For npm packages, `scan` and `check` suggest maintained replacements (built-in APIs such as `fetch`
or `structuredClone`, smaller maintained packages, or a one-line snippet) using the e18e community's
[module-replacements](https://github.com/e18e/module-replacements) dataset (MIT). Suggestions are
shown for every finding except plain upgrades, and link to the e18e migration guide when one exists.
