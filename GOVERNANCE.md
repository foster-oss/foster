# Governance

Foster publishes code that millions of projects may run. Taking over abandoned packages is also
exactly what supply-chain attackers do (see xz-utils, 2024). These rules exist so that Foster is
the trustworthy version of that, and they come first, before speed or growth.

## Principles

1. **Patch, don't take over.** Foster never claims an existing package name. Patches ship under
   `@foster-oss/*`. A registry name transfer (e.g. PyPI PEP 541) is only requested when the
   community asks for it and the registry's own process approves it.
2. **Upstream first.** Every patch is offered to the original project before Foster releases anything.
3. **Smallest possible diff.** Security and breakage fixes only. No features, refactors, style
   changes or dependency bumps that the fix does not need.
4. **AI proposes, humans decide.** See [AI_POLICY.md](AI_POLICY.md).
5. **Reproducible and auditable.** Anyone can rebuild a Foster release from the upstream registry
   tarball plus the public `fix.patch` and get the same files.
6. **No single person.** Foster must never depend on one maintainer (the lesson of Jazzband's 2026 wind-down).
7. **Leave when no longer needed.** When upstream ships a fix or a new maintainer appears, Foster
   retires its patch and points people back upstream.

## Roles

- **Contributors**: anyone opening issues or PRs.
- **Reviewers**: people trusted to approve patches. Listed in `MAINTAINERS.md` with their organisation.
  Added by consensus of existing maintainers after a track record of careful reviews.
- **Maintainers**: reviewers who can also merge and trigger releases. At least **three**, from at
  least **two different organisations**, before the first patch release.

There is no open membership with push access. Contributions come through pull requests only.

## Adopting a package

All must be true:

1. The package is in the ecosyste.ms critical set **or** has more than 1,000 dependent packages or repositories.
2. It has a real, unfixed problem: a published advisory with no fixed release (see
   [METHODOLOGY.md](METHODOLOGY.md)), or a breakage that blocks security updates elsewhere.
3. It is dead or dormant per the methodology, and the problem has gone unanswered upstream.
4. Its license allows modification and redistribution.

Process:

1. **Nominate**: issue using the "Nominate a package for adoption" template.
2. **Patch**: PR adding `patches/<ecosystem>/<name>/` with `fix.patch`, `foster.json`,
   tests and `ADOPTION.md`. CI rebuilds and verifies it.
3. **Review**: two approvals from reviewers in different organisations. Reviewers check that the
   diff is minimal, the tests fail on the original and pass on the patch, and the behaviour changes
   are documented.
4. **Contact upstream**: open a PR or issue upstream with the patch and email the listed maintainer.
   Log every attempt in `ADOPTION.md`.
5. **Wait six weeks.** If upstream merges and releases: close the adoption, no Foster release.
6. **Release**: a reviewed PR sets the status to `released`; a maintainer runs the
   `release-patch` workflow, which needs approval from a second maintainer in the `patch-release`
   environment. The package is rebuilt and re-verified in CI and published with provenance.
7. **Retire**: when upstream fixes it, set the status to `retired`. `foster-oss scan` stops
   recommending the patch and reports "upgrade" instead.

**Emergency path**: for an actively exploited critical vulnerability, maintainers may shorten the
six-week window to 7 days after contact attempts, with the reason recorded in `ADOPTION.md`.

## Decisions

Day-to-day decisions: lazy consensus on GitHub (72 hours, no objection). Adding or removing
maintainers, changing these rules, or accepting funding: explicit approval from a majority of
maintainers, recorded in an issue.

## Funding

Money must never buy a release, a priority, or a seat. Funding sources are listed publicly in the README.
