# Security policy

## Reporting a problem in Foster

Use GitHub's private vulnerability reporting:
<https://github.com/foster-oss/foster/security/advisories/new>.
Please do not open public issues for vulnerabilities in Foster's code, workflows or published patches.

We aim to acknowledge within 3 days and to publish a fix or mitigation within 30 days.

## Reporting a problem in an orphaned package

If the package is unmaintained and the issue is already public (a published advisory), nominate it
with the "Nominate a package for adoption" issue template.

If it is **not yet public**, report it privately to the GitHub Advisory Database or the ecosystem's
security team first (npm: <https://github.com/advisories>, PyPI: security@python.org). Foster only
works on publicly disclosed issues.

## How Foster protects its releases

- Patched packages are rebuilt in CI from the upstream registry tarball plus the public `fix.patch`;
  nothing is published from a laptop.
- Publishing uses npm trusted publishing (OIDC) with provenance; no long-lived npm tokens exist.
- Upstream install scripts are removed from patched packages.
- Releases require two human approvals (see GOVERNANCE.md).
