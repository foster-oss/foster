# Security policy

## Reporting a problem in Foster

Use GitHub's private vulnerability reporting:
<https://github.com/rekalnx/foster/security/advisories/new>.
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

## Trust model of the CLI

- `foster-oss` downloads the patch registry and the Orphan Index from this repository's `main`
  branch (falling back to the copy bundled in the npm release). Changes to `registry/` only land
  through reviewed pull requests, and CI validates every entry.
- `foster-oss fix` only rewrites `package.json`; it never installs anything. Run it with
  `--dry-run` first, read the provider's source for each patch it proposes, then install yourself.
- Set `FOSTER_REGISTRY_URL` / `FOSTER_INDEX_URL` to pin your own reviewed copies, or use
  `--offline` to rely only on the data bundled in the release you installed.
