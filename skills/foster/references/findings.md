# Foster findings

## guard reasons

| Reason | Decision | Meaning |
|---|---|---|
| known malware | deny | The package or this exact release is in OSV / the OpenSSF malicious-packages database. |
| does not exist | deny | The name is not on the registry: a typo or a hallucinated name, which attackers register ("slopsquatting"). |
| vulnerability no release fixes | deny | Known advisory and no fixed version anywhere; Foster names maintained alternatives when it knows them. |
| malware or squat in the lockfile | deny | The lockfile itself would install something malicious or non-existent. |
| look-alike | ask | The name is one edit away from a far more popular package (`expres` vs `express`). |
| new package with install scripts | ask | Published in the last 30 days and runs code on install. |
| release adds an install script | ask | This version runs install code the previous one did not, a common sign of a hijacked release. |
| URL / git / tarball source | ask | Not a registry package, so it cannot be checked. |
| vulnerable version with a fix | ask | Typed directly on the command line; suggest the fixed version. |
| dead / dormant, upgrade available | allow, with a note | Mention it if the user is choosing a new dependency. |

## scan findings

| Finding | Meaning | What to do |
|---|---|---|
| `MALWARE` | Known malicious package or hijacked release | Stop. Tell the user to remove it now and rotate credentials and tokens the machine or CI can reach. |
| `PATCH READY` | A published drop-in patch exists for this exact version | Show the user, then `foster-oss fix` (ask before editing package.json). |
| `ORPHANED+VULN` | Known vulnerability, no fix anywhere, package dead or dormant | Prefer a maintained alternative; otherwise it can be nominated for adoption. |
| `NO FIX YET` | Known vulnerability, no fix released, package seems maintained | Watch for a release; consider mitigations. |
| `UPGRADE` | Fixed upstream | Upgrade normally. |
| `ORPHANED` | Widely used, unmaintained, no known vulnerability | Informational. Avoid for new code; a `consider:` line names maintained replacements. |

## Other commands

- `foster-oss check <name>[@version] [--ecosystem …]`: one package.
- `foster-oss scan --sbom <file>`: a CycloneDX or SPDX JSON SBOM.
- `foster-oss scan --since <git-ref>`: only dependencies added or changed since a ref (pull requests).
- `foster-oss fix <dir>`: point dependencies at released drop-in patches; run the project's install and tests afterwards.
- Exit codes for `scan`: 1 when findings reach `--fail-on` (default: malware).
