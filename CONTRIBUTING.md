# Contributing

Thanks for helping. The most valuable contributions, in order:

1. **Review a patch.** Read a small diff under `patches/`, run `node scripts/build-patch.mjs <eco>/<name>`,
   and comment. Careful reviews are how people become reviewers (see GOVERNANCE.md).
2. **Write a patch** for a package in the adoption queue ([patches/README.md](patches/README.md)).
3. **Nominate a package** with the issue template.
4. **Improve the CLI**: more lockfile formats, more ecosystems (Cargo, Go, Maven, RubyGems…),
   `fix` support for Python.
5. **Correct the index**: if a package is wrongly marked dead or dormant, open an issue with evidence.
   Better rules in `classify.ts` are welcome, with tests.

## Development

```bash
npm ci
npm run build        # TypeScript → dist/
npm test             # unit tests (vitest)
node dist/cli.js scan test/fixtures/npm-v3 --offline --include-staged
npm run index:build  # rebuild the Orphan Index (takes a few minutes, calls ecosyste.ms)
```

## Writing a patch

```
patches/<ecosystem>/<name>/
  foster.json      metadata: upstream version, replacement name/version, advisories, changed files, status
  fix.patch        unified diff against the upstream release, paths relative to the package root
  test/*.test.cjs  node:test tests; load the package from process.env.FOSTER_TARGET
  ADOPTION.md      the problem, the fix, behaviour changes, verification, contact log, reviews
```

1. `npm pack <name>@<version>` and unpack it twice (original and working copy).
2. Write the smallest fix in the working copy. Generate `fix.patch` with `diff -u`, then rewrite the
   header lines to `--- a/<file>` and `+++ b/<file>`.
3. Write tests that reproduce the advisory. Run `node scripts/build-patch.mjs <eco>/<name>`. It
   fails if your tests pass on the unpatched release, or if the patch touches files not listed in `foster.json`.
4. Add an entry to `registry/patches.json` with status `staged`.
5. Open a PR and disclose any AI assistance.

## Style

TypeScript, strict mode, no new runtime dependencies without discussion. Keep messages in the CLI
short and actionable. Every rule change in `classify.ts` must update METHODOLOGY.md.

By contributing you agree that your contributions are licensed under Apache-2.0 (patches to
upstream packages: under the upstream package's license).
