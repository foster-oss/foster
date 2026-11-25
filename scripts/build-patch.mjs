// Build and verify one Foster patch.
//
//   node scripts/build-patch.mjs npm/ip [--pack]
//
// 1. downloads the exact upstream release from the registry (npm pack)
// 2. applies patches/<eco>/<name>/fix.patch
// 3. checks the patch only touched the files listed in foster.json
// 4. renames the package to the Foster replacement name/version
// 5. runs Foster's advisory tests, then the upstream test suite (if configured)
// 6. with --pack, writes the tarball to patches/<eco>/<name>/dist/ and prints its sha512
//
// The same script runs in CI for every pull request and in the release workflow.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const [target, ...flags] = process.argv.slice(2);
if (!target) {
  console.error("usage: node scripts/build-patch.mjs <ecosystem>/<name> [--pack]");
  process.exit(2);
}
const pack = flags.includes("--pack");
const patchDir = join(root, "patches", target);
const meta = JSON.parse(readFileSync(join(patchDir, "foster.json"), "utf8"));
if (meta.ecosystem !== "npm") throw new Error("only npm patches can be built automatically for now");

const isWin = process.platform === "win32";
const run = (cmd, args, cwd, extraEnv = {}) =>
  execFileSync(cmd, args, { cwd, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, ...extraEnv }, shell: isWin && cmd === "npm" }).toString();

const work = mkdtempSync(join(tmpdir(), "foster-build-"));
const step = (s) => console.log(`\n▶ ${s}`);
try {
  step(`fetching ${meta.name}@${meta.upstreamVersion} from the registry`);
  const tgz = run("npm", ["pack", `${meta.name}@${meta.upstreamVersion}`, "--silent"], work).trim().split(/\r?\n/).pop();
  run("tar", ["xzf", tgz], work);
  const upstream = join(work, "upstream");
  cpSync(join(work, "package"), upstream, { recursive: true });
  const pkgDir = join(work, "package");

  step("applying fix.patch");
  run("git", ["apply", "--verbose", join(patchDir, "fix.patch")], pkgDir);

  step("checking the patch stays minimal");
  const changed = diffFiles(upstream, pkgDir);
  const unexpected = changed.filter((f) => !meta.files.includes(f));
  if (unexpected.length) throw new Error(`patch touched files not listed in foster.json: ${unexpected.join(", ")}`);
  console.log(`  changed: ${changed.join(", ") || "(nothing!)"}`);
  if (changed.length === 0) throw new Error("patch changed nothing");

  step(`renaming to ${meta.replacement.name}@${meta.replacement.version}`);
  const pkgJsonPath = join(pkgDir, "package.json");
  const pkg = JSON.parse(readFileSync(pkgJsonPath, "utf8"));
  const upstreamName = pkg.name;
  pkg.name = meta.replacement.name;
  pkg.version = meta.replacement.version;
  pkg.description = `Foster security patch of ${upstreamName}@${meta.upstreamVersion} (${meta.advisories.join(", ")}). ${pkg.description ?? ""}`.trim();
  pkg.foster = {
    upstream: `${upstreamName}@${meta.upstreamVersion}`,
    advisories: meta.advisories,
    patch: `https://github.com/rekalnx/foster/tree/main/patches/${target}`,
  };
  pkg.publishConfig = { access: "public", provenance: true };
  delete pkg.scripts; // never run upstream lifecycle scripts from a Foster release
  writeFileSync(pkgJsonPath, JSON.stringify(pkg, null, 2) + "\n");
  writeFileSync(
    join(pkgDir, "FOSTER.md"),
    `# ${meta.replacement.name}@${meta.replacement.version}\n\n` +
      `This is \`${upstreamName}@${meta.upstreamVersion}\` with one security fix applied by Foster.\n\n` +
      `- Fixes: ${meta.advisories.map((a) => `https://github.com/advisories/${a}`).join(", ")}\n` +
      `- What changed: ${meta.summary}\n` +
      `- Exact diff, tests and review history: https://github.com/rekalnx/foster/tree/main/patches/${target}\n\n` +
      `Use it without changing your imports:\n\n\`\`\`json\n{ "overrides": { "${upstreamName}": "npm:${meta.replacement.name}@${meta.replacement.version}" } }\n\`\`\`\n\n` +
      `or run \`npx foster-oss fix\`.\n`,
  );
  if (Array.isArray(pkg.files) && !pkg.files.includes("FOSTER.md")) {
    pkg.files.push("FOSTER.md");
    writeFileSync(pkgJsonPath, JSON.stringify(pkg, null, 2) + "\n");
  }

  step("running Foster advisory tests");
  const testDir = join(patchDir, "test");
  const testFiles = readdirSync(testDir).filter((f) => /\.test\.c?js$/.test(f)).map((f) => join(testDir, f));
  console.log(run(process.execPath, ["--test", "--test-reporter=spec", ...testFiles], root, { FOSTER_TARGET: pkgDir }).split(/\r?\n/).filter((l) => /^ℹ (tests|pass|fail)/.test(l)).join("\n"));

  step("checking the advisory reproduces on the unpatched release");
  let reproduced = false;
  try {
    run(process.execPath, ["--test", ...testFiles], root, { FOSTER_TARGET: upstream });
  } catch {
    reproduced = true;
  }
  if (!reproduced) throw new Error("advisory tests pass on the unpatched release: they do not test the vulnerability");
  console.log("  ok: tests fail on the original, pass on the patch");

  if (meta.upstreamTests) {
    step("running the upstream test suite against the patch");
    const res = await fetch(meta.upstreamTests.url, { headers: { "User-Agent": "foster-oss build" } });
    if (!res.ok) throw new Error(`could not download upstream tests: HTTP ${res.status}`);
    const testPath = join(pkgDir, meta.upstreamTests.path);
    mkdirSync(dirname(testPath), { recursive: true });
    writeFileSync(testPath, await res.text());
    const shim = join(work, "run-upstream.cjs");
    writeFileSync(shim, 'const { describe, it } = require("node:test"); global.describe = describe; global.it = it; require(process.argv[2]);\n');
    let out = "";
    try {
      out = run(process.execPath, ["--test-reporter=spec", shim, testPath], pkgDir);
    } catch (err) {
      out = String(err.stdout ?? "");
    }
    // node's spec reporter ends with a "failing tests:" list containing only the failed leaf tests.
    const failingSection = out.split("failing tests:")[1] ?? "";
    const failed = [...new Set([...failingSection.matchAll(/^\s*✖ (.+?) \(\d/gm)].map((m) => m[1].trim()))];
    const unexpectedFailures = failed.filter((n) => !(meta.upstreamTests.knownFailures ?? []).includes(n));
    console.log(out.split(/\r?\n/).filter((l) => /^ℹ (tests|pass|fail)/.test(l)).join("\n"));
    if (unexpectedFailures.length) throw new Error(`upstream tests failed: ${unexpectedFailures.join("; ")}`);
    if (failed.length) console.log(`  known, environment-dependent failures: ${(meta.upstreamTests.knownFailures ?? []).join("; ")}`);
    rmSync(join(pkgDir, "test"), { recursive: true, force: true }); // not part of the published package
  }

  if (pack) {
    step("packing");
    const outDir = join(patchDir, "dist");
    mkdirSync(outDir, { recursive: true });
    const file = run("npm", ["pack", "--silent", "--pack-destination", outDir], pkgDir).trim().split(/\r?\n/).pop();
    const bytes = readFileSync(join(outDir, file));
    console.log(`  ${relative(root, join(outDir, file))}`);
    console.log(`  sha512-${createHash("sha512").update(bytes).digest("base64")}`);
  }
  console.log(`\n✔ ${meta.replacement.name}@${meta.replacement.version} verified`);
} finally {
  rmSync(work, { recursive: true, force: true });
}

function diffFiles(a, b) {
  const files = new Set([...walk(a), ...walk(b)].map((p) => p));
  const changed = [];
  for (const f of files) {
    const pa = join(a, f);
    const pb = join(b, f);
    if (!existsSync(pa) || !existsSync(pb) || !readFileSync(pa).equals(readFileSync(pb))) changed.push(f);
  }
  return changed.sort();
}

function walk(dir, base = dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(join(dir, e.name), base) : [relative(base, join(dir, e.name)).replace(/\\/g, "/")],
  );
}
