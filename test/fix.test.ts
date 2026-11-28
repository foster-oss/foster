import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parse } from "yaml";
import { applyFixes, stringifyLike } from "../src/lib/fix.js";
import { formatFix } from "../src/lib/report.js";
import { scanProject } from "../src/lib/scan.js";
import type { Dependency, Finding, PatchEntry } from "../src/lib/types.js";

const patch: PatchEntry = {
  ecosystem: "npm",
  name: "ip",
  affected: "<=2.0.1",
  replacement: { name: "@foster-oss/ip", version: "2.0.1-foster.1" },
  advisories: ["GHSA-2p57-rm9w-gvfp"],
  status: "released",
  patchDir: "patches/npm/ip",
  summary: "",
};

function finding(over: Partial<Dependency> = {}): Finding {
  return {
    kind: "patch-available",
    dependency: { ecosystem: "npm", name: "ip", version: "2.0.1", direct: false, source: "package-lock.json", ...over },
    status: "dormant",
    severity: "HIGH",
    advisories: [],
    patch,
    message: "",
  };
}

const dirs: string[] = [];
function project(pkg: object, lockfile = "package-lock.json"): string {
  const dir = mkdtempSync(join(tmpdir(), "foster-fix-"));
  dirs.push(dir);
  writeFileSync(join(dir, "package.json"), JSON.stringify(pkg, null, 4) + "\n");
  writeFileSync(join(dir, lockfile), lockfile.endsWith(".json") ? "{}" : "");
  return dir;
}
const read = (dir: string) => JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("applyFixes", () => {
  it("adds an npm override for a transitive dependency", () => {
    const dir = project({ name: "x", dependencies: { socks: "^2.7.1" } });
    const res = applyFixes(dir, [finding()]);
    expect(res.written).toBe(true);
    // versioned key: only the affected copy is replaced, never other versions in the tree
    expect(read(dir).overrides).toEqual({ "ip@2.0.1": "npm:@foster-oss/ip@2.0.1-foster.1" });
  });

  it("rewrites a direct dependency in place instead of overriding it", () => {
    const dir = project({ name: "x", dependencies: { ip: "^2.0.0" } });
    applyFixes(dir, [finding({ direct: true })]);
    const pkg = read(dir);
    expect(pkg.dependencies.ip).toBe("npm:@foster-oss/ip@2.0.1-foster.1");
    expect(pkg.overrides).toBeUndefined();
  });

  it("uses pnpm.overrides for pnpm projects and resolutions for yarn", () => {
    const pnpm = project({ name: "x" }, "pnpm-lock.yaml");
    applyFixes(pnpm, [finding()]);
    expect(read(pnpm).pnpm.overrides["ip@2.0.1"]).toBe("npm:@foster-oss/ip@2.0.1-foster.1");

    const yarn = project({ name: "x" }, "yarn.lock");
    applyFixes(yarn, [finding()]);
    expect(read(yarn).resolutions.ip).toBe("npm:@foster-oss/ip@2.0.1-foster.1");
  });

  it("keeps an existing different override unless forced", () => {
    const dir = project({ name: "x", overrides: { "ip@2.0.1": "1.1.9" } });
    const res = applyFixes(dir, [finding()]);
    expect(res.written).toBe(false);
    expect(res.changes[0]).toMatchObject({ applied: false });
    expect(read(dir).overrides["ip@2.0.1"]).toBe("1.1.9");

    applyFixes(dir, [finding()], { force: true });
    expect(read(dir).overrides["ip@2.0.1"]).toBe("npm:@foster-oss/ip@2.0.1-foster.1");
  });

  it("never points a safe direct dependency on another major at the patch", () => {
    // ip@3 is direct and safe; a vulnerable ip@2.0.1 sits under socks
    const dir = project({ name: "x", dependencies: { ip: "^3.0.0", socks: "^2.7.1" } });
    applyFixes(dir, [finding({ direct: true })]);
    const pkg = read(dir);
    expect(pkg.dependencies.ip).toBe("^3.0.0");
    expect(pkg.overrides).toEqual({ "ip@2.0.1": "npm:@foster-oss/ip@2.0.1-foster.1" });
  });

  it("rewrites the package in every dependency field whose range installed it", () => {
    const dir = project({ name: "x", dependencies: { ip: "^2.0.0" }, devDependencies: { ip: "2.0.1" } });
    applyFixes(dir, [finding({ direct: true })]);
    const pkg = read(dir);
    expect(pkg.dependencies.ip).toBe("npm:@foster-oss/ip@2.0.1-foster.1");
    expect(pkg.devDependencies.ip).toBe("npm:@foster-oss/ip@2.0.1-foster.1");
  });

  it("keeps nested npm overrides when replacing with --force", () => {
    const dir = project({ name: "x", overrides: { "ip@2.0.1": { ".": "2.0.1", foo: "1.0.0" } } });
    const res = applyFixes(dir, [finding()]);
    expect(res.changes[0]?.from).toBe("2.0.1");
    applyFixes(dir, [finding()], { force: true });
    expect(read(dir).overrides["ip@2.0.1"]).toEqual({ ".": "npm:@foster-oss/ip@2.0.1-foster.1", foo: "1.0.0" });
  });

  it("handles a package.json with a UTF-8 byte order mark and keeps it", () => {
    const dir = project({ name: "x" });
    const path = join(dir, "package.json");
    writeFileSync(path, String.fromCharCode(0xfeff) + readFileSync(path, "utf8"));
    applyFixes(dir, [finding()]);
    const text = readFileSync(path, "utf8");
    expect(text.charCodeAt(0)).toBe(0xfeff);
    expect(JSON.parse(text.slice(1)).overrides["ip@2.0.1"]).toBe("npm:@foster-oss/ip@2.0.1-foster.1");
  });

  it("refuses a yarn resolution that would also replace an unaffected copy", () => {
    const dir = project({ name: "x" }, "yarn.lock");
    writeFileSync(join(dir, "yarn.lock"), ['ip@^2.0.0:', '  version "2.0.1"', "", "ip@^3.0.0:", '  version "3.0.0"', ""].join("\n"));
    const res = applyFixes(dir, [finding()]);
    expect(res.written).toBe(false);
    expect(res.skipped[0]?.reason).toMatch(/unaffected copies/);
  });

  it("scopes overrides per version when several versions are installed", () => {
    const dir = project({ name: "x" });
    applyFixes(dir, [finding({ version: "2.0.0" }), finding({ version: "2.0.1" })]);
    expect(Object.keys(read(dir).overrides).sort()).toEqual(["ip@2.0.0", "ip@2.0.1"]);
  });

  it("does nothing on dry run and is idempotent", () => {
    const dir = project({ name: "x" });
    const before = readFileSync(join(dir, "package.json"), "utf8");
    const dry = applyFixes(dir, [finding()], { dryRun: true });
    expect(dry.changes).toHaveLength(1);
    expect(readFileSync(join(dir, "package.json"), "utf8")).toBe(before);

    applyFixes(dir, [finding()]);
    const second = applyFixes(dir, [finding()]);
    expect(second.changes).toHaveLength(0);
  });

  it("skips PyPI findings with an explanation", () => {
    const dir = project({ name: "x" });
    const res = applyFixes(dir, [finding({ ecosystem: "pypi", name: "foo" })]);
    expect(res.skipped[0]?.reason).toMatch(/npm-only/);
  });

  it("ignores findings that are not patch-available", () => {
    const dir = project({ name: "x" });
    const res = applyFixes(dir, [{ ...finding(), kind: "orphaned-vulnerable", patch: undefined }]);
    expect(res.changes).toHaveLength(0);
    expect(res.written).toBe(false);
  });

  it("works on a copy of a real fixture project", () => {
    const dir = mkdtempSync(join(tmpdir(), "foster-fix-"));
    dirs.push(dir);
    cpSync(join(__dirname, "fixtures", "npm-v3"), dir, { recursive: true });
    applyFixes(dir, [finding({ direct: true })]);
    expect(read(dir).dependencies.ip).toBe("npm:@foster-oss/ip@2.0.1-foster.1");
  });
});

describe("stringifyLike", () => {
  it("keeps indentation, CRLF and the trailing newline", () => {
    const original = '{\r\n    "a": 1\r\n}\r\n';
    expect(stringifyLike(original, { a: 2 })).toBe('{\r\n    "a": 2\r\n}\r\n');
    expect(stringifyLike('{\n\t"a": 1\n}', { a: 1 })).toBe('{\n\t"a": 1\n}');
  });
});

describe("pnpm workspace overrides", () => {
  const target = "npm:@foster-oss/ip@2.0.1-foster.1";
  const workspaceFile = "pnpm-workspace.yaml";
  const text = (dir: string, file: string) => readFileSync(join(dir, file), "utf8");
  function workspace(yaml: string, pkg: object = { name: "x" }, lock = "pnpm-lock.yaml") {
    const dir = project(pkg, lock);
    writeFileSync(join(dir, workspaceFile), yaml);
    return dir;
  }

  it("uses an existing workspace map without changing package.json or the lockfile", () => {
    const yaml = '# workspace\npackages:\n  - "apps/*"\n\noverrides:\n  other: "^1.0.0" # keep\nonlyBuiltDependencies: [esbuild]\n';
    const dir = workspace(yaml, { name: "x", pnpm: { overrides: { "ip@2.0.1": "legacy" }, other: true } });
    const pkgBefore = text(dir, "package.json");
    const lockBefore = text(dir, "pnpm-lock.yaml");
    const result = applyFixes(dir, [finding()]);
    expect(result.written).toBe(true);
    expect(text(dir, workspaceFile)).toBe(yaml.replace('  other: "^1.0.0" # keep\n', `  other: "^1.0.0" # keep\n  ip@2.0.1: ${target}\n`));
    expect(text(dir, "package.json")).toBe(pkgBefore);
    expect(text(dir, "pnpm-lock.yaml")).toBe(lockBefore);
    expect(formatFix(result, "pnpm install")).toContain("pnpm-workspace.yaml updated.");
    expect(formatFix(result, "pnpm install")).not.toContain("package.json updated.");
  });

  it("reads workspace conflicts, preserves them by default, and replaces only the selected value with force", () => {
    const yaml = "# workspace\npackages:\n    - 'apps/*' # keep\n\noverrides:\n    'ip@2.0.1': '1.1.9' # reason\n    ip@3.0.0: ^3.0.0\n";
    const dir = workspace(yaml);
    const pkgBefore = text(dir, "package.json");
    const kept = applyFixes(dir, [finding()]);
    expect(kept.written).toBe(false);
    expect(kept.changes[0]).toMatchObject({ from: "1.1.9", applied: false });
    expect(text(dir, workspaceFile)).toBe(yaml);
    applyFixes(dir, [finding()], { force: true });
    expect(text(dir, workspaceFile)).toBe(yaml.replace("'1.1.9'", `'${target}'`));
    expect(text(dir, "package.json")).toBe(pkgBefore);
  });

  it.each(["overrides: {}\n", "overrides:\n  other: ^1.0.0\n"])("supports empty and populated maps, dry-run and repeat runs: %s", (yaml) => {
    const dir = workspace(yaml);
    const pkgBefore = text(dir, "package.json");
    const dry = applyFixes(dir, [finding()], { dryRun: true });
    expect(dry.written).toBe(false);
    expect(dry.changes).toHaveLength(1);
    expect(formatFix(dry, "pnpm install")).toContain("would update pnpm-workspace.yaml");
    expect(text(dir, workspaceFile)).toBe(yaml);
    expect(text(dir, "package.json")).toBe(pkgBefore);
    applyFixes(dir, [finding()]);
    const after = text(dir, workspaceFile);
    expect(parse(after).overrides["ip@2.0.1"]).toBe(target);
    const repeated = applyFixes(dir, [finding()]);
    expect(repeated.changes).toHaveLength(0);
    expect(repeated.written).toBe(false);
    expect(text(dir, workspaceFile)).toBe(after);
    expect(text(dir, "package.json")).toBe(pkgBefore);
  });

  it.each(["", "# workspace\npackages:\n  - 'apps/*'\n"])("keeps the package.json fallback when no overrides field exists: %s", (yaml) => {
    const dir = workspace(yaml);
    applyFixes(dir, [finding()]);
    expect(read(dir).pnpm.overrides["ip@2.0.1"]).toBe(target);
    expect(text(dir, workspaceFile)).toBe(yaml);
  });

  it("writes direct and transitive fixes to their respective files", () => {
    const yaml = "overrides:\n  unrelated: ^1.0.0\n";
    const dir = workspace(yaml, { name: "x", dependencies: { direct: "^2.0.0", ip: "^3.0.0" } });
    const result = applyFixes(dir, [finding({ name: "direct", direct: true }), finding()]);
    expect(read(dir).dependencies).toEqual({ direct: target, ip: "^3.0.0" });
    expect(read(dir).pnpm).toBeUndefined();
    expect(parse(text(dir, workspaceFile)).overrides).toEqual({ unrelated: "^1.0.0", "ip@2.0.1": target });
    expect(formatFix(result, "pnpm install")).toContain("package.json, pnpm-workspace.yaml updated.");
  });

  it("leaves workspace bytes alone for a direct-only fix", () => {
    const yaml = "# no transitive change\noverrides: {other: '^1'}\n";
    const dir = workspace(yaml, { dependencies: { ip: "^2.0.0" } });
    applyFixes(dir, [finding()]);
    expect(read(dir).dependencies.ip).toBe(target);
    expect(text(dir, workspaceFile)).toBe(yaml);
  });

  it("keeps version-scoped keys, including scoped package names", () => {
    const dir = workspace("overrides: {}\n");
    applyFixes(dir, [finding({ version: "2.0.0" }), finding(), finding({ name: "@scope/ip" })]);
    expect(parse(text(dir, workspaceFile)).overrides).toEqual({ "ip@2.0.0": target, "ip@2.0.1": target, "@scope/ip@2.0.1": target });
  });

  it.each(["package-lock.json", "yarn.lock"])("ignores workspace overrides for %s", (lock) => {
    const yaml = "overrides:\n  ip@2.0.1: existing\n";
    const dir = workspace(yaml, { name: "x" }, lock);
    applyFixes(dir, [finding()]);
    expect(text(dir, workspaceFile)).toBe(yaml);
    expect(lock === "yarn.lock" ? read(dir).resolutions.ip : read(dir).overrides["ip@2.0.1"]).toBe(target);
  });

  it.each([true, false])("preserves BOM, CRLF and trailing-newline choice (%s)", (trailing) => {
    const yaml = "\ufeff# workspace\r\noverrides:\r\n  'ip@2.0.1': 'old' # keep" + (trailing ? "\r\n" : "");
    const dir = workspace(yaml);
    applyFixes(dir, [finding()], { force: true });
    expect(text(dir, workspaceFile)).toBe(yaml.replace("'old'", `'${target}'`));
  });

  it.each(["overrides: [", "overrides: []\n", "overrides: old\n", "overrides: {}\noverrides: {}\n"])("rejects invalid workspace configuration before writing either file: %s", (yaml) => {
    const dir = workspace(yaml, { dependencies: { direct: "^2.0.0" } });
    const pkgBefore = text(dir, "package.json");
    expect(() => applyFixes(dir, [finding({ name: "direct", direct: true }), finding()])).toThrow(/pnpm-workspace.yaml/);
    expect(text(dir, workspaceFile)).toBe(yaml);
    expect(text(dir, "package.json")).toBe(pkgBefore);
  });

  it("reads an aliased override and replaces it without changing its source", () => {
    const yaml = "version: &version 'old'\noverrides:\n  # keep this reason\n  ip@2.0.1: *version # important why\nother: *version\n";
    const dir = workspace(yaml);
    expect(applyFixes(dir, [finding()]).changes[0]).toMatchObject({ from: "old", applied: false });
    applyFixes(dir, [finding()], { force: true });
    expect(parse(text(dir, workspaceFile))).toEqual({ version: "old", overrides: { "ip@2.0.1": target }, other: "old" });
    expect(text(dir, workspaceFile)).toBe(yaml.replace("*version # important why", `${target} # important why`));
  });

  it("reads alias-backed maps without writing for conflicts, no-ops or dry-runs", () => {
    const yaml = "defaults: &defaults\n  ip@2.0.1: old\noverrides: *defaults # keep\n";
    const dir = workspace(yaml);
    const kept = applyFixes(dir, [finding()]);
    expect(kept.changes[0]).toMatchObject({ from: "old", applied: false });
    const dry = applyFixes(dir, [finding()], { dryRun: true, force: true });
    expect(dry.changes[0]).toMatchObject({ from: "old", applied: true });
    expect(dry.written).toBe(false);
    expect(text(dir, workspaceFile)).toBe(yaml);
    const identical = yaml.replace("old", target);
    writeFileSync(join(dir, workspaceFile), identical);
    expect(applyFixes(dir, [finding()]).changes).toHaveLength(0);
    expect(text(dir, workspaceFile)).toBe(identical);
  });

  it("updates an alias-backed map without changing its defaults or other consumers", () => {
    const defaults = 'defaults: &defaults\n  "ip@2.0.1": &version "old" # original\n  unrelated: *version\n';
    const dir = workspace(defaults + "overrides: *defaults # project overrides\nelsewhere: *defaults\n");
    applyFixes(dir, [finding(), finding({ name: "@scope/ip" })], { force: true });
    const after = text(dir, workspaceFile);
    expect(after.startsWith(defaults)).toBe(true);
    expect(after).toContain("# project overrides");
    // The default's comment stays with its original definition, which remains byte-identical above.
    expect(after.match(/# original/g)).toHaveLength(1);
    const values = parse(after);
    expect(values.defaults).toEqual({ "ip@2.0.1": "old", unrelated: "old" });
    expect(values.elsewhere).toEqual(values.defaults);
    expect(values.overrides).toEqual({ "ip@2.0.1": target, unrelated: "old", "@scope/ip@2.0.1": target });
    expect(applyFixes(dir, [finding()]).changes).toHaveLength(0);
    expect(text(dir, workspaceFile)).toBe(after);
  });

  it("keeps aliases bound to their original values when a later anchor reuses the name", () => {
    const yaml = "defaults: &defaults\n  foo: &version '1.0.0'\n  unrelated: *version # keep old version\nother: &version '2.0.0'\noverrides: *defaults\n";
    const dir = workspace(yaml);
    const before = parse(yaml);
    applyFixes(dir, [finding()]);
    const after = parse(text(dir, workspaceFile));
    expect(after).toEqual({ ...before, overrides: { ...before.overrides, "ip@2.0.1": target } });
    expect(text(dir, workspaceFile)).toContain("unrelated: *version # keep old version");
  });

  it.each([false, true])("respects aliased selector keys (alias-backed map: %s)", (aliasedMap) => {
    const yaml = "selector: &selector ip@2.0.1\n" +
      (aliasedMap ? "defaults: &defaults\n" : "overrides:\n") +
      "  ? *selector\n  : '1.0.0' # chosen version\n" + (aliasedMap ? "overrides: *defaults\n" : "");
    const dir = workspace(yaml);
    const kept = applyFixes(dir, [finding()]);
    expect(kept.changes[0]).toMatchObject({ from: "1.0.0", applied: false });
    expect(kept.written).toBe(false);
    expect(text(dir, workspaceFile)).toBe(yaml);
    const identical = yaml.replace("'1.0.0'", `'${target}'`);
    writeFileSync(join(dir, workspaceFile), identical);
    expect(applyFixes(dir, [finding()]).changes).toHaveLength(0);
    expect(text(dir, workspaceFile)).toBe(identical);
    writeFileSync(join(dir, workspaceFile), yaml);
    applyFixes(dir, [finding()], { force: true });
    const after = text(dir, workspaceFile);
    expect(parse(after).overrides).toEqual({ "ip@2.0.1": target });
    expect(after).toContain("# chosen version");
    if (aliasedMap) expect(parse(after).defaults).toEqual({ "ip@2.0.1": "1.0.0" });
  });

  it("rejects duplicate selectors hidden behind an alias before writing", () => {
    const yaml = "selector: &selector ip@2.0.1\noverrides:\n  ? *selector\n  : old\n  ip@2.0.1: other\n";
    const dir = workspace(yaml);
    expect(() => applyFixes(dir, [finding()], { force: true })).toThrow(/duplicate override/);
    expect(text(dir, workspaceFile)).toBe(yaml);
  });

  it("updates an aliased root overrides key without adding a duplicate field", () => {
    const yaml = "key: &key overrides\n? *key\n: \n  ip@2.0.1: '1.0.0' # chosen version\n  other: '2.0.0'\n";
    const dir = workspace(yaml);
    const pkgBefore = text(dir, "package.json");
    expect(applyFixes(dir, [finding()]).changes[0]).toMatchObject({ from: "1.0.0", applied: false });
    expect(text(dir, workspaceFile)).toBe(yaml);
    applyFixes(dir, [finding()], { force: true, dryRun: true });
    expect(text(dir, workspaceFile)).toBe(yaml);
    applyFixes(dir, [finding()], { force: true });
    const after = text(dir, workspaceFile);
    expect(parse(after).overrides).toEqual({ "ip@2.0.1": target, other: "2.0.0" });
    expect(after).not.toMatch(/^overrides:/m);
    expect(after).toContain("# chosen version");
    expect(text(dir, "package.json")).toBe(pkgBefore);
    expect(applyFixes(dir, [finding()]).changes).toHaveLength(0);
    expect(text(dir, workspaceFile)).toBe(after);
  });

  it.each([
    "overrides: &overrides\n  ip@2.0.1: old\nother: *overrides\n",
    "overrides:\n  ip@2.0.1: &version old\n  unrelated: *version\n",
  ])("refuses to change an anchor shared with unrelated configuration: %s", (yaml) => {
    const dir = workspace(yaml);
    expect(() => applyFixes(dir, [finding()], { force: true })).toThrow(/shared YAML anchor/);
    expect(text(dir, workspaceFile)).toBe(yaml);
  });

  it.each(["null", "123", "{child: old}"])("rejects an invalid override value without overwriting it: %s", (value) => {
    const yaml = `overrides:\n  ip@2.0.1: ${value}\n`;
    const dir = workspace(yaml);
    expect(() => applyFixes(dir, [finding()], { force: true })).toThrow(/must be a string/);
    expect(text(dir, workspaceFile)).toBe(yaml);
  });

  it("rejects unresolved aliases before any write", () => {
    const yaml = "overrides:\n  ip@2.0.1: *missing\n";
    const dir = workspace(yaml);
    expect(() => applyFixes(dir, [finding()], { force: true })).toThrow(/pnpm-workspace.yaml.*Unresolved alias/);
    expect(text(dir, workspaceFile)).toBe(yaml);
  });

  it.each([
    "defaults: &defaults\n  ip@2.0.1: '1.0.0'\n  other: ^3.0.0\noverrides:\n  <<: *defaults\n",
    "defaults: &defaults\n  overrides:\n    ip@2.0.1: '1.0.0'\n    other: ^3.0.0\n<<: *defaults\n",
  ])("reads and updates merged overrides with the same conflict rules: %s", (yaml) => {
    const dir = workspace(yaml);
    const pkgBefore = text(dir, "package.json");
    const before = parse(yaml, { merge: true });
    const kept = applyFixes(dir, [finding()]);
    expect(kept.changes[0]).toMatchObject({ from: "1.0.0", applied: false });
    expect(kept.written).toBe(false);
    expect(text(dir, workspaceFile)).toBe(yaml);
    applyFixes(dir, [finding()], { force: true, dryRun: true });
    expect(text(dir, workspaceFile)).toBe(yaml);
    applyFixes(dir, [finding()], { force: true });
    const after = text(dir, workspaceFile);
    expect(parse(after, { merge: true })).toEqual({ ...before, overrides: { ...before.overrides, "ip@2.0.1": target } });
    expect(text(dir, "package.json")).toBe(pkgBefore);
    expect(applyFixes(dir, [finding()]).changes).toHaveLength(0);
    expect(text(dir, workspaceFile)).toBe(after);
  });

  it.each(["pnpm-v6", "pnpm-v9"])("uses real %s scan findings and preserves the lockfile", async (fixture) => {
    const dir = workspace("packages:\n- 'apps/*'\noverrides:\n  other: ^1.0.0\n");
    cpSync(join(__dirname, "fixtures", fixture, "pnpm-lock.yaml"), join(dir, "pnpm-lock.yaml"));
    const lockBefore = text(dir, "pnpm-lock.yaml");
    const scan = await scanProject(dir, { offline: true });
    expect(scan.findings.some((f) => f.dependency.name === "ip" && f.kind === "patch-available")).toBe(true);
    applyFixes(dir, scan.findings);
    expect(parse(text(dir, workspaceFile)).overrides["ip@2.0.1"]).toBe("npm:@keep-lts/ip@2.0.2");
    expect(text(dir, workspaceFile)).toContain("packages:\n- 'apps/*'\n");
    expect(text(dir, "pnpm-lock.yaml")).toBe(lockBefore);
  });
});
