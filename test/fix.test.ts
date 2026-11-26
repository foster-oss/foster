import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { applyFixes, stringifyLike } from "../src/lib/fix.js";
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
