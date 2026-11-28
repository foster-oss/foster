import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { findPatch, type PatchRegistry } from "../src/lib/data.js";
import { analyzeDependencies, projectDir, scanProject, shouldFail } from "../src/lib/scan.js";
import { formatMarkdown, formatText } from "../src/lib/report.js";
import { compareVersions, rangeIncludes } from "../src/lib/versions.js";
import type { Dependency, Finding } from "../src/lib/types.js";

const fixtures = join(__dirname, "fixtures");
const registryFile = join(fixtures, "registry.json");
const indexFile = join(fixtures, "index.json");
const dep = (name: string, version: string, ecosystem: "npm" | "pypi" = "npm"): Dependency => ({ ecosystem, name, version, direct: true, source: "test" });

describe("offline scan with bundled data", () => {
  it("reports a staged patch only when asked, otherwise orphaned+vulnerable", async () => {
    const opts = { offline: true, registryFile, indexFile };
    const plain = await analyzeDependencies([dep("ip", "2.0.1")], opts);
    expect(plain[0]).toMatchObject({ kind: "orphaned-vulnerable", severity: "HIGH", status: "dormant" });

    const staged = await analyzeDependencies([dep("ip", "2.0.1")], { ...opts, includeStaged: true });
    expect(staged[0]).toMatchObject({ kind: "patch-available" });
    expect(staged[0]?.patch?.replacement.name).toBe("@foster-oss/ip");
  });

  it("reports quiet orphans without advisories and ignores healthy packages", async () => {
    const findings = await analyzeDependencies([dep("left-pad", "1.3.0"), dep("healthy", "1.0.0")], { offline: true, registryFile, indexFile });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ kind: "orphaned", status: "dead" });
  });

  it("only applies index advisories to versions inside the vulnerable range", async () => {
    const findings = await analyzeDependencies([dep("oldlib", "3.0.0")], { offline: true, registryFile, indexFile });
    expect(findings[0]?.kind).toBe("orphaned");
  });

  it("scans a fixture project end to end", async () => {
    const result = await scanProject(join(fixtures, "npm-v3"), { offline: true, registryFile, indexFile });
    expect(result.lockfiles).toEqual(["package-lock.json"]);
    expect(result.dependencyCount).toBe(5);
    expect(result.findings.map((f) => `${f.kind}:${f.dependency.name}`)).toEqual(["orphaned-vulnerable:ip", "orphaned:utils-merge"]);
    expect(formatText(result)).toContain("ORPHANED+VULN");
    expect(formatMarkdown(result)).toContain("nominate for adoption");
  });

  it("warns when there is no lockfile", async () => {
    const result = await scanProject(join(fixtures, "fixme"), { offline: true, registryFile, indexFile });
    expect(result.warnings[0]).toMatch(/no supported lockfile/);
    expect(formatText(result)).toMatch(/No orphaned/);
  });
});

describe("findPatch", () => {
  const registry: PatchRegistry = JSON.parse(require("node:fs").readFileSync(registryFile, "utf8"));
  it("matches by semver range and status", () => {
    expect(findPatch(registry, dep("ip", "2.0.1"), true)).toBeDefined();
    expect(findPatch(registry, dep("ip", "1.1.9"), true)).toBeDefined();
    expect(findPatch(registry, dep("ip", "2.0.2"), true)).toBeUndefined();
    expect(findPatch(registry, dep("ip", "2.0.1"), false)).toBeUndefined();
    expect(findPatch(registry, dep("ip", "2.0.1", "pypi"), true)).toBeUndefined();
  });
});

describe("shouldFail", () => {
  const f = (kind: Finding["kind"]) => ({ kind }) as Finding;
  it("respects thresholds", () => {
    expect(shouldFail([f("orphaned")], "none")).toBe(false);
    expect(shouldFail([f("orphaned")], "any")).toBe(true);
    expect(shouldFail([f("upgrade-available")], "unpatched")).toBe(false);
    expect(shouldFail([f("unpatched-vulnerable")], "unpatched")).toBe(true);
    expect(shouldFail([f("unpatched-vulnerable")], "orphaned-vulnerable")).toBe(false);
    expect(shouldFail([f("orphaned-vulnerable")], "orphaned-vulnerable")).toBe(true);
    expect(shouldFail([f("patch-available")], "patch-available")).toBe(true);
  });
});

describe("versions", () => {
  it("compares semver and PEP 440-ish versions", () => {
    expect(compareVersions("2.0.1", "2.0.10")).toBe(-1);
    expect(compareVersions("1.9.1", "0.23.0")).toBe(1);
    expect(compareVersions("5.1.0.95", "4.1.0.25")).toBe(1);
    expect(compareVersions("1.0", "1.0.0")).toBe(0);
  });

  it("evaluates GitHub advisory ranges", () => {
    expect(rangeIncludes("<= 2.0.1", "2.0.1")).toBe(true);
    expect(rangeIncludes("<= 2.0.1", "2.0.2")).toBe(false);
    expect(rangeIncludes(">= 2.0.0, <= 3.0.0", "2.1693.0")).toBe(true);
    expect(rangeIncludes(">= 1.4.1", "1.4.0")).toBe(false);
    expect(rangeIncludes("= 1.2.9", "1.2.8")).toBe(false);
    expect(rangeIncludes("< 10.2.7", "10.2.6")).toBe(true);
    expect(rangeIncludes("weird", "1.0.0")).toBe(true);
    expect(rangeIncludes(undefined, "1.0.0")).toBe(true);
  });
});

describe("recursive (monorepo) scan", () => {
  it("finds lockfiles in subfolders, prefixes their paths and dedupes packages", async () => {
    const result = await scanProject(fixtures, { offline: true, registryFile, indexFile, recursive: true });
    expect(result.lockfiles).toContain("npm-v3/package-lock.json");
    expect(result.lockfiles).toContain("cargo/Cargo.lock");
    expect(result.lockfiles.some((l) => l.startsWith("sbom/"))).toBe(false); // SBOMs are not lockfiles
    const ips = result.findings.filter((f) => f.dependency.name === "ip" && f.dependency.version === "2.0.1");
    expect(ips).toHaveLength(1);
    expect(ips[0]?.dependency.source).toMatch(/\/(package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$/);
  });

  it("without --recursive, a monorepo root with no lockfile suggests the flag", async () => {
    const result = await scanProject(fixtures, { offline: true, registryFile, indexFile });
    expect(result.warnings[0]).toMatch(/--recursive/);
  });
});

describe("folders that are not there", () => {
  it("is an error, not a clean scan of nothing", async () => {
    expect(() => projectDir(join(__dirname, "no-such-folder"))).toThrow(/no such folder/);
    expect(() => projectDir(join(__dirname, "scan.test.ts"))).toThrow(/no such folder/);
    await expect(scanProject(join(__dirname, "no-such-folder"), { offline: true })).rejects.toMatchObject({ code: "FOSTER_NO_DIR" });
    expect(projectDir(__dirname)).toBe(__dirname);
  });
});
