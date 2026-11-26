import { describe, expect, it } from "vitest";
import { classify } from "../src/lib/classify.js";
import { parseGoMod, parsePnpmLock, parseComposerLock, parseGemfileLock } from "../src/lib/lockfile.js";
import { describeForDependency, intervalEndFor, lowestFixAbove, type OsvVuln } from "../src/lib/osv.js";
import { parsePurl } from "../src/lib/sbom.js";
import type { Dependency } from "../src/lib/types.js";

// Bugs found by the November 2026 review; each test pins the corrected behaviour.

const dep = (version: string, ecosystem: Dependency["ecosystem"] = "npm"): Dependency => ({ ecosystem, name: "x", version, direct: true, source: "t" });

describe("OSV ranges", () => {
  const vuln = (events: object[], type = "SEMVER"): OsvVuln => ({ id: "GHSA-test", affected: [{ package: { name: "x" }, ranges: [{ type, events }] }] });

  it("only uses the fix of the interval that contains the installed version", () => {
    const v = vuln([{ introduced: "0" }, { fixed: "1.2.3" }, { introduced: "2.0.0" }]);
    expect(describeForDependency(v, dep("2.5.0")).fixedVersions).toEqual([]); // open-ended: no fix on 2.x
    expect(describeForDependency(v, dep("1.0.0")).fixedVersions).toEqual(["1.2.3"]);
  });

  it("picks the fix on the installed release line", () => {
    const v = vuln([{ introduced: "0" }, { fixed: "8.5.52" }, { introduced: "9.0.0" }, { fixed: "9.6.33" }]);
    expect(describeForDependency(v, dep("9.6.13")).fixedVersions).toEqual(["9.6.33"]);
  });

  it("ignores GIT ranges (commit hashes)", () => {
    const v = vuln([{ introduced: "0" }, { fixed: "a5f9cb52e0d0" }], "GIT");
    expect(describeForDependency(v, dep("1.0.0")).fixedVersions).toEqual([]);
  });

  it("never suggests a fix below the installed version", () => {
    expect(lowestFixAbove(dep("10.0.0"), ["8.5.52", "9.6.33"])).toBeUndefined();
  });

  it("reports last_affected bounds", () => {
    expect(intervalEndFor([{ introduced: "0" }, { last_affected: "2.0.1" }], "2.0.1")).toEqual({ last_affected: "2.0.1" });
    expect(intervalEndFor([{ introduced: "3.0.0" }, { fixed: "3.1.0" }], "2.0.0")).toBe("unrelated");
  });
});

describe("lockfiles", () => {
  it("keeps pnpm packages with underscores in their names", () => {
    expect(parsePnpmLock("lockfileVersion: '9.0'\npackages:\n  string_decoder@1.3.0:\n    resolution: {integrity: x}\n")).toEqual([["string_decoder", "1.3.0"]]);
    expect(parsePnpmLock("lockfileVersion: 5.4\npackages:\n  /string_decoder/1.3.0_react@18.2.0:\n    resolution: {integrity: x}\n")).toEqual([["string_decoder", "1.3.0"]]);
  });

  it("reads go.mod blocks whose opening line has a comment", () => {
    expect(parseGoMod("module m\n\nrequire ( // deps\n\tgithub.com/a/b v1.2.3\n)\n").pairs).toEqual([["github.com/a/b", "v1.2.3"]]);
  });

  it("applies a version-specific go.mod replace only to that version", () => {
    const mod = parseGoMod("module m\nrequire github.com/c/d v0.0.0-2021\nreplace github.com/c/d v0.0.1 => github.com/e/f v1.0.0\n");
    expect(mod.pairs).toEqual([["github.com/c/d", "v0.0.0-2021"]]);
  });

  it("ignores toolchain, exclude and retract directives", () => {
    const mod = parseGoMod("module m\ngo 1.22\ntoolchain go1.22.1\nexclude github.com/x/y v1.0.0\nretract (\n\tv1.0.0\n)\nrequire github.com/a/b v1.0.0\n");
    expect(mod.pairs).toEqual([["github.com/a/b", "v1.0.0"]]);
  });

  it("strips more Ruby platforms and skips composer branch aliases", () => {
    const gems = parseGemfileLock("GEM\n  remote: x\n  specs:\n    ffi (1.16.3-i386-mingw32)\n    sass-embedded (1.60.0-wasm32-wasi)\n\nDEPENDENCIES\n  ffi\n");
    expect(gems.pairs).toEqual([["ffi", "1.16.3"], ["sass-embedded", "1.60.0"]]);
    expect(parseComposerLock(JSON.stringify({ packages: [{ name: "a/b", version: "2.x-dev" }, { name: "c/d", version: "1.0.0" }] }))).toEqual([["c/d", "1.0.0"]]);
  });
});

describe("classification", () => {
  it("returns unknown instead of dead when there are no activity dates", () => {
    expect(classify({ name: "x", repo_metadata: { archived: false, pushed_at: null }, issue_metadata: { past_year_issues_count: 3 } }).status).toBe("unknown");
  });
});

describe("purls", () => {
  it("accepts an unencoded npm scope and survives bad percent-encoding", () => {
    expect(parsePurl("pkg:npm/@babel/core@7.22.5")).toEqual({ type: "npm", name: "@babel/core", version: "7.22.5" });
    expect(parsePurl("pkg:npm/foo%zz@1.0.0")).toBeNull();
  });
});
