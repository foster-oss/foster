import { describe, expect, it } from "vitest";
import { atRisk, formatFund, fundingCandidates, fundingLabel } from "../src/lib/fund.js";
import type { Dependency, OrphanRecord } from "../src/lib/types.js";

const dep = (name: string): Dependency => ({ ecosystem: "npm", name, version: "1.0.0", direct: true, source: "package-lock.json" });
function rec(name: string, over: Partial<OrphanRecord & { funding: string[] }> = {}): OrphanRecord & { funding?: string[] } {
  return {
    ecosystem: "npm",
    name,
    status: "dormant",
    reasons: [],
    downloadsLastMonth: 1,
    dependentRepos: 100,
    dependentPackages: 1,
    latestVersion: "1.0.0",
    latestReleaseAt: null,
    repoUrl: null,
    archived: false,
    lastPushAt: null,
    publishers: 2,
    unpatchedAdvisories: [],
    priority: 1,
    ...over,
  };
}

describe("fund", () => {
  it("lists unmaintained or vulnerable packages, not healthy ones", () => {
    expect(atRisk(rec("a", { status: "active" }))).toEqual([]);
    expect(atRisk(rec("b", { status: "dead", publishers: 1 }))).toEqual(["unmaintained (dead)", "one person can publish it"]);
    expect(atRisk(rec("c", { status: "active", unpatchedAdvisories: [{ id: "GHSA-x", url: "", severity: "HIGH", title: "" }] }))).toEqual(["1 advisory(ies) no release fixes"]);
  });

  it("ranks dead before dormant, then by how many repositories rely on it, and splits by funding link", () => {
    const records = new Map([
      ["npm:small-dead", rec("small-dead", { status: "dead", dependentRepos: 10, funding: ["https://github.com/sponsors/x"] })],
      ["npm:big-dormant", rec("big-dormant", { dependentRepos: 1_000_000, funding: ["https://opencollective.com/y"] })],
      ["npm:big-dead", rec("big-dead", { status: "dead", dependentRepos: 5_000_000, funding: ["https://github.com/sponsors/z"] })],
      ["npm:nobody", rec("nobody", { status: "dead", dependentRepos: 50 })],
      ["npm:healthy", rec("healthy", { status: "active", funding: ["https://github.com/sponsors/h"] })],
    ]);
    const { fundable, unfundable } = fundingCandidates(
      ["small-dead", "big-dormant", "big-dead", "nobody", "healthy", "not-in-index", "big-dead"].map(dep),
      records,
    );
    expect(fundable.map((c) => c.dependency.name)).toEqual(["big-dead", "small-dead", "big-dormant"]);
    expect(unfundable.map((c) => c.dependency.name)).toEqual(["nobody"]);
  });

  it("labels common sponsorship platforms", () => {
    expect(fundingLabel("https://github.com/sponsors/epoberezkin")).toBe("GitHub Sponsors: epoberezkin");
    expect(fundingLabel("https://opencollective.com/webpack/donate")).toBe("Open Collective: webpack");
    expect(fundingLabel("https://tidelift.com/funding/github/npm/x")).toBe("Tidelift");
    expect(fundingLabel("https://ko-fi.com/softprops")).toBe("Ko-fi: softprops");
    expect(fundingLabel("https://example.org/donate")).toBe("example.org");
  });

  it("prints links and a short list of packages nobody can fund", () => {
    const text = formatFund({
      dir: "/p",
      dependencyCount: 3,
      fundable: [{ dependency: dep("a"), status: "dead", reasons: ["unmaintained (dead)"], dependentRepos: 1000, links: ["https://github.com/sponsors/a"], repoUrl: null }],
      unfundable: [{ dependency: dep("b"), status: "dormant", reasons: ["unmaintained (dormant)"], dependentRepos: 5, links: [], repoUrl: null }],
      warnings: [],
    });
    expect(text).toContain("GitHub Sponsors: a");
    expect(text).toContain("no funding link is known (1). You can still help:");
    expect(text).toContain("b (npm) · unmaintained (dormant)");
    expect(text).toContain("no source repository is linked");
  });

  it("suggests help that takes no money", async () => {
    const { helpFor } = await import("../src/lib/fund.js");
    const base = { dependency: dep("b"), status: "dead" as const, reasons: ["unmaintained (dead)"], dependentRepos: 5, links: [] };
    expect(helpFor({ ...base, repoUrl: "https://github.com/o/b.git" })).toEqual(["offer to co-maintain, or review and send fixes: https://github.com/o/b/issues"]);
    expect(helpFor({ ...base, repoUrl: "https://github.com/o/b", archived: true })[0]).toMatch(/archived.*Fork it together/);
    expect(helpFor({ ...base, repoUrl: "https://example.org/b" })).toEqual(["send fixes or offer help: https://example.org/b"]);
    expect(helpFor({ ...base, repoUrl: null, alternatives: { options: [{ kind: "package", name: "c" } as never], source: "Foster registry" } })[1]).toBe("or switch to: c");
  });
});
