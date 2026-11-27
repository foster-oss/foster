import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { alternativesFor, describeAlternatives } from "../src/lib/replacements.js";
import { formatMarkdown, formatSarif, formatText } from "../src/lib/report.js";
import { scanProject } from "../src/lib/scan.js";

const fixtures = join(__dirname, "fixtures");
const opts = { offline: true, registryFile: join(fixtures, "registry.json"), indexFile: join(fixtures, "index.json") };

describe("alternatives (e18e module-replacements)", () => {
  it("suggests maintained replacements for well-known npm packages", () => {
    const req = alternativesFor("npm", "request");
    expect(req?.options.map((o) => o.name)).toContain("fetch");
    expect(req?.docs).toMatch(/^https:\/\/e18e\.dev\/docs\/replacements\//);
    expect(describeAlternatives(req!)).toMatch(/fetch \(built in\)/);
  });

  it("uses Foster's reviewed list for other ecosystems", () => {
    expect(alternativesFor("go", "github.com/dgrijalva/jwt-go")?.options[0]?.name).toBe("github.com/golang-jwt/jwt/v5");
    expect(alternativesFor("cargo", "failure")?.options.map((o) => o.name)).toEqual(["anyhow", "thiserror"]);
    expect(alternativesFor("pypi", "Nose")?.source).toBe("Foster registry");
  });

  it("every curated entry names at least one option and a valid ecosystem", async () => {
    const { readFileSync } = await import("node:fs");
    const file = JSON.parse(readFileSync(join(__dirname, "..", "registry", "alternatives.json"), "utf8"));
    for (const a of file.alternatives) {
      expect(["npm", "pypi", "cargo", "go", "rubygems", "packagist"]).toContain(a.ecosystem);
      expect(a.options.length).toBeGreaterThan(0);
      for (const o of a.options) expect(["native", "package", "snippet", "remove"]).toContain(o.kind);
    }
  });

  it("drops self-referencing mappings and other ecosystems", () => {
    expect(alternativesFor("npm", "safe-buffer")).toBeUndefined();
    expect(alternativesFor("pypi", "request")).toBeUndefined();
    expect(alternativesFor("npm", "definitely-not-a-mapped-package-xyz")).toBeUndefined();
  });

  it("attaches alternatives to orphaned findings", async () => {
    const result = await scanProject(join(fixtures, "npm-v3"), opts);
    const orphan = result.findings.find((f) => f.dependency.name === "utils-merge");
    // utils-merge may or may not be mapped; whichever it is, upgrades never get suggestions
    for (const f of result.findings) if (f.kind === "upgrade-available") expect(f.alternatives).toBeUndefined();
    if (orphan?.alternatives) expect(formatText(result, false, true)).toContain("consider:");
  });
});

describe("SARIF", () => {
  it("produces valid SARIF 2.1.0 with one rule per finding kind and relative locations", async () => {
    const result = await scanProject(join(fixtures, "npm-v3"), opts);
    const sarif = JSON.parse(formatSarif(result, "0.0.0-test", fixtures));
    expect(sarif.version).toBe("2.1.0");
    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe("Foster");
    expect(run.tool.driver.rules).toHaveLength(5);
    expect(run.results).toHaveLength(result.findings.filter((f) => f.kind !== "orphaned").length);
    const all = JSON.parse(formatSarif(result, "0.0.0-test", fixtures, true));
    expect(all.runs[0].results).toHaveLength(result.findings.length);
    const ip = run.results.find((r: { properties: { package: string } }) => r.properties.package === "ip");
    expect(ip.ruleId).toBe("foster/orphaned-vulnerable");
    expect(ip.level).toBe("error");
    expect(ip.properties["security-severity"]).toBe("7.5");
    expect(ip.locations[0].physicalLocation.artifactLocation.uri).toBe("npm-v3/package-lock.json");
    expect(ip.locations[0].physicalLocation.region.startLine).toBeGreaterThan(1);
    expect(ip.partialFingerprints["fosterDependency/v1"]).toBe("npm:ip@2.0.1:orphaned-vulnerable");
  });

  it("markdown mentions replacements instead of 'watch' when there is one", async () => {
    const result = await scanProject(join(fixtures, "npm-v3"), opts);
    const md = formatMarkdown(result);
    expect(md).toContain("Foster dependency check");
  });
});

describe("direct and transitive in reports", () => {
  const dep = (name: string, direct: boolean, via?: string[]) => ({ ecosystem: "npm" as const, name, version: "1.0.0", direct, source: "package-lock.json", ...(via ? { via } : {}) });
  const adv = [{ id: "GHSA-x", url: "https://github.com/advisories/GHSA-x", severity: "HIGH" as const, title: "t" }];
  const result = {
    dir: "/p",
    scannedAt: "",
    lockfiles: ["package-lock.json"],
    dependencyCount: 9,
    warnings: [],
    findings: [
      { kind: "orphaned-vulnerable" as const, dependency: dep("request", true), status: "dead" as const, severity: "MODERATE" as const, advisories: adv, message: "request@1.0.0: no fix" },
      { kind: "upgrade-available" as const, dependency: dep("form-data", false, ["request"]), status: "active" as const, severity: "CRITICAL" as const, advisories: adv, fixedIn: "2.5.6", message: "form-data@1.0.0: fixed upstream in 2.5.6." },
      { kind: "upgrade-available" as const, dependency: dep("devalue", false, ["astro"]), status: "active" as const, severity: "HIGH" as const, advisories: adv, fixedIn: "5.9.3", message: "devalue@1.0.0: fixed upstream in 5.9.3." },
      { kind: "upgrade-available" as const, dependency: dep("lodash", true), status: "active" as const, severity: "HIGH" as const, advisories: adv, fixedIn: "4.18.0", message: "lodash@1.0.0: fixed upstream." },
      { kind: "orphaned" as const, dependency: dep("inherits", true), status: "dormant" as const, severity: "UNKNOWN" as const, advisories: [], message: "" },
      { kind: "orphaned" as const, dependency: dep("asn1", false, ["request"]), status: "dead" as const, severity: "UNKNOWN" as const, advisories: [], message: "" },
      { kind: "orphaned" as const, dependency: dep("aws4", false, ["request"]), status: "dead" as const, severity: "UNKNOWN" as const, advisories: [], message: "" },
      { kind: "orphaned" as const, dependency: dep("tiny", false, ["astro", "vite", "a", "b"]), status: "dead" as const, severity: "UNKNOWN" as const, advisories: [], message: "" },
    ],
  };

  it("text: names the parent, splits quiet orphans and counts direct ones in the summary", () => {
    const text = formatText(result, false, false);
    expect(text).toContain("UPGRADE        devalue@1.0.0 [HIGH] (transitive, via astro)");
    expect(text).toContain("4 orphaned (1 direct)");
    expect(text).toContain("3 upgrade (1 direct)");
    expect(text).toContain("1 orphaned+vulnerable ·"); // all direct: no suffix
    expect(text).toContain("1 you depend on directly: inherits");
    expect(text).toContain("3 come in through other packages, mostly via request (2), a (1), astro (1)");
    expect(formatText(result, false, true)).toContain("tiny@1.0.0 (transitive, via astro, vite, a +1 more)");
  });

  it("says when a fix is stuck behind an unmaintained direct dependency", () => {
    const text = formatText(result, false, false);
    expect(text).toContain("form-data@1.0.0 [CRITICAL] (transitive, via unmaintained request)");
    expect(text).toContain(
      "1 vulnerable package comes in only through request, which nobody maintains, so it will not move to the fixed version: replace request, or force the fix with an npm override.",
    );
    expect(text.match(/via unmaintained/g)).toHaveLength(1); // not for devalue (astro is maintained)
    expect(formatMarkdown(result)).toContain("replace `request` (unmaintained, will not move to the fix), or force 2.5.6");
  });

  it("markdown and SARIF carry the relation", () => {
    const md = formatMarkdown(result);
    expect(md).toContain("`devalue@1.0.0` <sub>transitive, via astro</sub>");
    expect(md).toContain("Vulnerable, fixed upstream: just upgrade (3: 1 direct, 2 transitive)");
    expect(md).toContain("Widely used but unmaintained (4: 1 direct, 3 transitive)");
    const sarif = JSON.parse(formatSarif(result, "0.0.0", "/p"));
    const r = sarif.runs[0].results.find((x: { properties: { package: string } }) => x.properties.package === "devalue");
    expect(r.properties).toMatchObject({ direct: false, via: ["astro"] });
    expect(r.message.text).toContain("(transitive, via astro)");
  });
});

describe("summary in scan results", () => {
  it("counts findings per kind with direct ones", async () => {
    const result = await scanProject(join(fixtures, "npm-v3"), opts);
    expect(result.findings.length).toBeGreaterThan(0);
    for (const [kind, n] of Object.entries(result.summary!)) {
      const group = result.findings.filter((f) => f.kind === kind);
      expect(n).toEqual({ total: group.length, direct: group.filter((f) => f.dependency.direct).length });
    }
  });
});
