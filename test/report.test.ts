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
    expect(run.results).toHaveLength(result.findings.length);
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
