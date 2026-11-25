import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parsePurl, readSbom } from "../src/lib/sbom.js";
import { scanSbom } from "../src/lib/scan.js";

const fx = (f: string) => join(__dirname, "fixtures", "sbom", f);

describe("purl", () => {
  it("parses scoped, Go and encoded purls", () => {
    expect(parsePurl("pkg:npm/%40babel/core@7.24.0")).toEqual({ type: "npm", name: "@babel/core", version: "7.24.0" });
    expect(parsePurl("pkg:golang/github.com/a/b@v1.0.0%2Bincompatible?x=y")).toEqual({ type: "golang", name: "github.com/a/b", version: "v1.0.0+incompatible" });
    expect(parsePurl("pkg:npm/left-pad")).toEqual({ type: "npm", name: "left-pad", version: undefined });
    expect(parsePurl("not a purl")).toBeNull();
  });
});

describe("SBOM", () => {
  it("reads CycloneDX including nested components, skipping unsupported types", () => {
    const sbom = readSbom(fx("bom.cdx.json"));
    expect(sbom.format).toBe("cyclonedx");
    expect(sbom.dependencies.map((d) => `${d.ecosystem}:${d.name}@${d.version}`).sort()).toEqual([
      "cargo:time@0.1.43",
      "go:github.com/dgrijalva/jwt-go@v3.2.0+incompatible",
      "npm:@babel/core@7.24.0",
      "npm:ip@2.0.1",
      "pypi:requests@2.31.0",
      "rubygems:rack@2.2.8",
    ]);
    expect(sbom.skipped).toEqual({ maven: 1 });
  });

  it("reads SPDX purl external references", () => {
    const sbom = readSbom(fx("sbom.spdx.json"));
    expect(sbom.format).toBe("spdx");
    expect(sbom.dependencies.map((d) => `${d.ecosystem}:${d.name}@${d.version}`).sort()).toEqual(["npm:ip@2.0.1", "packagist:symfony/http-kernel@4.4.0"]);
    expect(sbom.skipped).toEqual({ nuget: 1 });
  });

  it("scans an SBOM offline and warns about uncovered ecosystems", async () => {
    const fixtures = join(__dirname, "fixtures");
    const result = await scanSbom(fx("bom.cdx.json"), { offline: true, registryFile: join(fixtures, "registry.json"), indexFile: join(fixtures, "index.json") });
    expect(result.lockfiles).toEqual(["bom.cdx.json"]);
    expect(result.dependencyCount).toBe(6);
    expect(result.warnings.join(" ")).toMatch(/1 maven/);
    expect(result.findings.find((f) => f.dependency.name === "ip")?.kind).toBe("orphaned-vulnerable");
  });

  it("rejects files that are not SBOMs", () => {
    expect(() => readSbom(join(__dirname, "fixtures", "registry.json"))).toThrow(/not a CycloneDX or SPDX/);
  });
});
