import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parse, parseAllDocuments } from "yaml";

const root = join(__dirname, "..");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const server = JSON.parse(readFileSync(join(root, "server.json"), "utf8"));

describe("release metadata", () => {
  it("server.json matches package.json, so the MCP Registry accepts the release", () => {
    expect(server.name).toBe(pkg.mcpName);
    expect(server.version).toBe(pkg.version);
    expect(server.packages[0].identifier).toBe(pkg.name);
    expect(server.packages[0].version).toBe(pkg.version);
    expect(server.description.length).toBeLessThanOrEqual(100);
  });
});

describe("YAML files", () => {
  // GitHub refuses to load an action or workflow with a YAML error, and only says so when it runs.
  const files = execFileSync("git", ["ls-files", "*.yml", "*.yaml"], { cwd: root, encoding: "utf8" }).split("\n").filter(Boolean);

  it("finds the action and the workflows", () => {
    expect(files).toContain("action.yml");
    expect(files.some((f) => f.startsWith(".github/workflows/"))).toBe(true);
  });

  it.each(files)("%s parses without errors", (file) => {
    const docs = parseAllDocuments(readFileSync(join(root, file), "utf8"));
    expect(docs.flatMap((d) => d.errors.map((e) => e.message))).toEqual([]);
  });

  it("action.yml has the shape GitHub expects", () => {
    const action = parse(readFileSync(join(root, "action.yml"), "utf8"));
    expect(action.runs.using).toBe("composite");
    for (const [name, input] of Object.entries<{ description: unknown }>(action.inputs)) {
      expect(typeof input.description, name).toBe("string");
    }
  });
});
