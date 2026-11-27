import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { lockfileAt, scanProject } from "../src/lib/scan.js";

const fixtures = join(__dirname, "fixtures");
const opts = { offline: true, registryFile: join(fixtures, "registry.json"), indexFile: join(fixtures, "index.json") };
const lock = (deps: Record<string, string>) =>
  JSON.stringify({ name: "x", lockfileVersion: 3, packages: { "": { name: "x" }, ...Object.fromEntries(Object.entries(deps).map(([n, v]) => [`node_modules/${n}`, { version: v }])) } });

const dir = mkdtempSync(join(tmpdir(), "foster-since-"));
const git = (...a: string[]) => execFileSync("git", ["-C", dir, ...a], { stdio: "pipe" }).toString().trim();
git("init", "-q", "-b", "main");
git("config", "user.email", "t@example.com");
git("config", "user.name", "t");
writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "x", dependencies: { "utils-merge": "1.0.1" } }));
writeFileSync(join(dir, "package-lock.json"), lock({ "utils-merge": "1.0.1" }));
git("add", "-A");
git("commit", "-qm", "base");
const base = git("rev-parse", "HEAD");
writeFileSync(join(dir, "package-lock.json"), lock({ "utils-merge": "1.0.1", ip: "2.0.1" }));

afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("scan --since", () => {
  it("only reports dependencies added or changed since the ref", async () => {
    const all = await scanProject(dir, opts);
    expect(all.findings.map((f) => f.dependency.name).sort()).toEqual(["ip", "utils-merge"]);
    const since = await scanProject(dir, { ...opts, since: base });
    expect(since.findings.map((f) => f.dependency.name)).toEqual(["ip"]);
    expect(since.since).toBe(base);
    expect(since.unchangedCount).toBe(1);
  });

  it("treats a lockfile that did not exist at the ref as entirely new", () => {
    expect(lockfileAt(dir, "Cargo.lock", base)).toEqual({ text: null });
  });

  it("warns and checks everything when the ref is unknown", async () => {
    const r = await scanProject(dir, { ...opts, since: "does-not-exist" });
    expect(r.warnings.join(" ")).toMatch(/not found/);
    expect(r.findings).toHaveLength(2);
  });
});
