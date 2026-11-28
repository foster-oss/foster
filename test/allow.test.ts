import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadAllowList, privateScopeRegistry } from "../src/lib/allow.js";
import type { CheckResult } from "../src/lib/check.js";
import { FALSE_ALARM, guardCommand } from "../src/lib/guard.js";
import type { Ecosystem } from "../src/lib/types.js";

const dir = (files: Record<string, string>) => {
  const d = mkdtempSync(join(tmpdir(), "foster-allow-"));
  for (const [f, text] of Object.entries(files)) {
    mkdirSync(join(d, f, ".."), { recursive: true });
    writeFileSync(join(d, f), text);
  }
  return d;
};
const noEnv = {} as NodeJS.ProcessEnv;
const record = (ecosystem: Ecosystem, name: string) => ({ ecosystem, name, status: "active" as const, reasons: [], downloadsLastMonth: 1, dependentRepos: 10_000, dependentPackages: 1, latestVersion: "1.0.0", latestReleaseAt: null, repoUrl: null, archived: false, lastPushAt: null, publishers: 2, unpatchedAdvisories: [], priority: 0 });
// every name exists and is widely used, except "acme-internal" and "zz-nowhere", which no registry has
const check = async (ecosystem: Ecosystem, name: string, version?: string): Promise<CheckResult> =>
  /acme-internal|zz-nowhere|@acme\//.test(name)
    ? { ecosystem, name, version, record: null, findings: [], notFound: true }
    : { ecosystem, name, version, record: record(ecosystem, name), findings: [], notFound: false };
const exists = async (_e: Ecosystem, name: string) => !/acme-internal|zz-nowhere|@acme\//.test(name);
const probes = (bad: string[] = []) => ({
  malware: async (_e: Ecosystem, name: string) => (bad.includes(name) ? [{ id: "MAL-1", url: "", title: `${name} is malware`, wholePackage: true }] : []),
  installRisk: async () => null,
  resolveRange: async () => undefined,
  lockfileMalware: async () => [],
  samePublisher: async () => null,
});

describe("allow lists", () => {
  it("matches names, ecosystems, wildcards and PyPI's spelling", () => {
    const d = dir({ ".foster.json": JSON.stringify({ allow: ["acme-internal", "npm:@acme/*", "pypi:Acme_Tools", "go:github.com/acme/*"] }) });
    const list = loadAllowList(d, noEnv)!;
    expect(list.source).toBe(`.foster.json in ${d}`);
    expect(list.matches("npm", "acme-internal")).toBe(true);
    expect(list.matches("pypi", "acme-internal")).toBe(true);
    expect(list.matches("npm", "@acme/ui")).toBe(true);
    expect(list.matches("npm", "@acme-evil/ui")).toBe(false);
    expect(list.matches("pypi", "acme-tools")).toBe(true);
    expect(list.matches("npm", "acme-tools")).toBe(false);
    expect(list.matches("go", "github.com/acme/lib")).toBe(true);
    expect(list.matches("npm", "acme-internal-2")).toBe(false);
  });
  it("is found in a folder above, combined with FOSTER_ALLOW, and a broken file is reported", () => {
    const d = dir({ ".foster.json": JSON.stringify({ allow: ["a1"] }), "web/package.json": "{}" });
    const list = loadAllowList(join(d, "web"), { FOSTER_ALLOW: "b1, npm:c1" })!;
    expect(["a1", "b1", "c1"].every((n) => list.matches("npm", n))).toBe(true);
    expect(list.source).toMatch(/^FOSTER_ALLOW and \.foster\.json/);
    const broken = loadAllowList(dir({ ".foster.json": "{ allow: [" }), noEnv)!;
    expect(broken.source).toBe("");
    expect(broken.error).toMatch(/could not be read/);
  });
  it("turns a question or a missing name into a note, never silently", async () => {
    const d = dir({ ".foster.json": JSON.stringify({ allow: ["acme-internal"] }) });
    const r = await guardCommand("npm i acme-internal react", check, exists, { ...probes(), cwd: d });
    expect(r.decision).toBe("allow");
    expect(r.message).toMatch(/acme-internal \(npm\) does not exist on the registry.*Allowed by \.foster\.json/s);
    // without the list it is blocked, with the way to report a false alarm
    const blocked = await guardCommand("npm i acme-internal", check, exists, { ...probes(), cwd: d, allow: null });
    expect(blocked.decision).toBe("deny");
    expect(blocked.message).toContain(FALSE_ALARM);
  });
  it("never allows known malware", async () => {
    const d = dir({ ".foster.json": JSON.stringify({ allow: ["*"] }) });
    const r = await guardCommand("npm i crossenv", check, exists, { ...probes(["crossenv"]), cwd: d });
    expect(r.decision).toBe("deny");
    expect(r.message).toMatch(/known malware/);
    // known malware gets no "false alarm?" line
    expect(r.message).not.toContain(FALSE_ALARM);
  });
  it("leaves everything else alone", async () => {
    const d = dir({ ".foster.json": JSON.stringify({ allow: ["acme-internal"] }) });
    expect((await guardCommand("npm i zz-nowhere", check, exists, { ...probes(), cwd: d })).decision).toBe("deny");
  });
});

describe("private npm scopes", () => {
  it("reads the scope's registry from the nearest .npmrc", () => {
    const d = dir({ ".npmrc": "registry=https://registry.npmjs.org/\n@acme:registry=https://npm.acme.dev/\n@pub:registry=https://registry.npmjs.org/\n", "web/x": "" });
    expect(privateScopeRegistry(join(d, "web"), "@acme/ui", { NPM_CONFIG_USERCONFIG: join(d, "none") })).toBe("https://npm.acme.dev/");
    expect(privateScopeRegistry(d, "@pub/ui", { NPM_CONFIG_USERCONFIG: join(d, "none") })).toBeNull();
    expect(privateScopeRegistry(d, "react", { NPM_CONFIG_USERCONFIG: join(d, "none") })).toBeNull();
  });
  it("installs a private scope with a note instead of calling it missing", async () => {
    const d = dir({ "web/.npmrc": "@acme:registry=https://npm.acme.dev/\n", "web/package.json": "{}" });
    const r = await guardCommand("cd web && npm i @acme/ui", check, exists, { ...probes(), cwd: d, allow: null });
    expect(r.decision).toBe("allow");
    expect(r.message).toMatch(/@acme\/ui \(npm\) comes from npm\.acme\.dev, a private registry/);
  });
});
