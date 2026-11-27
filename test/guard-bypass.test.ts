import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import type { CheckResult } from "../src/lib/check.js";
import { guardCommand, installsSomething, parseCommand, parseInstallCommand } from "../src/lib/guard.js";
import { resolveNpmVersion, type FetchJson } from "../src/lib/npmrisk.js";
import { shellInit } from "../src/lib/shell.js";
import type { Ecosystem } from "../src/lib/types.js";

// The four ways past guard that an outside review found in 0.7.0, plus the shell integration.

function lockDir(packages: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "foster-guard-"));
  const pkgs: Record<string, unknown> = { "": { name: "demo", version: "1.0.0", dependencies: packages } };
  for (const [n, v] of Object.entries(packages)) pkgs[`node_modules/${n}`] = { version: v };
  writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ name: "demo", version: "1.0.0", lockfileVersion: 3, requires: true, packages: pkgs }));
  return dir;
}

const healthy = async (ecosystem: Ecosystem, name: string, version?: string): Promise<CheckResult> => ({
  ecosystem,
  name,
  version,
  record: { ecosystem, name, status: "active", reasons: [], downloadsLastMonth: 1, dependentRepos: 10_000, dependentPackages: 1, latestVersion: "4.3.2", latestReleaseAt: null, repoUrl: null, archived: false, lastPushAt: null, publishers: 2, unpatchedAdvisories: [], priority: 0 },
  findings: [],
  notFound: false,
});

const quiet = { malware: async () => [], installRisk: async () => null, resolveRange: async () => undefined, lockfileMalware: async () => [] };

describe("lockfile installs (npm ci and friends)", () => {
  it("recognises installs that take their list from a lockfile, and where", () => {
    const cwd = resolve("/work");
    const l = (line: string) => parseCommand(line, cwd).lockfiles.map((x) => `${x.tool}|${x.dir}|${x.file ?? ""}`);
    expect(l("npm ci")).toEqual([`npm ci|${cwd}|`]);
    expect(l("npm install --no-audit")).toEqual([`npm install|${cwd}|`]);
    expect(l("cd app && npm i")).toEqual([`npm i|${resolve(cwd, "app")}|`]);
    expect(l("npm ci --prefix web")).toEqual([`npm ci|${resolve(cwd, "web")}|`]);
    expect(l("pnpm install --frozen-lockfile")).toEqual([`pnpm install|${cwd}|`]);
    expect(l("yarn")).toEqual([`yarn install|${cwd}|`]);
    expect(l("yarn --immutable")).toEqual([`yarn install|${cwd}|`]);
    expect(l("pip install -r requirements/dev.txt")).toEqual([`pip install -r|${cwd}|requirements/dev.txt`]);
    // uv and poetry read the same Python lockfiles here: checked once
    expect(l("uv sync && poetry install && bundle install && composer install")).toHaveLength(3);
    // these install nothing from a lockfile
    expect(l("npm run build && yarn build && npm add")).toEqual([]);
    expect(installsSomething("npm test")).toBe(false);
    expect(installsSomething("npm ci")).toBe(true);
  });

  it("denies a lockfile install that would put known malware on disk", async () => {
    const dir = lockDir({ crossenv: "0.0.2-security", lodash: "4.17.21" });
    const seen: string[] = [];
    const r = await guardCommand("npm ci", healthy, async () => true, {
      ...quiet,
      cwd: dir,
      lockfileMalware: async (deps) => {
        seen.push(...deps.map((d) => `${d.name}@${d.version}`));
        const evil = deps.find((d) => d.name === "crossenv")!;
        return [{ dependency: evil, report: { id: "GHSA-c2m4-w5hm-vqjw", url: "", title: "crossenv is malware", wholePackage: false } }];
      },
    });
    expect(seen.sort()).toEqual(["crossenv@0.0.2-security", "lodash@4.17.21"]);
    expect(r.decision).toBe("deny");
    expect(r.message).toMatch(/npm ci \(package-lock\.json\) would install known malware: crossenv@0\.0\.2-security/);
    expect(r.message).toMatch(/security placeholder/);
  });

  it("allows a clean lockfile and says how much it checked", async () => {
    const dir = lockDir({ lodash: "4.17.21" });
    const r = await guardCommand("npm ci", healthy, async () => true, { ...quiet, cwd: dir });
    expect(r.decision).toBe("allow");
    expect(r.message).toMatch(/1 locked package\(s\) checked for known malware/);
  });

  it("stays quiet where there is no lockfile, and fails open when OSV is down", async () => {
    const empty = mkdtempSync(join(tmpdir(), "foster-guard-"));
    expect((await guardCommand("npm ci", healthy, async () => true, { ...quiet, cwd: empty })).message).toMatch(/no package installs/);
    const dir = lockDir({ lodash: "4.17.21" });
    mkdirSync(join(dir, "sub"));
    const down = await guardCommand("npm ci", healthy, async () => true, {
      ...quiet,
      cwd: dir,
      lockfileMalware: async () => {
        throw new Error("offline");
      },
    });
    expect(down.decision).toBe("allow");
    expect(down.verdicts[0]?.reason).toMatch(/could not be checked/);
  });
});

describe("aliases, tarballs and URLs", () => {
  const names = (line: string) => parseInstallCommand(line).map((r) => `${r.name}@${r.version ?? r.range ?? ""}${r.remote ? " (remote)" : ""}`);

  it("checks the real package behind an npm alias", () => {
    expect(names("npm i tc@npm:@ctrl/tinycolor@4.1.1")).toEqual(["@ctrl/tinycolor@4.1.1"]);
    expect(names("pnpm add lodash4@npm:lodash@^4")).toEqual(["lodash@^4"]);
  });

  it("reads package and version from npm registry tarball URLs", () => {
    expect(names("npm i https://registry.npmjs.org/@ctrl/tinycolor/-/tinycolor-4.1.1.tgz")).toEqual(["@ctrl/tinycolor@4.1.1"]);
    expect(names("npm i https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")).toEqual(["lodash@4.17.21"]);
  });

  it("asks about code from other URLs and git", async () => {
    expect(names("npm i https://evil.example/x.tgz github:a/b")).toEqual(["https://evil.example/x.tgz@ (remote)", "github:a/b@ (remote)"]);
    expect(names("pip install git+https://github.com/a/b.git 'pkg @ https://x.example/p.whl'")).toHaveLength(2);
    const r = await guardCommand("npm i https://evil.example/x.tgz", healthy, async () => true, quiet);
    expect(r.decision).toBe("ask");
    expect(r.message).toMatch(/cannot check it/);
  });

  it("keeps ranges and dist-tags to resolve them", () => {
    expect(names(`npm i "@ctrl/tinycolor@^4.1.0" react@next lodash@latest vue@3.4.0`)).toEqual(["@ctrl/tinycolor@^4.1.0", "react@next", "lodash@", "vue@3.4.0"]);
  });
});

describe("version ranges", () => {
  const get = (async (url: string) => {
    if (url.endsWith("/lodash")) return { "dist-tags": { latest: "4.17.21", next: "5.0.0-rc.1" }, versions: { "3.10.0": {}, "3.10.1": {}, "4.17.21": {}, "5.0.0-rc.1": {} } };
    throw new Error(url);
  }) as FetchJson;

  it("needs no request when the latest release satisfies the range", async () => {
    expect(await resolveNpmVersion("lodash", "^4.1.0", "4.17.21", get)).toBe("4.17.21");
  });

  it("finds the best match for older ranges and dist-tags", async () => {
    expect(await resolveNpmVersion("lodash", "^3", "4.17.21", get)).toBe("3.10.1");
    expect(await resolveNpmVersion("lodash", "next", "4.17.21", get)).toBe("5.0.0-rc.1");
    expect(await resolveNpmVersion("lodash", "^9", "4.17.21", get)).toBeUndefined();
  });

  it("checks the resolved version, not the latest", async () => {
    const asked: string[] = [];
    const r = await guardCommand("npm i tinycolor@~4.1.0", healthy, async () => true, {
      ...quiet,
      resolveRange: async () => "4.1.1",
      malware: async (_e, name, version) => {
        asked.push(`${name}@${version}`);
        return version === "4.1.1" ? [{ id: "MAL-2025-47141", url: "", title: "Malicious code in tinycolor", wholePackage: false }] : [];
      },
    });
    expect(asked).toEqual(["tinycolor@4.1.1"]);
    expect(r.decision).toBe("deny");
    expect(r.message).toMatch(/tinycolor@4\.1\.1 \(npm\) is known malware/);
  });
});

describe("shell-init", () => {
  it("wraps install subcommands only, and lets guard failures through", () => {
    const sh = shellInit("bash");
    expect(sh).toMatch(/^npm\(\) \{ case "\$\{1:-\}" in install\|i\|/m);
    expect(sh).toMatch(/^yarn\(\) \{ case "\$\{1:-\}" in ""\|add/m);
    expect(sh).toMatch(/^npx\(\) \{ __foster_guard npx "\$@" \|\| return 1; command npx "\$@"; \}/m);
    expect(sh).toContain("*) return 0 ;; # guard itself could not run");
    expect(shellInit("powershell")).toMatch(/function global:npm \{ if \(+\$args.Count -gt 0 -and @\('install'/);
  });

  it("produces valid bash", () => {
    const res = spawnSync("bash", ["-n"], { input: shellInit("bash"), encoding: "utf8" });
    if (res.error) return; // no bash on this machine
    expect(res.status, res.stderr).toBe(0);
  });
});

describe("Windows paths in commands", () => {
  it("keeps backslashes in cd targets, quoted or not", () => {
    const base = resolve("/work");
    // resolve(base, …): an absolute C:\ path on Windows, a (strange but harmless) relative one elsewhere
    expect(parseCommand(String.raw`cd "C:\Users\me\app" && npm ci`, base).lockfiles[0]?.dir).toBe(resolve(base, String.raw`C:\Users\me\app`));
    expect(parseCommand(String.raw`cd C:\proj\web; npm ci`, base).lockfiles[0]?.dir).toBe(resolve(base, String.raw`C:\proj\web`));
  });

  it("still honours POSIX escapes", async () => {
    const { splitCommands } = await import("../src/lib/guard.js");
    expect(splitCommands(String.raw`echo "a\"b" "c\$d" x\ y`)).toEqual([["echo", 'a"b', "c$d", "x y"]]);
  });
});

describe("found in the 0.8.0 review", () => {
  it("reads global options before the subcommand", () => {
    const cwd = resolve("/mono");
    const dir = (line: string) => parseCommand(line, cwd).lockfiles.map((l) => l.dir);
    for (const line of ["npm --prefix apps/a ci", "npm -C apps/a ci", "npm --prefix=apps/a ci", "npm ci --prefix apps/a", "pnpm -C apps/a install", "yarn --cwd apps/a install", "yarn --cwd apps/a"])
      expect(dir(line), line).toEqual([resolve(cwd, "apps/a")]);
    expect(parseCommand("npm --prefix apps/a i lodash", cwd).packages.map((p) => p.name)).toEqual(["lodash"]);
    expect(parseCommand("pip --disable-pip-version-check -q install requests", cwd).packages.map((p) => p.name)).toEqual(["requests"]);
  });

  it("checks package.json when there is no lockfile to read", async () => {
    const dir = mkdtempSync(join(tmpdir(), "foster-guard-"));
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify({ dependencies: { crossenv: "0.0.2-security", lodash: "^4.17.0", local: "file:../x", ws: "workspace:*" }, devDependencies: { tc: "npm:@ctrl/tinycolor@4.1.1", gh: "github:a/b" } }),
    );
    const seen: string[] = [];
    const r = await guardCommand("npm install", healthy, async () => true, {
      ...quiet,
      cwd: dir,
      malware: async (_e, name, version) => {
        seen.push(`${name}@${version ?? ""}`);
        return name === "crossenv" ? [{ id: "GHSA-c2m4-w5hm-vqjw", url: "", title: "crossenv is malware", wholePackage: true }] : [];
      },
    });
    expect(seen.sort()).toEqual(["@ctrl/tinycolor@4.1.1", "crossenv@0.0.2-security", "lodash@4.3.2"]);
    expect(r.decision).toBe("deny");
    expect(r.message).toMatch(/crossenv@0\.0\.2-security \(npm\) is known malware/);
    expect(r.message).toMatch(/gh@github:a\/b \(package\.json, no lockfile\) is installed straight from a URL or git/);
  });

  it("checks lockfile names for slopsquats and look-alikes", async () => {
    const dir = lockDir({ expres: "4.18.2", lodash: "4.17.21", lodahs: "4.17.21" });
    const lookups: string[] = [];
    const check = async (ecosystem: Ecosystem, name: string, version?: string): Promise<CheckResult> => {
      lookups.push(name);
      if (name === "expres") return { ...(await healthy(ecosystem, name, version)), record: null, notFound: true };
      const base = await healthy(ecosystem, name, version);
      return { ...base, record: { ...base.record!, dependentRepos: 3 } };
    };
    const r = await guardCommand("npm ci", check, async (_e, name) => name !== "expres", { ...quiet, cwd: dir });
    expect(lookups.sort()).toEqual(["expres", "lodahs"]); // only look-alikes are looked up, never lodash
    expect(r.decision).toBe("deny");
    expect(r.message).toMatch(/do not exist on the registry: expres@4\.18\.2 \(did you mean express\?\)/);
    expect(r.message).toMatch(/lodahs@4\.17\.21 looks like lodash/);
  });
});

describe("look-alikes that are simply new and huge", () => {
  it("trusts names with heavy downloads even when dependent counts lag", async () => {
    const { lookAlike } = await import("../src/lib/typosquat.js");
    // call-bound vs call-bind: a billion downloads a month, but ecosyste.ms counts 0 dependent repos
    expect(lookAlike("npm", "call-bound", 0)).toBeDefined();
    expect(lookAlike("npm", "call-bound", 0, 1_000_000_000)).toBeUndefined();
    expect(lookAlike("npm", "lodahs", 0, 40)).toBeDefined();
  });
});
