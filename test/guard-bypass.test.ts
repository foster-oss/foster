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

describe("found in the 0.8.1 review", () => {
  function mono(): string {
    const root = mkdtempSync(join(tmpdir(), "foster-mono-"));
    writeFileSync(join(root, "package.json"), JSON.stringify({ name: "root", private: true, workspaces: ["apps/*", "!apps/ignored"] }));
    for (const [dir, pkg] of [
      ["apps/a", { name: "a", dependencies: { crossenv: "0.0.2-security", b: "workspace:*", c: "^1.0.0" } }],
      ["apps/c", { name: "c", dependencies: { lodash: "^4.17.0" } }],
      ["apps/ignored", { name: "ignored", dependencies: { "left-pad": "1.3.0" } }],
    ] as const) {
      mkdirSync(join(root, dir), { recursive: true });
      writeFileSync(join(root, dir, "package.json"), JSON.stringify(pkg));
    }
    return root;
  }

  it("includes every workspace's dependencies in a monorepo root install without a lockfile", async () => {
    const { manifestPackages } = await import("../src/lib/guard.js");
    const specs = manifestPackages(mono()).map((p) => p.spec).sort();
    // c is another workspace (internal), b uses workspace:, apps/ignored is excluded
    expect(specs).toEqual(["crossenv@0.0.2-security (apps/a/package.json, no lockfile)", "lodash@^4.17.0 (apps/c/package.json, no lockfile)"]);
  });

  it("reads pnpm-workspace.yaml", async () => {
    const { manifestPackages } = await import("../src/lib/guard.js");
    const root = mono();
    writeFileSync(join(root, "package.json"), JSON.stringify({ name: "root", private: true }));
    writeFileSync(join(root, "pnpm-workspace.yaml"), "packages:\n  - 'apps/*'\n  # comment\n  - '!apps/ignored'\n");
    expect(manifestPackages(root).map((p) => p.name).sort()).toEqual(["crossenv", "lodash"]);
  });

  for (const line of ["npm install", "pnpm install", "yarn install", "npm i --workspace a", "npm i -w a"]) {
    it(`denies malware in a workspace: ${line}`, async () => {
      const r = await guardCommand(line, healthy, async () => true, {
        ...quiet,
        cwd: mono(),
        malware: async (_e, name) => (name === "crossenv" ? [{ id: "GHSA-c2m4-w5hm-vqjw", url: "", title: "crossenv is malware", wholePackage: true }] : []),
      });
      expect(r.decision).toBe("deny");
      expect(r.message).toMatch(/crossenv@0\.0\.2-security \(npm\) is known malware/);
    });
  }

  it("treats npm exec and npm x like npx", () => {
    const names = (line: string) => parseInstallCommand(line).map((p) => p.name);
    expect(names("npm exec crossenv")).toEqual(["crossenv"]);
    expect(names("npm x -- cowsay hi")).toEqual(["cowsay"]);
    expect(names("npm exec --package=create-vite@5 -- create-vite app")).toEqual(["create-vite"]);
    expect(shellInit("bash")).toMatch(/^npm\(\) \{ case "\$\{1:-\}" in [^)]*\|exec\|x\)/m);
  });

  it("notes unmaintained packages without stopping the install", async () => {
    const dead = async (ecosystem: Ecosystem, name: string, version?: string): Promise<CheckResult> => {
      const base = await healthy(ecosystem, name, version);
      return { ...base, record: { ...base.record!, status: "dead", reasons: ["source repository is archived"], downloadsLastMonth: 10_000_000 } };
    };
    const r = await guardCommand("npm i cross-env", dead, async () => true, quiet);
    expect(r.decision).toBe("allow");
    expect(r.message).toMatch(/nothing to flag\.\nNote \(not blocking\):\n- cross-env \(npm\) looks dead \(source repository is archived\)/);
  });
});

describe("found in the 0.8.2 review", () => {
  function staleMono(): string {
    // the root lockfile was written before apps/a added crossenv (a merge, a new workspace)
    const root = lockDir({ lodash: "4.17.21" });
    writeFileSync(join(root, "package.json"), JSON.stringify({ name: "root", private: true, workspaces: ["apps/*"], dependencies: { lodash: "^4.17.0" } }));
    mkdirSync(join(root, "apps/a"), { recursive: true });
    writeFileSync(join(root, "apps/a/package.json"), JSON.stringify({ name: "a", dependencies: { crossenv: "0.0.2-security", lodash: "^4.17.0" } }));
    return root;
  }
  const malware = async (_e: Ecosystem, name: string) => (name === "crossenv" ? [{ id: "GHSA-c2m4-w5hm-vqjw", url: "", title: "crossenv is malware", wholePackage: true }] : []);

  for (const line of ["npm install", "npm i", "yarn install", "pnpm install", "bun install"]) {
    it(`checks what a stale lockfile does not have yet: ${line}`, async () => {
      const asked: string[] = [];
      const r = await guardCommand(line, healthy, async () => true, {
        ...quiet,
        cwd: staleMono(),
        malware: async (e, name, v) => {
          asked.push(name);
          return malware(e, name);
        },
      });
      expect(r.decision).toBe("deny");
      expect(r.message).toMatch(/crossenv@0\.0\.2-security \(npm\) is known malware/);
      expect(asked).toEqual(["crossenv"]); // lodash is in the lockfile: not looked up again
    });
  }

  for (const line of ["npm ci", "pnpm install --frozen-lockfile", "yarn install --immutable", "bun install --frozen-lockfile"]) {
    it(`trusts the lockfile when the install cannot change it: ${line}`, async () => {
      const r = await guardCommand(line, healthy, async () => true, { ...quiet, cwd: staleMono(), malware });
      expect(r.decision).toBe("allow");
    });
  }

  it("notes, rather than asks about, fixable vulnerabilities read from package.json", async () => {
    const dir = mkdtempSync(join(tmpdir(), "foster-guard-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ dependencies: { lodash: "4.17.21" } }));
    const vulnerable = async (ecosystem: Ecosystem, name: string, version?: string): Promise<CheckResult> => ({
      ...(await healthy(ecosystem, name, version)),
      findings: version
        ? [{ kind: "upgrade-available", dependency: { ecosystem, name, version, direct: true, source: "t" }, status: "active", severity: "HIGH", advisories: [{ id: "GHSA-r5fr-rjxr-66jc", url: "", severity: "HIGH", title: "" }], fixedIn: "4.18.0", message: "" }]
        : [],
    });
    const fromManifest = await guardCommand("npm install", vulnerable, async () => true, { ...quiet, cwd: dir });
    expect(fromManifest.decision).toBe("allow");
    expect(fromManifest.message).toMatch(/Note \(not blocking\):\n- lodash@4\.17\.21 \(npm\) is vulnerable/);
    // typed on the command line, it is still a question
    expect((await guardCommand("npm i lodash@4.17.21", vulnerable, async () => true, quiet)).decision).toBe("ask");
  });
});

describe("malware found by the version check itself", () => {
  it("denies a malicious finding with the same detail as the malware lookup", async () => {
    const { verdictFor } = await import("../src/lib/guard.js");
    const v = verdictFor(
      { ecosystem: "npm", name: "evil", version: "1.0.0", spec: "evil@1.0.0" },
      {
        ...(await healthy("npm", "evil", "1.0.0")),
        findings: [{ kind: "malicious", dependency: { ecosystem: "npm", name: "evil", version: "1.0.0", direct: true, source: "t" }, status: "active", severity: "CRITICAL", advisories: [{ id: "MAL-1", url: "https://osv.dev/vulnerability/MAL-1", severity: "CRITICAL", title: "Malicious code in evil" }], message: "" }],
      },
    );
    expect(v.decision).toBe("deny");
    expect(v.reason).toMatch(/known malware \(MAL-1: Malicious code in evil\).*rotate.*Details: https:\/\/osv\.dev/);
  });
});

describe("found in the 0.8.3 review", () => {
  it("denies malware even when the name also looks like a popular package (crossenv vs cross-env)", async () => {
    const { verdictFor } = await import("../src/lib/guard.js");
    const base = await healthy("npm", "crossenv", "0.0.2-security");
    const v = verdictFor(
      { ecosystem: "npm", name: "crossenv", spec: "crossenv" },
      {
        ...base,
        record: { ...base.record!, dependentRepos: 76 },
        findings: [{ kind: "malicious", dependency: { ecosystem: "npm", name: "crossenv", version: "0.0.2-security", direct: true, source: "t" }, status: "unknown", severity: "CRITICAL", advisories: [{ id: "GHSA-c2m4-w5hm-vqjw", url: "https://github.com/advisories/GHSA-c2m4-w5hm-vqjw", severity: "CRITICAL", title: "crossenv is malware" }], message: "" }],
      },
      // exactly what the live path computes for crossenv: a look-alike, version known, no separate malware probe hit
      { lookAlike: { name: "cross-env", dependentRepos: 573_000, distance: 1 }, versionKnown: true, malware: [] },
    );
    expect(v.decision).toBe("deny");
    expect(v.reason).toMatch(/crossenv \(npm\) is known malware \(GHSA-c2m4-w5hm-vqjw: crossenv is malware\)/);
  });

  function staleProject(): string {
    const root = lockDir({ lodash: "4.17.21", ms: "2.1.3" });
    writeFileSync(join(root, "package.json"), JSON.stringify({ name: "root", private: true, workspaces: ["apps/*"], dependencies: { lodash: "^4.17.0", ms: "^3.0.0" } }));
    mkdirSync(join(root, "apps/a"), { recursive: true });
    writeFileSync(join(root, "apps/a/package.json"), JSON.stringify({ name: "a", dependencies: { crossenv: "0.0.2-security" } }));
    return root;
  }

  it("checks what a named install brings along from a stale lockfile", async () => {
    const asked: string[] = [];
    const r = await guardCommand("npm install express", healthy, async () => true, {
      ...quiet,
      cwd: staleProject(),
      lockfileMalware: async () => {
        throw new Error("the lockfile itself is not rescanned for a named install");
      },
      malware: async (_e, name) => {
        asked.push(name);
        return name === "crossenv" ? [{ id: "GHSA-c2m4-w5hm-vqjw", url: "", title: "crossenv is malware", wholePackage: true }] : [];
      },
    });
    expect(r.decision).toBe("deny");
    // express (named), crossenv (not in the lock), ms (the lock has 2.1.3, package.json wants ^3)
    expect(asked.sort()).toEqual(["crossenv", "express", "ms"]);
  });

  it("leaves global installs alone", () => {
    expect(parseCommand("npm i -g typescript", resolve("/p")).lockfiles).toEqual([]);
    expect(parseCommand("npm i typescript", resolve("/p")).lockfiles.map((l) => l.named)).toEqual([true]);
  });

  it("compares versions, not only names", async () => {
    const { unlocked } = await import("../src/lib/guard.js");
    const dep = (name: string, version: string) => ({ ecosystem: "npm" as const, name, version, direct: true, source: "t" });
    const pkg = (name: string, extra: Record<string, unknown>) => ({ ecosystem: "npm" as const, name, spec: name, ...extra });
    const locked = [dep("a", "1.2.0"), dep("b", "4.1.0"), dep("c", "1.0.0")];
    expect(
      unlocked([pkg("a", { range: "^1.0.0" }), pkg("b", { version: "4.1.1" }), pkg("c", { range: "^2" }), pkg("d", { range: "*" }), pkg("a", { range: "latest" })], locked).map((p) => p.name),
    ).toEqual(["b", "c", "d"]);
  });
});

describe("found in the 0.8.4 review", () => {
  it("reads npm overrides, yarn resolutions and pnpm overrides", async () => {
    const { overrideEntries } = await import("../src/lib/guard.js");
    expect(
      overrideEntries({
        overrides: { ms: "npm:crossenv@0.0.2-security", "foo@1.x": "1.2.3", express: { ".": "4.21.2", "body-parser": "1.20.3" }, debug: "$debug" },
        resolutions: { "**/left-pad": "1.3.0", "a/@scope/b": "2.0.0", "c@^1": "1.0.1" },
        pnpm: { overrides: { "x>y": "npm:crossenv@0.0.2-security", "z@<2": "2.0.0", gone: "-" } },
      }),
    ).toEqual([
      ["ms", "npm:crossenv@0.0.2-security", "overrides"],
      ["foo", "1.2.3", "overrides"],
      ["express", "4.21.2", "overrides"],
      ["body-parser", "1.20.3", "overrides"],
      ["debug", "$debug", "overrides"],
      ["left-pad", "1.3.0", "resolutions"],
      ["@scope/b", "2.0.0", "resolutions"],
      ["c", "1.0.1", "resolutions"],
      ["y", "npm:crossenv@0.0.2-security", "pnpm.overrides"],
      ["z", "2.0.0", "pnpm.overrides"],
      ["gone", "-", "pnpm.overrides"],
    ]);
  });

  for (const [field, value] of [
    ["overrides", { ms: "npm:crossenv@0.0.2-security" }],
    ["resolutions", { "**/ms": "npm:crossenv@0.0.2-security" }],
    ["pnpm", { overrides: { ms: "npm:crossenv@0.0.2-security" } }],
  ] as const) {
    it(`denies malware brought in through ${field}`, async () => {
      const dir = mkdtempSync(join(tmpdir(), "foster-guard-"));
      writeFileSync(join(dir, "package.json"), JSON.stringify({ dependencies: { express: "4.21.2" }, [field]: value }));
      const r = await guardCommand("npm install", healthy, async () => true, {
        ...quiet,
        cwd: dir,
        malware: async (_e, name) => (name === "crossenv" ? [{ id: "GHSA-c2m4-w5hm-vqjw", url: "", title: "crossenv is malware", wholePackage: true }] : []),
      });
      expect(r.decision).toBe("deny");
      expect(r.message).toMatch(/crossenv@0\.0\.2-security \(npm\) is known malware/);
    });
  }

  it("skips override references and removals", async () => {
    const { manifestPackages } = await import("../src/lib/guard.js");
    const dir = mkdtempSync(join(tmpdir(), "foster-guard-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ dependencies: { debug: "^4" }, overrides: { debug: "$debug" }, pnpm: { overrides: { foo: "-" } } }));
    expect(manifestPackages(dir).map((p) => p.spec)).toEqual(["debug@^4 (package.json, no lockfile)"]);
  });

  it("understands corepack", () => {
    const cwd = resolve("/p");
    expect(parseCommand("corepack pnpm install", cwd).lockfiles.map((l) => l.tool)).toEqual(["pnpm install"]);
    expect(parseCommand("corepack yarn@4.1.0 install", cwd).lockfiles.map((l) => l.tool)).toEqual(["yarn install"]);
    expect(parseCommand("corepack pnpm@9.1.0 add crossenv", cwd).packages.map((p) => p.name)).toEqual(["crossenv"]);
    expect(parseCommand("pnpx crossenv", cwd).packages.map((p) => p.name)).toEqual(["crossenv"]);
    expect(parseCommand("corepack enable", cwd)).toEqual({ packages: [], lockfiles: [] });
    expect(shellInit("bash")).toMatch(/^corepack\(\) \{ case "\$\{1:-\}" in npm\|npx\|pnpm\|pnpx\|yarn\)/m);
  });
});
