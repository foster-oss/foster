import { describe, expect, it } from "vitest";
import type { CheckResult } from "../src/lib/check.js";
import { commandLineFrom, goModuleOf, guardCommand, parseCommand, parseInstallCommand, splitCommands, splitGuardArgs, verdictFor } from "../src/lib/guard.js";
import type { Ecosystem } from "../src/lib/types.js";
import { impersonatesFoster } from "../src/lib/typosquat.js";

const noProbes = { malware: async () => [], installRisk: async () => null };

const names = (line: string) => parseInstallCommand(line).map((r) => `${r.ecosystem}:${r.name}${r.version ? `@${r.version}` : ""}`);

describe("commandLineFrom", () => {
  it("takes a single quoted argument as the whole command line", () => {
    expect(names(commandLineFrom(["npm install lodahs"]))).toEqual(["npm:lodahs"]);
  });
  it("joins separate tokens and keeps tokens with spaces together", () => {
    expect(commandLineFrom(["npm", "install", "lodahs"])).toBe("npm install lodahs");
    expect(commandLineFrom(["sh", "-c", "npm i x"])).toBe(`sh -c "npm i x"`);
  });
});

describe("splitGuardArgs", () => {
  it("keeps the command away from Foster's own options, with or without --", () => {
    expect(splitGuardArgs(["guard", "--", "npm", "i", "-D", "vitest"])).toEqual({ own: [], command: ["npm", "i", "-D", "vitest"] });
    // PowerShell drops "--" on the way into npm's .ps1 shim
    expect(splitGuardArgs(["guard", "npm", "i", "-D", "vitest"])).toEqual({ own: [], command: ["npm", "i", "-D", "vitest"] });
    expect(splitGuardArgs(["guard", "--strict", "-q", "pnpm", "add", "--save-dev", "x"])).toEqual({ own: ["--strict", "-q"], command: ["pnpm", "add", "--save-dev", "x"] });
    expect(splitGuardArgs(["guard", "--json", "--", "npm", "i", "--json"])).toEqual({ own: ["--json"], command: ["npm", "i", "--json"] });
  });

  it("passes guard options that take a value, and leaves other subcommands alone", () => {
    expect(splitGuardArgs(["guard", "--hook", "claude"])).toEqual({ own: ["--hook", "claude"], command: [] });
    expect(splitGuardArgs(["guard", "--command", "npm i -D x"])).toEqual({ own: ["--command", "npm i -D x"], command: [] });
    expect(splitGuardArgs(["guard", "--command=npm i x"])).toEqual({ own: ["--command=npm i x"], command: [] });
    expect(splitGuardArgs(["scan", "."])).toBeNull();
  });
});

describe("splitCommands", () => {
  it("splits on operators and honours quotes", () => {
    expect(splitCommands(`cd app && npm i "left pad" ; echo 'a && b' | cat`)).toEqual([["cd", "app"], ["npm", "i", "left pad"], ["echo", "a && b"], ["cat"]]);
  });
});

describe("scaffolders", () => {
  it("checks the create-* package that npm/pnpm/yarn/bun create and npm init run", () => {
    expect(names("npm create vite@latest my-app -- --template react")).toEqual(["npm:create-vite"]);
    expect(names("npm init next-app@14.2.0 web")).toEqual(["npm:create-next-app@14.2.0"]);
    expect(names("pnpm create astro && yarn create remix && bun create hono")).toEqual(["npm:create-astro", "npm:create-remix", "npm:create-hono"]);
    expect(names("npm init @angular")).toEqual(["npm:@angular/create"]);
    expect(names("npm create @scope/app@1.0.0")).toEqual(["npm:@scope/create-app@1.0.0"]);
  });
  it("leaves plain npm init and git templates alone", () => {
    expect(names("npm init -y")).toEqual([]);
    expect(names("bun create user/repo app")).toEqual([]);
  });
});

describe("redirections and command names", () => {
  it("does not take a redirection's target for a package", () => {
    expect(names("npm i react > out.log 2>&1")).toEqual(["npm:react"]);
    expect(names("npm i react >> out.log")).toEqual(["npm:react"]);
    expect(names("npm i react 2> err.txt")).toEqual(["npm:react"]);
    expect(names("npm i react &> all.log")).toEqual(["npm:react"]);
    expect(names("npm i react *> all.log")).toEqual(["npm:react"]);
    expect(names("npm i react 2>$null")).toEqual(["npm:react"]);
    expect(names('npm i react > "my log.txt" && npm i zod')).toEqual(["npm:react", "npm:zod"]);
    expect(names("npm i react 2>&1 | tee log.txt")).toEqual(["npm:react"]);
    expect(names("npm i react >out.log")).toEqual(["npm:react"]);
    expect(names("pip install -r requirements.txt < /dev/null")).toEqual([]);
  });
  it("finds the tool whatever its case or Windows extension", () => {
    expect(names("NPM i crossenv")).toEqual(["npm:crossenv"]);
    expect(names("npm.ps1 i crossenv")).toEqual(["npm:crossenv"]);
    expect(names("C:\\nodejs\\npx.cmd crossenv")).toEqual(["npm:crossenv"]);
  });
});

describe("Go modules", () => {
  const known = new Set(["golang.org/x/tools", "golang.org/x/tools/gopls", "github.com/spf13/cobra"]);
  const exists = async (_e: Ecosystem, n: string) => known.has(n);
  it("checks the module a package path belongs to", async () => {
    expect(await goModuleOf("golang.org/x/tools/cmd/goimports", exists)).toBe("golang.org/x/tools");
    expect(await goModuleOf("golang.org/x/tools/gopls", exists)).toBe("golang.org/x/tools/gopls");
    expect(await goModuleOf("github.com/spf13/cobra", exists)).toBe("github.com/spf13/cobra");
  });
  it("keeps a path nobody knows, so it is reported as not found", async () => {
    expect(await goModuleOf("github.com/nobody/nothing/cmd/x", exists)).toBe("github.com/nobody/nothing/cmd/x");
  });
  it("keeps the path when the proxy cannot be reached", async () => {
    expect(await goModuleOf("golang.org/x/tools/cmd/goimports", async () => null)).toBe("golang.org/x/tools/cmd/goimports");
  });
});

describe("commands inside other commands", () => {
  it("reads command lines handed to bash, cmd, PowerShell, eval and iex", () => {
    expect(names('bash -c "npm i crossenv"')).toEqual(["npm:crossenv"]);
    expect(names("sh -lc 'pip install requests'")).toEqual(["pypi:requests"]);
    expect(names("cmd /c npm i crossenv")).toEqual(["npm:crossenv"]);
    expect(names('powershell -NoProfile -Command "npm i crossenv"')).toEqual(["npm:crossenv"]);
    expect(names('pwsh -c "pnpm add zod"')).toEqual(["npm:zod"]);
    const enc = Buffer.from("npm i crossenv", "utf16le").toString("base64");
    expect(names(`powershell -EncodedCommand ${enc}`)).toEqual(["npm:crossenv"]);
    expect(names('eval "npm i crossenv"')).toEqual(["npm:crossenv"]);
    expect(names('iex "npm i crossenv"')).toEqual(["npm:crossenv"]);
  });

  it("reads installs in subshells, blocks and after shell keywords", () => {
    expect(names("(npm i crossenv)")).toEqual(["npm:crossenv"]);
    expect(names("echo $(npm i crossenv)")).toEqual(["npm:crossenv"]);
    expect(names("if true; then npm i crossenv; fi")).toEqual(["npm:crossenv"]);
    expect(names("for x in 1; do npm i crossenv; done")).toEqual(["npm:crossenv"]);
    expect(names("! npm i crossenv")).toEqual(["npm:crossenv"]);
    expect(names("{ npm i crossenv; }")).toEqual(["npm:crossenv"]);
    expect(names("npm i react & npm i crossenv")).toEqual(["npm:react", "npm:crossenv"]);
  });

  it("reads PowerShell: the call operator, blocks, Set-Location", () => {
    expect(names("& npm i crossenv")).toEqual(["npm:crossenv"]);
    expect(names("if ($true) { npm i crossenv }")).toEqual(["npm:crossenv"]);
    expect(names('npm install zod; "EXIT=$LASTEXITCODE"')).toEqual(["npm:zod"]);
    const dirs = parseCommand("Set-Location -Path web; npm ci", "/repo").lockfiles.map((l) => l.dir.replace(/\\/g, "/").replace(/^[A-Z]:/, ""));
    expect(dirs).toEqual(["/repo/web"]);
  });

  it("leaves redirections, braces in words and quoted text alone", () => {
    expect(names("npm i react 2>&1 | tee log")).toEqual(["npm:react"]);
    expect(names("npm i react &>/dev/null")).toEqual(["npm:react"]);
    expect(names("echo ${HOME}; npm i react")).toEqual(["npm:react"]);
    expect(names('git commit -m "fix (x) & {y}"')).toEqual([]);
  });
});

describe("parseInstallCommand", () => {
  it("reads npm, pnpm, yarn and bun installs, skipping flags and their values", () => {
    expect(names("npm install -D typescript @types/node@20.11.0 --registry https://r.example lodash@^4")).toEqual(["npm:typescript", "npm:@types/node@20.11.0", "npm:lodash"]);
    expect(names("pnpm add -F web react && yarn add vue && bun add zod@3.22.4")).toEqual(["npm:react", "npm:vue", "npm:zod@3.22.4"]);
  });

  it("ignores installs that are not registry packages", () => {
    expect(names("npm install ./local-dir ../x file:../y link:../z")).toEqual([]);
    expect(names("npm install")).toEqual([]);
    expect(names("pip install -r requirements.txt -e .")).toEqual([]);
    // code from git or a URL is reported as remote: nothing can vouch for it
    const remote = parseInstallCommand("npm install git+https://g.com/a/b.git user/repo https://x/y.tgz");
    expect(remote.map((r) => r.remote)).toEqual([true, true, true]);
  });

  it("checks what npx and dlx would run", () => {
    expect(names("npx -y create-vite@5.1.0 my-app")).toEqual(["npm:create-vite@5.1.0"]);
    expect(names("pnpm dlx cowsay hi")).toEqual(["npm:cowsay"]);
    expect(names("npx --package typescript tsc --init")).toEqual(["npm:typescript"]);
  });

  it("reads npm aliases as the real package", () => {
    expect(names("npm i myip@npm:ip@2.0.1")).toEqual(["npm:ip@2.0.1"]);
  });

  it("reads Python installers", () => {
    expect(names("pip install requests==2.31.0 'flask[async]>=2' -i https://pypi.example/simple")).toEqual(["pypi:requests@2.31.0", "pypi:flask"]);
    expect(names("python3 -m pip install numpy && uv add httpx && uv pip install rich==13.7.0 && poetry add django")).toEqual(["pypi:numpy", "pypi:httpx", "pypi:rich@13.7.0", "pypi:django"]);
  });

  it("reads cargo, go, gem, bundle and composer", () => {
    expect(names("cargo add serde@1.0.195 tokio --features full")).toEqual(["cargo:serde@1.0.195", "cargo:tokio"]);
    expect(names("go get github.com/dgrijalva/jwt-go@v3.2.0+incompatible ./... && go install golang.org/x/tools/gopls@latest")).toEqual([
      "go:github.com/dgrijalva/jwt-go@v3.2.0+incompatible",
      "go:golang.org/x/tools/gopls",
    ]);
    expect(names("gem install rails -v 7.1.3 && bundle add nokogiri")).toEqual(["rubygems:rails@7.1.3", "rubygems:nokogiri"]);
    expect(names("composer require monolog/monolog:^3.0 phpoffice/phpexcel")).toEqual(["packagist:monolog/monolog", "packagist:phpoffice/phpexcel"]);
  });

  it("strips sudo, env assignments and paths to the binary", () => {
    expect(names("sudo NODE_ENV=dev /usr/bin/npm install express")).toEqual(["npm:express"]);
  });

  it("ignores commands that install nothing", () => {
    expect(names("ls -la && git status && npm test && npm run build")).toEqual([]);
  });
});

function result(over: Partial<CheckResult> = {}): CheckResult {
  return { ecosystem: "npm", name: "x", record: null, findings: [], notFound: false, ...over };
}

describe("verdicts", () => {
  const req = { ecosystem: "npm" as Ecosystem, name: "x", spec: "x" };

  it("denies names that do not exist (hallucinated or typo'd)", () => {
    expect(verdictFor(req, result({ notFound: true })).decision).toBe("deny");
  });

  it("denies vulnerabilities nobody fixes", () => {
    const v = verdictFor(req, result({ findings: [{ kind: "orphaned-vulnerable", dependency: { ecosystem: "npm", name: "x", version: "1.0.0", direct: true, source: "t" }, status: "dead", severity: "HIGH", advisories: [{ id: "GHSA-a", url: "", severity: "HIGH", title: "" }], message: "" }] }));
    expect(v.decision).toBe("deny");
    expect(v.reason).toMatch(/GHSA-a/);
  });

  it("asks for fixable vulnerabilities, notes unmaintained packages, allows healthy ones", () => {
    expect(verdictFor(req, result({ findings: [{ kind: "upgrade-available", dependency: { ecosystem: "npm", name: "x", version: "1.0.0", direct: true, source: "t" }, status: "active", severity: "LOW", advisories: [], fixedIn: "1.0.1", message: "" }] })).decision).toBe("ask");
    expect(verdictFor(req, result({ record: { ecosystem: "npm", name: "x", status: "dormant", reasons: ["no release for 3 years"], downloadsLastMonth: 1, dependentRepos: 1, dependentPackages: 1, latestVersion: "1.0.0", latestReleaseAt: null, repoUrl: null, archived: false, lastPushAt: null, publishers: 1, unpatchedAdvisories: [], priority: 1 } }))).toMatchObject({ decision: "allow", note: expect.stringMatching(/looks dormant/) });
    expect(verdictFor(req, result()).decision).toBe("allow");
  });
});

describe("guardCommand", () => {
  it("takes the most severe verdict and checks the latest version when none is pinned", async () => {
    const seen: string[] = [];
    const check = async (ecosystem: Ecosystem, name: string, version?: string): Promise<CheckResult> => {
      seen.push(`${name}@${version ?? ""}`);
      if (name === "ghost") return result({ notFound: true, name });
      return result({ name, record: { ecosystem, name, status: "active", reasons: [], downloadsLastMonth: 1, dependentRepos: 1, dependentPackages: 1, latestVersion: "2.0.0", latestReleaseAt: null, repoUrl: null, archived: false, lastPushAt: null, publishers: 1, unpatchedAdvisories: [], priority: 0 } });
    };
    const r = await guardCommand("npm i good ghost", check, async () => false, noProbes);
    expect(r.decision).toBe("deny");
    expect(seen.sort()).toEqual(["ghost@", "good@", "good@2.0.0"]);
    expect(r.message).toMatch(/ghost/);
  });

  it("fails open when the check itself fails", async () => {
    const r = await guardCommand(
      "npm i x",
      async () => {
        throw new Error("offline");
      },
      async () => null,
      noProbes,
    );
    expect(r.decision).toBe("allow");
    expect(r.verdicts[0]?.reason).toMatch(/could not be checked/);
  });

  it("says when a command installs nothing", async () => {
    expect((await guardCommand("echo hi")).message).toMatch(/no package installs/);
  });
});

describe("look-alike (typosquat) detection", () => {
  it("measures edit distance with transpositions", async () => {
    const { editDistance } = await import("../src/lib/typosquat.js");
    expect(editDistance("lodahs", "lodash")).toBe(1);
    expect(editDistance("expresss", "express")).toBe(1);
    expect(editDistance("abc", "xyz", 2)).toBe(3);
  });

  it("flags rarely used names next to very popular packages, not real neighbours", async () => {
    const { lookAlike } = await import("../src/lib/typosquat.js");
    expect(lookAlike("npm", "lodahs", 3)?.name).toBe("lodash");
    expect(lookAlike("pypi", "reqeusts", 0)?.name).toBe("requests");
    expect(lookAlike("npm", "preact", 78_992)).toBeUndefined(); // popular in its own right
    expect(lookAlike("npm", "lodash", 1_900_000)).toBeUndefined(); // is the popular package
    expect(lookAlike("npm", "ws", 0)).toBeUndefined(); // too short to judge
  });

  it("asks about look-alikes and adds 'did you mean' to unknown names", () => {
    const req = { ecosystem: "npm" as Ecosystem, name: "lodahs", spec: "lodahs" };
    const like = { name: "lodash", dependentRepos: 1_900_000, distance: 1 };
    const ask = verdictFor(req, result({ record: null }), { lookAlike: like });
    expect(ask.decision).toBe("ask");
    expect(ask.reason).toMatch(/typo of a much more popular package: lodash/);
    const deny = verdictFor(req, result({ notFound: true }), { lookAlike: like, existsOnRegistry: false });
    expect(deny.decision).toBe("deny");
    expect(deny.reason).toMatch(/Did you mean lodash/);
  });

  it("asks (not denies) for brand-new packages the index does not know yet", () => {
    const req = { ecosystem: "npm" as Ecosystem, name: "brand-new-thing", spec: "brand-new-thing" };
    expect(verdictFor(req, result({ notFound: true }), { existsOnRegistry: true }).decision).toBe("ask");
  });
});

describe("look-alikes of Foster itself", () => {
  it("knows which names pose as Foster", () => {
    for (const n of ["fostre-oss", "foster-os", "foster-osss", "fster-oss", "foster-oss-cli", "fosteross-guard", "foster", "@foster-oss/cli", "@evil/foster-oss", "foster_oss"]) {
      expect(impersonatesFoster("npm", n), n).toBe(true);
    }
    expect(impersonatesFoster("pypi", "foster-oss")).toBe(true);
    expect(impersonatesFoster("go", "github.com/evil/foster-oss")).toBe(true);
  });
  it("leaves Foster and names that only look similar by chance alone", () => {
    for (const n of ["foster-oss", "poster", "faster", "roster", "fastify", "forester", "fostering", "react"]) {
      expect(impersonatesFoster("npm", n), n).toBe(false);
    }
    expect(impersonatesFoster("pypi", "foster")).toBe(false);
  });
  it("asks about a registered look-alike and points to the real name for a missing one", () => {
    const fake = { ecosystem: "npm" as Ecosystem, name: "fostre-oss", spec: "fostre-oss" };
    const registered = verdictFor(fake, result({ name: "fostre-oss" }));
    expect(registered.decision).toBe("ask");
    expect(registered.reason).toMatch(/is not Foster.*"foster-oss" on npm/);
    const brandNew = verdictFor(fake, result({ notFound: true }), { existsOnRegistry: true });
    expect(brandNew.decision).toBe("ask");
    expect(brandNew.reason).toMatch(/is not Foster/);
    const missing = verdictFor(fake, result({ notFound: true }), { existsOnRegistry: false });
    expect(missing.decision).toBe("deny");
    expect(missing.reason).toMatch(/Did you mean foster-oss/);
    expect(verdictFor({ ecosystem: "npm", name: "foster-oss", spec: "foster-oss" }, result({ name: "foster-oss" })).decision).toBe("allow");
  });
  it("still denies a look-alike that is known malware", () => {
    const v = verdictFor({ ecosystem: "npm", name: "fostre-oss", spec: "fostre-oss" }, result(), { malware: [{ id: "MAL-1", url: "u", title: "t", wholePackage: true }] });
    expect(v.decision).toBe("deny");
  });
});
