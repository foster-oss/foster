import { describe, expect, it } from "vitest";
import type { CheckResult } from "../src/lib/check.js";
import { commandLineFrom, guardCommand, parseInstallCommand, splitCommands, verdictFor } from "../src/lib/guard.js";
import type { Ecosystem } from "../src/lib/types.js";

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

describe("splitCommands", () => {
  it("splits on operators and honours quotes", () => {
    expect(splitCommands(`cd app && npm i "left pad" ; echo 'a && b' | cat`)).toEqual([["cd", "app"], ["npm", "i", "left pad"], ["echo", "a && b"], ["cat"]]);
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

  it("asks for fixable vulnerabilities and unmaintained packages, allows healthy ones", () => {
    expect(verdictFor(req, result({ findings: [{ kind: "upgrade-available", dependency: { ecosystem: "npm", name: "x", version: "1.0.0", direct: true, source: "t" }, status: "active", severity: "LOW", advisories: [], fixedIn: "1.0.1", message: "" }] })).decision).toBe("ask");
    expect(verdictFor(req, result({ record: { ecosystem: "npm", name: "x", status: "dormant", reasons: ["no release for 3 years"], downloadsLastMonth: 1, dependentRepos: 1, dependentPackages: 1, latestVersion: "1.0.0", latestReleaseAt: null, repoUrl: null, archived: false, lastPushAt: null, publishers: 1, unpatchedAdvisories: [], priority: 1 } })).decision).toBe("ask");
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
