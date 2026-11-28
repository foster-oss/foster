import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { lifecyclePackages, manifestPackages, otherManifestPackages, parseCommand } from "../src/lib/guard.js";
import { parseBunLock, parsePnpmLock, readDependencies } from "../src/lib/lockfile.js";

const project = (files: Record<string, string>) => {
  const dir = mkdtempSync(join(tmpdir(), "foster-files-"));
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(join(dir, path, ".."), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  return dir;
};
const names = (rs: { name: string }[]) => rs.map((r) => r.name).sort();

describe("lockfiles", () => {
  it("reads a pnpm lockfile written as several YAML documents", () => {
    const text = "---\npackageManagerDependencies:\n  pnpm: 12.0.0\n---\nlockfileVersion: '9.0'\npackages:\n  react@18.2.0:\n    resolution: {integrity: x}\n";
    expect(parsePnpmLock(text)).toEqual([["react", "18.2.0"]]);
  });
  it("reads bun.lock (JSONC) and skips workspace and git entries", () => {
    const text = `{
  // bun.lock
  "lockfileVersion": 1,
  "workspaces": { "": { "name": "app", "dependencies": { "react": "^18" } }, },
  "packages": {
    "react": ["react@18.2.0", "", {}, "sha512-a"],
    "@types/node": ["@types/node@20.0.0", "", {}, "sha512-b"],
    "app-lib": ["app-lib@workspace:packages/lib"],
    "gitdep": ["gitdep@github:owner/repo#abc", {}],
  },
}`;
    expect(parseBunLock(text)).toEqual([["react", "18.2.0"], ["@types/node", "20.0.0"]]);
    const dir = project({ "bun.lock": text, "package.json": '{"dependencies":{"react":"^18"}}' });
    expect(readDependencies(dir, { file: "bun.lock", kind: "bun-lock", ecosystem: "npm" }).map((d) => d.name).sort()).toEqual(["@types/node", "react"]);
  });
});

describe("pnpm-workspace.yaml and package.json", () => {
  it("reads flow-style packages, overrides and catalogs", () => {
    const dir = project({
      "package.json": '{"name":"root","dependencies":{"react":"catalog:","vue":"catalog:legacy"}}',
      "pnpm-workspace.yaml": "packages: ['apps/*']\ncatalog:\n  react: npm:zz-cat@1.0.0\ncatalogs:\n  legacy:\n    vue: 2.7.0\noverrides:\n  loose-envify: npm:zz-over@1.0.0\n",
      "apps/web/package.json": '{"name":"web","dependencies":{"zz-ws":"1.0.0"}}',
    });
    expect(names(manifestPackages(dir))).toEqual(["vue", "zz-cat", "zz-over", "zz-ws"]);
  });
  it("expands braces in workspace globs", () => {
    const dir = project({ "package.json": '{"workspaces":["packages/{a,b}"]}', "packages/a/package.json": '{"dependencies":{"zz-a":"1.0.0"}}', "packages/b/package.json": '{"dependencies":{"zz-b":"1.0.0"}}' });
    expect(names(manifestPackages(dir))).toEqual(["zz-a", "zz-b"]);
  });
  it("reads install scripts in the root package.json", () => {
    const dir = project({ "package.json": '{"scripts":{"postinstall":"npm i zz-post","build":"npm i zz-not-run"}}' });
    expect(names(lifecyclePackages(dir))).toEqual(["zz-post"]);
  });
});

describe("manifests outside npm", () => {
  it("reads pyproject, composer.json, Cargo.toml and Gemfile when there is no lockfile", () => {
    const dir = project({
      "pyproject.toml": '[project]\nname = "app"\ndependencies = ["requests>=2", "zz-py"]\n',
      "composer.json": '{"require":{"php":">=8","ext-json":"*","zz/php":"5.0.2"}}',
      "Cargo.toml": '[package]\nname = "app"\n[dependencies]\nzz-rs = "0.1"\n',
      "Gemfile": 'source "https://rubygems.org"\ngem "zz-rb", "1.0"\n',
    });
    expect(names(otherManifestPackages(dir, "pypi"))).toEqual(["requests", "zz-py"]);
    expect(names(otherManifestPackages(dir, "packagist"))).toEqual(["zz/php"]);
    expect(names(otherManifestPackages(dir, "cargo"))).toEqual(["zz-rs"]);
    expect(names(otherManifestPackages(dir, "rubygems"))).toEqual(["zz-rb"]);
  });
  it("treats pip install . and -e . as a project install", () => {
    const l = parseCommand("pip install . && pip install -e ./lib", "/w").lockfiles;
    expect(l.map((x) => x.manifest)).toEqual([true, true]);
    expect(parseCommand("pip install ./dist/x.whl", "/w").lockfiles).toEqual([]);
  });
});
