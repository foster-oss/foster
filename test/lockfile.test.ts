import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { detectLockfiles, readDependencies } from "../src/lib/lockfile.js";

const fx = (name: string) => join(__dirname, "fixtures", name);

function pairs(dir: string) {
  return detectLockfiles(dir)
    .flatMap((l) => readDependencies(dir, l))
    .map((d) => `${d.name}@${d.version}`)
    .sort();
}

describe("lockfile parsing", () => {
  it("reads package-lock v3 including scoped, nested and aliased packages, skipping links", () => {
    expect(pairs(fx("npm-v3"))).toEqual(["@scope/thing@3.1.0", "express@4.18.2", "ip@2.0.1", "real-name@1.2.3", "utils-merge@1.0.1"]);
  });

  it("marks direct dependencies from package.json", () => {
    const dir = fx("npm-v3");
    const deps = readDependencies(dir, detectLockfiles(dir)[0]!);
    expect(deps.find((d) => d.name === "ip")?.direct).toBe(true);
    expect(deps.find((d) => d.name === "utils-merge")?.direct).toBe(false);
  });

  it("reads package-lock v1 with nested deps and npm aliases, skipping file: deps", () => {
    expect(pairs(fx("npm-v1"))).toEqual(["ip@1.1.8", "lodash@4.17.21", "qs@6.5.3", "request@2.88.2"]);
  });

  it("reads pnpm lockfile v6 with peer suffixes", () => {
    expect(pairs(fx("pnpm-v6"))).toEqual(["@babel/core@7.24.0", "ip@2.0.1", "react-dom@18.2.0"]);
  });

  it("reads pnpm lockfile v9", () => {
    expect(pairs(fx("pnpm-v9"))).toEqual(["@types/node@20.11.0", "ip@2.0.1"]);
  });

  it("reads yarn classic lockfiles including aliases", () => {
    expect(pairs(fx("yarn-v1"))).toEqual(["@babel/code-frame@7.23.5", "ip@2.0.1", "lodash@4.17.21"]);
  });

  it("reads yarn berry lockfiles and skips workspaces", () => {
    expect(pairs(fx("yarn-berry"))).toEqual(["@babel/code-frame@7.23.5", "ip@2.0.1"]);
  });

  it("reads exact pins from requirements.txt and normalises names", () => {
    expect(pairs(fx("python-req"))).toEqual(["django@4.2.7", "requests@2.31.0", "zope-interface@6.1"]);
  });

  it("reads uv.lock and skips the editable project itself", () => {
    expect(pairs(fx("python-uv"))).toEqual(["requests@2.31.0", "typing-extensions@4.9.0"]);
  });

  it("reads poetry.lock and Pipfile.lock", () => {
    expect(pairs(fx("poetry"))).toEqual(["requests@2.31.0", "urllib3@2.1.0"]);
    expect(pairs(fx("pipenv"))).toEqual(["flask@2.0.1", "pytest@7.4.0"]);
  });

  it("reads Cargo.lock registry packages and marks Cargo.toml deps as direct", () => {
    const dir = fx("cargo");
    expect(pairs(dir)).toEqual(["itoa@1.0.10", "serde@1.0.195", "time@0.1.43"]);
    const deps = readDependencies(dir, detectLockfiles(dir)[0]!);
    expect(deps.every((d) => d.ecosystem === "cargo")).toBe(true);
    expect(deps.find((d) => d.name === "serde")?.direct).toBe(true);
    expect(deps.find((d) => d.name === "itoa")?.direct).toBe(false);
  });

  it("reads go.mod requires, honours replace directives and // indirect", () => {
    const dir = fx("go");
    expect(pairs(dir)).toEqual(["github.com/gin-gonic/gin@v1.9.1", "github.com/new/lib@v1.1.0", "github.com/single/dep@v0.2.0", "golang.org/x/text@v0.3.0"]);
    const deps = readDependencies(dir, detectLockfiles(dir)[0]!);
    expect(deps.find((d) => d.name === "golang.org/x/text")?.direct).toBe(false);
    expect(deps.find((d) => d.name === "github.com/new/lib")?.direct).toBe(true);
  });

  it("reads Gemfile.lock, strips platform suffixes and finds direct gems", () => {
    const dir = fx("ruby");
    expect(pairs(dir)).toEqual(["actionpack@7.0.8", "nokogiri@1.15.4", "racc@1.7.3", "rack@2.2.8"]);
    const deps = readDependencies(dir, detectLockfiles(dir)[0]!);
    expect(deps.find((d) => d.name === "nokogiri")?.direct).toBe(true);
    expect(deps.find((d) => d.name === "rack")?.direct).toBe(false);
  });

  it("reads composer.lock, drops the v prefix and dev branches", () => {
    const dir = fx("php");
    expect(pairs(dir)).toEqual(["phpunit/phpunit@9.6.13", "psr/log@1.1.4", "symfony/http-kernel@4.4.0"]);
    const deps = readDependencies(dir, detectLockfiles(dir)[0]!);
    expect(deps.find((d) => d.name === "psr/log")?.direct).toBe(false);
    expect(deps.find((d) => d.name === "symfony/http-kernel")?.direct).toBe(true);
  });

  it("finds nothing in a directory without lockfiles", () => {
    expect(detectLockfiles(join(__dirname))).toEqual([]);
  });
});
