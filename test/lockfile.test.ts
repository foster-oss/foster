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

  it("finds nothing in a directory without lockfiles", () => {
    expect(detectLockfiles(join(__dirname))).toEqual([]);
  });
});
