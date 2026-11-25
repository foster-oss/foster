import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import YAML from "yaml";
import { normalizePyName } from "./osv.js";
import type { Dependency } from "./types.js";

export type NodeManager = "npm" | "pnpm" | "yarn";

export interface LockfileInfo {
  file: string;
  kind: "package-lock" | "pnpm-lock" | "yarn-lock" | "requirements" | "uv-lock";
  manager?: NodeManager;
}

const CANDIDATES: LockfileInfo[] = [
  { file: "package-lock.json", kind: "package-lock", manager: "npm" },
  { file: "npm-shrinkwrap.json", kind: "package-lock", manager: "npm" },
  { file: "pnpm-lock.yaml", kind: "pnpm-lock", manager: "pnpm" },
  { file: "yarn.lock", kind: "yarn-lock", manager: "yarn" },
  { file: "uv.lock", kind: "uv-lock" },
  { file: "requirements.txt", kind: "requirements" },
];

export function detectLockfiles(dir: string): LockfileInfo[] {
  return CANDIDATES.filter((c) => existsSync(join(dir, c.file)));
}

/** Names listed directly in package.json, used to mark direct dependencies. */
export function directNpmNames(dir: string): Set<string> {
  const path = join(dir, "package.json");
  if (!existsSync(path)) return new Set();
  try {
    const pkg = JSON.parse(readFileSync(path, "utf8")) as Record<string, Record<string, string> | undefined>;
    const names = new Set<string>();
    for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      for (const n of Object.keys(pkg[field] ?? {})) names.add(n);
    }
    return names;
  } catch {
    return new Set();
  }
}

export function readDependencies(dir: string, lock: LockfileInfo): Dependency[] {
  const text = readFileSync(join(dir, lock.file), "utf8");
  const direct = lock.manager ? directNpmNames(dir) : new Set<string>();
  let pairs: [string, string][];
  switch (lock.kind) {
    case "package-lock":
      pairs = parsePackageLock(text);
      break;
    case "pnpm-lock":
      pairs = parsePnpmLock(text);
      break;
    case "yarn-lock":
      pairs = parseYarnLock(text);
      break;
    case "requirements":
      pairs = parseRequirements(text);
      break;
    case "uv-lock":
      pairs = parseUvLock(text);
      break;
  }
  const ecosystem = lock.manager ? "npm" : "pypi";
  return dedupe(
    pairs.map(([name, version]) => ({
      ecosystem,
      name: ecosystem === "pypi" ? normalizePyName(name) : name,
      version,
      direct: ecosystem === "npm" ? direct.has(name) : true,
      source: lock.file,
    })),
  );
}

function dedupe(deps: Dependency[]): Dependency[] {
  const map = new Map<string, Dependency>();
  for (const d of deps) {
    const key = `${d.ecosystem}:${d.name}@${d.version}`;
    const prev = map.get(key);
    if (!prev) map.set(key, d);
    else if (d.direct && !prev.direct) prev.direct = true;
  }
  return [...map.values()];
}

/** package-lock.json / npm-shrinkwrap.json, lockfileVersion 1, 2 and 3. */
export function parsePackageLock(text: string): [string, string][] {
  const lock = JSON.parse(text) as {
    packages?: Record<string, { version?: string; name?: string; link?: boolean }>;
    dependencies?: Record<string, LockV1Dep>;
  };
  const out: [string, string][] = [];
  if (lock.packages) {
    for (const [path, entry] of Object.entries(lock.packages)) {
      if (!path || entry.link || !entry.version) continue;
      const idx = path.lastIndexOf("node_modules/");
      if (idx === -1) continue; // workspace folder, not an installed package
      const name = entry.name ?? path.slice(idx + "node_modules/".length);
      if (entry.version.startsWith("file:") || entry.version.startsWith("link:")) continue;
      out.push([name, entry.version]);
    }
    return out;
  }
  const walk = (deps: Record<string, LockV1Dep> | undefined) => {
    for (const [name, d] of Object.entries(deps ?? {})) {
      if (d.version && !d.version.startsWith("file:")) {
        const alias = d.version.match(/^npm:(.+)@([^@]+)$/);
        if (alias?.[1] && alias[2]) out.push([alias[1], alias[2]]);
        else out.push([name, d.version]);
      }
      walk(d.dependencies);
    }
  };
  walk(lock.dependencies);
  return out;
}

interface LockV1Dep {
  version?: string;
  dependencies?: Record<string, LockV1Dep>;
}

/** Split "name@version" where name may be scoped ("@scope/name@1.0.0"). */
export function splitNameVersion(spec: string): [string, string] | null {
  const at = spec.lastIndexOf("@");
  if (at <= 0) return null;
  return [spec.slice(0, at), spec.slice(at + 1)];
}

/** pnpm-lock.yaml, lockfile versions 5.x, 6.x and 9.x. */
export function parsePnpmLock(text: string): [string, string][] {
  const doc = YAML.parse(text) as { packages?: Record<string, { name?: string; version?: string }> } | null;
  const out: [string, string][] = [];
  for (const [rawKey, entry] of Object.entries(doc?.packages ?? {})) {
    let key = rawKey.replace(/^\//, "");
    key = key.replace(/\(.*$/, ""); // peer suffix "(react@18.2.0)"
    key = key.replace(/_.*$/, ""); // v5 peer suffix
    if (entry?.name && entry.version) {
      out.push([entry.name, entry.version]);
      continue;
    }
    // v5 uses "/name/1.2.3", v6+ uses "/name@1.2.3"
    let pair = splitNameVersion(key);
    if (!pair || pair[1].includes("/")) {
      const slash = key.lastIndexOf("/");
      if (slash > 0) pair = [key.slice(0, slash), key.slice(slash + 1)];
    }
    if (pair && /^\d/.test(pair[1])) out.push(pair);
  }
  return out;
}

/** yarn.lock, both classic (v1) and berry (v2+). */
export function parseYarnLock(text: string): [string, string][] {
  const out: [string, string][] = [];
  let currentName: string | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith("#")) continue;
    if (!line.startsWith(" ") && line.endsWith(":")) {
      currentName = null;
      const first = line.slice(0, -1).split(",")[0]?.trim().replace(/^"|"$/g, "");
      if (!first || first === "__metadata") continue;
      if (first.includes("@workspace:") || first.includes("@patch:") || first.includes("@link:") || first.includes("@file:")) continue;
      const npmProto = first.indexOf("@npm:");
      if (npmProto > 0) {
        // berry: "name@npm:^1.0.0" or alias "alias@npm:real@^1.0.0"
        const target = first.slice(npmProto + "@npm:".length);
        const aliased = splitNameVersion(target);
        currentName = aliased && !/^[\^~<>=*\d]/.test(target) ? aliased[0] : first.slice(0, npmProto);
      } else {
        const pair = splitNameVersion(first);
        currentName = pair ? pair[0] : null;
      }
      continue;
    }
    const m = line.match(/^\s+version:?\s+"?([^"\s]+)"?/);
    if (m?.[1] && currentName) {
      out.push([currentName, m[1]]);
      currentName = null;
    }
  }
  return out;
}

/** requirements.txt: only exact pins (name==version) are resolvable without running pip. */
export function parseRequirements(text: string): [string, string][] {
  const out: [string, string][] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line || line.startsWith("-")) continue;
    const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*===?\s*([^\s;,]+)/);
    if (m?.[1] && m[3]) out.push([m[1], m[3]]);
  }
  return out;
}

/** uv.lock (TOML): read name/version pairs from [[package]] tables. */
export function parseUvLock(text: string): [string, string][] {
  const out: [string, string][] = [];
  for (const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const name = block.match(/^name\s*=\s*"([^"]+)"/m)?.[1];
    const version = block.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
    const isLocal = /^source\s*=\s*\{\s*(editable|virtual|directory)\s*=/m.test(block);
    if (name && version && !isLocal) out.push([name, version]);
  }
  return out;
}
