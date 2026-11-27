import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import YAML from "yaml";
import {
  cargoLockGraph,
  composerLockGraph,
  type DepGraph,
  gemfileLockGraph,
  introducedBy,
  nodeKey,
  packageLockGraph,
  pnpmLockGraph,
  poetryLockGraph,
  uvLockGraph,
  yarnLockGraph,
} from "./graph.js";
import { normalizePyName } from "./osv.js";
import type { Dependency, Ecosystem } from "./types.js";

export type NodeManager = "npm" | "pnpm" | "yarn";

export type LockfileKind =
  | "package-lock"
  | "pnpm-lock"
  | "yarn-lock"
  | "requirements"
  | "uv-lock"
  | "poetry-lock"
  | "pipfile-lock"
  | "cargo-lock"
  | "go-mod"
  | "gemfile-lock"
  | "composer-lock";

export interface LockfileInfo {
  file: string;
  kind: LockfileKind;
  ecosystem: Ecosystem;
  manager?: NodeManager;
}

const CANDIDATES: LockfileInfo[] = [
  { file: "package-lock.json", kind: "package-lock", ecosystem: "npm", manager: "npm" },
  { file: "npm-shrinkwrap.json", kind: "package-lock", ecosystem: "npm", manager: "npm" },
  { file: "pnpm-lock.yaml", kind: "pnpm-lock", ecosystem: "npm", manager: "pnpm" },
  { file: "yarn.lock", kind: "yarn-lock", ecosystem: "npm", manager: "yarn" },
  { file: "uv.lock", kind: "uv-lock", ecosystem: "pypi" },
  { file: "poetry.lock", kind: "poetry-lock", ecosystem: "pypi" },
  { file: "Pipfile.lock", kind: "pipfile-lock", ecosystem: "pypi" },
  { file: "requirements.txt", kind: "requirements", ecosystem: "pypi" },
  { file: "Cargo.lock", kind: "cargo-lock", ecosystem: "cargo" },
  { file: "go.mod", kind: "go-mod", ecosystem: "go" },
  { file: "Gemfile.lock", kind: "gemfile-lock", ecosystem: "rubygems" },
  { file: "composer.lock", kind: "composer-lock", ecosystem: "packagist" },
];

export function detectLockfiles(dir: string): LockfileInfo[] {
  return CANDIDATES.filter((c) => existsSync(join(dir, c.file)));
}

/** Read a text file, dropping a UTF-8 byte order mark (common on Windows) so JSON.parse accepts it. */
export function readText(path: string): string {
  const text = readFileSync(path, "utf8");
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

/** Names and version ranges listed directly in package.json. */
export function npmSpecs(dir: string): Record<string, string> {
  const path = join(dir, "package.json");
  if (!existsSync(path)) return {};
  try {
    const pkg = JSON.parse(readText(path)) as Record<string, Record<string, string> | undefined>;
    const specs: Record<string, string> = {};
    for (const field of ["peerDependencies", "optionalDependencies", "devDependencies", "dependencies"]) {
      Object.assign(specs, pkg[field] ?? {});
    }
    return specs;
  } catch {
    return {};
  }
}

/** Names listed directly in package.json, used to mark direct dependencies. */
export function directNpmNames(dir: string): Set<string> {
  return new Set(Object.keys(npmSpecs(dir)));
}

/** The text inside `key = [ … ]`, honouring quotes (so "uvicorn[standard]" does not end the array). */
function tomlArray(body: string, key: string): string | undefined {
  const start = body.match(new RegExp(`^${key}\\s*=\\s*\\[`, "m"));
  if (start?.index === undefined) return undefined;
  let depth = 0;
  let quote: string | null = null;
  const from = start.index + start[0].length - 1;
  for (let i = from; i < body.length; i++) {
    const ch = body[i]!;
    if (quote) {
      if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") quote = ch;
    else if (ch === "#") i = body.indexOf("\n", i) === -1 ? body.length : body.indexOf("\n", i);
    else if (ch === "[") depth++;
    else if (ch === "]" && --depth === 0) return body.slice(from + 1, i);
  }
  return undefined;
}

const pyName = (spec: string) => spec.trim().match(/^([A-Za-z0-9][A-Za-z0-9._-]*)/)?.[1];

/**
 * Python packages the project declares itself: pyproject.toml (PEP 621 [project] dependencies and
 * optional-dependencies, PEP 735 [dependency-groups], [tool.uv] dev-dependencies, Poetry's
 * dependency tables) and Pipfile ([packages], [dev-packages]).
 */
export function directPythonNames(dir: string): Set<string> {
  const names = new Set<string>();
  const add = (n: string | undefined) => {
    if (n && n.toLowerCase() !== "python") names.add(normalizePyName(n));
  };
  // String items of TOML arrays, skipping inline tables such as { include-group = "docs" }.
  const strings = (text: string) =>
    [...text.replace(/\{[^}]*\}/g, "").matchAll(/"([^"]*)"|'([^']*)'/g)].map((m) => m[1] ?? m[2] ?? "");
  const tables = (text: string) =>
    text.split(/^(?=\[)/m).map((sec) => ({ header: sec.match(/^\[([^\]]+)\]/)?.[1]?.trim() ?? "", body: sec.slice(sec.indexOf("\n") + 1) }));
  const keys = (body: string) => [...body.matchAll(/^\s*"?([A-Za-z0-9][A-Za-z0-9._-]*)"?\s*=/gm)].map((m) => m[1]);

  const pyproject = join(dir, "pyproject.toml");
  if (existsSync(pyproject)) {
    for (const { header, body } of tables(readText(pyproject))) {
      if (header === "project" || header === "tool.uv") {
        const arr = tomlArray(body, header === "project" ? "dependencies" : "dev-dependencies");
        if (arr) for (const s of strings(arr)) add(pyName(s));
      } else if (header === "project.optional-dependencies" || header === "dependency-groups") {
        for (const s of strings(body)) add(pyName(s));
      } else if (/^tool\.poetry\.(dependencies|dev-dependencies|group\.[^.]+\.dependencies)$/.test(header)) {
        for (const k of keys(body)) add(k);
      }
    }
  }
  const pipfile = join(dir, "Pipfile");
  if (existsSync(pipfile)) {
    for (const { header, body } of tables(readText(pipfile))) {
      if (header === "packages" || header === "dev-packages") for (const k of keys(body)) add(k);
    }
  }
  return names;
}

export function readDependencies(dir: string, lock: LockfileInfo, textOverride?: string): Dependency[] {
  const text = textOverride ?? readText(join(dir, lock.file));
  // null = the lockfile format does not tell direct from transitive; report all as direct.
  let direct: Set<string> | null = null;
  // Who depends on whom, when the lockfile records it: names the direct dependency that brings each
  // transitive one in, and (when the lockfile lists the project's own dependencies) marks direct ones
  // exactly, by version.
  let graph: DepGraph | null = null;
  let pairs: [string, string][];
  switch (lock.kind) {
    case "package-lock":
      pairs = parsePackageLock(text);
      direct = directNpmNames(dir);
      graph = packageLockGraph(text);
      break;
    case "pnpm-lock":
      pairs = parsePnpmLock(text);
      direct = directNpmNames(dir);
      graph = pnpmLockGraph(text);
      break;
    case "yarn-lock":
      pairs = parseYarnLock(text);
      direct = directNpmNames(dir);
      graph = yarnLockGraph(text, npmSpecs(dir));
      break;
    case "requirements":
      pairs = parseRequirements(text);
      break;
    case "uv-lock":
      pairs = parseUvLock(text);
      direct = directPythonNames(dir);
      graph = uvLockGraph(text);
      break;
    case "poetry-lock":
      pairs = parsePoetryLock(text);
      direct = directPythonNames(dir);
      graph = poetryLockGraph(text);
      break;
    case "pipfile-lock":
      pairs = parsePipfileLock(text);
      direct = directPythonNames(dir);
      break;
    case "cargo-lock":
      pairs = parseCargoLock(text);
      direct = directCargoNames(dir);
      graph = cargoLockGraph(text);
      break;
    case "go-mod": {
      const mod = parseGoMod(text);
      pairs = mod.pairs;
      direct = mod.direct;
      break;
    }
    case "gemfile-lock": {
      const gems = parseGemfileLock(text);
      pairs = gems.pairs;
      direct = gems.direct;
      graph = gemfileLockGraph(text);
      break;
    }
    case "composer-lock":
      pairs = parseComposerLock(text);
      direct = directComposerNames(dir);
      graph = composerLockGraph(text);
      break;
  }
  const ecosystem = lock.ecosystem;
  const norm = (name: string) => (ecosystem === "pypi" ? normalizePyName(name) : name);
  const declared = direct && direct.size > 0 ? new Set([...direct].map(norm)) : null;
  // Exact roots from the lockfile win over manifest names (they also tell two versions of one name apart).
  const roots = graph?.roots && graph.roots.size > 0 ? graph.roots : null;
  const isDirect = (name: string, version: string) =>
    roots ? roots.has(nodeKey(name, version)) : declared === null ? true : declared.has(norm(name));
  const via = graph ? introducedBy(graph, roots ?? pairs.filter(([n, v]) => isDirect(n, v)).map(([n, v]) => nodeKey(n, v))) : null;
  return dedupe(
    pairs.map(([name, version]): Dependency => {
      const isRoot = isDirect(name, version);
      const by = isRoot ? undefined : via?.get(nodeKey(name, version));
      return {
        ecosystem,
        name: norm(name),
        version,
        direct: isRoot,
        ...(by && by.size > 0 ? { via: [...new Set([...by].map(norm))].sort() } : {}),
        source: lock.file,
      };
    }),
  );
}

/** Poetry's poetry.lock (TOML): [[package]] tables with name and version. */
export function parsePoetryLock(text: string): [string, string][] {
  return tomlPackages(text);
}

/** Pipenv's Pipfile.lock (JSON): "default" and "develop" maps of name → { version: "==1.2.3" }. */
export function parsePipfileLock(text: string): [string, string][] {
  const lock = JSON.parse(text) as Record<string, Record<string, { version?: string }> | undefined>;
  const out: [string, string][] = [];
  for (const section of ["default", "develop"]) {
    for (const [name, spec] of Object.entries(lock[section] ?? {})) {
      const v = spec?.version?.replace(/^===?/, "");
      if (v) out.push([name, v]);
    }
  }
  return out;
}

/** Cargo.lock: registry packages only (workspace members and git/path deps have no registry source). */
export function parseCargoLock(text: string): [string, string][] {
  const out: [string, string][] = [];
  for (const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const name = block.match(/^name\s*=\s*"([^"]+)"/m)?.[1];
    const version = block.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
    const source = block.match(/^source\s*=\s*"([^"]+)"/m)?.[1];
    if (name && version && source?.startsWith("registry+")) out.push([name, version]);
  }
  return out;
}

/** Dependency names declared in Cargo.toml ([dependencies], [dev-dependencies], [build-dependencies], target tables). */
export function directCargoNames(dir: string): Set<string> {
  const path = join(dir, "Cargo.toml");
  const names = new Set<string>();
  if (!existsSync(path)) return names;
  let inDeps = false;
  for (const raw of readFileSync(path, "utf8").split(/\r?\n/)) {
    const line = raw.trim();
    const header = line.match(/^\[(.+)\]$/);
    if (header?.[1]) {
      const h = header[1];
      const sub = h.match(/(?:^|\.)(?:dependencies|dev-dependencies|build-dependencies)\.([A-Za-z0-9_-]+)$/);
      if (sub?.[1]) {
        names.add(sub[1]);
        inDeps = false;
      } else {
        inDeps = /(?:^|\.)(?:dependencies|dev-dependencies|build-dependencies)$/.test(h);
      }
      continue;
    }
    if (!inDeps) continue;
    const m = line.match(/^([A-Za-z0-9_-]+)\s*=/);
    if (!m?.[1]) continue;
    const pkg = line.match(/package\s*=\s*"([^"]+)"/)?.[1];
    names.add(pkg ?? m[1]);
  }
  return names;
}

/**
 * go.mod: the require directives list the full module graph needed for the build since Go 1.17;
 * `// indirect` marks transitive ones. `replace` directives are honoured for module path and version.
 */
export function parseGoMod(text: string): { pairs: [string, string][]; direct: Set<string> } {
  const pairs: [string, string][] = [];
  const direct = new Set<string>();
  // replace directives: "from [fromVersion] => to [toVersion]"; a version on the left limits the replace to it.
  const replaces: { from: string; fromVersion?: string; to: [string, string] | null }[] = [];
  let block: "require" | "replace" | "other" | null = null;
  for (const raw of text.split(/\r?\n/)) {
    const indirect = /\/\/\s*indirect\b/.test(raw);
    const line = raw.replace(/\/\/.*$/, "").trim();
    if (!line) continue;
    const opener = line.match(/^(\w+)\s*\($/);
    if (opener?.[1]) {
      block = opener[1] === "require" ? "require" : opener[1] === "replace" ? "replace" : "other";
      continue;
    }
    if (line === ")") {
      block = null;
      continue;
    }
    let kind: "require" | "replace" | null = null;
    let body = line;
    const single = line.match(/^(require|replace)\s+(.+)$/);
    if (single?.[1] && single[2]) {
      kind = single[1] as "require" | "replace";
      body = single[2];
    } else if (block === "require" || block === "replace") {
      kind = block;
    }
    if (!kind) continue; // module, go, toolchain, exclude, retract…
    if (kind === "require") {
      const [mod, ver] = body.split(/\s+/);
      if (mod && ver) {
        pairs.push([mod, ver]);
        if (!indirect) direct.add(mod);
      }
    } else {
      const [left, right] = body.split("=>").map((x) => x.trim());
      const [from, fromVersion] = (left ?? "").split(/\s+/);
      const [to, toVer] = (right ?? "").split(/\s+/);
      if (!from) continue;
      // Local path replacements (./x, ../x, /abs) are not registry packages.
      replaces.push({ from, fromVersion: fromVersion || undefined, to: to && toVer && !/^[./]/.test(to) ? [to, toVer] : null });
    }
  }
  const out: [string, string][] = [];
  for (const [mod, ver] of pairs) {
    // A version-specific replace wins over a module-wide one, as in the go command.
    const r = replaces.find((x) => x.from === mod && x.fromVersion === ver) ?? replaces.find((x) => x.from === mod && !x.fromVersion);
    if (!r) {
      out.push([mod, ver]);
      continue;
    }
    if (r.to) {
      out.push(r.to);
      if (direct.has(mod)) direct.add(r.to[0]);
    }
  }
  return { pairs: out, direct };
}

/** Gemfile.lock: gems under the GEM specs section; DEPENDENCIES lists the direct ones. */
export function parseGemfileLock(text: string): { pairs: [string, string][]; direct: Set<string> } {
  const pairs: [string, string][] = [];
  const direct = new Set<string>();
  let section = "";
  let inSpecs = false;
  for (const raw of text.split(/\r?\n/)) {
    if (/^[A-Z][A-Z ]*$/.test(raw)) {
      section = raw.trim();
      inSpecs = false;
      continue;
    }
    if (section === "GEM" && raw.trim() === "specs:") {
      inSpecs = true;
      continue;
    }
    if (section === "GEM" && inSpecs) {
      const m = raw.match(/^ {4}([^\s(]+) \(([^)]+)\)$/);
      if (m?.[1] && m[2]) {
        // strip platform suffixes like "1.15.4-x86_64-linux" or "-java"
        const version = m[2].replace(/-(x86|x64|i386|i686|arm|aarch|universal|java|mingw|mswin|darwin|linux|ruby|wasm)[\w.-]*$/i, "");
        pairs.push([m[1], version]);
      }
    }
    if (section === "DEPENDENCIES") {
      const m = raw.match(/^ {2}([^\s!(]+)/);
      if (m?.[1]) direct.add(m[1]);
    }
  }
  return { pairs, direct };
}

/** composer.lock: "packages" and "packages-dev"; versions may carry a leading "v". */
export function parseComposerLock(text: string): [string, string][] {
  const lock = JSON.parse(text) as Record<string, { name?: string; version?: string }[] | undefined>;
  const out: [string, string][] = [];
  for (const section of ["packages", "packages-dev"]) {
    for (const p of lock[section] ?? []) {
      if (!p.name || !p.version || p.version.startsWith("dev-") || p.version.endsWith("-dev")) continue; // branches, not releases
      out.push([p.name, p.version.replace(/^v(?=\d)/, "")]);
    }
  }
  return out;
}

export function directComposerNames(dir: string): Set<string> {
  const path = join(dir, "composer.json");
  if (!existsSync(path)) return new Set();
  try {
    const pkg = JSON.parse(readText(path)) as Record<string, Record<string, string> | undefined>;
    return new Set([...Object.keys(pkg.require ?? {}), ...Object.keys(pkg["require-dev"] ?? {})]);
  } catch {
    return new Set();
  }
}

/** Shared reader for TOML lockfiles made of [[package]] tables (poetry.lock). */
function tomlPackages(text: string): [string, string][] {
  const out: [string, string][] = [];
  for (const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const name = block.match(/^name\s*=\s*"([^"]+)"/m)?.[1];
    const version = block.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
    if (name && version) out.push([name, version]);
  }
  return out;
}

/** Combine two sightings of the same package version: direct anywhere wins, "via" lists are joined. */
export function mergeInto(prev: Dependency, d: Dependency): void {
  if (d.direct) prev.direct = true;
  if (prev.direct) delete prev.via;
  else if (d.via) prev.via = [...new Set([...(prev.via ?? []), ...d.via])].sort();
}

function dedupe(deps: Dependency[]): Dependency[] {
  const map = new Map<string, Dependency>();
  for (const d of deps) {
    const key = `${d.ecosystem}:${d.name}@${d.version}`;
    const prev = map.get(key);
    if (!prev) map.set(key, d);
    else mergeInto(prev, d);
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
    key = key.replace(/(\/\d[^/_]*)_.*$/, "$1"); // v5 peer suffix after the version ("/foo/1.0.0_react@18"), never in a name
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
