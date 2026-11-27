import YAML from "yaml";
import { splitNameVersion } from "./lockfile.js";

/**
 * Dependency graphs read from lockfiles, used to say which direct dependency brings in each
 * transitive one ("devalue, via astro"): that is the package the user can actually upgrade or replace.
 *
 * Nodes are "name@version" keys, matching the pairs the lockfile parsers return.
 */
export interface DepGraph {
  /** node → the nodes it depends on */
  edges: Map<string, Set<string>>;
  /**
   * The nodes the project itself depends on, when the lockfile records them (npm v2+, pnpm, yarn with
   * package.json, uv, Cargo). Absent when only the manifest's names are known.
   */
  roots?: Set<string>;
}

export const nodeKey = (name: string, version: string) => `${name}@${version}`;

export function nodeName(key: string): string {
  const at = key.lastIndexOf("@");
  return at > 0 ? key.slice(0, at) : key;
}

function addEdge(g: DepGraph, from: string, to: string | undefined) {
  if (!to || from === to) return;
  let set = g.edges.get(from);
  if (!set) g.edges.set(from, (set = new Set()));
  set.add(to);
}

/** At most this many parents are kept per package; reports show three and "many more" past this. */
export const MAX_VIA = 10;

/**
 * For every node reachable from a root, the names of the roots that reach it (up to MAX_VIA).
 * Roots themselves are left out (they are direct).
 *
 * A node that already has MAX_VIA roots is not walked again: every root that reached it also reached
 * everything below it, so its descendants are full too. This keeps large monorepo graphs fast.
 */
export function introducedBy(g: DepGraph, roots: Iterable<string>): Map<string, Set<string>> {
  const via = new Map<string, Set<string>>();
  for (const root of roots) {
    const rootName = nodeName(root);
    const seen = new Set<string>([root]);
    const queue = [root];
    while (queue.length) {
      const n = queue.pop()!;
      for (const child of g.edges.get(n) ?? []) {
        if (seen.has(child)) continue;
        seen.add(child);
        let s = via.get(child);
        if (!s) via.set(child, (s = new Set()));
        if (s.size >= MAX_VIA && !s.has(rootName)) continue; // full: so is everything below it
        s.add(rootName);
        queue.push(child);
      }
    }
  }
  return via;
}

// ---------------------------------------------------------------------------------------------
// npm: package-lock.json v2/v3 (the "packages" map). v1 has no reliable graph and returns null.

type LockEntry = {
  name?: string;
  version?: string;
  link?: boolean;
  resolved?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
};

export function packageLockGraph(text: string): DepGraph | null {
  const lock = JSON.parse(text) as { packages?: Record<string, LockEntry> };
  const pk = lock.packages;
  if (!pk) return null;
  const g: DepGraph = { edges: new Map(), roots: new Set() };

  const keyAt = (path: string): string | undefined => {
    const e = pk[path];
    if (!e || e.link || !e.version || /^(file|link):/.test(e.version)) return undefined;
    const idx = path.lastIndexOf("node_modules/");
    if (idx === -1) return undefined;
    return nodeKey(e.name ?? path.slice(idx + "node_modules/".length), e.version);
  };
  // Node's resolution: the nearest node_modules/<name> walking up from the requiring package.
  const resolveFrom = (from: string, name: string): string | undefined => {
    let base = from;
    for (;;) {
      const candidate = base ? `${base}/node_modules/${name}` : `node_modules/${name}`;
      const entry = pk[candidate];
      if (entry) return entry.link ? undefined : candidate; // a linked workspace is the project's own code
      if (!base) return undefined;
      const i = base.lastIndexOf("/node_modules/");
      base = i >= 0 ? base.slice(0, i) : "";
    }
  };
  const depNames = (e: LockEntry, withDev: boolean) => [
    ...Object.keys(e.dependencies ?? {}),
    ...Object.keys(e.optionalDependencies ?? {}),
    ...Object.keys(e.peerDependencies ?? {}),
    ...(withDev ? Object.keys(e.devDependencies ?? {}) : []),
  ];

  for (const [path, entry] of Object.entries(pk)) {
    const isProject = path === "" || !path.includes("node_modules/"); // the root or a workspace folder
    if (isProject) {
      for (const name of depNames(entry, true)) {
        const child = resolveFrom(path, name);
        const key = child && keyAt(child);
        if (key) g.roots!.add(key);
      }
      continue;
    }
    const from = keyAt(path);
    if (!from) continue;
    for (const name of depNames(entry, false)) {
      const child = resolveFrom(path, name);
      addEdge(g, from, child && keyAt(child));
    }
  }
  return g;
}

// ---------------------------------------------------------------------------------------------
// pnpm-lock.yaml v5, v6 and v9.

/** "1.2.3(react@18.2.0)", "/foo@1.2.3", "npm:foo@1.2.3", "/foo/1.2.3_react@18" → node key for dependency `name`. */
function pnpmRefKey(name: string, ref: string): string | undefined {
  if (/^(link|file|workspace):/.test(ref)) return undefined;
  let r = ref.replace(/\(.*$/, "").replace(/^npm:/, "").replace(/^\//, "");
  r = r.replace(/(\/\d[^/_]*)_.*$/, "$1").replace(/^(\d[^_]*)_.*$/, "$1");
  if (/^\d/.test(r)) return nodeKey(name, r);
  // an alias or a v6 path: "other@1.2.3" or "other/1.2.3"
  const pair = splitNameVersion(r);
  if (pair && /^\d/.test(pair[1])) return nodeKey(pair[0], pair[1]);
  const slash = r.lastIndexOf("/");
  if (slash > 0 && /^\d/.test(r.slice(slash + 1))) return nodeKey(r.slice(0, slash), r.slice(slash + 1));
  return undefined;
}

function pnpmEntryKey(rawKey: string, entry: { name?: string; version?: string } | null): string | undefined {
  if (entry?.name && entry.version) return nodeKey(entry.name, entry.version);
  const key = rawKey.replace(/^\//, "");
  const pair = splitNameVersion(key.replace(/\(.*$/, ""));
  if (pair && /^\d/.test(pair[1]) && !pair[1].includes("/")) return pnpmRefKey(pair[0], pair[1]);
  const slash = key.replace(/(\/\d[^/_]*)_.*$/, "$1").lastIndexOf("/");
  if (slash > 0) return pnpmRefKey(key.slice(0, slash), key.slice(slash + 1));
  return undefined;
}

type PnpmDeps = Record<string, string | { version?: string }> | undefined;

export function pnpmLockGraph(text: string): DepGraph | null {
  type Entry = { name?: string; version?: string; dependencies?: PnpmDeps; optionalDependencies?: PnpmDeps };
  type Importer = { dependencies?: PnpmDeps; devDependencies?: PnpmDeps; optionalDependencies?: PnpmDeps };
  const doc = YAML.parse(text) as
    | ({ importers?: Record<string, Importer>; snapshots?: Record<string, Entry>; packages?: Record<string, Entry> } & Importer)
    | null;
  if (!doc) return null;
  const g: DepGraph = { edges: new Map(), roots: new Set() };
  const refOf = (v: string | { version?: string }) => (typeof v === "string" ? v : (v?.version ?? ""));
  const entries = doc.snapshots ?? doc.packages ?? {};
  for (const [rawKey, entry] of Object.entries(entries)) {
    const from = pnpmEntryKey(rawKey, doc.packages?.[rawKey] ?? entry);
    if (!from) continue;
    for (const deps of [entry?.dependencies, entry?.optionalDependencies]) {
      for (const [name, v] of Object.entries(deps ?? {})) addEdge(g, from, pnpmRefKey(name, refOf(v)));
    }
  }
  const importers: Importer[] = doc.importers ? Object.values(doc.importers) : [doc];
  for (const imp of importers) {
    for (const deps of [imp?.dependencies, imp?.devDependencies, imp?.optionalDependencies]) {
      for (const [name, v] of Object.entries(deps ?? {})) {
        const key = pnpmRefKey(name, refOf(v));
        if (key) g.roots!.add(key);
      }
    }
  }
  return g;
}

// ---------------------------------------------------------------------------------------------
// yarn.lock, classic (v1) and berry (v2+). Entries are keyed by the descriptors that resolve to them
// ("lodash@^4.17.0", berry "lodash@npm:^4.17.0"), and list their own dependencies by descriptor.

const unquote = (s: string) => s.trim().replace(/^"|"$/g, "");

export function yarnLockGraph(text: string, rootSpecs: Record<string, string> = {}): DepGraph {
  const g: DepGraph = { edges: new Map(), roots: new Set() };
  const byDescriptor = new Map<string, string>();
  type Block = { descriptors: string[]; version?: string; deps: [string, string][]; workspace: boolean };
  const blocks: Block[] = [];
  let cur: Block | null = null;
  let inDeps = false;
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith("#")) continue;
    if (!line.startsWith(" ") && line.endsWith(":")) {
      const descriptors = line.slice(0, -1).split(",").map(unquote).filter(Boolean);
      cur = { descriptors, deps: [], workspace: descriptors.some((d) => d.includes("@workspace:")) };
      blocks.push(cur);
      inDeps = false;
      continue;
    }
    if (!cur) continue;
    const indent = line.length - line.trimStart().length;
    if (indent <= 2) {
      inDeps = /^\s+(dependencies|optionalDependencies):?\s*$/.test(line);
      const v = line.match(/^\s+version:?\s+"?([^"\s]+)"?/);
      if (v?.[1]) cur.version = v[1];
      continue;
    }
    if (inDeps) {
      // classic: `    name "^1.0.0"`; berry: `    name: "npm:^1.0.0"` (names may be quoted)
      const m = line.trim().match(/^("[^"]+"|[^\s:]+):?\s+(.+)$/);
      if (m?.[1] && m[2]) cur.deps.push([unquote(m[1]), unquote(m[2])]);
    }
  }
  const nameOfDescriptor = (d: string) => {
    const npm = d.indexOf("@npm:");
    if (npm > 0) {
      const target = d.slice(npm + 5);
      const aliased = splitNameVersion(target);
      return aliased && !/^[\^~<>=*\d]/.test(target) ? aliased[0] : d.slice(0, npm);
    }
    return splitNameVersion(d)?.[0];
  };
  for (const b of blocks) {
    if (b.workspace || !b.version) continue;
    const name = b.descriptors.map(nameOfDescriptor).find(Boolean);
    if (!name) continue;
    const key = nodeKey(name, b.version);
    for (const d of b.descriptors) byDescriptor.set(d, key);
  }
  const resolve = (name: string, range: string) =>
    byDescriptor.get(`${name}@${range}`) ?? byDescriptor.get(`${name}@npm:${range}`) ?? byDescriptor.get(`${name}@${range.replace(/^npm:/, "")}`);
  for (const b of blocks) {
    if (!b.version && !b.workspace) continue;
    const name = b.workspace ? undefined : b.descriptors.map(nameOfDescriptor).find(Boolean);
    const from = name && b.version ? nodeKey(name, b.version) : undefined;
    for (const [depName, range] of b.deps) {
      const to = resolve(depName, range);
      if (b.workspace) {
        if (to) g.roots!.add(to);
      } else if (from) addEdge(g, from, to);
    }
  }
  for (const [name, range] of Object.entries(rootSpecs)) {
    const to = resolve(name, range);
    if (to) g.roots!.add(to);
  }
  return g;
}

// ---------------------------------------------------------------------------------------------
// TOML lockfiles made of [[package]] tables: Cargo.lock, uv.lock, poetry.lock.

function tomlBlocks(text: string): string[] {
  return text.split(/^\[\[package\]\]\s*$/m).slice(1);
}

function field(block: string, name: string): string | undefined {
  return block.match(new RegExp(`^${name}\\s*=\\s*"([^"]+)"`, "m"))?.[1];
}

/** Cargo.lock: `dependencies = ["name", "name 1.2.3", "name 1.2.3 (registry+…)"]`. Workspace members are the roots. */
export function cargoLockGraph(text: string): DepGraph {
  const g: DepGraph = { edges: new Map(), roots: new Set() };
  const parsed = tomlBlocks(text).map((b) => ({
    name: field(b, "name"),
    version: field(b, "version"),
    registry: field(b, "source")?.startsWith("registry+") ?? false,
    deps: [...(b.match(/^dependencies\s*=\s*\[([\s\S]*?)\]/m)?.[1] ?? "").matchAll(/"([^"]+)"/g)].map((m) => m[1]!.split(" ")),
  }));
  const versionsByName = new Map<string, string[]>();
  for (const p of parsed) if (p.name && p.version) versionsByName.set(p.name, [...(versionsByName.get(p.name) ?? []), p.version]);
  const resolve = ([name, version]: string[]) => {
    if (!name) return undefined;
    const v = version ?? (versionsByName.get(name)?.length === 1 ? versionsByName.get(name)![0] : undefined);
    return v ? nodeKey(name, v) : undefined;
  };
  for (const p of parsed) {
    if (!p.name || !p.version) continue;
    const from = nodeKey(p.name, p.version);
    for (const d of p.deps) {
      const to = resolve(d);
      if (!p.registry) {
        if (to) g.roots!.add(to); // a workspace or path crate: the project's own code
      } else addEdge(g, from, to);
    }
  }
  return g;
}

/** uv.lock: each package lists `{ name = "…" }` dependencies; the editable/virtual project package is the root. */
export function uvLockGraph(text: string): DepGraph {
  const g: DepGraph = { edges: new Map(), roots: new Set() };
  const parsed = tomlBlocks(text).map((b) => {
    // only the dependency tables, not [package.metadata] (requires-dist repeats the specifiers)
    const depText = b.split(/^\[package\.metadata[\].]/m)[0] ?? "";
    return {
      name: field(b, "name"),
      version: field(b, "version"),
      local: /^source\s*=\s*\{\s*(editable|virtual|directory)\s*=/m.test(b),
      deps: [...depText.matchAll(/\{\s*name\s*=\s*"([^"]+)"(?:\s*,\s*version\s*=\s*"([^"]+)")?/g)].map((m) => [m[1]!, m[2]] as const),
    };
  });
  const versionOf = new Map<string, string>();
  for (const p of parsed) if (p.name && p.version) versionOf.set(p.name, p.version);
  for (const p of parsed) {
    if (!p.name || !p.version) continue;
    const from = nodeKey(p.name, p.version);
    for (const [name, version] of p.deps) {
      const v = version ?? versionOf.get(name);
      const to = v ? nodeKey(name, v) : undefined;
      if (p.local) {
        if (to) g.roots!.add(to);
      } else addEdge(g, from, to);
    }
  }
  return g;
}

/** poetry.lock: `[package.dependencies]` tables, by name. Roots come from pyproject.toml. */
export function poetryLockGraph(text: string): DepGraph {
  const g: DepGraph = { edges: new Map() };
  const parsed = tomlBlocks(text).map((b) => {
    const section = b.match(/^\[package\.dependencies\]\s*$([\s\S]*?)(?=^\[|(?![\s\S]))/m)?.[1] ?? "";
    return {
      name: field(b, "name"),
      version: field(b, "version"),
      deps: [...section.matchAll(/^"?([A-Za-z0-9][A-Za-z0-9._-]*)"?\s*=/gm)].map((m) => m[1]!),
    };
  });
  const versionOf = new Map<string, string>();
  for (const p of parsed) if (p.name && p.version) versionOf.set(p.name.toLowerCase(), p.version);
  for (const p of parsed) {
    if (!p.name || !p.version) continue;
    for (const d of p.deps) {
      const v = versionOf.get(d.toLowerCase());
      if (v) addEdge(g, nodeKey(p.name, p.version), nodeKey(parsed.find((x) => x.name?.toLowerCase() === d.toLowerCase())?.name ?? d, v));
    }
  }
  return g;
}

// ---------------------------------------------------------------------------------------------
// Gemfile.lock and composer.lock: dependencies by name.

export function gemfileLockGraph(text: string): DepGraph {
  const g: DepGraph = { edges: new Map() };
  const versionOf = new Map<string, string>();
  const pending: [string, string][] = [];
  let section = "";
  let current: string | undefined;
  for (const raw of text.split(/\r?\n/)) {
    if (/^[A-Z][A-Z ]*$/.test(raw)) {
      section = raw.trim();
      current = undefined;
      continue;
    }
    if (section !== "GEM") continue;
    const spec = raw.match(/^ {4}([^\s(]+) \(([^)]+)\)$/);
    if (spec?.[1] && spec[2]) {
      const version = spec[2].replace(/-(x86|x64|i386|i686|arm|aarch|universal|java|mingw|mswin|darwin|linux|ruby|wasm)[\w.-]*$/i, "");
      current = nodeKey(spec[1], version);
      versionOf.set(spec[1], version);
      continue;
    }
    const dep = raw.match(/^ {6}([^\s(]+)/);
    if (dep?.[1] && current) pending.push([current, dep[1]]);
  }
  for (const [from, name] of pending) {
    const v = versionOf.get(name);
    if (v) addEdge(g, from, nodeKey(name, v));
  }
  return g;
}

export function composerLockGraph(text: string): DepGraph {
  const g: DepGraph = { edges: new Map() };
  const lock = JSON.parse(text) as Record<string, { name?: string; version?: string; require?: Record<string, string> }[] | undefined>;
  const all = [...(lock.packages ?? []), ...(lock["packages-dev"] ?? [])];
  const versionOf = new Map<string, string>();
  for (const p of all) if (p.name && p.version) versionOf.set(p.name.toLowerCase(), p.version.replace(/^v(?=\d)/, ""));
  for (const p of all) {
    if (!p.name || !p.version) continue;
    const from = nodeKey(p.name, p.version.replace(/^v(?=\d)/, ""));
    for (const name of Object.keys(p.require ?? {})) {
      const v = versionOf.get(name.toLowerCase());
      if (v) addEdge(g, from, nodeKey(all.find((x) => x.name?.toLowerCase() === name.toLowerCase())!.name!, v));
    }
  }
  return g;
}
