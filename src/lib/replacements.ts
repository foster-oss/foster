import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import type { Ecosystem } from "./types.js";

/**
 * Suggested replacements for orphaned packages: Foster's own reviewed list
 * (registry/alternatives.json, all ecosystems) first, then, for npm, the e18e community's
 * module-replacements dataset (MIT, https://github.com/e18e/module-replacements).
 */

interface Manifest {
  mappings: Record<string, { moduleName?: string; replacements?: string[]; url?: { type?: string; id?: string } }>;
  replacements: Record<string, { id: string; type?: string; description?: string; url?: { type?: string; id?: string } }>;
}

export interface Alternative {
  /** e.g. "fetch", "Object.assign", "day.js" */
  name: string;
  kind: "native" | "package" | "snippet" | "remove";
  description?: string;
}

export interface AlternativeSet {
  options: Alternative[];
  /** Guide explaining the migration, when the dataset links one. */
  docs?: string;
  source: "e18e module-replacements" | "Foster registry";
}

interface CuratedFile {
  alternatives: { ecosystem: Ecosystem; name: string; options: Alternative[]; docs?: string }[];
}

let curated: Map<string, AlternativeSet> | null = null;

/** registry/alternatives.json: reviewed successors for packages outside npm (and npm overrides). */
function loadCurated(): Map<string, AlternativeSet> {
  if (curated) return curated;
  curated = new Map();
  try {
    const file = JSON.parse(readFileSync(new URL("../../registry/alternatives.json", import.meta.url), "utf8")) as CuratedFile;
    for (const a of file.alternatives) curated.set(`${a.ecosystem}:${a.name}`, { options: a.options, docs: a.docs, source: "Foster registry" });
  } catch {
    // optional data
  }
  return curated;
}

let cache: Map<string, AlternativeSet> | null = null;

function load(): Map<string, AlternativeSet> {
  if (cache) return cache;
  cache = new Map();
  const require = createRequire(import.meta.url);
  for (const file of ["preferred", "native", "micro-utilities"]) {
    let manifest: Manifest;
    try {
      manifest = JSON.parse(readFileSync(require.resolve(`module-replacements/manifests/${file}.json`), "utf8")) as Manifest;
    } catch {
      continue; // dataset missing: suggestions are optional
    }
    for (const [name, mapping] of Object.entries(manifest.mappings)) {
      if (cache.has(name)) continue;
      const ids = (mapping.replacements ?? []).filter((id) => id !== name); // "safe-buffer → safe-buffer" carries no advice
      if (ids.length === 0) continue;
      const options = ids.map((id): Alternative => {
        const r = manifest.replacements[id];
        if (id.startsWith("snippet::")) return { name: id.slice("snippet::".length), kind: "snippet", description: r?.description };
        if (r?.type === "removal") return { name: id, kind: "remove", description: r.description };
        if (r?.type === "native") return { name: id, kind: "native", description: r.description };
        return { name: id, kind: "package", description: r?.description };
      });
      const docs = mapping.url?.type === "e18e" && mapping.url.id ? `https://e18e.dev/docs/replacements/${mapping.url.id}.html` : undefined;
      cache.set(name, { options, docs, source: "e18e module-replacements" });
    }
  }
  return cache;
}

export function alternativesFor(ecosystem: Ecosystem, name: string): AlternativeSet | undefined {
  const own = loadCurated().get(`${ecosystem}:${ecosystem === "pypi" ? name.toLowerCase() : name}`);
  if (own) return own;
  if (ecosystem !== "npm") return undefined;
  return load().get(name);
}

/** One-line human summary, e.g. "fetch (built in), ofetch, ky — https://e18e.dev/docs/replacements/fetch.html" */
export function describeAlternatives(set: AlternativeSet): string {
  const names = set.options.slice(0, 4).map((o) =>
    o.kind === "native" ? `${o.name} (built in)` : o.kind === "snippet" ? `a one-line snippet (${o.name})` : o.kind === "remove" ? "removing it" : o.name,
  );
  return `${names.join(", ")}${set.options.length > 4 ? ", …" : ""}${set.docs ? ` (${set.docs})` : ""}`;
}
