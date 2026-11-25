import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import type { Ecosystem } from "./types.js";

/**
 * Suggested replacements for npm packages, from the e18e community's module-replacements
 * dataset (MIT, https://github.com/e18e/module-replacements). Foster uses it to tell people
 * what to move to when a dependency is orphaned.
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
  source: "e18e module-replacements";
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
