import { readFileSync } from "node:fs";
import { type DepGraph, introducedBy, nodeKey } from "./graph.js";
import { normalizePyName } from "./osv.js";
import type { Dependency, Ecosystem } from "./types.js";

/**
 * Read dependencies from a Software Bill of Materials: CycloneDX JSON (components[].purl)
 * or SPDX JSON (packages[].externalRefs[] of type purl). Package URLs (purl) carry the
 * ecosystem, name and version, so any tool that emits an SBOM can feed Foster.
 */

const PURL_TYPE: Record<string, Ecosystem> = {
  npm: "npm",
  pypi: "pypi",
  cargo: "cargo",
  golang: "go",
  gem: "rubygems",
  composer: "packagist",
};

export interface SbomRead {
  format: "cyclonedx" | "spdx";
  dependencies: Dependency[];
  /** purl types Foster does not cover yet (e.g. maven, nuget), with counts. */
  skipped: Record<string, number>;
}

/** Parse a purl such as pkg:npm/%40scope/name@1.2.3 or pkg:golang/github.com/a/b@v1.0.0. */
export function parsePurl(purl: string): { type: string; name: string; version?: string } | null {
  // The name may start with an unencoded npm scope ("pkg:npm/@babel/core@7.22.5").
  const m = purl.match(/^pkg:([a-zA-Z0-9.+-]+)\/(@?[^@?#]+)(?:@([^?#]+))?/);
  if (!m?.[1] || !m[2]) return null;
  try {
    const type = m[1].toLowerCase();
    const name = m[2].split("/").map(decodeURIComponent).join("/");
    const version = m[3] ? decodeURIComponent(m[3]) : undefined;
    return { type, name, version };
  } catch {
    return null; // malformed percent-encoding
  }
}

export function readSbom(path: string): SbomRead {
  const doc = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  const purls: string[] = [];
  // Element id (CycloneDX bom-ref, SPDX SPDXID) → purl, and who depends on whom, when the SBOM records it.
  const purlOf = new Map<string, string>();
  const dependsOn: [string, string][] = [];
  const top = new Set<string>(); // the element(s) the SBOM describes: the project itself
  let format: SbomRead["format"];
  if (doc.bomFormat === "CycloneDX" || Array.isArray(doc.components)) {
    format = "cyclonedx";
    type Component = { purl?: string; "bom-ref"?: string; components?: unknown[] };
    const walk = (components: unknown) => {
      for (const c of (components as Component[] | undefined) ?? []) {
        if (c.purl) purls.push(c.purl);
        if (c.purl && c["bom-ref"]) purlOf.set(c["bom-ref"], c.purl);
        if (c.components) walk(c.components);
      }
    };
    walk(doc.components);
    const root = (doc.metadata as { component?: Component } | undefined)?.component?.["bom-ref"];
    if (root) top.add(root);
    for (const d of (doc.dependencies as { ref?: string; dependsOn?: string[] }[] | undefined) ?? []) {
      for (const to of d.dependsOn ?? []) if (d.ref) dependsOn.push([d.ref, to]);
    }
  } else if (typeof doc.spdxVersion === "string" || Array.isArray(doc.packages)) {
    format = "spdx";
    type Pkg = { SPDXID?: string; externalRefs?: { referenceType?: string; referenceLocator?: string }[] };
    for (const p of (doc.packages as Pkg[] | undefined) ?? []) {
      for (const ref of p.externalRefs ?? []) {
        if (ref.referenceType === "purl" && ref.referenceLocator) {
          purls.push(ref.referenceLocator);
          if (p.SPDXID) purlOf.set(p.SPDXID, ref.referenceLocator);
        }
      }
    }
    for (const id of (doc.documentDescribes as string[] | undefined) ?? []) top.add(id);
    type Rel = { spdxElementId?: string; relationshipType?: string; relatedSpdxElement?: string };
    for (const r of (doc.relationships as Rel[] | undefined) ?? []) {
      if (!r.spdxElementId || !r.relatedSpdxElement) continue;
      if (r.relationshipType === "DESCRIBES") top.add(r.relatedSpdxElement);
      else if (r.relationshipType === "DEPENDS_ON") dependsOn.push([r.spdxElementId, r.relatedSpdxElement]);
      else if (r.relationshipType === "DEPENDENCY_OF") dependsOn.push([r.relatedSpdxElement, r.spdxElementId]);
    }
  } else {
    throw new Error(`${path} is not a CycloneDX or SPDX JSON document`);
  }

  const dependencies: Dependency[] = [];
  const skipped: Record<string, number> = {};
  const seen = new Set<string>();
  for (const purl of purls) {
    const p = parsePurl(purl);
    if (!p) {
      skipped["unreadable purl"] = (skipped["unreadable purl"] ?? 0) + 1;
      continue;
    }
    if (!p.version) continue;
    const ecosystem = PURL_TYPE[p.type];
    if (!ecosystem) {
      skipped[p.type] = (skipped[p.type] ?? 0) + 1;
      continue;
    }
    const name = ecosystem === "pypi" ? normalizePyName(p.name) : p.name;
    const key = `${ecosystem}:${name}@${p.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    dependencies.push({ ecosystem, name, version: p.version, direct: true, source: path.replace(/^.*[\\/]/, "") });
  }
  markDirect(dependencies, purlOf, dependsOn, top);
  return { format, dependencies, skipped };
}

/** With a dependency graph and a known root, mark only the root's own dependencies as direct and name the rest's "via". */
function markDirect(deps: Dependency[], purlOf: Map<string, string>, dependsOn: [string, string][], top: Set<string>): void {
  if (top.size === 0 || dependsOn.length === 0) return; // no graph: everything stays direct, as before
  const keyOfId = (id: string): string | undefined => {
    const p = parsePurl(purlOf.get(id) ?? "");
    const ecosystem = p && PURL_TYPE[p.type];
    if (!p?.version || !ecosystem) return undefined;
    return nodeKey(ecosystem === "pypi" ? normalizePyName(p.name) : p.name, p.version);
  };
  const graph: DepGraph = { edges: new Map(), roots: new Set() };
  for (const [from, to] of dependsOn) {
    const toKey = keyOfId(to);
    if (!toKey) continue;
    if (top.has(from)) graph.roots!.add(toKey);
    else {
      const fromKey = keyOfId(from);
      if (!fromKey) continue;
      let set = graph.edges.get(fromKey);
      if (!set) graph.edges.set(fromKey, (set = new Set()));
      set.add(toKey);
    }
  }
  if (graph.roots!.size === 0) return;
  const via = introducedBy(graph, graph.roots!);
  for (const d of deps) {
    const key = nodeKey(d.name, d.version);
    d.direct = graph.roots!.has(key);
    const by = d.direct ? undefined : via.get(key);
    if (by?.size) d.via = [...by].sort();
  }
}
