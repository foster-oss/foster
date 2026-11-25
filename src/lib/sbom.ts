import { readFileSync } from "node:fs";
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
  const m = purl.match(/^pkg:([a-zA-Z0-9.+-]+)\/([^@?#]+)(?:@([^?#]+))?/);
  if (!m?.[1] || !m[2]) return null;
  const type = m[1].toLowerCase();
  const name = m[2].split("/").map(decodeURIComponent).join("/");
  const version = m[3] ? decodeURIComponent(m[3]) : undefined;
  return { type, name, version };
}

export function readSbom(path: string): SbomRead {
  const doc = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  const purls: string[] = [];
  let format: SbomRead["format"];
  if (doc.bomFormat === "CycloneDX" || Array.isArray(doc.components)) {
    format = "cyclonedx";
    const walk = (components: unknown) => {
      for (const c of (components as { purl?: string; components?: unknown[] }[] | undefined) ?? []) {
        if (c.purl) purls.push(c.purl);
        if (c.components) walk(c.components);
      }
    };
    walk(doc.components);
  } else if (typeof doc.spdxVersion === "string" || Array.isArray(doc.packages)) {
    format = "spdx";
    for (const p of (doc.packages as { externalRefs?: { referenceType?: string; referenceLocator?: string }[] }[] | undefined) ?? []) {
      for (const ref of p.externalRefs ?? []) {
        if (ref.referenceType === "purl" && ref.referenceLocator) purls.push(ref.referenceLocator);
      }
    }
  } else {
    throw new Error(`${path} is not a CycloneDX or SPDX JSON document`);
  }

  const dependencies: Dependency[] = [];
  const skipped: Record<string, number> = {};
  const seen = new Set<string>();
  for (const purl of purls) {
    const p = parsePurl(purl);
    if (!p?.version) continue;
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
  return { format, dependencies, skipped };
}
