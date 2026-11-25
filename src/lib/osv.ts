import { normalizeSeverity } from "./classify.js";
import { fetchJson, mapLimit } from "./http.js";
import type { AdvisorySummary, Dependency, Ecosystem, Severity } from "./types.js";

const OSV = "https://api.osv.dev/v1";
const OSV_ECOSYSTEM: Record<Ecosystem, string> = {
  npm: "npm",
  pypi: "PyPI",
  cargo: "crates.io",
  go: "Go",
  rubygems: "RubyGems",
  packagist: "Packagist",
};

interface OsvBatchResponse {
  results: { vulns?: { id: string }[]; next_page_token?: string }[];
}

interface OsvRangeEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}

export interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  withdrawn?: string;
  database_specific?: { severity?: string };
  affected?: {
    package?: { ecosystem?: string; name?: string };
    ranges?: { type?: string; events?: OsvRangeEvent[] }[];
    versions?: string[];
    database_specific?: { severity?: string };
  }[];
}

export interface VulnForDependency {
  advisory: AdvisorySummary;
  /** Versions that fix this vulnerability for this package, from OSV "fixed" events. Empty when no fix exists. */
  fixedVersions: string[];
  /** Highest version known to be affected ("last_affected" events). A newer release is then not affected. */
  lastAffected: string[];
  isMalware: boolean;
}

/** Query OSV for every dependency in batches of up to 1000. Returns vuln ids per dependency index. */
export async function queryBatch(deps: readonly Dependency[]): Promise<string[][]> {
  const out: string[][] = deps.map(() => []);
  for (let start = 0; start < deps.length; start += 1000) {
    const chunk = deps.slice(start, start + 1000);
    const body = {
      queries: chunk.map((d) => ({ package: { name: d.name, ecosystem: OSV_ECOSYSTEM[d.ecosystem] }, version: d.version })),
    };
    const res = await fetchJson<OsvBatchResponse>(`${OSV}/querybatch`, { method: "POST", body, timeoutMs: 60_000 });
    res.results.forEach((r, i) => {
      out[start + i] = (r.vulns ?? []).map((v) => v.id);
    });
  }
  return out;
}

const vulnCache = new Map<string, Promise<OsvVuln>>();

export function getVuln(id: string): Promise<OsvVuln> {
  let p = vulnCache.get(id);
  if (!p) {
    p = fetchJson<OsvVuln>(`${OSV}/vulns/${encodeURIComponent(id)}`);
    vulnCache.set(id, p);
  }
  return p;
}

/** Fetch full records for a set of ids (deduplicated, limited concurrency). */
export async function getVulns(ids: Iterable<string>): Promise<Map<string, OsvVuln>> {
  const unique = [...new Set(ids)];
  const vulns = await mapLimit(unique, 8, (id) => getVuln(id));
  return new Map(unique.map((id, i) => [id, vulns[i] as OsvVuln]));
}

function displayId(v: OsvVuln): string {
  if (v.id.startsWith("GHSA-")) return v.id;
  return v.aliases?.find((a) => a.startsWith("GHSA-")) ?? v.id;
}

/** Summarise one OSV vulnerability from the point of view of a single dependency. */
export function describeForDependency(v: OsvVuln, dep: Dependency): VulnForDependency {
  const fixed: string[] = [];
  const lastAffected: string[] = [];
  let severity: Severity = normalizeSeverity(v.database_specific?.severity);
  for (const aff of v.affected ?? []) {
    if (!sameName(aff.package?.name, dep)) continue;
    if (severity === "UNKNOWN") severity = normalizeSeverity(aff.database_specific?.severity);
    for (const range of aff.ranges ?? []) {
      for (const ev of range.events ?? []) {
        if (ev.fixed) fixed.push(ev.fixed);
        if (ev.last_affected) lastAffected.push(ev.last_affected);
      }
    }
  }
  const id = displayId(v);
  const isMalware = v.id.startsWith("MAL-") || MALWARE_TITLE.test(v.summary ?? "");
  return {
    advisory: {
      id,
      url: id.startsWith("GHSA-") ? `https://github.com/advisories/${id}` : `https://osv.dev/vulnerability/${v.id}`,
      severity,
      title: v.summary ?? v.details?.split("\n")[0]?.slice(0, 160) ?? id,
    },
    fixedVersions: [...new Set(fixed)],
    lastAffected: [...new Set(lastAffected)],
    isMalware,
  };
}

/** Advisories about hijacked or sabotaged releases: the answer is "avoid that version", not a patch. */
export const MALWARE_TITLE = /malicious|malware|compromised|hijack|embedded .*(code|payload)|protestware|sabotage/i;

export { compareVersions } from "./versions.js";
import { compareVersions } from "./versions.js";

/**
 * Is there a release newer than every "last_affected" bound? Then upgrading fixes the advisory,
 * even though OSV records no explicit "fixed" event.
 */
export function newerReleaseEscapes(v: VulnForDependency, latest: string | null | undefined): boolean {
  if (!latest || v.lastAffected.length === 0 || v.fixedVersions.length > 0) return false;
  return v.lastAffected.every((la) => compareVersions(latest, la) > 0);
}

function sameName(name: string | undefined, dep: Dependency): boolean {
  if (!name) return false;
  if (dep.ecosystem === "pypi") return normalizePyName(name) === normalizePyName(dep.name);
  return name === dep.name;
}

export function normalizePyName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}

/**
 * The lowest fixed version above the installed one. OSV lists one "fixed" event per release line
 * (e.g. 8.5.52 and 9.6.33), so the nearest fix above the installed version is the relevant one.
 */
export function lowestFixAbove(dep: Dependency, fixedVersions: string[]): string | undefined {
  if (fixedVersions.length === 0) return undefined;
  const installed = dep.version.replace(/^v(?=\d)/, "");
  const above = fixedVersions
    .filter((f) => compareVersions(f.replace(/^v(?=\d)/, ""), installed) > 0)
    .sort((a, b) => compareVersions(a.replace(/^v(?=\d)/, ""), b.replace(/^v(?=\d)/, "")));
  return above[0] ?? [...fixedVersions].sort(compareVersions).at(-1);
}
