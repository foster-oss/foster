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
  const installed = stripV(dep.version);
  for (const aff of v.affected ?? []) {
    if (!sameName(aff.package?.name, dep)) continue;
    if (severity === "UNKNOWN") severity = normalizeSeverity(aff.database_specific?.severity);
    for (const range of aff.ranges ?? []) {
      // GIT ranges hold commit hashes, not release versions.
      if (range.type && range.type !== "SEMVER" && range.type !== "ECOSYSTEM") continue;
      const end = intervalEndFor(range.events ?? [], installed);
      if (end === "unrelated") continue;
      if (end?.fixed) fixed.push(end.fixed);
      if (end?.last_affected) lastAffected.push(end.last_affected);
      // end === null: the installed version is in an open-ended interval, nothing fixes it on this line.
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

function stripV(version: string): string {
  return version.replace(/^v(?=\d)/, "");
}

/**
 * OSV ranges are lists of intervals: introduced → fixed / last_affected, possibly several per
 * range (one per release line). Return the end of the interval that contains the installed
 * version: { fixed } or { last_affected }, null when that interval is open-ended (no fix), or
 * "unrelated" when no interval contains it.
 */
export function intervalEndFor(events: OsvRangeEvent[], installed: string): { fixed?: string; last_affected?: string } | null | "unrelated" {
  let start: string | null = null;
  const cmp = (a: string, b: string) => compareVersions(stripV(a), stripV(b));
  for (const ev of events) {
    if (ev.introduced !== undefined) {
      start = ev.introduced;
      continue;
    }
    if (start === null) continue;
    const afterStart = start === "0" || cmp(installed, start) >= 0;
    if (ev.fixed !== undefined) {
      if (afterStart && cmp(installed, ev.fixed) < 0) return { fixed: ev.fixed };
      start = null;
    } else if (ev.last_affected !== undefined) {
      if (afterStart && cmp(installed, ev.last_affected) <= 0) return { last_affected: ev.last_affected };
      start = null;
    }
  }
  if (start !== null && (start === "0" || cmp(installed, start) >= 0)) return null;
  return "unrelated";
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
  // Never suggest a fix below the installed version: that would be a downgrade.
  return above[0];
}
