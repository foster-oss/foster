import { normalizeSeverity } from "./classify.js";
import { fetchJson, mapLimit } from "./http.js";
import type { AdvisorySummary, Dependency, Ecosystem, Severity } from "./types.js";

const OSV = "https://api.osv.dev/v1";
export const OSV_ECOSYSTEM: Record<Ecosystem, string> = {
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
  database_specific?: { severity?: string; cwe_ids?: string[] };
  affected?: {
    package?: { ecosystem?: string; name?: string };
    ranges?: { type?: string; events?: OsvRangeEvent[] }[];
    versions?: string[];
    database_specific?: { severity?: string; informational?: string };
  }[];
}

/**
 * RustSec notices that are not vulnerabilities ("unmaintained", "unsound", "notice"): maintenance
 * information, which Foster reports from its own index and never blocks on.
 */
export function isInformational(v: Pick<OsvVuln, "affected">): boolean {
  const affected = v.affected ?? [];
  return affected.length > 0 && affected.every((a) => !!a.database_specific?.informational);
}

export interface VulnForDependency {
  advisory: AdvisorySummary;
  /** Versions that fix this vulnerability for this package, from OSV "fixed" events. Empty when no fix exists. */
  fixedVersions: string[];
  /** Highest version known to be affected ("last_affected" events). A newer release is then not affected. */
  lastAffected: string[];
  isMalware: boolean;
}

/** Answers already fetched in this process, per "ecosystem:name@version". */
const batchCache = new Map<string, string[]>();
const batchKey = (d: Dependency) => `${d.ecosystem}:${d.name}@${d.version}`;

/**
 * Query OSV for every dependency in batches of up to 1000. Returns vuln ids per dependency index.
 * Answers are remembered for the life of the process, so guard can ask about every package of a
 * command in one request up front and the per-package checks after it need none.
 */
export async function queryBatch(deps: readonly Dependency[]): Promise<string[][]> {
  const missing = [...new Map(deps.filter((d) => !batchCache.has(batchKey(d))).map((d) => [batchKey(d), d])).values()];
  for (let start = 0; start < missing.length; start += 1000) {
    const chunk = missing.slice(start, start + 1000);
    const body = {
      queries: chunk.map((d) => ({ package: { name: d.name, ecosystem: OSV_ECOSYSTEM[d.ecosystem] }, version: d.version })),
    };
    const res = await fetchJson<OsvBatchResponse>(`${OSV}/querybatch`, { method: "POST", body, timeoutMs: 60_000 });
    res.results.forEach((r, i) => batchCache.set(batchKey(chunk[i]!), (r.vulns ?? []).map((v) => v.id)));
  }
  return deps.map((d) => batchCache.get(batchKey(d)) ?? []);
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
  const isMalware = isMalwareRecord(v);
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

/**
 * How GitHub and the OpenSSF malicious-packages database title malware reports: "Malicious code in x",
 * "Embedded malware in x", "x is malware". Stricter than MALWARE_TITLE, so that an ordinary
 * vulnerability ("session hijacking", "lets an attacker inject malicious code into ...") is not
 * mistaken for a malicious release.
 */
const MALWARE_REPORT =
  /\b(embedded )?(malicious (code|package|version|release|payload)s?|malware|protestware) in\b|\bis (a )?malware\b|\bcontain(s|ed)? (a )?(malware|malicious (code|crypto ?miner|payload|version))\b|^malware\b|\bcompromised (package|version|release)s?\b|\bmalicious (version|release)s? (caus|of|with|publish)/i;

/** Is this OSV record a malware report (a malicious package or a hijacked release) rather than a vulnerability? */
export function isMalwareRecord(v: Pick<OsvVuln, "id" | "aliases" | "summary"> & { database_specific?: OsvVuln["database_specific"] }): boolean {
  // CWE-506: Embedded Malicious Code
  if (v.database_specific?.cwe_ids?.includes("CWE-506")) return true;
  return v.id.startsWith("MAL-") || (v.aliases ?? []).some((a) => a.startsWith("MAL-")) || MALWARE_REPORT.test(v.summary ?? "");
}

export interface MalwareReport {
  id: string;
  url: string;
  title: string;
  /** Every release is malicious (the report starts at version 0), not just some hijacked versions. */
  wholePackage: boolean;
}

/**
 * Known malware reports for a package (OSV, which includes the OpenSSF malicious-packages database
 * and GitHub's malware advisories). With a version, only reports that cover that version.
 */
export async function malwareReports(ecosystem: Ecosystem, name: string, version?: string): Promise<MalwareReport[]> {
  const body = { package: { name, ecosystem: OSV_ECOSYSTEM[ecosystem] }, ...(version ? { version } : {}) };
  const res = await fetchJson<{ vulns?: OsvVuln[] }>(`${OSV}/query`, { method: "POST", body, timeoutMs: 15_000, retries: 1 });
  const dep: Dependency = { ecosystem, name, version: version ?? "0", direct: true, source: "guard" };
  return (res.vulns ?? [])
    .filter((v) => !v.withdrawn && isMalwareRecord(v))
    .map((v) => {
      const id = v.id.startsWith("MAL-") ? v.id : (v.aliases?.find((a) => a.startsWith("MAL-")) ?? displayId(v));
      const wholePackage = (v.affected ?? []).some(
        (a) => sameName(a.package?.name, dep) && (a.ranges ?? []).some((r) => r.events?.[0]?.introduced === "0"),
      );
      return { id, url: `https://osv.dev/vulnerability/${v.id}`, title: v.summary ?? id, wholePackage };
    });
}

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

export interface LockedMalware {
  dependency: Dependency;
  report: MalwareReport;
}

/**
 * Known malware among locked dependencies: one OSV batch query for all of them, then the details
 * of the advisories found (cached), keeping only malware reports.
 */
export async function lockfileMalware(deps: Dependency[]): Promise<LockedMalware[]> {
  if (deps.length === 0) return [];
  const ids = await queryBatch(deps);
  const details = await getVulns(ids.flat());
  const out: LockedMalware[] = [];
  deps.forEach((dep, i) => {
    for (const id of ids[i] ?? []) {
      const v = details.get(id);
      if (!v || v.withdrawn || !isMalwareRecord(v)) continue;
      const mal = v.id.startsWith("MAL-") ? v.id : (v.aliases?.find((a) => a.startsWith("MAL-")) ?? displayId(v));
      out.push({ dependency: dep, report: { id: mal, url: `https://osv.dev/vulnerability/${v.id}`, title: v.summary ?? mal, wholePackage: false } });
    }
  });
  return out;
}
