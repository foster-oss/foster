import { resolve } from "node:path";
import { indexByName, indexKey, loadOrphanIndex, type LoadOptions } from "./data.js";
import { detectLockfiles, readDependencies } from "./lockfile.js";
import { findProjectDirs } from "./scan.js";
import type { Dependency, MaintenanceStatus, OrphanRecord } from "./types.js";

/**
 * `foster-oss fund`: the root cause of orphaned packages is that nobody pays to maintain them.
 * This lists the dependencies of a project that are unmaintained or at risk, ranked by how much
 * the ecosystem relies on them, with the ways their maintainers accept support. Like `npm fund`,
 * but across six ecosystems and ordered by risk instead of alphabetically.
 */

export interface FundingCandidate {
  dependency: Dependency;
  status: MaintenanceStatus;
  /** Why this package is listed: unmaintained, single publisher, unfixed advisories. */
  reasons: string[];
  dependentRepos: number | null;
  /** Sponsorship pages (GitHub Sponsors, Open Collective, Tidelift, Ko-fi, …). Empty when none is known. */
  links: string[];
  repoUrl: string | null;
}

export interface FundResult {
  dir: string;
  dependencyCount: number;
  /** At-risk dependencies whose maintainers accept support, most relied-upon first. */
  fundable: FundingCandidate[];
  /** At-risk dependencies with no known funding link. */
  unfundable: FundingCandidate[];
  warnings: string[];
}

type RecordWithFunding = OrphanRecord & { funding?: string[] };

const STATUS_ORDER: MaintenanceStatus[] = ["dead", "dormant", "unknown", "active"];

/** Is this record a package worth funding: unmaintained, run by one person, or carrying unfixed advisories? */
export function atRisk(r: RecordWithFunding): string[] {
  const reasons: string[] = [];
  if (r.status === "dead" || r.status === "dormant") reasons.push(r.status === "dead" ? "unmaintained (dead)" : "unmaintained (dormant)");
  if (r.unpatchedAdvisories.length) reasons.push(`${r.unpatchedAdvisories.length} advisory(ies) no release fixes`);
  if (r.publishers === 1 && reasons.length) reasons.push("one person can publish it");
  return reasons;
}

/** Rank at-risk dependencies by status, then by how many repositories rely on them. */
export function fundingCandidates(deps: Dependency[], records: Map<string, RecordWithFunding>): { fundable: FundingCandidate[]; unfundable: FundingCandidate[] } {
  const seen = new Set<string>();
  const out: FundingCandidate[] = [];
  for (const d of deps) {
    const key = indexKey(d.ecosystem, d.name);
    if (seen.has(key)) continue;
    const r = records.get(key);
    if (!r) continue;
    const reasons = atRisk(r);
    if (!reasons.length) continue;
    seen.add(key);
    out.push({ dependency: d, status: r.status, reasons, dependentRepos: r.dependentRepos, links: [...new Set(r.funding ?? [])], repoUrl: r.repoUrl });
  }
  out.sort(
    (a, b) =>
      STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status) ||
      (b.dependentRepos ?? 0) - (a.dependentRepos ?? 0) ||
      a.dependency.name.localeCompare(b.dependency.name),
  );
  return { fundable: out.filter((c) => c.links.length > 0), unfundable: out.filter((c) => c.links.length === 0) };
}

export async function fundProject(dirInput: string, opts: LoadOptions & { recursive?: boolean; indexFile?: string } = {}): Promise<FundResult> {
  const dir = resolve(dirInput);
  const warnings: string[] = [];
  const dirs = opts.recursive ? findProjectDirs(dir) : [dir];
  const deps: Dependency[] = [];
  for (const pd of dirs) for (const lock of detectLockfiles(pd)) deps.push(...readDependencies(pd, lock));
  if (deps.length === 0) warnings.push("no supported lockfile found");
  const index = await loadOrphanIndex({ offline: opts.offline, file: opts.indexFile }, warnings);
  const records = indexByName(index) as Map<string, RecordWithFunding>;
  const { fundable, unfundable } = fundingCandidates(deps, records);
  return { dir, dependencyCount: deps.length, fundable, unfundable, warnings };
}

function compact(n: number | null): string {
  return n === null ? "?" : Intl.NumberFormat("en", { notation: "compact" }).format(n);
}

/** Short label for a sponsorship URL. */
export function fundingLabel(url: string): string {
  const m = url.match(/^https?:\/\/(?:www\.)?([^/]+)\/(.*)$/);
  if (!m) return url;
  const [, host = "", path = ""] = m;
  if (host === "github.com" && path.startsWith("sponsors/")) return `GitHub Sponsors: ${path.slice("sponsors/".length)}`;
  if (host === "opencollective.com") return `Open Collective: ${path.split("/")[0]}`;
  if (host === "tidelift.com") return "Tidelift";
  if (host === "ko-fi.com") return `Ko-fi: ${path.split("/")[0]}`;
  if (host === "patreon.com") return `Patreon: ${path.split("/")[0]}`;
  if (host === "liberapay.com") return `Liberapay: ${path.split("/")[0]}`;
  if (host === "buymeacoffee.com") return `Buy Me a Coffee: ${path.split("/")[0]}`;
  return host;
}

export function formatFund(result: FundResult): string {
  const lines: string[] = [`Foster fund: ${result.dir}`, `${result.dependencyCount} packages checked`, ""];
  for (const w of result.warnings) lines.push(`warning: ${w}`);
  if (result.fundable.length === 0 && result.unfundable.length === 0) {
    lines.push("None of your dependencies in the Orphan Index is unmaintained or at risk. 🎉");
    return lines.join("\n");
  }
  if (result.fundable.length) {
    lines.push("Your project relies on these at-risk packages, and their maintainers accept support:", "");
    for (const c of result.fundable) {
      lines.push(`  ${c.dependency.name} (${c.dependency.ecosystem}) · ${c.reasons.join(", ")} · ${compact(c.dependentRepos)} dependent repos`);
      for (const l of c.links) lines.push(`      ${fundingLabel(l)}  ${l}`);
    }
    lines.push("");
  }
  if (result.unfundable.length) {
    const names = result.unfundable.slice(0, 12).map((c) => c.dependency.name).join(", ");
    lines.push(`At risk, but no funding link is known (${result.unfundable.length}): ${names}${result.unfundable.length > 12 ? ", …" : ""}`);
    lines.push("  Help by sending fixes upstream, offering to co-maintain, or asking a foundation to adopt them.");
    lines.push("");
  }
  lines.push("Funding the people who maintain what you depend on fixes the cause; scanners only show the symptoms.");
  return lines.join("\n");
}
