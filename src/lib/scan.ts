import { resolve } from "node:path";
import { maxSeverity, toOrphanRecord } from "./classify.js";
import { findPatch, indexByName, indexKey, loadOrphanIndex, loadRegistry, type PatchRegistry } from "./data.js";
import { getPackage } from "./ecosystems.js";
import { mapLimit } from "./http.js";
import { detectLockfiles, readDependencies } from "./lockfile.js";
import { describeForDependency, getVulns, lowestFixAbove, newerReleaseEscapes, queryBatch, type OsvVuln, type VulnForDependency } from "./osv.js";
import { compareVersions, rangeIncludes } from "./versions.js";
import type { AdvisorySummary, Dependency, Finding, MaintenanceStatus, OrphanRecord, ScanResult, Severity } from "./types.js";

export interface ScanOptions {
  /** Use only data bundled with this release: no OSV, no ecosyste.ms, no remote registry. */
  offline?: boolean;
  includeStaged?: boolean;
  /** Look up maintenance status live for vulnerable packages missing from the index. Default true. */
  deep?: boolean;
  /** Maximum live ecosyste.ms lookups per scan. */
  deepLimit?: number;
  registryFile?: string;
  indexFile?: string;
  /** Maintenance records already known to the caller (key: "ecosystem:name"); they take precedence over the index. */
  records?: Map<string, OrphanRecord>;
}

const KIND_ORDER: Finding["kind"][] = ["patch-available", "orphaned-vulnerable", "unpatched-vulnerable", "upgrade-available", "orphaned"];
const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"];

export async function scanProject(dirInput: string, opts: ScanOptions = {}): Promise<ScanResult> {
  const dir = resolve(dirInput);
  const warnings: string[] = [];
  const locks = detectLockfiles(dir);
  if (locks.length === 0) {
    warnings.push("no supported lockfile found (package-lock.json, pnpm-lock.yaml, yarn.lock, uv.lock, requirements.txt)");
  }
  const deps = locks.flatMap((l) => readDependencies(dir, l));
  const findings = await analyzeDependencies(deps, opts, warnings);
  return {
    dir,
    scannedAt: new Date().toISOString(),
    lockfiles: locks.map((l) => l.file),
    dependencyCount: deps.length,
    findings,
    warnings,
  };
}

export async function analyzeDependencies(deps: Dependency[], opts: ScanOptions = {}, warnings: string[] = []): Promise<Finding[]> {
  const loadOpts = { offline: opts.offline };
  const [registry, indexFile] = await Promise.all([
    loadRegistry({ ...loadOpts, file: opts.registryFile }, warnings),
    loadOrphanIndex({ ...loadOpts, file: opts.indexFile }, warnings),
  ]);
  const index = indexByName(indexFile);
  for (const [key, record] of opts.records ?? []) index.set(key, record);

  // 1. Live vulnerability data from OSV (skipped offline).
  let vulnIds: string[][] = deps.map(() => []);
  if (!opts.offline && deps.length > 0) {
    try {
      vulnIds = await queryBatch(deps);
    } catch (err) {
      warnings.push(`OSV vulnerability lookup failed, results use bundled data only: ${(err as Error).message}`);
    }
  }
  let vulnDetails = new Map<string, OsvVuln>();
  try {
    vulnDetails = await getVulns(vulnIds.flat());
  } catch (err) {
    warnings.push(`could not fetch vulnerability details: ${(err as Error).message}`);
  }

  // 2. Per-dependency vulnerability descriptions.
  interface Pending {
    dep: Dependency;
    vulns: VulnForDependency[];
    record?: OrphanRecord;
  }
  const pending: Pending[] = deps.map((dep, i) => {
    const vulns: VulnForDependency[] = [];
    for (const id of vulnIds[i] ?? []) {
      const v = vulnDetails.get(id);
      if (!v || v.withdrawn) continue;
      const d = describeForDependency(v, dep);
      if (d.isMalware) continue; // hijacked releases need removal, not a patch; npm audit / OSV scanners report them
      vulns.push(d);
    }
    const record = index.get(indexKey(dep.ecosystem, dep.name));
    // Offline, fall back to the index's own list of unpatched advisories for this package.
    if (opts.offline && record) {
      for (const a of record.unpatchedAdvisories) {
        if (!a.range || rangeIncludes(a.range, dep.version)) vulns.push({ advisory: a, fixedVersions: [], lastAffected: [], isMalware: false });
      }
    }
    return { dep, vulns, record };
  });

  // 3. Live maintenance lookups for vulnerable packages the index does not cover.
  if (!opts.offline && opts.deep !== false) {
    const needLookup = pending.filter((p) => p.vulns.some((v) => v.fixedVersions.length === 0) && !p.record);
    const unique = [...new Map(needLookup.map((p) => [indexKey(p.dep.ecosystem, p.dep.name), p.dep])).values()].slice(0, opts.deepLimit ?? 50);
    const looked = new Map<string, OrphanRecord>();
    await mapLimit(unique, 4, async (dep) => {
      try {
        const raw = await getPackage(dep.ecosystem, dep.name);
        looked.set(indexKey(dep.ecosystem, dep.name), toOrphanRecord(raw, dep.ecosystem));
      } catch {
        // unknown status is fine; reported as such
      }
    });
    for (const p of needLookup) p.record = looked.get(indexKey(p.dep.ecosystem, p.dep.name));
  }

  // 4. Split into "fixed somewhere upstream" and "no fix anywhere", then turn into findings.
  const findings: Finding[] = [];
  for (const p of pending) {
    const unpatched: AdvisorySummary[] = [];
    const fixable: AdvisorySummary[] = [];
    const fixes: string[] = [];
    for (const v of p.vulns) {
      if (v.fixedVersions.length > 0) {
        fixable.push(v.advisory);
        const f = lowestFixAbove(p.dep, v.fixedVersions);
        if (f) fixes.push(f);
      } else if (newerReleaseEscapes(v, p.record?.latestVersion)) {
        fixable.push(v.advisory);
        fixes.push(p.record!.latestVersion!);
      } else {
        unpatched.push(v.advisory);
      }
    }
    const f = toFinding(p.dep, dedupeAdvisories(unpatched), dedupeAdvisories(fixable), highestVersion(fixes), p.record, registry, opts.includeStaged ?? false);
    if (f) findings.push(f);
  }
  return sortFindings(findings);
}

function dedupeAdvisories(list: AdvisorySummary[]): AdvisorySummary[] {
  return [...new Map(list.map((a) => [a.id, a])).values()];
}

function toFinding(
  dep: Dependency,
  unpatched: AdvisorySummary[],
  fixable: AdvisorySummary[],
  fixedIn: string | undefined,
  record: OrphanRecord | undefined,
  registry: PatchRegistry,
  includeStaged: boolean,
): Finding | null {
  const status: MaintenanceStatus = record?.status ?? "unknown";
  const patch = findPatch(registry, dep, includeStaged);
  const label = `${dep.name}@${dep.version}`;

  if (patch) {
    const advisories = unpatched.length ? unpatched : patch.advisories.map((id) => ({ id, url: id.startsWith("GHSA-") ? `https://github.com/advisories/${id}` : `https://osv.dev/vulnerability/${id}`, severity: "UNKNOWN" as Severity, title: id }));
    return {
      kind: "patch-available",
      dependency: dep,
      status,
      severity: maxSeverity(advisories),
      advisories,
      patch,
      message: `${label}: Foster patch ${patch.replacement.name}@${patch.replacement.version}${patch.status === "staged" ? " (staged, not yet released)" : ""} fixes ${patch.advisories.join(", ")}. Run \`foster-oss fix\`.`,
    };
  }
  if (unpatched.length > 0) {
    const orphaned = status === "dead" || status === "dormant";
    return {
      kind: orphaned ? "orphaned-vulnerable" : "unpatched-vulnerable",
      dependency: dep,
      status,
      severity: maxSeverity(unpatched),
      advisories: unpatched,
      message: orphaned
        ? `${label}: ${unpatched.length} advisory(ies) with no fix anywhere, and the package looks ${status}. A good candidate for Foster adoption.`
        : `${label}: ${unpatched.length} advisory(ies) with no released fix yet (maintenance: ${status}).`,
    };
  }
  if (fixable.length > 0) {
    return {
      kind: "upgrade-available",
      dependency: dep,
      status,
      severity: maxSeverity(fixable),
      advisories: fixable,
      fixedIn,
      message: `${label}: fixed upstream${fixedIn ? ` in ${fixedIn}` : ""}. Upgrade normally; no patch needed.`,
    };
  }
  if (record && (record.status === "dead" || record.status === "dormant")) {
    return {
      kind: "orphaned",
      dependency: dep,
      status: record.status,
      severity: "UNKNOWN",
      advisories: [],
      message: `${label}: widely used but ${record.status} (${record.reasons.join("; ")}). No known vulnerability today.`,
    };
  }
  return null;
}

/** Highest of several fix versions: upgrading to it fixes every listed advisory. */
function highestVersion(versions: string[]): string | undefined {
  if (versions.length === 0) return undefined;
  return [...versions].sort(compareVersions).at(-1);
}

export function sortFindings(findings: Finding[]): Finding[] {
  return findings.sort(
    (a, b) =>
      KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind) ||
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
      a.dependency.name.localeCompare(b.dependency.name),
  );
}

export type FailOn = "none" | "patch-available" | "orphaned-vulnerable" | "unpatched" | "any";

/** Whether the scan should fail CI, given the --fail-on threshold. */
export function shouldFail(findings: Finding[], failOn: FailOn): boolean {
  switch (failOn) {
    case "none":
      return false;
    case "patch-available":
      return findings.some((f) => f.kind === "patch-available");
    case "orphaned-vulnerable":
      return findings.some((f) => f.kind === "patch-available" || f.kind === "orphaned-vulnerable");
    case "unpatched":
      return findings.some((f) => ["patch-available", "orphaned-vulnerable", "unpatched-vulnerable"].includes(f.kind));
    case "any":
      return findings.length > 0;
  }
}
