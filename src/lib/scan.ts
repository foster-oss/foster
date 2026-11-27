import { execFileSync } from "node:child_process";
import { readdirSync, type Dirent } from "node:fs";
import { basename, dirname, join, relative, resolve } from "node:path";
import { readSbom } from "./sbom.js";
import { maxSeverity, toOrphanRecord } from "./classify.js";
import { findPatch, indexByName, indexKey, loadOrphanIndex, loadRegistry, type PatchRegistry } from "./data.js";
import { getPackage } from "./ecosystems.js";
import { mapLimit } from "./http.js";
import { detectLockfiles, mergeInto, readDependencies } from "./lockfile.js";
import { describeForDependency, getVulns, lowestFixAbove, newerReleaseEscapes, queryBatch, type OsvVuln, type VulnForDependency } from "./osv.js";
import { compareVersions, rangeIncludes } from "./versions.js";
import { alternativesFor } from "./replacements.js";
import type { AdvisorySummary, Dependency, Finding, FindingSummary, MaintenanceStatus, OrphanRecord, ScanResult, Severity } from "./types.js";

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
  /** Also scan lockfiles in subfolders (monorepos), skipping node_modules, vendor, target, etc. */
  recursive?: boolean;
  /** Only check dependencies added or changed since this git ref (e.g. the base of a pull request). */
  since?: string;
}

const KIND_ORDER: Finding["kind"][] = ["patch-available", "orphaned-vulnerable", "unpatched-vulnerable", "upgrade-available", "orphaned"];
const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"];

/** Folders never worth descending into when looking for lockfiles. */
const SKIP_DIRS = new Set(["node_modules", ".git", "vendor", "target", "dist", "build", ".venv", "venv", "__pycache__", ".next", ".nuxt", ".cache", "coverage", ".tox", "bower_components"]);

/** Directories under `root` (including root) that contain at least one supported lockfile. */
export function findProjectDirs(root: string, maxDepth = 6): string[] {
  const out: string[] = [];
  const walk = (dir: string, depth: number) => {
    if (detectLockfiles(dir).length) out.push(dir);
    if (depth >= maxDepth) return;
    let entries: Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (!e.isDirectory() || SKIP_DIRS.has(e.name) || (e.name.startsWith(".") && e.name !== ".")) continue;
      walk(join(dir, e.name), depth + 1);
    }
  };
  walk(root, 0);
  return out;
}

export async function scanProject(dirInput: string, opts: ScanOptions = {}): Promise<ScanResult> {
  const dir = resolve(dirInput);
  const warnings: string[] = [];
  const projectDirs = opts.recursive ? findProjectDirs(dir) : [dir];
  const lockfiles: string[] = [];
  const all: Dependency[] = [];
  let unchanged = 0;
  for (const pd of projectDirs) {
    for (const lock of detectLockfiles(pd)) {
      const prefix = relative(dir, pd).replace(/\\/g, "/");
      const source = prefix ? `${prefix}/${lock.file}` : lock.file;
      lockfiles.push(source);
      let current = readDependencies(pd, lock);
      if (opts.since) {
        const before = lockfileAt(pd, lock.file, opts.since);
        if (before.error) warnings.push(`--since ${opts.since}: ${before.error}; checking every dependency in ${source}`);
        else {
          const old = new Set(before.text === null ? [] : readDependencies(pd, lock, before.text).map(depKey));
          const kept = current.filter((d) => !old.has(depKey(d)));
          unchanged += current.length - kept.length;
          current = kept;
        }
      }
      for (const d of current) all.push({ ...d, source });
    }
  }
  if (lockfiles.length === 0) {
    warnings.push(
      `no supported lockfile found${opts.recursive ? " in this folder or its subfolders" : " (use --recursive for monorepos)"}: package-lock.json, pnpm-lock.yaml, yarn.lock, uv.lock, poetry.lock, Pipfile.lock, requirements.txt, Cargo.lock, go.mod, Gemfile.lock, composer.lock`,
    );
  }
  // The same package version used by several sub-projects is reported once (first lockfile wins).
  const merged = new Map<string, Dependency>();
  for (const d of all) {
    const key = `${d.ecosystem}:${d.name}@${d.version}`;
    const prev = merged.get(key);
    if (!prev) merged.set(key, { ...d });
    else mergeInto(prev, d); // direct in any sub-project counts
  }
  const deps = [...merged.values()];
  const findings = await analyzeDependencies(deps, opts, warnings);
  return {
    dir,
    scannedAt: new Date().toISOString(),
    lockfiles,
    dependencyCount: deps.length,
    findings,
    summary: summarize(findings),
    warnings,
    ...(opts.since ? { since: opts.since, unchangedCount: unchanged } : {}),
  };
}

function depKey(d: Dependency): string {
  return `${d.ecosystem}:${d.name}@${d.version}`;
}

/**
 * The lockfile's content at a git ref: text, null when the file did not exist then (everything is new),
 * or an error when git is unavailable or the ref is unknown.
 */
export function lockfileAt(dir: string, file: string, ref: string): { text: string | null; error?: string } {
  try {
    execFileSync("git", ["-C", dir, "rev-parse", "--verify", "--quiet", `${ref}^{commit}`], { stdio: "pipe" });
  } catch {
    return { text: null, error: `git ref "${ref}" not found here (shallow clone? fetch it first)` };
  }
  try {
    const out = execFileSync("git", ["-C", dir, "show", `${ref}:./${file}`], { stdio: ["ignore", "pipe", "pipe"], maxBuffer: 1 << 28 }).toString("utf8");
    return { text: out.charCodeAt(0) === 0xfeff ? out.slice(1) : out };
  } catch {
    return { text: null }; // the file did not exist at that ref
  }
}

/** Scan an SBOM (CycloneDX or SPDX JSON) instead of lockfiles. */
export async function scanSbom(file: string, opts: ScanOptions = {}): Promise<ScanResult> {
  const path = resolve(file);
  const warnings: string[] = [];
  const sbom = readSbom(path);
  const skipped = Object.entries(sbom.skipped);
  if (skipped.length) warnings.push(`not covered yet: ${skipped.map(([t, n]) => `${n} ${t}`).join(", ")} package(s)`);
  if (sbom.dependencies.length === 0) warnings.push(`no supported packages with versions found in this ${sbom.format} SBOM`);
  const findings = await analyzeDependencies(sbom.dependencies, opts, warnings);
  return {
    dir: dirname(path),
    scannedAt: new Date().toISOString(),
    lockfiles: [basename(path)],
    dependencyCount: sbom.dependencies.length,
    findings,
    summary: summarize(findings),
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
    if (f) {
      // Where to go next: a maintained replacement, for anything that is not a plain upgrade.
      if (f.kind !== "upgrade-available") f.alternatives = alternativesFor(f.dependency.ecosystem, f.dependency.name);
      // The cause of orphaned packages is unpaid maintenance: show where to fund it.
      if (f.kind !== "upgrade-available" && p.record?.funding?.length) f.funding = p.record.funding;
      findings.push(f);
    }
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
      message: `${label}: drop-in patch ${patch.replacement.name}@${patch.replacement.version} by ${patch.provider?.name ?? "Foster"}${patch.status === "staged" ? " (staged, not yet released)" : ""} fixes ${patch.advisories.join(", ")}. Run \`foster-oss fix\`.`,
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
      Number(b.dependency.direct) - Number(a.dependency.direct) || // what you can change yourself first
      a.dependency.name.localeCompare(b.dependency.name),
  );
}

/** Findings per kind, and how many of them are direct dependencies (the ones the project declares itself). */
export function summarize(findings: Finding[]): FindingSummary {
  const s = Object.fromEntries(KIND_ORDER.map((k) => [k, { total: 0, direct: 0 }])) as FindingSummary;
  for (const f of findings) {
    s[f.kind].total++;
    if (f.dependency.direct) s[f.kind].direct++;
  }
  return s;
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
