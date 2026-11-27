import type { AlternativeSet } from "./replacements.js";

export type Ecosystem = "npm" | "pypi" | "cargo" | "go" | "rubygems" | "packagist";

export const ECOSYSTEMS: readonly Ecosystem[] = ["npm", "pypi", "cargo", "go", "rubygems", "packagist"] as const;

/** Human-readable names, used in reports and the site. */
export const ECOSYSTEM_LABEL: Record<Ecosystem, string> = {
  npm: "npm",
  pypi: "PyPI",
  cargo: "Cargo",
  go: "Go",
  rubygems: "RubyGems",
  packagist: "Packagist",
};

/** A resolved package found in a project's lockfile. */
export interface Dependency {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  /** True when the package is listed directly in the project manifest. */
  direct: boolean;
  /**
   * For a transitive dependency: the direct dependencies that bring it in (upgrade or replace those).
   * Present only when the lockfile records the dependency graph.
   */
  via?: string[];
  /** Lockfile the dependency was read from (relative to the scanned dir). */
  source: string;
}

export type MaintenanceStatus = "active" | "dormant" | "dead" | "unknown";

export type Severity = "CRITICAL" | "HIGH" | "MODERATE" | "LOW" | "UNKNOWN";

export interface AdvisorySummary {
  id: string;
  url: string;
  severity: Severity;
  title: string;
  /** Vulnerable version range as published by the advisory source. */
  range?: string;
}

/** One row of the Orphan Index. */
export interface OrphanRecord {
  ecosystem: Ecosystem;
  name: string;
  status: MaintenanceStatus;
  reasons: string[];
  downloadsLastMonth: number | null;
  dependentRepos: number | null;
  dependentPackages: number | null;
  latestVersion: string | null;
  latestReleaseAt: string | null;
  repoUrl: string | null;
  archived: boolean;
  lastPushAt: string | null;
  /** Number of accounts able to publish to the registry, when known. */
  publishers: number | null;
  unpatchedAdvisories: AdvisorySummary[];
  /** Priority score: higher means more people are exposed to an unmaintained, vulnerable package. */
  priority: number;
  /** Sponsorship pages for the package's maintainers (GitHub Sponsors, Open Collective, …), when known. */
  funding?: string[];
}

export type PatchStatus = "staged" | "released" | "retired";

/** An entry in Foster's patch registry (registry/patches.json). */
export interface PatchEntry {
  ecosystem: Ecosystem;
  /** Original package name. */
  name: string;
  /** semver range of original versions this patch replaces. */
  affected: string;
  replacement: {
    name: string;
    version: string;
  };
  advisories: string[];
  status: PatchStatus;
  /** Who publishes and maintains the patched package. Absent means Foster itself. */
  provider?: { name: string; url: string };
  /** Path of the patch folder inside the Foster repo (Foster patches only), e.g. patches/npm/ip. */
  patchDir?: string;
  summary: string;
}

export type FindingKind =
  /** A published drop-in security patch (from Foster or another provider) exists for this exact version. */
  | "patch-available"
  /** Known vulnerability with no upstream fix, and the package is dead or dormant. */
  | "orphaned-vulnerable"
  /** Known vulnerability with no upstream fix; maintenance status active or unknown. */
  | "unpatched-vulnerable"
  /** Known vulnerability that is fixed in a newer upstream version: just upgrade. */
  | "upgrade-available"
  /** Critical package that is dead or dormant, no known vulnerability (yet). */
  | "orphaned";

export interface Finding {
  kind: FindingKind;
  dependency: Dependency;
  status: MaintenanceStatus;
  severity: Severity;
  advisories: AdvisorySummary[];
  patch?: PatchEntry;
  /** For upgrade-available: the lowest version that fixes all listed advisories, if known. */
  fixedIn?: string;
  /** Maintained replacements worth moving to (npm only, from e18e module-replacements). */
  alternatives?: AlternativeSet;
  /** Where to fund the maintainers of an unmaintained or at-risk package. */
  funding?: string[];
  message: string;
}

export interface ScanResult {
  dir: string;
  scannedAt: string;
  lockfiles: string[];
  dependencyCount: number;
  findings: Finding[];
  /** Data sources that could not be reached; results may be incomplete. */
  warnings: string[];
  /** When set, only dependencies added or changed since this git ref were checked. */
  since?: string;
  /** Packages skipped because they were already present at `since`. */
  unchangedCount?: number;
  /** Findings per kind, with how many are direct dependencies. */
  summary?: FindingSummary;
}

export type FindingSummary = Record<FindingKind, { total: number; direct: number }>;
