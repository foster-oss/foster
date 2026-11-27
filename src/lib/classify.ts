import type { RawPackage } from "./ecosystems.js";
import type { AdvisorySummary, Ecosystem, MaintenanceStatus, OrphanRecord, Severity } from "./types.js";
import { rangeIncludes } from "./versions.js";

const DAY = 24 * 60 * 60 * 1000;

export interface Classification {
  status: MaintenanceStatus;
  reasons: string[];
}

function ageDays(iso: string | null | undefined, now: Date): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.floor((now.getTime() - t) / DAY);
}

/**
 * Classify how well a package is maintained, using only public metadata.
 *
 * This mirrors the buckets used by Andrew Nesbitt's 2026 analysis of the ecosyste.ms critical set
 * (Active / Dormant / Dead / Unknown). "Write-access response" is approximated by closes and merges,
 * because ecosyste.ms does not expose who responded. See METHODOLOGY.md.
 */
export function classify(pkg: RawPackage, now: Date = new Date()): Classification {
  const repo = pkg.repo_metadata ?? null;
  const issues = pkg.issue_metadata ?? null;
  const releaseAge = ageDays(pkg.latest_release_published_at, now);
  const pushAge = ageDays(repo?.pushed_at, now);

  if (pkg.status && ["removed", "deprecated"].includes(pkg.status)) {
    return { status: "dead", reasons: [`registry marks the package as ${pkg.status}`] };
  }

  if (!repo) {
    if (releaseAge !== null && releaseAge > 730) {
      return { status: "dormant", reasons: ["no linked source repository", `no release for ${years(releaseAge)}`] };
    }
    return { status: "unknown", reasons: ["no linked source repository"] };
  }

  if (repo.archived) {
    return { status: "dead", reasons: ["source repository is archived"] };
  }

  // No push date and no release date: we cannot tell, so do not guess dead or dormant.
  if (!repo.pushed_at && !pkg.latest_release_published_at) {
    return { status: "unknown", reasons: ["no activity dates available"] };
  }

  const reasons: string[] = [];
  const pushedRecently = pushAge !== null && pushAge <= 365;
  const releasedRecently = releaseAge !== null && releaseAge <= 365;

  if (issues) {
    const opened = (issues.past_year_issues_count ?? 0) + (issues.past_year_pull_requests_count ?? 0);
    const closed = (issues.past_year_issues_closed_count ?? 0) + (issues.past_year_pull_requests_closed_count ?? 0);
    const merged = issues.past_year_merged_pull_requests_count ?? 0;
    if (opened > 0 && closed === 0 && merged === 0 && !pushedRecently && !releasedRecently) {
      reasons.push(`${opened} issue(s)/PR(s) opened in the past year, none closed or merged`);
      if (pushAge !== null) reasons.push(`last push ${years(pushAge)} ago`);
      return { status: "dead", reasons };
    }
  }

  if (!pushedRecently && !releasedRecently) {
    if (releaseAge !== null) reasons.push(`no release for ${years(releaseAge)}`);
    if (pushAge !== null) reasons.push(`no push for ${years(pushAge)}`);
    if (reasons.length === 0) reasons.push("no recent release or push");
    return { status: "dormant", reasons };
  }

  if (!issues && releaseAge === null && pushAge === null) {
    return { status: "unknown", reasons: ["not enough activity data"] };
  }

  return { status: "active", reasons: [] };
}

function years(days: number): string {
  if (days < 60) return `${days} days`;
  if (days < 730) return `${Math.round(days / 30)} months`;
  return `${(days / 365).toFixed(1)} years`;
}

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MODERATE", "LOW"];

export function normalizeSeverity(s: string | null | undefined): Severity {
  const up = (s ?? "").toUpperCase();
  if (up === "MEDIUM") return "MODERATE";
  return (SEVERITIES as string[]).includes(up) ? (up as Severity) : "UNKNOWN";
}

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 10,
  HIGH: 7,
  MODERATE: 4,
  LOW: 1,
  UNKNOWN: 2,
};

export function maxSeverity(list: { severity: Severity }[]): Severity {
  let best: Severity = "UNKNOWN";
  let bestWeight = -1;
  for (const a of list) {
    const order = SEVERITIES.indexOf(a.severity);
    const w = order === -1 ? -0.5 : SEVERITIES.length - order;
    if (w > bestWeight) {
      bestWeight = w;
      best = a.severity;
    }
  }
  return best;
}

/** How each ecosystem is spelled in GitHub/ecosyste.ms advisory records. */
const ADVISORY_ECOSYSTEM: Record<Ecosystem, string[]> = {
  npm: ["npm"],
  pypi: ["pypi", "pip"],
  cargo: ["cargo", "crates.io", "rust"],
  go: ["go", "golang"],
  rubygems: ["rubygems", "gem"],
  packagist: ["packagist", "composer"],
};

/** Same pattern as MALWARE_TITLE in osv.ts; duplicated to keep this module free of network code. */
const MALWARE_TITLE = /malicious|malware|compromised|hijack|embedded .*(code|payload)|protestware|sabotage/i;

/**
 * Advisories against this package that no release fixes: no patched version is published
 * AND the latest release is still inside the vulnerable range.
 * Withdrawn advisories and malware/hijack reports are skipped: those need "avoid this version", not a patch.
 */
export function unpatchedAdvisories(pkg: RawPackage, ecosystem: Ecosystem): AdvisorySummary[] {
  const out: AdvisorySummary[] = [];
  const seen = new Set<string>();
  const latest = pkg.latest_release_number ?? null;
  for (const adv of pkg.advisories ?? []) {
    if (adv.withdrawn_at) continue;
    if ((adv.classification ?? "").toUpperCase() === "MALWARE") continue;
    if (MALWARE_TITLE.test(adv.title ?? "")) continue;
    for (const p of adv.packages ?? []) {
      if (p.package_name !== pkg.name) continue;
      if (p.ecosystem && !ADVISORY_ECOSYSTEM[ecosystem].includes(p.ecosystem.toLowerCase())) continue;
      for (const v of p.versions ?? []) {
        if (v.first_patched_version) continue;
        // If the newest release is outside the range, upgrading fixes it: not an orphan problem.
        if (latest && !rangeIncludes(v.vulnerable_version_range ?? undefined, latest)) continue;
        const id = adv.identifiers?.find((x) => x.startsWith("GHSA-")) ?? adv.url?.split("/").pop() ?? adv.uuid ?? "unknown";
        const key = `${id}|${v.vulnerable_version_range ?? ""}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({
          id,
          url: adv.url ?? `https://github.com/advisories/${id}`,
          severity: normalizeSeverity(adv.severity),
          title: adv.title ?? id,
          range: v.vulnerable_version_range ?? undefined,
        });
      }
    }
  }
  return out;
}

const STATUS_WEIGHT: Record<MaintenanceStatus, number> = { dead: 3, dormant: 2, unknown: 1, active: 0 };

/** Build an Orphan Index row from a raw ecosyste.ms package record. */
export function toOrphanRecord(pkg: RawPackage, ecosystem: Ecosystem, now: Date = new Date()): OrphanRecord {
  const { status, reasons } = classify(pkg, now);
  const advisories = unpatchedAdvisories(pkg, ecosystem);
  const dependentRepos = pkg.dependent_repos_count ?? null;
  const dependentPackages = pkg.dependent_packages_count ?? null;
  const reach = Math.log10(1 + (dependentRepos ?? 0) + 10 * (dependentPackages ?? 0) + (pkg.downloads ?? 0) / 1000);
  const advWeight = advisories.length ? SEVERITY_WEIGHT[maxSeverity(advisories)] : 1;
  const priority = Math.round(reach * STATUS_WEIGHT[status] * advWeight * 10) / 10;
  return {
    ecosystem,
    name: pkg.name,
    status,
    reasons,
    downloadsLastMonth: pkg.downloads_period === "last-month" ? (pkg.downloads ?? null) : null,
    dependentRepos,
    dependentPackages,
    latestVersion: pkg.latest_release_number ?? null,
    latestReleaseAt: pkg.latest_release_published_at ?? null,
    repoUrl: pkg.repo_metadata?.html_url ?? pkg.repository_url ?? null,
    archived: Boolean(pkg.repo_metadata?.archived),
    lastPushAt: pkg.repo_metadata?.pushed_at ?? null,
    publishers: Array.isArray(pkg.maintainers) ? pkg.maintainers.length : null,
    ...(pkg.funding_links?.length ? { funding: [...new Set(pkg.funding_links)] } : {}),
    unpatchedAdvisories: advisories,
    priority,
  };
}
