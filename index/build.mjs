// Builds the Orphan Index: classifies the ecosyste.ms "critical" package set and writes
//   data/orphans.json      full dataset (every critical package)
//   data/orphans.min.json  non-active or vulnerable packages only, bundled with the CLI
//   data/orphans.csv       spreadsheet-friendly copy
//   data/stats.json        headline numbers
//   site/                  static website (index.html + data copy)
//
// Usage: npm run build && node index/build.mjs [--ecosystems npm,pypi] [--max-pages N] [--from-cache]
import { existsSync, mkdirSync, readFileSync, writeFileSync, copyFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { listCriticalPage, toOrphanRecord } from "../dist/index.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const { values } = parseArgs({
  options: {
    ecosystems: { type: "string", default: "npm,pypi" },
    "max-pages": { type: "string", default: "500" },
    "from-cache": { type: "boolean", default: false },
    "per-page": { type: "string", default: "100" },
  },
});

const ecosystems = values.ecosystems.split(",").map((s) => s.trim());
const maxPages = Number(values["max-pages"]);
const perPage = Number(values["per-page"]);
const cacheDir = join(root, "index", ".raw");
mkdirSync(cacheDir, { recursive: true });

const now = new Date();
const records = [];

for (const eco of ecosystems) {
  let total = 0;
  for (let page = 1; page <= maxPages; page++) {
    const cacheFile = join(cacheDir, `${eco}-${page}.json`);
    let slim;
    if (values["from-cache"] && existsSync(cacheFile)) {
      slim = JSON.parse(readFileSync(cacheFile, "utf8"));
    } else {
      const raw = await listCriticalPage(eco, page, perPage);
      // Keep only the fields Foster reads, so the cache stays small.
      slim = raw.map((p) => ({
        name: p.name,
        downloads: p.downloads,
        downloads_period: p.downloads_period,
        dependent_repos_count: p.dependent_repos_count,
        dependent_packages_count: p.dependent_packages_count,
        latest_release_number: p.latest_release_number,
        latest_release_published_at: p.latest_release_published_at,
        repository_url: p.repository_url,
        maintainers: Array.isArray(p.maintainers) ? p.maintainers.map(() => 1) : null,
        status: p.status,
        advisories: p.advisories,
        repo_metadata: p.repo_metadata
          ? { html_url: p.repo_metadata.html_url, archived: p.repo_metadata.archived, pushed_at: p.repo_metadata.pushed_at }
          : null,
        issue_metadata: p.issue_metadata
          ? {
              past_year_issues_count: p.issue_metadata.past_year_issues_count,
              past_year_pull_requests_count: p.issue_metadata.past_year_pull_requests_count,
              past_year_issues_closed_count: p.issue_metadata.past_year_issues_closed_count,
              past_year_pull_requests_closed_count: p.issue_metadata.past_year_pull_requests_closed_count,
              past_year_merged_pull_requests_count: p.issue_metadata.past_year_merged_pull_requests_count,
            }
          : null,
      }));
      writeFileSync(cacheFile, JSON.stringify(slim));
    }
    if (slim.length === 0) break;
    for (const p of slim) records.push(toOrphanRecord(p, eco, now));
    total += slim.length;
    process.stderr.write(`\r${eco}: ${total} packages (page ${page})   `);
    if (slim.length < perPage) break;
  }
  process.stderr.write("\n");
}

// De-duplicate (pagination can shift while the API updates).
const unique = [...new Map(records.map((r) => [`${r.ecosystem}:${r.name}`, r])).values()];
unique.sort((a, b) => b.priority - a.priority || (b.dependentRepos ?? 0) - (a.dependentRepos ?? 0));

const stats = buildStats(unique);
const dataDir = join(root, "data");
const siteDir = join(root, "site");
mkdirSync(dataDir, { recursive: true });
mkdirSync(join(siteDir, "data"), { recursive: true });

const meta = {
  version: 1,
  generatedAt: now.toISOString(),
  source: "ecosyste.ms critical package set (packages.ecosyste.ms), classified by Foster; see METHODOLOGY.md",
};
writeFileSync(join(dataDir, "orphans.json"), JSON.stringify({ ...meta, records: unique }, null, 1));
const min = unique.filter((r) => r.status !== "active" || r.unpatchedAdvisories.length > 0);
writeFileSync(join(dataDir, "orphans.min.json"), JSON.stringify({ ...meta, records: min }));
writeFileSync(join(dataDir, "orphans.csv"), toCsv(unique));
writeFileSync(join(dataDir, "stats.json"), JSON.stringify({ generatedAt: meta.generatedAt, ...stats }, null, 2));

for (const f of ["orphans.json", "orphans.csv", "stats.json"]) copyFileSync(join(dataDir, f), join(siteDir, "data", f));
const template = readFileSync(join(root, "index", "template.html"), "utf8");
writeFileSync(
  join(siteDir, "index.html"),
  template.replace("/*__STATS__*/null", JSON.stringify({ generatedAt: meta.generatedAt, ...stats })),
);

console.log(JSON.stringify(stats.totals, null, 2));
console.log(`wrote ${unique.length} records (${min.length} in the bundled min file)`);

function buildStats(rows) {
  const byEco = {};
  const totals = { packages: 0, active: 0, dormant: 0, dead: 0, unknown: 0, unmaintainedDownloadsPerMonth: 0, deadDownloadsPerMonth: 0, unmaintainedDependentRepos: 0, deadDependentRepos: 0, unpatchedAdvisories: 0, packagesWithUnpatchedAdvisories: 0, orphanedWithUnpatchedAdvisories: 0, singlePublisherUnmaintained: 0 };
  for (const r of rows) {
    const e = (byEco[r.ecosystem] ??= { packages: 0, active: 0, dormant: 0, dead: 0, unknown: 0 });
    e.packages++;
    e[r.status]++;
    totals.packages++;
    totals[r.status]++;
    const unmaintained = r.status === "dead" || r.status === "dormant";
    if (unmaintained) {
      totals.unmaintainedDownloadsPerMonth += r.downloadsLastMonth ?? 0;
      totals.unmaintainedDependentRepos += r.dependentRepos ?? 0;
      if (r.publishers === 1) totals.singlePublisherUnmaintained++;
    }
    if (r.status === "dead") {
      totals.deadDownloadsPerMonth += r.downloadsLastMonth ?? 0;
      totals.deadDependentRepos += r.dependentRepos ?? 0;
    }
    if (r.unpatchedAdvisories.length) {
      totals.unpatchedAdvisories += r.unpatchedAdvisories.length;
      totals.packagesWithUnpatchedAdvisories++;
      if (unmaintained) totals.orphanedWithUnpatchedAdvisories++;
    }
  }
  const top = rows
    .filter((r) => r.status !== "active")
    .slice(0, 25)
    .map((r) => ({ ecosystem: r.ecosystem, name: r.name, status: r.status, priority: r.priority, downloadsLastMonth: r.downloadsLastMonth, dependentRepos: r.dependentRepos, unpatched: r.unpatchedAdvisories.map((a) => a.id) }));
  return { totals, byEcosystem: byEco, top };
}

function toCsv(rows) {
  const cols = ["ecosystem", "name", "status", "priority", "downloadsLastMonth", "dependentRepos", "dependentPackages", "latestVersion", "latestReleaseAt", "lastPushAt", "archived", "publishers", "unpatchedAdvisories", "reasons", "repoUrl"];
  const esc = (v) => {
    const s = v === null || v === undefined ? "" : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [cols.join(",")];
  for (const r of rows) {
    lines.push(
      cols
        .map((c) => (c === "unpatchedAdvisories" ? r.unpatchedAdvisories.map((a) => a.id).join(" ") : c === "reasons" ? r.reasons.join("; ") : r[c]))
        .map(esc)
        .join(","),
    );
  }
  return lines.join("\n") + "\n";
}
