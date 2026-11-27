// Builds the Orphan Index: classifies the ecosyste.ms "critical" package set and writes
//   data/orphans.json      full dataset (every critical package)
//   data/orphans.min.json  non-active or vulnerable packages only, bundled with the CLI
//   data/orphans.csv       spreadsheet-friendly copy
//   data/stats.json        headline numbers
//   site/                  static website (index.html + data copy)
//
// Usage: npm run build && node index/build.mjs [--ecosystems npm,pypi,cargo,go,rubygems,packagist] [--max-pages N] [--from-cache]
import { existsSync, mkdirSync, readFileSync, writeFileSync, copyFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { listCriticalPage, toOrphanRecord } from "../dist/index.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const { values } = parseArgs({
  options: {
    ecosystems: { type: "string", default: "npm,pypi,cargo,go,rubygems,packagist" },
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
        funding_links: [...new Set(p.funding_links ?? [])],
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

// Never overwrite good data with a partial pull (rate limit, outage, blocked user agent).
const minRecords = Number(process.env.FOSTER_MIN_RECORDS ?? 1000);
if (unique.length < minRecords && !values["max-pages"].startsWith("0") && Number(values["max-pages"]) >= 50) {
  console.error(`only ${unique.length} records fetched (expected at least ${minRecords}); refusing to write the index`);
  process.exit(1);
}

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

// What changed since the previous build: the weekly report and the Atom feed.
const previousPath = join(dataDir, "orphans.json");
const previous = existsSync(previousPath) ? JSON.parse(readFileSync(previousPath, "utf8")) : null;
// Same-day rebuilds (e.g. --from-cache) are not a new week: only compare across days.
const changes = previous && previous.generatedAt.slice(0, 10) !== meta.generatedAt.slice(0, 10) ? diffIndex(previous, unique, meta.generatedAt) : null;
const historyPath = join(dataDir, "history.json");
const history = existsSync(historyPath) ? JSON.parse(readFileSync(historyPath, "utf8")) : [];
if (changes) {
  const day = changes.date.slice(0, 10);
  const kept = history.filter((h) => h.date.slice(0, 10) !== day);
  kept.unshift(changes);
  history.length = 0;
  history.push(...kept.slice(0, 52));
}
writeFileSync(historyPath, JSON.stringify(history, null, 1));
writeFileSync(join(siteDir, "feed.xml"), atomFeed(history));

writeFileSync(join(dataDir, "orphans.json"), JSON.stringify({ ...meta, records: unique }, null, 1));
const min = unique.filter((r) => r.status !== "active" || r.unpatchedAdvisories.length > 0);
writeFileSync(join(dataDir, "orphans.min.json"), JSON.stringify({ ...meta, records: min }));
writeFileSync(join(dataDir, "orphans.csv"), toCsv(unique));
// Names people rely on, for look-alike (typosquat) detection in foster-oss guard.
const popular = {};
for (const r of unique) if ((r.dependentRepos ?? 0) >= 1000) (popular[r.ecosystem] ??= []).push([r.name, r.dependentRepos]);
for (const l of Object.values(popular)) l.sort((a, b) => b[1] - a[1]);
writeFileSync(join(dataDir, "popular.json"), JSON.stringify({ version: 1, generatedAt: meta.generatedAt, packages: popular }));
writeFileSync(join(dataDir, "stats.json"), JSON.stringify({ generatedAt: meta.generatedAt, ...stats }, null, 2));

for (const f of ["orphans.json", "orphans.csv", "stats.json", "history.json"]) copyFileSync(join(dataDir, f), join(siteDir, "data", f));
copyFileSync(join(root, "brand", "logo.svg"), join(siteDir, "logo.svg"));
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
  // Unmaintained packages many projects rely on, whose maintainers accept support: where money helps most.
  const fundable = rows
    .filter((r) => (r.status === "dead" || r.status === "dormant") && r.funding?.length)
    .sort((a, b) => (b.dependentRepos ?? 0) - (a.dependentRepos ?? 0))
    .slice(0, 30)
    .map((r) => ({ ecosystem: r.ecosystem, name: r.name, status: r.status, dependentRepos: r.dependentRepos, downloadsLastMonth: r.downloadsLastMonth, funding: r.funding, unpatched: r.unpatchedAdvisories.map((a) => a.id) }));
  totals.unmaintainedWithFunding = rows.filter((r) => (r.status === "dead" || r.status === "dormant") && r.funding?.length).length;
  const top = rows
    .filter((r) => r.status !== "active")
    .slice(0, 25)
    .map((r) => ({ ecosystem: r.ecosystem, name: r.name, status: r.status, priority: r.priority, downloadsLastMonth: r.downloadsLastMonth, dependentRepos: r.dependentRepos, unpatched: r.unpatchedAdvisories.map((a) => a.id) }));
  return { totals, byEcosystem: byEco, top, fundable };
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

function diffIndex(prev, rows, date) {
  const key = (r) => `${r.ecosystem}:${r.name}`;
  const before = new Map(prev.records.map((r) => [key(r), r]));
  const unmaintained = (s) => s === "dead" || s === "dormant";
  const brief = (r, extra = {}) => ({ ecosystem: r.ecosystem, name: r.name, status: r.status, dependentRepos: r.dependentRepos, downloadsLastMonth: r.downloadsLastMonth, ...extra });
  const byReach = (a, b) => (b.dependentRepos ?? 0) - (a.dependentRepos ?? 0);
  const newlyUnmaintained = [];
  const recovered = [];
  const newUnfixed = [];
  const resolvedUnfixed = [];
  for (const r of rows) {
    const p = before.get(key(r));
    if (!p) continue; // new to the critical set: not a change in maintenance
    if (unmaintained(r.status) && !unmaintained(p.status)) newlyUnmaintained.push(brief(r, { from: p.status, reasons: r.reasons }));
    if (!unmaintained(r.status) && unmaintained(p.status)) recovered.push(brief(r, { from: p.status }));
    const prevIds = new Set(p.unpatchedAdvisories.map((a) => a.id));
    const nowIds = new Set(r.unpatchedAdvisories.map((a) => a.id));
    const added = r.unpatchedAdvisories.filter((a) => !prevIds.has(a.id));
    const gone = p.unpatchedAdvisories.filter((a) => !nowIds.has(a.id));
    if (added.length) newUnfixed.push(brief(r, { advisories: added.map((a) => ({ id: a.id, severity: a.severity, title: a.title })) }));
    if (gone.length) resolvedUnfixed.push(brief(r, { advisories: gone.map((a) => a.id) }));
  }
  return {
    date,
    since: prev.generatedAt,
    newlyUnmaintained: newlyUnmaintained.sort(byReach).slice(0, 100),
    recovered: recovered.sort(byReach).slice(0, 100),
    newUnfixed: newUnfixed.sort(byReach),
    resolvedUnfixed: resolvedUnfixed.sort(byReach),
    counts: { newlyUnmaintained: newlyUnmaintained.length, recovered: recovered.length, newUnfixed: newUnfixed.length, resolvedUnfixed: resolvedUnfixed.length },
  };
}

function atomFeed(entries) {
  const site = "https://foster-oss.github.io/foster/";
  const x = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  const fmt = (n) => (n == null ? "?" : Intl.NumberFormat("en", { notation: "compact" }).format(n));
  const li = (r, tail = "") => `<li>${x(r.ecosystem)} <b>${x(r.name)}</b> (${fmt(r.dependentRepos)} dependent repos)${tail}</li>`;
  const items = entries.map((e) => {
    const c = e.counts;
    const title = `Orphan Index ${e.date.slice(0, 10)}: ${c.newlyUnmaintained} newly unmaintained, ${c.newUnfixed} with new unfixed advisories, ${c.recovered} maintained again`;
    const body = [
      e.newUnfixed.length ? `<h3>New advisories that no release fixes</h3><ul>${e.newUnfixed.map((r) => li(r, `: ${r.advisories.map((a) => `${x(a.id)} (${x(a.severity)})`).join(", ")}`)).join("")}</ul>` : "",
      e.newlyUnmaintained.length ? `<h3>Newly unmaintained</h3><ul>${e.newlyUnmaintained.slice(0, 30).map((r) => li(r, ` → ${x(r.status)}`)).join("")}</ul>` : "",
      e.recovered.length ? `<h3>Maintained again</h3><ul>${e.recovered.slice(0, 30).map((r) => li(r)).join("")}</ul>` : "",
      e.resolvedUnfixed.length ? `<h3>Advisories now fixed</h3><ul>${e.resolvedUnfixed.map((r) => li(r, `: ${r.advisories.map(x).join(", ")}`)).join("")}</ul>` : "",
    ].join("") || "<p>No changes this week.</p>";
    return `  <entry>
    <id>${site}#${e.date.slice(0, 10)}</id>
    <title>${x(title)}</title>
    <updated>${e.date}</updated>
    <link href="${site}"/>
    <content type="html">${x(body)}</content>
  </entry>`;
  });
  return `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>${site}</id>
  <title>Foster Orphan Index: weekly changes</title>
  <subtitle>Critical open source packages that became unmaintained, or gained security advisories no release fixes.</subtitle>
  <link href="${site}"/>
  <link rel="self" href="${site}feed.xml"/>
  <updated>${entries[0]?.date ?? new Date().toISOString()}</updated>
  <author><name>Foster</name></author>
${items.join("\n")}
</feed>
`;
}
