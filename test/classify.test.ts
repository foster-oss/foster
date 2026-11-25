import { describe, expect, it } from "vitest";
import { classify, maxSeverity, toOrphanRecord, unpatchedAdvisories } from "../src/lib/classify.js";
import type { RawPackage } from "../src/lib/ecosystems.js";

const NOW = new Date("2026-11-26T00:00:00Z");
const daysAgo = (d: number) => new Date(NOW.getTime() - d * 86_400_000).toISOString();

function pkg(over: Partial<RawPackage> = {}): RawPackage {
  return {
    name: "thing",
    downloads: 1_000_000,
    downloads_period: "last-month",
    dependent_repos_count: 5000,
    dependent_packages_count: 100,
    latest_release_number: "1.0.0",
    latest_release_published_at: daysAgo(30),
    repo_metadata: { html_url: "https://github.com/x/thing", archived: false, pushed_at: daysAgo(10) },
    issue_metadata: {
      past_year_issues_count: 4,
      past_year_pull_requests_count: 2,
      past_year_issues_closed_count: 3,
      past_year_pull_requests_closed_count: 2,
      past_year_merged_pull_requests_count: 1,
    },
    ...over,
  };
}

describe("classify", () => {
  it("calls a recently released package active", () => {
    expect(classify(pkg(), NOW).status).toBe("active");
  });

  it("calls an archived repository dead", () => {
    const r = classify(pkg({ repo_metadata: { archived: true, pushed_at: daysAgo(10) } }), NOW);
    expect(r.status).toBe("dead");
    expect(r.reasons[0]).toMatch(/archived/);
  });

  it("calls a package dead when issues pile up with no response and no activity", () => {
    const r = classify(
      pkg({
        latest_release_published_at: daysAgo(900),
        repo_metadata: { archived: false, pushed_at: daysAgo(800) },
        issue_metadata: { past_year_issues_count: 5, past_year_pull_requests_count: 3, past_year_issues_closed_count: 0, past_year_pull_requests_closed_count: 0, past_year_merged_pull_requests_count: 0 },
      }),
      NOW,
    );
    expect(r.status).toBe("dead");
  });

  it("calls a quiet but not ignored package dormant", () => {
    const r = classify(
      pkg({
        latest_release_published_at: daysAgo(900),
        repo_metadata: { archived: false, pushed_at: daysAgo(500) },
        issue_metadata: { past_year_issues_count: 0, past_year_pull_requests_count: 0 },
      }),
      NOW,
    );
    expect(r.status).toBe("dormant");
    expect(r.reasons.join(" ")).toMatch(/no release/);
  });

  it("does not call a package dead if someone pushed recently", () => {
    const r = classify(
      pkg({
        latest_release_published_at: daysAgo(900),
        repo_metadata: { archived: false, pushed_at: daysAgo(20) },
        issue_metadata: { past_year_issues_count: 5, past_year_issues_closed_count: 0, past_year_merged_pull_requests_count: 0 },
      }),
      NOW,
    );
    expect(r.status).toBe("active");
  });

  it("returns unknown without a linked repository and a recent release", () => {
    expect(classify(pkg({ repo_metadata: null }), NOW).status).toBe("unknown");
  });

  it("treats registry-deprecated packages as dead", () => {
    expect(classify(pkg({ status: "deprecated" }), NOW).status).toBe("dead");
  });
});

describe("unpatchedAdvisories", () => {
  const advisories: RawPackage["advisories"] = [
    {
      url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
      title: "SSRF in isPublic",
      severity: "HIGH",
      identifiers: ["GHSA-aaaa-bbbb-cccc", "CVE-2024-1"],
      packages: [{ ecosystem: "npm", package_name: "thing", versions: [{ first_patched_version: null, vulnerable_version_range: "<= 2.0.1" }] }],
    },
    {
      url: "https://github.com/advisories/GHSA-fixd-fixd-fixd",
      severity: "CRITICAL",
      packages: [{ ecosystem: "npm", package_name: "thing", versions: [{ first_patched_version: "1.0.1", vulnerable_version_range: "< 1.0.1" }] }],
    },
    {
      url: "https://github.com/advisories/GHSA-with-draw-nnnn",
      severity: "HIGH",
      withdrawn_at: "2024-01-01",
      packages: [{ ecosystem: "npm", package_name: "thing", versions: [{ first_patched_version: null }] }],
    },
    {
      url: "https://github.com/advisories/GHSA-malw-aree-xxxx",
      severity: "CRITICAL",
      classification: "MALWARE",
      packages: [{ ecosystem: "npm", package_name: "thing", versions: [{ first_patched_version: null }] }],
    },
    {
      url: "https://github.com/advisories/GHSA-othe-rpkg-yyyy",
      severity: "LOW",
      packages: [{ ecosystem: "npm", package_name: "other", versions: [{ first_patched_version: null }] }],
    },
  ];

  it("keeps only live, non-malware advisories with no patched version for this package", () => {
    const out = unpatchedAdvisories(pkg({ advisories }), "npm");
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ id: "GHSA-aaaa-bbbb-cccc", severity: "HIGH", range: "<= 2.0.1" });
  });

  it("ranks vulnerable unmaintained packages above quiet ones", () => {
    const quiet = toOrphanRecord(pkg({ latest_release_published_at: daysAgo(900), repo_metadata: { pushed_at: daysAgo(900) } }), "npm", NOW);
    const vulnerable = toOrphanRecord(pkg({ latest_release_published_at: daysAgo(900), repo_metadata: { pushed_at: daysAgo(900) }, advisories }), "npm", NOW);
    expect(vulnerable.priority).toBeGreaterThan(quiet.priority);
    expect(toOrphanRecord(pkg(), "npm", NOW).priority).toBe(0);
  });
});

describe("maxSeverity", () => {
  it("picks the most severe", () => {
    expect(maxSeverity([{ severity: "LOW" }, { severity: "CRITICAL" }, { severity: "HIGH" }])).toBe("CRITICAL");
    expect(maxSeverity([{ severity: "UNKNOWN" }, { severity: "LOW" }])).toBe("LOW");
    expect(maxSeverity([])).toBe("UNKNOWN");
  });
});
