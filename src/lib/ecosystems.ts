import { fetchJson } from "./http.js";
import type { Ecosystem } from "./types.js";

const BASE = "https://packages.ecosyste.ms/api/v1";

const REGISTRY: Record<Ecosystem, string> = {
  npm: "npmjs.org",
  pypi: "pypi.org",
  cargo: "crates.io",
  go: "proxy.golang.org",
  rubygems: "rubygems.org",
  packagist: "packagist.org",
};

/** The subset of the ecosyste.ms package record that Foster relies on. */
export interface RawAdvisoryPackage {
  ecosystem?: string;
  package_name?: string;
  versions?: { first_patched_version?: string | null; vulnerable_version_range?: string | null }[];
}

export interface RawAdvisory {
  uuid?: string;
  url?: string;
  title?: string;
  severity?: string | null;
  classification?: string | null;
  withdrawn_at?: string | null;
  identifiers?: string[];
  packages?: RawAdvisoryPackage[];
}

export interface RawIssueMetadata {
  past_year_issues_count?: number | null;
  past_year_pull_requests_count?: number | null;
  past_year_issues_closed_count?: number | null;
  past_year_pull_requests_closed_count?: number | null;
  past_year_merged_pull_requests_count?: number | null;
}

export interface RawRepoMetadata {
  html_url?: string | null;
  archived?: boolean | null;
  pushed_at?: string | null;
}

export interface RawPackage {
  name: string;
  ecosystem?: string;
  downloads?: number | null;
  downloads_period?: string | null;
  dependent_repos_count?: number | null;
  dependent_packages_count?: number | null;
  latest_release_number?: string | null;
  latest_release_published_at?: string | null;
  repository_url?: string | null;
  maintainers?: unknown[] | null;
  funding_links?: string[] | null;
  status?: string | null;
  critical?: boolean | null;
  advisories?: RawAdvisory[] | null;
  repo_metadata?: RawRepoMetadata | null;
  issue_metadata?: RawIssueMetadata | null;
}

export async function getPackage(ecosystem: Ecosystem, name: string): Promise<RawPackage> {
  const url = `${BASE}/registries/${REGISTRY[ecosystem]}/packages/${encodeURIComponent(name)}`;
  return fetchJson<RawPackage>(url);
}

/** One page of the ecosyste.ms "critical" package set for a registry. Empty array when past the end. */
export async function listCriticalPage(ecosystem: Ecosystem, page: number, perPage = 100): Promise<RawPackage[]> {
  const url = `${BASE}/registries/${REGISTRY[ecosystem]}/packages?critical=true&per_page=${perPage}&page=${page}`;
  return fetchJson<RawPackage[]>(url, { timeoutMs: 120_000, retries: 4 });
}
