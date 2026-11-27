import semver from "semver";
import { fetchJson } from "./http.js";
import type { OrphanRecord } from "./types.js";

/**
 * Install-time code is how most npm malware runs: a `preinstall`/`install`/`postinstall` script
 * executes on `npm install`, before any of your code imports the package. Two patterns are worth a
 * second look before installing:
 *
 *  - a package first published a few weeks ago that runs an install script (typical of
 *    typosquats and slopsquats), and
 *  - a recent release that adds an install script the previous release did not have (typical of a
 *    hijacked maintainer account, as in the 2025 "Shai-Hulud" worm).
 *
 * Neither proves malice: native modules run install scripts too. Guard asks; it does not block.
 */

const REGISTRY = "https://registry.npmjs.org";
const LIFECYCLE = ["preinstall", "install", "postinstall"] as const;
const DAY = 24 * 60 * 60 * 1000;

/** A package younger than this is "brand new". */
export const NEW_PACKAGE_DAYS = 30;
/** A release younger than this that adds an install script is worth a look. */
export const RECENT_RELEASE_DAYS = 30;
/** Below this many dependent repositories, fetching the full (small) packument is cheap. */
const LOW_USAGE_REPOS = 500;

export interface NpmManifest {
  name?: string;
  version?: string;
  scripts?: Record<string, string>;
  gypfile?: boolean;
  hasInstallScript?: boolean;
}

interface Packument {
  "dist-tags"?: Record<string, string>;
  time?: Record<string, string>;
  versions?: Record<string, NpmManifest>;
}

export interface InstallRisk {
  version: string;
  /** Lifecycle scripts that run on install, with their commands: "postinstall: node bundle.js". */
  scripts: string[];
  pattern: "new-package" | "new-install-script";
  /** Days since the package was first published (new-package) or this release was published. */
  ageDays: number | null;
  /** The previous release, which had no install script (new-install-script). */
  previous?: string;
  reason: string;
}

export type FetchJson = <T>(url: string, opts?: { headers?: Record<string, string> }) => Promise<T>;

const defaultFetch: FetchJson = (url, opts) => fetchJson(url, { timeoutMs: 10_000, retries: 0, ...opts });

function pkgPath(name: string): string {
  return name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}

/** The install-time scripts a manifest declares. A binding.gyp (gypfile) implies `node-gyp rebuild`. */
export function installScripts(m: NpmManifest | undefined): string[] {
  if (!m) return [];
  const out: string[] = [];
  for (const k of LIFECYCLE) {
    const cmd = m.scripts?.[k];
    if (typeof cmd === "string" && cmd.trim()) out.push(`${k}: ${cmd.trim().length > 80 ? `${cmd.trim().slice(0, 77)}...` : cmd.trim()}`);
  }
  if (out.length === 0 && m.gypfile) out.push("install: node-gyp rebuild");
  return out;
}

function ageDays(iso: string | null | undefined, now: Date): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : Math.floor((now.getTime() - t) / DAY);
}

/** The release just before `version`, in semver order (prereleases only when `version` is one). */
export function previousVersion(versions: string[], version: string): string | undefined {
  const pre = semver.prerelease(version) !== null;
  return versions
    .filter((v) => semver.valid(v) && semver.lt(v, version) && (pre || semver.prerelease(v) === null))
    .sort(semver.rcompare)[0];
}

function plural(n: number | null, unit: string): string {
  if (n === null) return `recently`;
  if (n <= 0) return `today`;
  return `${n} ${unit}${n === 1 ? "" : "s"} ago`;
}

/**
 * Does installing this npm package run install-time code in a suspicious context? Returns null
 * when not (most packages: one small request for the version manifest).
 */
export async function npmInstallRisk(
  name: string,
  version: string | undefined,
  record: OrphanRecord | null,
  now: Date = new Date(),
  get: FetchJson = defaultFetch,
): Promise<InstallRisk | null> {
  const manifest = await get<NpmManifest>(`${REGISTRY}/${pkgPath(name)}/${version ? encodeURIComponent(version) : "latest"}`);
  const scripts = installScripts(manifest);
  const v = manifest.version ?? version;
  if (scripts.length === 0 || !v) return null;
  const label = `${name}@${v}`;
  const runs = `runs code on install (${scripts.join("; ")})`;

  const lowUsage = !record || (record.dependentRepos ?? 0) < LOW_USAGE_REPOS;
  if (lowUsage) {
    // Little-used packages have small packuments: the full one has publish times.
    const full = await get<Packument>(`${REGISTRY}/${pkgPath(name)}`);
    const created = ageDays(full.time?.created, now);
    if (created !== null && created <= NEW_PACKAGE_DAYS) {
      return {
        version: v,
        scripts,
        pattern: "new-package",
        ageDays: created,
        reason: `${label} was first published ${plural(created, "day")} and ${runs}. New packages that run install scripts are the usual shape of npm malware: read the script before installing.`,
      };
    }
    const published = ageDays(full.time?.[v], now);
    const prev = previousVersion(Object.keys(full.versions ?? {}), v);
    if (published !== null && published <= RECENT_RELEASE_DAYS && prev && installScripts(full.versions?.[prev]).length === 0) {
      return newScript(label, v, scripts, published, prev, runs);
    }
    return null;
  }

  // Widely used package: only a recent release is interesting. ecosyste.ms may not have seen a
  // brand-new release yet, so a version newer than the one it knows counts as recent.
  const known = record?.latestVersion ?? null;
  let published: number | null = null;
  if (known && v === known) {
    published = ageDays(record?.latestReleaseAt, now);
    if (published === null || published > RECENT_RELEASE_DAYS) return null;
  } else if (!(known && semver.valid(v) && semver.valid(known) && semver.gt(v, known))) {
    return null; // an older, pinned release: hijacked versions are pulled within days
  }
  // The abbreviated packument says, per release, whether it has an install script.
  const abbreviated = await get<Packument>(`${REGISTRY}/${pkgPath(name)}`, { headers: { Accept: "application/vnd.npm.install-v1+json" } });
  const prev = previousVersion(Object.keys(abbreviated.versions ?? {}), v);
  if (!prev || abbreviated.versions?.[prev]?.hasInstallScript) return null;
  return newScript(label, v, scripts, published, prev, runs);
}

function newScript(label: string, v: string, scripts: string[], published: number | null, prev: string, runs: string): InstallRisk {
  return {
    version: v,
    scripts,
    pattern: "new-install-script",
    ageDays: published,
    previous: prev,
    reason: `${label} (released ${plural(published, "day")}) ${runs}, and the previous release ${prev} did not. A new install script in a fresh release is how hijacked packages spread: check the release is genuine, or pin ${prev}.`,
  };
}

/**
 * The version npm would install for a range or dist-tag ("^4.1.0", "next"). The latest release
 * satisfies most ranges and needs no request; otherwise the abbreviated packument is read.
 */
export async function resolveNpmVersion(name: string, range: string, latestKnown: string | null, get: FetchJson = defaultFetch): Promise<string | undefined> {
  const valid = semver.validRange(range);
  if (latestKnown && valid && semver.satisfies(latestKnown, range)) return latestKnown;
  const doc = await get<Packument>(`${REGISTRY}/${pkgPath(name)}`, { headers: { Accept: "application/vnd.npm.install-v1+json" } });
  const tagged = doc["dist-tags"]?.[range];
  if (tagged) return tagged;
  if (!valid) return undefined;
  return semver.maxSatisfying(Object.keys(doc.versions ?? {}), range) ?? undefined;
}
