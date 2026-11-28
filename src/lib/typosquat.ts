import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { fetchJson, HttpError, userAgent } from "./http.js";
import type { Ecosystem } from "./types.js";

/**
 * Look-alike detection: is a requested name one or two keystrokes away from a far more popular
 * package? Popularity comes from data/popular.json (the ecosyste.ms critical set, built with the
 * Orphan Index), so this works offline and across all six ecosystems.
 */

type PopularFile = { version: 1; generatedAt: string; packages: Partial<Record<Ecosystem, [string, number][]>> };

let popular: Map<Ecosystem, Map<string, number>> | null = null;

function loadPopular(): Map<Ecosystem, Map<string, number>> {
  if (popular) return popular;
  popular = new Map();
  const path = fileURLToPath(new URL("../../data/popular.json", import.meta.url));
  if (!existsSync(path)) return popular;
  try {
    const file = JSON.parse(readFileSync(path, "utf8")) as PopularFile;
    for (const [eco, list] of Object.entries(file.packages) as [Ecosystem, [string, number][]][]) {
      popular.set(eco, new Map(list.map(([n, d]) => [key(eco, n), d])));
    }
  } catch {
    // optional data
  }
  return popular;
}

function key(eco: Ecosystem, name: string): string {
  return eco === "pypi" ? name.toLowerCase().replace(/[-_.]+/g, "-") : eco === "packagist" ? name.toLowerCase() : name;
}

/** Optimal string alignment distance (Levenshtein plus adjacent transpositions). */
export function editDistance(a: string, b: string, max = 3): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array<number>(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) d[0]![j] = j;
  for (let i = 1; i <= a.length; i++) {
    let rowMin = Infinity;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, d[i - 2]![j - 2]! + 1);
      d[i]![j] = v;
      rowMin = Math.min(rowMin, v);
    }
    if (rowMin > max) return max + 1;
  }
  return d[a.length]![b.length]!;
}

export interface LookAlike {
  /** The popular package the name resembles. */
  name: string;
  dependentRepos: number;
  distance: number;
  /**
   * The name is a member of the popular package's family by its shape (aws-sdk-ecs next to aws-sdk-ecr):
   * a look-alike only when someone else publishes it. Settle it with samePublisher before reporting.
   */
  unlessSamePublisher?: boolean;
  /** Settled: shaped like a family member, but published by other accounts than the popular package. */
  otherPublisher?: boolean;
}

/** Names whose owner is part of the name itself: an npm scope, a Packagist vendor, a Go module path. */
function intrinsicOwner(ecosystem: Ecosystem, a: string, b: string): boolean {
  const head = (s: string, sep: string, n: number) => s.split(sep).slice(0, n).join(sep);
  if (ecosystem === "npm") return a.startsWith("@") && a.includes("/") && head(a, "/", 1) === head(b, "/", 1);
  if (ecosystem === "packagist") return head(a, "/", 1) === head(b, "/", 1);
  // github.com/owner/…, gopkg.in/yaml.v3: the host and owner (or gopkg.in's package) are the path's start
  if (ecosystem === "go") return head(a, "/", a.startsWith("gopkg.in/") ? 2 : 3).replace(/\.v\d+$/, "") === head(b, "/", b.startsWith("gopkg.in/") ? 2 : 3).replace(/\.v\d+$/, "");
  return false;
}

/** Who can publish a package: registry accounts, not the repository field anyone can copy. Null when unknown. */
const publisherCache = new Map<string, Promise<string[] | null>>();

export function publishers(ecosystem: Ecosystem, name: string): Promise<string[] | null> {
  const k = `${ecosystem}:${name}`;
  let p = publisherCache.get(k);
  if (!p) publisherCache.set(k, (p = readPublishers(ecosystem, name)));
  return p;
}

async function readPublishers(ecosystem: Ecosystem, name: string): Promise<string[] | null> {
  const enc = encodeURIComponent;
  try {
    if (ecosystem === "npm") {
      const doc = await fetchJson<{ maintainers?: { name?: string }[]; _npmUser?: { name?: string } }>(
        `https://registry.npmjs.org/${name.startsWith("@") ? `@${enc(name.slice(1))}` : enc(name)}/latest`,
        { timeoutMs: 10_000, retries: 1 },
      );
      const names = [...(doc.maintainers ?? []).map((m) => m.name), doc._npmUser?.name].filter((n): n is string => Boolean(n));
      return names.length ? names : null;
    }
    if (ecosystem === "pypi") {
      const doc = await fetchJson<{ ownership?: { organization?: string | null; roles?: { user?: string }[] } }>(`https://pypi.org/pypi/${enc(name)}/json`, { timeoutMs: 10_000, retries: 1 });
      const names = [...(doc.ownership?.roles ?? []).map((r) => r.user), doc.ownership?.organization ? `org:${doc.ownership.organization}` : undefined].filter((n): n is string => Boolean(n));
      return names.length ? names : null;
    }
    if (ecosystem === "cargo") {
      const doc = await fetchJson<{ users?: { login?: string }[] }>(`https://crates.io/api/v1/crates/${enc(name)}/owners`, { timeoutMs: 10_000, retries: 1 });
      const names = (doc.users ?? []).map((u) => u.login).filter((n): n is string => Boolean(n));
      return names.length ? names : null;
    }
    if (ecosystem === "rubygems") {
      const doc = await fetchJson<{ handle?: string; id?: number }[]>(`https://rubygems.org/api/v1/gems/${enc(name)}/owners.json`, { timeoutMs: 10_000, retries: 1 });
      const names = doc.map((o) => o.handle ?? (o.id !== undefined ? `id:${o.id}` : undefined)).filter((n): n is string => Boolean(n));
      return names.length ? names : null;
    }
  } catch {
    return null;
  }
  return null;
}

/**
 * Do two packages share a publisher? True or false when both are known; null when they cannot be read
 * (offline, a registry error, owners hidden).
 */
export async function samePublisher(ecosystem: Ecosystem, a: string, b: string, lookup = publishers, repos = repoOwner): Promise<boolean | null> {
  if (intrinsicOwner(ecosystem, a, b)) return true;
  const overlap = (x: string[], y: string[]) => {
    const theirs = new Set(y.map((n) => n.toLowerCase()));
    return x.some((n) => theirs.has(n.toLowerCase()));
  };
  const [x, y] = await Promise.all([lookup(ecosystem, a), lookup(ecosystem, b)]);
  if (x && y) return overlap(x, y);
  // RubyGems hides the owners of organisation gems (aws-sdk-*): fall back to the repository's owner
  const [p, q] = await Promise.all([repos(ecosystem, a), repos(ecosystem, b)]);
  return p && q ? p === q : null;
}

/** The GitHub/GitLab owner of a package's source repository, from its registry metadata. Null when unknown. */
export async function repoOwner(ecosystem: Ecosystem, name: string): Promise<string | null> {
  if (ecosystem !== "rubygems") return null;
  try {
    const doc = await fetchJson<{ source_code_uri?: string | null; homepage_uri?: string | null }>(`https://rubygems.org/api/v1/gems/${encodeURIComponent(name)}.json`, { timeoutMs: 10_000, retries: 1 });
    for (const url of [doc.source_code_uri, doc.homepage_uri]) {
      const m = /^https?:\/\/(?:www\.)?(?:github|gitlab)\.com\/([^/]+)\/[^/]+/i.exec(url ?? "");
      if (m) return m[1]!.toLowerCase();
    }
  } catch {
    // unknown
  }
  return null;
}

/** Popular names that need to be at least this widely used to be "impersonated". */
const MIN_TARGET_REPOS = 1000;
/** A look-alike name already used by this many repositories is treated as legitimate. */
const OWN_REPOS_TRUSTED = 1000;
/** A look-alike name downloaded this often per month is treated as legitimate. */
const DOWNLOADS_TRUSTED = 100_000;

/**
 * Siblings in one family of packages, not a typo of each other: serde_core / serde_cbor, aws-sdk-sts /
 * aws-sdk-s3. Same words up to the last separator, and the last words are different words (not one
 * word with a letter swapped): a squat changes a letter, a family adds a member.
 */
function sameFamily(a: string, b: string): "words" | "codes" | null {
  const split = (s: string) => {
    const i = Math.max(s.lastIndexOf("-"), s.lastIndexOf("_"), s.lastIndexOf("."));
    return i > 0 ? [s.slice(0, i + 1), s.slice(i + 1)] as const : null;
  };
  const x = split(a);
  const y = split(b);
  if (!x || !y || x[0] !== y[0] || x[1].length < 2 || y[1].length < 2) return null;
  // SDK families name members with short codes (aws-sdk-sts, aws-sdk-sns, aws-sdk-s3): one letter apart,
  // still siblings, but one letter is also what a typo changes, so these count only from the same publisher
  if ((x[0].match(/[-_.]/g)?.length ?? 0) >= 2 && x[0].length >= 8 && x[1].length <= 3 && y[1].length <= 3) return "codes";
  return editDistance(x[1], y[1], 2) >= 2 ? "words" : null;
}

/**
 * The popular package `name` most likely imitates, or undefined. `ownRepos` is the requested
 * package's own dependent-repo count when known: a name that is itself widely used is not a squat.
 */
export function lookAlike(ecosystem: Ecosystem, name: string, ownRepos?: number | null, ownDownloads?: number | null): LookAlike | undefined {
  // Dependent-repo counts lag for packages that are new but huge (call-bound, get-proto: a billion
  // downloads a month, "0 dependent repos"). Downloads at this level are not a squat.
  if (ownDownloads !== undefined && ownDownloads !== null && ownDownloads >= DOWNLOADS_TRUSTED) return undefined;
  const list = loadPopular().get(ecosystem);
  if (!list) return undefined;
  const k = key(ecosystem, name);
  if (list.has(k)) return undefined; // it is one of the popular packages itself
  // Compare the last path segment for scoped/vendored names too ("@evil/lodash" vs "lodash" is out of scope here).
  if (k.length < 4) return undefined; // very short names collide by chance
  const maxDist = k.length >= 8 ? 2 : 1;
  let best: LookAlike | undefined;
  let sibling: LookAlike | undefined;
  for (const [candidate, repos] of list) {
    if (repos < MIN_TARGET_REPOS) continue;
    if (Math.abs(candidate.length - k.length) > maxDist) continue;
    const dist = editDistance(k, candidate, maxDist);
    if (dist > maxDist) continue;
    const family = sameFamily(k, candidate);
    if (family === "words") continue;
    if (family === "codes") {
      // a member of the same family only if the same people publish it: see samePublisher
      if (!intrinsicOwner(ecosystem, k, candidate) && (!sibling || repos > sibling.dependentRepos)) sibling = { name: candidate, dependentRepos: repos, distance: dist, unlessSamePublisher: true };
      continue;
    }
    // separator-only differences ("lodash.merge" vs "lodash-merge") are a classic trick too
    if (!best || repos > best.dependentRepos) best = { name: candidate, dependentRepos: repos, distance: dist };
  }
  best ??= sibling;
  if (!best) return undefined;
  // A package many projects already use is a real package with a similar name (preact/react,
  // vuex/vue, ulid/uuid), not a squat. Squats typically have a handful of dependents.
  if (ownRepos !== undefined && ownRepos !== null && (ownRepos >= OWN_REPOS_TRUSTED || ownRepos * 100 >= best.dependentRepos)) return undefined;
  return best;
}

// ---------------------------------------------------------------- Foster's own name

/** Foster itself is published once: "foster-oss" on npm. */
export const FOSTER_PACKAGE = "foster-oss";
const FOSTER_FLAT = "fosteross";
const FOSTER_SUFFIXES = ["", "cli", "guard", "mcp", "skill", "ai", "js", "node", "bin", "app", "agent", "check", "scan"];

/**
 * Does a name pose as Foster? A security tool is installed on trust, so its look-alikes are worth a
 * squatter's while long before Foster is popular enough for the popularity-based check above to see
 * them: foster-os, fostre-oss, foster-oss-cli, @foster-oss/guard, and foster-oss on any other registry.
 */
export function impersonatesFoster(ecosystem: Ecosystem, name: string): boolean {
  const lower = name.toLowerCase();
  if (ecosystem === "npm" && name === FOSTER_PACKAGE) return false;
  const flat = (s: string) => s.replace(/[-_.\s]+/g, "");
  const parts = lower.startsWith("@") && lower.includes("/") ? [lower.slice(1, lower.indexOf("/")), lower.slice(lower.indexOf("/") + 1)] : [lower];
  // the last path element too: github.com/x/foster-oss, vendor/foster-oss
  parts.push(lower.split("/").pop()!);
  return parts.some((p) => {
    const f = flat(p);
    if (f.length < 6) return false;
    if (editDistance(f, FOSTER_FLAT, 2) <= 2) return true;
    for (const base of [FOSTER_FLAT, "foster"]) {
      if (f.startsWith(base) && FOSTER_SUFFIXES.includes(f.slice(base.length)) && !(base === "foster" && f === "foster" && ecosystem !== "npm")) return true;
    }
    return false;
  });
}

/** What guard and check say about a name that poses as Foster. */
export function fosterImpostorMessage(ecosystem: Ecosystem, name: string): string {
  return `${name} (${ecosystem}) is not Foster. Foster is published only as "${FOSTER_PACKAGE}" on npm, from github.com/foster-oss/foster; look-alike names of a security tool are an easy way to slip in malware. Install it only if this is really the package you want.`;
}

// ---------------------------------------------------------------- does it exist at all?

/**
 * Ask the real registry whether a name exists. ecosyste.ms can lag behind brand-new packages, so a
 * "not found" there is confirmed here before calling a name hallucinated. Returns null when unsure.
 */
export async function existsOnRegistry(ecosystem: Ecosystem, name: string): Promise<boolean | null> {
  const enc = encodeURIComponent;
  const url: Record<Ecosystem, string> = {
    npm: `https://registry.npmjs.org/${name.startsWith("@") ? `@${enc(name.slice(1))}` : enc(name)}`,
    pypi: `https://pypi.org/pypi/${enc(name)}/json`,
    cargo: `https://crates.io/api/v1/crates/${enc(name)}`,
    // the module proxy writes capitals as "!" plus the lower-case letter (github.com/!burnt!sushi/toml)
    go: `https://proxy.golang.org/${name.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`)}/@v/list`,
    rubygems: `https://rubygems.org/api/v1/gems/${enc(name)}.json`,
    packagist: `https://repo.packagist.org/p2/${name.toLowerCase()}.json`,
  };
  try {
    if (ecosystem === "go") {
      const res = await fetch(url.go, { headers: { "User-Agent": userAgent() }, signal: AbortSignal.timeout(10_000) });
      if (res.status === 404 || res.status === 410) return false;
      return res.ok ? true : null;
    }
    await fetchJson(url[ecosystem], { timeoutMs: 10_000, retries: 1 });
    return true;
  } catch (err) {
    if (err instanceof HttpError && (err.status === 404 || err.status === 410)) return false;
    return null;
  }
}
