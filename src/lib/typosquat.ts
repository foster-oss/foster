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
}

/** Popular names that need to be at least this widely used to be "impersonated". */
const MIN_TARGET_REPOS = 1000;
/** A look-alike name already used by this many repositories is treated as legitimate. */
const OWN_REPOS_TRUSTED = 1000;
/** A look-alike name downloaded this often per month is treated as legitimate. */
const DOWNLOADS_TRUSTED = 100_000;

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
  for (const [candidate, repos] of list) {
    if (repos < MIN_TARGET_REPOS) continue;
    if (Math.abs(candidate.length - k.length) > maxDist) continue;
    const dist = editDistance(k, candidate, maxDist);
    if (dist > maxDist) continue;
    // separator-only differences ("lodash.merge" vs "lodash-merge") are a classic trick too
    if (!best || repos > best.dependentRepos) best = { name: candidate, dependentRepos: repos, distance: dist };
  }
  if (!best) return undefined;
  // A package many projects already use is a real package with a similar name (preact/react,
  // vuex/vue, ulid/uuid), not a squat. Squats typically have a handful of dependents.
  if (ownRepos !== undefined && ownRepos !== null && (ownRepos >= OWN_REPOS_TRUSTED || ownRepos * 100 >= best.dependentRepos)) return undefined;
  return best;
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
