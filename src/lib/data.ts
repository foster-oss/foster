import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import semver from "semver";
import { fetchJson } from "./http.js";
import { normalizePyName } from "./osv.js";
import type { Dependency, Ecosystem, OrphanRecord, PatchEntry } from "./types.js";

/** Where the public copies live once the repository is published. Overridable for forks and tests. */
export const REMOTE_REGISTRY_URL =
  process.env.FOSTER_REGISTRY_URL ?? "https://raw.githubusercontent.com/foster-oss/foster/main/registry/patches.json";
export const REMOTE_INDEX_URL =
  process.env.FOSTER_INDEX_URL ?? "https://raw.githubusercontent.com/foster-oss/foster/main/data/orphans.min.json";

function packageFile(rel: string): string {
  // dist/lib/data.js and src/lib/data.ts are both two levels below the package root
  return fileURLToPath(new URL(`../../${rel}`, import.meta.url));
}

export interface PatchRegistry {
  version: 1;
  patches: PatchEntry[];
}

export interface OrphanIndexFile {
  version: 1;
  generatedAt: string;
  source: string;
  records: OrphanRecord[];
}

function readBundled<T>(rel: string): T | null {
  const path = packageFile(rel);
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

export interface LoadOptions {
  /** Skip the network and use only the copy bundled with this release. */
  offline?: boolean;
  /** Explicit local file to load instead of the bundled/remote copy. */
  file?: string;
}

async function load<T>(rel: string, remoteUrl: string, opts: LoadOptions, warnings: string[]): Promise<T | null> {
  if (opts.file) return JSON.parse(readFileSync(opts.file, "utf8")) as T;
  const bundled = readBundled<T>(rel);
  if (!opts.offline) {
    try {
      const remote = await fetchJson<T>(remoteUrl, { timeoutMs: 10_000, retries: 0 });
      // CDNs can serve a stale copy: never let an older remote file replace newer bundled data.
      const stamp = (x: unknown) => (x && typeof (x as { generatedAt?: unknown }).generatedAt === "string" ? Date.parse((x as { generatedAt: string }).generatedAt) : NaN);
      const r = stamp(remote);
      const b = stamp(bundled);
      if (!bundled || Number.isNaN(r) || Number.isNaN(b) || r >= b) return remote;
      return bundled;
    } catch {
      // Fall through to the bundled snapshot. Not a warning: offline use is expected.
    }
  }
  if (!bundled) warnings.push(`no ${rel} available`);
  return bundled;
}

export async function loadRegistry(opts: LoadOptions = {}, warnings: string[] = []): Promise<PatchRegistry> {
  return (await load<PatchRegistry>("registry/patches.json", REMOTE_REGISTRY_URL, opts, warnings)) ?? { version: 1, patches: [] };
}

export async function loadOrphanIndex(opts: LoadOptions = {}, warnings: string[] = []): Promise<OrphanIndexFile> {
  return (
    (await load<OrphanIndexFile>("data/orphans.min.json", REMOTE_INDEX_URL, opts, warnings)) ?? {
      version: 1,
      generatedAt: "",
      source: "none",
      records: [],
    }
  );
}

export function indexKey(ecosystem: Ecosystem, name: string): string {
  return `${ecosystem}:${ecosystem === "pypi" ? normalizePyName(name) : name}`;
}

export function indexByName(file: OrphanIndexFile): Map<string, OrphanRecord> {
  return new Map(file.records.map((r) => [indexKey(r.ecosystem, r.name), r]));
}

/** Find the patch that applies to this exact installed version. */
export function findPatch(registry: PatchRegistry, dep: Dependency, includeStaged = false): PatchEntry | undefined {
  return registry.patches.find((p) => {
    if (p.ecosystem !== dep.ecosystem) return false;
    if (indexKey(p.ecosystem, p.name) !== indexKey(dep.ecosystem, dep.name)) return false;
    if (p.status === "retired") return false;
    if (p.status === "staged" && !includeStaged) return false;
    if (dep.ecosystem === "npm") {
      return semver.valid(dep.version) !== null && semver.satisfies(dep.version, p.affected, { includePrerelease: true });
    }
    return p.affected.split("||").map((s) => s.trim()).includes(dep.version) || p.affected === "*";
  });
}
