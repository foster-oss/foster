import { alternativesFor, type AlternativeSet } from "./replacements.js";
import { toOrphanRecord } from "./classify.js";
import { findPatch, indexKey, loadRegistry } from "./data.js";
import { getPackage } from "./ecosystems.js";
import { fetchJson, HttpError } from "./http.js";
import { malwareReports } from "./osv.js";
import { analyzeDependencies } from "./scan.js";
import type { Ecosystem, Finding, OrphanRecord, PatchEntry } from "./types.js";

export interface CheckResult {
  ecosystem: Ecosystem;
  name: string;
  version?: string;
  record: OrphanRecord | null;
  /** Findings for the given version (only when a version was supplied). */
  findings: Finding[];
  patch?: PatchEntry;
  notFound: boolean;
  /** Maintained replacements (npm only). */
  alternatives?: AlternativeSet;
}

/** Parse "name", "name@1.2.3" or "@scope/name@1.2.3". */
export function parseSpec(spec: string): { name: string; version?: string } {
  const at = spec.lastIndexOf("@");
  if (at > 0) return { name: spec.slice(0, at), version: spec.slice(at + 1) || undefined };
  return { name: spec };
}

/** Live check of one package: maintenance status, unpatched advisories and Foster patches. */
export async function checkPackage(ecosystem: Ecosystem, name: string, version?: string, opts: { includeStaged?: boolean } = {}): Promise<CheckResult> {
  let record: OrphanRecord | null = null;
  let notFound = false;
  try {
    record = toOrphanRecord(await getPackage(ecosystem, name), ecosystem);
  } catch (err) {
    if (err instanceof HttpError && err.status === 404) notFound = true;
    else throw err;
  }
  let findings: Finding[] = [];
  let patch: PatchEntry | undefined;
  if (version) {
    const dep = { ecosystem, name, version, direct: true, source: "cli" };
    const records = new Map(record ? [[indexKey(ecosystem, name), record] as const] : []);
    findings = await analyzeDependencies([dep], { includeStaged: opts.includeStaged, deep: false, records });
    patch = findPatch(await loadRegistry(), dep, opts.includeStaged);
  }
  return { ecosystem, name, version, record, findings, patch, notFound, alternatives: alternativesFor(ecosystem, name) };
}

/**
 * What `check` says about known malware: with no version a package check looks at the latest release
 * only, and a package taken down for malware (crossenv) or hijacked in a few releases (ua-parser-js)
 * would read as merely unmaintained. Asks OSV about the package as a whole; null when nothing is known
 * or the lookup fails (it fails open, like every other lookup).
 */
export async function malwareNotice(ecosystem: Ecosystem, name: string, version: string | undefined, findings: Finding[]): Promise<string | null> {
  if (findings.some((f) => f.kind === "malicious")) return null;
  const reports = await malwareReports(ecosystem, name, version).catch(() => []);
  if (reports.length === 0) return null;
  const list = reports.slice(0, 3).map((r) => `${r.id} (${r.url})`).join(", ");
  if (version || reports.some((r) => r.wholePackage))
    return `MALWARE: ${name}${version ? `@${version}` : ""} (${ecosystem}) is known malware: ${list}. Do not install it; if it is installed, remove it and rotate the credentials and tokens this machine holds.`;
  return `MALWARE: some releases of ${name} (${ecosystem}) were malicious: ${list}. Check the exact version before you install or keep it.`;
}

/**
 * Does this exact version exist on the registry? `check x@99.0.0` must not read as "no known
 * vulnerability" for a version nobody can install. null when the registry cannot say (or is not asked).
 */
export async function versionExists(ecosystem: Ecosystem, name: string, version: string): Promise<boolean | null> {
  const e = encodeURIComponent;
  const npmName = name.startsWith("@") ? `@${e(name.slice(1))}` : e(name);
  const url: Partial<Record<Ecosystem, string>> = {
    npm: `https://registry.npmjs.org/${npmName}/${e(version)}`,
    pypi: `https://pypi.org/pypi/${e(name)}/${e(version)}/json`,
    cargo: `https://crates.io/api/v1/crates/${e(name)}/${e(version)}`,
    rubygems: `https://rubygems.org/api/v2/rubygems/${e(name)}/versions/${e(version)}.json`,
    go: `https://proxy.golang.org/${name.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`)}/@v/${e(version)}.info`,
  };
  const target = url[ecosystem];
  if (!target || !/^[\w.+-]+$/.test(version)) return target ? false : null;
  try {
    await fetchJson(target, { timeoutMs: 10_000, retries: 1 });
    return true;
  } catch (err) {
    if (err instanceof HttpError && (err.status === 404 || err.status === 410)) return false;
    return null;
  }
}
