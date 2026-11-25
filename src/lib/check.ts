import { alternativesFor, type AlternativeSet } from "./replacements.js";
import { toOrphanRecord } from "./classify.js";
import { findPatch, indexKey, loadRegistry } from "./data.js";
import { getPackage } from "./ecosystems.js";
import { HttpError } from "./http.js";
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
