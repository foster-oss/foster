import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { detectLockfiles, type NodeManager } from "./lockfile.js";
import type { Finding } from "./types.js";

const DEP_FIELDS = ["dependencies", "devDependencies", "optionalDependencies"] as const;

export interface FixChange {
  package: string;
  /** Where the change goes: a dependency field, or the manager's override field. */
  field: string;
  key: string;
  from?: string;
  to: string;
  applied: boolean;
  note?: string;
}

export interface FixResult {
  dir: string;
  manager: NodeManager | null;
  changes: FixChange[];
  skipped: { package: string; reason: string }[];
  written: boolean;
}

export interface FixOptions {
  dryRun?: boolean;
  /** Replace an existing, different override for the same package. */
  force?: boolean;
}

export function detectManager(dir: string): NodeManager | null {
  const locks = detectLockfiles(dir);
  for (const m of ["pnpm", "yarn", "npm"] as const) {
    if (locks.some((l) => l.manager === m)) return m;
  }
  return existsSync(join(dir, "package.json")) ? "npm" : null;
}

type Json = Record<string, unknown>;

function overrideContainer(pkg: Json, manager: NodeManager): { field: string; obj: Record<string, string> } {
  if (manager === "pnpm") {
    const pnpm = (pkg.pnpm ??= {}) as Json;
    return { field: "pnpm.overrides", obj: (pnpm.overrides ??= {}) as Record<string, string> };
  }
  if (manager === "yarn") return { field: "resolutions", obj: (pkg.resolutions ??= {}) as Record<string, string> };
  return { field: "overrides", obj: (pkg.overrides ??= {}) as Record<string, string> };
}

/**
 * Point every dependency that has a released Foster patch at the patched package, using an npm alias
 * ("npm:@foster-oss/ip@2.0.1-foster.1"). Code keeps importing the original name; only the bytes change.
 * Direct dependencies are rewritten in place (npm rejects overrides that conflict with direct deps);
 * transitive ones get an override/resolution entry.
 */
export function applyFixes(dirInput: string, findings: Finding[], opts: FixOptions = {}): FixResult {
  const dir = resolve(dirInput);
  const manager = detectManager(dir);
  const result: FixResult = { dir, manager, changes: [], skipped: [], written: false };
  const patchable = findings.filter((f) => f.kind === "patch-available" && f.patch);

  for (const f of patchable) {
    if (f.dependency.ecosystem !== "npm") {
      result.skipped.push({
        package: `${f.dependency.name}@${f.dependency.version}`,
        reason: "automatic fixes are npm-only for now; see the patch folder for manual pip/uv instructions",
      });
    }
  }
  const npmPatchable = patchable.filter((f) => f.dependency.ecosystem === "npm");
  if (npmPatchable.length === 0) return result;
  if (!manager) {
    result.skipped.push({ package: "*", reason: "no package.json found" });
    return result;
  }

  const pkgPath = join(dir, "package.json");
  const original = readFileSync(pkgPath, "utf8");
  const pkg = JSON.parse(original) as Json;

  // Group installed versions per package so we know whether one override covers all of them.
  const byName = new Map<string, Finding[]>();
  for (const f of npmPatchable) {
    const list = byName.get(f.dependency.name) ?? [];
    list.push(f);
    byName.set(f.dependency.name, list);
  }

  for (const [name, group] of byName) {
    const patches = new Map(group.map((f) => [`${f.patch!.replacement.name}@${f.patch!.replacement.version}`, f]));
    if (patches.size > 1) {
      result.skipped.push({ package: name, reason: "several installed versions map to different Foster patches; fix by hand" });
      continue;
    }
    const first = group[0]!;
    const target = `npm:${first.patch!.replacement.name}@${first.patch!.replacement.version}`;

    const directField = DEP_FIELDS.find((field) => (pkg[field] as Record<string, string> | undefined)?.[name] !== undefined);
    if (directField) {
      const deps = pkg[directField] as Record<string, string>;
      const from = deps[name];
      if (from === target) continue;
      deps[name] = target;
      result.changes.push({ package: name, field: directField, key: name, from, to: target, applied: true });
      continue;
    }

    const { field, obj } = overrideContainer(pkg, manager);
    const keys =
      manager === "yarn" || group.length === 1 ? [name] : group.map((f) => `${name}@${f.dependency.version}`);
    for (const key of keys) {
      const existing = obj[key];
      if (existing === target) continue;
      if (existing !== undefined && !opts.force) {
        result.changes.push({ package: name, field, key, from: existing, to: target, applied: false, note: "existing override kept; rerun with --force to replace it" });
        continue;
      }
      obj[key] = target;
      result.changes.push({ package: name, field, key, from: existing, to: target, applied: true });
    }
  }

  const applied = result.changes.some((c) => c.applied);
  if (applied && !opts.dryRun) {
    writeFileSync(pkgPath, stringifyLike(original, pkg));
    result.written = true;
  }
  return result;
}

/** Re-serialise JSON keeping the original indentation and trailing newline. */
export function stringifyLike(original: string, value: unknown): string {
  const indentMatch = original.match(/^[ \t]+(?=")/m);
  const indent = indentMatch ? indentMatch[0] : "  ";
  const eol = original.includes("\r\n") ? "\r\n" : "\n";
  let out = JSON.stringify(value, null, indent);
  if (eol === "\r\n") out = out.replace(/\n/g, "\r\n");
  return original.endsWith("\n") ? out + eol : out;
}

export function installCommand(manager: NodeManager | null): string {
  switch (manager) {
    case "pnpm":
      return "pnpm install";
    case "yarn":
      return "yarn install";
    default:
      return "npm install";
  }
}
