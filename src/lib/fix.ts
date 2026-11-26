import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import semver from "semver";
import { detectLockfiles, readDependencies, type NodeManager } from "./lockfile.js";
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
 * Point every dependency that has a released drop-in patch (Foster or another provider) at the patched package, using an npm alias
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
  const raw = readFileSync(pkgPath, "utf8");
  const hasBom = raw.charCodeAt(0) === 0xfeff;
  const original = hasBom ? raw.slice(1) : raw;
  const pkg = JSON.parse(original) as Json;

  // Every installed version of every npm package, so an override never reaches a copy that is not affected.
  const installed = new Map<string, Set<string>>();
  for (const lock of detectLockfiles(dir).filter((l) => l.ecosystem === "npm")) {
    for (const d of readDependencies(dir, lock)) {
      const set = installed.get(d.name) ?? new Set<string>();
      set.add(d.version);
      installed.set(d.name, set);
    }
  }

  const byName = new Map<string, Finding[]>();
  for (const f of npmPatchable) {
    const list = byName.get(f.dependency.name) ?? [];
    list.push(f);
    byName.set(f.dependency.name, list);
  }

  for (const [name, group] of byName) {
    for (const f of group) {
      const version = f.dependency.version;
      const target = `npm:${f.patch!.replacement.name}@${f.patch!.replacement.version}`;

      // A direct dependency is rewritten only where its declared range is what installed this exact version;
      // a safe "ip": "^3.0.0" must never be pointed back at a 2.x patch.
      const directFields = DEP_FIELDS.filter((field) => {
        const spec = (pkg[field] as Record<string, string> | undefined)?.[name];
        return spec !== undefined && semver.validRange(spec) !== null && semver.satisfies(version, spec, { includePrerelease: true });
      });
      if (directFields.length > 0) {
        for (const field of directFields) {
          const deps = pkg[field] as Record<string, string>;
          const from = deps[name];
          if (from === target) continue;
          deps[name] = target;
          result.changes.push({ package: name, field, key: name, from, to: target, applied: true });
        }
        continue;
      }

      const { field, obj } = overrideContainer(pkg, manager);
      let key = `${name}@${version}`;
      if (manager === "yarn") {
        // Yarn resolutions cannot target one resolved version, so only override when every installed copy is affected.
        const all = installed.get(name) ?? new Set([version]);
        const affected = new Set(group.map((g) => g.dependency.version));
        if ([...all].some((v) => !affected.has(v))) {
          result.skipped.push({ package: `${name}@${version}`, reason: "yarn resolutions would also replace unaffected copies of this package; fix by hand" });
          continue;
        }
        key = name;
      }
      const existing = (obj as Record<string, unknown>)[key];
      const existingValue = typeof existing === "object" && existing !== null ? (existing as Record<string, string>)["."] : (existing as string | undefined);
      if (existingValue === target) continue;
      if (existing !== undefined && !opts.force) {
        result.changes.push({ package: name, field, key, from: existingValue ?? JSON.stringify(existing), to: target, applied: false, note: "existing override kept; rerun with --force to replace it" });
        continue;
      }
      if (typeof existing === "object" && existing !== null) {
        // npm nested override: keep the child overrides, replace only the package itself.
        (existing as Record<string, string>)["."] = target;
      } else {
        obj[key] = target;
      }
      result.changes.push({ package: name, field, key, from: existingValue, to: target, applied: true });
      if (manager === "yarn") break; // one name-level resolution covers every copy
    }
  }

  const applied = result.changes.some((c) => c.applied);
  if (applied && !opts.dryRun) {
    writeFileSync(pkgPath, (hasBom ? "﻿" : "") + stringifyLike(original, pkg));
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
