import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import semver from "semver";
import { isAlias, isCollection, isMap, isScalar, parseDocument, Scalar, visit, type YAMLMap } from "yaml";
import { detectLockfiles, readDependencies, type NodeManager } from "./lockfile.js";
import type { Finding } from "./types.js";

const DEP_FIELDS = ["dependencies", "devDependencies", "optionalDependencies"] as const;

export interface FixChange {
  package: string;
  /** Where the change goes: a dependency field, or the manager's override field. */
  field: string;
  /** Omitted for package.json, for compatibility with existing consumers. */
  file?: string;
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

interface OverrideContainer {
  field: string;
  file?: string;
  get(key: string): unknown;
  set(key: string, value: string): void;
  stringify?(): string;
}

function overrideContainer(pkg: Json, manager: NodeManager, dir: string): OverrideContainer {
  const file = "pnpm-workspace.yaml";
  if (manager === "pnpm" && existsSync(join(dir, file))) {
    const raw = readFileSync(join(dir, file), "utf8");
    const original = raw.replace(/^\uFEFF/, "");
    const doc = parseDocument(original, { merge: true });
    if (doc.errors.length) throw new Error(`${file}: ${doc.errors[0]!.message}`);
    // pnpm reads resolved YAML values, including aliases and merge keys.
    const configuration = () => {
      try {
        return doc.toJS({ mapAsMap: true });
      } catch (error) {
        throw new Error(`${file}: ${error instanceof Error ? error.message : String(error)}`);
      }
    };
    const config = configuration();
    if (config instanceof Map && config.has("overrides")) {
      const effectiveOverrides = (): Map<unknown, unknown> => {
        const values = configuration().get("overrides");
        if (!(values instanceof Map)) throw new Error(`${file}: overrides must be a mapping`);
        return values;
      };
      effectiveOverrides();
      const keyNode = (map: YAMLMap | undefined, key: string) => {
        const matches = map?.items.filter((pair) => {
          const node = isAlias(pair.key) ? pair.key.resolve(doc) : pair.key;
          return (isScalar(node) ? node.value : node) === key;
        }) ?? [];
        if (matches.length > 1) throw new Error(`${file}: duplicate override ${key}`);
        return matches[0]?.key ?? key;
      };
      const rootKey = keyNode(isMap(doc.contents) ? doc.contents : undefined, "overrides");
      const source = doc.get(rootKey, true);
      let overrides = isMap(source) ? source : undefined;
      let flowCollectionPadding = true;
      visit(doc, (_, node) => {
        if (isCollection(node) && node.flow && node.range) {
          flowCollectionPadding = /\s/.test(original[node.range[0] + 1] ?? "");
          return visit.BREAK;
        }
      });
      return {
        field: "overrides", file,
        get: (key) => {
          keyNode(overrides, key); // reject ambiguous explicit selectors before considering a replacement
          const values = effectiveOverrides();
          if (!values.has(key)) return undefined;
          const value = values.get(key);
          if (typeof value !== "string") throw new Error(`${file}: override ${key} must be a string`);
          return value;
        },
        set: (key, value) => {
          if (!overrides) {
            // Materialise inherited values locally, leaving defaults and their other consumers intact.
            overrides = doc.createNode(effectiveOverrides());
            if (isAlias(source)) {
              overrides.comment = source.comment;
              overrides.commentBefore = source.commentBefore;
              overrides.spaceBefore = source.spaceBefore;
            }
            doc.set(rootKey, overrides);
          }
          const selectedKey = keyNode(overrides, key);
          const node = overrides.get(selectedKey, true);
          // Editing an anchor also changes its aliases, possibly outside overrides.
          visit(doc, (_, alias) => {
            if (isAlias(alias) && (alias.resolve(doc) === overrides || (node && alias.resolve(doc) === node))) {
              throw new Error(`${file}: override ${key} uses a shared YAML anchor; edit it manually`);
            }
          });
          if (isAlias(node)) {
            const replacement = new Scalar(value);
            replacement.comment = node.comment;
            replacement.commentBefore = node.commentBefore;
            replacement.spaceBefore = node.spaceBefore;
            overrides.set(selectedKey, replacement);
          } else overrides.set(selectedKey, value);
        },
        stringify: () => {
          const indent = original.match(/^( +)\S/m)?.[1]?.length ?? 2;
          let out = doc.toString({ indent, indentSeq: !/^- /m.test(original), lineWidth: 0, flowCollectionPadding });
          if (!original.endsWith("\n")) out = out.replace(/\n$/, "");
          if (original.includes("\r\n")) out = out.replace(/\n/g, "\r\n");
          return (raw.startsWith("\uFEFF") ? "\uFEFF" : "") + out;
        },
      };
    }
  }

  let field: string;
  let obj: Json;
  if (manager === "pnpm") {
    const pnpm = (pkg.pnpm ??= {}) as Json;
    field = "pnpm.overrides";
    obj = (pnpm.overrides ??= {}) as Json;
  } else {
    field = manager === "yarn" ? "resolutions" : "overrides";
    obj = (pkg[field] ??= {}) as Json;
  }
  return {
    field,
    get: (key) => obj[key],
    set: (key, value) => {
      const existing = obj[key];
      if (typeof existing === "object" && existing !== null) {
        // npm nested override: keep the child overrides, replace only the package itself.
        (existing as Json)["."] = value;
      } else obj[key] = value;
    },
  };
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

  // Resolve the override destination only if a transitive fix needs it. Direct fixes stay in package.json.
  let overrides: OverrideContainer | undefined;

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

      overrides ??= overrideContainer(pkg, manager, dir);
      const { field, file } = overrides;
      const location = file ? { file } : {};
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
      const existing = overrides.get(key);
      const existingValue = typeof existing === "object" && existing !== null ? (existing as Record<string, string>)["."] : (existing as string | undefined);
      if (existingValue === target) continue;
      if (existing !== undefined && !opts.force) {
        result.changes.push({ package: name, field, ...location, key, from: existingValue ?? JSON.stringify(existing), to: target, applied: false, note: "existing override kept; rerun with --force to replace it" });
        continue;
      }
      overrides.set(key, target);
      result.changes.push({ package: name, field, ...location, key, from: existingValue, to: target, applied: true });
      if (manager === "yarn") break; // one name-level resolution covers every copy
    }
  }

  const files = new Set(result.changes.filter((c) => c.applied).map((c) => c.file ?? "package.json"));
  if (files.size && !opts.dryRun) {
    // Serialise every changed document before writing, so a YAML error cannot leave a partial fix.
    const writes = [...files].map((file) => [
      join(dir, file),
      file === "package.json" ? (hasBom ? "﻿" : "") + stringifyLike(original, pkg) : overrides!.stringify!(),
    ] as const);
    for (const [path, content] of writes) writeFileSync(path, content);
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
