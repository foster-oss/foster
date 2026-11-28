import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { Ecosystem } from "./types.js";

/**
 * Packages a project's people have looked at and accept: internal packages on a private registry,
 * a look-alike name that really is the one they mean. Listed in `.foster.json` ({"allow": [...]}) in the
 * project or a folder above it, or in FOSTER_ALLOW (comma or space separated).
 *
 * Entries are names with an optional ecosystem and `*` wildcards: "lodahs", "npm:@acme/*", "pypi:acme-*".
 * An allowed package is installed with a note saying why, never silently, and known malware is blocked
 * whatever the list says: the list answers "is this the package we mean?", not "is it safe?".
 */
export interface AllowList {
  /** Where the list came from, for the note: ".foster.json in /work/app", "FOSTER_ALLOW". */
  source: string;
  matches(ecosystem: Ecosystem, name: string): boolean;
  /** The list file could not be read: it counts as empty, and guard says so. */
  error?: string;
}

const ECOSYSTEMS = new Set<Ecosystem>(["npm", "pypi", "cargo", "go", "rubygems", "packagist"]);
const norm = (ecosystem: Ecosystem | null, name: string) =>
  ecosystem === "pypi" ? name.toLowerCase().replace(/[-_.]+/g, "-") : ecosystem === "packagist" || ecosystem === "go" ? name.toLowerCase() : name;

function compile(entries: string[], source: string): AllowList | null {
  const rules = entries
    .map((e) => e.trim())
    .filter(Boolean)
    .map((e) => {
      const m = /^([a-z]+):(.+)$/.exec(e);
      const ecosystem = m && ECOSYSTEMS.has(m[1] as Ecosystem) ? (m[1] as Ecosystem) : null;
      return { ecosystem, pattern: ecosystem ? m![2]! : e };
    });
  if (!rules.length) return null;
  // each name is compared in its registry's spelling: PyPI ignores case and -_., Packagist and Go case
  const test = (pattern: string, ecosystem: Ecosystem, name: string) => {
    const body = norm(ecosystem, pattern).split("*").map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*");
    return new RegExp(`^${body}$`).test(norm(ecosystem, name));
  };
  return {
    source,
    matches: (ecosystem, name) => rules.some((r) => (!r.ecosystem || r.ecosystem === ecosystem) && test(r.pattern, ecosystem, name)),
  };
}

const PUBLIC_NPM = /^https?:\/\/registry\.(npmjs\.org|yarnpkg\.com|npmmirror\.com)\/?/i;

/**
 * The private registry an npm scope installs from (`@acme:registry=https://npm.acme.dev/` in an .npmrc
 * in the project, a folder above it, or the home folder), or null. Such packages are not on the public
 * registry, so "does not exist" would be a false alarm, and no public advisory database covers them.
 */
export function privateScopeRegistry(dir: string, name: string, env: NodeJS.ProcessEnv = process.env): string | null {
  const scope = /^(@[^/]+)\//.exec(name)?.[1]?.toLowerCase();
  if (!scope) return null;
  const files: string[] = [];
  for (let d = resolve(dir); ; d = dirname(d)) {
    files.push(join(d, ".npmrc"));
    if (dirname(d) === d) break;
  }
  files.push(env.NPM_CONFIG_USERCONFIG ?? join(homedir(), ".npmrc"));
  const fromEnv = env[`npm_config_${scope}:registry`] ?? env[`NPM_CONFIG_${scope}:registry`];
  if (fromEnv) return PUBLIC_NPM.test(fromEnv) ? null : fromEnv;
  for (const f of files) {
    if (!existsSync(f)) continue;
    let text = "";
    try {
      text = readFileSync(f, "utf8");
    } catch {
      continue;
    }
    for (const line of text.split(/\r?\n/)) {
      const m = /^\s*(@[^:\s]+):registry\s*=\s*(\S+)/.exec(line);
      if (m && m[1]!.toLowerCase() === scope) return PUBLIC_NPM.test(m[2]!) ? null : m[2]!.replace(/^["']|["']$/g, "");
    }
  }
  return null;
}

/** The `.foster.json` nearest to dir (dir itself, then each folder above it), if any. */
export function findAllowFile(dir: string): string | null {
  let d = resolve(dir);
  for (;;) {
    const f = join(d, ".foster.json");
    if (existsSync(f)) return f;
    const up = dirname(d);
    if (up === d) return null;
    d = up;
  }
}

/**
 * The allow list for a command run in `cwd`: FOSTER_ALLOW and the nearest `.foster.json`, combined.
 * A file that cannot be read or parsed counts as empty (and `error` says why).
 */
export function loadAllowList(cwd: string, env: NodeJS.ProcessEnv = process.env): AllowList | null {
  const lists: AllowList[] = [];
  let error: string | undefined;
  const fromEnv = (env.FOSTER_ALLOW ?? "").split(/[\s,]+/).filter(Boolean);
  if (fromEnv.length) lists.push(compile(fromEnv, "FOSTER_ALLOW")!);
  const file = findAllowFile(cwd);
  if (file) {
    try {
      const doc = JSON.parse(readFileSync(file, "utf8").replace(/^﻿/, "")) as { allow?: unknown };
      const entries = Array.isArray(doc.allow) ? doc.allow.filter((x): x is string => typeof x === "string") : [];
      const where = dirname(file) === resolve(homedir()) ? "~/.foster.json" : `.foster.json in ${dirname(file)}`;
      const list = compile(entries, where);
      if (list) lists.push(list);
    } catch (err) {
      error = `${file} could not be read (${(err as Error).message.slice(0, 120)}); its allow list is ignored`;
    }
  }
  if (!lists.length) return error ? { source: "", matches: () => false, error } : null;
  return {
    source: lists.map((l) => l.source).join(" and "),
    matches: (e, n) => lists.some((l) => l.matches(e, n)),
    ...(error ? { error } : {}),
  };
}
