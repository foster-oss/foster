import { existsSync, readdirSync, readFileSync } from "node:fs";
import semver from "semver";
import YAML from "yaml";
import { homedir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { checkPackage, type CheckResult } from "./check.js";
import { mapLimit } from "./http.js";
import { detectLockfiles, directCargoNames, directComposerNames, directPythonNames, readDependencies, type LockfileInfo } from "./lockfile.js";
import { npmInstallRisk, resolveNpmVersion, type InstallRisk } from "./npmrisk.js";
import { lockfileMalware, malwareReports, queryBatch, type LockedMalware, type MalwareReport } from "./osv.js";
import { describeAlternatives } from "./replacements.js";
import type { Dependency, Ecosystem } from "./types.js";
import { existsOnRegistry, FOSTER_PACKAGE, fosterImpostorMessage, impersonatesFoster, lookAlike, type LookAlike } from "./typosquat.js";

/**
 * `foster-oss guard`: inspect a shell command before it runs and stop installs of packages that
 * do not exist (hallucinated or typo'd names, the "slopsquatting" risk), have vulnerabilities no
 * release fixes, or are unmaintained. Built for AI coding agents, usable from any shell.
 */

export interface RequestedPackage {
  ecosystem: Ecosystem;
  name: string;
  /** Exact version when the command pins one. */
  version?: string;
  /** A range or dist-tag ("^4.1.0", "next") to resolve against the registry (npm). */
  range?: string;
  /** Installed straight from a URL or git: no registry or advisory database covers it. */
  remote?: boolean;
  /** Read from the project's package.json (an install with no names), not typed in the command. */
  fromManifest?: boolean;
  /**
   * The command installs something Foster cannot see: a shell variable ($PKG, %PKG%), command
   * substitution, names read from stdin (xargs), or a command nested deeper than Foster follows.
   */
  unresolved?: boolean;
  /** The token as written in the command. */
  spec: string;
}

/** An install that takes its package list from a lockfile: `npm ci`, `pip install -r`, `bundle install`, … */
export interface LockfileInstall {
  /** The command as a short label: "npm ci". */
  tool: string;
  dir: string;
  ecosystem: Ecosystem;
  /** An explicit file (`pip install -r dev.txt`); otherwise the lockfiles found in `dir`. */
  file?: string;
  /** Installs exactly what the lockfile says (`npm ci`, `--frozen-lockfile`, `--immutable`). */
  frozen?: boolean;
  /** Installs the project from its manifest whatever lockfile is there (`pip install .`, `pip install -e .`). */
  manifest?: boolean;
  /**
   * The command also names packages ("npm install x"): only what package.json would add beyond the
   * lockfile is checked here (the named packages are checked on their own), not the whole lockfile again.
   */
  named?: boolean;
}

export type Decision = "allow" | "ask" | "deny";

export interface PackageVerdict {
  requested: RequestedPackage;
  decision: Decision;
  reason: string;
  /** Worth knowing, but not a reason to stop: an unmaintained package with no known vulnerability. */
  note?: string;
  /** The check itself failed (network): allowed, and said so. */
  unchecked?: boolean;
}

export interface GuardResult {
  decision: Decision;
  verdicts: PackageVerdict[];
  /** One message suitable for showing to an agent or a person. */
  message: string;
}

// ---------------------------------------------------------------- command parsing

/** Shells that run a script they are given (on -c, on stdin or from a here-doc). */
const SHELLS = new Set(["bash", "sh", "zsh", "dash", "ksh", "fish", "ash", "mksh", "busybox"]);
const baseName = (t: string) => t.replace(/^.*[\\/]/, "").replace(/\.(exe|cmd|bat|ps1)$/i, "").toLowerCase();

/** Split a shell line into simple commands (on ;, &&, ||, |, newlines) and tokens, honouring quotes. */
export function splitCommands(line: string): string[][] {
  const commands: string[][] = [];
  const extra: string[] = []; // scripts handed to a shell as a here-string: bash <<< "npm i x"
  let tokens: string[] = [];
  let cur = "";
  let quote: '"' | "'" | null = null;
  let hasToken = false;
  // here-docs whose body starts at the next newline: skipped unless a shell reads it
  let heredocs: { delim: string; dash: boolean; script: boolean }[] = [];
  const pushToken = () => {
    if (hasToken) tokens.push(cur);
    cur = "";
    hasToken = false;
  };
  const pushCommand = () => {
    pushToken();
    if (tokens.length) commands.push(tokens);
    tokens = [];
  };
  const continuation = (i: number) => line[i + 1] === "\n" ? 1 : line[i + 1] === "\r" && line[i + 2] === "\n" ? 2 : 0;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (quote) {
      if (ch === quote) quote = null;
      // inside double quotes a backslash escapes only $ ` " \ (POSIX); elsewhere it is literal (C:\Users)
      else if (ch === "\\" && quote === '"' && i + 1 < line.length && '$`"\\'.includes(line[i + 1]!)) cur += line[++i];
      else cur += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      hasToken = true;
      continue;
    }
    // line continuations: "\" (bash), "`" (PowerShell) and "^" (cmd) before a newline join the lines
    if ((ch === "\\" || ch === "`" || ch === "^") && continuation(i)) {
      i += continuation(i);
      continue;
    }
    // comments: "#" at the start of a word runs to the end of the line; PowerShell's <# … #> blocks
    if (ch === "#" && !hasToken) {
      while (i + 1 < line.length && line[i + 1] !== "\n") i++;
      continue;
    }
    if (ch === "<" && line[i + 1] === "#") {
      const end = line.indexOf("#>", i + 2);
      i = end < 0 ? line.length : end + 1;
      continue;
    }
    // "\x" unquoted escapes x, except in Windows paths (C:\Users\me), where the backslash is a separator
    if (ch === "\\" && i + 1 < line.length && line[i + 1] !== "\n" && !/[A-Za-z0-9_.~-]/.test(line[i + 1]!)) {
      cur += line[++i];
      hasToken = true;
      continue;
    }
    // cmd's caret escapes the next character (n^p^m, a^&b); in a version range (^1.2) it is part of the word
    if (ch === "^" && i + 1 < line.length && /[A-Za-z&|<>()^%!-]/.test(line[i + 1]!)) {
      cur += line[++i];
      hasToken = true;
      continue;
    }
    // backticks: PowerShell's escape inside a word (n`p`m), bash's command substitution elsewhere (`npm i x`)
    if (ch === "`") {
      if (hasToken && /[A-Za-z0-9]/.test(line[i + 1] ?? "")) continue;
      pushCommand();
      continue;
    }
    if (ch === "\n" && heredocs.length) {
      pushCommand();
      // skip each here-doc body that is only data (cat <<EOF > file); a shell reading it runs it as commands
      for (const doc of heredocs) {
        if (doc.script) continue;
        let j = i + 1;
        for (;;) {
          const end = line.indexOf("\n", j);
          const text = (end < 0 ? line.slice(j) : line.slice(j, end)).replace(/\r$/, "");
          if ((doc.dash ? text.replace(/^\t+/, "") : text) === doc.delim || end < 0) {
            i = end < 0 ? line.length : end;
            break;
          }
          j = end + 1;
        }
      }
      heredocs = [];
      continue;
    }
    if (ch === "\n" || ch === ";" || ch === "|" || (ch === "&" && line[i + 1] === "&")) {
      if (ch === "&" || (ch === "|" && line[i + 1] === "|")) i++;
      pushCommand();
      continue;
    }
    // a single "&" also starts a command: "a & b" (bash background, cmd), "& npm i x" (PowerShell's call
    // operator); not in redirections such as 2>&1 or &>file
    if (ch === "&" && !/[<>]$/.test(cur) && line[i + 1] !== ">") {
      pushCommand();
      continue;
    }
    // subshells and blocks: "(npm i x)", "$(npm i x)", "{ npm i x; }", PowerShell's "if ($c) { npm i x }";
    // a brace inside a word (${VAR}, a={b}) stays part of it
    if (ch === "(" || ch === ")" || (ch === "{" && !hasToken) || (ch === "}" && !cur.includes("{"))) {
      pushCommand();
      continue;
    }
    // redirections ("> out.log", "2>&1", "&>>x", "*> x", "< in.txt") are not arguments: drop the
    // operator, its file descriptor and its target, so "npm i react > out.log" installs only react
    if (ch === ">" || ch === "<") {
      if (/^(\d+|&|\*)$/.test(cur)) { cur = ""; hasToken = false; }
      else pushToken();
      const start = i;
      while (i + 1 < line.length && /[<>&|]/.test(line[i + 1]!)) i++;
      const op = line.slice(start, i + 1);
      if (line[i] === "&" && /\d|-/.test(line[i + 1] ?? "")) { i++; continue; } // >&1, <&-: a descriptor, no file
      let dash = false;
      if (op === "<<" && line[i + 1] === "-") { dash = true; i++; }
      while (i + 1 < line.length && (line[i + 1] === " " || line[i + 1] === "\t")) i++;
      let q: string | null = null;
      let target = "";
      while (i + 1 < line.length) {
        const c = line[i + 1]!;
        if (q) { if (c === q) q = null; else target += c; i++; continue; }
        if (c === '"' || c === "'") { q = c; i++; continue; }
        if (/[\s;|&()<>]/.test(c)) break;
        target += c;
        i++;
      }
      // a here-doc (<<EOF) or here-string (<<< "…") is a script when a shell or iex reads it, data otherwise
      const reader = [...tokens, cur].some((t) => SHELLS.has(baseName(t)) || /^(iex|invoke-expression)$/i.test(t));
      if (op === "<<<" && reader) extra.push(target);
      else if (op === "<<" && target) heredocs.push({ delim: target, dash, script: reader });
      continue;
    }
    if (ch === " " || ch === "\t" || ch === "\r") {
      pushToken();
      continue;
    }
    cur += ch;
    hasToken = true;
  }
  pushCommand();
  for (const script of extra) commands.push(...splitCommands(script));
  return commands;
}

/** Flags that take a value, per tool, so the value is not mistaken for a package name. */
const VALUE_FLAGS: Record<string, string[]> = {
  npm: [
    "--registry", "--prefix", "-C", "--tag", "--workspace", "-w", "--save-prefix", "--cache", "--userconfig", "--globalconfig", "--omit", "--include",
    "--before", "--otp", "--loglevel", "--script-shell", "--install-strategy", "--fetch-retries", "--fetch-retry-mintimeout", "--fetch-retry-maxtimeout",
    "--fetch-timeout", "--audit-level", "--location", "--scope", "--node-options", "--maxsockets", "--umask", "--cafile", "--cert", "--key", "--proxy",
    "--https-proxy", "--noproxy", "--user-agent", "--lockfile-version", "--auth-type", "--browser", "--editor", "--shell", "--init-module", "--call", "-c",
  ],
  pnpm: [
    "--filter", "-F", "--dir", "-C", "--registry", "--loglevel", "--reporter", "--store-dir", "--virtual-store-dir", "--modules-dir", "--lockfile-dir",
    "--network-concurrency", "--child-concurrency", "--workspace-concurrency", "--resolution-mode", "--node-linker", "--package-import-method", "--config",
  ],
  yarn: [
    "--cwd", "--registry", "--network-timeout", "--mutex", "--modules-folder", "--cache-folder", "--global-folder", "--link-folder", "--network-concurrency",
    "--use-yarnrc", "--https-proxy", "--proxy", "--otp", "--preferred-cache-folder",
  ],
  bun: ["--cwd", "--registry", "--backend", "--cache-dir", "--network-concurrency", "--concurrent-scripts", "--config", "-c", "--linker", "--ca", "--cafile"],
  pip: [
    "-i", "--index-url", "--extra-index-url", "-f", "--find-links", "-c", "--constraint", "-t", "--target", "--prefix", "--root", "--python", "--platform",
    "--trusted-host", "--src", "--upgrade-strategy", "--only-binary", "--no-binary", "-r", "--requirement", "-e", "--editable", "--timeout", "--retries",
    "--proxy", "--cache-dir", "--log", "--cert", "--client-cert", "--exists-action", "--progress-bar", "--root-user-action", "--report", "--implementation",
    "--abi", "--python-version", "--config-settings", "-C", "--global-option", "--use-feature", "--use-deprecated", "--keyring-provider", "--prefer-binary-for",
  ],
  uv: [
    "--index", "--index-url", "--extra-index-url", "--default-index", "--python", "-p", "--group", "--optional", "--package", "-r", "--requirements", "-e",
    "--editable", "--directory", "--project", "--find-links", "-f", "--cache-dir", "--config-file", "--index-strategy", "--keyring-provider",
    "--resolution", "--prerelease", "--exclude-newer", "--link-mode", "--compile-bytecode-timeout", "--extra", "--with", "--with-requirements",
    "--with-editable", "--from", "-w", "--constraint", "-c", "--override", "--build-constraint", "-b", "--branch", "--tag", "--rev", "--marker", "-m",
  ],
  poetry: ["--group", "-G", "--source", "--extras", "-E", "--python", "--directory", "-C", "-P", "--project"],
  cargo: [
    "--features", "-F", "--package", "-p", "--path", "--git", "--branch", "--tag", "--rev", "--registry", "--rename", "--target", "--manifest-path",
    "--version", "--root", "--jobs", "-j", "--config", "--color", "--index", "--target-dir", "--profile", "--bin", "--example", "--lockfile-path", "-Z",
  ],
  go: ["-C", "-modfile", "-tags", "-p", "-ldflags", "-gcflags", "-asmflags", "-mod", "-o", "-overlay", "-pkgdir", "-toolexec", "-buildmode"],
  gem: ["-v", "--version", "-s", "--source", "-i", "--install-dir", "--platform", "-n", "--bindir", "--document", "--build-root", "-P", "--trust-policy", "-g", "--file"],
  bundle: ["--version", "-v", "--group", "-g", "--source", "-s", "--git", "--github", "--branch", "--ref", "--path", "--gemfile", "--jobs", "-j", "--retry", "--glob"],
  composer: ["--working-dir", "-d", "--repository", "--stability", "-s", "--prefer-install", "--audit-format"],
};

function positional(args: string[], tool: string): string[] {
  const valueFlags = new Set([...(VALUE_FLAGS[tool] ?? []), ...(GLOBAL_VALUE_FLAGS[tool] ?? [])]);
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--") {
      out.push(...args.slice(i + 1));
      break;
    }
    if (a.startsWith("-")) {
      if (!a.includes("=") && valueFlags.has(a)) i++;
      continue;
    }
    out.push(a);
  }
  return out;
}

function flagValue(args: string[], ...names: string[]): string | undefined {
  return flagValues(args, ...names)[0];
}

/** Every value given to a repeatable flag: npx -p a -p b, npm exec --package=a --package=b. */
function flagValues(args: string[], ...names: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--") break;
    for (const n of names) {
      if (a === n && args[i + 1] !== undefined) out.push(args[++i]!);
      else if (a.startsWith(`${n}=`)) out.push(a.slice(n.length + 1));
    }
  }
  return out;
}

/** A shell variable, expression or loop variable Foster cannot see the value of: $P, ${P}, $env:P, %P%, %%p, $_. */
const VAR_REF = /\$\{?[A-Za-z_][\w:]*\}?|%[A-Za-z_]\w*%|^%%?[A-Za-z]$|^\$\(?$|^\$_$/;

/** A few advisory IDs and a count, not a wall of 40. */
function listIds(ids: string[], max = 5): string {
  return ids.length > max ? `${ids.slice(0, max).join(", ")} and ${ids.length - max} more` : ids.join(", ");
}

function unresolvedSpec(ecosystem: Ecosystem, spec: string): RequestedPackage {
  return { ecosystem, name: spec, unresolved: true, spec };
}

/** Short flags written with their value attached: pip -rreqs.txt, gem -v1.2.3, -e. → -r reqs.txt. */
function attachedValues(args: string[], flags: string[]): string[] {
  return args.flatMap((a) => {
    const f = flags.find((x) => a.startsWith(x) && a.length > x.length && !a.startsWith("--"));
    return f ? [f, a.slice(f.length)] : [a];
  });
}

/** Where the command a runner runs starts (uv run [options] cmd …): the first word that is not an option. */
function commandStart(args: string[], tool: string): number {
  const values = new Set([...(VALUE_FLAGS[tool] ?? []), ...(GLOBAL_VALUE_FLAGS[tool] ?? [])]);
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--") return i + 1 < args.length ? i + 1 : -1;
    if (!a.startsWith("-")) return i;
    if (!a.includes("=") && values.has(a)) i++;
  }
  return -1;
}

/** A requirement line pinned to one version (name==1.2.3): the lockfile check covers it. */
const PINNED_REQUIREMENT = /^[A-Za-z0-9][A-Za-z0-9._-]*\s*(\[[^\]]*\])?\s*===?\s*[^\s;,*]+\s*(;.*)?$/;

/** The entries of a requirements file: requirements, nested -r files and -e installs. Unreadable files give none. */
export function requirementEntries(path: string): { kind: "requirement" | "file" | "editable"; value: string }[] {
  let text: string;
  try {
    text = readFileSync(path, "utf8").replace(/^﻿/, "");
  } catch {
    return [];
  }
  const out: { kind: "requirement" | "file" | "editable"; value: string }[] = [];
  for (const raw of text.replace(/\\\r?\n/g, "").split(/\r?\n/)) {
    const line = raw.replace(/(^|\s)#.*$/, "").trim();
    if (!line) continue;
    const opt = /^(-r|--requirement|-e|--editable|-c|--constraint)(?:\s*=?\s*)(\S.*)$/.exec(line);
    if (opt) {
      if (opt[1] === "-r" || opt[1] === "--requirement") out.push({ kind: "file", value: opt[2]!.trim() });
      else if (opt[1] === "-e" || opt[1] === "--editable") out.push({ kind: "editable", value: opt[2]!.trim() });
      continue;
    }
    if (line.startsWith("-")) continue; // --index-url, --hash, … : options, not packages
    out.push({ kind: "requirement", value: line.replace(/\s+--hash[= ]\S+/g, "").trim() });
  }
  return out;
}

const LOCAL_OR_URL = /^(\.{0,2}\/|~\/|[a-zA-Z]:\\|file:|link:|workspace:|git(\+|:)|https?:|github:|gitlab:|bitbucket:|ssh:)|\.(tgz|tar\.gz|whl|zip|gem)$/i;

/** Code fetched from a URL or a git host, not from the registry. */
const REMOTE = /^(git(\+[a-z]+)?:|git@|https?:\/\/|github:|gitlab:|bitbucket:|ssh:\/\/)/i;
/** A tarball on the npm registry itself names the package and version: check those. */
const NPM_TARBALL = /^https?:\/\/registry\.(?:npmjs\.org|yarnpkg\.com)\/((?:@[^/]+\/)?[^/]+)\/-\/[^/]+?-(\d+\.\d+\.\d+[^/]*?)\.tgz$/i;
const NPM_NAME = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i;

function npmSpec(spec: string): RequestedPackage | null {
  // "name@<url or git>": what gets installed is whatever the URL points at, not the registry package
  const urlAt = /^((?:@[^/@]+\/)?[^@/]+)@((?:https?|git(?:\+[a-z]+)?|ssh|file|github|gitlab|bitbucket):.+)$/i.exec(spec);
  if (urlAt) {
    const r = npmSpec(urlAt[2]!);
    return r && { ...r, spec };
  }
  // alias "x@npm:real@1.0.0" (npm, pnpm, yarn): what gets installed is the real package
  const alias = spec.indexOf("@npm:", 1);
  if (alias > 0 || spec.startsWith("npm:")) {
    const r = npmSpec(spec.slice(alias > 0 ? alias + "@npm:".length : "npm:".length));
    return r && !r.remote ? { ...r, spec } : r;
  }
  if (/^(\.{0,2}\/|~\/|[a-zA-Z]:\\|file:|link:|workspace:)/.test(spec)) return null; // local folders and files
  const tarball = spec.match(NPM_TARBALL);
  if (tarball) return { ecosystem: "npm", name: decodeURIComponent(tarball[1]!), version: tarball[2]!, spec };
  // git, URLs, and the "user/repo" GitHub shorthand
  if (REMOTE.test(spec) || (!spec.startsWith("@") && /^[\w.-]+\/[\w.-]+(#.*)?$/.test(spec))) return { ecosystem: "npm", name: spec, remote: true, spec };
  if (LOCAL_OR_URL.test(spec)) return null;
  const at = spec.lastIndexOf("@");
  const name = at > 0 ? spec.slice(0, at) : spec;
  const raw = at > 0 ? spec.slice(at + 1) : undefined;
  if (!NPM_NAME.test(name)) return null;
  // an npm version has three parts: express@4 and next@14.2 are ranges (the newest 4.x / 14.2.x)
  const version = raw && /^[=v]*\d+\.\d+\.\d+/.test(raw) ? exact(raw) : undefined;
  return { ecosystem: "npm", name, version, ...(raw && !version && raw !== "latest" ? { range: raw } : {}), spec };
}

/** Keep only exact versions; ranges and tags ("^1", "latest") mean "whatever resolves", checked as latest. */
function exact(v: string | undefined): string | undefined {
  if (!v) return undefined;
  const clean = v.replace(/^[=v]+/, "");
  return /^\d+(\.\d+)*([-.+][0-9A-Za-z.+-]+)?$/.test(clean) ? clean : undefined;
}

function pipSpec(spec: string): RequestedPackage | null {
  // "git+https://...", "pkg @ https://..." fetch code that no index covers
  if (REMOTE.test(spec) || /^[A-Za-z0-9._-]+\s*@\s*(git\+|https?:)/.test(spec)) return { ecosystem: "pypi", name: spec, remote: true, spec };
  if (LOCAL_OR_URL.test(spec) || spec.includes("://") || spec.startsWith("-") || spec === ".") return null;
  // the whole token must be a requirement: a name cut short by an escape (xlsx\writr) is not the name
  const m = spec.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*((?:[=!<>~]=?=?|===)\s*[^\s;,]+(?:\s*,\s*[=!<>~]=?=?\s*[^\s;,]+)*)?\s*(;.*)?$/);
  if (!m?.[1]) return null;
  const constraint = m[3]?.replace(/\s+/g, "");
  const pin = constraint && /^===?[^,*]+$/.test(constraint) ? exact(constraint.replace(/^===?/, "")) : undefined;
  // a range (>=1.2, ~=1.0, ==1.*) installs whatever matches: not the latest release, and not one known version
  return { ecosystem: "pypi", name: m[1], version: pin, ...(constraint && !pin ? { range: constraint } : {}), spec };
}

function cargoSpec(spec: string): RequestedPackage | null {
  const [name, version] = spec.split("@");
  if (!name || !/^[A-Za-z0-9_-]+$/.test(name)) return null;
  const pin = version && /^=?\d+\.\d+\.\d+/.test(version) ? exact(version.replace(/^=/, "")) : undefined;
  return { ecosystem: "cargo", name, version: pin, ...(version && !pin ? { range: version } : {}), spec };
}

function goSpec(spec: string): RequestedPackage | null {
  const at = spec.lastIndexOf("@");
  const path = at > 0 ? spec.slice(0, at) : spec;
  const version = at > 0 ? spec.slice(at + 1) : undefined;
  // module paths have a dot in the first element (github.com/..., golang.org/...); "./..." and "all" are local
  if (!/^[a-z0-9.-]+\.[a-z]{2,}\//i.test(path)) return null;
  return { ecosystem: "go", name: path, version: version && /^v\d/.test(version) ? version : undefined, spec };
}

/** A version constraint as written ("= 1.6.13", "==5.0.2", "v5.0.2@stable", ">=5 <6"): the exact version, or the range. */
function constraintOf(raw: string | undefined): { version?: string; range?: string } {
  if (!raw) return {};
  const clean = raw.trim().replace(/@(stable|rc|beta|alpha|dev)$/i, "").replace(/^(={1,2}|v)\s*/i, "").trim();
  if (/^\d+\.\d+(\.\d+)*([-.+][0-9A-Za-z.+-]+)?$/.test(clean)) return { version: clean };
  return clean ? { range: clean } : {};
}

function gemSpec(spec: string, version?: string): RequestedPackage | null {
  // gem install name:1.2.3
  const [name, inline] = spec.split(":");
  if (!name || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name) || LOCAL_OR_URL.test(spec)) return null;
  return { ecosystem: "rubygems", name, ...constraintOf(inline ?? version), spec };
}

function composerSpec(spec: string, version?: string): RequestedPackage | null {
  // vendor/pkg, vendor/pkg:1.0, vendor/pkg:==1.0, "vendor/pkg 1.0", vendor/pkg=1.0
  const m = /^([a-z0-9_.-]+\/[a-z0-9_.-]+)(?:\s*[:= ]\s*(.+))?$/i.exec(spec.trim());
  if (!m) return null;
  return { ecosystem: "packagist", name: m[1]!.toLowerCase(), ...constraintOf(m[2] ?? version), spec };
}

/** Package install requests found in a shell command line. Unknown commands yield nothing. */
/**
 * Rebuild a command line from CLI arguments. `guard -- npm i x` arrives as separate tokens (quote the
 * ones that contain whitespace so they stay one word); `guard "npm i x"` arrives as one token that is
 * already the whole command line.
 */
const GUARD_FLAGS = new Set(["--strict", "--quiet", "-q", "--json", "--help", "-h", "--include-staged", "--offline"]);
const GUARD_VALUE_FLAGS = new Set(["--hook", "--command"]);

/**
 * Split `guard …` arguments into guard's own options and the command to check. The command starts at
 * "--" or at the first token that is not a guard option, so "--" is optional: PowerShell drops it on the
 * way into npm's .ps1 shims, and "foster-oss guard -- npm i -D x" would otherwise reach the option parser
 * as "-D". Returns null when argv is not a guard call.
 */
export function splitGuardArgs(argv: string[]): { own: string[]; command: string[] } | null {
  if (argv[0] !== "guard") return null;
  const own: string[] = [];
  for (let i = 1; i < argv.length; i++) {
    const t = argv[i]!;
    if (t === "--") return { own, command: argv.slice(i + 1) };
    if (GUARD_FLAGS.has(t) || /^--(hook|command)=/.test(t)) { own.push(t); continue; }
    if (GUARD_VALUE_FLAGS.has(t)) { own.push(t, ...argv.slice(i + 1, i + 2)); i++; continue; }
    return { own, command: argv.slice(i) };
  }
  return { own, command: [] };
}

export function commandLineFrom(tokens: string[]): string {
  const [only] = tokens;
  if (tokens.length === 1 && only !== undefined) return only;
  return tokens.map((t) => (/\s/.test(t) ? JSON.stringify(t) : t)).join(" ");
}

export function parseInstallCommand(line: string): RequestedPackage[] {
  return parseCommand(line).packages;
}

/** Options that may precede the subcommand and take a value, per tool. */
const GLOBAL_VALUE_FLAGS: Record<string, string[]> = {
  npm: ["--prefix", "-C", "--registry", "--userconfig", "--cache", "--workspace", "-w", "--loglevel"],
  pnpm: ["-C", "--dir", "--filter", "-F", "--loglevel", "--reporter"],
  yarn: ["--cwd", "--registry"],
  bun: ["--cwd"],
  pip: ["--python", "--log", "--cache-dir", "--proxy", "--timeout", "--retries", "--cert", "--client-cert"],
  uv: ["--directory", "--project", "--cache-dir", "--config-file"],
  poetry: ["-C", "--directory", "-P", "--project"],
  cargo: ["-C", "--config", "-Z"],
  composer: ["-d", "--working-dir"],
};

/**
 * The package an initializer runs, as npm maps it: "vite" -> create-vite, "@scope" -> @scope/create,
 * "@scope/app" -> @scope/create-app; a version stays attached. Git, URL and path templates are not packages.
 */
export function createPackage(spec: string): string | null {
  if (/^[./~]|:/.test(spec) || (!spec.startsWith("@") && spec.includes("/"))) return null;
  const m = /^(@[^/@]+)(?:\/([^@]+))?(@.+)?$/.exec(spec) ?? /^()([^@]+)(@.+)?$/.exec(spec);
  if (!m) return null;
  const [, scope, name, version = ""] = m;
  if (scope) return `${scope}/${name ? `create-${name}` : "create"}${version}`;
  return `create-${name}${version}`;
}

const NPM_INSTALL = ["install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall", "add", "install-test", "it"];
const NPM_LOCKED = ["ci", "clean-install", "ic", "install-clean", "isntall-clean", "install-ci-test", "cit"];
const NPM_UPDATE = ["update", "up", "upgrade", "udpate"];

/** Shell keywords a command can follow (bash's then/do, PowerShell's & and . call operators). */
const KEYWORDS = new Set(["then", "else", "elif", "while", "until", "do", "!", "&", ".", "{", "}"]);

/**
 * Wrapper commands that run the command after them: each lists the options that take a value, and
 * how many plain arguments come before the wrapped command (timeout's duration, flock's lock file).
 */
const WRAPPERS: Record<string, { values: string[]; skip?: number; until?: string }> = {
  sudo: { values: ["-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-T", "--user", "--group", "--host", "--prompt", "--chdir", "--role", "--type", "--other-user", "--command-timeout", "--close-from"] },
  doas: { values: ["-u", "-C"] },
  env: { values: ["-u", "--unset", "-C", "--chdir"] },
  nice: { values: ["-n", "--adjustment"] },
  ionice: { values: ["-c", "-n", "--class", "--classdata"] },
  timeout: { values: ["-s", "--signal", "-k", "--kill-after"], skip: 1 },
  stdbuf: { values: ["-i", "-o", "-e", "--input", "--output", "--error"] },
  time: { values: ["-f", "-o", "--format", "--output"] },
  command: { values: [] },
  builtin: { values: [] },
  exec: { values: ["-a"] },
  nohup: { values: [] },
  chronic: { values: [] },
  unbuffer: { values: [] },
  caffeinate: { values: ["-t", "-w"] },
  torsocks: { values: ["-u", "-p", "-a", "-P"] },
  proxychains: { values: ["-f"] },
  proxychains4: { values: ["-f"] },
  flock: { values: ["-w", "--timeout", "-E", "--conflict-exit-code"], skip: 1 },
  watch: { values: ["-n", "--interval", "-q", "--equexit"] },
  "xvfb-run": { values: ["-n", "--server-num", "-s", "--server-args", "-f", "--auth-file", "-e", "--error-file", "-p", "--xauth-protocol", "-w", "--wait"] },
  wsl: { values: ["-d", "--distribution", "-u", "--user", "--cd", "--shell-type"] },
  runuser: { values: ["-u", "--user", "-g", "--group", "-G", "--supp-group"] },
  call: { values: [] },
  xargs: { values: ["-a", "--arg-file", "-d", "--delimiter", "-E", "-e", "-I", "-i", "-L", "-l", "-n", "--max-args", "-P", "--max-procs", "-s", "--max-chars"] },
  "asdf": { values: [], until: "exec" },
};

/** Runner packages run with npx that run the command after them: npx cross-env A=1 npm i x. */
const NPX_RUNNERS: Record<string, string[]> = {
  "cross-env": [],
  "cross-env-shell": [],
  dotenv: ["-e", "-v", "-c"],
  "dotenv-cli": ["-e", "-v", "-c"],
  "env-cmd": ["-f", "--file", "-e", "--environments", "-r", "--rc-file"],
};

const assignment = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s;

/** Replace the variables Foster saw assigned earlier on the line: $P, ${P}, $env:P, %P%. Unknown ones stay. */
function expandVars(token: string, vars: Map<string, string>): string {
  if (!vars.size || !/[$%]/.test(token)) return token;
  const get = (name: string) => vars.get(name) ?? vars.get(name.toLowerCase());
  return token
    .replace(/\$\{([A-Za-z_]\w*)\}/g, (m, n: string) => get(n) ?? m)
    .replace(/\$(env:[A-Za-z_]\w*|[A-Za-z_]\w*)/gi, (m, n: string) => get(n) ?? m)
    .replace(/%([A-Za-z_]\w*)%/g, (m, n: string) => get(n) ?? m);
}

/**
 * Record a command that only assigns variables (bash P=x, export P=x; PowerShell $p = 'x', $env:P = 'x';
 * cmd set P=x) so later commands on the line can be expanded. Returns true when nothing else runs.
 */
function recordAssignments(tokens: string[], vars: Map<string, string>): boolean {
  const set = (name: string, value: string) => {
    vars.set(name, value);
    vars.set(name.toLowerCase(), value);
  };
  let t = tokens;
  if (["export", "declare", "local", "readonly", "typeset"].includes(t[0] ?? "")) t = t.slice(1).filter((x) => !x.startsWith("-"));
  if (t.length && t.every((x) => assignment.test(x))) {
    for (const x of t) {
      const m = assignment.exec(x)!;
      set(m[1]!, m[2]!);
    }
    return true;
  }
  const ps = /^\$((?:env:)?[A-Za-z_]\w*)(?:=(.+))?$/i.exec(t[0] ?? "");
  if (ps && ps[2] !== undefined && t.length === 1) {
    set(ps[1]!, ps[2]);
    return true;
  }
  if (ps && t[1] === "=" && t.length === 3) {
    set(ps[1]!, t[2]!);
    return true;
  }
  if (/^set$/i.test(t[0] ?? "") && t.length === 2 && assignment.test(t[1]!)) {
    const m = assignment.exec(t[1]!)!;
    set(m[1]!, m[2]!);
    return true;
  }
  return false;
}

/**
 * Strip what runs a command without being one: variable prefixes (P=1 npm …), PowerShell assignments
 * ($out = npm …), shell keywords, cmd's @ and `if exist x`, and wrappers with their own options
 * (sudo -E, timeout 60, env -S "…", nice -n 10, nvm exec 20, mise exec --, find … -exec, …).
 * `stdin` is set when the command takes its arguments from stdin (xargs).
 */
function stripWrappers(tokens: string[], vars: Map<string, string>): { tokens: string[]; stdin: boolean } {
  let t = tokens;
  let stdin = false;
  for (let guard = 0; guard < 32 && t.length; guard++) {
    const first = t[0]!;
    const word = baseName(first.replace(/^@/, ""));
    if (first.startsWith("@") && first.length > 1 && !first.includes("/")) {
      t = [first.slice(1), ...t.slice(1)];
      continue;
    }
    if (assignment.test(first)) {
      const m = assignment.exec(first)!;
      vars.set(m[1]!, m[2]!);
      t = t.slice(1);
      continue;
    }
    // PowerShell: $null = npm i x, $out = npm i x, [void](…)
    if (/^\$(?:env:)?[\w:]+$/i.test(first) && t[1] === "=") {
      t = t.slice(2);
      continue;
    }
    if (KEYWORDS.has(first) && t.length > 1) {
      t = t.slice(1);
      continue;
    }
    if (word === "if") {
      // cmd: if [not] exist x, if errorlevel 1, if [not] defined X; bash's `if cmd` and PowerShell's if (…) need nothing more
      let k = 1;
      if (/^\/i$/i.test(t[k] ?? "")) k++;
      if (/^not$/i.test(t[k] ?? "")) k++;
      if (/^(exist|errorlevel|defined)$/i.test(t[k] ?? "")) k += 2;
      else if (/==/.test(t[k] ?? "")) k++; // if "%x%"=="y" npm i …
      t = t.slice(k);
      continue;
    }
    if (word === "find") {
      const i = t.findIndex((x) => /^-(exec|execdir|ok|okdir)$/.test(x));
      if (i < 0) break;
      const end = t.findIndex((x, j) => j > i && (x === ";" || x === "+"));
      t = t.slice(i + 1, end < 0 ? undefined : end);
      continue;
    }
    if (word === "nvm" && t[1] === "exec") {
      t = t.slice(2);
      if (/^(v?\d|lts|node$|iojs$|--lts)/i.test(t[0] ?? "")) t = t.slice(1);
      continue;
    }
    if (word === "fnm" && t[1] === "exec") {
      t = t.slice(2);
      while (t[0]?.startsWith("--using")) t = t.slice(t[0].includes("=") ? 1 : 2);
      continue;
    }
    if ((word === "mise" || word === "rtx") && (t[1] === "exec" || t[1] === "x")) {
      const dd = t.indexOf("--");
      t = dd >= 0 ? t.slice(dd + 1) : t.slice(2).filter((x) => !x.includes("@"));
      continue;
    }
    if (word === "volta" && t[1] === "run") {
      t = t.slice(2);
      while (t[0]?.startsWith("--")) t = t.slice(/^--(node|npm|yarn|pnpm|env)$/.test(t[0]!) ? 2 : 1);
      continue;
    }
    if (word === "volta" && t[1] === "install") {
      // volta install x is a global npm install
      t = ["npm", "install", "-g", ...t.slice(2)];
      continue;
    }
    if (word === "start" || word === "start-process" || word === "saps") {
      t = startTarget(t.slice(1));
      continue;
    }
    const w = WRAPPERS[word];
    if (!w || t.length < 2) break;
    if (word === "xargs") stdin = true;
    if (w.until) {
      const i = t.indexOf(w.until);
      if (i < 0) break;
      t = t.slice(i + 1);
      continue;
    }
    let k = 1;
    while (k < t.length) {
      const a = t[k]!;
      if (a === "--") { k++; break; }
      if (word === "env" && (a === "-S" || a === "--split-string" || a.startsWith("--split-string=") || /^-S./.test(a))) {
        const s = a === "-S" || a === "--split-string" ? t[k + 1] ?? "" : a.replace(/^--split-string=|^-S/, "");
        t = [...(splitCommands(s)[0] ?? []), ...t.slice(a === "-S" || a === "--split-string" ? k + 2 : k + 1)];
        k = 0;
        break;
      }
      if (word === "env" && assignment.test(a)) {
        const m = assignment.exec(a)!;
        vars.set(m[1]!, m[2]!);
        k++;
        continue;
      }
      if (!a.startsWith("-")) break;
      k += !a.includes("=") && w.values.includes(a) ? 2 : 1;
    }
    if (k === 0) continue; // env -S rebuilt the command
    k += w.skip ?? 0;
    t = t.slice(k);
  }
  return { tokens: t, stdin };
}

/** The command Start-Process / saps (PowerShell) or start (cmd) runs. */
function startTarget(args: string[]): string[] {
  if (args.some((a) => /^-/.test(a))) {
    // PowerShell: Start-Process [-FilePath] exe [[-ArgumentList] 'a b' | 'a','b']
    let exe: string | undefined;
    const list: string[] = [];
    const positional: string[] = [];
    for (let i = 0; i < args.length; i++) {
      const a = args[i]!;
      if (/^-f(i(l(e(p(a(t(h)?)?)?)?)?)?)?$/i.test(a)) exe = args[++i];
      else if (/^-(ar(g(u(m(e(n(t(l(i(s(t)?)?)?)?)?)?)?)?)?)?|args)$/i.test(a)) list.push(args[++i] ?? "");
      else if (/^-/.test(a)) {
        if (/^-(wo|workingdirectory|verb|windowstyle|redirectstandard\w*|credential)/i.test(a)) i++;
      } else positional.push(a);
    }
    if (!exe) exe = positional.shift();
    list.push(...positional);
    const argTokens = list.flatMap((x) => (x.includes(",") && !/\s/.test(x) ? x.split(",") : (splitCommands(x)[0] ?? [])));
    return exe ? [exe, ...argTokens] : [];
  }
  // cmd: start [/b] [/wait] [/d dir] ["title"] command args
  let k = 0;
  while (k < args.length && /^\//.test(args[k]!)) k += /^\/d$/i.test(args[k]!) ? 2 : 1;
  if (args[k] === "") k++;
  const [exe, ...more] = args.slice(k);
  // start npm "i x" (PowerShell's start alias without parameter names): a quoted argument list
  return exe ? [exe, ...more.flatMap((x) => (/\s/.test(x) ? (splitCommands(x)[0] ?? []) : [x]))] : [];
}

/** The command line a shell is told to run, when tokens hand one to bash/sh/zsh, cmd, PowerShell, eval or iex. */
function innerScript(tokens: string[]): string | null {
  let [first, ...rest] = tokens;
  if (!first) return null;
  let cmd = /^%comspec%$/i.test(first) ? "cmd" : baseName(first);
  if (cmd === "busybox" && rest[0] && SHELLS.has(baseName(rest[0]))) {
    cmd = baseName(rest[0]);
    rest = rest.slice(1);
  }
  if (SHELLS.has(cmd) || cmd === "su" || cmd === "script" || cmd === "runuser") {
    const i = rest.findIndex((t) => /^-[a-z]*c[a-z]*$/.test(t) || t === "--command"); // -c, -lc, -ec, -qc, …
    if (i < 0) return null;
    let j = i + 1;
    if (rest[j] === "--") j++;
    let script = rest[j];
    if (script === undefined) return null;
    // sh -c 'npm i "$1"' _ x: the words after the script are its $0, $1, …
    const params = rest.slice(j + 1);
    if (params.length) script = script.replace(/\$\{?(\d)\}?/g, (m, d: string) => params[Number(d)] ?? m).replace(/"\$[@*]"|\$[@*]/g, params.slice(1).join(" "));
    return script;
  }
  if (cmd === "cmd") {
    const glued = rest.findIndex((t) => /^\/[ck]\S/i.test(t)); // cmd /c"npm i x"
    if (glued >= 0) return [rest[glued]!.slice(2), ...rest.slice(glued + 1)].join(" ");
    const i = rest.findIndex((t) => /^\/[ck]$/i.test(t));
    return i >= 0 ? rest.slice(i + 1).join(" ") : null;
  }
  if (cmd === "powershell" || cmd === "pwsh") {
    const enc = rest.findIndex((t) => /^[-/]e(n(c(o(d(e(d(c(o(m(m(a(n(d)?)?)?)?)?)?)?)?)?)?)?)?)?$/i.test(t) || /^[-/]ec$/i.test(t));
    if (enc >= 0 && rest[enc + 1]) {
      try {
        return Buffer.from(rest[enc + 1]!, "base64").toString("utf16le");
      } catch {
        return null;
      }
    }
    const i = rest.findIndex((t) => /^[-/]c(o(m(m(a(n(d(withargs)?)?)?)?)?)?)?$/i.test(t) || /^-cwa$/i.test(t));
    if (i >= 0) return rest.slice(i + 1).join(" ");
    if (rest.some((t) => /^[-/]f(i(l(e)?)?)?$/i.test(t))) return null; // -File runs a script file
    // powershell "npm i x" / powershell npm i x: the first word that is not an option is the command
    const valued = /^[-/](executionpolicy|ex|ep|windowstyle|w|version|v|inputformat|outputformat|of|if|configurationname|workingdirectory|wd|settingsfile|custompipename)$/i;
    let k = 0;
    while (k < rest.length && /^[-/]/.test(rest[k]!)) k += valued.test(rest[k]!) ? 2 : 1;
    return k < rest.length ? rest.slice(k).join(" ") : null;
  }
  if (cmd === "eval" || cmd === "iex" || cmd === "invoke-expression") {
    const args = rest.filter((t, i) => !(/^-c(o(m(m(a(n(d)?)?)?)?)?)?$/i.test(t) && i === 0));
    return args.join(" ") || null;
  }
  return null;
}

/** A command that runs whatever text arrives on stdin: sh, bash, iex, powershell -, … */
function readsScriptFromStdin(tokens: string[]): boolean {
  const cmd = baseName(tokens[0] ?? "");
  if (SHELLS.has(cmd)) return tokens.slice(1).every((t) => t.startsWith("-") && !/^-[a-z]*c[a-z]*$/.test(t));
  if (cmd === "iex" || cmd === "invoke-expression") return tokens.length === 1;
  if (cmd === "powershell" || cmd === "pwsh") return tokens.slice(1).every((t) => /^[-/]/.test(t)) && (tokens.includes("-") || tokens.some((t) => /^[-/]c(ommand)?$/i.test(t)) || tokens.length === 1);
  return false;
}

/** The text a command writes to stdout when it is a plain literal: echo "…", printf '…', Write-Output, "…". */
function literalOutput(tokens: string[]): string | null {
  const cmd = (tokens[0] ?? "").toLowerCase();
  if (cmd === "echo" || cmd === "write-output" || cmd === "write" || cmd === "write-host") return tokens.slice(1).filter((t) => !/^-[ne]+$/.test(t)).join(" ");
  if (cmd === "printf") return (tokens[1] ?? "").replace(/\\n/g, "\n");
  if (tokens.length === 1 && /\s/.test(tokens[0]!)) return tokens[0]!.replace(/^@\r?\n?|\r?\n?@$/g, ""); // a quoted string or here-string piped on
  return null;
}

/**
 * Everything a command line would install: packages named on it, and installs that take their list
 * from a lockfile (`npm ci`, `npm install` with no names, `pip install -r`, `bundle install`, …).
 * `cd dir &&` and `--prefix`/`--dir`/`--cwd` style flags move where the lockfile is looked for.
 */
/** How deep Foster follows a command handed to another shell (bash -c "sh -c '…'"); deeper is an ask. */
const MAX_DEPTH = 8;

export function parseCommand(
  line: string,
  cwd: string = process.cwd(),
  depth = 0,
  vars: Map<string, string> = new Map(),
): { packages: RequestedPackage[]; lockfiles: LockfileInstall[] } {
  const found: RequestedPackage[] = [];
  const locked: LockfileInstall[] = [];
  let dir = cwd;
  const nested = (script: string) => {
    if (depth + 1 >= MAX_DEPTH) {
      found.push(unresolvedSpec("npm", `${script.slice(0, 80)} (nested ${MAX_DEPTH} shells deep)`));
      return;
    }
    const inner = parseCommand(script, dir, depth + 1, new Map(vars));
    found.push(...inner.packages);
    locked.push(...inner.lockfiles);
  };
  let prev: string[] | null = null;
  for (const raw of splitCommands(line)) {
    let tokens = raw.map((t) => expandVars(t, vars));
    const previous = prev;
    prev = tokens;
    if (recordAssignments(tokens, vars)) continue;
    // a command line handed to another shell: bash -c "…", cmd /c …, powershell -Command "…", eval, iex,
    // and text piped into one: echo "npm i x" | sh, "npm i x" | iex
    const handed = (t: string[]) => {
      const script = innerScript(t);
      if (script !== null && script.trim() !== "-") return script;
      const text = previous && readsScriptFromStdin(t) ? literalOutput(previous) : null;
      return text;
    };
    let script = handed(tokens);
    let stdin = false;
    if (script === null) {
      // strip env assignments, wrappers (sudo -E, timeout 60, nice, call, start /b, …) and shell keywords
      const w = stripWrappers(tokens, vars);
      tokens = w.tokens.map((t) => expandVars(t, vars));
      stdin = w.stdin;
      script = handed(tokens);
    }
    if (script !== null) {
      nested(script);
      continue;
    }
    // corepack runs the package manager a project pins: "corepack pnpm install", "corepack yarn@4.1.0 add x"
    if (/^corepack(\.cmd|\.exe)?$/i.test(tokens[0] ?? "") && /^(npm|npx|pnpm|pnpx|yarn)(@[^\s]+)?$/.test(tokens[1] ?? "")) tokens = tokens.slice(1);
    // node …/npm-cli.js i x runs npm itself
    if (baseName(tokens[0] ?? "") === "node" && /(^|[\\/])np([mx])-cli\.js$/i.test(tokens[1] ?? "")) {
      tokens = [/npx-cli/i.test(tokens[1]!) ? "npx" : "npm", ...tokens.slice(2)];
    }
    // cargo +nightly install x: the toolchain is not the subcommand
    if (baseName(tokens[0] ?? "") === "cargo" && tokens[1]?.startsWith("+")) tokens = [tokens[0]!, ...tokens.slice(2)];
    const [cmd0, ...rest] = tokens;
    if (!cmd0) continue;
    // "pnpm@9.1.0" (the corepack form) is pnpm; Windows finds NPM, npm.cmd and npm.ps1 alike
    const cmd = baseName(cmd0).replace(/^(npm|npx|pnpm|pnpx|yarn)@.*$/, "$1");
    if (["cd", "pushd", "chdir", "set-location", "sl", "push-location"].includes(cmd)) {
      // PowerShell: Set-Location -Path web; cmd: cd /d D:\web; bash: cd -- web, cd -P web, cd ~/web
      const to = rest.filter((a) => !/^-(path|literalpath)$/i.test(a) && !/^\/d$/i.test(a) && a !== "--" && !/^-[LPe@]+$/.test(a))[0];
      if (to && to !== "-") dir = resolve(dir, to.replace(/^(~|\$HOME|\$env:USERPROFILE|%USERPROFILE%)(?=$|[\\/])/i, homedir()));
      continue;
    }
    // Global options may come before the subcommand: "npm --prefix app ci", "pnpm -C app i", "yarn --cwd app".
    // They are moved after it, so the same flag lookups and positional parsing see them.
    const globals = GLOBAL_VALUE_FLAGS[/^pip3?(\.\d+)?$/.test(cmd) ? "pip" : cmd];
    const lead: string[] = [];
    let k = 0;
    while (globals && k < rest.length && rest[k]!.startsWith("-")) {
      const a = rest[k++]!;
      lead.push(a);
      if (!a.includes("=") && globals.includes(a) && k < rest.length) lead.push(rest[k++]!);
    }
    const sub = rest[k];
    const args = [...lead, ...rest.slice(k + 1)];
    const before = found.length;
    const add = (r: RequestedPackage | null) => r && found.push(r);
    // a name Foster cannot see ($PKG, %PKG%, $(…)) is reported as such, not skipped
    const spec = (ecosystem: Ecosystem, s: string, parse: (s: string) => RequestedPackage | null) => {
      if (VAR_REF.test(s)) return add(unresolvedSpec(ecosystem, s));
      // xlsx\writr: bash drops the backslash, so the name that installs is xlsxwritr
      const word = /^[\w.@/-]+\\[\w.\\-]+$/.test(s) && !/^[a-zA-Z]:\\/.test(s) ? s.replace(/\\/g, "") : s;
      return add(parse(word));
    };
    const npm = (s: string) => spec("npm", s, npmSpec);
    const pip = (s: string) => spec("pypi", s, pipSpec);
    // pip install -e git+https://…: code from a repository, not the index
    // a local project (pip install ., pip install -e ./lib): its pyproject.toml dependencies get installed
    const localProject = (p: string) => /^(\.{1,2}([\\/].*)?|[a-zA-Z]:\\.*|\/.*)$/.test(p) && !/\.(whl|tar\.gz|zip)$/i.test(p);
    const projectInstall = (p: string) => locked.push({ tool: `pip install ${p}`, dir: resolve(dir, p), ecosystem: "pypi", manifest: true });
    const editable = (e: string) => (REMOTE.test(e) ? add({ ecosystem: "pypi", name: e, remote: true, spec: e }) : localProject(e) ? projectInstall(e) : undefined);
    // a requirements file: pinned lines go to the lockfile check; ranges, unpinned names, URLs and nested -r files are read here
    const requirements = (tool: string, file: string, seen = new Set<string>()) => {
      const path = resolve(dir, file);
      if (seen.has(path)) return;
      seen.add(path);
      lock(tool, "pypi", undefined, path);
      for (const entry of requirementEntries(path)) {
        if (entry.kind === "file") requirements(tool, resolve(dirname(path), entry.value), seen);
        else if (entry.kind === "editable") editable(entry.value);
        else if (!PINNED_REQUIREMENT.test(entry.value)) pip(entry.value);
      }
    };
    // npm ci and --frozen-lockfile / --immutable installs use the lockfile as it is; others may rewrite it
    const frozen = (cmd === "npm" && !!sub && NPM_LOCKED.includes(sub)) || args.some((a) => ["--frozen-lockfile", "--immutable", "--immutable-cache"].includes(a));
    const lock = (tool: string, ecosystem: Ecosystem, at?: string, file?: string, named = false) =>
      locked.push({ tool, dir: at ? resolve(dir, at) : dir, ecosystem, ...(file ? { file } : {}), ...(frozen ? { frozen } : {}), ...(named ? { named } : {}) });
    // "npm install x" in a project installs the whole project too: whatever package.json adds that the
    // lockfile lacks comes along. A global install (-g) has no project.
    const global = args.includes("-g") || args.includes("--global") || args.includes("--location=global") || (args.includes("--location") && args[args.indexOf("--location") + 1] === "global");
    // a run-once tool (npx x, bun x x): its own options come before the package; what follows belongs to
    // the tool it runs (npx http-server -p 8080, npx tsc -p tsconfig.json)
    const runOnce = (runArgs: string[], parse: (s: string) => void) => {
      const own: string[] = [];
      let first: string | undefined;
      for (let i = 0; i < runArgs.length; i++) {
        const a = runArgs[i]!;
        if (a === "--") {
          first = runArgs[i + 1];
          break;
        }
        if (!a.startsWith("-")) {
          first = a;
          break;
        }
        own.push(a);
        if (!a.includes("=") && /^(-p|--package|-c|--call|--registry|--cache|--userconfig|-w|--workspace|--prefix|-C|--node-options)$/.test(a)) own.push(runArgs[++i] ?? "");
      }
      const named = flagValues(own, "-p", "--package");
      named.forEach(parse);
      // npx tsc in a project that has it: npx runs the local copy, not a registry package
      const local = first && !named.length && ["", ".cmd", ".ps1"].some((ext) => existsSync(join(dir, "node_modules", ".bin", first!.replace(/(.)@.*$/, "$1") + ext)));
      if (first && !named.length && !local) parse(first);
      return { own, first };
    };

    if (cmd === "npm" && sub && NPM_LOCKED.includes(sub)) lock(`npm ${sub}`, "npm", flagValue(args, "--prefix", "-C"));
    else if (cmd === "npm" && sub && (NPM_INSTALL.includes(sub) || NPM_UPDATE.includes(sub))) {
      const specs = positional(args, "npm");
      if (specs.length) {
        specs.forEach(npm);
        if (!global) lock(`npm ${sub}`, "npm", flagValue(args, "--prefix", "-C"), undefined, true);
      } else if (sub !== "add") lock(`npm ${sub}`, "npm", flagValue(args, "--prefix", "-C"));
    } else if (cmd === "pnpm" && sub && ["add", "install", "i", "update", "up", "upgrade"].includes(sub)) {
      const specs = positional(args, "pnpm");
      if (specs.length) {
        specs.forEach(npm);
        if (!global) lock(`pnpm ${sub}`, "npm", flagValue(args, "--dir", "-C"), undefined, true);
      } else if (sub !== "add") lock(`pnpm ${sub}`, "npm", flagValue(args, "--dir", "-C"));
    } else if (cmd === "yarn" && sub === "workspace" && args[1] === "add") {
      // yarn workspace web add x
      positional(args.slice(2), "yarn").forEach(npm);
      lock("yarn workspace add", "npm", flagValue(args, "--cwd"), undefined, true);
    } else if (cmd === "yarn" && sub === "workspaces" && args.includes("add")) {
      // yarn workspaces foreach -A add x
      positional(args.slice(args.indexOf("add") + 1), "yarn").forEach(npm);
      lock("yarn workspaces add", "npm", flagValue(args, "--cwd"), undefined, true);
    } else if (cmd === "yarn" && (sub === "add" || sub === "up" || sub === "upgrade" || (sub === "global" && args[0] === "add"))) {
      positional(sub === "global" ? args.slice(1) : args, "yarn").forEach(npm);
      if (sub !== "global") lock(`yarn ${sub}`, "npm", flagValue(args, "--cwd"), undefined, true);
    } else if (cmd === "yarn" && (sub === undefined || sub === "install" || sub.startsWith("-"))) lock("yarn install", "npm", flagValue(args, "--cwd"));
    else if (cmd === "bun" && sub && ["add", "install", "i", "update"].includes(sub)) {
      const specs = positional(args, "bun");
      if (specs.length) {
        specs.forEach(npm);
        if (!global) lock(`bun ${sub}`, "npm", flagValue(args, "--cwd"), undefined, true);
      } else if (sub !== "add") lock(`bun ${sub}`, "npm", flagValue(args, "--cwd"));
    } else if (cmd === "deno" && sub && ["add", "install", "i", "run", "x"].includes(sub)) {
      // deno add npm:x, deno install -g npm:x, deno run npm:x: only npm: specifiers come from npm
      const names = positional(args.filter((a) => !/^--allow-|^-A$/.test(a)), "npm").filter((s) => s.startsWith("npm:"));
      (sub === "run" || sub === "x" ? names.slice(0, 1) : names).forEach(npm);
    }
    else if (((cmd === "npm" && sub && ["create", "init", "innit"].includes(sub)) || ((cmd === "yarn" || cmd === "pnpm" || cmd === "bun") && sub === "create")) && positional(args, "npm")[0]) {
      // scaffolders: "npm create vite@latest", "npm init next-app", "pnpm create astro" run create-<name> from the registry
      const initializer = createPackage(positional(args, "npm")[0]!);
      if (initializer) npm(initializer);
    } else if (cmd === "npx" || cmd === "bunx" || cmd === "pnpx" || (cmd === "npm" && (sub === "exec" || sub === "x")) || (cmd === "pnpm" && sub === "dlx") || (cmd === "yarn" && sub === "dlx") || (cmd === "bun" && sub === "x")) {
      const runArgs = cmd === "npx" || cmd === "bunx" || cmd === "pnpx" ? rest : args;
      const { own, first } = runOnce(runArgs, npm);
      // npx -c "npm i x" / npm exec --call: a command line
      for (const call of flagValues(own, "-c", "--call")) nested(call);
      // npx cross-env A=1 npm i x, npx dotenv -- npm i x, npx npm@10 i x: the command after the runner
      const at = first ? runArgs.indexOf(first) : -1;
      const runner = first ? first.replace(/(.)@.*$/, "$1") : "";
      if (at >= 0 && (runner in NPX_RUNNERS || ["npm", "pnpm", "yarn"].includes(runner))) {
        let after = runArgs.slice(at + 1);
        if (runner in NPX_RUNNERS) {
          const values = NPX_RUNNERS[runner]!;
          while (after.length && (after[0]!.startsWith("-") || assignment.test(after[0]!))) after = after.slice(after[0] === "--" ? 1 : values.includes(after[0]!) ? 2 : 1);
        } else after = [runner, ...after];
        if (after.length) nested(commandLineFrom(after));
      }
    } else if (/^python[\d.]*$|^py$/.test(cmd) && rest.some((a) => a === "-m" || /^-m[a-z]/.test(a))) {
      // python -m pip install x, py -3.12 -m pip …, python -mpip …, python -I -m uv pip install …
      const i = rest.findIndex((a) => a === "-m" || /^-m[a-z]/.test(a));
      const module = rest[i] === "-m" ? rest[i + 1] : rest[i]!.slice(2);
      const after = rest.slice(rest[i] === "-m" ? i + 2 : i + 1);
      if (module && /^(pip[\d.]*|uv|pipx|poetry|pipenv|pdm)$/.test(module)) nested(commandLineFrom([module.replace(/^pip[\d.]*$/, "pip"), ...after]));
    } else if (/^pip[\d.]*$/.test(cmd) && sub && ["install", "download", "wheel"].includes(sub)) {
      // pip download and pip wheel build source packages, which runs their setup code
      const a = attachedValues(args, ["-r", "-e", "-c"]);
      for (const file of flagValues(a, "-r", "--requirement")) requirements(`${cmd} ${sub} -r`, file);
      for (const e of flagValues(a, "-e", "--editable")) editable(e);
      for (const p of positional(a, "pip")) (localProject(p) ? projectInstall(p) : pip(p));
    } else if (cmd === "uv" && sub === "pip" && (args[0] === "install" || args[0] === "sync")) {
      const a = attachedValues(args.slice(1), ["-r", "-e", "-c"]);
      if (args[0] === "sync") {
        const file = positional(a, "uv")[0];
        if (file) requirements("uv pip sync", file);
      } else {
        for (const file of flagValues(a, "-r", "--requirements", "--requirement")) requirements("uv pip install -r", file);
        for (const e of flagValues(a, "-e", "--editable")) editable(e);
        positional(a, "uv").forEach(pip);
      }
    } else if (cmd === "uv" && sub === "add") {
      const a = attachedValues(args, ["-r"]);
      for (const file of flagValues(a, "-r", "--requirements")) requirements("uv add -r", file);
      positional(a, "uv").forEach(pip);
    } else if (cmd === "uv" && sub === "sync") lock("uv sync", "pypi", flagValue(args, "--directory", "--project"));
    else if (cmd === "uvx" || (cmd === "uv" && sub === "tool" && (args[0] === "run" || args[0] === "install"))) {
      // uvx x, uv tool run x, uv tool install x; --from / --with name the packages too
      const runArgs = cmd === "uvx" ? rest : args.slice(1);
      flagValues(runArgs, "--with", "-w", "--from").forEach((s) => s.split(",").forEach(pip));
      if (!flagValue(runArgs, "--from") || args[0] === "install") positional(runArgs, "uv").slice(0, 1).forEach(pip);
    } else if (cmd === "uv" && sub === "run") {
      // uv run syncs the project from uv.lock, then runs the command: --with adds packages for this run
      flagValues(args, "--with", "-w").forEach((s) => s.split(",").forEach(pip));
      lock("uv run", "pypi", flagValue(args, "--directory", "--project"));
      const cmdAt = commandStart(args, "uv");
      if (cmdAt >= 0) nested(commandLineFrom(args.slice(cmdAt)));
    } else if (cmd === "pipx" && sub && ["run", "install", "inject"].includes(sub)) {
      const names = positional(args, "uv");
      flagValues(args, "--spec").forEach(pip);
      (sub === "inject" ? names.slice(1) : sub === "run" ? names.slice(0, 1) : names).forEach(pip);
    } else if ((cmd === "poetry" || cmd === "pdm" || cmd === "rye") && sub === "add") positional(args, "poetry").forEach(pip);
    else if (cmd === "poetry" && sub && ["install", "sync", "update", "lock"].includes(sub) && sub !== "lock") lock(`poetry ${sub}`, "pypi", flagValue(args, "--directory", "-C", "--project", "-P"));
    else if (cmd === "pipenv" && sub && ["install", "sync", "update"].includes(sub)) {
      const a = attachedValues(args, ["-r"]);
      for (const file of flagValues(a, "-r", "--requirements")) requirements("pipenv install -r", file);
      const names = positional(a, "pip");
      names.forEach(pip);
      if (!names.length) lock(`pipenv ${sub}`, "pypi");
    } else if (["poetry", "pipenv", "pdm", "hatch", "rye", "bundle", "bundler"].includes(cmd) && (sub === "run" || sub === "exec")) {
      // poetry run pip install x, pipenv run …, bundle exec …: the command after run
      if (args.length) nested(commandLineFrom(args));
    } else if (cmd === "gem" && (sub === "install" || sub === "i")) {
      const a = attachedValues(args, ["-v", "-g"]);
      const gemfile = flagValue(a, "-g", "--file");
      if (gemfile !== undefined) lock("gem install -g", "rubygems", dirname(gemfile));
      const version = flagValue(a, "-v", "--version");
      positional(a, "gem").forEach((s) => spec("rubygems", s, (x) => gemSpec(x, version)));
    } else if ((cmd === "bundle" || cmd === "bundler") && sub === "add") {
      const version = flagValue(args, "-v", "--version");
      positional(args, "bundle").forEach((s) => spec("rubygems", s, (x) => gemSpec(x, version)));
    } else if ((cmd === "bundle" || cmd === "bundler") && (sub === undefined || ["install", "i", "update"].includes(sub))) {
      const gemfile = flagValue(args, "--gemfile") ?? vars.get("BUNDLE_GEMFILE");
      lock(`bundle ${sub ?? "install"}`, "rubygems", gemfile ? dirname(gemfile) : undefined);
    } else if (cmd === "composer" && sub && (["require", "req", "r"].includes(sub) || (sub === "global" && ["require", "req", "r"].includes(args[0] ?? "")))) {
      const list = positional(sub === "global" ? args.slice(1) : args, "composer");
      for (let i = 0; i < list.length; i++) {
        const s = list[i]!;
        const next = list[i + 1];
        // composer require vendor/pkg 5.0.2: a following word that is not a package is its version
        if (next !== undefined && !next.includes("/") && /^[\d^~<>=*v!|]/.test(next)) {
          spec("packagist", s, (x) => composerSpec(x, next));
          i++;
        } else spec("packagist", s, (x) => composerSpec(x));
      }
    } else if (cmd === "composer" && sub && ["install", "i", "update", "u", "upgrade"].includes(sub)) lock(`composer ${sub}`, "packagist", flagValue(args, "--working-dir", "-d"));
    else if (cmd === "composer" && sub === "create-project") {
      const [first, version] = positional(args, "composer");
      if (first) spec("packagist", first, (x) => composerSpec(x, version && /^[\d^~<>=*v]/.test(version) ? version : undefined));
    } else if (cmd === "cargo" && sub && ["add", "install", "binstall"].includes(sub)) {
      const git = flagValue(args, "--git");
      if (git) add({ ecosystem: "cargo", name: git, remote: true, spec: git });
      else if (!flagValue(args, "--path")) {
        const version = flagValue(args, "--version", "--vers");
        positional(args, "cargo").forEach((s) => {
          if (VAR_REF.test(s)) return add(unresolvedSpec("cargo", s));
          const r = cargoSpec(s);
          if (r && !r.version && version) Object.assign(r, constraintOf(version));
          add(r);
        });
      }
    } else if (cmd === "cargo" && sub && ["build", "b", "fetch", "run", "r", "test", "t", "check", "c", "clippy", "update", "doc", "d", "bench", "vendor"].includes(sub)) {
      const manifest = flagValue(args, "--manifest-path");
      lock(`cargo ${sub}`, "cargo", manifest ? dirname(manifest) : undefined);
    } else if (cmd === "go" && sub && ["get", "install"].includes(sub)) {
      const names = positional(args, "go");
      names.forEach((s) => spec("go", s, goSpec));
      if (!names.length) lock(`go ${sub}`, "go", flagValue(args, "-C"));
    } else if (cmd === "go" && sub === "run") {
      // go run pkg@version fetches and runs a module; go run . builds the local module with its go.mod
      const first = positional(args, "go")[0];
      if (first?.includes("@")) spec("go", first, goSpec);
      else lock("go run", "go", flagValue(args, "-C"));
    } else if (cmd === "go" && sub === "mod" && args[0] === "download") {
      const names = positional(args.slice(1), "go");
      names.forEach((s) => spec("go", s, goSpec));
      if (!names.length) lock("go mod download", "go", flagValue(args, "-C"));
    } else if (cmd === "go" && ((sub === "mod" && ["tidy", "vendor"].includes(args[0] ?? "")) || (sub && ["build", "test", "vet", "generate"].includes(sub)))) {
      lock(`go ${sub}`, "go", flagValue(args, "-C"));
    }
    // xargs npm i: the names come from stdin, which Foster cannot see
    if (stdin && found.length === before && /^(npm|pnpm|yarn|bun|npx|bunx|pnpx|pip3?|uv|uvx|pipx|poetry|cargo|go|gem|bundle|composer)$/.test(cmd)) {
      found.push(unresolvedSpec("npm", `${tokens.join(" ")} (package names read from stdin)`));
    }
  }
  // de-duplicate
  return {
    packages: [...new Map(found.map((r) => [`${r.ecosystem}:${r.name}@${r.version ?? r.range ?? ""}`, r])).values()],
    lockfiles: [...new Map(locked.map((l) => [`${l.ecosystem}:${l.dir}:${l.file ?? ""}`, l])).values()],
  };
}

/** The dependencies a lockfile install would put on disk. Empty when no lockfile is there. */
export function lockedDependencies(install: LockfileInstall): { files: string[]; deps: Dependency[] } {
  const locks: { dir: string; lock: LockfileInfo }[] = install.file
    ? [{ dir: dirname(resolve(install.dir, install.file)), lock: { file: basename(install.file), kind: "requirements", ecosystem: "pypi" } }]
    : detectLockfiles(install.dir)
        .filter((l) => l.ecosystem === install.ecosystem)
        .map((lock) => ({ dir: install.dir, lock }));
  const files: string[] = [];
  const deps: Dependency[] = [];
  for (const { dir, lock } of locks) {
    try {
      deps.push(...readDependencies(dir, lock));
      files.push(lock.file);
    } catch {
      // unreadable or missing: nothing to check
    }
  }
  return { files, deps };
}

// ---------------------------------------------------------------- decisions

const RANK: Record<Decision, number> = { allow: 0, ask: 1, deny: 2 };

export type Checker = (ecosystem: Ecosystem, name: string, version?: string) => Promise<CheckResult>;

export interface VerdictExtras {
  /** Answer from the real registry when the package index did not know the name. */
  existsOnRegistry?: boolean | null;
  /** A far more popular package this name closely resembles. */
  lookAlike?: LookAlike;
  /** Known malware reports (OSV / OpenSSF malicious-packages) for this package or version. */
  malware?: MalwareReport[];
  /** False when no version could be determined (the package index does not know it yet). */
  versionKnown?: boolean;
  /** Install-time code in a suspicious context (npm only). */
  installRisk?: InstallRisk | null;
}

function fmtRepos(n: number): string {
  return Intl.NumberFormat("en", { notation: "compact" }).format(n);
}

/** Decide about one package from a live check. */
export function verdictFor(requested: RequestedPackage, check: CheckResult, extras: VerdictExtras = {}): PackageVerdict {
  const label = `${requested.name}${requested.version ? `@${requested.version}` : ""} (${requested.ecosystem})`;
  const malware = extras.malware ?? [];
  if (malware.length) {
    const ids = malware.map((m) => m.id).join(", ");
    const what = malware[0]!.title;
    // Without a version we only know some releases were malicious, unless the report covers them all.
    if (extras.versionKnown === false && !malware.some((m) => m.wholePackage)) {
      return { requested, decision: "ask", reason: `Some releases of ${label} were malicious (${ids}: ${what}). Pin a version that is not affected: https://osv.dev/vulnerability/${malware[0]!.id}` };
    }
    return { requested, decision: "deny", reason: `${label} is known malware (${ids}: ${what}). Do not install it. If it is already installed, remove it and rotate any credentials and tokens this machine holds. Details: ${malware[0]!.url}` };
  }
  // Malware found by the version check outranks everything else, look-alike names included: a known
  // malicious package is a deny however it is reached (0.8.3 asked about crossenv as a cross-env typo).
  const malicious = check.findings.find((f) => f.kind === "malicious");
  if (malicious) {
    const first = malicious.advisories[0];
    return {
      requested,
      decision: "deny",
      reason: `${label} is known malware (${malicious.advisories.map((a) => `${a.id}: ${a.title}`).join("; ")}). Do not install it. If it is already installed, remove it and rotate any credentials and tokens this machine holds.${first?.url ? ` Details: ${first.url}` : ""}`,
    };
  }
  const base = baseVerdict(requested, check, extras, label);
  const risk = extras.installRisk;
  if (!risk || base.decision === "deny") return base;
  return { requested, decision: "ask", reason: base.decision === "allow" ? `${risk.reason}${base.note ? ` Also: ${base.note}` : ""}` : `${base.reason} Also: ${risk.reason}` };
}

function baseVerdict(requested: RequestedPackage, check: CheckResult, extras: VerdictExtras, label: string): PackageVerdict {
  const like = extras.lookAlike;
  const didYouMean = like ? ` Did you mean ${like.name} (used by ${fmtRepos(like.dependentRepos)} repositories)?` : impersonatesFoster(requested.ecosystem, requested.name) ? ` Did you mean ${FOSTER_PACKAGE} (Foster itself, on npm)?` : "";
  // Look-alikes of Foster itself: a name nobody has registered is blocked like any other missing name.
  if (impersonatesFoster(requested.ecosystem, requested.name) && !(check.notFound && extras.existsOnRegistry !== true)) {
    return { requested, decision: "ask", reason: fosterImpostorMessage(requested.ecosystem, requested.name) };
  }
  if (check.notFound) {
    if (extras.existsOnRegistry === true) {
      return { requested, decision: "ask", reason: `${label} exists but is brand new or almost unused: no package index tracks it yet. Make sure it is the package you mean.${didYouMean}` };
    }
    return { requested, decision: "deny", reason: `${label} does not exist on the registry. It may be a misspelled or hallucinated name; attackers register such names ("slopsquatting").${didYouMean || " Check the exact package name first."}` };
  }
  if (like) {
    return { requested, decision: "ask", reason: `${label} looks like a typo of a much more popular package: ${like.name} (used by ${fmtRepos(like.dependentRepos)} repositories; this one by ${fmtRepos(check.record?.dependentRepos ?? 0)}). Look-alike names are a common way to slip in malware. Install it only if this is really the package you want.` };
  }
  const alt = check.alternatives ? ` Maintained alternatives: ${describeAlternatives(check.alternatives)}.` : "";
  const finding = check.findings[0];
  if (finding?.kind === "patch-available" && finding.patch) {
    return { requested, decision: "ask", reason: `${label} has ${listIds(finding.advisories.map((a) => a.id))} with no upstream fix. A drop-in patch exists: ${finding.patch.replacement.name}@${finding.patch.replacement.version} (run \`npx foster-oss@latest fix\` after installing).${alt}` };
  }
  if (finding?.kind === "orphaned-vulnerable" || finding?.kind === "unpatched-vulnerable") {
    const status = check.record?.status ?? "unknown";
    const reason = `${label} has security advisories that no release fixes (${listIds(finding.advisories.map((a) => `${a.id} ${a.severity}`))}); maintenance: ${status}.${alt}`;
    // a dependency the project already chose (installing a fresh clone) is reported, not blocked:
    // `foster-oss scan` covers it, and blocking the whole install leaves nobody able to work on the project
    if (requested.fromManifest) return { requested, decision: "allow", reason, note: reason };
    return { requested, decision: "deny", reason };
  }
  if (finding?.kind === "upgrade-available") {
    const reason = `${label} is vulnerable (${listIds(finding.advisories.map((a) => a.id))}); ${finding.fixedIn ? `version ${finding.fixedIn} fixes it` : "a newer release fixes it"}. Install a fixed version instead.`;
    // From a project's own package.json the dependency is already chosen: asking on every install is
    // noise. `foster-oss scan` reports it; here it is a note.
    if (requested.fromManifest) return { requested, decision: "allow", reason, note: reason };
    return { requested, decision: "ask", reason };
  }
  const status = check.record?.status;
  if (status === "dead" || status === "dormant") {
    // Maintenance is not a security problem today: say so, but do not stop the install (CI has nobody to ask).
    const note = `${label} looks ${status} (${check.record!.reasons.join("; ")}). Nobody may fix future security problems.${alt || " Prefer a maintained package if one exists."}`;
    return { requested, decision: "allow", reason: note, note };
  }
  return { requested, decision: "allow", reason: `${label}: ok` };
}

/** Network lookups guard makes besides the package check; replaceable for tests. */
export interface GuardProbes {
  malware: (ecosystem: Ecosystem, name: string, version?: string) => Promise<MalwareReport[]>;
  installRisk: (name: string, version: string | undefined, record: CheckResult["record"]) => Promise<InstallRisk | null>;
  /** Resolve an npm range or dist-tag to the version npm would pick. */
  resolveRange: (name: string, range: string, latestKnown: string | null) => Promise<string | undefined>;
  /** Known malware among locked dependencies. */
  lockfileMalware: (deps: Dependency[]) => Promise<LockedMalware[]>;
}

export interface GuardOptions extends Partial<GuardProbes> {
  /** Directory the command runs in: where lockfile installs read their lockfile. */
  cwd?: string;
}

const LIVE_PROBES: GuardProbes = {
  // With a version, the package check already asked OSV (it reports malware as a "malicious" finding):
  // a second query per package would double the requests. Without one, ask about the package as a whole.
  malware: (e, n, v) => (v ? Promise.resolve([]) : malwareReports(e, n)),
  installRisk: (n, v, r) => npmInstallRisk(n, v, r),
  resolveRange: (n, range, latest) => resolveNpmVersion(n, range, latest),
  lockfileMalware,
};

/** npm replaces removed malware with an empty "0.0.1-security" placeholder. */
const SECURITY_PLACEHOLDER = /^0\.0\.\d+-security(\.\d+)?$/;

function readManifest(dir: string): Record<string, unknown> | null {
  try {
    return JSON.parse(readFileSync(join(dir, "package.json"), "utf8").replace(/^﻿/, "")) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** Workspace patterns of a monorepo root: package.json "workspaces" (npm, yarn, bun) and pnpm-workspace.yaml. */
function workspacePatterns(dir: string, pkg: Record<string, unknown>): string[] {
  const ws = pkg.workspaces;
  const out: string[] = Array.isArray(ws) ? ws.filter((x): x is string => typeof x === "string") : [];
  if (ws && typeof ws === "object" && !Array.isArray(ws) && Array.isArray((ws as { packages?: unknown }).packages)) {
    out.push(...((ws as { packages: unknown[] }).packages.filter((x): x is string => typeof x === "string")));
  }
  const packages = pnpmWorkspace(dir).packages;
  if (Array.isArray(packages)) out.push(...packages.filter((x): x is string => typeof x === "string"));
  return out.flatMap(expandBraces);
}

/** pnpm-workspace.yaml: packages, and (pnpm 9+/10) overrides and catalogs. Empty when there is none. */
function pnpmWorkspace(dir: string): { packages?: unknown; overrides?: unknown; catalog?: unknown; catalogs?: unknown } {
  try {
    const doc = YAML.parse(readFileSync(join(dir, "pnpm-workspace.yaml"), "utf8")) as unknown;
    return doc && typeof doc === "object" ? (doc as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/** "packages/{a,b}" → packages/a, packages/b (nested braces too). */
function expandBraces(pattern: string): string[] {
  const m = /\{([^{}]*)\}/.exec(pattern);
  if (!m) return [pattern];
  return m[1]!.split(",").flatMap((alt) => expandBraces(pattern.slice(0, m.index) + alt + pattern.slice(m.index + m[0].length)));
}

/** Expand workspace globs ("apps/*", "packages/**", "tools/cli") to folders with a package.json. */
export function workspaceDirs(root: string, patterns: string[]): string[] {
  const excluded = patterns.filter((p) => p.startsWith("!")).map((p) => globRegex(p.slice(1)));
  const found = new Set<string>();
  const walk = (dir: string, parts: string[], depth: number) => {
    if (depth > 6) return;
    if (parts.length === 0) {
      if (existsSync(join(dir, "package.json"))) found.add(dir);
      return;
    }
    const [head, ...tail] = parts as [string, ...string[]];
    if (head === "**") {
      walk(dir, tail, depth);
      for (const e of subdirs(dir)) walk(join(dir, e), parts, depth + 1);
    } else if (head.includes("*")) {
      const re = new RegExp(`^${head.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`);
      for (const e of subdirs(dir)) if (re.test(e)) walk(join(dir, e), tail, depth + 1);
    } else walk(join(dir, head), tail, depth + 1);
  };
  for (const p of patterns) if (!p.startsWith("!")) walk(root, p.replace(/^\.\//, "").replace(/\/$/, "").split("/").filter(Boolean), 0);
  return [...found].filter((d) => {
    const rel = relative(root, d).replace(/\\/g, "/");
    return !excluded.some((re) => re.test(rel));
  });
}

/** "packages/**" / "apps/*" / "tools/cli" as a regex over a relative folder path. */
function globRegex(pattern: string): RegExp {
  const p = pattern.replace(/^\.\//, "").replace(/\/$/, "");
  let re = "";
  for (let i = 0; i < p.length; i++) {
    const ch = p[i]!;
    if (ch === "*" && p[i + 1] === "*") {
      re += p[i + 2] === "/" ? "(?:.*/)?" : ".*";
      i += p[i + 2] === "/" ? 2 : 1;
    } else if (ch === "*") re += "[^/]*";
    else re += /[.+?^${}()|[\]\\]/.test(ch) ? `\\${ch}` : ch;
  }
  return new RegExp(`^${re}$`);
}

function subdirs(dir: string): string[] {
  try {
    return readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isDirectory() && e.name !== "node_modules" && !e.name.startsWith("."))
      .map((e) => e.name);
  } catch {
    return [];
  }
}

/**
 * What `npm install` (or pnpm, yarn, bun) resolves from package.json when there is no lockfile it can
 * read: a fresh clone, a new project, or bun's binary bun.lockb. In a monorepo root, every workspace's
 * dependencies are installed too, so they are included. Local folders and the workspaces themselves
 * (`workspace:*`, or a dependency on another workspace by name) are skipped.
 */
export function manifestPackages(dir: string, why = "no lockfile"): RequestedPackage[] {
  const root = readManifest(dir);
  if (!root) return [];
  const manifests: { rel: string; pkg: Record<string, unknown> }[] = [{ rel: "package.json", pkg: root }];
  for (const ws of workspaceDirs(dir, workspacePatterns(dir, root))) {
    const pkg = readManifest(ws);
    if (pkg) manifests.push({ rel: `${relative(dir, ws).replace(/\\/g, "/")}/package.json`, pkg });
  }
  const internal = new Set(manifests.map((m) => m.pkg.name).filter((n): n is string => typeof n === "string"));
  const out = new Map<string, RequestedPackage>();
  const ws = pnpmWorkspace(dir);
  // pnpm catalogs: "react": "catalog:" takes its spec from pnpm-workspace.yaml
  const fromCatalog = (name: string, spec: string): string | null => {
    const which = spec.slice("catalog:".length) || "default";
    const table = (which === "default" ? (ws.catalog ?? (ws.catalogs as Record<string, unknown> | undefined)?.default) : (ws.catalogs as Record<string, unknown> | undefined)?.[which]) as Record<string, unknown> | undefined;
    const value = table?.[name];
    return typeof value === "string" ? value : null;
  };
  const addDep = (name: string, rawSpec: string, where: string) => {
    if (internal.has(name)) return;
    const spec = rawSpec.startsWith("catalog:") ? fromCatalog(name, rawSpec) : rawSpec;
    if (spec === null) return;
    if (/^(file:|link:|workspace:|portal:|patch:|\.{0,2}\/|~\/|\$|-$)/.test(spec)) return;
    const key = `${name}@${spec}`;
    if (out.has(key)) return;
    const remote = REMOTE.test(spec) || /^[\w.-]+\/[\w.-]+(#.*)?$/.test(spec);
    const r: RequestedPackage | null = remote ? { ecosystem: "npm", name, remote: true, spec } : npmSpec(key);
    if (r) out.set(key, { ...r, fromManifest: true, spec: `${key} (${where}, ${why})` });
  };
  for (const { rel, pkg } of manifests) {
    // npm 7+ and pnpm 8+ install peer dependencies too, except the ones peerDependenciesMeta marks optional
    const optionalPeers = new Set(
      Object.entries((pkg.peerDependenciesMeta ?? {}) as Record<string, { optional?: boolean } | undefined>)
        .filter(([, meta]) => meta?.optional === true)
        .map(([name]) => name),
    );
    for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      const deps = pkg[field];
      if (!deps || typeof deps !== "object") continue;
      for (const [name, spec] of Object.entries(deps as Record<string, unknown>)) {
        if (typeof spec !== "string" || (field === "peerDependencies" && optionalPeers.has(name))) continue;
        addDep(name, spec, rel);
      }
    }
  }
  // Overrides replace what a dependency installs, and only the root's count: "ms": "npm:crossenv@…"
  // installs crossenv under the name ms. Check the replacement like any other dependency.
  for (const [name, spec, field] of overrideEntries(root)) addDep(name, spec, `package.json ${field}`);
  // pnpm 10 keeps overrides in pnpm-workspace.yaml
  if (ws.overrides && typeof ws.overrides === "object") {
    for (const [k, v] of Object.entries(ws.overrides as Record<string, unknown>)) if (typeof v === "string") addDep(overrideTarget(k, "pnpm"), v, "pnpm-workspace.yaml overrides");
  }
  return [...out.values()];
}

/**
 * What a Python, Rust, PHP or Ruby install resolves from the project's manifest when it has no lockfile
 * (or reads the manifest by design, as `pip install .` does): pyproject.toml/Pipfile, Cargo.toml,
 * composer.json, Gemfile. Names only; each is checked at the version the registry would hand out.
 */
export function otherManifestPackages(dir: string, ecosystem: Ecosystem, why = "no lockfile"): RequestedPackage[] {
  let names: Iterable<string> = [];
  let file = "";
  if (ecosystem === "pypi") {
    names = directPythonNames(dir);
    file = existsSync(join(dir, "pyproject.toml")) ? "pyproject.toml" : "Pipfile";
  } else if (ecosystem === "cargo") {
    names = directCargoNames(dir);
    file = "Cargo.toml";
  } else if (ecosystem === "packagist") {
    names = [...directComposerNames(dir)].filter((n) => n.includes("/") && !/^(php|ext-|lib-|composer\/)/.test(n));
    file = "composer.json";
  } else if (ecosystem === "rubygems") {
    file = "Gemfile";
    try {
      names = [...readFileSync(join(dir, "Gemfile"), "utf8").matchAll(/^\s*gem\s+["']([^"']+)["']/gm)].map((m) => m[1]!);
    } catch {
      names = [];
    }
  }
  return [...new Set(names)].map((name) => ({ ecosystem, name, fromManifest: true, spec: `${name} (${file}, ${why})` }));
}

/**
 * Packages the root package.json's install scripts would install: "postinstall": "npm i x" runs on
 * every `npm install` in the project, after the dependencies.
 */
export function lifecyclePackages(dir: string): RequestedPackage[] {
  const scripts = readManifest(dir)?.scripts;
  if (!scripts || typeof scripts !== "object") return [];
  const out: RequestedPackage[] = [];
  for (const hook of ["preinstall", "install", "postinstall", "prepare"]) {
    const script = (scripts as Record<string, unknown>)[hook];
    if (typeof script !== "string") continue;
    for (const r of parseCommand(script, dir, 1).packages) out.push({ ...r, spec: `${r.spec} (package.json "${hook}" script)` });
  }
  return out;
}

/** The package a key of npm overrides, yarn resolutions or pnpm overrides applies to ("**\/a/ms@^1" → ms). */
function overrideTarget(key: string, style: "npm" | "yarn" | "pnpm"): string {
  let k = key;
  if (style === "pnpm") k = k.split(">").pop()!;
  if (style === "yarn") {
    const parts = k.split("/");
    k = parts.length >= 2 && parts[parts.length - 2]!.startsWith("@") ? parts.slice(-2).join("/") : parts[parts.length - 1]!;
  }
  const at = k.lastIndexOf("@");
  return at > 0 ? k.slice(0, at) : k;
}

/** [package, replacement spec, field] for every override in a root package.json. */
export function overrideEntries(pkg: Record<string, unknown>): [string, string, string][] {
  const out: [string, string, string][] = [];
  const npm = (obj: unknown, parent?: string) => {
    if (!obj || typeof obj !== "object") return;
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      if (k === ".") {
        if (parent && typeof v === "string") out.push([parent, v, "overrides"]);
        continue;
      }
      const name = overrideTarget(k, "npm");
      if (typeof v === "string") out.push([name, v, "overrides"]);
      else npm(v, name); // nested: overrides that apply below this package
    }
  };
  npm(pkg.overrides);
  const flat = (obj: unknown, style: "yarn" | "pnpm", field: string) => {
    if (!obj || typeof obj !== "object") return;
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) if (typeof v === "string") out.push([overrideTarget(k, style), v, field]);
  };
  flat(pkg.resolutions, "yarn", "resolutions");
  const pnpm = pkg.pnpm as { overrides?: unknown } | undefined;
  flat(pnpm?.overrides, "pnpm", "pnpm.overrides");
  return out;
}

/**
 * Manifest packages the lockfile does not satisfy: the name is missing, or no locked copy has the
 * pinned version or one inside the requested range. These are what a non-frozen install would fetch.
 */
export function unlocked(pkgs: RequestedPackage[], deps: Dependency[]): RequestedPackage[] {
  const versions = new Map<string, string[]>();
  for (const d of deps) versions.set(d.name, [...(versions.get(d.name) ?? []), d.version]);
  return pkgs.filter((p) => {
    const have = versions.get(p.name);
    if (!have) return true;
    if (p.remote) return false;
    if (p.version) return !have.includes(p.version);
    if (p.range && semver.validRange(p.range)) return !have.some((v) => semver.valid(v) && semver.satisfies(v, p.range!, { includePrerelease: true }));
    return false; // a dist-tag or something npm resolves itself: the locked copy stays
  });
}

/** At most this many look-alike names in one lockfile are confirmed online. */
const MAX_LOCK_SUSPECTS = 60;

interface LockSquat {
  dependency: Dependency;
  /** The name does not exist on the registry at all. */
  missing: boolean;
  like?: LookAlike;
  ownRepos?: number | null;
}

/**
 * Names in a lockfile that look like a typo of a popular package. The first pass is offline (the
 * popular-package list); only those few are looked up: does the name exist, and how widely is it used?
 */
async function lockfileSquats(deps: Dependency[], check: Checker, exists: (e: Ecosystem, n: string) => Promise<boolean | null>): Promise<{ squats: LockSquat[]; unchecked: number }> {
  const all = [...new Map(deps.filter((d) => lookAlike(d.ecosystem, d.name)).map((d) => [`${d.ecosystem}:${d.name}`, d])).values()];
  const suspects = all.slice(0, MAX_LOCK_SUSPECTS);
  const found = await mapLimit(suspects, 4, async (d): Promise<LockSquat | null> => {
    try {
      const res = await check(d.ecosystem, d.name);
      if (res.notFound) {
        const there = await exists(d.ecosystem, d.name);
        if (there === false) return { dependency: d, missing: true, like: lookAlike(d.ecosystem, d.name) };
        if (there === null) return null;
      }
      const ownRepos = res.notFound ? 0 : res.record?.dependentRepos;
      const like = lookAlike(d.ecosystem, d.name, ownRepos, res.record?.downloadsLastMonth);
      return like ? { dependency: d, missing: false, like, ownRepos } : null;
    } catch {
      return null; // fail open
    }
  });
  return { squats: found.filter((x): x is LockSquat => x !== null), unchecked: all.length - suspects.length };
}

async function checkLockfileInstall(
  install: LockfileInstall,
  probe: GuardProbes,
  check: Checker,
  exists: (e: Ecosystem, n: string) => Promise<boolean | null>,
): Promise<{ verdict: PackageVerdict | null; count: number }> {
  const { files, deps } = lockedDependencies(install);
  if (deps.length === 0) return { verdict: null, count: 0 };
  const requested: RequestedPackage = { ecosystem: install.ecosystem, name: files.join(", "), spec: install.tool };
  const where = `${install.tool} (${files.join(", ")})`;
  let failed: string | null = null;
  const [hits, { squats, unchecked }] = await Promise.all([
    probe.lockfileMalware(deps).catch((err: Error) => ((failed = err.message), [] as LockedMalware[])),
    lockfileSquats(deps, check, exists),
  ]);
  const reasons: string[] = [];
  let decision: Decision = "allow";
  // npm's empty "0.0.1-security" placeholders replace a removed malicious package: nothing runs, so they are a note
  const placeholders = hits.filter((h) => SECURITY_PLACEHOLDER.test(h.dependency.version));
  const realHits = hits.filter((h) => !SECURITY_PLACEHOLDER.test(h.dependency.version));
  if (realHits.length) {
    decision = "deny";
    const list = [...new Map(realHits.map((h) => [`${h.dependency.name}@${h.dependency.version}`, h])).values()];
    const shown = list
      .slice(0, 5)
      .map((h) => `${h.dependency.name}@${h.dependency.version} (${h.report.id}: ${h.report.title})`)
      .join("; ");
    reasons.push(`${where} would install known malware: ${shown}${list.length > 5 ? `; and ${list.length - 5} more` : ""}. Remove it from the manifest and the lockfile first, then rotate any credentials this machine or CI holds. \`npx foster-oss@latest scan\` lists every finding.`);
  }
  const missing = squats.filter((s) => s.missing);
  if (missing.length) {
    decision = "deny";
    const shown = missing.map((s) => `${s.dependency.name}@${s.dependency.version}${s.like ? ` (did you mean ${s.like.name}?)` : ""}`).join(", ");
    reasons.push(`${where} pins package names that do not exist on the registry: ${shown}. Anyone can register such a name and ship malware under it ("slopsquatting"). Fix the name in the manifest and regenerate the lockfile.`);
  }
  const alike = squats.filter((s) => !s.missing && s.like);
  if (alike.length) {
    if (decision === "allow") decision = "ask";
    const shown = alike
      .map((s) => `${s.dependency.name}@${s.dependency.version} looks like ${s.like!.name} (used by ${fmtRepos(s.like!.dependentRepos)} repositories; this one by ${fmtRepos(s.ownRepos ?? 0)})`)
      .join("; ");
    reasons.push(`${where} pins look-alike names of popular packages: ${shown}. Make sure these are the packages you mean.`);
  }
  if (decision !== "allow") return { verdict: { requested, decision, reason: reasons.join(" ") }, count: deps.length };
  const reason = failed ? `${where}: could not be checked for malware (${failed})` : `${where}: ${deps.length} locked packages, no known malware or look-alike names`;
  const placeholderNote = placeholders.length
    ? `${where} lists npm's empty placeholder for a removed malicious package: ${[...new Set(placeholders.map((h) => h.dependency.name))].join(", ")}. It installs nothing, but whatever depends on it once named the malware: remove that dependency.`
    : undefined;
  const lookups = unchecked ? `${where}: ${unchecked} more look-alike name(s) were not looked up (limit ${MAX_LOCK_SUSPECTS} per lockfile). Run \`foster-oss scan\` for the full picture.` : undefined;
  const note = [failed ? reason : undefined, placeholderNote, lookups].filter(Boolean).join(" ") || undefined;
  return { verdict: { requested, decision: "allow", reason, ...(note ? { note } : {}), ...(failed ? { unchecked: true } : {}) }, count: deps.length };
}

/**
 * The module a Go package path belongs to: the path itself when the module proxy knows it, else the
 * longest parent it knows (golang.org/x/tools/cmd/goimports -> golang.org/x/tools). When no parent is
 * known either, the path is returned as given, so it is reported as not found.
 */
export async function goModuleOf(path: string, exists: (e: Ecosystem, n: string) => Promise<boolean | null>): Promise<string> {
  if ((await exists("go", path)) !== false) return path;
  const parts = path.split("/");
  for (let n = parts.length - 1; n >= 2; n--) {
    const parent = parts.slice(0, n).join("/");
    if ((await exists("go", parent)) === true) return parent;
  }
  return path;
}

export async function guardCommand(
  line: string,
  check: Checker = checkPackage,
  exists: (ecosystem: Ecosystem, name: string) => Promise<boolean | null> = existsOnRegistry,
  options: GuardOptions = {},
): Promise<GuardResult> {
  const { cwd, ...probes } = options;
  const probe: GuardProbes = { ...LIVE_PROBES, ...probes };
  const parsed = parseCommand(line, cwd);
  const requested = [...parsed.packages];
  const lockfiles: LockfileInstall[] = [];
  // Packages named on the command line are checked as such; the project's own copy of them is not.
  const named = new Set(parsed.packages.map((p) => `${p.ecosystem}:${p.name}`));
  const notNamed = (p: RequestedPackage) => !named.has(`${p.ecosystem}:${p.name}`);
  for (const install of parsed.lockfiles) {
    const lockedNpm = install.ecosystem === "npm" && !install.file ? lockedDependencies(install) : null;
    // the root's preinstall/install/postinstall/prepare scripts run on a project install
    if (install.ecosystem === "npm" && !install.file) requested.push(...lifecyclePackages(install.dir).filter(notNamed));
    // pip install . reads pyproject.toml; poetry/composer/cargo/bundle without a lockfile resolve the manifest
    if (install.ecosystem !== "npm" && !install.file && (install.manifest || lockedDependencies(install).files.length === 0)) {
      requested.push(...otherManifestPackages(install.dir, install.ecosystem, install.manifest ? "installed from the project" : "no lockfile").filter(notNamed));
      if (install.manifest) continue;
    }
    // No lockfile npm/pnpm/yarn/bun can read: they resolve package.json instead, so check those packages.
    if (lockedNpm && lockedNpm.files.length === 0) {
      requested.push(...manifestPackages(install.dir).filter(notNamed));
      continue;
    }
    // "npm install x" is checked for x; the lockfile it keeps needs no second malware scan.
    if (!install.named) lockfiles.push(install);
    // A plain install rewrites a stale lockfile from package.json (a merge that added a dependency, a new
    // workspace, a version bump): check what it would add or change.
    if (lockedNpm && !install.frozen) requested.push(...unlocked(manifestPackages(install.dir, "not in the lockfile yet"), lockedNpm.deps).filter(notNamed));
  }
  // Packages are checked in parallel (a few at a time): guard runs before every install.
  const width = requested.length > 30 ? 16 : requested.length > 8 ? 8 : 4;
  // 0. "go install golang.org/x/tools/cmd/goimports" names a package inside a module: check the module.
  await mapLimit(requested, width, async (r, i) => {
    if (r.ecosystem !== "go" || r.remote || r.unresolved) return;
    const mod = await goModuleOf(r.name, exists);
    if (mod !== r.name) requested[i] = { ...r, name: mod };
  });
  // 1. Which version each package would install: pinned, the range's best match, else the latest release.
  const resolved = await mapLimit(requested, width, async (r): Promise<{ version?: string; first?: CheckResult; error?: Error }> => {
    if (r.remote || r.unresolved || r.version) return { version: r.version };
    try {
      const first = await check(r.ecosystem, r.name);
      if (first.notFound) return { first };
      // a range outside npm (pip >=1, composer ^5, gem ~> 1): Foster cannot tell which release it picks, so
      // known malware in any release counts (checked without a version below)
      if (r.range && r.ecosystem !== "npm") return { first };
      let target = first.record?.latestVersion ?? undefined;
      if (r.range && r.ecosystem === "npm") target = (await probe.resolveRange(r.name, r.range, target ?? null).catch(() => undefined)) ?? target;
      return { version: target, first };
    } catch (err) {
      return { error: err as Error };
    }
  });
  // 2. One OSV request for all of them; the per-package checks below then find their answers cached.
  if (check === checkPackage) {
    const deps = requested.flatMap((r, i) => (!r.remote && !r.unresolved && resolved[i]!.version ? [{ ecosystem: r.ecosystem, name: r.name, version: resolved[i]!.version!, direct: true, source: "guard" }] : []));
    if (deps.length > 1) await queryBatch(deps).catch(() => undefined);
  }
  // 3. The checks themselves.
  const verdicts = await mapLimit(requested, width, async (r, i): Promise<PackageVerdict> => {
    if (r.remote) {
      return { requested: r, decision: "ask", reason: `${r.spec} is installed straight from a URL or git repository: no registry or advisory database covers it, so Foster cannot check it. Install it only from a source you trust.` };
    }
    if (r.unresolved) {
      return {
        requested: r,
        decision: "ask",
        reason: `${r.spec}: the command installs something Foster cannot see (a shell variable, command substitution, names read from stdin, or a command nested too deep), so it cannot be checked. Write the package names out in the command, or check them first with \`foster-oss check <name>\`.`,
      };
    }
    try {
      const pre = resolved[i]!;
      if (pre.error) throw pre.error;
      const version = pre.version;
      const result = version ? await check(r.ecosystem, r.name, version) : pre.first!;
      const extras: VerdictExtras = { lookAlike: lookAlike(r.ecosystem, r.name, result.record?.dependentRepos, result.record?.downloadsLastMonth) };
      if (result.notFound) extras.existsOnRegistry = await exists(r.ecosystem, r.name);
      if (!(result.notFound && extras.existsOnRegistry === false)) {
        extras.versionKnown = version !== undefined;
        // Both lookups fail open: a slow registry must not block an install.
        const [malware, installRisk] = await Promise.all([
          probe.malware(r.ecosystem, r.name, version).catch(() => [] as MalwareReport[]),
          r.ecosystem === "npm" ? probe.installRisk(r.name, r.version ?? (r.range ? version : undefined), result.record).catch(() => null) : Promise.resolve(null),
        ]);
        extras.malware = malware;
        extras.installRisk = installRisk;
      }
      const shown = r.range && version ? { ...r, version } : r;
      return { ...verdictFor(shown, result, extras), requested: r };
    } catch (err) {
      // Fail open: a network problem must not block development, but say so. Known malware is still
      // looked up on its own (OSV), so a package index that is down does not let it through.
      const reason = `${r.name} (${r.ecosystem}): could not be checked (${(err as Error).message.slice(0, 160)})`;
      const malware = await probe.malware(r.ecosystem, r.name).catch(() => [] as MalwareReport[]);
      if (malware.length) return { ...verdictFor(r, { ecosystem: r.ecosystem, name: r.name, record: null, findings: [], notFound: false }, { malware, versionKnown: false }), requested: r };
      return { requested: r, decision: "allow", reason, note: reason, unchecked: true };
    }
  });
  let lockedCount = 0;
  for (const install of lockfiles) {
    const { verdict, count } = await checkLockfileInstall(install, probe, check, exists);
    lockedCount += count;
    if (verdict) verdicts.push(verdict);
  }
  const decision = verdicts.reduce<Decision>((d, v) => (RANK[v.decision] > RANK[d] ? v.decision : d), "allow");
  const flagged = verdicts.filter((v) => v.decision !== "allow");
  const notChecked = verdicts.filter((v) => v.unchecked).length;
  const checked = [requested.length ? `${requested.length} package(s) checked` : "", lockedCount ? `${lockedCount} locked package(s) checked for known malware and look-alike names` : ""].filter(Boolean);
  const notes = verdicts.filter((v) => v.decision === "allow" && v.note).map((v) => `- ${v.note}`);
  const head =
    flagged.length === 0
      ? checked.length
        ? notChecked
          ? `Foster guard: could not check ${notChecked} of ${requested.length + lockfiles.length} (network problem). Nothing else to flag, but that part is unverified: treat it like an ask.`
          : `Foster guard: ${checked.join(", ")}, nothing to flag.`
        : "Foster guard: no package installs in this command."
      : `Foster guard ${decision === "deny" ? "blocked" : "flagged"} this install:\n${flagged.map((v) => `- ${v.reason}`).join("\n")}`;
  // Notes do not stop the install; they say what is worth a look later. A few, not a wall of text.
  const MAX_NOTES = 5;
  const more = notes.length > MAX_NOTES ? `\n- …and ${notes.length - MAX_NOTES} more. \`npx foster-oss@latest scan --all\` lists them.` : "";
  const message = notes.length ? `${head}\nNote (not blocking):\n${notes.slice(0, MAX_NOTES).join("\n")}${more}` : head;
  return { decision, verdicts, message };
}

/**
 * guardCommand with a deadline: a blackholed network must not hold an agent for minutes. Past the
 * deadline it fails open and says that nothing was verified (`timedOut`).
 */
export async function guardWithin(line: string, options: GuardOptions = {}, ms = 30_000): Promise<GuardResult & { timedOut?: boolean }> {
  let timer: NodeJS.Timeout | undefined;
  const late = new Promise<GuardResult & { timedOut: boolean }>((done) => {
    timer = setTimeout(
      () =>
        done({
          decision: "allow",
          verdicts: [],
          timedOut: true,
          message: `Foster guard: could not finish checking within ${Math.round(ms / 1000)} s (slow or blocked network). Nothing was verified: treat it like an ask.`,
        }),
      ms,
    );
    timer.unref();
  });
  try {
    return await Promise.race([guardCommand(line, checkPackage, existsOnRegistry, options), late]);
  } finally {
    clearTimeout(timer);
  }
}

/** Does this command install anything Foster can check? Cheap: no network. */
export function installsSomething(line: string, cwd?: string): boolean {
  const { packages, lockfiles } = parseCommand(line, cwd);
  return packages.length > 0 || lockfiles.length > 0;
}
