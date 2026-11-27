import { readFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { checkPackage, type CheckResult } from "./check.js";
import { mapLimit } from "./http.js";
import { detectLockfiles, readDependencies, type LockfileInfo } from "./lockfile.js";
import { npmInstallRisk, resolveNpmVersion, type InstallRisk } from "./npmrisk.js";
import { lockfileMalware, malwareReports, type LockedMalware, type MalwareReport } from "./osv.js";
import { describeAlternatives } from "./replacements.js";
import type { Dependency, Ecosystem } from "./types.js";
import { existsOnRegistry, lookAlike, type LookAlike } from "./typosquat.js";

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
}

export type Decision = "allow" | "ask" | "deny";

export interface PackageVerdict {
  requested: RequestedPackage;
  decision: Decision;
  reason: string;
}

export interface GuardResult {
  decision: Decision;
  verdicts: PackageVerdict[];
  /** One message suitable for showing to an agent or a person. */
  message: string;
}

// ---------------------------------------------------------------- command parsing

/** Split a shell line into simple commands (on ;, &&, ||, |, newlines) and tokens, honouring quotes. */
export function splitCommands(line: string): string[][] {
  const commands: string[][] = [];
  let tokens: string[] = [];
  let cur = "";
  let quote: '"' | "'" | null = null;
  let hasToken = false;
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
    // "\x" unquoted escapes x, except in Windows paths (C:\Users\me), where the backslash is a separator
    if (ch === "\\" && i + 1 < line.length && line[i + 1] !== "\n" && !/[A-Za-z0-9_.~-]/.test(line[i + 1]!)) {
      cur += line[++i];
      hasToken = true;
      continue;
    }
    if (ch === "\n" || ch === ";" || ch === "|" || (ch === "&" && line[i + 1] === "&")) {
      if (ch === "&" || (ch === "|" && line[i + 1] === "|")) i++;
      pushCommand();
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
  return commands;
}

/** Flags that take a value, per tool, so the value is not mistaken for a package name. */
const VALUE_FLAGS: Record<string, string[]> = {
  npm: ["--registry", "--prefix", "-C", "--tag", "--workspace", "-w", "--save-prefix", "--cache", "--userconfig", "--omit", "--include"],
  pnpm: ["--filter", "-F", "--dir", "-C", "--registry", "--workspace"],
  yarn: ["--cwd", "--registry"],
  bun: ["--cwd", "--registry", "--backend"],
  pip: ["-i", "--index-url", "--extra-index-url", "-f", "--find-links", "-c", "--constraint", "-t", "--target", "--prefix", "--root", "--python", "--platform", "--trusted-host", "--src", "--upgrade-strategy", "--only-binary", "--no-binary", "-r", "--requirement", "-e", "--editable"],
  uv: ["--index", "--index-url", "--extra-index-url", "--python", "-p", "--group", "--optional", "--package", "-r", "--requirements", "-e", "--editable", "--directory", "--project", "--find-links", "-f"],
  poetry: ["--group", "-G", "--source", "--extras", "-E", "--python", "--directory", "-C"],
  cargo: ["--features", "-F", "--package", "-p", "--path", "--git", "--branch", "--tag", "--rev", "--registry", "--rename", "--target", "--manifest-path", "--version", "--root"],
  go: ["-C", "-modfile", "-tags"],
  gem: ["-v", "--version", "-s", "--source", "-i", "--install-dir", "--platform"],
  bundle: ["--version", "-v", "--group", "-g", "--source", "-s", "--git", "--github", "--branch", "--ref", "--path"],
  composer: ["--working-dir", "-d"],
};

function positional(args: string[], tool: string): string[] {
  const valueFlags = new Set(VALUE_FLAGS[tool] ?? []);
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
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    for (const n of names) {
      if (a === n) return args[i + 1];
      if (a.startsWith(`${n}=`)) return a.slice(n.length + 1);
    }
  }
  return undefined;
}

const LOCAL_OR_URL = /^(\.{0,2}\/|~\/|[a-zA-Z]:\\|file:|link:|workspace:|git(\+|:)|https?:|github:|gitlab:|bitbucket:|ssh:)|\.(tgz|tar\.gz|whl|zip|gem)$/i;

/** Code fetched from a URL or a git host, not from the registry. */
const REMOTE = /^(git(\+[a-z]+)?:|git@|https?:\/\/|github:|gitlab:|bitbucket:|ssh:\/\/)/i;
/** A tarball on the npm registry itself names the package and version: check those. */
const NPM_TARBALL = /^https?:\/\/registry\.(?:npmjs\.org|yarnpkg\.com)\/((?:@[^/]+\/)?[^/]+)\/-\/[^/]+?-(\d+\.\d+\.\d+[^/]*?)\.tgz$/i;
const NPM_NAME = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i;

function npmSpec(spec: string): RequestedPackage | null {
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
  const version = exact(raw);
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
  if (LOCAL_OR_URL.test(spec) || spec.includes("://") || spec.startsWith("-")) return null;
  const m = spec.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(?:(===?)\s*([^\s;,]+))?/);
  if (!m?.[1]) return null;
  return { ecosystem: "pypi", name: m[1], version: m[3] ? exact(m[4]) : undefined, spec };
}

function cargoSpec(spec: string): RequestedPackage | null {
  const [name, version] = spec.split("@");
  if (!name || !/^[A-Za-z0-9_-]+$/.test(name)) return null;
  return { ecosystem: "cargo", name, version: exact(version), spec };
}

function goSpec(spec: string): RequestedPackage | null {
  const at = spec.lastIndexOf("@");
  const path = at > 0 ? spec.slice(0, at) : spec;
  const version = at > 0 ? spec.slice(at + 1) : undefined;
  // module paths have a dot in the first element (github.com/..., golang.org/...); "./..." and "all" are local
  if (!/^[a-z0-9.-]+\.[a-z]{2,}\//i.test(path)) return null;
  return { ecosystem: "go", name: path, version: version && /^v\d/.test(version) ? version : undefined, spec };
}

function gemSpec(spec: string, version?: string): RequestedPackage | null {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(spec) || LOCAL_OR_URL.test(spec)) return null;
  return { ecosystem: "rubygems", name: spec, version: exact(version), spec };
}

function composerSpec(spec: string): RequestedPackage | null {
  const [name, version] = spec.split(/[:=]/);
  if (!name || !/^[a-z0-9_.-]+\/[a-z0-9_.-]+$/i.test(name)) return null;
  return { ecosystem: "packagist", name: name.toLowerCase(), version: exact(version), spec };
}

/** Package install requests found in a shell command line. Unknown commands yield nothing. */
/**
 * Rebuild a command line from CLI arguments. `guard -- npm i x` arrives as separate tokens (quote the
 * ones that contain whitespace so they stay one word); `guard "npm i x"` arrives as one token that is
 * already the whole command line.
 */
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

const NPM_INSTALL = ["install", "i", "in", "add", "isntall"];
const NPM_LOCKED = ["ci", "clean-install", "ic", "install-clean", "isntall-clean", "install-test", "it", "install-ci-test", "cit"];

/**
 * Everything a command line would install: packages named on it, and installs that take their list
 * from a lockfile (`npm ci`, `npm install` with no names, `pip install -r`, `bundle install`, …).
 * `cd dir &&` and `--prefix`/`--dir`/`--cwd` style flags move where the lockfile is looked for.
 */
export function parseCommand(line: string, cwd: string = process.cwd()): { packages: RequestedPackage[]; lockfiles: LockfileInstall[] } {
  const found: RequestedPackage[] = [];
  const locked: LockfileInstall[] = [];
  let dir = cwd;
  for (let tokens of splitCommands(line)) {
    // strip env assignments and wrappers
    while (tokens.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[0]!) || ["sudo", "env", "time", "exec", "command", "nohup"].includes(tokens[0]!))) {
      tokens = tokens.slice(1);
    }
    const [cmd0, ...rest] = tokens;
    if (!cmd0) continue;
    const cmd = cmd0.replace(/^.*[\\/]/, "").replace(/\.(exe|cmd)$/i, "");
    if ((cmd === "cd" || cmd === "pushd") && rest[0] && rest[0] !== "-" && !rest[0].startsWith("~")) {
      dir = resolve(dir, rest[0]);
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
    const add = (r: RequestedPackage | null) => r && found.push(r);
    const lock = (tool: string, ecosystem: Ecosystem, at?: string, file?: string) =>
      locked.push({ tool, dir: at ? resolve(dir, at) : dir, ecosystem, ...(file ? { file } : {}) });

    if (cmd === "npm" && sub && NPM_LOCKED.includes(sub)) lock(`npm ${sub}`, "npm", flagValue(args, "--prefix", "-C"));
    else if (cmd === "npm" && sub && NPM_INSTALL.includes(sub)) {
      const specs = positional(args, "npm");
      if (specs.length) specs.forEach((s) => add(npmSpec(s)));
      else if (sub !== "add") lock(`npm ${sub}`, "npm", flagValue(args, "--prefix", "-C"));
    } else if (cmd === "pnpm" && sub && ["add", "install", "i"].includes(sub)) {
      const specs = positional(args, "pnpm");
      if (specs.length) specs.forEach((s) => add(npmSpec(s)));
      else if (sub !== "add") lock(`pnpm ${sub}`, "npm", flagValue(args, "--dir", "-C"));
    } else if (cmd === "yarn" && (sub === "add" || (sub === "global" && args[0] === "add"))) positional(sub === "global" ? args.slice(1) : args, "yarn").forEach((s) => add(npmSpec(s)));
    else if (cmd === "yarn" && (sub === undefined || sub === "install" || sub.startsWith("-"))) lock("yarn install", "npm", flagValue(args, "--cwd"));
    else if (cmd === "bun" && sub && ["add", "install", "i"].includes(sub)) {
      const specs = positional(args, "bun");
      if (specs.length) specs.forEach((s) => add(npmSpec(s)));
      else if (sub !== "add") lock(`bun ${sub}`, "npm", flagValue(args, "--cwd"));
    } else if (/^pip3?(\.\d+)?$/.test(cmd) && sub === "install" && flagValue(args, "-r", "--requirement")) {
      lock(`${cmd} install -r`, "pypi", undefined, flagValue(args, "-r", "--requirement"));
      positional(args, "pip").forEach((s) => add(pipSpec(s)));
    } else if (cmd === "uv" && sub === "sync") lock("uv sync", "pypi", flagValue(args, "--directory", "--project"));
    else if (cmd === "uv" && sub === "pip" && (args[0] === "sync" || (args[0] === "install" && flagValue(args, "-r", "--requirements")))) {
      const file = args[0] === "sync" ? positional(args.slice(1), "uv")[0] : flagValue(args, "-r", "--requirements");
      if (file) lock(`uv pip ${args[0]}`, "pypi", undefined, file);
      if (args[0] === "install") positional(args.slice(1), "uv").forEach((s) => add(pipSpec(s)));
    } else if ((cmd === "poetry" && sub === "install") || (cmd === "pipenv" && (sub === "sync" || (sub === "install" && positional(args, "pip").length === 0))))
      lock(`${cmd} ${sub}`, "pypi", flagValue(args, "--directory", "-C", "--project", "-P"));
    else if (cmd === "pipenv" && sub === "install") positional(args, "pip").forEach((s) => add(pipSpec(s)));
    else if (cmd === "bundle" && (sub === undefined || sub === "install")) {
      const gemfile = flagValue(args, "--gemfile");
      lock("bundle install", "rubygems", gemfile ? dirname(gemfile) : undefined);
    } else if (cmd === "composer" && sub === "install") lock("composer install", "packagist", flagValue(args, "--working-dir", "-d"));
    else if (cmd === "cargo" && (sub === "build" || sub === "fetch")) lock(`cargo ${sub}`, "cargo");
    else if (cmd === "npx" || cmd === "bunx" || (cmd === "pnpm" && sub === "dlx") || (cmd === "yarn" && sub === "dlx")) {
      const runArgs = cmd === "npx" || cmd === "bunx" ? rest : args;
      const pkgFlag = flagValue(runArgs, "-p", "--package");
      const first = pkgFlag ?? positional(runArgs.filter((a) => a !== "-y" && a !== "--yes"), "npm")[0];
      if (first) add(npmSpec(first));
    } else if (/^pip3?(\.\d+)?$/.test(cmd) && sub === "install") positional(args, "pip").forEach((s) => add(pipSpec(s)));
    else if (/^python3?(\.\d+)?$|^py$/.test(cmd) && sub === "-m" && /^pip3?$/.test(args[0] ?? "") && args[1] === "install") positional(args.slice(2), "pip").forEach((s) => add(pipSpec(s)));
    else if (cmd === "uv" && sub === "add") positional(args, "uv").forEach((s) => add(pipSpec(s)));
    else if (cmd === "uv" && sub === "pip" && args[0] === "install") positional(args.slice(1), "uv").forEach((s) => add(pipSpec(s)));
    else if (cmd === "uv" && sub === "tool" && args[0] === "install") positional(args.slice(1), "uv").forEach((s) => add(pipSpec(s)));
    else if ((cmd === "poetry" && sub === "add") || (cmd === "pipx" && sub === "install")) positional(args, "poetry").forEach((s) => add(pipSpec(s)));
    else if (cmd === "cargo" && (sub === "add" || sub === "install")) {
      const version = flagValue(args, "--version");
      positional(args, "cargo").forEach((s) => {
        const r = cargoSpec(s);
        if (r && !r.version && version) r.version = exact(version);
        add(r);
      });
    } else if (cmd === "go" && (sub === "get" || sub === "install")) positional(args, "go").forEach((s) => add(goSpec(s)));
    else if (cmd === "gem" && sub === "install") {
      const version = flagValue(args, "-v", "--version");
      positional(args, "gem").forEach((s) => add(gemSpec(s, version)));
    } else if (cmd === "bundle" && sub === "add") {
      const version = flagValue(args, "-v", "--version");
      positional(args, "bundle").forEach((s) => add(gemSpec(s, version)));
    } else if (cmd === "composer" && (sub === "require" || sub === "req")) positional(args, "composer").forEach((s) => add(composerSpec(s)));
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
  const base = baseVerdict(requested, check, extras, label);
  const risk = extras.installRisk;
  if (!risk || base.decision === "deny") return base;
  return { requested, decision: "ask", reason: base.decision === "allow" ? risk.reason : `${base.reason} Also: ${risk.reason}` };
}

function baseVerdict(requested: RequestedPackage, check: CheckResult, extras: VerdictExtras, label: string): PackageVerdict {
  const like = extras.lookAlike;
  const didYouMean = like ? ` Did you mean ${like.name} (used by ${fmtRepos(like.dependentRepos)} repositories)?` : "";
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
  if (finding?.kind === "malicious") {
    return { requested, decision: "deny", reason: `${label} is known malware (${finding.advisories.map((a) => a.id).join(", ")}). Do not install it.` };
  }
  if (finding?.kind === "patch-available" && finding.patch) {
    return { requested, decision: "ask", reason: `${label} has ${finding.advisories.map((a) => a.id).join(", ")} with no upstream fix. A drop-in patch exists: ${finding.patch.replacement.name}@${finding.patch.replacement.version} (run \`npx foster-oss fix\` after installing).${alt}` };
  }
  if (finding?.kind === "orphaned-vulnerable" || finding?.kind === "unpatched-vulnerable") {
    const status = check.record?.status ?? "unknown";
    return { requested, decision: "deny", reason: `${label} has security advisories that no release fixes (${finding.advisories.map((a) => `${a.id} ${a.severity}`).join(", ")}); maintenance: ${status}.${alt}` };
  }
  if (finding?.kind === "upgrade-available") {
    return { requested, decision: "ask", reason: `${label} is vulnerable (${finding.advisories.map((a) => a.id).join(", ")}); ${finding.fixedIn ? `version ${finding.fixedIn} fixes it` : "a newer release fixes it"}. Install a fixed version instead.` };
  }
  const status = check.record?.status;
  if (status === "dead" || status === "dormant") {
    return { requested, decision: "ask", reason: `${label} looks ${status} (${check.record!.reasons.join("; ")}). Nobody may fix future security problems.${alt || " Prefer a maintained package if one exists."}` };
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
  malware: malwareReports,
  installRisk: (n, v, r) => npmInstallRisk(n, v, r),
  resolveRange: (n, range, latest) => resolveNpmVersion(n, range, latest),
  lockfileMalware,
};

/** npm replaces removed malware with an empty "0.0.1-security" placeholder. */
const SECURITY_PLACEHOLDER = /^0\.0\.\d+-security(\.\d+)?$/;

/**
 * What `npm install` (or pnpm, yarn, bun) resolves from package.json when there is no lockfile it can
 * read: a fresh clone, a new project, or bun's binary bun.lockb. Local folders and workspaces are skipped.
 */
export function manifestPackages(dir: string): RequestedPackage[] {
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8").replace(/^﻿/, "")) as Record<string, unknown>;
  } catch {
    return [];
  }
  const out = new Map<string, RequestedPackage>();
  for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
    const deps = pkg[field];
    if (!deps || typeof deps !== "object") continue;
    for (const [name, spec] of Object.entries(deps as Record<string, unknown>)) {
      if (typeof spec !== "string" || out.has(name)) continue;
      if (/^(file:|link:|workspace:|portal:|patch:|\.{0,2}\/|~\/)/.test(spec)) continue;
      const remote = REMOTE.test(spec) || /^[\w.-]+\/[\w.-]+(#.*)?$/.test(spec);
      const r: RequestedPackage | null = remote ? { ecosystem: "npm", name, remote: true, spec } : npmSpec(`${name}@${spec}`);
      if (r) out.set(name, { ...r, spec: `${name}@${spec} (package.json, no lockfile)` });
    }
  }
  return [...out.values()];
}

/** At most this many look-alike names in one lockfile are confirmed online. */
const MAX_LOCK_SUSPECTS = 20;

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
async function lockfileSquats(deps: Dependency[], check: Checker, exists: (e: Ecosystem, n: string) => Promise<boolean | null>): Promise<LockSquat[]> {
  const suspects = [...new Map(deps.filter((d) => lookAlike(d.ecosystem, d.name)).map((d) => [`${d.ecosystem}:${d.name}`, d])).values()].slice(0, MAX_LOCK_SUSPECTS);
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
  return found.filter((x): x is LockSquat => x !== null);
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
  const [hits, squats] = await Promise.all([
    probe.lockfileMalware(deps).catch((err: Error) => ((failed = err.message), [] as LockedMalware[])),
    lockfileSquats(deps, check, exists),
  ]);
  const reasons: string[] = [];
  let decision: Decision = "allow";
  if (hits.length) {
    decision = "deny";
    const list = [...new Map(hits.map((h) => [`${h.dependency.name}@${h.dependency.version}`, h])).values()];
    const shown = list
      .slice(0, 5)
      .map((h) => `${h.dependency.name}@${h.dependency.version} (${h.report.id}: ${h.report.title})${SECURITY_PLACEHOLDER.test(h.dependency.version) ? " [npm's empty security placeholder: the name itself was malware]" : ""}`)
      .join("; ");
    reasons.push(`${where} would install known malware: ${shown}${list.length > 5 ? `; and ${list.length - 5} more` : ""}. Remove it from the manifest and the lockfile first, then rotate any credentials this machine or CI holds. \`npx foster-oss scan\` lists every finding.`);
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
  return { verdict: { requested, decision: "allow", reason }, count: deps.length };
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
  for (const install of parsed.lockfiles) {
    // No lockfile npm/pnpm/yarn/bun can read: they resolve package.json instead, so check those packages.
    if (install.ecosystem === "npm" && !install.file && lockedDependencies(install).deps.length === 0) requested.push(...manifestPackages(install.dir));
    else lockfiles.push(install);
  }
  // Packages are checked in parallel (a few at a time): guard runs before every install.
  const verdicts = await mapLimit(requested, requested.length > 8 ? 8 : 4, async (r): Promise<PackageVerdict> => {
    if (r.remote) {
      return { requested: r, decision: "ask", reason: `${r.spec} is installed straight from a URL or git repository: no registry or advisory database covers it, so Foster cannot check it. Install it only from a source you trust.` };
    }
    try {
      let result = await check(r.ecosystem, r.name, r.version);
      let version = r.version;
      if (!version && !result.notFound) {
        // With no exact version, check what would be installed: the range's best match, else the latest release.
        let target = result.record?.latestVersion ?? undefined;
        if (r.range && r.ecosystem === "npm") target = (await probe.resolveRange(r.name, r.range, target ?? null).catch(() => undefined)) ?? target;
        if (target) {
          result = await check(r.ecosystem, r.name, target);
          version = target;
        }
      }
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
      // Fail open: a network problem must not block development, but say so.
      return { requested: r, decision: "allow", reason: `${r.name} (${r.ecosystem}): could not be checked (${(err as Error).message})` };
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
  const checked = [requested.length ? `${requested.length} package(s) checked` : "", lockedCount ? `${lockedCount} locked package(s) checked for known malware and look-alike names` : ""].filter(Boolean);
  const message =
    flagged.length === 0
      ? checked.length
        ? `Foster guard: ${checked.join(", ")}, nothing to flag.`
        : "Foster guard: no package installs in this command."
      : `Foster guard ${decision === "deny" ? "blocked" : "flagged"} this install:\n${flagged.map((v) => `- ${v.reason}`).join("\n")}`;
  return { decision, verdicts, message };
}

/** Does this command install anything Foster can check? Cheap: no network. */
export function installsSomething(line: string, cwd?: string): boolean {
  const { packages, lockfiles } = parseCommand(line, cwd);
  return packages.length > 0 || lockfiles.length > 0;
}
