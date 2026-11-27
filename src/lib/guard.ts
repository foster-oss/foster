import { checkPackage, type CheckResult } from "./check.js";
import { describeAlternatives } from "./replacements.js";
import type { Ecosystem } from "./types.js";

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
  /** The token as written in the command. */
  spec: string;
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
      else if (ch === "\\" && quote === '"' && i + 1 < line.length) cur += line[++i];
      else cur += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      hasToken = true;
      continue;
    }
    if (ch === "\\" && i + 1 < line.length && line[i + 1] !== "\n") {
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
  npm: ["--registry", "--prefix", "--tag", "--workspace", "-w", "--save-prefix", "--cache", "--userconfig", "--omit", "--include"],
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

function npmSpec(spec: string): RequestedPackage | null {
  if (LOCAL_OR_URL.test(spec)) return null;
  // "user/repo" without a scope is a GitHub shorthand, not a registry package
  if (!spec.startsWith("@") && spec.includes("/")) return null;
  // alias "x@npm:real@1.0.0": check the real package
  const alias = spec.indexOf("@npm:", 1);
  if (alias > 0) {
    const real = spec.slice(alias + "@npm:".length);
    const rat = real.lastIndexOf("@");
    return { ecosystem: "npm", name: rat > 0 ? real.slice(0, rat) : real, version: exact(rat > 0 ? real.slice(rat + 1) : undefined), spec };
  }
  const at = spec.lastIndexOf("@");
  const name = at > 0 ? spec.slice(0, at) : spec;
  let version = at > 0 ? spec.slice(at + 1) : undefined;
  if (!/^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i.test(name)) return null;
  version = exact(version);
  return { ecosystem: "npm", name, version, spec };
}

/** Keep only exact versions; ranges and tags ("^1", "latest") mean "whatever resolves", checked as latest. */
function exact(v: string | undefined): string | undefined {
  if (!v) return undefined;
  const clean = v.replace(/^[=v]+/, "");
  return /^\d+(\.\d+)*([-.+][0-9A-Za-z.+-]+)?$/.test(clean) ? clean : undefined;
}

function pipSpec(spec: string): RequestedPackage | null {
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
export function parseInstallCommand(line: string): RequestedPackage[] {
  const found: RequestedPackage[] = [];
  for (let tokens of splitCommands(line)) {
    // strip env assignments and wrappers
    while (tokens.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[0]!) || ["sudo", "env", "time", "exec", "command", "nohup"].includes(tokens[0]!))) {
      tokens = tokens.slice(1);
    }
    const [cmd0, ...rest] = tokens;
    if (!cmd0) continue;
    const cmd = cmd0.replace(/^.*[\\/]/, "").replace(/\.(exe|cmd)$/i, "");
    const sub = rest[0];
    const args = rest.slice(1);
    const add = (r: RequestedPackage | null) => r && found.push(r);

    if (cmd === "npm" && sub && ["install", "i", "in", "add", "isntall"].includes(sub)) positional(args, "npm").forEach((s) => add(npmSpec(s)));
    else if (cmd === "pnpm" && sub && ["add", "install", "i"].includes(sub)) positional(args, "pnpm").forEach((s) => add(npmSpec(s)));
    else if (cmd === "yarn" && (sub === "add" || (sub === "global" && args[0] === "add"))) positional(sub === "global" ? args.slice(1) : args, "yarn").forEach((s) => add(npmSpec(s)));
    else if (cmd === "bun" && sub && ["add", "install", "i"].includes(sub)) positional(args, "bun").forEach((s) => add(npmSpec(s)));
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
  return [...new Map(found.map((r) => [`${r.ecosystem}:${r.name}@${r.version ?? ""}`, r])).values()];
}

// ---------------------------------------------------------------- decisions

const RANK: Record<Decision, number> = { allow: 0, ask: 1, deny: 2 };

export type Checker = (ecosystem: Ecosystem, name: string, version?: string) => Promise<CheckResult>;

/** Decide about one package from a live check. */
export function verdictFor(requested: RequestedPackage, check: CheckResult): PackageVerdict {
  const label = `${requested.name}${requested.version ? `@${requested.version}` : ""} (${requested.ecosystem})`;
  if (check.notFound) {
    return { requested, decision: "deny", reason: `${label} does not exist on the registry. It may be a misspelled or hallucinated name; attackers register such names ("slopsquatting"). Check the exact package name first.` };
  }
  const alt = check.alternatives ? ` Maintained alternatives: ${describeAlternatives(check.alternatives)}.` : "";
  const finding = check.findings[0];
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

export async function guardCommand(line: string, check: Checker = checkPackage): Promise<GuardResult> {
  const requested = parseInstallCommand(line);
  const verdicts: PackageVerdict[] = [];
  for (const r of requested) {
    try {
      // With no pinned version, check the version that would be installed: the latest release.
      let result = await check(r.ecosystem, r.name, r.version);
      if (!r.version && result.record?.latestVersion && !result.notFound) {
        result = await check(r.ecosystem, r.name, result.record.latestVersion);
      }
      verdicts.push(verdictFor(r, result));
    } catch (err) {
      // Fail open: a network problem must not block development, but say so.
      verdicts.push({ requested: r, decision: "allow", reason: `${r.name} (${r.ecosystem}): could not be checked (${(err as Error).message})` });
    }
  }
  const decision = verdicts.reduce<Decision>((d, v) => (RANK[v.decision] > RANK[d] ? v.decision : d), "allow");
  const flagged = verdicts.filter((v) => v.decision !== "allow");
  const message =
    flagged.length === 0
      ? requested.length
        ? `Foster guard: ${requested.length} package(s) checked, nothing to flag.`
        : "Foster guard: no package installs in this command."
      : `Foster guard ${decision === "deny" ? "blocked" : "flagged"} this install:\n${flagged.map((v) => `- ${v.reason}`).join("\n")}`;
  return { decision, verdicts, message };
}
