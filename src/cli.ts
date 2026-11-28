#!/usr/bin/env node
import { appendFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { checkPackage, malwareNotice, parseSpec } from "./lib/check.js";
import { applyFixes, installCommand } from "./lib/fix.js";
import { fosterVersion } from "./lib/http.js";
import { formatFix, formatMarkdown, formatRecord, formatSarif, formatText } from "./lib/report.js";
import { describeAlternatives } from "./lib/replacements.js";
import { commandLineFrom, guardCommand, installsSomething, splitGuardArgs } from "./lib/guard.js";
import { shellInit, SHELLS, type Shell } from "./lib/shell.js";
import { FOSTER_PACKAGE, fosterImpostorMessage, impersonatesFoster } from "./lib/typosquat.js";
import { AGENT_DIRS, fosterOnPath, installSkill, skillText } from "./lib/skill.js";
import { formatFund, fundProject } from "./lib/fund.js";
import { scanProject, scanSbom, shouldFail, type FailOn } from "./lib/scan.js";
import { ECOSYSTEMS, type Ecosystem } from "./lib/types.js";

const HELP = `foster-oss ${fosterVersion()}: stop installs of malware, hallucinated and abandoned packages,
and find the dependencies nobody maintains, with the fixes that exist for them.

Usage:
  foster-oss guard -- <command>    Check what a shell command would install, before it runs: known malware,
                                   names that don't exist, look-alikes, unfixed vulnerabilities, and what
                                   lockfiles, package.json, workspaces and overrides bring along
  foster-oss guard --hook claude   Same, as a Claude Code PreToolUse hook (reads the hook JSON on stdin)
                                   guard exits 0 (allow), 1 (deny) or 10 (ask: a person should decide)
  foster-oss skill install [dir]   Add the Foster agent skill so coding agents check installs themselves
                                   (.agents/skills for Codex, Cursor, Gemini CLI, Copilot, OpenCode, …;
                                   .claude/skills; --global for your user; --agent <id> for one agent)
  foster-oss skill print           Print the skill (SKILL.md) for any other agent
  foster-oss shell-init <shell>    Print shell functions that guard npm, pip, … installs (bash, zsh, powershell)
  foster-oss scan [dir]            Check a project's lockfiles
  foster-oss scan --sbom <file>    Check a CycloneDX or SPDX JSON SBOM instead
  foster-oss fund [dir]            Which at-risk dependencies you rely on, and where to fund their maintainers
  foster-oss fix [dir]             Point dependencies at released drop-in patches (edits package.json or pnpm-workspace.yaml)
  foster-oss check <name[@ver]>    Look up one package
  foster-oss mcp                   Start the MCP server (stdio) for AI agents

Examples:
  npx foster-oss guard -- npm install left-pad
  npx foster-oss guard -- npm ci
  npx foster-oss skill install
  npx foster-oss scan --since main

Options:
  --json                 Machine-readable output (scan, check)
  --markdown             Markdown report (scan)
  --all                  List every unmaintained dependency, not only the vulnerable ones (scan)
  -r, --recursive        Also scan lockfiles in subfolders (monorepos)
  --since <git-ref>      Only check dependencies added or changed since a git ref (e.g. a PR's base)
  --summary-file <path>  Also append the markdown report to this file (e.g. $GITHUB_STEP_SUMMARY)
  --sarif <path>         Also write a SARIF 2.1.0 report (GitHub code scanning, other dashboards)
  --fail-on <level>      Exit 1 when findings reach a level:
                         none | malicious | patch-available | orphaned-vulnerable | unpatched | any
                         (default: malicious, so known malware always fails; every level above none does)
  --offline              Use only data bundled with this release (no network)
  --include-staged       Also use patches that are reviewed but not yet released
  --dry-run              Show what fix would change without writing
  --force                Replace existing overrides for the same package (fix)
  --strict               guard: exit 1 on ask too (default: ask exits 10)
  -q, --quiet            guard: print nothing when the install is allowed
  --ecosystem <name>     Ecosystem for check: npm, pypi, cargo, go, rubygems, packagist (default: npm)
  -v, --version          Print version
  -h, --help             Show this help

Data: ecosyste.ms (maintenance, reach), OSV.dev (vulnerabilities), patch registry (Foster and other providers such as Keep LTS).
Docs: https://github.com/foster-oss/foster`;

const SUBCOMMAND_HELP: Record<string, () => string> = {
  skill: () => `foster-oss skill: the Foster Agent Skill, so coding agents check every install before running it

Usage:
  foster-oss skill install [dir]        Install into a project (default: current directory):
                                        .agents/skills/foster (Codex, Cursor, Gemini CLI, GitHub Copilot,
                                        OpenCode, Amp, Cline, Zed, Warp, …), .claude/skills/foster (Claude Code),
                                        and the skills folder of any other agent already set up in the project
  foster-oss skill install --global     Install for your user, into every agent installed on this machine
                                        (and ~/.agents/skills)
  foster-oss skill install --agent <id> Only these agents (repeat the flag or separate with commas)
  foster-oss skill install --no-permissions
                                        Leave Claude Code's settings alone. By default .claude/settings.json is
                                        set to allow "foster-oss guard" and "foster-oss check" (they only read,
                                        Bash and PowerShell), so the check runs without a prompt
  foster-oss skill print                Print SKILL.md, for agents that take instructions another way

Agent ids: ${AGENT_DIRS.map(([ids]) => ids[0]).join(", ")}

Also: npx skills add foster-oss/foster, or the Claude Code plugin:
  /plugin install foster --marketplace foster-oss/foster`,
  guard: () => `foster-oss guard: check what a command would install, before it runs

Usage:
  foster-oss guard -- <command>         e.g. foster-oss guard -- npm install left-pad
  foster-oss guard --command "<line>"   the same, with the command line as one string
  foster-oss guard --hook claude        Claude Code PreToolUse hook (reads the hook JSON on stdin)

Exit codes: 0 allow, 1 deny, 10 ask (a person should decide).
Options:
  --strict      exit 1 on ask too (CI and other places where nobody can answer)
  -q, --quiet   print nothing when the install is allowed
  --json        machine-readable result

Run it from the directory the command runs in: guard follows "cd dir &&" and --prefix/-C/--dir/--cwd, and
reads that directory's lockfile, package.json and workspaces. Packages it cannot reach the registry or OSV
for are allowed with a "could not be checked" line.`,
};

const FAIL_LEVELS: FailOn[] =["none", "malicious", "patch-available", "orphaned-vulnerable", "unpatched", "any"];

async function main(argv: string[]): Promise<number> {
  // guard's command is never parsed as Foster options, with or without "--" (PowerShell drops it)
  const guardArgs = splitGuardArgs(argv);
  if (guardArgs) argv = ["guard", ...guardArgs.own];
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      json: { type: "boolean", default: false },
      all: { type: "boolean", default: false },
      markdown: { type: "boolean", default: false },
      "summary-file": { type: "string" },
      sarif: { type: "string" },
      sbom: { type: "string" },
      since: { type: "string" },
      recursive: { type: "boolean", short: "r", default: false },
      "fail-on": { type: "string", default: "malicious" },
      offline: { type: "boolean", default: false },
      "include-staged": { type: "boolean", default: false },
      "dry-run": { type: "boolean", default: false },
      force: { type: "boolean", default: false },
      ecosystem: { type: "string", default: "npm" },
      version: { type: "boolean", short: "v", default: false },
      help: { type: "boolean", short: "h", default: false },
      hook: { type: "string" },
      command: { type: "string" },
      strict: { type: "boolean", default: false },
      quiet: { type: "boolean", short: "q", default: false },
      global: { type: "boolean", short: "g", default: false },
      agent: { type: "string", multiple: true },
      "no-permissions": { type: "boolean", default: false },
    },
  });

  const [command, arg] = positionals;
  if (values.version) {
    console.log(fosterVersion());
    return 0;
  }
  if (values.help && command && SUBCOMMAND_HELP[command]) {
    console.log(SUBCOMMAND_HELP[command]());
    return 0;
  }
  if (values.help || !command) {
    console.log(HELP);
    return command || values.help ? 0 : 1;
  }

  switch (command) {
    case "scan": {
      const failOn = values["fail-on"] as FailOn;
      if (!FAIL_LEVELS.includes(failOn)) throw new UsageError(`--fail-on must be one of ${FAIL_LEVELS.join(", ")}`);
      const scanOpts = { offline: values.offline, includeStaged: values["include-staged"], recursive: values.recursive, since: values.since };
      const result = values.sbom ? await scanSbom(values.sbom, scanOpts) : await scanProject(arg ?? ".", scanOpts);
      if (values.json) console.log(JSON.stringify(result, null, 2));
      else if (values.markdown) console.log(formatMarkdown(result));
      else console.log(formatText(result, process.stdout.isTTY ?? false, values.all));
      if (values["summary-file"]) appendFileSync(values["summary-file"], formatMarkdown(result) + "\n");
      if (values.sarif) writeFileSync(values.sarif, formatSarif(result, fosterVersion(), process.cwd(), values.all));
      return shouldFail(result.findings, failOn) ? 1 : 0;
    }
    case "fix": {
      const dir = arg ?? ".";
      const scan = await scanProject(dir, { offline: values.offline, includeStaged: values["include-staged"] });
      const result = applyFixes(dir, scan.findings, { dryRun: values["dry-run"], force: values.force });
      console.log(formatFix(result, installCommand(result.manager)));
      return 0;
    }
    case "check": {
      if (!arg) throw new UsageError("check needs a package name, e.g. foster-oss check ip@2.0.1");
      const ecosystem = values.ecosystem as Ecosystem;
      if (!ECOSYSTEMS.includes(ecosystem)) throw new UsageError(`--ecosystem must be one of ${ECOSYSTEMS.join(", ")}`);
      const { name, version } = parseSpec(arg);
      const result = await checkPackage(ecosystem, name, version, { includeStaged: values["include-staged"] });
      const malware = result.notFound ? null : await malwareNotice(ecosystem, name, version, result.findings);
      if (values.json) {
        console.log(JSON.stringify(malware ? { ...result, malware } : result, null, 2));
        return 0;
      }
      if (result.notFound) {
        console.log(`${name} was not found on ${ecosystem}.${impersonatesFoster(ecosystem, name) ? ` Did you mean ${FOSTER_PACKAGE} (Foster itself, on npm)?` : ""}`);
        return 1;
      }
      if (malware) console.log(`${malware}\n`);
      if (impersonatesFoster(ecosystem, name)) console.log(`NOT FOSTER: ${fosterImpostorMessage(ecosystem, name)}\n`);
      if (result.record) console.log(formatRecord(result.record));
      for (const f of result.findings) console.log(`\n${f.message}`);
      if (version && result.findings.length === 0) console.log(`
${name}@${version}: no known vulnerabilities.`);
      if (result.alternatives && result.record && result.record.status !== "active") console.log(`
Maintained alternatives: ${describeAlternatives(result.alternatives)}`);
      return 0;
    }
    case "guard": {
      if (values.hook !== undefined) {
        if (values.hook !== "claude") throw new UsageError('--hook supports "claude"');
        await runClaudeHook();
        return 0;
      }
      const rest = guardArgs?.command ?? positionals.slice(1);
      // Windows PowerShell 5.1 splits a --command value at its inner double quotes
      // ('iex "npm i x"' arrives as "iex npm", "i", "x"): words after the value belong to it
      const line = values.command !== undefined ? [values.command, ...rest].join(" ") : commandLineFrom(rest);
      if (!line.trim()) throw new UsageError("guard needs a command, e.g. foster-oss guard -- npm install left-pad");
      const result = await guardCommand(line);
      if (values.json) console.log(JSON.stringify(result, null, 2));
      else if (!(values.quiet && result.decision === "allow")) console.log(result.message);
      // ask is its own exit code, so "guard -- x && x" stops and a wrapper can ask the person
      return result.decision === "deny" || (values.strict && result.decision === "ask") ? 1 : result.decision === "ask" ? 10 : 0;
    }
    case "skill": {
      const action = arg ?? "install";
      if (action === "print") {
        process.stdout.write(skillText());
        return 0;
      }
      if (action !== "install") throw new UsageError('skill takes "install" or "print", e.g. foster-oss skill install');
      const agents = (values.agent ?? []).flatMap((a) => a.split(",")).map((a) => a.trim()).filter(Boolean);
      const result = installSkill(positionals[2] ?? ".", { global: values.global, agents, permissions: !values["no-permissions"] });
      if (result.unknownAgents.length) console.error(`foster-oss: unknown agent ${result.unknownAgents.join(", ")}; known: ${AGENT_DIRS.map(([ids]) => ids[0]).join(", ")}`);
      if (!result.installed.length) return 2;
      const list = result.installed.map((p) => `  ${p}`).join("\n");
      console.log(`Installed the Foster skill:\n${list}\n\nAgents that read these folders now check every install with foster-oss guard before running it.`);
      for (const f of result.permissions.updated) console.log(`Claude Code may run Foster's check (guard, check) without asking: ${f}`);
      for (const f of result.permissions.skipped) console.error(`foster-oss: ${f} is not valid JSON, so it was left alone; allow "Bash(foster-oss guard:*)" and "PowerShell(foster-oss guard *)" there yourself.`);
      if (!fosterOnPath()) console.log(`
Tip: install Foster once with "npm i -g foster-oss". Agents then run "foster-oss guard" directly: about
1.5 s faster, and not blocked by permission systems that refuse "npx -y …@latest" (Claude Code's auto mode).
In Claude Code the plugin works without it: /plugin install foster --marketplace foster-oss/foster`);
      return 0;
    }
    case "shell-init": {
      if (!arg || !SHELLS.includes(arg as Shell)) throw new UsageError(`shell-init needs a shell: ${SHELLS.join(", ")}`);
      console.log(shellInit(arg as Shell));
      return 0;
    }
    case "fund": {
      const result = await fundProject(arg ?? ".", { offline: values.offline, recursive: values.recursive });
      if (values.json) console.log(JSON.stringify(result, null, 2));
      else console.log(formatFund(result));
      return 0;
    }
    case "mcp": {
      const { startMcpServer } = await import("./mcp.js");
      await startMcpServer();
      return -1; // keep running
    }
    default:
      throw new UsageError(`unknown command "${command}". Run foster-oss --help.`);
  }
}

class UsageError extends Error {}

/**
 * Claude Code PreToolUse hook: read the hook JSON from stdin, and for Bash commands that install
 * packages, answer with permissionDecision "deny" or "ask". Silent (no output, exit 0) otherwise.
 * Fails open: any error or a slow network leaves the normal permission flow untouched.
 */
async function runClaudeHook(): Promise<void> {
  try {
    const raw = await new Promise<string>((resolve, reject) => {
      let data = "";
      process.stdin.setEncoding("utf8");
      process.stdin.on("data", (c) => (data += c));
      process.stdin.on("end", () => resolve(data));
      process.stdin.on("error", reject);
    });
    const input = JSON.parse(raw || "{}") as { hook_event_name?: string; tool_name?: string; cwd?: string; tool_input?: { command?: string } };
    if (!["Bash", "PowerShell"].includes(input.tool_name ?? "") || (input.hook_event_name && input.hook_event_name !== "PreToolUse")) return;
    const line = input.tool_input?.command ?? "";
    const cwd = input.cwd || process.cwd();
    if (!installsSomething(line, cwd)) return;
    const result = await Promise.race([
      guardCommand(line, undefined, undefined, { cwd }),
      new Promise<null>((resolve) => setTimeout(() => resolve(null), 25_000).unref()),
    ]);
    if (!result || result.decision === "allow") return;
    process.stdout.write(
      JSON.stringify({
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: result.decision,
          permissionDecisionReason:
            result.decision === "deny"
              ? `${result.message}
Do not install it. Tell the user why, and suggest a maintained alternative or a fixed version.`
              : result.message,
        },
      }),
    );
  } catch {
    // fail open
  }
}

main(process.argv.slice(2)).then(
  (code) => {
    if (code >= 0) process.exitCode = code;
  },
  (err: unknown) => {
    const code = (err as { code?: string }).code;
    if (err instanceof UsageError || code?.startsWith("ERR_PARSE_ARGS") || code === "FOSTER_NO_DIR" || code === "ENOENT") {
      console.error(`foster-oss: ${(err as Error).message}`);
      process.exitCode = 2;
    } else {
      console.error(`foster-oss: ${(err as Error).stack ?? err}`);
      process.exitCode = 3;
    }
  },
);
