#!/usr/bin/env node
import { appendFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { checkPackage, parseSpec } from "./lib/check.js";
import { applyFixes, installCommand } from "./lib/fix.js";
import { fosterVersion } from "./lib/http.js";
import { formatFix, formatMarkdown, formatRecord, formatSarif, formatText } from "./lib/report.js";
import { describeAlternatives } from "./lib/replacements.js";
import { commandLineFrom, guardCommand, installsSomething } from "./lib/guard.js";
import { shellInit, SHELLS, type Shell } from "./lib/shell.js";
import { formatFund, fundProject } from "./lib/fund.js";
import { scanProject, scanSbom, shouldFail, type FailOn } from "./lib/scan.js";
import { ECOSYSTEMS, type Ecosystem } from "./lib/types.js";

const HELP = `foster-oss ${fosterVersion()}: find dependencies nobody maintains, swap in reviewed patches.

Usage:
  foster-oss scan [dir]            Check a project's lockfiles
  foster-oss scan --sbom <file>    Check a CycloneDX or SPDX JSON SBOM instead
  foster-oss fix [dir]             Point dependencies at released drop-in patches (edits package.json)
  foster-oss check <name[@ver]>    Look up one package
  foster-oss fund [dir]            Which at-risk dependencies you rely on, and where to fund their maintainers
  foster-oss mcp                   Start the MCP server (stdio) for AI agents
  foster-oss guard -- <command>    Check the packages a shell command would install
  foster-oss guard --hook claude   Same, as a Claude Code PreToolUse hook (reads the hook JSON on stdin)
                                   guard exits 0 (allow), 1 (deny) or 10 (ask: a person should decide)
  foster-oss shell-init <shell>    Print shell functions that guard npm, pip, … installs (bash, zsh, powershell)

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

const FAIL_LEVELS: FailOn[] = ["none", "malicious", "patch-available", "orphaned-vulnerable", "unpatched", "any"];

async function main(argv: string[]): Promise<number> {
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
    },
  });

  const [command, arg] = positionals;
  if (values.version) {
    console.log(fosterVersion());
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
      if (values.json) {
        console.log(JSON.stringify(result, null, 2));
        return 0;
      }
      if (result.notFound) {
        console.log(`${name} was not found on ${ecosystem}.`);
        return 1;
      }
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
      const line = values.command ?? commandLineFrom(positionals.slice(1));
      if (!line.trim()) throw new UsageError("guard needs a command, e.g. foster-oss guard -- npm install left-pad");
      const result = await guardCommand(line);
      if (values.json) console.log(JSON.stringify(result, null, 2));
      else if (!(values.quiet && result.decision === "allow")) console.log(result.message);
      // ask is its own exit code, so "guard -- x && x" stops and a wrapper can ask the person
      return result.decision === "deny" || (values.strict && result.decision === "ask") ? 1 : result.decision === "ask" ? 10 : 0;
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
    if (input.tool_name !== "Bash" || (input.hook_event_name && input.hook_event_name !== "PreToolUse")) return;
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
    if (err instanceof UsageError || (err as { code?: string }).code?.startsWith("ERR_PARSE_ARGS")) {
      console.error(`foster-oss: ${(err as Error).message}`);
      process.exitCode = 2;
    } else {
      console.error(`foster-oss: ${(err as Error).stack ?? err}`);
      process.exitCode = 3;
    }
  },
);
