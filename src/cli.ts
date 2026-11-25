#!/usr/bin/env node
import { appendFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { checkPackage, parseSpec } from "./lib/check.js";
import { applyFixes, installCommand } from "./lib/fix.js";
import { fosterVersion } from "./lib/http.js";
import { formatFix, formatMarkdown, formatRecord, formatText } from "./lib/report.js";
import { scanProject, shouldFail, type FailOn } from "./lib/scan.js";
import type { Ecosystem } from "./lib/types.js";

const HELP = `foster-oss ${fosterVersion()}: find dependencies nobody maintains, swap in reviewed patches.

Usage:
  foster-oss scan [dir]            Check a project's lockfiles
  foster-oss fix [dir]             Point dependencies at released Foster patches (edits package.json)
  foster-oss check <name[@ver]>    Look up one package
  foster-oss mcp                   Start the MCP server (stdio) for AI agents

Options:
  --json                 Machine-readable output (scan, check)
  --markdown             Markdown report (scan)
  --all                  List every unmaintained dependency, not only the vulnerable ones (scan)
  --summary-file <path>  Also append the markdown report to this file (e.g. $GITHUB_STEP_SUMMARY)
  --fail-on <level>      Exit 1 when findings reach a level:
                         none | patch-available | orphaned-vulnerable | unpatched | any (default: none)
  --offline              Use only data bundled with this release (no network)
  --include-staged       Also use patches that are reviewed but not yet released
  --dry-run              Show what fix would change without writing
  --force                Replace existing overrides for the same package (fix)
  --ecosystem <npm|pypi> Ecosystem for check (default: npm)
  -v, --version          Print version
  -h, --help             Show this help

Data: ecosyste.ms (maintenance, reach), OSV.dev (vulnerabilities), Foster patch registry.
Docs: https://github.com/foster-oss/foster`;

const FAIL_LEVELS: FailOn[] = ["none", "patch-available", "orphaned-vulnerable", "unpatched", "any"];

async function main(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      json: { type: "boolean", default: false },
      all: { type: "boolean", default: false },
      markdown: { type: "boolean", default: false },
      "summary-file": { type: "string" },
      "fail-on": { type: "string", default: "none" },
      offline: { type: "boolean", default: false },
      "include-staged": { type: "boolean", default: false },
      "dry-run": { type: "boolean", default: false },
      force: { type: "boolean", default: false },
      ecosystem: { type: "string", default: "npm" },
      version: { type: "boolean", short: "v", default: false },
      help: { type: "boolean", short: "h", default: false },
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
      const result = await scanProject(arg ?? ".", { offline: values.offline, includeStaged: values["include-staged"] });
      if (values.json) console.log(JSON.stringify(result, null, 2));
      else if (values.markdown) console.log(formatMarkdown(result));
      else console.log(formatText(result, process.stdout.isTTY ?? false, values.all));
      if (values["summary-file"]) appendFileSync(values["summary-file"], formatMarkdown(result) + "\n");
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
      if (ecosystem !== "npm" && ecosystem !== "pypi") throw new UsageError("--ecosystem must be npm or pypi");
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
      if (version && result.findings.length === 0) console.log(`\n${name}@${version}: no known vulnerabilities.`);
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
