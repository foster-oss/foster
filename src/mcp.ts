import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { checkPackage, malwareNotice, versionExists } from "./lib/check.js";
import { loadRegistry } from "./lib/data.js";
import { fosterVersion } from "./lib/http.js";
import { formatMarkdown, formatRecord } from "./lib/report.js";
import { scanProject } from "./lib/scan.js";
import { guardWithin } from "./lib/guard.js";
import { formatFund, fundProject } from "./lib/fund.js";
import { describeAlternatives } from "./lib/replacements.js";
import { fosterImpostorMessage, impersonatesFoster } from "./lib/typosquat.js";

function text(s: string) {
  return { content: [{ type: "text" as const, text: s }] };
}

export function createMcpServer(): McpServer {
  const server = new McpServer({ name: "foster-oss", version: fosterVersion() });

  server.registerTool(
    "foster_check_package",
    {
      title: "Check a package before depending on it",
      description:
        "Check whether a package (npm, PyPI, Cargo, Go, RubyGems or Packagist) is still maintained, whether it has vulnerabilities with no fix, " +
        "and whether a published drop-in security patch exists (from Foster or providers like Keep LTS). Call this before adding a new dependency.",
      inputSchema: {
        name: z.string().min(1).max(214).describe("Package name, e.g. 'ip' or '@scope/name'"),
        version: z.string().optional().describe("Exact version to check, e.g. '2.0.1'"),
        ecosystem: z.enum(["npm", "pypi", "cargo", "go", "rubygems", "packagist"]).default("npm"),
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ name, version, ecosystem }) => {
      const r = await checkPackage(ecosystem, name, version);
      if (r.notFound) return text(`${name} was not found on ${ecosystem}. Check the spelling: it may be a hallucinated or typosquatted name.`);
      const parts: string[] = [];
      const malware = await malwareNotice(ecosystem, name, version, r.findings);
      if (version && (await versionExists(ecosystem, name, version)) === false) parts.push(`VERSION NOT FOUND: ${name}@${version} does not exist on ${ecosystem}. Check the version before adding it.`);
      if (malware) parts.push(malware);
      if (impersonatesFoster(ecosystem, name)) parts.push(`NOT FOSTER: ${fosterImpostorMessage(ecosystem, name)}`);
      if (r.record) parts.push(formatRecord(r.record));
      for (const f of r.findings) parts.push(f.message);
      if (version && r.findings.length === 0) parts.push(`${name}@${version}: no known vulnerabilities.`);
      if (r.alternatives) parts.push(`Maintained alternatives: ${describeAlternatives(r.alternatives)}`);
      if (r.record && (r.record.status === "dead" || r.record.status === "dormant"))
        parts.push("Advice: prefer a maintained alternative for new code; if you must use it, pin the version and watch for advisories.");
      return text(parts.join("\n\n"));
    },
  );

  server.registerTool(
    "foster_scan_project",
    {
      title: "Scan a project for orphaned dependencies",
      description:
        "Scan the lockfiles in a directory (npm, pnpm, yarn, uv, poetry, pipenv, requirements.txt, Cargo.lock, go.mod, Gemfile.lock, composer.lock) " +
        "and report dependencies that are unmaintained, vulnerable with no fix, or have a drop-in security patch.",
      inputSchema: {
        path: z.string().describe("Absolute path of the project directory"),
        recursive: z.boolean().default(false).describe("Also scan lockfiles in subfolders (monorepos)"),
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ path, recursive }) => {
      const result = await scanProject(path, { recursive });
      return text(formatMarkdown(result));
    },
  );

  server.registerTool(
    "foster_check_install_command",
    {
      title: "Check an install command before running it",
      description:
        "Before running a shell command that installs packages (npm/pnpm/yarn/bun, npx, pip/uv/poetry, cargo, go get, gem, composer), " +
        "check every package it would install. Returns deny for known malware, names that do not exist (hallucinated or typo'd) and " +
        "vulnerabilities no release fixes; ask for look-alike names, brand-new npm packages or fresh releases that run install scripts, " +
        "and fixable vulnerable versions; allow otherwise, with a note for unmaintained packages. Pass cwd, the folder the command runs in: " +
        "installs that read a lockfile or package.json (npm ci, npm install, pip install -r) are checked from there.",
      inputSchema: {
        command: z.string().min(1).max(100_000).describe("The exact shell command you are about to run, e.g. 'npm install left-pad'"),
        cwd: z.string().max(4096).optional().describe("Absolute path of the folder the command runs in (default: the server's working directory)"),
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ command, cwd }) => {
      const r = await guardWithin(command, cwd ? { cwd } : {});
      return text(`Decision: ${r.decision.toUpperCase()}${r.timedOut || r.verdicts.some((v) => v.unchecked) ? " (partly unverified: treat it like ASK)" : ""}
${r.message}`);
    },
  );

  server.registerTool(
    "foster_fund_project",
    {
      title: "Where to fund the maintainers a project depends on",
      description:
        "List the project's dependencies that are unmaintained or at risk, ranked by how much the ecosystem relies on them, " +
        "with their maintainers' sponsorship links (GitHub Sponsors, Open Collective, Tidelift, …).",
      inputSchema: {
        path: z.string().describe("Absolute path of the project directory"),
        recursive: z.boolean().default(false).describe("Also scan lockfiles in subfolders (monorepos)"),
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ path, recursive }) => text(formatFund(await fundProject(path, { recursive }))),
  );

  server.registerTool(
    "foster_list_patches",
    {
      title: "List known drop-in patches",
      description: "List known drop-in security patches for abandoned packages (Foster and other providers), with the versions they replace and the advisories they fix.",
      inputSchema: {},
      annotations: { readOnlyHint: true },
    },
    async () => {
      const reg = await loadRegistry();
      if (reg.patches.length === 0) return text("No patches in the registry yet.");
      return text(
        reg.patches
          .filter((p) => p.status !== "retired")
          .map((p) => `- ${p.ecosystem}:${p.name}@${p.affected} → ${p.replacement.name}@${p.replacement.version} by ${p.provider?.name ?? "Foster"} [${p.status}] fixes ${p.advisories.join(", ")}. ${p.summary}`)
          .join("\n"),
      );
    },
  );

  return server;
}

export async function startMcpServer(): Promise<void> {
  const server = createMcpServer();
  await server.connect(new StdioServerTransport());
}
