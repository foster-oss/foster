import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { checkPackage } from "./lib/check.js";
import { loadRegistry } from "./lib/data.js";
import { fosterVersion } from "./lib/http.js";
import { formatMarkdown, formatRecord } from "./lib/report.js";
import { scanProject } from "./lib/scan.js";

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
        "Check whether an npm or PyPI package is still maintained, whether it has vulnerabilities with no fix, " +
        "and whether a reviewed Foster patch exists. Call this before adding a new dependency.",
      inputSchema: {
        name: z.string().describe("Package name, e.g. 'ip' or '@scope/name'"),
        version: z.string().optional().describe("Exact version to check, e.g. '2.0.1'"),
        ecosystem: z.enum(["npm", "pypi"]).default("npm"),
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ name, version, ecosystem }) => {
      const r = await checkPackage(ecosystem, name, version);
      if (r.notFound) return text(`${name} was not found on ${ecosystem}. Check the spelling: it may be a hallucinated or typosquatted name.`);
      const parts: string[] = [];
      if (r.record) parts.push(formatRecord(r.record));
      for (const f of r.findings) parts.push(f.message);
      if (version && r.findings.length === 0) parts.push(`${name}@${version}: no known vulnerabilities.`);
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
        "Scan the lockfiles in a directory (package-lock.json, pnpm-lock.yaml, yarn.lock, uv.lock, requirements.txt) " +
        "and report dependencies that are unmaintained, vulnerable with no fix, or have a Foster patch.",
      inputSchema: {
        path: z.string().describe("Absolute path of the project directory"),
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ path }) => {
      const result = await scanProject(path);
      return text(formatMarkdown(result));
    },
  );

  server.registerTool(
    "foster_list_patches",
    {
      title: "List Foster patches",
      description: "List the packages Foster has patched, with the versions they replace and the advisories they fix.",
      inputSchema: {},
      annotations: { readOnlyHint: true },
    },
    async () => {
      const reg = await loadRegistry();
      if (reg.patches.length === 0) return text("No Foster patches yet.");
      return text(
        reg.patches
          .map((p) => `- ${p.ecosystem}:${p.name}@${p.affected} → ${p.replacement.name}@${p.replacement.version} [${p.status}] fixes ${p.advisories.join(", ")}. ${p.summary}`)
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
