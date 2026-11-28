import { fundingLabel } from "./fund.js";
import { readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { MAX_VIA } from "./graph.js";
import { describeAlternatives } from "./replacements.js";
import type { FixResult } from "./fix.js";
import type { Dependency, Finding, FindingKind, OrphanRecord, ScanResult } from "./types.js";

const KIND_LABEL: Record<FindingKind, string> = {
  malicious: "MALWARE",
  "patch-available": "PATCH READY",
  "orphaned-vulnerable": "ORPHANED+VULN",
  "unpatched-vulnerable": "NO FIX YET",
  "upgrade-available": "UPGRADE",
  orphaned: "ORPHANED",
};

const KIND_TITLE: Record<FindingKind, string> = {
  malicious: "Known malware: remove it now",
  "patch-available": "Drop-in security patch available",
  "orphaned-vulnerable": "Vulnerable, no fix exists, and nobody maintains it",
  "unpatched-vulnerable": "Vulnerable, no fix released yet",
  "upgrade-available": "Vulnerable, fixed upstream: just upgrade",
  orphaned: "Widely used but unmaintained",
};

function counts(findings: Finding[]): Record<FindingKind, { total: number; direct: number }> {
  const c = Object.fromEntries(Object.keys(KIND_LABEL).map((k) => [k, { total: 0, direct: 0 }])) as Record<FindingKind, { total: number; direct: number }>;
  for (const f of findings) {
    c[f.kind].total++;
    if (f.dependency.direct) c[f.kind].direct++;
  }
  return c;
}

/** "transitive, via astro" / "transitive, via a, b, c +2 more" / "transitive"; empty for a direct dependency. */
export function relationNote(d: Dependency): string {
  if (d.direct) return "";
  if (!d.via?.length) return "transitive";
  const more = d.via.length >= MAX_VIA ? " and many more" : d.via.length > 3 ? ` +${d.via.length - 3} more` : "";
  return `transitive, via ${d.via.slice(0, 3).join(", ")}${more}`;
}

/** The direct dependencies that bring in most of these transitive findings: "request (40), astro (12)". */
function topVia(findings: Finding[], limit = 3): string {
  const n = new Map<string, number>();
  for (const f of findings) for (const v of f.dependency.via ?? []) n.set(v, (n.get(v) ?? 0) + 1);
  return [...n.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([name, count]) => `${name} (${count})`)
    .join(", ");
}

const nameList = (list: Finding[], max = 6) => list.slice(0, max).map((f) => f.dependency.name).join(", ") + (list.length > max ? ", …" : "");

/**
 * A vulnerable transitive package that comes in only through direct dependencies nobody maintains:
 * those will never ship the fix, so the way out is replacing them. Returns their names, or null.
 */
export function stuckBehind(f: Finding, findings: Finding[]): string[] | null {
  if (f.dependency.direct || !f.dependency.via?.length || f.kind === "orphaned" || f.kind === "patch-available" || f.kind === "malicious") return null;
  const unmaintained = new Set(
    findings.filter((x) => x.dependency.direct && (x.status === "dead" || x.status === "dormant")).map((x) => x.dependency.name),
  );
  return f.dependency.via.every((v) => unmaintained.has(v)) ? f.dependency.via : null;
}

export function formatText(result: ScanResult, color = false, showAll = false): string {
  const c = (code: number, s: string) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const lines: string[] = [];
  lines.push(c(1, `Foster scan: ${result.dir}`));
  lines.push(`Lockfiles: ${result.lockfiles.join(", ") || "none"} · ${result.dependencyCount} packages checked`);
  if (result.since) lines.push(c(90, `Only dependencies added or changed since ${result.since} (${result.unchangedCount ?? 0} unchanged packages skipped)`));
  for (const w of result.warnings) lines.push(c(33, `warning: ${w}`));
  lines.push("");
  if (result.findings.length === 0) {
    lines.push(c(32, "No orphaned or unpatched dependencies found."));
    return lines.join("\n");
  }
  const quiet = result.findings.filter((f) => f.kind === "orphaned");
  const shown = showAll ? result.findings : result.findings.filter((f) => f.kind !== "orphaned");
  const stuckGroups = new Map<string, Finding[]>();
  for (const f of shown) {
    const tagColor = f.kind === "malicious" ? 41 : f.kind === "patch-available" ? 36 : f.kind === "orphaned-vulnerable" ? 31 : f.kind === "unpatched-vulnerable" ? 33 : 90;
    const tag = c(tagColor, KIND_LABEL[f.kind].padEnd(14));
    const sev = f.severity === "UNKNOWN" ? "" : ` [${f.severity}]`;
    const stuck = stuckBehind(f, result.findings);
    if (stuck) stuckGroups.set(stuck.join(", "), [...(stuckGroups.get(stuck.join(", ")) ?? []), f]);
    const note = f.dependency.direct ? "" : ` (${relationNote(f.dependency).replace(/^transitive, via /, stuck ? "transitive, via unmaintained " : "$&")})`;
    lines.push(`${tag} ${f.dependency.name}@${f.dependency.version}${sev}${c(90, note)}`);
    // "Upgrade normally" does not hold when the only parent will never update (see the line under the list)
    lines.push(`               ${f.message.replace(/^[^:]+: /, "").replace(stuck ? / Upgrade normally; no patch needed\.$/ : /$^/, "")}`);
    for (const a of f.advisories.slice(0, 3)) lines.push(c(90, `               - ${a.id}: ${a.title}`));
    if (f.advisories.length > 3) lines.push(c(90, `               - ...and ${f.advisories.length - 3} more`));
    if (f.funding?.length) lines.push(c(35, `               fund: ${f.funding.slice(0, 2).map((u) => `${fundingLabel(u)} (${u})`).join(", ")}`));
    if (f.alternatives) lines.push(c(32, `               consider: ${describeAlternatives(f.alternatives)}`));
  }
  // One line per unmaintained direct dependency that holds fixes back, instead of one per finding.
  const stuckLines: string[] = [];
  for (const [parents, group] of stuckGroups) {
    const many = parents.includes(",");
    const force = group[0]!.dependency.ecosystem === "npm" ? "an npm override" : "pinning the fixed versions in your own manifest";
    stuckLines.push(
      c(
        33,
        `${group.length} vulnerable package${group.length > 1 ? "s come" : " comes"} in only through ${parents}, which nobody maintains, so ${many ? "they" : "it"} will not move to the fixed version${group.length > 1 ? "s" : ""}: replace ${parents}, or force the fix${group.length > 1 ? "es" : ""} with ${force}.`,
      ),
    );
  }
  if (!showAll && quiet.length > 0) {
    const direct = quiet.filter((f) => f.dependency.direct);
    const transitive = quiet.filter((f) => !f.dependency.direct);
    lines.push(c(90, `ORPHANED       ${quiet.length} widely used dependencies nobody maintains, with no known vulnerability today`));
    if (direct.length) lines.push(c(90, `               ${direct.length} you depend on directly: ${nameList(direct)}`));
    if (transitive.length) {
      const top = topVia(transitive);
      lines.push(c(90, `               ${transitive.length} come in through other packages${top ? `, mostly via ${top}` : `: ${nameList(transitive)}`}`));
    }
    lines.push(c(90, `               Run with --all to list them.`));
  }
  lines.push("");
  if (stuckLines.length) lines.push(...stuckLines, "");
  lines.push(summaryLine(result.findings));
  if (result.findings.some((f) => f.kind === "malicious"))
    lines.push(c(41, "Known malware is installed. Remove it, then rotate every credential and token this machine and your CI can reach."));
  if (result.findings.some((f) => f.kind === "patch-available")) lines.push(c(36, "Run `npx foster-oss fix` to switch to the patched packages."));
  if (shown.some((f) => f.kind !== "patch-available" && f.kind !== "orphaned" && f.dependency.via?.length))
    lines.push(c(90, "A transitive package is fixed by upgrading (or replacing) the direct dependency named after \"via\"."));
  if (result.findings.some((f) => f.kind === "orphaned-vulnerable"))
    lines.push("Orphaned + vulnerable packages can be nominated for adoption: https://github.com/foster-oss/foster/issues/new?template=adopt.yml");
  return lines.join("\n");
}

function summaryLine(findings: Finding[]): string {
  const n = counts(findings);
  // "(2 direct)" only when some of them are transitive: the direct ones are what the project can change itself
  const part = (k: FindingKind, label: string) => `${n[k].total} ${label}${n[k].direct < n[k].total ? ` (${n[k].direct} direct)` : ""}`;
  return `Summary: ${n.malicious.total ? `${part("malicious", "MALWARE")} · ` : ""}${part("patch-available", "patch available")} · ${part("orphaned-vulnerable", "orphaned+vulnerable")} · ${part("unpatched-vulnerable", "no fix yet")} · ${part("upgrade-available", "upgrade")} · ${part("orphaned", "orphaned")}`;
}

/** Markdown for PR comments and GitHub job summaries. */
export function formatMarkdown(result: ScanResult): string {
  const out: string[] = ["## 🏠 Foster dependency check", ""];
  if (result.since) out.push(`Dependencies **added or changed** since \`${result.since.slice(0, 12)}\` (${result.unchangedCount ?? 0} unchanged packages skipped).`, "");
  if (result.findings.length === 0) {
    out.push(result.since && result.dependencyCount === 0 ? "No dependency changes. ✅" : `No orphaned or unpatched dependencies among ${result.dependencyCount} ${result.since ? "new or changed " : ""}packages. ✅`);
  } else {
    for (const kind of Object.keys(KIND_TITLE) as FindingKind[]) {
      const group = result.findings.filter((f) => f.kind === kind);
      if (group.length === 0) continue;
      const collapse = kind === "orphaned";
      const direct = group.filter((f) => f.dependency.direct).length;
      const count = direct < group.length ? `${group.length}: ${direct} direct, ${group.length - direct} transitive` : `${group.length}`;
      if (collapse) out.push(`<details><summary><b>${KIND_TITLE[kind]} (${count})</b>: no known vulnerability today</summary>`, "");
      else out.push(`### ${KIND_TITLE[kind]} (${count})`, "");
      out.push("| Package | Severity | Maintenance | Advisories | Action |", "|---|---|---|---|---|");
      for (const f of group) {
        const adv = f.advisories.slice(0, 3).map((a) => `[${a.id}](${a.url})`).join(", ") || "-";
        const stuck = stuckBehind(f, result.findings);
        const action = f.kind === "malicious"
          ? `**remove now**${f.fixedIn ? ` (or move to ${f.fixedIn})` : ""}, then rotate credentials`
          : stuck
          ? `replace ${stuck.map((n) => `\`${n}\``).join(", ")} (unmaintained, will not move to the fix)${f.fixedIn ? `, or force ${f.fixedIn}` : ""}`
          : f.kind === "patch-available"
            ? `\`npx foster-oss fix\` → \`${f.patch!.replacement.name}@${f.patch!.replacement.version}\``
            : f.kind === "upgrade-available"
              ? `upgrade${f.fixedIn ? ` to ${f.fixedIn}` : ""}`
              : f.alternatives
                ? `replace with ${f.alternatives.options.slice(0, 3).map((o) => (o.kind === "snippet" ? "a snippet" : `\`${o.name}\``)).join(", ")}${f.alternatives.docs ? ` ([guide](${f.alternatives.docs}))` : ""}`
                : f.kind === "orphaned-vulnerable"
                  ? "[nominate for adoption](https://github.com/foster-oss/foster/issues/new?template=adopt.yml)"
                  : "watch";
        out.push(`| \`${f.dependency.name}@${f.dependency.version}\`${f.dependency.direct ? "" : ` <sub>${relationNote(f.dependency)}</sub>`} | ${f.severity} | ${f.status} | ${adv} | ${action} |`);
      }
      out.push("");
      if (collapse) out.push("</details>", "");
    }
    out.push(summaryLine(result.findings));
  }
  for (const w of result.warnings) out.push("", `> ⚠️ ${w}`);
  out.push("", `<sub>Checked ${result.dependencyCount} packages from ${result.lockfiles.join(", ") || "no lockfile"} with [Foster](https://github.com/foster-oss/foster).</sub>`);
  return out.join("\n");
}

export function formatFix(result: FixResult, installCmd: string): string {
  const lines: string[] = [];
  if (result.changes.length === 0 && result.skipped.length === 0) return "Nothing to fix: no released drop-in patch matches your dependencies.";
  for (const ch of result.changes) {
    const verb = ch.applied ? (result.written ? "updated" : "would update") : "kept";
    lines.push(`${verb} ${ch.file ? `${ch.file} ` : ""}${ch.field}["${ch.key}"]: ${ch.from ?? "(none)"} → ${ch.to}${ch.note ? `  (${ch.note})` : ""}`);
  }
  for (const s of result.skipped) lines.push(`skipped ${s.package}: ${s.reason}`);
  if (result.written) {
    const files = [...new Set(result.changes.filter((ch) => ch.applied).map((ch) => ch.file ?? "package.json"))];
    lines.push("", `${files.join(", ")} updated. Now run \`${installCmd}\` and your tests.`);
  }
  return lines.join("\n");
}

export function formatRecord(r: OrphanRecord): string {
  const lines = [
    `${r.name} (${r.ecosystem}): ${r.status.toUpperCase()}`,
    ...(r.reasons.length ? [`  why: ${r.reasons.join("; ")}`] : []),
    `  latest: ${r.latestVersion ?? "?"}${r.latestReleaseAt ? ` (${r.latestReleaseAt.slice(0, 10)})` : ""}`,
    `  reach: ${fmt(r.downloadsLastMonth)} downloads/month · ${fmt(r.dependentRepos)} dependent repos · ${fmt(r.dependentPackages)} dependent packages`,
    `  repo: ${r.repoUrl ?? "none"}${r.archived ? " (archived)" : ""}`,
  ];
  if (r.unpatchedAdvisories.length) {
    lines.push(`  advisories with no fix:`);
    for (const a of r.unpatchedAdvisories) lines.push(`    - ${a.id} [${a.severity}] ${a.title}${a.range ? ` (${a.range})` : ""}`);
  }
  return lines.join("\n");
}

function fmt(n: number | null): string {
  if (n === null) return "?";
  return Intl.NumberFormat("en", { notation: "compact" }).format(n);
}

const SARIF_LEVEL: Record<FindingKind, "error" | "warning" | "note"> = {
  malicious: "error",
  "orphaned-vulnerable": "error",
  "patch-available": "warning",
  "unpatched-vulnerable": "warning",
  "upgrade-available": "warning",
  orphaned: "note",
};

const SECURITY_SEVERITY: Record<string, string | undefined> = { CRITICAL: "9.5", HIGH: "7.5", MODERATE: "5.5", LOW: "3.0" };

const RULE_HELP: Record<FindingKind, string> = {
  malicious: "This exact package version is a known malicious package or a hijacked release (OSV, OpenSSF malicious-packages). Remove it or move to an unaffected version, then rotate every credential and token the machine or CI runner could reach: install scripts run before any of your code does.",
  "patch-available": "A published drop-in security patch exists for this exact version. Run `npx foster-oss fix` to switch to it through an npm alias; your imports do not change.",
  "orphaned-vulnerable": "This dependency has a known vulnerability that no release fixes, and nobody appears to maintain it. Replace it, or nominate it for adoption.",
  "unpatched-vulnerable": "This dependency has a known vulnerability with no fixed release yet. The package still looks maintained; watch for a release.",
  "upgrade-available": "This dependency has a known vulnerability that a newer upstream release fixes. Upgrade it.",
  orphaned: "This widely used dependency is no longer maintained. There is no known vulnerability today, but nobody will fix one. Prefer a maintained alternative for new code.",
};

/**
 * SARIF 2.1.0 for GitHub code scanning and other security dashboards.
 * Locations point at the lockfile line that declares the package, relative to `baseDir`.
 */
export function formatSarif(result: ScanResult, version: string, baseDir: string = process.cwd(), includeQuiet = false): string {
  const lockText = new Map<string, string[]>();
  const lineOf = (source: string, name: string): number => {
    let lines = lockText.get(source);
    if (!lines) {
      try {
        lines = readFileSync(join(result.dir, source), "utf8").split(/\r?\n/);
      } catch {
        lines = [];
      }
      lockText.set(source, lines);
    }
    const needles = [`node_modules/${name}"`, `"${name}"`, `/${name}@`, `${name}@`, ` ${name} `, name];
    for (const n of needles) {
      const i = lines.findIndex((l) => l.includes(n));
      if (i >= 0) return i + 1;
    }
    return 1;
  };
  const kinds = Object.keys(KIND_TITLE) as FindingKind[];
  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Foster",
            informationUri: "https://github.com/foster-oss/foster",
            version,
            rules: kinds.map((k) => ({
              id: `foster/${k}`,
              name: KIND_TITLE[k].replace(/[^A-Za-z]+/g, ""),
              shortDescription: { text: KIND_TITLE[k] },
              fullDescription: { text: RULE_HELP[k] },
              help: { text: RULE_HELP[k], markdown: RULE_HELP[k] },
              helpUri: "https://github.com/foster-oss/foster#what-the-findings-mean",
              defaultConfiguration: { level: SARIF_LEVEL[k] },
              properties: { tags: ["security", "supply-chain", "dependencies"] },
            })),
          },
        },
        // Quiet orphans (no known vulnerability) only with --all, like the text report: alerts must be actionable.
        results: result.findings.filter((f) => includeQuiet || f.kind !== "orphaned").map((f) => {
          const rel = relative(baseDir, join(result.dir, f.dependency.source)).replace(/\\/g, "/");
          // Another drive (Windows) or outside the checkout: fall back to an absolute file URI.
          const uri = /^[A-Za-z]:\//.test(rel) || rel.startsWith("/") ? `file:///${rel.replace(/^\//, "")}` : rel;
          const extra = (f.alternatives ? ` Consider: ${describeAlternatives(f.alternatives)}.` : "") + (f.dependency.direct ? "" : ` (${relationNote(f.dependency)})`);
          return {
            ruleId: `foster/${f.kind}`,
            level: SARIF_LEVEL[f.kind],
            message: { text: `${f.message}${extra}` },
            locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: lineOf(f.dependency.source, f.dependency.name) } } }],
            partialFingerprints: { "fosterDependency/v1": `${f.dependency.ecosystem}:${f.dependency.name}@${f.dependency.version}:${f.kind}` },
            properties: {
              ...(SECURITY_SEVERITY[f.severity] ? { "security-severity": SECURITY_SEVERITY[f.severity] } : {}),
              ecosystem: f.dependency.ecosystem,
              package: f.dependency.name,
              version: f.dependency.version,
              direct: f.dependency.direct,
              ...(f.dependency.via ? { via: f.dependency.via } : {}),
              maintenance: f.status,
              advisories: f.advisories.map((a) => a.id),
            },
          };
        }),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}
