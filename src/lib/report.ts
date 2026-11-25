import type { FixResult } from "./fix.js";
import type { Finding, FindingKind, OrphanRecord, ScanResult } from "./types.js";

const KIND_LABEL: Record<FindingKind, string> = {
  "patch-available": "PATCH READY",
  "orphaned-vulnerable": "ORPHANED+VULN",
  "unpatched-vulnerable": "NO FIX YET",
  "upgrade-available": "UPGRADE",
  orphaned: "ORPHANED",
};

const KIND_TITLE: Record<FindingKind, string> = {
  "patch-available": "Drop-in security patch available",
  "orphaned-vulnerable": "Vulnerable, no fix exists, and nobody maintains it",
  "unpatched-vulnerable": "Vulnerable, no fix released yet",
  "upgrade-available": "Vulnerable, fixed upstream: just upgrade",
  orphaned: "Widely used but unmaintained",
};

function counts(findings: Finding[]): Record<FindingKind, number> {
  const c: Record<FindingKind, number> = { "patch-available": 0, "orphaned-vulnerable": 0, "unpatched-vulnerable": 0, "upgrade-available": 0, orphaned: 0 };
  for (const f of findings) c[f.kind]++;
  return c;
}

export function formatText(result: ScanResult, color = false, showAll = false): string {
  const c = (code: number, s: string) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const lines: string[] = [];
  lines.push(c(1, `Foster scan: ${result.dir}`));
  lines.push(`Lockfiles: ${result.lockfiles.join(", ") || "none"} · ${result.dependencyCount} packages checked`);
  for (const w of result.warnings) lines.push(c(33, `warning: ${w}`));
  lines.push("");
  if (result.findings.length === 0) {
    lines.push(c(32, "No orphaned or unpatched dependencies found."));
    return lines.join("\n");
  }
  const quiet = result.findings.filter((f) => f.kind === "orphaned");
  const shown = showAll ? result.findings : result.findings.filter((f) => f.kind !== "orphaned");
  for (const f of shown) {
    const tagColor = f.kind === "patch-available" ? 36 : f.kind === "orphaned-vulnerable" ? 31 : f.kind === "unpatched-vulnerable" ? 33 : 90;
    const tag = c(tagColor, KIND_LABEL[f.kind].padEnd(14));
    const sev = f.severity === "UNKNOWN" ? "" : ` [${f.severity}]`;
    lines.push(`${tag} ${f.dependency.name}@${f.dependency.version}${sev}${f.dependency.direct ? "" : c(90, " (transitive)")}`);
    lines.push(`               ${f.message.replace(/^[^:]+: /, "")}`);
    for (const a of f.advisories.slice(0, 3)) lines.push(c(90, `               - ${a.id}: ${a.title}`));
    if (f.advisories.length > 3) lines.push(c(90, `               - ...and ${f.advisories.length - 3} more`));
  }
  if (!showAll && quiet.length > 0) {
    const names = quiet.slice(0, 6).map((f) => f.dependency.name).join(", ");
    lines.push(
      c(90, `ORPHANED       ${quiet.length} widely used dependencies nobody maintains, with no known vulnerability today: ${names}${quiet.length > 6 ? ", …" : ""}`),
      c(90, `               Run with --all to list them.`),
    );
  }
  lines.push("");
  lines.push(summaryLine(result.findings));
  if (result.findings.some((f) => f.kind === "patch-available")) lines.push(c(36, "Run `npx foster-oss fix` to switch to the patched packages."));
  if (result.findings.some((f) => f.kind === "orphaned-vulnerable"))
    lines.push("Orphaned + vulnerable packages can be nominated for adoption: https://github.com/rekalnx/foster/issues/new?template=adopt.yml");
  return lines.join("\n");
}

function summaryLine(findings: Finding[]): string {
  const n = counts(findings);
  return `Summary: ${n["patch-available"]} patch available · ${n["orphaned-vulnerable"]} orphaned+vulnerable · ${n["unpatched-vulnerable"]} no fix yet · ${n["upgrade-available"]} upgrade · ${n.orphaned} orphaned`;
}

/** Markdown for PR comments and GitHub job summaries. */
export function formatMarkdown(result: ScanResult): string {
  const out: string[] = ["## 🏠 Foster dependency check", ""];
  if (result.findings.length === 0) {
    out.push(`No orphaned or unpatched dependencies among ${result.dependencyCount} packages. ✅`);
  } else {
    for (const kind of Object.keys(KIND_TITLE) as FindingKind[]) {
      const group = result.findings.filter((f) => f.kind === kind);
      if (group.length === 0) continue;
      const collapse = kind === "orphaned";
      if (collapse) out.push(`<details><summary><b>${KIND_TITLE[kind]} (${group.length})</b>: no known vulnerability today</summary>`, "");
      else out.push(`### ${KIND_TITLE[kind]} (${group.length})`, "");
      out.push("| Package | Severity | Maintenance | Advisories | Action |", "|---|---|---|---|---|");
      for (const f of group) {
        const adv = f.advisories.slice(0, 3).map((a) => `[${a.id}](${a.url})`).join(", ") || "-";
        const action =
          f.kind === "patch-available"
            ? `\`npx foster-oss fix\` → \`${f.patch!.replacement.name}@${f.patch!.replacement.version}\``
            : f.kind === "upgrade-available"
              ? `upgrade${f.fixedIn ? ` to ${f.fixedIn}` : ""}`
              : f.kind === "orphaned-vulnerable"
                ? "[nominate for adoption](https://github.com/rekalnx/foster/issues/new?template=adopt.yml)"
                : "watch";
        out.push(`| \`${f.dependency.name}@${f.dependency.version}\`${f.dependency.direct ? "" : " (transitive)"} | ${f.severity} | ${f.status} | ${adv} | ${action} |`);
      }
      out.push("");
      if (collapse) out.push("</details>", "");
    }
    out.push(summaryLine(result.findings));
  }
  for (const w of result.warnings) out.push("", `> ⚠️ ${w}`);
  out.push("", `<sub>Checked ${result.dependencyCount} packages from ${result.lockfiles.join(", ") || "no lockfile"} with [Foster](https://github.com/rekalnx/foster).</sub>`);
  return out.join("\n");
}

export function formatFix(result: FixResult, installCmd: string): string {
  const lines: string[] = [];
  if (result.changes.length === 0 && result.skipped.length === 0) return "Nothing to fix: no released drop-in patch matches your dependencies.";
  for (const ch of result.changes) {
    const verb = ch.applied ? (result.written ? "updated" : "would update") : "kept";
    lines.push(`${verb} ${ch.field}["${ch.key}"]: ${ch.from ?? "(none)"} → ${ch.to}${ch.note ? `  (${ch.note})` : ""}`);
  }
  for (const s of result.skipped) lines.push(`skipped ${s.package}: ${s.reason}`);
  if (result.written) lines.push("", `package.json updated. Now run \`${installCmd}\` and your tests.`);
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
