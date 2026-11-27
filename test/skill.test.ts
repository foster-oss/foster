import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CHECK_RULES, installSkill, skillText } from "../src/lib/skill.js";

const dirs: string[] = [];
const tmp = () => { const d = mkdtempSync(join(tmpdir(), "foster-skill-")); dirs.push(d); return d; };
afterEach(() => { while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true }); });

describe("skill", () => {
  it("follows the Agent Skills format: name matches the folder, description within 1024 characters", () => {
    const text = skillText();
    const front = /^---\n([\s\S]*?)\n---/.exec(text.replace(/\r\n/g, "\n"))![1]!;
    expect(/^name: foster$/m.test(front)).toBe(true);
    const description = /^description: (.*)$/m.exec(front)![1]!;
    expect(description.length).toBeGreaterThan(50);
    expect(description.length).toBeLessThanOrEqual(1024);
    expect(text).toContain("foster-oss@latest guard --");
  });

  it("installs into the shared folder, Claude Code's, and agents already set up in the project", () => {
    const dir = tmp();
    mkdirSync(join(dir, ".windsurf"));
    const { installed } = installSkill(dir, { home: tmp() });
    const rel = installed.map((p) => p.slice(dir.length + 1).replace(/\\/g, "/"));
    expect(rel).toEqual([".agents/skills/foster", ".claude/skills/foster", ".windsurf/skills/foster"]);
    expect(readFileSync(join(dir, ".agents/skills/foster/SKILL.md"), "utf8")).toContain("name: foster");
    expect(existsSync(join(dir, ".claude/skills/foster/references/findings.md"))).toBe(true);
  });

  it("installs globally only for agents that exist, plus the shared folder", () => {
    const home = tmp();
    mkdirSync(join(home, ".codex"));
    mkdirSync(join(home, ".claude"));
    const { installed } = installSkill(tmp(), { global: true, home });
    const rel = installed.map((p) => p.slice(home.length + 1).replace(/\\/g, "/"));
    expect(rel).toEqual([".agents/skills/foster", ".claude/skills/foster", ".codex/skills/foster"]);
  });

  it("knows Hermes, in the project and in the home folder", () => {
    const dir = tmp(), home = tmp();
    mkdirSync(join(home, ".hermes"));
    const rel = (base: string, paths: string[]) => paths.map((p) => p.slice(base.length + 1).replace(/\\/g, "/"));
    expect(rel(dir, installSkill(dir, { agents: ["hermes"], home }).installed)).toEqual([".hermes/skills/foster"]);
    expect(rel(home, installSkill(dir, { global: true, home }).installed)).toEqual([".agents/skills/foster", ".hermes/skills/foster"]);
  });

  it("lets Claude Code run Foster's own check without a prompt, merging into existing settings", () => {
    const dir = tmp();
    mkdirSync(join(dir, ".claude"));
    writeFileSync(join(dir, ".claude", "settings.json"), JSON.stringify({ model: "x", permissions: { allow: ["Bash(git status)"], deny: ["Bash(rm:*)"] } }));
    const { permissions } = installSkill(dir, { home: tmp() });
    expect(permissions.updated).toHaveLength(1);
    const s = JSON.parse(readFileSync(join(dir, ".claude", "settings.json"), "utf8"));
    expect(s.model).toBe("x");
    expect(s.permissions.deny).toEqual(["Bash(rm:*)"]);
    expect(s.permissions.allow[0]).toBe("Bash(git status)");
    for (const r of CHECK_RULES) expect(s.permissions.allow).toContain(r);
    // a second install adds nothing twice
    installSkill(dir, { home: tmp() });
    const again = JSON.parse(readFileSync(join(dir, ".claude", "settings.json"), "utf8"));
    expect(again.permissions.allow).toHaveLength(1 + CHECK_RULES.length);
    // the rules only cover the read-only check, never an install
    expect(CHECK_RULES.every((r) => / (guard|check):\*\)$/.test(r))).toBe(true);
  });

  it("leaves settings it cannot parse alone, and skips them on request or without Claude Code", () => {
    const dir = tmp();
    mkdirSync(join(dir, ".claude"));
    writeFileSync(join(dir, ".claude", "settings.json"), "{ not json");
    expect(installSkill(dir, { home: tmp() }).permissions.skipped).toHaveLength(1);
    expect(readFileSync(join(dir, ".claude", "settings.json"), "utf8")).toBe("{ not json");
    const d2 = tmp();
    expect(installSkill(d2, { home: tmp(), permissions: false }).permissions.updated).toEqual([]);
    expect(existsSync(join(d2, ".claude", "settings.json"))).toBe(false);
    const d3 = tmp();
    expect(installSkill(d3, { home: tmp(), agents: ["cursor"] }).permissions.updated).toEqual([]);
  });

  it("installs for named agents and reports unknown ones", () => {
    const dir = tmp();
    const { installed, unknownAgents } = installSkill(dir, { agents: ["cursor", "kiro", "nope"], home: tmp() });
    expect(installed.map((p) => p.slice(dir.length + 1).replace(/\\/g, "/"))).toEqual([".agents/skills/foster", ".kiro/skills/foster"]);
    expect(unknownAgents).toEqual(["nope"]);
  });
});
