import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { installSkill, skillText } from "../src/lib/skill.js";

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

  it("installs for named agents and reports unknown ones", () => {
    const dir = tmp();
    const { installed, unknownAgents } = installSkill(dir, { agents: ["cursor", "kiro", "nope"], home: tmp() });
    expect(installed.map((p) => p.slice(dir.length + 1).replace(/\\/g, "/"))).toEqual([".agents/skills/foster", ".kiro/skills/foster"]);
    expect(unknownAgents).toEqual(["nope"]);
  });
});
