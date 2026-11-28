import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { allowChecks, CHECK_RULES, fosterOnPath, installSkill, skillText, UNSAFE_RULES } from "../src/lib/skill.js";

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
    expect(CHECK_RULES.every((r) => / (guard|check)(:\*| \*)\)$/.test(r))).toBe(true);
    // Bash for macOS and Linux, PowerShell for Claude Code on Windows
    expect(CHECK_RULES).toContain("Bash(foster-oss guard:*)");
    expect(CHECK_RULES).toContain("PowerShell(foster-oss guard *)");
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

  it("finds an installed foster-oss on PATH, but not npx's temporary copy or node_modules/.bin", () => {
    // npm puts a plain script on macOS and Linux, .cmd and .ps1 shims on Windows
    const win = process.platform === "win32";
    const sep = win ? ";" : ":", name = win ? "foster-oss.cmd" : "foster-oss";
    const bin = tmp(), npx = join(tmp(), "_npx", "abc", "node_modules", ".bin");
    mkdirSync(npx, { recursive: true });
    writeFileSync(join(npx, name), "");
    expect(fosterOnPath({ PATH: npx })).toBe(false);
    writeFileSync(join(bin, name), "");
    expect(fosterOnPath({ PATH: [npx, bin].join(sep) })).toBe(true);
    expect(fosterOnPath({ Path: [join(bin, "nope"), bin].join(sep) })).toBe(true);
    expect(fosterOnPath({ PATH: "" })).toBe(false);
  });

  it("installs for named agents and reports unknown ones", () => {
    const dir = tmp();
    const { installed, unknownAgents } = installSkill(dir, { agents: ["cursor", "kiro", "nope"], home: tmp() });
    expect(installed.map((p) => p.slice(dir.length + 1).replace(/\\/g, "/"))).toEqual([".agents/skills/foster", ".kiro/skills/foster"]);
    expect(unknownAgents).toEqual(["nope"]);
  });
});

describe("allow rules", () => {
  const settingsIn = (text: string) => {
    const dir = mkdtempSync(join(tmpdir(), "foster-settings-"));
    mkdirSync(join(dir, ".claude"), { recursive: true });
    writeFileSync(join(dir, ".claude", "settings.json"), text);
    return join(dir, ".claude", "settings.json");
  };
  const allowOf = (file: string) => (JSON.parse(readFileSync(file, "utf8").replace(/^﻿/, "")) as { permissions: { allow: string[] } }).permissions.allow;

  it("never allows npx without @latest, which would run a project's own node_modules/.bin/foster-oss", () => {
    for (const r of CHECK_RULES) expect(r, r).not.toMatch(/npx (-y )?foster-oss (guard|check)/);
  });
  it("removes the unsafe rules earlier versions added, and keeps the user's own", () => {
    const file = settingsIn(JSON.stringify({ permissions: { allow: ["Bash(ls:*)", "Bash(npx foster-oss guard:*)", "PowerShell(npx foster-oss check *)"] } }));
    expect(allowChecks(file)).toBe(true);
    const allow = allowOf(file);
    expect(allow[0]).toBe("Bash(ls:*)");
    for (const bad of UNSAFE_RULES) expect(allow).not.toContain(bad);
    for (const good of CHECK_RULES) expect(allow).toContain(good);
  });
  it("reads settings with a BOM, an empty file and a single rule written as a string", () => {
    expect(allowChecks(settingsIn("﻿{}"))).toBe(true);
    expect(allowChecks(settingsIn(""))).toBe(true);
    const file = settingsIn(JSON.stringify({ permissions: { allow: "Bash(ls:*)" } }));
    expect(allowChecks(file)).toBe(true);
    expect(allowOf(file)[0]).toBe("Bash(ls:*)");
    expect(allowChecks(settingsIn(JSON.stringify({ permissions: [1, 2] })))).toBe(false);
  });
});
