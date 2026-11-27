import { cpSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/** The skill folder shipped in the npm package (skills/foster, the Agent Skills format). */
export const SKILL_DIR = fileURLToPath(new URL("../../skills/foster", import.meta.url));

export function skillText(): string {
  return readFileSync(join(SKILL_DIR, "SKILL.md"), "utf8");
}

/**
 * Where agents look for skills: [agent ids, project folder, global folder (relative to home)].
 * `.agents/skills` is the shared folder of the Agent Skills standard (Codex, Cursor, Gemini CLI,
 * GitHub Copilot, OpenCode, Amp, Cline, Zed, Warp, …); a few agents keep their own.
 */
export const AGENT_DIRS: [string[], string, string | null][] = [
  [["claude-code", "claude"], ".claude/skills", ".claude/skills"],
  [["codex"], ".agents/skills", ".codex/skills"],
  [["cursor"], ".agents/skills", ".cursor/skills"],
  [["gemini-cli", "gemini"], ".agents/skills", ".gemini/skills"],
  [["github-copilot", "copilot"], ".agents/skills", ".copilot/skills"],
  [["opencode"], ".agents/skills", ".config/opencode/skills"],
  [["amp"], ".agents/skills", ".config/agents/skills"],
  [["cline", "zed", "warp", "universal"], ".agents/skills", ".agents/skills"],
  [["windsurf"], ".windsurf/skills", ".codeium/windsurf/skills"],
  [["roo"], ".roo/skills", ".roo/skills"],
  [["kiro", "kiro-cli"], ".kiro/skills", ".kiro/skills"],
  [["goose"], ".goose/skills", ".config/goose/skills"],
  [["continue"], ".continue/skills", ".continue/skills"],
  [["kilo"], ".kilocode/skills", ".kilocode/skills"],
  [["qwen-code", "qwen"], ".qwen/skills", ".qwen/skills"],
  [["trae"], ".trae/skills", ".trae/skills"],
  [["droid", "factory"], ".factory/skills", ".factory/skills"],
  [["augment"], ".augment/skills", ".augment/skills"],
  [["openhands"], ".openhands/skills", ".openhands/skills"],
  [["junie"], ".junie/skills", ".junie/skills"],
];

/** Folders that are always written: the shared folder and Claude Code's. */
const DEFAULT_PROJECT = [".agents/skills", ".claude/skills"];

export interface SkillInstallOptions {
  global?: boolean;
  /** agent ids from AGENT_DIRS; empty means "the shared folders plus every agent already set up here" */
  agents?: string[];
  home?: string;
}

export interface SkillInstallResult {
  installed: string[];
  unknownAgents: string[];
}

/**
 * Copy the skill into the skills folders agents read. Without `agents`, the project install writes the
 * shared `.agents/skills` and `.claude/skills` plus any agent folder that already exists in the project;
 * the global install writes into the home folder of every agent that is installed (and ~/.agents/skills).
 */
export function installSkill(dir: string, opts: SkillInstallOptions = {}): SkillInstallResult {
  const home = opts.home ?? homedir();
  const base = opts.global ? home : dir;
  const unknownAgents: string[] = [];
  const targets = new Set<string>();
  if (opts.agents?.length) {
    for (const a of opts.agents) {
      const row = AGENT_DIRS.find(([ids]) => ids.includes(a.toLowerCase()));
      if (!row) { unknownAgents.push(a); continue; }
      const rel = opts.global ? row[2] : row[1];
      if (rel) targets.add(rel);
    }
  } else if (opts.global) {
    targets.add(".agents/skills");
    for (const [, , g] of AGENT_DIRS) {
      if (!g) continue;
      // ".config/opencode/skills" belongs to an agent whose home is ".config/opencode"
      const agentHome = g.replace(/\/skills$/, "");
      if (agentHome !== ".agents" && existsSync(join(home, agentHome))) targets.add(g);
    }
  } else {
    DEFAULT_PROJECT.forEach((t) => targets.add(t));
    for (const [, p] of AGENT_DIRS) if (existsSync(join(dir, p.split("/")[0]!))) targets.add(p);
  }
  const installed: string[] = [];
  for (const rel of [...targets].sort()) {
    const dest = join(base, rel, "foster");
    mkdirSync(dest, { recursive: true });
    cpSync(SKILL_DIR, dest, { recursive: true });
    installed.push(dest);
  }
  return { installed, unknownAgents };
}
