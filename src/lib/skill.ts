import { cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
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
 * GitHub Copilot, OpenCode, Amp, Cline, Zed, Warp, Kimi, …); the others keep their own (Hermes, Windsurf, Kiro, …).
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
  [["hermes", "hermes-agent"], ".hermes/skills", ".hermes/skills"],
  [["crush"], ".crush/skills", ".config/crush/skills"],
  [["devin"], ".devin/skills", ".config/devin/skills"],
  [["mistral-vibe", "vibe"], ".vibe/skills", ".vibe/skills"],
  [["pi"], ".pi/skills", ".pi/agent/skills"],
  [["tabnine", "tabnine-cli"], ".tabnine/agent/skills", ".tabnine/agent/skills"],
  [["qoder"], ".qoder/skills", ".qoder/skills"],
  [["codebuddy"], ".codebuddy/skills", ".codebuddy/skills"],
  [["zencoder"], ".zencoder/skills", ".zencoder/skills"],
];

/** Folders that are always written: the shared folder and Claude Code's. */
const DEFAULT_PROJECT = [".agents/skills", ".claude/skills"];

export interface SkillInstallOptions {
  global?: boolean;
  /** agent ids from AGENT_DIRS; empty means "the shared folders plus every agent already set up here" */
  agents?: string[];
  home?: string;
  /** add Claude Code permission rules for Foster's own check (default: true) */
  permissions?: boolean;
}

export interface SkillInstallResult {
  installed: string[];
  unknownAgents: string[];
  /** settings files that now allow Foster's check, and ones that could not be read */
  permissions: { updated: string[]; skipped: string[] };
}

/**
 * The commands the skill tells an agent to run. They only read (check a command or a package, never
 * install), so Claude Code may run them without a prompt. Claude Code runs commands through its Bash
 * tool, or its PowerShell tool on Windows, and each tool has its own rules. Auto mode drops the npx
 * rules (they fetch and run code) and blocks "npx -y …@latest", so there the skill uses an installed
 * foster-oss, which auto mode lets run.
 */
export const CHECK_RULES = [
  "Bash(npx -y foster-oss@latest guard:*)",
  "Bash(npx -y foster-oss guard:*)",
  "Bash(npx foster-oss guard:*)",
  "Bash(foster-oss guard:*)",
  "Bash(npx -y foster-oss@latest check:*)",
  "Bash(npx foster-oss check:*)",
  "Bash(foster-oss check:*)",
  "PowerShell(npx -y foster-oss@latest guard *)",
  "PowerShell(npx foster-oss guard *)",
  "PowerShell(foster-oss guard *)",
  "PowerShell(npx -y foster-oss@latest check *)",
  "PowerShell(npx foster-oss check *)",
  "PowerShell(foster-oss check *)",
];

/**
 * Whether an installed foster-oss is on PATH (not npx's temporary copy or a project's node_modules/.bin,
 * which an agent's shell does not see). Works with POSIX and Windows PATHs and npm's .cmd/.ps1 shims.
 */
export function fosterOnPath(env: NodeJS.ProcessEnv = process.env, platform: NodeJS.Platform = process.platform): boolean {
  const pathVar = env.PATH ?? env.Path ?? "";
  const sep = platform === "win32" ? ";" : ":";
  const names = platform === "win32" ? ["foster-oss.cmd", "foster-oss.ps1", "foster-oss.exe", "foster-oss"] : ["foster-oss"];
  return pathVar.split(sep).some((d) => {
    if (!d || /[\\/]_npx[\\/]|node_modules[\\/]\.bin/.test(d)) return false;
    return names.some((n) => existsSync(join(d, n)));
  });
}

/** Merge CHECK_RULES into a Claude Code settings file. Returns false when the file exists but is not JSON. */
export function allowChecks(settingsPath: string): boolean {
  let settings: Record<string, unknown> = {};
  if (existsSync(settingsPath)) {
    try {
      const parsed = JSON.parse(readFileSync(settingsPath, "utf8")) as unknown;
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return false;
      settings = parsed as Record<string, unknown>;
    } catch {
      return false; // never rewrite a file we cannot read
    }
  }
  const perms = (settings.permissions && typeof settings.permissions === "object" ? settings.permissions : {}) as Record<string, unknown>;
  const allow = Array.isArray(perms.allow) ? (perms.allow as unknown[]).filter((r): r is string => typeof r === "string") : [];
  const missing = CHECK_RULES.filter((r) => !allow.includes(r));
  if (!missing.length) return true;
  settings.permissions = { ...perms, allow: [...(Array.isArray(perms.allow) ? perms.allow : []), ...missing] };
  mkdirSync(join(settingsPath, ".."), { recursive: true });
  writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + "\n");
  return true;
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
  const permissions = { updated: [] as string[], skipped: [] as string[] };
  if (opts.permissions !== false && [...targets].includes(".claude/skills")) {
    const file = join(base, ".claude", "settings.json");
    (allowChecks(file) ? permissions.updated : permissions.skipped).push(file);
  }
  return { installed, unknownAgents, permissions };
}
