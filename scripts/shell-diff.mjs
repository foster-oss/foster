#!/usr/bin/env node
/**
 * Differential test of guard's command parser against real shells.
 *
 * Every command in the corpus is run in a real shell (bash, PowerShell, cmd) with fake package managers on
 * PATH: npm, pip, cargo, … only record the arguments they receive. What the shell actually ran is the truth;
 * guard's parser must see every package in it. A package the shell installs that guard did not see is a
 * MISS (a way past guard); a package guard reports that the shell never installs is EXTRA (a false alarm).
 * Either fails the run, except EXTRA on corpus lines marked `conservative` (a || b checks b on purpose).
 *
 *   node scripts/shell-diff.mjs [bash|pwsh|powershell|cmd ...]   (default: the shells this machine has)
 *
 * Nothing is installed and nothing touches the network: the fake tools only write a log line.
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { commandLineFrom, parseCommand } from "../dist/lib/guard.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const corpus = JSON.parse(readFileSync(join(root, "test/fixtures/shell-diff/corpus.json"), "utf8"));
const TOOLS = ["npm", "npx", "pnpm", "pnpx", "yarn", "bun", "bunx", "deno", "corepack", "pip", "pip3", "uv", "uvx", "pipx", "poetry", "pipenv", "cargo", "go", "gem", "bundle", "composer"];
// commands that need privileges, open windows, detach, or reach other machines: not run here
const SKIP = /\b(sudo|doas|su|runuser|wsl|docker|ssh|start|Start-Process|saps|watch|flock|xvfb-run|nvm|fnm|mise|volta|asdf|ionice|script)\b/;

const work = mkdtempSync(join(tmpdir(), "foster-shell-diff-"));
const bin = join(work, "bin");
const log = join(work, "calls.jsonl");
const fake = join(work, "fake.cjs");
mkdirSync(bin);
for (const d of ["web", "app", "d", "sp dir", "packages/a"]) mkdirSync(join(work, "cwd", d), { recursive: true });
// one line per call: the words, separated by the ASCII unit separator
writeFileSync(fake, `require("fs").appendFileSync(process.env.FOSTER_DIFF_LOG, process.argv.slice(2).join("\\x1f") + "\\n");\n`);
for (const tool of TOOLS) {
  // a shell script for bash (also Git Bash on Windows, which ignores .cmd), a .cmd shim for cmd and PowerShell
  writeFileSync(join(bin, tool), `#!/bin/sh\n{ printf '%s' ${tool}; for a in "$@"; do printf '\\037%s' "$a"; done; printf '\\n'; } >> "$FOSTER_DIFF_LOG"\n`, { mode: 0o755 });
  if (process.platform === "win32") writeFileSync(join(bin, `${tool}.cmd`), `@node "%FOSTER_FAKE%" ${tool} %*\r\n`);
}

const available = (shell) => {
  const args = shell === "cmd" ? ["/d", "/c", "exit 0"] : shell === "bash" ? ["-c", "exit 0"] : ["-NoProfile", "-Command", "exit 0"];
  return spawnSync(shell, args, { stdio: "ignore" }).status === 0;
};
const wanted = process.argv.slice(2);
const shells = (wanted.length ? wanted : ["bash", "pwsh", "powershell", "cmd"]).filter((s) => (s !== "cmd" && s !== "powershell") || process.platform === "win32").filter(available);

const env = { ...process.env, PATH: `${bin}${delimiter}${process.env.PATH ?? process.env.Path ?? ""}`, FOSTER_FAKE: fake, FOSTER_DIFF_LOG: log };
delete env.Path;
const cwd = join(work, "cwd");

function run(shell, line) {
  writeFileSync(log, "");
  const opts = { cwd, env, input: "zzsent\n", timeout: 20_000, encoding: "utf8", windowsVerbatimArguments: shell === "cmd" };
  const args =
    shell === "cmd" ? ["/d", "/s", "/c", `"${line}"`] : shell === "bash" ? ["-c", line] : ["-NoProfile", "-NonInteractive", "-Command", line];
  const res = spawnSync(shell, args, opts);
  const calls = readFileSync(log, "utf8").split("\n").filter(Boolean).map((l) => l.replace(/\r$/, "").split("\x1f"));
  return { status: res.status, calls };
}

const key = (p) => `${p.ecosystem}:${p.name.toLowerCase()}`;
let misses = 0;
let extras = 0;
let ran = 0;
for (const shell of shells) {
  const cases = corpus.filter((c) => c.shell === (shell === "powershell" ? "pwsh" : shell) && !SKIP.test(c.line));
  // `conservative` marks a line where guard checks more than this shell runs on purpose (a || b checks b)
  for (const { line, conservative } of cases) {
    const { calls } = run(shell, line);
    ran++;
    const truth = new Map();
    for (const argv of calls) for (const p of parseCommand(commandLineFrom(argv), cwd).packages) if (!p.unresolved) truth.set(key(p), p);
    const seen = parseCommand(line, cwd).packages;
    const asks = seen.some((p) => p.unresolved); // guard asks about what it cannot see: that covers it
    const seenKeys = new Set(seen.map(key));
    const missed = [...truth.keys()].filter((k) => !seenKeys.has(k));
    const extra = [...seenKeys].filter((k) => !truth.has(k) && !seen.find((p) => key(p) === k)?.unresolved);
    if (missed.length && !asks) {
      misses++;
      console.log(`MISS  [${shell}] ${JSON.stringify(line)}\n      shell ran: ${calls.map((c) => c.join(" ")).join(" | ")}\n      guard saw: ${[...seenKeys].join(", ") || "nothing"}`);
    }
    if (extra.length && calls.length && !conservative) {
      extras++;
      console.log(`EXTRA [${shell}] ${JSON.stringify(line)}\n      shell ran: ${calls.map((c) => c.join(" ")).join(" | ")}\n      guard saw: ${extra.join(", ")}`);
    }
  }
}
rmSync(work, { recursive: true, force: true });
console.log(`shell-diff: ${ran} command lines in ${shells.join(", ")}: ${misses} missed, ${extras} with extra packages`);
// a miss is a way past guard, an extra a false alarm: both fail (mark deliberate extras `conservative`)
process.exit(misses || extras ? 1 : 0);
