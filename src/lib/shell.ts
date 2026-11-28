/**
 * `foster-oss shell-init <shell>`: shell functions that run `foster-oss guard` before package
 * installs typed by a person, the way the Claude Code hook does for an agent. A deny cancels the
 * install, an ask prompts "Install anyway? [y/N]" (cancelled when nobody can answer), and a guard
 * that cannot run lets the install through. `command npm ...` (bash/zsh) skips the check once.
 */

export const SHELLS = ["bash", "zsh", "powershell"] as const;
export type Shell = (typeof SHELLS)[number];

/**
 * First words that never install anything, per tool: these skip the check. Everything else goes to guard,
 * which knows the install forms (npm --prefix app install, npm create, bun x, uv run --with, …) and answers
 * quickly for the rest. "" means the tool run with no arguments (npm prints help; yarn and bundle install).
 */
const COMMON_SAFE = ["-h", "--help", "help", "-v", "-V", "--version", "version"];
const SAFE: Record<string, string[]> = {
  npm: ["", ...COMMON_SAFE, "run", "run-script", "rum", "urn", "test", "t", "tst", "start", "stop", "restart", "view", "info", "show", "ls", "list", "ll", "la", "outdated", "config", "get", "set", "whoami", "login", "logout", "adduser", "publish", "pack", "audit", "doctor", "prefix", "root", "explain", "why", "fund", "search", "owner", "team", "token", "ping", "cache", "completion", "docs", "home", "bugs", "repo", "edit", "uninstall", "remove", "rm", "r", "un", "unlink", "query", "diff", "sbom", "pkg", "access", "deprecate", "dist-tag", "unpublish", "star", "stars", "unstar", "shrinkwrap"],
  npx: [],
  pnpm: [...COMMON_SAFE, "run", "test", "t", "start", "exec", "ls", "list", "ll", "outdated", "why", "store", "remove", "rm", "uninstall", "un", "publish", "pack", "audit", "root", "bin", "config", "licenses"],
  yarn: [...COMMON_SAFE, "run", "test", "start", "build", "info", "why", "list", "outdated", "remove", "config", "cache", "bin", "publish", "pack", "plugin", "set", "constraints", "explain"],
  bun: ["", ...COMMON_SAFE, "run", "test", "build", "pm", "remove", "rm", "outdated", "publish", "upgrade"],
  bunx: [],
  pnpx: [],
  corepack: [...COMMON_SAFE, "enable", "disable"],
  pip: ["", ...COMMON_SAFE, "list", "show", "freeze", "uninstall", "config", "cache", "check", "debug", "search", "hash", "inspect", "completion"],
  pip3: ["", ...COMMON_SAFE, "list", "show", "freeze", "uninstall", "config", "cache", "check", "debug", "search", "hash", "inspect", "completion"],
  uv: ["", ...COMMON_SAFE, "venv", "python", "lock", "tree", "export", "cache", "self", "remove", "init", "build", "publish", "generate-shell-completion"],
  uvx: [],
  poetry: ["", ...COMMON_SAFE, "show", "check", "build", "publish", "config", "env", "new", "init", "remove", "lock", "search", "about", "shell", "list", "debug", "self", "export"],
  pipx: ["", ...COMMON_SAFE, "list", "uninstall", "uninstall-all", "ensurepath", "completions", "environment"],
  pipenv: [...COMMON_SAFE, "shell", "graph", "check", "lock", "--venv", "--where", "--rm", "clean", "uninstall", "open", "requirements", "scripts", "verify"],
  cargo: ["", ...COMMON_SAFE, "fmt", "new", "init", "search", "publish", "login", "logout", "owner", "yank", "clean", "remove", "rm", "uninstall", "locate-project", "pkgid", "report", "verify-project"],
  go: ["", ...COMMON_SAFE, "env", "fmt", "doc", "clean", "tool", "fix", "bug", "telemetry"],
  gem: ["", ...COMMON_SAFE, "list", "search", "info", "query", "env", "environment", "which", "contents", "uninstall", "cleanup", "sources", "specification", "dependency", "owner", "push", "yank", "build", "cert", "signin", "signout", "check", "outdated", "rdoc", "stale"],
  bundle: [...COMMON_SAFE, "show", "list", "info", "outdated", "config", "check", "open", "platform", "viz", "init", "gem", "binstubs", "clean", "doctor", "lock", "remove"],
  composer: ["", ...COMMON_SAFE, "show", "info", "outdated", "search", "depends", "why", "why-not", "prohibits", "diagnose", "validate", "config", "about", "list", "licenses", "status", "check-platform-reqs", "fund", "suggests", "archive", "run-script", "run", "exec", "dump-autoload", "dumpautoload", "clear-cache", "clearcache", "cc", "remove", "rm", "uninstall", "self-update", "audit", "bump", "browse", "home"],
};

function posix(shell: "bash" | "zsh"): string {
  const fns = Object.entries(SAFE).map(([tool, safe]) => {
    if (!safe.length) return `${tool}() { __foster_guard ${tool} "$@" || return 1; command ${tool} "$@"; }`;
    const patterns = safe.map((s) => (s === "" ? '""' : s)).join("|");
    return `${tool}() { case "\${1:-}" in ${patterns}) ;; *) __foster_guard ${tool} "$@" || return 1 ;; esac; command ${tool} "$@"; }`;
  });
  return [
    `# Foster guard for ${shell}: checks package installs before they run (https://github.com/foster-oss/foster).`,
    `# Add to ~/.${shell}rc:  eval "$(foster-oss shell-init ${shell})"`,
    `# Skip the check once: command npm install ...`,
    `__foster_guard() {`,
    `  if command -v foster-oss >/dev/null 2>&1; then command foster-oss guard --quiet -- "$@"`,
    `  else command npx -y foster-oss@latest guard --quiet -- "$@"; fi`,
    `  case $? in`,
    `    0) return 0 ;;`,
    `    1) echo "[foster] install cancelled. To install anyway: command $*" >&2; return 1 ;;`,
    `    10)`,
    `      if [ -t 0 ] && [ -t 2 ]; then`,
    `        printf '[foster] Install anyway? [y/N] ' >&2`,
    `        read -r __foster_answer`,
    `        case "$__foster_answer" in [yY]|[yY][eE][sS]) return 0 ;; esac`,
    `      fi`,
    `      echo "[foster] install cancelled." >&2; return 1 ;;`,
    `    *) return 0 ;; # guard itself could not run: do not block`,
    `  esac`,
    `}`,
    ...fns,
  ].join("\n");
}

function powershell(): string {
  const fns = Object.entries(SAFE).map(([tool, safe]) => {
    const named = safe.filter(Boolean);
    const skip = [safe.includes("") ? "$args.Count -eq 0" : "", named.length ? `($args.Count -gt 0 -and @(${named.map((s) => `'${s}'`).join(",")}) -contains "$($args[0])")` : ""].filter(Boolean).join(" -or ");
    const cond = skip ? `-not (${skip})` : "$true";
    return `function global:${tool} { if (${cond}) { if (-not (__FosterGuard '${tool}' $args)) { return } }; & (Get-Command '${tool}' -CommandType Application -ErrorAction Stop)[0] @args }`;
  });
  return [
    `# Foster guard for PowerShell: checks package installs before they run (https://github.com/foster-oss/foster).`,
    `# Add to $PROFILE:  foster-oss shell-init powershell | Out-String | Invoke-Expression`,
    `# Skip the check once: & (Get-Command npm -CommandType Application)[0] install ...`,
    `function global:__FosterGuard([string]$Tool, [object[]]$Rest) {`,
    `  $line = (@($Tool) + @($Rest | ForEach-Object { if ("$_" -match '\\s') { '"' + $_ + '"' } else { "$_" } })) -join ' '`,
    `  $foster = Get-Command foster-oss -CommandType Application -ErrorAction SilentlyContinue`,
    `  if ($foster) { & $foster[0] guard --quiet --command $line | Out-Host }`,
    `  else { & (Get-Command npx -CommandType Application)[0] -y foster-oss@latest guard --quiet --command $line | Out-Host }`,
    `  switch ($LASTEXITCODE) {`,
    `    0 { return $true }`,
    `    1 { Write-Host '[foster] install cancelled.' -ForegroundColor Red; return $false }`,
    `    10 {`,
    `      if ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {`,
    `        $answer = Read-Host '[foster] Install anyway? [y/N]'`,
    `        if ($answer -match '^(y|yes)$') { return $true }`,
    `      }`,
    `      Write-Host '[foster] install cancelled.' -ForegroundColor Yellow; return $false`,
    `    }`,
    `    default { return $true } # guard itself could not run: do not block`,
    `  }`,
    `}`,
    ...fns,
  ].join("\n");
}

export function shellInit(shell: Shell): string {
  return shell === "powershell" ? powershell() : posix(shell);
}
