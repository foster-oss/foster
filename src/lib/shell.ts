/**
 * `foster-oss shell-init <shell>`: shell functions that run `foster-oss guard` before package
 * installs typed by a person, the way the Claude Code hook does for an agent. A deny cancels the
 * install, an ask prompts "Install anyway? [y/N]" (cancelled when nobody can answer), and a guard
 * that cannot run lets the install through. `command npm ...` (bash/zsh) skips the check once.
 */

export const SHELLS = ["bash", "zsh", "powershell"] as const;
export type Shell = (typeof SHELLS)[number];

/** Subcommands worth checking, per tool. "" means the tool run with no subcommand (`yarn`, `bundle`). */
const WRAPPED: Record<string, string[] | "all"> = {
  npm: ["install", "i", "in", "add", "isntall", "ci", "clean-install", "ic", "install-clean", "it", "cit", "install-test", "install-ci-test", "exec", "x"],
  npx: "all",
  pnpm: ["add", "install", "i", "dlx"],
  yarn: ["", "add", "install", "dlx", "global"],
  bun: ["add", "install", "i"],
  bunx: "all",
  pnpx: "all",
  corepack: ["npm", "npx", "pnpm", "pnpx", "yarn"],
  pip: ["install"],
  pip3: ["install"],
  uv: ["add", "sync", "pip", "tool"],
  poetry: ["add", "install"],
  pipx: ["install"],
  pipenv: ["install", "sync"],
  cargo: ["add", "install", "fetch"],
  go: ["get", "install"],
  gem: ["install"],
  bundle: ["", "install", "add"],
  composer: ["require", "req", "install"],
};

function posix(shell: "bash" | "zsh"): string {
  const fns = Object.entries(WRAPPED).map(([tool, subs]) => {
    if (subs === "all") return `${tool}() { __foster_guard ${tool} "$@" || return 1; command ${tool} "$@"; }`;
    const empty = subs.includes("");
    const list = subs.filter(Boolean).join("|");
    const test = empty ? `"\${1:-}" in ""|${list}` : `"\${1:-}" in ${list}`;
    return `${tool}() { case ${test}) __foster_guard ${tool} "$@" || return 1 ;; esac; command ${tool} "$@"; }`;
  });
  return [
    `# Foster guard for ${shell}: checks package installs before they run (https://github.com/foster-oss/foster).`,
    `# Add to ~/.${shell}rc:  eval "$(foster-oss shell-init ${shell})"`,
    `# Skip the check once: command npm install ...`,
    `__foster_guard() {`,
    `  if command -v foster-oss >/dev/null 2>&1; then command foster-oss guard --quiet -- "$@"`,
    `  else command npx -y foster-oss@0 guard --quiet -- "$@"; fi`,
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
  const fns = Object.entries(WRAPPED).map(([tool, subs]) => {
    const cond =
      subs === "all"
        ? "$true"
        : `(${subs.includes("") ? "$args.Count -eq 0 -or " : ""}($args.Count -gt 0 -and @(${subs
            .filter(Boolean)
            .map((s) => `'${s}'`)
            .join(",")}) -contains $args[0]))`;
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
    `  else { & (Get-Command npx -CommandType Application)[0] -y foster-oss@0 guard --quiet --command $line | Out-Host }`,
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
