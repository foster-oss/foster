import { describe, expect, it } from "vitest";
import { parseCommand, splitCommands } from "../src/lib/guard.js";

/** What guard would look at: names, with "?" for names it cannot resolve (variables, stdin, deep nesting). */
const seen = (line: string) => parseCommand(line, process.cwd()).packages.map((p) => (p.unresolved ? "?" : "") + p.name);
const S = "zz-sentinel";
const has = (line: string) => expect(seen(line).some((n) => n.includes(S) || n.startsWith("?")), line).toBe(true);

describe("line continuations, comments and here-docs", () => {
  it("joins lines continued with \, ` and ^", () => {
    for (const nl of ["\n", "\r\n"]) {
      has(`npm install \${nl}  ${S}`);
      has(`npm install \`${nl}  ${S}`);
      has(`npm i ^${nl}  ${S}`);
    }
    expect(seen(`npm install react \\n ${S} \\n --save`)).toEqual(["react", S]);
  });
  it("skips comments and here-doc bodies that are only data", () => {
    expect(seen("npm i react # zz-not-a-package")).toEqual(["react"]);
    expect(seen(`echo hi # ; npm i ${S}`)).toEqual([]);
    expect(seen(`cat <<'EOF' > README.md\nnpm i ${S}\nEOF\nnpm i zod`)).toEqual(["zod"]);
    expect(seen(`cat <<-EOF\n\tnpm i ${S}\n\tEOF`)).toEqual([]);
    expect(seen(`<# npm i ${S} #> npm i zod`)).toEqual(["zod"]);
  });
  it("reads a here-doc or here-string a shell runs", () => {
    has(`sh <<'EOF'\nnpm i ${S}\nEOF`);
    has(`bash <<< "npm i ${S}"`);
  });
  it("keeps carets in version ranges and git refs", () => {
    expect(seen("npm i react@^18.2.0")).toEqual(["react"]);
    expect(splitCommands("git log HEAD^ && echo x")).toEqual([["git", "log", "HEAD^"], ["echo", "x"]]);
  });
});

describe("variables and substitutions", () => {
  it("expands variables assigned earlier on the line", () => {
    for (const line of [`P=${S}; npm i $P`, `P=${S}; npm i "\${P}"`, `export P=${S} && npm install $P`, `$x='${S}'; npm i $x`, `$x = '${S}'; npm i "$x"`, `set P=${S} && npm i %P%`, `set "P=${S}" & npm i %P%`]) {
      expect(seen(line), line).toEqual([S]);
    }
  });
  it("reports names it cannot see instead of skipping them", () => {
    for (const line of ["npm i $PKG", "npm i %PKG%", "pip install $REQ", `npm i $(echo ${S})`, "foreach ($p in $list) { npm i $p }", `'${S}' | ForEach-Object { npm i $_ }`, `echo ${S} | xargs npm i`, `xargs -n1 npm i < deps.txt`]) {
      expect(seen(line).some((n) => n.startsWith("?")), line).toBe(true);
    }
  });
  it("reads backtick substitution and text piped into a shell", () => {
    has(`echo \`npm i ${S}\``);
    has(`echo "npm i ${S}" | sh`);
    has(`printf 'npm i ${S}\n' | bash`);
    has(`"npm i ${S}" | iex`);
    has(`@'\nnpm i ${S}\n'@ | iex`);
  });
});

describe("wrapper commands", () => {
  it("looks past wrappers and their options", () => {
    for (const w of ["env -i", "env -u X", "timeout 60", "timeout -s KILL 60", "nice -n 10", "nice -10", "ionice -c 3", "doas", "stdbuf -oL", "time -p", "command -p", "builtin command", "exec -a x", "sudo -E", "sudo -u node", "sudo -H", "watch -n 5", "flock /tmp/l", "xvfb-run -a", "wsl -e", "wsl --", "wsl -d Ubuntu", "nvm exec 20", "fnm exec --using=20", "mise exec node@20 --", "volta run", "call", "start /b", 'start ""', "@"]) {
      has(`${w}${w === "@" ? "" : " "}npm i ${S}`);
    }
    has(`env -S "npm i ${S}"`);
    has(`find . -name x -exec npm i ${S} \;`);
    has(`volta install ${S}`);
    has(`node C:/nodejs/node_modules/npm/bin/npm-cli.js i ${S}`);
  });
  it("reads npx runners and npm run through npx", () => {
    has(`npx cross-env A=1 npm i ${S}`);
    has(`npx dotenv -e .env -- npm i ${S}`);
    has(`npx npm@10 i ${S}`);
    has(`npx -c 'npm i ${S}'`);
  });
  it("reads cmd's if, call and start, and PowerShell's assignments and Start-Process", () => {
    for (const line of [`if exist package.json npm i ${S}`, `if not exist x npm i ${S}`, `if errorlevel 1 npm i ${S}`, `call npm.cmd install ${S}`, `start /wait cmd /c npm i ${S}`, `$null = npm i ${S}`, `$out = npm i ${S}`, `. npm i ${S}`, `Start-Process npm -ArgumentList 'i ${S}'`, `Start-Process -FilePath npm -ArgumentList 'i','${S}'`, `saps npm 'i ${S}'`, `start npm "i ${S}"`, `n\`p\`m i ${S}`, `n^p^m i ${S}`]) {
      has(line);
    }
  });
});

describe("commands handed to another shell", () => {
  it("handles more shells and option forms", () => {
    const enc = Buffer.from(`npm i ${S}`, "utf16le").toString("base64");
    for (const line of [`bash -c -- "npm i ${S}"`, `sh -c 'npm i "$0"' ${S}`, `sh -c 'npm i "$1"' _ ${S}`, `busybox sh -c 'npm i ${S}'`, `su -c "npm i ${S}"`, `script -qc "npm i ${S}" /dev/null`, `powershell -enco ${enc}`, `powershell /enc ${enc}`, `pwsh -Encoded ${enc}`, `powershell "npm i ${S}"`, `powershell -NoProfile -ExecutionPolicy Bypass npm i ${S}`, `powershell /Command npm i ${S}`, `pwsh -CommandWithArgs 'npm i ${S}'`, `cmd /c"npm i ${S}"`, `%ComSpec% /c npm i ${S}`, `Invoke-Expression -Command "npm i ${S}"`]) {
      has(line);
    }
    expect(seen("powershell -File setup.ps1")).toEqual([]);
  });
  it("asks about nesting deeper than it follows", () => {
    let line = `npm i ${S}`;
    for (let d = 0; d < 7; d++) line = `bash -c ${JSON.stringify(line)}`;
    expect(seen(line)).toEqual([S]);
    line = `bash -c ${JSON.stringify(line)}`;
    expect(seen(line)[0]).toMatch(/^\?/);
  });
});

describe("package-manager spellings", () => {
  it("reads npm's abbreviations, install-test and update", () => {
    for (const sub of ["ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "install-test", "it", "update", "up", "upgrade"]) expect(seen(`npm ${sub} ${S}`), sub).toEqual([S]);
  });
  it("reads every -p / --package and name@url", () => {
    expect(seen(`npx -p react -p ${S} cmd`)).toEqual(["react", S]);
    expect(seen(`npm exec --package=react --package=${S} -- cmd`)).toEqual(["react", S]);
    expect(seen(`npm i ${S}@https://registry.npmjs.org/${S}/-/${S}-1.0.0.tgz`)).toEqual([S]);
    expect(parseCommand(`npm i x@https://evil.example/x.tgz`).packages[0]?.remote).toBe(true);
  });
  it("reads pnpm, yarn, bun and deno forms", () => {
    for (const line of [`pnpm add --workspace ${S}`, `yarn workspace web add ${S}`, `yarn workspaces foreach -A add ${S}`, `bun x ${S}`, `deno add npm:${S}`, `deno install -g npm:${S}`, `deno run -A npm:${S}`]) has(line);
  });
  it("does not read option values as packages", () => {
    for (const line of ["npm i react --before 2020-01-01", "npm i react --otp 123456", "npm i react --loglevel warn", "npm i react --script-shell bash", "yarn add react --network-timeout 100000", "pnpm add react --reporter silent"]) {
      expect(seen(line), line).toEqual(["react"]);
    }
    expect(seen("pip install requests --timeout 60 --retries 5 --progress-bar off")).toEqual(["requests"]);
    expect(seen("cargo install -j 4 ripgrep")).toEqual(["ripgrep"]);
  });
  it("follows cd options and the home folder", () => {
    expect(parseCommand("cd -- web && npm ci", "/repo").lockfiles[0]?.dir).toMatch(/web$/);
    expect(parseCommand("cd -P web && npm ci", "/repo").lockfiles[0]?.dir).toMatch(/web$/);
  });
});
