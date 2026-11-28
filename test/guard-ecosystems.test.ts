import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { parseCommand } from "../src/lib/guard.js";

const seen = (line: string, cwd = process.cwd()) => parseCommand(line, cwd).packages.map((p) => `${p.ecosystem}:${p.remote ? "remote:" : ""}${p.unresolved ? "?" : ""}${p.name}${p.version ? `@${p.version}` : p.range ? `~${p.range}` : ""}`);

describe("Python", () => {
  it("reads interpreter forms and pip's subcommands", () => {
    for (const line of ["py -3.12 -m pip install zzx", "py -3 -m pip install zzx", "python -mpip install zzx", "python -I -m pip install zzx", "python -m pip -q install zzx", "python -m pip --disable-pip-version-check install zzx", "pip download zzx", "pip wheel zzx", "python -m uv pip install zzx", "uv run pip install zzx", "poetry run pip install zzx", "pipenv run pip install zzx"]) {
      expect(seen(line), line).toContain("pypi:zzx");
    }
  });
  it("reads run-once tools", () => {
    for (const line of ["uvx zzx", "uv tool run zzx", "uv run --with zzx python x.py", "pipx run zzx", "pipx inject black zzx", "uvx --from zzx tool"]) expect(seen(line), line).toContain("pypi:zzx");
  });
  it("keeps pins exact and ranges as ranges", () => {
    expect(seen("pip install 'django==4.2.1' 'flask>=3' 'numpy~=1.26'")).toEqual(["pypi:django@4.2.1", "pypi:flask~>=3", "pypi:numpy~~=1.26"]);
    expect(seen("pip install 'a==1.*'")).toEqual(["pypi:a~==1.*"]);
  });
  it("does not take an escaped name for a shorter one", () => {
    // bash turns xlsx\writr into xlsxwritr; guard must not check the shorter "xlsx" instead
    expect(seen(String.raw`pip install xlsx\writr`).some((p) => p === "pypi:xlsx")).toBe(false);
  });
  it("asks about editable and VCS installs", () => {
    expect(seen("pip install -e git+https://github.com/x/y.git#egg=y")[0]).toMatch(/^pypi:remote:/);
  });
  it("reads requirements files: unpinned names, ranges, URLs and nested -r", () => {
    const dir = mkdtempSync(join(tmpdir(), "foster-req-"));
    writeFileSync(join(dir, "requirements.txt"), "# app\nrequests\nflask>=3 # web\npinned==1.0.0\n-r more.txt\n-e git+https://github.com/x/y.git#egg=y\nlib @ https://example.com/lib.whl\n--index-url https://pypi.org/simple\n");
    writeFileSync(join(dir, "more.txt"), "nested-unpinned\n");
    const r = parseCommand("pip install -r requirements.txt", dir);
    expect(r.packages.map((p) => `${p.remote ? "remote:" : ""}${p.name}`).sort()).toEqual(["flask", "nested-unpinned", "remote:git+https://github.com/x/y.git#egg=y", "remote:lib @ https://example.com/lib.whl", "requests"]);
    expect(r.lockfiles.map((l) => l.file).sort()).toEqual([resolve(dir, "more.txt"), resolve(dir, "requirements.txt")]);
    for (const line of ["pip install -rrequirements.txt", "python -m pip install -r requirements.txt", "uv pip install -r requirements.txt", "uv add -r requirements.txt", "pipenv install -r requirements.txt", "pip install -r more.txt -r requirements.txt"]) {
      expect(parseCommand(line, dir).packages.map((p) => p.name), line).toContain("requests");
    }
  });
});

describe("Ruby, PHP, Rust and Go", () => {
  it("reads gem and bundler forms", () => {
    expect(seen("gem install rest-client:1.6.13")).toEqual(["rubygems:rest-client@1.6.13"]);
    expect(seen("gem install rest-client -v1.6.13")).toEqual(["rubygems:rest-client@1.6.13"]);
    expect(seen("gem install rest-client -v '= 1.6.13'")).toEqual(["rubygems:rest-client@1.6.13"]);
    expect(seen("gem i rails")).toEqual(["rubygems:rails"]);
    expect(parseCommand("bundler install && bundle i && bundle update", "/w").lockfiles).toHaveLength(1);
    expect(parseCommand("BUNDLE_GEMFILE=app/Gemfile bundle install", resolve("/w")).lockfiles[0]?.dir).toBe(resolve("/w/app"));
  });
  it("reads composer forms", () => {
    expect(seen("composer require intercom/intercom-php 5.0.2")).toEqual(["packagist:intercom/intercom-php@5.0.2"]);
    expect(seen('composer require "intercom/intercom-php 5.0.2"')).toEqual(["packagist:intercom/intercom-php@5.0.2"]);
    expect(seen("composer require intercom/intercom-php:==5.0.2")).toEqual(["packagist:intercom/intercom-php@5.0.2"]);
    expect(seen("composer require intercom/intercom-php:5.0.2@stable")).toEqual(["packagist:intercom/intercom-php@5.0.2"]);
    expect(seen("composer require 'intercom/intercom-php:>=5.0.2 <5.0.3'")).toEqual(["packagist:intercom/intercom-php~>=5.0.2 <5.0.3"]);
    for (const line of ["composer global require a/b", "composer r a/b", "composer create-project a/b app"]) expect(seen(line), line).toEqual(["packagist:a/b"]);
    expect(parseCommand("composer update && composer i", "/w").lockfiles).toHaveLength(1);
  });
  it("reads cargo and go forms", () => {
    expect(seen("cargo +nightly install zzx")).toEqual(["cargo:zzx"]);
    expect(seen("cargo binstall zzx")).toEqual(["cargo:zzx"]);
    expect(seen("cargo install --git https://github.com/evil/x")).toEqual(["cargo:remote:https://github.com/evil/x"]);
    expect(parseCommand("cargo run && cargo test && cargo +stable build", "/w").lockfiles).toHaveLength(1);
    expect(seen("go run github.com/zz/x@latest")).toEqual(["go:github.com/zz/x"]);
    expect(seen("go mod download github.com/zz/x")).toEqual(["go:github.com/zz/x"]);
    expect(parseCommand("go mod download && go build ./... && go run .", "/w").lockfiles).toHaveLength(1);
  });
});
