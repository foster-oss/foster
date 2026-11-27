import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  cargoLockGraph,
  composerLockGraph,
  gemfileLockGraph,
  introducedBy,
  packageLockGraph,
  pnpmLockGraph,
  poetryLockGraph,
  uvLockGraph,
  yarnLockGraph,
} from "../src/lib/graph.js";
import { detectLockfiles, directPythonNames, readDependencies } from "../src/lib/lockfile.js";
import { readSbom } from "../src/lib/sbom.js";
import type { Dependency } from "../src/lib/types.js";

/** Write files into a fresh temp project and read its dependencies. */
function project(files: Record<string, string>): Dependency[] {
  const dir = mkdtempSync(join(tmpdir(), "foster-graph-"));
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(join(dir, name, ".."), { recursive: true });
    writeFileSync(join(dir, name), text);
  }
  return detectLockfiles(dir).flatMap((lock) => readDependencies(dir, lock));
}

const rel = (deps: Dependency[]) =>
  Object.fromEntries(deps.map((d) => [`${d.name}@${d.version}`, d.direct ? "direct" : (d.via ?? []).join("+") || "transitive"]));

const via = (g: ReturnType<typeof uvLockGraph>) =>
  Object.fromEntries([...introducedBy(g, g.roots ?? [])].map(([k, s]) => [k, [...s].sort().join("+")]));

describe("npm package-lock v3 graph", () => {
  const lock = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "": { name: "app", dependencies: { request: "2.88.2", ip: "npm:@keep-lts/ip@2.0.2" }, devDependencies: { socks: "^2" } },
      "node_modules/request": { version: "2.88.2", dependencies: { "form-data": "~2.3.2", qs: "~6.5.2" } },
      "node_modules/form-data": { version: "2.3.3", dependencies: { "combined-stream": "^1.0.6" } },
      "node_modules/combined-stream": { version: "1.0.8" },
      "node_modules/qs": { version: "6.13.0" },
      // a second qs, nested under request because request needs an older one
      "node_modules/request/node_modules/qs": { version: "6.5.5" },
      "node_modules/ip": { name: "@keep-lts/ip", version: "2.0.2" },
      "node_modules/socks": { version: "2.8.3", dependencies: { ip: "^2.0.0" } },
    },
  });

  it("follows node resolution, including nested copies and aliases", () => {
    expect(rel(project({ "package.json": JSON.stringify({ dependencies: { request: "2.88.2", ip: "npm:@keep-lts/ip@2.0.2" }, devDependencies: { socks: "^2" } }), "package-lock.json": lock }))).toEqual({
      "request@2.88.2": "direct",
      "form-data@2.3.3": "request",
      "combined-stream@1.0.8": "request",
      "qs@6.13.0": "transitive", // nothing requires the top-level copy
      "qs@6.5.5": "request",
      "@keep-lts/ip@2.0.2": "direct", // the alias resolves to the patched package
      "socks@2.8.3": "direct",
    });
  });

  it("returns no graph for lockfile v1", () => {
    expect(packageLockGraph(JSON.stringify({ lockfileVersion: 1, dependencies: {} }))).toBeNull();
  });
});

describe("pnpm graph", () => {
  it("reads v9 importers and snapshots, with peer suffixes", () => {
    const g = pnpmLockGraph(`lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      astro:
        specifier: ^5.18.0
        version: 5.18.2(typescript@5.6.3)
packages:
  astro@5.18.2:
    resolution: {integrity: x}
  devalue@5.9.2:
    resolution: {integrity: x}
  vite@6.4.3:
    resolution: {integrity: x}
snapshots:
  astro@5.18.2(typescript@5.6.3):
    dependencies:
      devalue: 5.9.2
      vite: 6.4.3(@types/node@22.0.0)
  devalue@5.9.2: {}
  vite@6.4.3(@types/node@22.0.0): {}
`)!;
    expect([...g.roots!]).toEqual(["astro@5.18.2"]);
    expect(via(g)).toEqual({ "devalue@5.9.2": "astro", "vite@6.4.3": "astro" });
  });

  it("reads v6 package paths", () => {
    const g = pnpmLockGraph(`lockfileVersion: '6.0'
importers:
  .:
    dependencies:
      a:
        specifier: ^1.0.0
        version: 1.0.0
packages:
  /a@1.0.0:
    dependencies:
      b: 2.0.0
  /b@2.0.0:
    dev: false
`)!;
    expect(via(g)).toEqual({ "b@2.0.0": "a" });
  });
});

describe("yarn graph", () => {
  it("resolves classic descriptors and package.json ranges", () => {
    const g = yarnLockGraph(
      `# yarn lockfile v1

request@2.88.2:
  version "2.88.2"
  dependencies:
    form-data "~2.3.2"

form-data@~2.3.2:
  version "2.3.3"
  dependencies:
    combined-stream "^1.0.6"

"combined-stream@^1.0.6", combined-stream@~1.0.6:
  version "1.0.8"
`,
      { request: "2.88.2" },
    );
    expect([...g.roots!]).toEqual(["request@2.88.2"]);
    expect(via(g)).toEqual({ "form-data@2.3.3": "request", "combined-stream@1.0.8": "request" });
  });

  it("reads berry workspace entries as roots", () => {
    const g = yarnLockGraph(`__metadata:
  version: 8

"form-data@npm:~2.3.2":
  version: 2.3.3
  resolution: "form-data@npm:2.3.3"

"request@npm:2.88.2":
  version: 2.88.2
  resolution: "request@npm:2.88.2"
  dependencies:
    form-data: "npm:~2.3.2"

"t@workspace:.":
  version: 0.0.0-use.local
  resolution: "t@workspace:."
  dependencies:
    request: "npm:2.88.2"
`);
    expect([...g.roots!]).toEqual(["request@2.88.2"]);
    expect(via(g)).toEqual({ "form-data@2.3.3": "request" });
  });
});

describe("TOML lockfile graphs", () => {
  it("Cargo.lock: workspace members are the roots, versions disambiguate", () => {
    const g = cargoLockGraph(`version = 3

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "serde",
 "rand 0.8.5",
]

[[package]]
name = "rand"
version = "0.8.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "rand_core 0.6.4",
]

[[package]]
name = "rand_core"
version = "0.6.4"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "serde"
version = "1.0.195"
source = "registry+https://github.com/rust-lang/crates.io-index"
`);
    expect([...g.roots!].sort()).toEqual(["rand@0.8.5", "serde@1.0.195"]);
    expect(via(g)).toEqual({ "rand_core@0.6.4": "rand" });
  });

  it("uv.lock: the virtual project lists the roots; metadata is ignored", () => {
    const g = uvLockGraph(`version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "flask" },
]

[package.dev-dependencies]
dev = [
    { name = "nose" },
]

[package.metadata]
requires-dist = [{ name = "werkzeug", specifier = ">=2" }]

[[package]]
name = "flask"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "werkzeug" },
]

[[package]]
name = "nose"
version = "1.3.7"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "werkzeug"
version = "3.1.3"
source = { registry = "https://pypi.org/simple" }
`);
    expect([...g.roots!].sort()).toEqual(["flask@2.0.0", "nose@1.3.7"]);
    expect(via(g)).toEqual({ "werkzeug@3.1.3": "flask" });
  });

  it("poetry.lock: [package.dependencies] by name", () => {
    const g = poetryLockGraph(`[[package]]
name = "flask"
version = "2.0.0"
optional = false

[package.dependencies]
click = ">=7.1.2"
Werkzeug = ">=2.0"

[package.extras]
async = ["asgiref (>=3.2)"]

[[package]]
name = "click"
version = "8.1.7"

[[package]]
name = "werkzeug"
version = "3.1.3"
`);
    expect([...introducedBy(g, ["flask@2.0.0"])].map(([k, s]) => `${k}<${[...s]}`).sort()).toEqual(["click@8.1.7<flask", "werkzeug@3.1.3<flask"]);
  });
});

describe("other graphs", () => {
  it("Gemfile.lock specs", () => {
    const g = gemfileLockGraph(`GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.0.8)
      rack (~> 2.0)
    rack (2.2.8)

DEPENDENCIES
  actionpack
`);
    expect([...introducedBy(g, ["actionpack@7.0.8"])].map(([k]) => k)).toEqual(["rack@2.2.8"]);
  });

  it("composer.lock require", () => {
    const g = composerLockGraph(JSON.stringify({ packages: [{ name: "symfony/http-kernel", version: "v6.4.0", require: { php: ">=8.1", "psr/log": "^3" } }, { name: "psr/log", version: "3.0.0" }] }));
    expect([...introducedBy(g, ["symfony/http-kernel@6.4.0"])].map(([k]) => k)).toEqual(["psr/log@3.0.0"]);
  });
});

describe("Python direct dependencies", () => {
  it("reads PEP 621, dependency groups, uv dev-dependencies, Poetry tables and Pipfile", () => {
    const dir = mkdtempSync(join(tmpdir(), "foster-py-"));
    writeFileSync(
      join(dir, "pyproject.toml"),
      `[project]
name = "app"
dependencies = [
  "FastAPI>=0.110",
  "uvicorn[standard]; python_version > '3.8'",
]

[project.optional-dependencies]
docs = ["mkdocs"]

[dependency-groups]
dev = ["pytest>=8", { include-group = "docs" }]

[tool.uv]
dev-dependencies = ["ruff"]

[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31"

[tool.poetry.group.test.dependencies]
"typing_extensions" = "*"
`,
    );
    writeFileSync(join(dir, "Pipfile"), `[packages]\nflask = "*"\n\n[dev-packages]\nblack = "*"\n\n[requires]\npython_version = "3.11"\n`);
    expect([...directPythonNames(dir)].sort()).toEqual(["black", "fastapi", "flask", "mkdocs", "pytest", "requests", "ruff", "typing-extensions", "uvicorn"]);
  });

  it("marks poetry.lock dependencies with pyproject.toml and names the parent", () => {
    const deps = project({
      "pyproject.toml": `[tool.poetry.dependencies]\npython = "^3.11"\nflask = "2.0.0"\n`,
      "poetry.lock": `[[package]]\nname = "flask"\nversion = "2.0.0"\n\n[package.dependencies]\nJinja2 = ">=3.0"\n\n[[package]]\nname = "jinja2"\nversion = "3.1.4"\n`,
    });
    expect(rel(deps)).toEqual({ "flask@2.0.0": "direct", "jinja2@3.1.4": "flask" });
  });
});

describe("SBOM graphs", () => {
  const write = (doc: unknown) => {
    const dir = mkdtempSync(join(tmpdir(), "foster-sbom-"));
    writeFileSync(join(dir, "bom.json"), JSON.stringify(doc));
    return join(dir, "bom.json");
  };

  it("CycloneDX: the metadata component's dependencies are direct", () => {
    const sbom = readSbom(
      write({
        bomFormat: "CycloneDX",
        metadata: { component: { "bom-ref": "app" } },
        components: [
          { "bom-ref": "r", purl: "pkg:npm/request@2.88.2" },
          { "bom-ref": "f", purl: "pkg:npm/form-data@2.3.3" },
        ],
        dependencies: [
          { ref: "app", dependsOn: ["r"] },
          { ref: "r", dependsOn: ["f"] },
        ],
      }),
    );
    expect(rel(sbom.dependencies)).toEqual({ "request@2.88.2": "direct", "form-data@2.3.3": "request" });
  });

  it("SPDX: DESCRIBES and DEPENDS_ON / DEPENDENCY_OF", () => {
    const purl = (id: string, p: string) => ({ SPDXID: id, externalRefs: [{ referenceType: "purl", referenceLocator: p }] });
    const sbom = readSbom(
      write({
        spdxVersion: "SPDX-2.3",
        packages: [{ SPDXID: "SPDXRef-app" }, purl("SPDXRef-r", "pkg:npm/request@2.88.2"), purl("SPDXRef-f", "pkg:npm/form-data@2.3.3")],
        relationships: [
          { spdxElementId: "SPDXRef-DOCUMENT", relationshipType: "DESCRIBES", relatedSpdxElement: "SPDXRef-app" },
          { spdxElementId: "SPDXRef-app", relationshipType: "DEPENDS_ON", relatedSpdxElement: "SPDXRef-r" },
          { spdxElementId: "SPDXRef-f", relationshipType: "DEPENDENCY_OF", relatedSpdxElement: "SPDXRef-r" },
        ],
      }),
    );
    expect(rel(sbom.dependencies)).toEqual({ "request@2.88.2": "direct", "form-data@2.3.3": "request" });
  });

  it("without a graph, everything stays direct", () => {
    const sbom = readSbom(write({ bomFormat: "CycloneDX", components: [{ purl: "pkg:npm/a@1.0.0" }] }));
    expect(sbom.dependencies[0]!.direct).toBe(true);
  });
});

describe("introducedBy limits", () => {
  it("keeps at most MAX_VIA parents and still reaches every node", async () => {
    const { MAX_VIA } = await import("../src/lib/graph.js");
    const edges = new Map<string, Set<string>>();
    const roots = Array.from({ length: 15 }, (_, i) => `r${i}@1.0.0`);
    for (const r of roots) edges.set(r, new Set(["shared@1.0.0"]));
    edges.set("shared@1.0.0", new Set(["leaf@1.0.0"]));
    const v = introducedBy({ edges }, roots);
    expect(v.get("shared@1.0.0")!.size).toBe(MAX_VIA);
    expect(v.get("leaf@1.0.0")!.size).toBe(MAX_VIA);
  });
});
