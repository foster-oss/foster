import semver from "semver";

interface Parsed {
  release: number[];
  /** -4 dev, -3 alpha, -2 beta, -1 rc/pre, 0 final, 1 post */
  phase: number;
  phaseNumber: number;
}

const PHASE: Record<string, number> = { dev: -4, alpha: -3, a: -3, beta: -2, b: -2, rc: -1, c: -1, pre: -1, preview: -1, post: 1, rev: 1, r: 1 };

/** Parse PEP 440 / RubyGems / Go style versions: release numbers plus an optional pre/post/dev tag. */
function parse(version: string): Parsed | null {
  const s = version.trim().toLowerCase().replace(/^v(?=\d)/, "").replace(/\+.*$/, "");
  const m = s.match(/^(\d+(?:\.\d+)*)(.*)$/);
  if (!m?.[1]) return null;
  const release = m[1].split(".").map(Number);
  const rest = (m[2] ?? "").replace(/^[.\-_]/, "");
  if (!rest) return { release, phase: 0, phaseNumber: 0 };
  // The leading tag decides ("1.0rc1.post2" sorts as an rc).
  const t = rest.match(/^(preview|alpha|beta|post|pre|rev|dev|rc|a|b|c|r)[.\-_]?(\d*)(?![a-z])/);
  if (t?.[1]) return { release, phase: PHASE[t[1]] ?? 0, phaseNumber: Number(t[2] || 0) };
  // Unknown suffix (platform, build tag): treat as the final release.
  return { release, phase: 0, phaseNumber: 0 };
}

/**
 * Compare two versions. Uses semver when both parse; otherwise understands release numbers and
 * pre/post-release tags (PEP 440 "2.0.0rc1" < "2.0.0" < "2.0.0.post1", RubyGems "7.1.0.rc1" < "7.1.0").
 */
export function compareVersions(a: string, b: string): number {
  if (semver.valid(a) && semver.valid(b)) return semver.compare(a, b);
  const pa = parse(a);
  const pb = parse(b);
  if (!pa || !pb) {
    // Fall back to digit groups for anything unparsable.
    const da = a.split(/[^0-9]+/).filter(Boolean).map(Number);
    const db = b.split(/[^0-9]+/).filter(Boolean).map(Number);
    return compareArrays(da, db);
  }
  return compareArrays(pa.release, pb.release) || Math.sign(pa.phase - pb.phase) || Math.sign(pa.phaseNumber - pb.phaseNumber);
}

function compareArrays(a: number[], b: number[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

/**
 * Does a GitHub-advisory style range (e.g. "<= 2.0.1", ">= 2.0.0, <= 3.0.0", "= 1.2.9")
 * include this version? Returns true when the range cannot be parsed, so callers err on the side of caution.
 */
export function rangeIncludes(range: string | undefined, version: string): boolean {
  if (!range) return true;
  const parts = range.split(",").map((s) => s.trim()).filter(Boolean);
  for (const part of parts) {
    const m = part.match(/^(<=|>=|<|>|=|==)?\s*v?([0-9][^\s]*)$/);
    if (!m?.[2]) return true;
    const cmp = compareVersions(version, m[2]);
    switch (m[1] ?? "=") {
      case "<=":
        if (!(cmp <= 0)) return false;
        break;
      case ">=":
        if (!(cmp >= 0)) return false;
        break;
      case "<":
        if (!(cmp < 0)) return false;
        break;
      case ">":
        if (!(cmp > 0)) return false;
        break;
      default:
        if (cmp !== 0) return false;
    }
  }
  return true;
}
