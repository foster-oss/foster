import semver from "semver";

/**
 * Compare two versions. Uses semver when both parse, otherwise a numeric
 * comparison of the digit groups (good enough for most PEP 440 releases).
 */
export function compareVersions(a: string, b: string): number {
  if (semver.valid(a) && semver.valid(b)) return semver.compare(a, b);
  const pa = a.split(/[^0-9]+/).filter(Boolean).map(Number);
  const pb = b.split(/[^0-9]+/).filter(Boolean).map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
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
