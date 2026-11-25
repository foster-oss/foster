export * from "./lib/types.js";
export { classify, toOrphanRecord, unpatchedAdvisories, maxSeverity } from "./lib/classify.js";
export { getPackage, listCriticalPage, type RawPackage } from "./lib/ecosystems.js";
export { queryBatch, getVuln, describeForDependency } from "./lib/osv.js";
export {
  detectLockfiles,
  readDependencies,
  parsePackageLock,
  parsePnpmLock,
  parseYarnLock,
  parseRequirements,
  parseUvLock,
} from "./lib/lockfile.js";
export { loadRegistry, loadOrphanIndex, findPatch, indexByName, type PatchRegistry, type OrphanIndexFile } from "./lib/data.js";
export { scanProject, analyzeDependencies, shouldFail, type ScanOptions, type FailOn } from "./lib/scan.js";
export { applyFixes, detectManager, type FixResult, type FixChange } from "./lib/fix.js";
export { checkPackage, parseSpec, type CheckResult } from "./lib/check.js";
export { formatText, formatMarkdown, formatFix, formatRecord } from "./lib/report.js";
export { fosterVersion } from "./lib/http.js";
