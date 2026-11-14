import base from "./vite.config";
const cacheDir = process.env.FRONTEND_NATIVE_FAULT_CACHE_DIR;
if (!cacheDir) throw new Error("SetupError: native provider fault requires an owned private cache");
export default { ...base, cacheDir, test: { ...base.test, cache: false, update: "none", include: ["tests/accountSecurityHkdfFailure.fault.tsx"], pool: "forks", maxWorkers: 1, fileParallelism: false, testTimeout: 120_000, hookTimeout: 120_000, coverage: { ...base.test?.coverage, enabled: false } } };
