import base from "./vite.config";
const cacheDir = process.env.FRONTEND_NATIVE_GC_CACHE_DIR;
if (!cacheDir) throw new Error("SetupError: owned backup code GC run requires a private cache");
export default { ...base, cacheDir, test: { ...base.test, cache: false, update: "none", include: ["tests/totpBackupCodeCollection.gc.tsx"], pool: "forks", execArgv: ["--expose-gc"], maxWorkers: 1, fileParallelism: false, testTimeout: 120_000, hookTimeout: 120_000, coverage: { ...base.test?.coverage, enabled: false } } };
