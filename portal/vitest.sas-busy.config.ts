import base from "./vite.config";
const cacheDir = process.env.FRONTEND_NATIVE_SAS_BUSY_CACHE_DIR;
if (!cacheDir || process.env.UV_THREADPOOL_SIZE !== "1") throw new Error("SetupError: SAS busy profile requires an owned private cache and UV1 child");
export default { ...base, cacheDir, test: { ...base.test, cache: false, update: "none", include: ["tests/sasFingerprintPending.busy.tsx"], pool: "forks", maxWorkers: 1, fileParallelism: false, testTimeout: 60_000, hookTimeout: 60_000, coverage: { ...base.test?.coverage, enabled: false } } };
