import base from "./vitest.config";

// This explicit task-scheduling profile is excluded by the ordinary *.test glob.
// Cache lives outside shared node_modules in both direct and mutation execution.
export default { ...base, cacheDir: process.env.HISTORY_TASK_CACHE_DIR ?? ".history-task-cache",
  test: { ...base.test, include: ["tests/historyPlaybackGate.task.tsx"], pool: "forks", maxWorkers: 1,
    fileParallelism: false, testTimeout: 15_000, hookTimeout: 15_000,
    coverage: { ...base.test?.coverage, enabled: false } } };
