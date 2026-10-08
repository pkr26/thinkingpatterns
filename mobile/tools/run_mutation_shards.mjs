import { closeSync, existsSync, mkdirSync, openSync, readFileSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const mobile = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const [planPath, lanesArgument = "4"] = process.argv.slice(2);
if (!planPath) throw new Error("usage: node tools/run_mutation_shards.mjs PLAN_JSON [LANES]");
const plan = JSON.parse(readFileSync(resolve(mobile, planPath), "utf8"));
const lanes = Number(lanesArgument);
if (!Number.isInteger(lanes) || lanes < 1 || lanes > 4) throw new Error("LANES must be 1..4");
const results = [];
let cursor = 0;
async function runLane(lane) {
  while (cursor < plan.jobs.length) {
    const job = plan.jobs[cursor++];
    const output = resolve(mobile, plan.output, job.name);
    mkdirSync(output, { recursive: true });
    const log = openSync(join(output, "run.log"), "w");
    const args = ["tools/run_frontend_mutation.mjs", "--mutate", job.files.join(","), "--reporters", "json,progress,mutation-events", "--concurrency", "1", "--timeoutMS", "2000"];
    console.log(`${new Date().toISOString()} lane ${lane}: ${job.name} started`);
    const start = Date.now();
    const child = spawn(process.execPath, args, { cwd: mobile, stdio: ["ignore", log, log], env: { ...process.env, MOBILE_MUTATION_REPORT_DIR: output, MOBILE_MUTATION_TEST_FILES_JSON: JSON.stringify(job.tests) } });
    const code = await new Promise((accept, reject) => { child.once("error", reject); child.once("exit", (status, signal) => accept({ status, signal })); });
    closeSync(log);
    const report = join(output, "mutation.json");
    const result = { name: job.name, files: job.files, tests: job.tests, ...code, completedReport: existsSync(report), elapsedMs: Date.now() - start };
    results.push(result);
    writeFileSync(resolve(mobile, plan.output, "shard-results.json"), JSON.stringify(results, null, 2) + "\n");
    console.log(`${new Date().toISOString()} lane ${lane}: ${job.name} finished ${JSON.stringify(result)}`);
  }
}
mkdirSync(resolve(mobile, plan.output), { recursive: true });
await Promise.all(Array.from({ length: lanes }, (_, lane) => runLane(lane + 1)));
if (results.some(result => result.status !== 0 || !result.completedReport)) process.exitCode = 1;
