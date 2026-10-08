#!/usr/bin/env node
/** Full portal mutation execution in a disposable copy. Source is never
 * instrumented in the working tree. Native runner compatibility is verified
 * with static and runtime known-kill and deliberate-survivor controls. */
import { cp, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { spawn } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const portalRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = dirname(portalRoot);
const args = process.argv.slice(2);
const option = (name, fallback) => {
  const index = args.indexOf(name);
  return index < 0 ? fallback : args[index + 1];
};
const label = option('--label', 'full');
if (!/^[A-Za-z0-9_-]+$/.test(label)) throw new Error('The label must contain letters, numbers, underscores or dashes.');
const reportRoot = resolve(portalRoot, option('--report-dir', 'reports/full-mutation'));
const concurrency = Number(option('--concurrency', '4'));
const fileConcurrency = Number(option('--workers-per-file', '1'));
const timeoutMS = Number(option('--timeout-ms', '2000'));
const workerBudgetFile = option('--worker-budget-file', '');
const replayReportPath = option('--replay-report', '');
const testGlob = option('--test-glob', '');
const testControlsOnly = args.includes('--test-controls-only');
const onlyFiles = option('--only-files', '').split(',').filter(Boolean).map(file => file.replace(/^src\//, ''));
const replayRanges = new Map();
if (replayReportPath) {
  const report = JSON.parse(await readFile(resolve(replayReportPath), 'utf8'));
  for (const [file, data] of Object.entries(report.files)) {
    if (data.source !== await readFile(join(portalRoot, file), 'utf8')) throw new Error(`Replay report has stale source: ${file}`);
    const ranges = new Set();
    for (const mutant of data.mutants) {
      if (testControlsOnly) {
        const controls = { 'src/kvstore.ts': [[62,64],[69,71]], 'src/noteDrafts.ts': [[27,30]], 'src/views/PatientView.tsx': [[575,577]] };
        if (!controls[file]?.some(([first,last]) => mutant.location.start.line >= first && mutant.location.end.line <= last)) throw new Error('Pristine async controls require a replay limited to reviewed fixture-control operators.');
      }
      if (mutant.status === 'Killed' && !/^(?:Test|Hook) timed out in \d+ms\./m.test(mutant.statusReason ?? '')) continue;
      const {start,end} = mutant.location;
      ranges.add(`${file}:${start.line}:${start.column - 1}-${end.line}:${end.column - 1}`);
    }
    if (ranges.size) replayRanges.set(file.replace(/^src\//, ''), [...ranges]);
  }
  if (!replayRanges.size) throw new Error('Replay report contains no unresolved mutations.');
  if (!args.includes('--file-shards')) throw new Error('Residual replay requires --file-shards.');
}
if (testControlsOnly && !replayReportPath) throw new Error('Pristine async controls require an explicit control-only replay report.');
if (!Number.isSafeInteger(concurrency) || concurrency < 1 || !Number.isSafeInteger(fileConcurrency) || fileConcurrency < 1 || !Number.isSafeInteger(timeoutMS) || timeoutMS < 1000) throw new Error('Invalid concurrency or timeout budget.');
await mkdir(reportRoot, { recursive: true });
const scratchRoot = await mkdtemp(join(tmpdir(), 'fathom-portal-mutation-'));
const workspace = join(scratchRoot, 'portal');
const excluded = new Set(['node_modules', 'reports', 'coverage', 'dist', '.git', 'stryker-tmp', '.stryker-tmp']);
await cp(portalRoot, workspace, { recursive: true, filter: path => !excluded.has(path.split('/').at(-1)) });
await cp(join(repoRoot, 'shared'), join(scratchRoot, 'shared'), { recursive: true });
await mkdir(join(scratchRoot, 'deploy', 'nginx'), { recursive: true });
await cp(join(repoRoot, 'deploy', 'nginx', 'mindpattern.conf.example'), join(scratchRoot, 'deploy', 'nginx', 'mindpattern.conf.example'));
console.log(`Disposable portal workspace: ${workspace}`);

async function run(command, commandArgs, name, cwd = workspace) {
  const logPath = join(reportRoot, `${label}-${name}.log`);
  await mkdir(dirname(logPath), { recursive: true });
  const log = createWriteStream(logPath);
  return await new Promise((resolveRun, reject) => {
    const child = spawn(command, commandArgs, { cwd, env: { ...process.env, ...(testControlsOnly ? { PORTAL_MUTATION_TEST_CONTROLS_ONLY: '1' } : {}) }, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', data => { log.write(data); process.stdout.write(data); });
    child.stderr.on('data', data => { log.write(data); process.stderr.write(data); });
    child.once('error', error => { log.end(); reject(error); });
    child.once('close', code => { log.end(); resolveRun(code ?? 1); });
  });
}
async function checked(command, commandArgs, name) {
  const code = await run(command, commandArgs, name);
  if (code !== 0) throw new Error(`${name} failed with exit code ${code}; see its log in ${reportRoot}. Workspace retained at ${workspace}.`);
}
async function digestTree(path, prefix = '') {
  const files = {};
  for (const entry of (await readdir(path, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) Object.assign(files, await digestTree(join(path, entry.name), relative));
    else if (entry.isFile()) files[relative] = createHash('sha256').update(await readFile(join(path, entry.name))).digest('hex');
  }
  return files;
}
await checked('npm', ['ci', '--no-audit', '--no-fund'], 'install');
// Stryker's native runner 10 is exercised against its supported Vitest 4
// APIs. The production project's lockfile and Vitest 5 remain untouched.
await checked('npm', ['install', '--no-save', '--package-lock=false', '--no-audit', '--no-fund', 'vitest@4.1.10', '@vitest/coverage-v8@4.1.10'], 'install-native-runner');
const sourceBefore = await digestTree(join(workspace, 'src'));
const inputs = { source: sourceBefore, tests: await digestTree(join(workspace, 'tests')), packageLock: createHash('sha256').update(await readFile(join(portalRoot, 'package-lock.json'))).digest('hex') };
const originalConfig = JSON.parse(await readFile(join(workspace, 'stryker.config.json'), 'utf8'));
// Primary shards exercise the file's direct public consumers. Residuals can
// be replayed against the full suite, without dropping production operators.
const viewTests = ['tests/views.test.tsx', 'tests/a11y.test.tsx', 'tests/app.test.tsx', 'tests/audit_*.test.tsx', 'tests/mutation_*.test.tsx', 'tests/remediation_*.test.tsx', 'tests/totp_*.test.tsx', 'tests/rotation_*.test.tsx', 'tests/voice_gating_*.test.tsx', 'tests/accountSecurityPresentation.test.tsx', 'tests/custodyRegressions.test.tsx', 'tests/pentest_*.test.tsx', 'tests/passwordStrength.test.tsx', 'tests/phraseHighlight.test.tsx'];
const consumerTests = {
  'crypto.ts': ['tests/crypto*.test.ts', 'tests/notesCustodyKeys.test.ts', 'tests/voice_crypto_*.test.ts'],
  'api.ts': ['tests/api*.test.ts'],
  'aad.ts': ['tests/crypto*.test.ts', 'tests/notesCustodyKeys.test.ts', 'tests/noteDrafts.test.ts', 'tests/voice_crypto_*.test.ts'],
  'ui.tsx': ['tests/uiPresentation.test.tsx', 'tests/views.test.tsx', 'tests/a11y.test.tsx', 'tests/accountSecurityPresentation.test.tsx'],
  'App.tsx': ['tests/app.test.tsx', 'tests/appLifecycleContracts.test.tsx', 'tests/mutation_*.test.tsx'],
  'ErrorBoundary.tsx': ['tests/errorBoundary.test.tsx', 'tests/main.test.tsx'],
  'main.tsx': ['tests/main.test.tsx'],
  'TotpQr.tsx': ['tests/totpQr.test.tsx', 'tests/totp_*.test.tsx', 'tests/accountSecurityPresentation.test.tsx'],
  'browserRoute.ts': ['tests/browserRoute.test.ts', 'tests/app.test.tsx'],
  'errors.ts': ['tests/errors.test.ts'],
  'kvstore.ts': ['tests/kvstore*.test.ts', 'tests/noteDrafts.test.ts'],
  'noteDrafts.ts': ['tests/noteDrafts.test.ts', 'tests/noteDraftsHook.test.tsx'],
  'platform.ts': ['tests/platform.test.ts', 'tests/mutation_2026_09_22_round2.pins.test.tsx'],
  'views/LoginView.tsx': [...viewTests, 'tests/api.test.ts', 'tests/loginPresentation.test.tsx'],
  'views/PatientsView.tsx': [...viewTests, 'tests/caseloadPresentation.test.tsx', 'tests/accountCustodyBehavior.test.tsx', 'tests/viewInitialDom.test.tsx'],
  'views/PatientView.tsx': [...viewTests, 'tests/patientPresentation.test.tsx', 'tests/patientFreshnessContracts.test.ts', 'tests/viewInitialDom.test.tsx', 'tests/patientBounds.test.tsx', 'tests/patientNativeHandoff.test.tsx'],
};
const campaignConfig = { ...originalConfig, testRunner: 'vitest', vitest: { related: false }, coverageAnalysis: 'perTest', concurrency, timeoutMS, inPlace: true, jsonReporter: { fileName: join(reportRoot, `${label}-mutation.json`) } };
// A Stryker-level testFiles filter incorrectly activates static mutants at
// runtime. Vitest's existing test.include owns suite discovery instead.
delete campaignConfig.testFiles;
const canarySource = 'export const staticKill = "protected-banner";\nexport const staticSurvivor = "loose-caption";\nexport function runtimeKill() { return "ready"; }\nexport function runtimeSurvivor() { return "loose"; }\nexport const snapshotKill = "protected snapshot";\nexport function closureKill() { return () => false; }\n';
const canaryTests = 'import {expect,it} from "vitest"; import {staticKill,staticSurvivor,runtimeKill,runtimeSurvivor,snapshotKill,closureKill} from "../tools/mutation-runner-canaries"; it("static exact output",()=>expect(staticKill).toBe("protected-banner")); it("static deliberate survivor",()=>expect(typeof staticSurvivor).toBe("string")); it("runtime exact output",()=>expect(runtimeKill()).toBe("ready")); it("runtime deliberate survivor",()=>expect(typeof runtimeSurvivor()).toBe("string")); it("snapshot output",()=>expect(snapshotKill).toMatchSnapshot()); it("runtime closure output",()=>expect(closureKill()()).toBe(false));\n';
await writeFile(join(workspace, 'tools/mutation-runner-canaries.ts'), canarySource);
await writeFile(join(workspace, 'tests/mutation-runner-canaries.test.ts'), canaryTests);
await mkdir(join(workspace, 'tests/__snapshots__'), { recursive: true });
await writeFile(join(workspace, 'tests/__snapshots__/mutation-runner-canaries.test.ts.snap'), '// Vitest Snapshot v1\n\nexports[`snapshot output 1`] = `"protected snapshot"`;\n');
await writeFile(join(workspace, 'mutation-canary.vitest.config.ts'), 'import base from "./vite.config"; export default {...base,test:{...base.test,update:"none",include:["tests/mutation-runner-canaries.test.ts"],coverage:{...base.test?.coverage,enabled:false}}};\n');
const canaryConfig = { ...campaignConfig, mutate: ['tools/mutation-runner-canaries.ts'], concurrency: 1, vitest: { related: false, configFile: 'mutation-canary.vitest.config.ts' }, thresholds: { break: 0 }, jsonReporter: { fileName: join(reportRoot, `${label}-runner-canaries.json`) } };
await writeFile(join(workspace, 'mutation-canary.config.json'), JSON.stringify(canaryConfig, null, 2));
await checked('node_modules/.bin/stryker', ['run', 'mutation-canary.config.json'], 'runner-canaries');
if (await readFile(join(workspace, 'tests/__snapshots__/mutation-runner-canaries.test.ts.snap'), 'utf8') !== '// Vitest Snapshot v1\n\nexports[`snapshot output 1`] = `"protected snapshot"`;\n') throw new Error('Native runner changed the snapshot oracle.');
const canaryReport = JSON.parse(await readFile(canaryConfig.jsonReporter.fileName, 'utf8'));
const canaries = Object.values(canaryReport.files).flatMap(file => file.mutants);
const expected = [
  [1, 'StringLiteral', 'Killed', true], [2, 'StringLiteral', 'Survived', true],
  [3, 'BlockStatement', 'Killed', false], [3, 'StringLiteral', 'Killed', false],
  [4, 'BlockStatement', 'Killed', false], [4, 'StringLiteral', 'Survived', false],
  [5, 'StringLiteral', 'Killed', true],
  [6, 'BlockStatement', 'Killed', false], [6, 'ArrowFunction', 'Killed', false], [6, 'BooleanLiteral', 'Killed', false],
];
if (canaries.length !== expected.length || expected.some(([line, operator, status, isStatic]) => !canaries.some(mutant => mutant.location.start.line === line && mutant.mutatorName === operator && mutant.status === status && mutant.static === isStatic && mutant.testsCompleted > 0))) {
  throw new Error(`Native runner controls failed; campaign was not started. See ${canaryConfig.jsonReporter.fileName}.`);
}
for (const path of ['tools/mutation-runner-canaries.ts', 'tests/mutation-runner-canaries.test.ts', 'tests/__snapshots__/mutation-runner-canaries.test.ts.snap', 'mutation-canary.vitest.config.ts', 'mutation-canary.config.json']) await rm(join(workspace, path));
if (args.includes('--canaries-only')) {
  console.log('Native static/runtime kill and survivor controls passed.');
  process.exit(0);
}
await checked('npm', ['test', '--', '--maxWorkers=2'], 'baseline-tests');
await writeFile(join(workspace, 'mutation-full.config.json'), JSON.stringify(campaignConfig, null, 2));
await writeFile(join(reportRoot, `${label}-config.json`), JSON.stringify(campaignConfig, null, 2));
const startedAt = new Date().toISOString();
let exitCode;
if (args.includes('--file-shards')) {
  const fileReports = join(reportRoot, `${label}-files`);
  await mkdir(fileReports, { recursive: true });
  const inventory = Object.keys(sourceBefore).filter(file => /\.tsx?$/.test(file));
  if (onlyFiles.some(file => !inventory.includes(file))) throw new Error('A selected source file is outside the full production mutation inventory.');
  const sourceFiles = inventory.filter(file => (!replayReportPath || replayRanges.has(file)) && (!onlyFiles.length || onlyFiles.includes(file)));
  // Largest files start first so smaller files fill freed workers.
  const lengths = Object.fromEntries(await Promise.all(sourceFiles.map(async file => [file, (await readFile(join(workspace, 'src', file))).length])));
  const queue = [...sourceFiles].sort((a, b) => lengths[b] - lengths[a]);
  const firstFiles = option('--first-files', '').split(',').filter(Boolean).map(file => file.replace(/^src\//, ''));
  if (firstFiles.some(file => !sourceFiles.includes(file))) throw new Error('A requested first file is outside the full production mutation inventory.');
  queue.sort((a, b) => {
    const rankA = firstFiles.indexOf(a), rankB = firstFiles.indexOf(b);
    return rankA < 0 && rankB < 0 ? 0 : (rankA < 0 ? firstFiles.length : rankA) - (rankB < 0 ? firstFiles.length : rankB);
  });
  const completed = [];
  const shardRuns = await Promise.allSettled(Array.from({ length: Math.min(concurrency, queue.length) }, async (_, workerIndex) => {
    while (queue.length) {
      while (workerBudgetFile && workerIndex >= Number((await readFile(resolve(workerBudgetFile), 'utf8')).trim())) {
        console.log(`Complete-file worker ${workerIndex + 1} is waiting for the shared host budget.`);
        await new Promise(resolveWait => setTimeout(resolveWait, 20_000));
        if (!queue.length) return;
      }
      const file = queue.shift();
      if (!file) return;
      const name = file.replace(/[^A-Za-z0-9_-]/g, '_');
      const shard = join(scratchRoot, `portal-file-${name}`);
      await cp(workspace, shard, { recursive: true, filter: path => !excluded.has(path.split('/').at(-1)) });
      await symlink(join(workspace, 'node_modules'), join(shard, 'node_modules'));
      const config = { ...campaignConfig, mutate: replayRanges.get(file) ?? [`src/${file}`], concurrency: fileConcurrency, jsonReporter: { fileName: join(fileReports, `${name}.json`) } };
      if (testGlob || args.includes('--consumer-shards') && !args.includes('--all-tests')) {
        const include = testGlob ? testGlob.split(',') : consumerTests[file];
        if (!include) throw new Error(`No consumer test mapping for ${file}`);
        await writeFile(join(shard, 'mutation-consumer.vitest.config.ts'), `import base from "./vite.config"; export default {...base,test:{...base.test,update:"none",include:${JSON.stringify(include)},coverage:{...base.test?.coverage,enabled:false}}};\n`);
        config.vitest = { related: false, configFile: 'mutation-consumer.vitest.config.ts' };
      }
      await writeFile(join(shard, 'mutation-file.config.json'), JSON.stringify(config, null, 2));
      console.log(`Starting ${replayReportPath ? 'unresolved source ranges' : 'complete file'}: src/${file}`);
      const code = await run('node_modules/.bin/stryker', ['run', 'mutation-file.config.json'], `files/${name}`, shard);
      const restored = await digestTree(join(shard, 'src'));
      if (JSON.stringify(sourceBefore) !== JSON.stringify(restored)) throw new Error(`Source was not restored in ${shard}`);
      const report = JSON.parse(await readFile(config.jsonReporter.fileName, 'utf8'));
      completed.push({ file, code, report, shard });
      console.log(`Completed full file: src/${file}`);
    }
  }));
  const failed = shardRuns.filter(result => result.status === "rejected");
  if (failed.length) throw new AggregateError(failed.map(result => result.reason), "One or more complete-file campaigns failed; successful shard reports were retained.");
  completed.sort((a, b) => a.file.localeCompare(b.file));
  const merged = { ...completed[0].report, files: {}, testFiles: {}, projectRoot: workspace, config: campaignConfig };
  completed.forEach(({ file, report }, index) => {
    const prefix = `file${index}:`;
    for (const [path, data] of Object.entries(report.testFiles ?? {})) {
      if (!merged.testFiles[path]) merged.testFiles[path] = { ...data, tests: [] };
      merged.testFiles[path].tests.push(...data.tests.map(test => ({ ...test, id: prefix + test.id })));
    }
    for (const [path, data] of Object.entries(report.files)) {
      if (path !== `src/${file}` || merged.files[path]) throw new Error(`Unexpected or duplicate file in shard: ${path}`);
      merged.files[path] = { ...data, mutants: data.mutants.map(mutant => ({ ...mutant, id: prefix + mutant.id, ...(mutant.killedBy ? { killedBy: mutant.killedBy.map(id => prefix + id) } : {}), ...(mutant.coveredBy ? { coveredBy: mutant.coveredBy.map(id => prefix + id) } : {}) })) };
    }
  });
  if (Object.keys(merged.files).length !== sourceFiles.length) throw new Error('Complete-file campaign omitted production files.');
  await writeFile(campaignConfig.jsonReporter.fileName, JSON.stringify(merged));
  await writeFile(join(reportRoot, `${label}-shards.json`), JSON.stringify(completed.map(({ file, code, shard }) => ({ file: `src/${file}`, code, workspace: shard })), null, 2));
  const mutants = Object.values(merged.files).flatMap(file => file.mutants);
  const scored = mutants.filter(mutant => ['Killed', 'Timeout', 'Survived', 'NoCoverage'].includes(mutant.status));
  const detected = scored.filter(mutant => ['Killed', 'Timeout'].includes(mutant.status)).length;
  const score = scored.length ? detected / scored.length * 100 : 100;
  // Preserve the original global Stryker floor after unioning complete files.
  // Timeout counts here follow Stryker's raw gate; review evidence reports
  // actual behavioral kills separately and never treats timeout as a kill.
  exitCode = score < campaignConfig.thresholds.break ? 1 : 0;
  console.log(`${replayReportPath ? 'Residual replay' : 'Full-scope'} raw Stryker score: ${score.toFixed(2)}; original global floor: ${campaignConfig.thresholds.break}.`);
} else {
  exitCode = await run('node_modules/.bin/stryker', ['run', 'mutation-full.config.json'], 'mutation');
}
const sourceAfter = await digestTree(join(workspace, 'src'));
if (JSON.stringify(sourceBefore) !== JSON.stringify(sourceAfter)) throw new Error(`Instrumented workspace source was not restored. Workspace retained at ${workspace}.`);
await writeFile(join(reportRoot, `${label}-execution.json`), JSON.stringify({ startedAt, completedAt: new Date().toISOString(), workspace, exitCode, vitest: '4.1.10', coverageProvider: '4.1.10', inputs, sourceRestored: true, scope: replayReportPath ? Object.fromEntries(replayRanges) : originalConfig.mutate, replayReport: replayReportPath || undefined, consumerTests: args.includes('--consumer-shards') && !args.includes('--all-tests') ? consumerTests : undefined, command: process.argv }, null, 2));
console.log(`Mutation report: ${campaignConfig.jsonReporter.fileName}`);
console.log(`Report workspace retained for targeted replays: ${workspace}`);
process.exitCode = exitCode;
