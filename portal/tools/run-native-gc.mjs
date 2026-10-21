#!/usr/bin/env node
/** Native garbage-collection test
 * command, with no Stryker/mutation classification or source modification. */
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hashObject, productInputs, recheckFiles, runtimeInventory, structuredResult, validateWitnesses } from './native-gc-support.mjs';

export const CASES = Object.freeze({
  'settled-slot': { package: 'mobile', config: 'vitest.settled-slot-gc.config.ts', testFile:'tests/frontendSettledSlotRetention.gc.ts', minimumBodies: 2,
    receiptEnvironment: { MEMO_OWNER_RECEIPT_FILE: 'public-receipt.json', SETTLED_SLOT_RETENTION_RECEIPT_FILE: 'resource-receipt.json' } },
  'local-rekey-tail': { package: 'mobile', config: 'vitest.local-rekey-tail-gc.config.ts', testFile:'tests/frontendLocalRekeyTailRetention.gc.tsx', minimumBodies: 1,
    receiptEnvironment: { LOCAL_REKEY_TAIL_RETENTION_RECEIPT: 'resource-receipt.json' } },
  'private-key': { package: 'portal', config: 'vitest.private-key-gc.config.ts', testFile:'tests/appPrivateKeyCollection.gc.tsx', minimumBodies: 1,
    receiptEnvironment: { FRONTEND_PORTAL_KEY_COLLECTION_RECEIPT: 'resource-receipt.json' } },
  'draft-tail': { package: 'portal', config: 'vitest.draft-tail-gc.config.ts', testFile:'tests/draftTailCollection.gc.tsx', minimumBodies: 1,
    receiptEnvironment: { FRONTEND_PORTAL_DRAFT_COLLECTION_RECEIPT: 'resource-receipt.json' } },
});
const hashFile = path => createHash('sha256').update(readFileSync(path)).digest('hex');
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const require = (value, message) => { if (!value) throw new Error('SetupError: native GC command: ' + message); };
export function groupAlive(pid) {
  try { process.kill(-pid, 0); return true; }
  catch (error) { if (error.code === 'ESRCH') return false; throw error; }
}
function groupSignal(pid, signal) {
  try { process.kill(-pid, signal); }
  catch (error) { if (error.code !== 'ESRCH') throw error; }
}
async function retired(pid, milliseconds) {
  const deadline = Date.now() + milliseconds;
  while (groupAlive(pid) && Date.now() < deadline) await wait(20);
  return !groupAlive(pid);
}

export function cleanEnvironment(inherited = process.env) {
  const env = {};
  const exact = new Set(['NODE_OPTIONS', 'NODE_PATH', 'UPDATE_SNAPSHOTS', 'WEB_API_PROXY',
    'MEMO_OWNER_RECEIPT_FILE', 'SETTLED_SLOT_RETENTION_RECEIPT_FILE', 'LOCAL_REKEY_TAIL_RETENTION_RECEIPT']);
  for (const [key, value] of Object.entries(inherited)) {
    if (value === undefined || exact.has(key) || /^(?:STRYKER_|FRONTEND_|GEN_|LIVE_)/.test(key)
        || /UPDATE.*(?:SNAPSHOT|PUBLIC_SURFACE)|(?:SNAPSHOT|PUBLIC_SURFACE).*UPDATE/i.test(key)) continue;
    env[key] = value;
  }
  return { ...env, CI: 'true', GEN_INTEROP: '', LIVE_DRILL: '', LIVE_DEMO: '',
    MOBILE_UPDATE_PUBLIC_SURFACES: '', WEB_UPDATE_PUBLIC_SURFACES: '', PORTAL_UPDATE_PUBLIC_SURFACES: '',
    VITEST_UPDATE_SNAPSHOTS: 'false' };
}

export async function runOwned(argv, { cwd, env, deadlineMs = 180000, graceMs = 2000, signal, stdio = 'inherit' }) {
  require(Array.isArray(argv) && argv.length > 0 && argv.every(value => typeof value === 'string'), 'invalid command');
  require(Number.isInteger(deadlineMs) && deadlineMs > 0 && Number.isInteger(graceMs) && graceMs > 0, 'finite deadline/grace required');
  require(process.platform !== 'win32', 'POSIX owned process-group cleanup is required by this proposal');
  const began = Date.now(); let child, ended, timer, interrupted = false, timedOut = false, spawnError;
  let resolveInterrupted;
  const interruption = new Promise(resolve => { resolveInterrupted = resolve; });
  let code = null, terminationSignal = null, cleanupError, descendantsOutlivedLeader = false;
  const result = { argv, cwd, deadlineMs, graceMs, evidenceClass: 'ordinary-native-node-gc-command', mutationExecution: false, verifiedRuntimeKillCredit: 0 };
  const stop = () => { interrupted = true; if (child?.pid) groupSignal(child.pid, 'SIGTERM'); resolveInterrupted(); };
  try {
    child = spawn(argv[0], argv.slice(1), { cwd, env, stdio, detached: true });
    ended = new Promise(resolve => {
      child.once('error', error => { spawnError = String(error); resolve(); });
      child.once('exit', (value, sig) => { code = value; terminationSignal = sig; resolve(); });
    });
    result.ownedProcessGroup = child.pid ?? null;
    if (signal) {
      signal.addEventListener('abort', stop, { once: true });
      if (signal.aborted) stop();
    }
    await Promise.race([ended, interruption, new Promise(resolve => { timer = setTimeout(() => { timedOut = true; resolve(); }, deadlineMs); })]);
    if (timer) clearTimeout(timer);
    if (child.pid) {
      if (timedOut || interrupted) groupSignal(child.pid, 'SIGTERM');
      else if (groupAlive(child.pid)) descendantsOutlivedLeader = true;
      if (!(await retired(child.pid, graceMs))) {
        groupSignal(child.pid, 'SIGKILL');
        require(await retired(child.pid, graceMs), 'own descendants did not retire after escalation');
      }
      // The leader is part of that same group and must be explicitly reaped.
      await ended;
      result.ownedGroupRetired = !groupAlive(child.pid);
    } else result.ownedGroupRetired = false;
  } catch (error) { cleanupError = String(error); }
  finally {
    if (timer) clearTimeout(timer);
    signal?.removeEventListener('abort', stop);
    // Never signal a PID discovered elsewhere; child.pid is from our spawn.
    if (child?.pid && groupAlive(child.pid)) {
      try { groupSignal(child.pid, 'SIGKILL'); await retired(child.pid, graceMs); await ended; }
      catch (error) { cleanupError = String(error); }
      result.ownedGroupRetired = !groupAlive(child.pid);
    }
  }
  return { ...result, exitCode: code, terminationSignal, timedOut, interrupted, spawnError, cleanupError,
    descendantsOutlivedLeader, durationMs: Date.now() - began,
    executionStatus: spawnError || cleanupError || timedOut || interrupted || descendantsOutlivedLeader || !result.ownedGroupRetired ? 'ExecutionError' : 'completed' };
}

export function invocation(packageRoot, caseId, inherited = process.env, modulesPath) {
  require(/^v22\./.test(process.version), 'use an explicit Node22 executable');
  const definition = CASES[caseId]; require(definition, 'unknown case ' + caseId);
  packageRoot = resolve(packageRoot); const pkg = JSON.parse(readFileSync(join(packageRoot, 'package.json')));
  require(pkg.name === 'mindpattern-' + definition.package, 'case/package mismatch');
  const runtime = runtimeInventory(modulesPath ? resolve(modulesPath) : join(packageRoot,'node_modules'));
  require(realpathSync(join(packageRoot,'node_modules'))===runtime.modules,'test/config imports must resolve to the same actual selected provider directory');
  const config = join(packageRoot, definition.config), vitest = join(runtime.modules, 'vitest/vitest.mjs');
  require(existsSync(config) && existsSync(vitest), 'promoted config and actual local Vitest provider required');
  require(existsSync(join(packageRoot,definition.testFile)), 'promoted genuine resource actor missing');
  const inputHashes = productInputs(packageRoot);
  inputHashes[fileURLToPath(import.meta.url)] = hashFile(fileURLToPath(import.meta.url));
  inputHashes[fileURLToPath(new URL('./native-gc-support.mjs',import.meta.url))] = hashFile(fileURLToPath(new URL('./native-gc-support.mjs',import.meta.url)));
  const directory = mkdtempSync(join(tmpdir(), 'mindpattern-' + definition.package + '-' + caseId + '-gc-'));
  // mkdtemp creates an owned0700 directory. The actors alone write witness
  // JSON; this command never fabricates a public producer/resource receipt.
  const env = cleanEnvironment(inherited), witnesses = {};
  env.FRONTEND_NATIVE_GC_CACHE_DIR = join(directory, 'private-cache');
  for (const [key, name] of Object.entries(definition.receiptEnvironment)) env[key] = witnesses[key] = join(directory, name);
  const structuredReport = join(directory, 'vitest.json');
  const argv = [process.execPath, vitest, 'run', '--config', definition.config, '--pool=forks',
    '--execArgv=--expose-gc', '--maxWorkers=1', '--coverage.enabled=false', '--reporter=json', '--outputFile', structuredReport];
  return { argv, cwd: packageRoot, env, directory, witnesses, structuredReport, definition, caseId, runtime, inputHashes,
    inputs: { node: { path: process.execPath, sha256: hashFile(process.execPath), version: process.version },
      runnerSha256: hashFile(fileURLToPath(import.meta.url)), config: { path: config, sha256: hashFile(config) },
      actualVitestEntry: { path: vitest, sha256: hashFile(vitest) } } };
}

export function verifyInvocation(plan) {
  require(realpathSync(join(plan.cwd,'node_modules'))===plan.runtime.modules,'actual package import provider binding changed');
  require(hashObject(plan.runtime.wholeProviderCompilerAndConsumerHashes)===plan.runtime.digest,'recorded runtime map/digest disagree');
  recheckFiles(plan.inputHashes);
  recheckFiles(Object.fromEntries(Object.entries(plan.runtime.wholeProviderCompilerAndConsumerHashes).map(([name,sha])=>[join(plan.runtime.modules,name),sha])));
  require(runtimeInventory(plan.runtime.modules).digest===plan.runtime.digest,'whole provider/compiler/consumer file inventory changed');
  const currentInputs=productInputs(plan.cwd);
  currentInputs[fileURLToPath(import.meta.url)]=hashFile(fileURLToPath(import.meta.url));
  currentInputs[fileURLToPath(new URL('./native-gc-support.mjs',import.meta.url))]=hashFile(fileURLToPath(new URL('./native-gc-support.mjs',import.meta.url)));
  require(hashObject(currentInputs)===hashObject(plan.inputHashes),'whole product source/test/config/shared inventory changed');
  require(plan.inputs.node.sha256===hashFile(process.execPath),'actual Node executable changed');
  require(plan.inputs.node.path===process.execPath && plan.inputs.node.version===process.version,'actual Node path/version binding changed');
}

export async function main(caseId = process.argv[2]) {
  require(process.argv.length === 3 || process.argv.length === 5 && process.argv[3] === '--modules', 'usage: node tools/run-native-gc.mjs <case> [--modules /actual/node_modules]');
  const plan = invocation(fileURLToPath(new URL('..', import.meta.url)), caseId, process.env, process.argv[4]);
  verifyInvocation(plan);
  const abort = new AbortController(), interrupt = () => abort.abort();
  process.on('SIGINT', interrupt); process.on('SIGTERM', interrupt);
  let step;
  try { step = await runOwned(plan.argv, { cwd: plan.cwd, env: plan.env, signal: abort.signal }); }
  finally { process.removeListener('SIGINT', interrupt); process.removeListener('SIGTERM', interrupt); }
  let raw = {}, structuredReportParsingError, structuredReportSha256;
  if (existsSync(plan.structuredReport)) {
    try { const bytes=readFileSync(plan.structuredReport); structuredReportSha256=createHash('sha256').update(bytes).digest('hex'); raw = JSON.parse(bytes); }
    catch (error) { structuredReportParsingError = 'SetupError: actual Vitest structured report parsing failed: ' + String(error); }
  }
  const witnessFiles = {}, parsed = {};
  let witnessValidation, witnessFault, custodyFault;
  try {
    for(const [key,path] of Object.entries(plan.witnesses)) {
      require(existsSync(path), 'actual actor witness output missing: '+key);
      const bytes=readFileSync(path); witnessFiles[key]={path,sha256:createHash('sha256').update(bytes).digest('hex')};
      parsed[key==='MEMO_OWNER_RECEIPT_FILE'?'public':'resource']=JSON.parse(bytes);
    }
    witnessValidation=validateWitnesses(caseId,parsed,process.version);
  } catch(error) { witnessFault='SetupError: actual public/resource witness validation failed: '+String(error); }
  try {
    verifyInvocation(plan);
    for(const value of Object.values(witnessFiles)) require(hashFile(value.path)===value.sha256,'actual witness bytes changed before publication');
    require(structuredReportSha256 && hashFile(plan.structuredReport)===structuredReportSha256,'structured report changed after parsing or is absent');
  } catch(error) { custodyFault='SetupError: actual input/runtime/report custody failed: '+String(error); }
  const accounting=structuredResult(raw,step,caseId,plan.cwd,plan.definition.testFile);
  const inputsPreserved=!custodyFault;
  const passed=!structuredReportParsingError && !witnessFault && inputsPreserved && accounting.passed;
  const receipt = { kind: 'ordinary-genuine-native-node-gc-command-v2', caseId, passed, inputs: plan.inputs,
    inputHashes:plan.inputHashes, runtimeBinding:plan.runtime, inputsPreserved, custodyFault, accounting,
    step, structuredReportParsingError, witnessFault, witnessValidation,
    structuredReport: { path: plan.structuredReport, sha256: structuredReportSha256??null }, witnessFiles,
    limitations: ['One genuine Node fork/exposed-GC command; V8 weak-retention behavior is not physical-device OOM or Keychain custody proof.',
      'All suite/setup/collection/cleanup/runtime faults are rejected; serialized failures remain unattributed ordinary failures.',
      'This ordinary test command provides no mutation kill credit and does not substitute for the separately typed mutation-resource/source-phase collectors.'],
    verifiedRuntimeKillCredit: 0, mutationExecution: false };
  const path = join(plan.directory, 'command-receipt.json'); writeFileSync(path, JSON.stringify(receipt, null, 2) + '\n');
  process.stdout.write(JSON.stringify({ caseId, passed, receipt: path, directory: plan.directory }) + '\n');
  process.exitCode = passed ? 0 : 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { process.stderr.write(String(error) + '\n'); process.exitCode = 1; });
}
