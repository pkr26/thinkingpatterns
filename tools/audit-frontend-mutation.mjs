#!/usr/bin/env node
// Inventory/status audit only: this does not establish that a test oracle is valid.
import { createHash } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';

const statuses = new Set(['Killed', 'Survived', 'NoCoverage', 'Timeout', 'CompileError', 'RuntimeError', 'Ignored']);
const unresolvedStatuses = new Set(['Survived', 'NoCoverage', 'Timeout', 'RuntimeError', 'Ignored']);
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const slash = (path) => path.split(sep).join('/');
// Vitest reports its own timeout as a failed test, which Stryker labels Killed.
// Preserve that raw label while preventing a watchdog failure earning a kill.
const testTimedOut = (mutant) => mutant.status === 'Killed' && /^(?:Test|Hook) timed out in \d+ms\./m.test(mutant.statusReason ?? '');
// A mutated setup import can fail before Vitest executes any test, while the
// runner still returns Killed or Survived. Such observations need a replay.
const zeroTestObservation = (mutant) => ['Killed', 'Survived'].includes(mutant.status) && mutant.testsCompleted === 0;

export function mutantKey(file, mutant) {
  const { start, end } = mutant.location;
  return hash(JSON.stringify([file, start.line, start.column, end.line, end.column, mutant.mutatorName, mutant.replacement]));
}

export async function inventory(packageDirectory) {
  const files = new Map();
  async function walk(directory) {
    const entries = await readdir(resolve(packageDirectory, directory), { withFileTypes: true });
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      const name = `${directory}/${entry.name}`;
      if (entry.isDirectory()) await walk(name);
      else if (entry.isFile() && /\.(?:[cm]?js|jsx|tsx?|mts|cts)$/.test(name) && !/\.d\.ts$/.test(name)) {
        files.set(name, await readFile(resolve(packageDirectory, name), 'utf8'));
      }
    }
  }
  await walk('src');
  // Runtime code outside src is part of the frontend campaign too.
  try { await walk('public'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  for (const name of ['App.tsx', 'index.js', 'installPolyfills.cjs']) {
    try { files.set(name, await readFile(resolve(packageDirectory, name), 'utf8')); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  return new Map([...files].sort(([a], [b]) => a.localeCompare(b)));
}

export async function enumerate(packageDirectory, sources) {
  const require = createRequire(resolve(packageDirectory, 'package.json'));
  const { Instrumenter } = await import(pathToFileURL(require.resolve('@stryker-mutator/instrumenter')).href);
  const logger = { debug() {}, info() {}, warn() {}, error() {}, trace() {}, isDebugEnabled: () => false };
  const input = [...sources].map(([name, content]) => ({ name: resolve(packageDirectory, name), content, mutate: true }));
  const result = await new Instrumenter(logger).instrument(input, { plugins: null, ignorers: [], excludedMutations: [] });
  return result.mutants.map((mutant) => ({
    ...mutant,
    fileName: slash(relative(packageDirectory, mutant.fileName)),
    location: {
      start: { ...mutant.location.start, line: mutant.location.start.line + 1, column: mutant.location.start.column + 1 },
      end: { ...mutant.location.end, line: mutant.location.end.line + 1, column: mutant.location.end.column + 1 },
    },
  }));
}

export function auditReport(sources, enumeration, report, reviews = []) {
  if (!report.files || typeof report.files !== 'object' || Array.isArray(report.files)) throw new Error('Missing report files');
  if (!Array.isArray(reviews)) throw new Error('Reviews must be an array');
  const expected = new Map();
  for (const mutant of enumeration) {
    const key = mutantKey(mutant.fileName, mutant);
    expected.set(key, (expected.get(key) ?? 0) + 1);
  }
  const reviewMap = new Map();
  for (const review of reviews) {
    if (reviewMap.has(review.key)) throw new Error(`Duplicate review: ${review.key}`);
    if (!['Equivalent', 'NonTermination', 'ResourceExhaustion'].includes(review.disposition) || !review.contract?.trim() || !review.reason?.trim() || !review.evidence?.length) {
      throw new Error(`Incomplete residual review: ${review.key}`);
    }
    reviewMap.set(review.key, review);
  }
  const counts = Object.fromEntries([...statuses].map((status) => [status, 0]));
  const rows = [];
  let total = 0;
  let equivalent = 0;
  let nonTerminating = 0;
  let resourceExhaustion = 0;
  let testTimeoutFailures = 0;
  let zeroTestObservations = 0;
  for (const [name, file] of Object.entries(report.files)) {
    if (!sources.has(name)) throw new Error(`Out-of-scope file: ${name}`);
    if (file.source !== sources.get(name)) throw new Error(`Stale report source: ${name}`);
    if (!Array.isArray(file.mutants)) throw new Error(`Missing mutants: ${name}`);
    const ids = new Set();
    for (const mutant of file.mutants) {
      if (!statuses.has(mutant.status)) throw new Error(`Unknown/incomplete status: ${name} ${mutant.id} ${mutant.status}`);
      if (ids.has(mutant.id)) throw new Error(`Duplicate mutant ID: ${name} ${mutant.id}`);
      ids.add(mutant.id);
      const key = mutantKey(name, mutant);
      const remaining = expected.get(key) ?? 0;
      if (remaining === 0) throw new Error(`Unexpected/duplicate mutant: ${name} ${mutant.id}`);
      expected.set(key, remaining - 1);
      counts[mutant.status]++;
      const stalledTest = testTimedOut(mutant);
      const emptyRun = zeroTestObservation(mutant);
      if (stalledTest) testTimeoutFailures++;
      if (emptyRun) zeroTestObservations++;
      total++;
      const review = reviewMap.get(key);
      if (review) {
        if (review.disposition === 'Equivalent') {
          if (!['Survived', 'NoCoverage'].includes(mutant.status)) throw new Error(`Equivalent review requires a survivor: ${name} ${mutant.id}`);
          if (emptyRun) throw new Error(`Equivalent review requires a valid test observation: ${name} ${mutant.id}`);
          equivalent++;
        } else {
          if (mutant.status !== 'Timeout' && !stalledTest) throw new Error(`Nontermination review requires a timeout: ${name} ${mutant.id}`);
          if (review.disposition === 'NonTermination') nonTerminating++;
          else resourceExhaustion++;
        }
        reviewMap.delete(key);
      }
      if (unresolvedStatuses.has(mutant.status) || stalledTest || emptyRun) {
        rows.push({ file: name, id: mutant.id, key, location: mutant.location, mutatorName: mutant.mutatorName,
          replacement: mutant.replacement, status: mutant.status, ...(stalledTest ? { testTimedOut: true } : {}), ...(emptyRun ? { zeroTestsCompleted: true } : {}), disposition: review ? review.disposition : 'Unresolved', ...(review ? { review } : {}) });
      }
    }
  }
  const missing = [...expected.values()].reduce((sum, count) => sum + count, 0);
  if (missing) throw new Error(`Incomplete campaign: ${missing} enumerated mutants are missing`);
  if (reviewMap.size) throw new Error(`Stale/unmatched residual reviews: ${reviewMap.size}`);
  const targets = [...sources].map(([name, source]) => ({
    file: name, sha256: hash(source), mutants: enumeration.filter((mutant) => mutant.fileName === name).length,
  }));
  const unresolved = rows.filter((row) => row.disposition === 'Unresolved').length;
  return { scope: 'Runtime frontend JS/TS/TSX, including entrypoints and public scripts; excludes tests, build tooling, dependencies, and native platform source',
    note: 'Validates operator inventory, target bytes, report statuses and review linkage. Runtime oracle validity and equivalent reasoning require separate review. Timeouts receive no runtime-kill credit.',
    total, counts, runtimeKills: counts.Killed - rows.filter(row => row.status === 'Killed' && (row.testTimedOut || row.zeroTestsCompleted)).length,
    testTimeoutFailures, zeroTestObservations, equivalent, nonTerminating, resourceExhaustion, unresolved, complete: unresolved === 0, targets, residuals: rows };
}

async function readJson(path) {
  const bytes = await readFile(path);
  return JSON.parse((path.endsWith('.gz') ? gunzipSync(bytes) : bytes).toString('utf8'));
}

async function main() {
  const [packagePath, reportPath, ...args] = process.argv.slice(2);
  if (!packagePath || !reportPath || args.length % 2) throw new Error('usage: node tools/audit-frontend-mutation.mjs PACKAGE REPORT [--reviews FILE] [--output FILE]');
  const options = {};
  for (let i = 0; i < args.length; i += 2) {
    if (!['--reviews', '--output'].includes(args[i]) || options[args[i]]) throw new Error(`Invalid option: ${args[i]}`);
    options[args[i]] = args[i + 1];
  }
  const packageDirectory = resolve(packagePath);
  const sources = await inventory(packageDirectory);
  const enumeration = await enumerate(packageDirectory, sources);
  const report = await readJson(reportPath);
  const reviews = options['--reviews'] ? await readJson(options['--reviews']) : [];
  const audit = auditReport(sources, enumeration, report, reviews);
  if (options['--output']) await writeFile(options['--output'], `${JSON.stringify(audit, null, 2)}\n`);
  console.log(JSON.stringify({ total: audit.total, counts: audit.counts, runtimeKills: audit.runtimeKills, testTimeoutFailures: audit.testTimeoutFailures, zeroTestObservations: audit.zeroTestObservations, equivalent: audit.equivalent, nonTerminating: audit.nonTerminating, resourceExhaustion: audit.resourceExhaustion, unresolved: audit.unresolved,
    targets: audit.targets.length, complete: audit.complete }));
  if (!audit.complete) process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => { console.error(`Invalid mutation evidence: ${error.message}`); process.exitCode = 2; });
}
