#!/usr/bin/env node
// Attribute pin-test kills only to matching mutants over identical source/scope.
// Usage: node verify_kills.js BEFORE AFTER [--file SUBSTRING]
import { readFileSync } from 'node:fs';

const args = process.argv.slice(2);
const [baselinePath, afterPath] = args.splice(0, 2);
let fileFilter = null;
if (args.length === 2 && args[0] === '--file' && args[1]) fileFilter = args[1];
else if (args.length) {
  console.error('usage: verify_kills.js BEFORE AFTER [--file SUBSTRING]');
  process.exit(64);
}
const terminal = new Set(['Killed', 'Timeout', 'Survived', 'NoCoverage', 'CompileError', 'RuntimeError', 'Ignored']);
const surviving = new Set(['Survived', 'NoCoverage']);
const killed = new Set(['Killed', 'Timeout']);
const relative = (path) => path.replaceAll('\\', '/').replace(/^.*\/(portal|mobile|web)\//, '$1/');
function identity(rel, m) {
  if (!m.location?.start || !m.location?.end || typeof m.mutatorName !== 'string') throw new Error(`invalid mutant identity in ${rel}`);
  return JSON.stringify([rel, m.location.start, m.location.end, m.mutatorName, m.replacement ?? '']);
}
function load(path) {
  const report = JSON.parse(readFileSync(path, 'utf8'));
  if (!report.files || typeof report.files !== 'object') throw new Error(`missing file scope in ${path}`);
  const mutants = new Map(), files = new Map();
  for (const [name, file] of Object.entries(report.files)) {
    const rel = relative(name);
    if (fileFilter && !rel.includes(fileFilter)) continue;
    if (files.has(rel) || typeof file.source !== 'string' || !Array.isArray(file.mutants)) throw new Error(`missing/ambiguous source or mutants: ${rel}`);
    const counts = { total: 0, survived: 0, killed: 0, errors: 0, ignored: 0 };
    files.set(rel, { source: file.source, counts });
    for (const m of file.mutants) {
      if (!terminal.has(m.status)) throw new Error(`incomplete mutant ${m.id} in ${rel}: ${m.status}`);
      const key = identity(rel, m);
      if (mutants.has(key)) throw new Error(`ambiguous duplicate mutant identity in ${rel}`);
      mutants.set(key, { rel, m });
      if (surviving.has(m.status)) counts.survived++;
      else if (killed.has(m.status)) counts.killed++;
      else if (m.status === 'Ignored') counts.ignored++;
      else counts.errors++;
      counts.total++;
    }
  }
  if (!files.size || !mutants.size) throw new Error('empty selected source/mutant scope');
  return { mutants, files };
}
try {
  if (!baselinePath || !afterPath) throw new Error('two report paths are required');
  const before = load(baselinePath), after = load(afterPath);
  if (before.files.size !== after.files.size || before.mutants.size !== after.mutants.size) throw new Error('source/mutant scope changed; kills cannot be attributed');
  for (const [rel, file] of before.files) {
    if (after.files.get(rel)?.source !== file.source) throw new Error(`source changed or missing: ${rel}`);
  }
  for (const key of before.mutants.keys()) if (!after.mutants.has(key)) throw new Error('mutant disappeared or changed identity; not a kill');
  let killedByPins = 0, stillAlive = 0, newSurvivors = 0, unresolved = 0;
  for (const [key, { m }] of before.mutants) {
    const next = after.mutants.get(key).m;
    if (surviving.has(m.status)) {
      if (killed.has(next.status)) killedByPins++;
      else if (surviving.has(next.status)) stillAlive++;
      else unresolved++;
    } else if (surviving.has(next.status)) newSurvivors++;
    else if (killed.has(m.status) && !killed.has(next.status)) unresolved++;
    if (next.status === 'RuntimeError' && !surviving.has(m.status) && !killed.has(m.status)) unresolved++;
  }
  const beforeSurvivors = [...before.files.values()].reduce((sum, f) => sum + f.counts.survived, 0);
  const afterSurvivors = [...after.files.values()].reduce((sum, f) => sum + f.counts.survived, 0);
  console.log(`survivors before: ${beforeSurvivors}`);
  console.log(`survivors after:  ${afterSurvivors}`);
  console.log(`killed by the pin batch: ${killedByPins}`);
  console.log(`still surviving: ${stillAlive}`);
  console.log(`unresolved mutants (errors/ignored or lost kills): ${unresolved}`);
  console.log(`NEW survivors (regression or nondeterminism): ${newSurvivors}`);
  for (const [rel, file] of [...after.files].sort(([a], [b]) => a.localeCompare(b))) {
    const a = file.counts, b = before.files.get(rel).counts;
    const scoreable = a.killed + a.survived;
    console.log(`  ${rel}: ${scoreable ? (100 * a.killed / scoreable).toFixed(1) : 'n/a'}% | survivors ${b.survived} -> ${a.survived} | errors ${a.errors} | ignored ${a.ignored}`);
  }
  if (unresolved) process.exitCode = 2;
  else if (newSurvivors) process.exitCode = 1;
} catch (error) {
  console.error(`invalid mutation comparison: ${error.message}`);
  process.exitCode = 2;
}
