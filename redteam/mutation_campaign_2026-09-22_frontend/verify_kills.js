#!/usr/bin/env node
// Compare two Stryker mutation.json runs over the same tree (before/after a
// pin batch) and report, per file, which previously-surviving mutants died —
// and which still survive. Mutant identity = (file, start line, start column,
// mutator, replacement), stable across runs of the same tree.
//
// Usage: node verify_kills.js <baseline.json> <after.json> [--file <substr>]
import { readFileSync } from 'node:fs';

const args = process.argv.slice(2);
const [baselinePath, afterPath] = [args.shift(), args.shift()];
let fileFilter = null;
if (args[0] === '--file') fileFilter = args[1];

const key = (rel, m) => `${rel}:${m.location.start.line}:${m.location.start.column}:${m.mutatorName}:${JSON.stringify(m.replacement ?? '')}`;

const load = (path) => {
  const r = JSON.parse(readFileSync(path, 'utf8'));
  const map = new Map();
  const perFile = new Map();
  for (const [abs, f] of Object.entries(r.files ?? {})) {
    const rel = abs.replace(/^.*\/(portal|mobile)\//, '$1/');
    if (fileFilter && !rel.includes(fileFilter)) continue;
    perFile.set(rel, { total: f.mutants.length, survived: 0, killed: 0 });
    for (const m of f.mutants) {
      if (m.status === 'Survived' || m.status === 'NoCoverage') {
        map.set(key(rel, m), { rel, m });
        perFile.get(rel).survived += 1;
      } else if (m.status === 'Killed' || m.status === 'Timeout') {
        perFile.get(rel).killed += 1;
      }
    }
  }
  return { map, perFile };
};

const before = load(baselinePath);
const after = load(afterPath);

let killedByPins = 0, stillAlive = 0, newSurvivors = 0;
const stillByFile = new Map();
for (const [k, entry] of before.map) {
  if (after.map.has(k)) {
    stillAlive += 1;
    stillByFile.set(entry.rel, (stillByFile.get(entry.rel) ?? 0) + 1);
  } else {
    killedByPins += 1;
  }
}
for (const k of after.map.keys()) if (!before.map.has(k)) newSurvivors += 1;

console.log(`survivors before: ${before.map.size}`);
console.log(`survivors after:  ${after.map.size}`);
console.log(`killed by the pin batch: ${killedByPins}`);
console.log(`still surviving:         ${stillAlive}`);
console.log(`NEW survivors (regression or nondeterminism): ${newSurvivors}`);
console.log('\nper-file scores after (killed/total, score) vs survivors before -> after:');
const rels = [...new Set([...before.perFile.keys(), ...after.perFile.keys()])].sort();
for (const rel of rels) {
  const b = before.perFile.get(rel);
  const a = after.perFile.get(rel);
  const score = a && a.total ? ((a.killed / a.total) * 100).toFixed(1) : 'n/a';
  console.log(`  ${rel}: ${score}% | survivors ${b?.survived ?? 0} -> ${a?.survived ?? 0}`);
}
