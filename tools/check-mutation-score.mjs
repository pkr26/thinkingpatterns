#!/usr/bin/env node
// Validate a complete Stryker report and enforce an inclusive minimum score.
import { readFileSync } from 'node:fs';

const [reportPath, rawMinimum, ...extra] = process.argv.slice(2);
const minimumScore = Number(rawMinimum);
if (
  !reportPath ||
  rawMinimum === undefined ||
  !rawMinimum.trim() ||
  extra.length ||
  !Number.isFinite(minimumScore) ||
  minimumScore < 0 ||
  minimumScore > 100
) {
  console.error('usage: node tools/check-mutation-score.mjs REPORT MINIMUM_0_TO_100');
  process.exit(64);
}

try {
  const report = JSON.parse(readFileSync(reportPath, 'utf8'));
  if (!report.files || typeof report.files !== 'object' || Array.isArray(report.files)) {
    throw new Error('missing report files');
  }

  const counts = {
    Killed: 0,
    Timeout: 0,
    Survived: 0,
    NoCoverage: 0,
    CompileError: 0,
    RuntimeError: 0,
    Ignored: 0,
  };
  for (const [name, file] of Object.entries(report.files)) {
    if (!Array.isArray(file.mutants)) {
      throw new Error(`missing mutants in ${name}`);
    }
    for (const mutant of file.mutants) {
      if (!Object.hasOwn(counts, mutant.status)) {
        throw new Error(`incomplete/unknown mutant status in ${name}: ${mutant.status}`);
      }
      counts[mutant.status]++;
    }
  }

  // Stryker excludes compile errors and ignored mutants. Runtime errors cannot
  // count as successful detections or make an incomplete campaign pass.
  if (counts.RuntimeError) {
    throw new Error(`${counts.RuntimeError} runtime-error mutants require investigation`);
  }
  const scoredMutants = counts.Killed + counts.Timeout + counts.Survived + counts.NoCoverage;
  if (!scoredMutants) {
    throw new Error('report has no scoreable mutants');
  }

  const score = 100 * (counts.Killed + counts.Timeout) / scoredMutants;
  console.log(`mutation score: ${score.toFixed(4)}%; minimum: ${minimumScore}%`);
  console.log(JSON.stringify(counts));
  if (score < minimumScore) {
    console.error(`mutation score is below ${minimumScore}%`);
    process.exitCode = 1;
  }
} catch (error) {
  console.error(`invalid mutation evidence: ${error.message}`);
  process.exitCode = 2;
}
