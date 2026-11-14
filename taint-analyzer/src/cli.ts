#!/usr/bin/env node
/**
 * CLI: ts-taint <projectDir> [--out results.sarif]
 */

import * as fs from 'fs';
import * as path from 'path';
import { analyzeProject } from './index';
import { toSarif } from './sarif';

function main(): void {
  const args = process.argv.slice(2);
  const projectDir = args.find((a) => !a.startsWith('-'));
  const outIdx = args.indexOf('--out');
  const outPath = outIdx >= 0 ? args[outIdx + 1] : undefined;

  if (!projectDir) {
    console.error('usage: ts-taint <projectDir> [--out results.sarif]');
    process.exit(2);
  }

  const { findings, files } = analyzeProject(projectDir);
  const sarif = toSarif(findings, require('../package.json').version);

  const out = outPath ?? path.join(path.resolve(projectDir), 'taint-results.sarif');
  fs.writeFileSync(out, JSON.stringify(sarif, null, 2));

  // human-readable summary on stdout
  console.log(`analyzed ${files.length} files, ${findings.length} finding(s)\n`);
  for (const f of findings) {
    console.log(`[${f.ruleId}] ${f.file}:${f.line}:${f.col}  ${f.message}`);
    for (const s of f.steps) {
      console.log(`    ${s.file}:${s.line}:${s.col}  ${s.message}`);
    }
    console.log();
  }
  console.log(`SARIF written to ${out}`);
  if (findings.length > 0) process.exitCode = 1;
}

main();
