/**
 * Programmatic API: analyze a project directory and return findings.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as ts from 'typescript';
import { analyze, Finding } from './engine';
import { DEFAULT_RULES, mergeRules, ProjectRuleFile, RuleTable } from './rules';

export { analyze, Finding } from './engine';
export { toSarif } from './sarif';
export { DEFAULT_RULES, mergeRules } from './rules';

export interface AnalyzeProjectOptions {
  /** extra sanitizer/sink rules merged on top of the defaults */
  rules?: ProjectRuleFile;
}

export function analyzeProject(
  projectDir: string,
  opts: AnalyzeProjectOptions = {},
): { findings: Finding[]; rules: RuleTable; files: string[] } {
  const rootDir = path.resolve(projectDir);

  const projectRulePath = path.join(rootDir, 'taint-rules.json');
  const fileExtra: ProjectRuleFile = fs.existsSync(projectRulePath)
    ? (JSON.parse(fs.readFileSync(projectRulePath, 'utf8')) as ProjectRuleFile)
    : {};
  const extra: ProjectRuleFile = {
    sanitizers: [...(fileExtra.sanitizers ?? []), ...(opts.rules?.sanitizers ?? [])],
    extraSinks: [...(fileExtra.extraSinks ?? []), ...(opts.rules?.extraSinks ?? [])],
    sourceProps: [...(fileExtra.sourceProps ?? []), ...(opts.rules?.sourceProps ?? [])],
  };
  const rules = mergeRules(DEFAULT_RULES, extra);

  const files = resolveProjectFiles(rootDir);
  const findings = analyze(rootDir, files, rules);
  return { findings, rules, files };
}

function resolveProjectFiles(rootDir: string): string[] {
  const tsconfigPath = path.join(rootDir, 'tsconfig.json');
  if (fs.existsSync(tsconfigPath)) {
    const config = ts.readConfigFile(tsconfigPath, ts.sys.readFile);
    if (config.config) {
      const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, rootDir);
      if (parsed.fileNames.length > 0) return parsed.fileNames;
    }
  }
  // fallback: every .ts file under the project, excluding node_modules and .d.ts
  return ts.sys
    .readDirectory(rootDir, ['.ts'], ['node_modules', 'dist'])
    .filter((f) => !f.endsWith('.d.ts'));
}
