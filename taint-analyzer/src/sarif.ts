/**
 * SARIF 2.1.0 output. Each finding becomes a result with a codeFlow whose
 * threadFlow steps are clickable in the VS Code SARIF Viewer extension.
 */

import { Finding, Step } from './engine';
import { RuleId } from './rules';

const RULE_META: Record<RuleId, { name: string; description: string }> = {
  'sql-injection': {
    name: 'SqlInjection',
    description: 'User-controlled request data reaches a SQL query string.',
  },
  'command-injection': {
    name: 'CommandInjection',
    description: 'User-controlled request data reaches an OS command.',
  },
  'path-traversal': {
    name: 'PathTraversal',
    description: 'User-controlled request data reaches a filesystem path.',
  },
};

function sarifLocation(file: string, line: number, col: number) {
  return {
    physicalLocation: {
      artifactLocation: { uri: file, uriBaseId: 'SRCROOT' },
      region: { startLine: line, startColumn: col },
    },
  };
}

export function toSarif(findings: Finding[], version: string): object {
  const usedRules = [...new Set(findings.map((f) => f.ruleId))];

  const results = findings.map((f) => ({
    ruleId: f.ruleId,
    level: 'error',
    message: { text: `${f.message} (${f.file}:${f.line})` },
    locations: [sarifLocation(f.file, f.line, f.col)],
    codeFlows: [
      {
        threadFlows: [
          {
            locations: f.steps.map((s: Step) => ({
              location: {
                ...sarifLocation(s.file, s.line, s.col),
                message: { text: s.message },
              },
            })),
          },
        ],
      },
    ],
  }));

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'ts-taint',
            version,
            informationUri: 'https://example.invalid/ts-taint',
            rules: usedRules.map((id) => ({
              id,
              name: RULE_META[id].name,
              shortDescription: { text: RULE_META[id].description },
              defaultConfiguration: { level: 'error' },
            })),
          },
        },
        originalUriBaseIds: { SRCROOT: { uri: 'file:///' } },
        results,
      },
    ],
  };
}
