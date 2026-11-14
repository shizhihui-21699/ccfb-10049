/**
 * End-to-end test: run the analyzer on test-project and check that
 *  - every real vulnerability is found (exact sink + source locations)
 *  - none of the sanitized/safe patterns produce a finding
 *  - every finding carries a full step trace with file/line
 *  - the SARIF output is well-formed and VS Code-navigable
 *
 * Run with: npm test
 */

const path = require('path');
const { analyzeProject, toSarif } = require('../dist/index.js');

const projectDir = path.join(__dirname, '..', 'test-project');
const { findings } = analyzeProject(projectDir);

// ruleId | sink file:line | source file:line  (first step of the trace)
const EXPECTED = [
  'sql-injection|src/utils/db.ts:6|src/controllers/userController.ts:7', // getUser: req.query.id -> runQuery -> pool.query
  'sql-injection|src/utils/db.ts:6|src/controllers/userController.ts:19', // searchUsers: return-taint via whereEquals/orderBy
  'command-injection|src/controllers/systemController.ts:6|src/controllers/systemController.ts:5', // pingHost: exec('ping ' + host)
  'command-injection|src/controllers/systemController.ts:16|src/controllers/systemController.ts:11', // reloadNginx: via runShell()
  'path-traversal|src/controllers/fileController.ts:9|src/controllers/fileController.ts:7', // download: res.sendFile
  'path-traversal|src/utils/templates.ts:4|src/controllers/fileController.ts:14', // readTemplateFile: via loadTemplate()
];

// Lines that must NOT appear as sinks — dangerous-looking but sanitized/safe:
//  - userController.ts listUsers (parameterized query)
//  - userController.ts getUserByName (escapeSql)
//  - userController.ts getUserByAge (parseInt)
//  - fileController.ts upload (path.basename)
//  - systemController.ts restartService (spawn arg vector, no shell)
//  - systemController.ts listLogs (encodeURIComponent)
const FORBIDDEN_SINKS = [
  'src/utils/db.ts:7', // runParameterized body
  'src/controllers/systemController.ts:22', // spawn('systemctl', ...)
  'src/controllers/systemController.ts:28', // exec('journalctl ...')
  'src/controllers/fileController.ts:20', // fs.writeFileSync
];

let failures = 0;
const fail = (msg) => {
  failures++;
  console.error('FAIL: ' + msg);
};

const key = (f) =>
  `${f.ruleId}|${f.file}:${f.line}|${f.steps[0] ? `${f.steps[0].file}:${f.steps[0].line}` : '?'}`;
const actual = findings.map(key);

// 1. exact match of the finding set (catches both false negatives and false positives)
const missing = EXPECTED.filter((e) => !actual.includes(e));
const unexpected = actual.filter((a) => !EXPECTED.includes(a));
for (const m of missing) fail(`missing expected finding: ${m}`);
for (const u of unexpected) fail(`unexpected finding (false positive?): ${u}`);

// 2. safe patterns must not appear as sink locations
for (const f of findings) {
  const sinkLoc = `${f.file}:${f.line}`;
  if (FORBIDDEN_SINKS.includes(sinkLoc)) {
    fail(`false positive at sanitized/safe location ${sinkLoc} [${f.ruleId}]`);
  }
}

// 3. every finding has a source-to-sink trace, each step with file and line
for (const f of findings) {
  if (f.steps.length < 2) fail(`finding ${key(f)} has no trace steps`);
  if (!f.steps[0].message.startsWith('source:')) fail(`finding ${key(f)} does not start at a source`);
  if (!f.steps[f.steps.length - 1].message.startsWith('sink:')) fail(`finding ${key(f)} does not end at a sink`);
  for (const s of f.steps) {
    if (!s.file || !(s.line > 0)) fail(`finding ${key(f)} has a step without file/line`);
  }
}

// 4. cross-file traces exist (the whole point of the exercise)
const crossFile = findings.filter((f) => new Set(f.steps.map((s) => s.file)).size > 1);
if (crossFile.length < 3) fail(`expected at least 3 cross-file traces, got ${crossFile.length}`);

// 5. SARIF structure
const sarif = toSarif(findings, '0.0.0-test');
if (sarif.version !== '2.1.0') fail('SARIF version is not 2.1.0');
const run = sarif.runs && sarif.runs[0];
if (!run) fail('SARIF has no run');
const results = run.results || [];
if (results.length !== findings.length) fail(`SARIF result count ${results.length} != findings ${findings.length}`);
for (const r of results) {
  const loc = r.locations && r.locations[0] && r.locations[0].physicalLocation;
  if (!loc || !loc.artifactLocation.uri || !(loc.region.startLine > 0)) {
    fail(`SARIF result ${r.ruleId} lacks a clickable location`);
  }
  const flow = r.codeFlows && r.codeFlows[0] && r.codeFlows[0].threadFlows[0];
  if (!flow || flow.locations.length < 2) fail(`SARIF result ${r.ruleId} lacks a code flow`);
}
const ruleIds = (run.tool.driver.rules || []).map((r) => r.id);
for (const id of new Set(findings.map((f) => f.ruleId))) {
  if (!ruleIds.includes(id)) fail(`SARIF rule metadata missing for ${id}`);
}

if (failures) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log(`ok — ${findings.length} findings, all expected; no false positives; SARIF valid`);
