/**
 * Rule table for the taint analyzer.
 *
 * Three kinds of entries:
 *  - sources:    expressions that introduce tainted data (req.query / req.body / ...)
 *  - sinks:      dangerous calls that must not receive tainted data
 *  - sanitizers: functions that neutralize taint for one or all sink rules
 *
 * The table is plain data so it can be extended per-project via a
 * `taint-rules.json` file in the analyzed project's root (see loadProjectRules).
 */

export type RuleId = 'sql-injection' | 'command-injection' | 'path-traversal';

export interface SourceRule {
  /** parameter names treated as an express-style request object */
  reqNames: string[];
  /** properties of the request object that hold attacker-controlled data */
  props: string[];
}

export interface SinkRule {
  id: RuleId;
  /** callee names that are sinks, e.g. 'query' matches db.query(...) */
  names: string[];
  /**
   * If set, the callee (identifier or the object of a property access) must
   * have been imported from one of these modules, e.g. 'child_process'.
   */
  modules?: string[];
  /**
   * If set, the receiver object name must match this regex
   * (used for db handles: pool.query, connection.execute, ...).
   */
  objectPattern?: string;
  /** index of the argument that must be untainted */
  argIndex: number;
  /**
   * If true, a tainted value inside the *array* argument at argIndex only
   * counts when the options argument sets `shell: true`
   * (spawn/execFile with an argument vector are safe from shell injection
   * unless a shell is involved).
   */
  arrayArgNeedsShell?: boolean;
  message: string;
}

export interface SanitizerRule {
  /** callee names, e.g. 'parseInt' or 'basename' */
  names: string[];
  /** if set, callee must come from one of these modules (e.g. 'path') */
  modules?: string[];
  /** sink rule ids this sanitizer neutralizes, or '*' for all */
  rules: RuleId[] | '*';
}

export interface RuleTable {
  sources: SourceRule;
  sinks: SinkRule[];
  sanitizers: SanitizerRule[];
}

export const ALL_RULES: RuleId[] = ['sql-injection', 'command-injection', 'path-traversal'];

export const DEFAULT_RULES: RuleTable = {
  sources: {
    reqNames: ['req', 'request'],
    props: ['query', 'body', 'headers', 'params', 'cookies'],
  },

  sinks: [
    {
      id: 'sql-injection',
      names: ['query', 'execute', 'raw'],
      objectPattern: '^(db|database|pool|conn|connection|client|sequelize|knex|orm|prisma)$',
      argIndex: 0,
      message: 'Tainted request data reaches a SQL query string',
    },
    {
      id: 'command-injection',
      names: ['exec', 'execSync'],
      modules: ['child_process', 'node:child_process'],
      argIndex: 0,
      message: 'Tainted request data reaches a shell command',
    },
    {
      id: 'command-injection',
      names: ['spawn', 'spawnSync', 'execFile', 'execFileSync'],
      modules: ['child_process', 'node:child_process'],
      argIndex: 0,
      message: 'Tainted request data used as the command of a child process',
    },
    {
      id: 'command-injection',
      names: ['spawn', 'spawnSync', 'execFile', 'execFileSync'],
      modules: ['child_process', 'node:child_process'],
      argIndex: 1,
      arrayArgNeedsShell: true,
      message: 'Tainted request data in child_process arguments with shell: true',
    },
    {
      id: 'path-traversal',
      names: [
        'readFileSync', 'writeFileSync', 'appendFileSync', 'createReadStream',
        'createWriteStream', 'readdirSync', 'unlinkSync', 'rmSync', 'mkdirSync',
        'accessSync', 'statSync', 'openSync', 'readFile', 'writeFile',
      ],
      modules: ['fs', 'node:fs'],
      argIndex: 0,
      message: 'Tainted request data reaches a filesystem path',
    },
    {
      id: 'path-traversal',
      names: ['sendFile'],
      objectPattern: '^(res|response|reply)$',
      argIndex: 0,
      message: 'Tainted request data reaches res.sendFile path',
    },
  ],

  sanitizers: [
    // numeric coercion kills every injection class: the result cannot contain
    // quotes, shell metacharacters or path separators
    { names: ['parseInt', 'parseFloat', 'Number'], rules: '*' },
    { names: ['floor', 'ceil', 'round', 'abs', 'trunc'], modules: ['Math'], rules: '*' },
    // percent-encodes every metacharacter relevant to SQL, shells and paths
    { names: ['encodeURIComponent'], rules: '*' },
    // path.basename('../../../etc/passwd') === 'passwd'
    { names: ['basename'], modules: ['path', 'node:path'], rules: ['path-traversal'] },
    // mysql / sqlstring escaping
    { names: ['escape', 'escapeId'], modules: ['mysql', 'mysql2', 'sqlstring'], rules: ['sql-injection'] },
  ],
};

/** Shape of an optional taint-rules.json in the analyzed project root. */
export interface ProjectRuleFile {
  sanitizers?: SanitizerRule[];
  extraSinks?: SinkRule[];
  sourceProps?: string[];
}

export function mergeRules(base: RuleTable, extra: ProjectRuleFile): RuleTable {
  return {
    sources: {
      reqNames: base.sources.reqNames,
      props: extra.sourceProps
        ? [...new Set([...base.sources.props, ...extra.sourceProps])]
        : base.sources.props,
    },
    sinks: [...base.sinks, ...(extra.extraSinks ?? [])],
    sanitizers: [...base.sanitizers, ...(extra.sanitizers ?? [])],
  };
}
