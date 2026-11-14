/**
 * Core taint engine.
 *
 * Two phases:
 *  1. Summary phase (fixed point): every function in the program is analyzed
 *     with its parameters symbolically tainted ("labels"). This yields, per
 *     function: which parameters taint the return value, and which parameters
 *     flow into a sink (with the intra-function trace).
 *  2. Entry phase: express-style handlers (first parameter named req/request)
 *     are analyzed with req.query/body/headers/params/cookies as taint
 *     sources. Tainted arguments flowing into another function are resolved
 *     through that function's summary, giving cross-function / cross-file
 *     traces with file + line for every step.
 */

import * as path from 'path';
import * as ts from 'typescript';
import { ALL_RULES, RuleId, RuleTable, SanitizerRule, SinkRule } from './rules';

const MAX_STEPS = 40;

export interface Step {
  file: string;
  line: number;
  col: number;
  message: string;
}

export interface Finding {
  ruleId: RuleId;
  message: string;
  file: string;
  line: number;
  col: number;
  steps: Step[];
}

interface Taint {
  steps: Step[];
  /** sink rules this value has been sanitized against */
  sanitized: Set<RuleId>;
  /** parameter indices of the function currently being summarized */
  labels: Set<number>;
  /** true if the taint originates from a real source (entry phase) */
  isSource: boolean;
}

interface ParamSink {
  paramIndex: number;
  ruleId: RuleId;
  message: string;
  sinkFile: string;
  sinkLine: number;
  sinkCol: number;
  /** trace inside the callee, from parameter to sink */
  steps: Step[];
}

interface Summary {
  returnFromParams: Set<number>;
  paramSinks: ParamSink[];
}

interface Ctx {
  checker: ts.TypeChecker;
  rules: RuleTable;
  rootDir: string;
  summaries: Map<ts.Node, Summary>;
  importMaps: Map<ts.SourceFile, Map<string, string>>;
  mode: 'summary' | 'entry';
  sourceRoots: Set<ts.Symbol>;
  currentFn: ts.FunctionLikeDeclaration | null;
  // accumulators for the function currently being analyzed
  paramSinks: ParamSink[];
  returnTaint: Taint | null;
  findings: Finding[];
}

type Env = Map<ts.Symbol, Taint>;

// ---------------------------------------------------------------------------
// public entry point
// ---------------------------------------------------------------------------

export function analyze(rootDir: string, fileNames: string[], rules: RuleTable): Finding[] {
  const program = ts.createProgram(fileNames, {
    target: ts.ScriptTarget.ES2020,
    module: ts.ModuleKind.CommonJS,
    moduleResolution: ts.ModuleResolutionKind.NodeJs,
    allowJs: false,
    noEmit: true,
    skipLibCheck: true,
    noResolve: false,
    strict: false,
  });
  const checker = program.getTypeChecker();
  const sourceFiles = program
    .getSourceFiles()
    .filter((sf) => !sf.isDeclarationFile && !sf.fileName.includes('node_modules'));

  const importMaps = new Map<ts.SourceFile, Map<string, string>>();
  for (const sf of sourceFiles) importMaps.set(sf, buildImportMap(sf));

  // collect every function with a body
  const fns: ts.FunctionLikeDeclaration[] = [];
  const collectFns = (n: ts.Node): void => {
    if (isFunctionWithBody(n) && n.body) fns.push(n);
    ts.forEachChild(n, collectFns);
  };
  for (const sf of sourceFiles) collectFns(sf);

  const base: Omit<Ctx, 'paramSinks' | 'returnTaint' | 'findings' | 'currentFn' | 'mode' | 'sourceRoots'> = {
    checker,
    rules,
    rootDir,
    summaries: new Map<ts.Node, Summary>(),
    importMaps,
  };

  // ---- phase 1: fixed-point summary computation --------------------------
  for (let iter = 0; iter < 10; iter++) {
    let changed = false;
    for (const fn of fns) {
      const summary = computeSummary(fn, base);
      if (summaryKey(summary) !== summaryKey(base.summaries.get(fn))) {
        base.summaries.set(fn, summary);
        changed = true;
      }
    }
    if (!changed) break;
  }

  // ---- phase 2: entry analysis -------------------------------------------
  const findings: Finding[] = [];
  const entryCtx = (): Ctx => ({
    ...base,
    mode: 'entry',
    sourceRoots: new Set<ts.Symbol>(),
    currentFn: null,
    paramSinks: [],
    returnTaint: null,
    findings,
  });

  for (const fn of fns) {
    if (!isHandler(fn, rules)) continue;
    const ctx = entryCtx();
    ctx.currentFn = fn;
    const p0 = fn.parameters[0];
    if (p0 && ts.isIdentifier(p0.name)) {
      const sym = checker.getSymbolAtLocation(p0.name);
      if (sym) ctx.sourceRoots.add(sym);
    }
    walkNode(fn.body!, new Map(), ctx);
  }

  // top-level statements of each module (catches module-scope flows)
  for (const sf of sourceFiles) {
    const ctx = entryCtx();
    walkNode(sf, new Map(), ctx);
  }

  return dedupeFindings(findings);
}

// ---------------------------------------------------------------------------
// summary phase
// ---------------------------------------------------------------------------

function computeSummary(
  fn: ts.FunctionLikeDeclaration,
  base: Omit<Ctx, 'paramSinks' | 'returnTaint' | 'findings' | 'currentFn' | 'mode' | 'sourceRoots'>,
): Summary {
  const ctx: Ctx = {
    ...base,
    mode: 'summary',
    sourceRoots: new Set(),
    currentFn: fn,
    paramSinks: [],
    returnTaint: null,
    findings: [],
  };
  const env: Env = new Map();
  fn.parameters.forEach((p, i) => {
    if (!ts.isIdentifier(p.name)) return;
    const sym = ctx.checker.getSymbolAtLocation(p.name);
    if (!sym) return;
    env.set(sym, {
      steps: [{ ...locOf(p, ctx.rootDir), message: `parameter '${p.name.text}'` }],
      sanitized: new Set(),
      labels: new Set([i]),
      isSource: false,
    });
  });
  if (fn.body) walkNode(fn.body, env, ctx);
  const returnFromParams = new Set<number>();
  if (ctx.returnTaint) for (const l of ctx.returnTaint.labels) returnFromParams.add(l);
  return { returnFromParams, paramSinks: ctx.paramSinks };
}

function summaryKey(s: Summary | undefined): string {
  if (!s) return '';
  return JSON.stringify({
    r: [...s.returnFromParams].sort(),
    s: s.paramSinks.map((p) => `${p.paramIndex}|${p.ruleId}|${p.sinkFile}|${p.sinkLine}`).sort(),
  });
}

function isHandler(fn: ts.FunctionLikeDeclaration, rules: RuleTable): boolean {
  const p0 = fn.parameters[0];
  return !!p0 && ts.isIdentifier(p0.name) && rules.sources.reqNames.includes(p0.name.text);
}

// ---------------------------------------------------------------------------
// statement walking
// ---------------------------------------------------------------------------

function walkNode(node: ts.Node, env: Env, ctx: Ctx): void {
  const visit = (n: ts.Node): void => {
    // nested functions are analyzed on their own (closures over tainted
    // locals are a known limitation)
    if (ts.isFunctionLike(n)) return;

    if (ts.isVariableDeclaration(n)) {
      handleVarDecl(n, env, ctx);
      return;
    }
    if (ts.isReturnStatement(n)) {
      if (n.expression) {
        const t = getExprTaint(n.expression, env, ctx);
        if (t) ctx.returnTaint = mergeTaint(ctx.returnTaint, t);
      }
      return;
    }
    if (ts.isCallExpression(n)) {
      // handleCall already recurses into the arguments via getExprTaint
      handleCall(n, env, ctx);
      return;
    }
    if (ts.isExpressionStatement(n)) {
      getExprTaint(n.expression, env, ctx);
      return;
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(node, visit);
}

function handleVarDecl(d: ts.VariableDeclaration, env: Env, ctx: Ctx): void {
  const initT = d.initializer ? getExprTaint(d.initializer, env, ctx) : null;

  if (ts.isIdentifier(d.name)) {
    const sym = ctx.checker.getSymbolAtLocation(d.name);
    if (sym) {
      if (initT) {
        env.set(sym, addStep(initT, stepAt(d.name, ctx, `assigned to '${d.name.text}'`)));
      } else {
        env.delete(sym);
      }
    }
    // aliasing a source root: `const q = req`
    if (d.initializer && ts.isIdentifier(d.initializer)) {
      const src = ctx.checker.getSymbolAtLocation(d.initializer);
      if (src && ctx.sourceRoots.has(src) && sym) ctx.sourceRoots.add(sym);
    }
    return;
  }

  // destructuring
  if (ts.isObjectBindingPattern(d.name) || ts.isArrayBindingPattern(d.name)) {
    // `const { query } = req` — pull source props out of a source root
    if (d.initializer && ts.isIdentifier(d.initializer)) {
      const src = ctx.checker.getSymbolAtLocation(d.initializer);
      if (src && ctx.sourceRoots.has(src) && ts.isObjectBindingPattern(d.name)) {
        for (const el of d.name.elements) {
          if (!ts.isIdentifier(el.name)) continue;
          const propName = el.propertyName && ts.isIdentifier(el.propertyName)
            ? el.propertyName.text
            : el.name.text;
          if (!ctx.rules.sources.props.includes(propName)) continue;
          const sym = ctx.checker.getSymbolAtLocation(el.name);
          if (sym) env.set(sym, makeSource(`req.${propName}`, el, ctx));
        }
        return;
      }
    }
    // `const { id } = req.query` — everything bound from a tainted object is tainted
    if (initT) {
      forEachBoundName(d.name, (id) => {
        const sym = ctx.checker.getSymbolAtLocation(id);
        if (sym) env.set(sym, initT);
      });
    }
  }
}

function forEachBoundName(pattern: ts.BindingPattern, fn: (id: ts.Identifier) => void): void {
  for (const el of pattern.elements) {
    if (ts.isBindingElement(el)) {
      if (ts.isIdentifier(el.name)) fn(el.name);
      else forEachBoundName(el.name, fn);
    }
  }
}

// ---------------------------------------------------------------------------
// expression taint
// ---------------------------------------------------------------------------

function getExprTaint(expr: ts.Expression, env: Env, ctx: Ctx): Taint | null {
  if (ts.isIdentifier(expr)) {
    const sym = ctx.checker.getSymbolAtLocation(expr);
    return (sym && env.get(sym)) || null;
  }

  if (ts.isPropertyAccessExpression(expr)) {
    if (ts.isIdentifier(expr.expression)) {
      const sym = ctx.checker.getSymbolAtLocation(expr.expression);
      if (sym && ctx.sourceRoots.has(sym) && ctx.rules.sources.props.includes(expr.name.text)) {
        return makeSource(`req.${expr.name.text}`, expr, ctx);
      }
    }
    return getExprTaint(expr.expression, env, ctx);
  }

  if (ts.isElementAccessExpression(expr)) {
    if (
      ts.isIdentifier(expr.expression) &&
      expr.argumentExpression &&
      ts.isStringLiteral(expr.argumentExpression)
    ) {
      const sym = ctx.checker.getSymbolAtLocation(expr.expression);
      if (sym && ctx.sourceRoots.has(sym) && ctx.rules.sources.props.includes(expr.argumentExpression.text)) {
        return makeSource(`req.${expr.argumentExpression.text}`, expr, ctx);
      }
    }
    return getExprTaint(expr.expression, env, ctx);
  }

  if (ts.isCallExpression(expr)) return handleCall(expr, env, ctx);

  if (ts.isTemplateExpression(expr)) {
    return mergeAll(expr.templateSpans.map((s) => getExprTaint(s.expression, env, ctx)));
  }

  if (ts.isTaggedTemplateExpression(expr)) {
    const tag = getExprTaint(expr.tag, env, ctx);
    const parts = ts.isTemplateExpression(expr.template)
      ? expr.template.templateSpans.map((s) => getExprTaint(s.expression, env, ctx))
      : [];
    return mergeTaint(tag, mergeAll(parts));
  }

  if (ts.isBinaryExpression(expr)) {
    if (expr.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const t = getExprTaint(expr.right, env, ctx);
      if (ts.isIdentifier(expr.left)) {
        const sym = ctx.checker.getSymbolAtLocation(expr.left);
        if (sym) {
          if (t) env.set(sym, t);
          else env.delete(sym);
        }
      }
      return t;
    }
    return mergeTaint(getExprTaint(expr.left, env, ctx), getExprTaint(expr.right, env, ctx));
  }

  if (
    ts.isParenthesizedExpression(expr) ||
    ts.isAsExpression(expr) ||
    ts.isNonNullExpression(expr) ||
    ts.isTypeAssertionExpression(expr) ||
    ts.isAwaitExpression(expr) ||
    ts.isSatisfiesExpression(expr) ||
    ts.isSpreadElement(expr)
  ) {
    return getExprTaint(expr.expression, env, ctx);
  }

  if (ts.isConditionalExpression(expr)) {
    return mergeTaint(getExprTaint(expr.whenTrue, env, ctx), getExprTaint(expr.whenFalse, env, ctx));
  }

  if (ts.isObjectLiteralExpression(expr)) {
    return mergeAll(
      expr.properties.map((p) => {
        if (ts.isPropertyAssignment(p)) return getExprTaint(p.initializer, env, ctx);
        if (ts.isShorthandPropertyAssignment(p)) return getExprTaint(p.name, env, ctx);
        if (ts.isSpreadAssignment(p)) return getExprTaint(p.expression, env, ctx);
        return null;
      }),
    );
  }

  if (ts.isArrayLiteralExpression(expr)) {
    return mergeAll(expr.elements.map((e) => getExprTaint(e, env, ctx)));
  }

  if (ts.isNewExpression(expr)) {
    return mergeAll((expr.arguments ?? []).map((a) => getExprTaint(a, env, ctx)));
  }

  return null;
}

// ---------------------------------------------------------------------------
// call handling: sanitizers, sinks, interprocedural summaries
// ---------------------------------------------------------------------------

interface CalleeInfo {
  simpleName: string | null;
  receiverName: string | null;
  module: string | null;
}

function calleeInfo(call: ts.CallExpression, ctx: Ctx): CalleeInfo {
  const e = call.expression;
  const importMap = ctx.importMaps.get(e.getSourceFile()) ?? new Map<string, string>();
  if (ts.isIdentifier(e)) {
    return { simpleName: e.text, receiverName: null, module: importMap.get(e.text) ?? null };
  }
  if (ts.isPropertyAccessExpression(e)) {
    let obj: ts.Expression = e.expression;
    while (ts.isPropertyAccessExpression(obj)) obj = obj.expression;
    const receiverName = ts.isIdentifier(obj) ? obj.text : null;
    return {
      simpleName: e.name.text,
      receiverName,
      module: receiverName ? importMap.get(receiverName) ?? null : null,
    };
  }
  return { simpleName: null, receiverName: null, module: null };
}

function handleCall(call: ts.CallExpression, env: Env, ctx: Ctx): Taint | null {
  const argTaints = call.arguments.map((a) => getExprTaint(a, env, ctx));
  const callee = calleeInfo(call, ctx);

  // ---- sanitizer ----
  const san = matchSanitizer(callee, ctx.rules.sanitizers);
  if (san) {
    const merged = mergeAll(argTaints);
    if (!merged) return null;
    const neutralized = san.rules === '*' ? ALL_RULES : san.rules;
    for (const r of neutralized) merged.sanitized.add(r);
    return addStep(merged, stepAt(call, ctx, `sanitized by ${callee.simpleName}()`));
  }

  // ---- sink ----
  for (const sink of ctx.rules.sinks) {
    if (matchSink(sink, callee)) checkSink(sink, call, argTaints, ctx);
  }

  // ---- known in-project callee: apply its summary ----
  const decl = resolveCallee(call, ctx);
  if (decl) {
    const sum = ctx.summaries.get(decl);
    if (sum) {
      applyParamSinks(sum, call, argTaints, ctx);
      let result: Taint | null = null;
      for (const i of sum.returnFromParams) {
        const at = argTaints[i];
        if (at) {
          result = mergeTaint(
            result,
            addStep(at, stepAt(call, ctx, `tainted value returned from ${fnName(decl)}()`)),
          );
        }
      }
      return result;
    }
  }

  // ---- unknown callee (library code): propagate receiver + arguments ----
  let recv: Taint | null = null;
  if (ts.isPropertyAccessExpression(call.expression)) {
    recv = getExprTaint(call.expression.expression, env, ctx);
  }
  return mergeAll([recv, ...argTaints]);
}

function matchSanitizer(callee: CalleeInfo, sanitizers: SanitizerRule[]): SanitizerRule | null {
  if (!callee.simpleName) return null;
  for (const s of sanitizers) {
    if (!s.names.includes(callee.simpleName)) continue;
    if (s.modules && !(callee.module && s.modules.includes(callee.module))) continue;
    return s;
  }
  return null;
}

function matchSink(sink: SinkRule, callee: CalleeInfo): boolean {
  if (!callee.simpleName || !sink.names.includes(callee.simpleName)) return false;
  if (sink.modules) return !!callee.module && sink.modules.includes(callee.module);
  if (sink.objectPattern) {
    return !!callee.receiverName && new RegExp(sink.objectPattern, 'i').test(callee.receiverName);
  }
  return true;
}

function checkSink(
  sink: SinkRule,
  call: ts.CallExpression,
  argTaints: (Taint | null)[],
  ctx: Ctx,
): void {
  const taint = argTaints[sink.argIndex];
  if (!taint || taint.sanitized.has(sink.id)) return;
  if (sink.arrayArgNeedsShell && !hasShellTrue(call)) return;

  const loc = locOf(call, ctx.rootDir);
  const sinkStep: Step = { ...loc, message: `sink: ${sink.message}` };
  if (ctx.mode === 'summary') {
    for (const label of taint.labels) {
      ctx.paramSinks.push({
        paramIndex: label,
        ruleId: sink.id,
        message: sink.message,
        sinkFile: loc.file,
        sinkLine: loc.line,
        sinkCol: loc.col,
        steps: [...taint.steps, sinkStep],
      });
    }
  } else if (taint.isSource) {
    ctx.findings.push({
      ruleId: sink.id,
      message: sink.message,
      file: loc.file,
      line: loc.line,
      col: loc.col,
      steps: [...taint.steps, sinkStep],
    });
  }
}

function hasShellTrue(call: ts.CallExpression): boolean {
  const opts = call.arguments[2];
  if (!opts || !ts.isObjectLiteralExpression(opts)) return false;
  for (const p of opts.properties) {
    if (
      ts.isPropertyAssignment(p) &&
      ts.isIdentifier(p.name) &&
      p.name.text === 'shell' &&
      p.initializer.kind === ts.SyntaxKind.TrueKeyword
    ) {
      return true;
    }
  }
  return false;
}

function applyParamSinks(
  sum: Summary,
  call: ts.CallExpression,
  argTaints: (Taint | null)[],
  ctx: Ctx,
): void {
  for (const ps of sum.paramSinks) {
    const at = argTaints[ps.paramIndex];
    if (!at || at.sanitized.has(ps.ruleId)) continue;
    const callStep = stepAt(
      call,
      ctx,
      `tainted value passed as argument ${ps.paramIndex + 1} of ${call.expression.getText()}()`,
    );
    const steps = [...at.steps, callStep, ...ps.steps].slice(0, MAX_STEPS);
    if (ctx.mode === 'summary') {
      for (const label of at.labels) {
        ctx.paramSinks.push({ ...ps, paramIndex: label, steps });
      }
    } else if (at.isSource) {
      ctx.findings.push({
        ruleId: ps.ruleId,
        message: ps.message,
        file: ps.sinkFile,
        line: ps.sinkLine,
        col: ps.sinkCol,
        steps,
      });
    }
  }
}

function resolveCallee(call: ts.CallExpression, ctx: Ctx): ts.FunctionLikeDeclaration | null {
  const e = call.expression;
  if (!ts.isIdentifier(e) && !ts.isPropertyAccessExpression(e)) return null;
  let sym = ctx.checker.getSymbolAtLocation(e);
  if (!sym) return null;
  if (sym.flags & ts.SymbolFlags.Alias) sym = ctx.checker.getAliasedSymbol(sym);
  for (const d of sym.getDeclarations() ?? []) {
    const fn = declToFn(d);
    if (fn && fn.body && !fn.getSourceFile().isDeclarationFile) return fn;
  }
  return null;
}

function declToFn(d: ts.Declaration): ts.FunctionLikeDeclaration | null {
  if (isFunctionWithBody(d)) return d;
  if (ts.isVariableDeclaration(d) && d.initializer && isFunctionWithBody(d.initializer)) {
    return d.initializer;
  }
  return null;
}

/** Function-like nodes that can have a body (excludes signature-only declarations). */
function isFunctionWithBody(n: ts.Node): n is ts.FunctionLikeDeclaration {
  return (
    ts.isFunctionDeclaration(n) ||
    ts.isFunctionExpression(n) ||
    ts.isArrowFunction(n) ||
    ts.isMethodDeclaration(n) ||
    ts.isConstructorDeclaration(n) ||
    ts.isGetAccessorDeclaration(n) ||
    ts.isSetAccessorDeclaration(n)
  );
}

// ---------------------------------------------------------------------------
// taint values
// ---------------------------------------------------------------------------

function makeSource(what: string, node: ts.Node, ctx: Ctx): Taint {
  return {
    steps: [{ ...locOf(node, ctx.rootDir), message: `source: ${what} (user-controlled request data)` }],
    sanitized: new Set(),
    labels: new Set(),
    isSource: true,
  };
}

function mergeTaint(a: Taint | null, b: Taint | null): Taint | null {
  if (!a) return b;
  if (!b) return a;
  const steps = [...a.steps];
  for (const s of b.steps) {
    if (steps.length >= MAX_STEPS) break;
    if (!steps.some((x) => x.file === s.file && x.line === s.line && x.message === s.message)) {
      steps.push(s);
    }
  }
  return {
    steps,
    sanitized: new Set([...a.sanitized].filter((r) => b.sanitized.has(r))),
    labels: new Set([...a.labels, ...b.labels]),
    isSource: a.isSource || b.isSource,
  };
}

function mergeAll(ts: (Taint | null)[]): Taint | null {
  return ts.reduce<Taint | null>((acc, t) => mergeTaint(acc, t), null);
}

function addStep(t: Taint, step: Step): Taint {
  if (t.steps.length >= MAX_STEPS) return t;
  return { ...t, steps: [...t.steps, step] };
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function locOf(node: ts.Node, rootDir: string): { file: string; line: number; col: number } {
  const sf = node.getSourceFile();
  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart());
  return {
    file: path.relative(rootDir, sf.fileName).split(path.sep).join('/'),
    line: line + 1,
    col: character + 1,
  };
}

function stepAt(node: ts.Node, ctx: Ctx, message: string): Step {
  return { ...locOf(node, ctx.rootDir), message };
}

function fnName(fn: ts.FunctionLikeDeclaration): string {
  return fn.name && ts.isIdentifier(fn.name) ? fn.name.text : '(anonymous)';
}

function buildImportMap(sf: ts.SourceFile): Map<string, string> {
  const m = new Map<string, string>();
  for (const st of sf.statements) {
    if (ts.isImportDeclaration(st) && ts.isStringLiteral(st.moduleSpecifier)) {
      const mod = st.moduleSpecifier.text;
      const c = st.importClause;
      if (!c) continue;
      if (c.name) m.set(c.name.text, mod);
      if (c.namedBindings) {
        if (ts.isNamespaceImport(c.namedBindings)) {
          m.set(c.namedBindings.name.text, mod);
        } else {
          for (const el of c.namedBindings.elements) m.set(el.name.text, mod);
        }
      }
    }
    if (ts.isVariableStatement(st)) {
      for (const d of st.declarationList.declarations) {
        if (
          ts.isIdentifier(d.name) &&
          d.initializer &&
          ts.isCallExpression(d.initializer) &&
          ts.isIdentifier(d.initializer.expression) &&
          d.initializer.expression.text === 'require' &&
          d.initializer.arguments.length > 0 &&
          ts.isStringLiteral(d.initializer.arguments[0])
        ) {
          m.set(d.name.text, d.initializer.arguments[0].text);
        }
      }
    }
  }
  return m;
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Map<string, Finding>();
  for (const f of findings) {
    // include the source step in the key: two different sources reaching the
    // same sink are two distinct findings, not duplicates
    const src = f.steps[0];
    const key = `${f.ruleId}|${f.file}|${f.line}|${f.col}|${src ? `${src.file}:${src.line}` : ''}`;
    if (!seen.has(key)) seen.set(key, f);
  }
  return [...seen.values()].sort(
    (a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.ruleId.localeCompare(b.ruleId),
  );
}
