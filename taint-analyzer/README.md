# ts-taint-analyzer

基于 TypeScript Compiler API 的 Node 服务静态污点分析工具。把 `req.query` / `req.body` / `req.headers` 等用户输入作为 source,追踪到 SQL 拼接、`child_process`、文件路径等 sink,支持**跨函数、跨文件**的参数与返回值传播,识别常见清洗函数并断开污点,结果输出 **SARIF 2.1.0**,在 VS Code 里装 SARIF Viewer 插件即可点击每一步跳转到对应文件和行号。

## 使用

```bash
npm install
npm run build

# 分析一个项目(默认输出 <项目>/taint-results.sarif)
node bin/ts-taint.js /path/to/your-service --out results.sarif

# 跑端到端测试(分析自带 test-project 并断言结果)
npm test
```

退出码:有发现时为 1,可直接接 CI。

VS Code:安装 **SARIF Viewer** 扩展,打开生成的 `.sarif` 文件,每个 finding 的 code flow 里每一步(source → 赋值 → 函数参数 → 返回值 → sink)都可点击跳转。

## 工作原理

两遍分析,均基于 `ts.Program` + `ts.TypeChecker`:

1. **摘要阶段(不动点迭代)**:每个函数的参数被符号化标记("label"),分析函数体得到摘要 —
   - 哪些参数会污染返回值(`returnFromParams`);
   - 哪些参数会流进 sink(`paramSinks`,含函数内部从参数到 sink 的完整步骤)。
   迭代至所有摘要收敛(上限 10 轮,兼容递归/互递归)。
2. **入口阶段**:第一个参数名为 `req`/`request` 的函数视为 express 风格 handler,把 `req.query/body/headers/params/cookies` 标记为污染源进行分析。被污染的实参传给项目内函数时,用被调方摘要接续传播,拼出跨文件完整路径。

其他要点:

- 未知函数(库代码)保守处理:返回值继承 receiver 和实参的污点(所以 `path.join(dir, tainted)` 仍被污染)。
- 污点携带 `sanitized` 集合:清洗函数按规则中和(如 `escapeSql` 只中和 sql-injection,不影响 path-traversal 判定)。
- 同名 sink 位置 + 同一 source 才去重;不同 source 到同一 sink 是两条独立 finding。

## 规则表

规则表在 `src/rules.ts`,纯数据,分三类:

```ts
{
  sources: { reqNames: ['req', 'request'], props: ['query', 'body', 'headers', 'params', 'cookies'] },
  sinks: [
    {
      id: 'sql-injection' | 'command-injection' | 'path-traversal',
      names: ['query', 'execute'],            // 被调函数名
      modules: ['child_process'],             // 可选:必须 import 自这些模块
      objectPattern: '^(db|pool|...)$',       // 可选:receiver 名字正则
      argIndex: 0,                            // 哪个参数不能被污染
      arrayArgNeedsShell: true,               // 可选:spawn 类,仅 shell:true 时报
      message: '...',
    },
  ],
  sanitizers: [
    { names: ['parseInt', 'Number'], rules: '*' },                 // 中和所有规则
    { names: ['basename'], modules: ['path'], rules: ['path-traversal'] },
  ],
}
```

默认规则摘要:

| 规则 | source | sink | 默认清洗 |
|---|---|---|---|
| `sql-injection` | `req.*` | `db/pool/conn/client/sequelize/knex.query|execute|raw` 第一个参数 | `parseInt/parseFloat/Number`、`encodeURIComponent`、mysql/sqlstring 的 `escape/escapeId` |
| `command-injection` | `req.*` | `child_process.exec/execSync` 命令串;`spawn/execFile` 的命令本身,或 `shell: true` 时的参数数组 | 数字转换、`encodeURIComponent` |
| `path-traversal` | `req.*` | `fs.readFileSync/writeFileSync/createReadStream/...`、`res.sendFile` 的路径参数 | 数字转换、`encodeURIComponent`、`path.basename` |

### 项目级扩展:`taint-rules.json`

被分析项目根目录可放 `taint-rules.json` 追加规则(典型用途:登记项目自己的清洗函数):

```json
{
  "sanitizers": [
    { "names": ["escapeSql"], "rules": ["sql-injection"] }
  ],
  "extraSinks": [],
  "sourceProps": []
}
```

## 测试项目

`test-project/` 是一个 express 风格的样例服务,包含 6 个真问题和 6 个"看着危险其实安全"的写法:

| 位置 | 情况 | 期望 |
|---|---|---|
| `userController.getUser` | `req.query.id` 拼 SQL,经 `utils/db.ts` 的 `runQuery` 跨文件进 `pool.query` | 报 |
| `userController.searchUsers` | 污点经 `whereEquals`/`orderBy` 的**返回值**带回再拼 SQL | 报 |
| `userController.listUsers` | 参数化查询 `?` 占位 | 不报 |
| `userController.getUserByName` | 项目自定义 `escapeSql` 清洗(taint-rules.json 登记) | 不报 |
| `userController.getUserByAge` | `parseInt` 清洗 | 不报 |
| `fileController.download` | `req.query.file` 经 `path.join` 进 `res.sendFile` | 报 |
| `fileController.readTemplateFile` | 经 `utils/templates.ts` 的 `loadTemplate` 跨文件进 `fs.readFileSync` | 报 |
| `fileController.upload` | `path.basename` 清洗 | 不报 |
| `systemController.pingHost` | `req.query.host` 拼进 `exec` | 报 |
| `systemController.reloadNginx` | 经本文件 `runShell` 进 `execSync` | 报 |
| `systemController.restartService` | `spawn` 参数数组、无 `shell: true` | 不报 |
| `systemController.listLogs` | `encodeURIComponent` 清洗 | 不报 |

`npm test` 会精确断言 finding 集合(ruleId + sink 位置 + source 位置)、无漏报无误报、每条路径步骤齐全且跨文件、SARIF 结构合法。

## 已知限制

- 闭包捕获:嵌套函数单独分析,不继承外层被污染的局部变量。
- 不做路径敏感分析:`if (/^\d+$/.test(x))` 这类正则守卫不会断开污点(建议改成显式清洗函数并登记进规则)。
- 对象属性流是粗粒度的:对象任一属性被污染,整个对象视为被污染。
- handler 识别基于命名约定(首参数 `req`/`request`),非常规命名需要调整 `rules.sources.reqNames`。
