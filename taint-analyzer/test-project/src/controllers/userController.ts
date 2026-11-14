import { runQuery, runParameterized } from '../utils/db';
import { whereEquals, orderBy } from '../utils/format';
import { escapeSql } from '../utils/sanitize';

// VULNERABLE: req.query.id is concatenated into SQL, sink is cross-file in utils/db.ts
export function getUser(req: any, res: any) {
  const id = req.query.id;
  runQuery('SELECT * FROM users WHERE id = ' + id).then((rows: any) => res.json(rows));
}

// SAFE: parameterized query — the tainted value never enters the SQL string
export function listUsers(req: any, res: any) {
  const name = req.query.name;
  runParameterized('SELECT * FROM users WHERE name = ?', [name]).then((rows: any) => res.json(rows));
}

// VULNERABLE: taint flows through the return values of whereEquals/orderBy
export function searchUsers(req: any, res: any) {
  const clause = whereEquals('name', req.body.name);
  const sort = orderBy(req.query.sort);
  runQuery('SELECT * FROM users WHERE ' + clause + sort).then((rows: any) => res.json(rows));
}

// SAFE: escaped with the project-specific escapeSql (registered in taint-rules.json)
export function getUserByName(req: any, res: any) {
  const name = escapeSql(req.query.name);
  runQuery("SELECT * FROM users WHERE name = '" + name + "'").then((rows: any) => res.json(rows));
}

// SAFE: parseInt coerces to a number, no injection payload can survive
export function getUserByAge(req: any, res: any) {
  const age = parseInt(req.query.age, 10);
  runQuery('SELECT * FROM users WHERE age = ' + age).then((rows: any) => res.json(rows));
}
