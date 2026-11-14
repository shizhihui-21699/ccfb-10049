// Thin wrapper around the connection pool. The actual sinks live here;
// taint arrives through the `sql` parameter from controllers in other files.
declare const pool: { query(sql: string, values?: unknown[]): Promise<any> };

export function runQuery(sql: string) {
  return pool.query(sql);
}

export function runParameterized(sql: string, values: unknown[]) {
  return pool.query(sql, values);
}
