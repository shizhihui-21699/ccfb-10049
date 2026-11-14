// Project-specific SQL escaper, registered as a sanitizer for the
// sql-injection rule in taint-rules.json.
export function escapeSql(value: string): string {
  return String(value).replace(/'/g, "''");
}
