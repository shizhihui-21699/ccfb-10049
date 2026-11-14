// String builders whose return values carry the taint of their arguments.
export function whereEquals(column: string, value: string): string {
  return column + " = '" + value + "'";
}

export function orderBy(column: string): string {
  return ' ORDER BY ' + column;
}
