import * as fs from 'fs';

export function loadTemplate(name: string): string {
  return fs.readFileSync('templates/' + name, 'utf8');
}
