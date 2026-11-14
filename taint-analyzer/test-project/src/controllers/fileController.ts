import * as fs from 'fs';
import * as path from 'path';
import { loadTemplate } from '../utils/templates';

// VULNERABLE: req.query.file flows into res.sendFile via path.join
export function download(req: any, res: any) {
  const name = req.query.file;
  const full = path.join(__dirname, 'files', name);
  res.sendFile(full);
}

// VULNERABLE: req.query.tpl flows cross-file into fs.readFileSync
export function readTemplateFile(req: any, res: any) {
  const content = loadTemplate(req.query.tpl);
  res.send(content);
}

// SAFE: path.basename strips any directory components (../../etc/passwd -> passwd)
export function upload(req: any, res: any) {
  const name = path.basename(req.body.filename);
  fs.writeFileSync(path.join(__dirname, 'uploads', name), req.body.data);
  res.send('ok');
}
