import { exec, execSync, spawn } from 'child_process';

// VULNERABLE: req.query.host is concatenated into a shell command
export function pingHost(req: any, res: any) {
  const host = req.query.host;
  exec('ping -c 1 ' + host, (err: any, out: string) => res.send(out));
}

// VULNERABLE: req.query.extra reaches execSync through the runShell helper
export function reloadNginx(req: any, res: any) {
  runShell('nginx -s reload ' + req.query.extra);
  res.send('ok');
}

function runShell(cmd: string) {
  execSync(cmd);
}

// SAFE: fixed argument vector without a shell — metacharacters are not interpreted
export function restartService(req: any, res: any) {
  const svc = req.body.service;
  spawn('systemctl', ['restart', svc]);
  res.send('ok');
}

// SAFE: encodeURIComponent percent-encodes every shell metacharacter
export function listLogs(req: any, res: any) {
  const unit = encodeURIComponent(req.query.unit);
  exec('journalctl -u ' + unit, (err: any, out: string) => res.send(out));
}
