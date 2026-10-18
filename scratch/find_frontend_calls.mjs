import fs from 'fs';
import path from 'path';

function findInDir(dir, pattern) {
  const matches = [];
  function walk(d) {
    for (const f of fs.readdirSync(d)) {
      if (f === 'node_modules' || f === '.git' || f === 'dist') continue;
      const full = path.join(d, f);
      const stat = fs.statSync(full);
      if (stat.isDirectory()) {
        walk(full);
      } else if (/\.(jsx?|tsx?)$/.test(f)) {
        const text = fs.readFileSync(full, 'utf8');
        const lines = text.split('\n');
        lines.forEach((l, i) => {
          if (pattern.test(l)) {
            matches.push({ file: full.replace(/\\/g, '/'), lineNum: i + 1, line: l.trim() });
          }
        });
      }
    }
  }
  walk(dir);
  return matches;
}

const alerts = findInDir('frontend/src', /(getAlerts|getUnreadCount|markRead|markAllRead|\/api\/alerts)/);
console.log('--- Frontend alerts calls ---');
alerts.forEach(m => console.log(`${m.file}:${m.lineNum} -> ${m.line}`));

const audit = findInDir('frontend/src', /(getAudit|\/api\/audit)/);
console.log('--- Frontend audit calls ---');
audit.forEach(m => console.log(`${m.file}:${m.lineNum} -> ${m.line}`));

const hp = findInDir('frontend/src', /(getHoneypot|\/api\/honeypot)/);
console.log('--- Frontend honeypot calls ---');
hp.forEach(m => console.log(`${m.file}:${m.lineNum} -> ${m.line}`));
