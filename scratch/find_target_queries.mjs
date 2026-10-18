import fs from 'fs';
import path from 'path';

function findInDir(dir, pattern) {
  const matches = [];
  function walk(d) {
    for (const f of fs.readdirSync(d)) {
      if (f === 'node_modules' || f === '.git') continue;
      const full = path.join(d, f);
      const stat = fs.statSync(full);
      if (stat.isDirectory()) {
        walk(full);
      } else if (/\.(js|json|md)$/.test(f)) {
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

const targets = findInDir('backend', /target\.id/i);
console.log('--- target.id occurrences in backend ---');
targets.forEach(m => console.log(`${m.file}:${m.lineNum} -> ${m.line}`));

const targetIdents = findInDir('backend', /target\.identifier/i);
console.log('--- target.identifier occurrences in backend ---');
targetIdents.forEach(m => console.log(`${m.file}:${m.lineNum} -> ${m.line}`));
