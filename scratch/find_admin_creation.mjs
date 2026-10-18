import fs from 'fs';
import path from 'path';

function searchDirs(dirs) {
  const matches = [];
  function walk(d) {
    for (const f of fs.readdirSync(d)) {
      if (f === 'node_modules' || f === '.git' || f === '.test-runtime' || f === 'dist' || f === '.system_generated') continue;
      const full = path.join(d, f);
      const stat = fs.statSync(full);
      if (stat.isDirectory()) {
        walk(full);
      } else if (/\.(js|mjs|cjs|json|env.*|md|sh|ps1)$/.test(f)) {
        const text = fs.readFileSync(full, 'utf8');
        if (text.includes('admin@sentinel.local')) {
          text.split('\n').forEach((l, i) => {
            if (l.includes('admin@sentinel.local')) {
              matches.push({ file: full.replace(/\\/g, '/'), lineNum: i + 1, line: l.trim() });
            }
          });
        }
      }
    }
  }
  dirs.forEach(walk);
  return matches;
}

const res = searchDirs(['backend', 'deployment', 'scripts', 'docs']);
console.log(`Found ${res.length} matches:`);
res.forEach(m => console.log(`${m.file}:${m.lineNum} -> ${m.line}`));
