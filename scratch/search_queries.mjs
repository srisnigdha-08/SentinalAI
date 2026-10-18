import fs from 'fs';
import path from 'path';

function searchDir(dir, patterns) {
  const results = [];
  function recurse(currentDir) {
    const files = fs.readdirSync(currentDir);
    for (const file of files) {
      const fullPath = path.join(currentDir, file);
      const stat = fs.statSync(fullPath);
      if (stat.isDirectory()) {
        if (file !== 'node_modules' && file !== '.git') {
          recurse(fullPath);
        }
      } else if (/\.(js|mjs|cjs|ts)$/.test(file)) {
        const content = fs.readFileSync(fullPath, 'utf8');
        const lines = content.split('\n');
        lines.forEach((line, idx) => {
          for (const [key, pat] of Object.entries(patterns)) {
            if (pat.test(line)) {
              results.push({ key, file: fullPath.replace(/\\/g, '/'), lineNum: idx + 1, line: line.trim() });
            }
          }
        });
      }
    }
  }
  recurse(dir);
  return results;
}

const patterns = {
  isRead: /isRead/,
  targetRoles: /targetRoles/,
  sourceRef: /sourceRef/,
  linkedThreatLog: /linkedThreatLog/,
  targetId: /target(\.|\['|")id/
};

const matches = searchDir('backend', patterns);
console.log(`Found ${matches.length} occurrences.`);
matches.forEach(m => {
  // filter out node_modules, tests for now to see app code first
  if (!m.file.includes('/tests/')) {
    console.log(`[${m.key}] ${m.file}:${m.lineNum} -> ${m.line}`);
  }
});
