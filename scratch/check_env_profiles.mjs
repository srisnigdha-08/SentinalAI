import fs from 'fs';

const files = [
  'backend/.env',
  'backend/.env.example',
  'deployment/.env.demo',
  'deployment/.env.demo.example',
  'deployment/.env.production',
  'deployment/.env.example',
  'deployment/.env'
];

console.log('=== PART 8: DEPLOYMENT PROFILES AUDIT ===\n');

for (const file of files) {
  if (!fs.existsSync(file)) continue;
  console.log(`--- Profile / File: ${file} ---`);
  const content = fs.readFileSync(file, 'utf8');
  const lines = content.split('\n');
  for (let line of lines) {
    line = line.trim();
    if (!line || line.startsWith('#')) continue;
    const idx = line.indexOf('=');
    if (idx === -1) continue;
    const key = line.substring(0, idx).trim();
    const val = line.substring(idx + 1).trim();
    if (key.includes('URI') || key.includes('MONGO') || key === 'PORT' || key === 'HOST' || key === 'NODE_ENV') {
      if (val.startsWith('mongodb://') || val.startsWith('mongodb+srv://')) {
        try {
          const u = new URL(val);
          console.log(`  ${key}: protocol=${u.protocol} host=${u.hostname} port=${u.port || 27017} db=${u.pathname.replace(/^\//, '')} authEnabled=${Boolean(u.username || u.password)}`);
        } catch {
          console.log(`  ${key}: [unparseable URI]`);
        }
      } else {
        console.log(`  ${key}: ${val}`);
      }
    }
  }
  console.log('');
}
