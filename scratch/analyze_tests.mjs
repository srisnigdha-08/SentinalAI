import fs from 'fs';
import path from 'path';

const testsDir = path.resolve('backend/tests');
const files = fs.readdirSync(testsDir).filter(f => f.endsWith('.test.js'));

console.log('=== CHECK 12: EXISTING TESTS & DATABASE LAYER AUDIT ===\n');
console.log(`Found ${files.length} test files in backend/tests/.\n`);

const results = [];
for (const file of files) {
  const content = fs.readFileSync(path.join(testsDir, file), 'utf8');
  const touchesMongoose = /mongoose/i.test(content);
  const mocksDb = /jest\.mock\(['\"].*db['\"]\)|jest\.mock\(['\"].*models\//i.test(content);
  const connectsRealMongo = /mongoose\.connect|new MongoClient/i.test(content);
  const usesInMemory = /MongoMemoryServer|mongodb-memory-server|authMemoryStore/i.test(content);
  const modifiesData = /create\(|\.save\(|insertMany|updateOne|deleteOne|deleteMany/i.test(content);

  let category = 'UNIT_MOCK (No DB)';
  if (connectsRealMongo && !usesInMemory) {
    category = 'REAL_DB_INTEGRATION';
  } else if (usesInMemory) {
    category = 'IN_MEMORY_DB';
  } else if (touchesMongoose && mocksDb) {
    category = 'MOCKED_MODELS';
  } else if (!touchesMongoose) {
    category = 'PURE_LOGIC (No Mongoose)';
  }

  results.push({
    file,
    category,
    touchesMongoose,
    mocksDb,
    connectsRealMongo,
    usesInMemory
  });
}

const byCategory = {};
results.forEach(r => {
  byCategory[r.category] = (byCategory[r.category] || []).concat(r.file);
});

for (const [cat, list] of Object.entries(byCategory)) {
  console.log(`--- Category: ${cat} (${list.length} files) ---`);
  list.forEach(f => console.log('  • ' + f));
  console.log('');
}
