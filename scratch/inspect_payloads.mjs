import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const mongoose = require('../backend/node_modules/mongoose');

async function inspectCommandPayloads() {
  await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');
  const db = mongoose.connection.db;

  const sessions = await db.collection('honeypotsessions').find({}).toArray();
  console.log(`=== HONEYPOT SESSIONS (${sessions.length} total) ===`);
  let totalCommands = 0;
  let totalUrls = 0;
  let totalMalware = 0;
  sessions.forEach(s => {
    const cmds = s.commands || [];
    const urls = s.iocExtracted?.urls || [];
    const mal = s.malwareDownloaded || [];
    totalCommands += cmds.length;
    totalUrls += urls.length;
    totalMalware += mal.length;
    console.log(`Session ${s.sessionId}: ${cmds.length} commands, ${urls.length} URLs, ${mal.length} malware URLs`);
    // Sample first 2 commands if any
    if (cmds.length > 0) {
      console.log(`  Sample command: ${cmds[0].command} | output: ${cmds[0].output?.slice(0, 50)}...`);
    }
  });
  console.log(`Total Commands stored: ${totalCommands}`);
  console.log(`Total URLs stored: ${totalUrls}`);

  const threats = await db.collection('threatlogs').find({}).toArray();
  console.log(`\n=== THREAT LOGS (${threats.length} total) ===`);
  threats.forEach(t => {
    console.log(`Threat ${t._id}: sourceIP=${t.sourceIP}, attackType=${t.attackType}, rawPayload=${t.rawPayload ? '[PRESENT]' : '[NONE]'}`);
  });

  await mongoose.disconnect();
}

inspectCommandPayloads().catch(console.error);
