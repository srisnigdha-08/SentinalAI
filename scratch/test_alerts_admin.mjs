import mongoose from '../backend/node_modules/mongoose/index.js';
import { findAlerts, getUnreadCount } from '../backend/services/alertService.js';

await mongoose.connect('mongodb://127.0.0.1:27017/sentinel-db');

console.log('=== TESTING ALERTS API QUERY (ADMIN ROLE) ===');
const unread = await getUnreadCount('admin');
console.log('Unread count for admin:', unread);

const res = await findAlerts({ role: 'admin', page: 1, limit: 10 });
console.log('Total alerts returned:', res.total);
for (const a of res.data) {
  console.log(`Alert ID: ${a._id} | Title: "${a.title}" | sourceRef: ${JSON.stringify(a.sourceRef)} | expiresAt: ${a.expiresAt}`);
}

await mongoose.disconnect();
