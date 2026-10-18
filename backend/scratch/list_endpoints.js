process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'unit-test-jwt-secret-role-matrix';
process.env.JWT_REFRESH_SECRET = 'unit-test-refresh-secret-role-matrix';
const { app } = require('../server');

const routerMap = new Map([
  [require('../routes/auth'), '/api/auth'],
  [require('../routes/threats'), '/api/threats'],
  [require('../routes/containment'), '/api/containment'],
  [require('../routes/honeypotIngest'), '/api/honeypot/ingest'],
  [require('../routes/honeypot'), '/api/honeypot'],
  [require('../routes/campaigns'), '/api/campaigns'],
  [require('../routes/alerts'), '/api/alerts'],
  [require('../routes/users'), '/api/users'],
  [require('../routes/aiEngine'), '/api/ai'],
  [require('../routes/trainingSamples'), '/api/training-samples'],
  [require('../routes/systemOutbox'), '/api/system/outbox'],
  [require('../routes/audit'), '/api/audit']
]);

const endpoints = [];

for (const layer of app.router.stack) {
  if (layer.route) {
    const methods = Object.keys(layer.route.methods);
    for (const m of methods) {
      endpoints.push({
        method: m.toUpperCase(),
        path: layer.route.path
      });
    }
  } else if (layer.handle && routerMap.has(layer.handle)) {
    const prefix = routerMap.get(layer.handle);
    for (const sub of layer.handle.stack) {
      if (sub.route) {
        const methods = Object.keys(sub.route.methods);
        for (const m of methods) {
          const subPath = sub.route.path === '/' ? '' : sub.route.path;
          endpoints.push({
            method: m.toUpperCase(),
            path: `${prefix}${subPath}`
          });
        }
      }
    }
  }
}

console.log('Total verified endpoints:', endpoints.length);
endpoints.forEach((ep, i) => console.log(`${String(i + 1).padStart(2, ' ')}. ${ep.method.padEnd(6)} ${ep.path}`));
process.exit(0);
