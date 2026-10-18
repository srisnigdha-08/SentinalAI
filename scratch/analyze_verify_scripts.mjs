import fs from 'fs';

const files = [
  'scratch/verify_browser_rbac.mjs',
  'scratch/verify_ui_controls.mjs',
  'scratch/verify_viewer_audit.mjs',
  'scratch/verify_analyst_feed.mjs',
  'scratch/verify_live_demotion.mjs'
];

for (const f of files) {
  const content = fs.readFileSync(f, 'utf8');
  console.log('=== ' + f + ' ===');
  
  // Routes visited (e.g. goto, /dashboard, etc.)
  const routeRegex = /(?:goto|fetch|get|post)\(['"`]((?:http:\/\/localhost:\d+)?\/[^'"`?]*)['"`]/gi;
  const routes = new Set();
  let m;
  while ((m = routeRegex.exec(content)) !== null) {
    let r = m[1].replace(/http:\/\/localhost:\d+/, '');
    routes.add(r);
  }
  // Also check template literals ${baseUrl}/...
  const tmplRegex = /`\$\{baseUrl\}(\/[^`]*)`/g;
  while ((m = tmplRegex.exec(content)) !== null) {
    routes.add(m[1]);
  }
  console.log('Routes:', Array.from(routes));

  // WebSocket events
  const wsEvents = new Set();
  const wsRegex = /(?:\.on|\.emit|\.subscribe)\(['"`]([a-zA-Z0-9_:-]+)['"`]/g;
  while ((m = wsRegex.exec(content)) !== null) {
    if (!['error', 'connect', 'disconnect', 'message', 'data', 'close'].includes(m[1])) {
      wsEvents.add(m[1]);
    }
  }
  console.log('WS Events:', Array.from(wsEvents));

  // Audit actions
  const auditActions = new Set();
  const actRegex = /(?:action|Action)(?:\s*:|\s*===|\s*==|\.includes\()\s*['"`]([A-Z0-9_]+)['"`]/g;
  while ((m = actRegex.exec(content)) !== null) {
    auditActions.add(m[1]);
  }
  console.log('Audit Actions:', Array.from(auditActions));
  console.log();
}
