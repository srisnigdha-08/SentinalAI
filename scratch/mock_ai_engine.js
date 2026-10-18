const http = require('http');

const server = http.createServer((req, res) => {
  res.setHeader('Content-Type', 'application/json');
  if (req.url === '/ready') {
    res.writeHead(200);
    res.end(JSON.stringify({ status: 'ok' }));
  } else if (req.url === '/model/info') {
    res.writeHead(200);
    res.end(JSON.stringify({ status: 'ok', model: 'SentinelAI-Ensemble', version: '2.4', accuracy: 0.96 }));
  } else if (req.url === '/model/stats') {
    res.writeHead(200);
    res.end(JSON.stringify({ status: 'ok', predictionsTotal: 100 }));
  } else {
    res.writeHead(200);
    res.end(JSON.stringify({ status: 'ok' }));
  }
});

server.listen(8000, '127.0.0.1', () => {
  console.log('Mock AI Engine listening on http://127.0.0.1:8000');
});
