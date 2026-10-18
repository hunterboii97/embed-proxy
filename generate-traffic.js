// Generate traffic to populate the dashboard
const http = require('http');

const PORT = 5001;
const WORKER_URL = `http://127.0.0.1:${PORT}`;

console.log('Generating traffic to populate dashboard...\n');

const endpoints = [
  '/docs',
  '/health',
  '/api/info',
  '/embed/zoko/mal/21/1/sub',
  '/player/zoko?mal=21&ep=1&lang=sub'
];

let requestCount = 0;
let successCount = 0;

function makeRequest(endpoint) {
  return new Promise((resolve) => {
    const url = `${WORKER_URL}${endpoint}`;
    http.get(url, (res) => {
      requestCount++;
      if (res.statusCode === 200 || res.statusCode === 404) {
        successCount++;
      }
      console.log(`   ${res.statusCode} - ${endpoint}`);
      resolve();
    }).on('error', (err) => {
      console.log(`   ❌ ${endpoint}: ${err.message}`);
      resolve();
    });
  });
}

async function generateTraffic() {
  console.log('Making requests to generate data...\n');

  // Make 20 requests to each endpoint
  for (let i = 0; i < 20; i++) {
    for (const endpoint of endpoints) {
      await makeRequest(endpoint);
      // Small delay to avoid overwhelming
      await new Promise(r => setTimeout(r, 50));
    }
  }

  console.log(`\n✅ Generated ${requestCount} requests (${successCount} successful)`);
  console.log('\nWait 30 seconds for the dashboard to update.');
  console.log('Then refresh: http://127.0.0.1:5100/admin');
}

generateTraffic().catch(console.error);
