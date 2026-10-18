// Quick test to verify admin dashboard is working
const http = require('http');

const COLLECTOR_PORT = 5100;
const WORKER_PORT = 5001;

console.log('Testing admin dashboard setup...\n');

// Test 1: Check if collector is running
console.log('1. Checking collector...');
http.get(`http://127.0.0.1:${COLLECTOR_PORT}/admin/api/health`, (res) => {
  if (res.statusCode === 200) {
    console.log('   ✅ Collector is running');
  } else {
    console.log(`   ❌ Collector returned status ${res.statusCode}`);
  }
  testWorker();
}).on('error', (err) => {
  console.log(`   ❌ Collector not accessible: ${err.message}`);
  console.log('   Start the collector with: node admin/collector.js');
  testWorker();
});

function testWorker() {
  console.log('\n2. Checking worker...');
  http.get(`http://127.0.0.1:${WORKER_PORT}/docs`, (res) => {
    if (res.statusCode === 200) {
      console.log('   ✅ Worker is running');
    } else {
      console.log(`   ❌ Worker returned status ${res.statusCode}`);
    }
    testSnapshot();
  }).on('error', (err) => {
    console.log(`   ❌ Worker not accessible: ${err.message}`);
    console.log('   Start the worker with: node app.js');
    testSnapshot();
  });
}

function testSnapshot() {
  console.log('\n3. Checking worker metrics...');
  // This will fail if ADMIN_METRICS is not enabled, which is expected
  console.log('   ℹ️  Worker metrics require ADMIN_METRICS=1 in .env');
  console.log('   ℹ️  Check if snapshots are being sent to collector');

  console.log('\n4. Generating test traffic...');
  http.get(`http://127.0.0.1:${WORKER_PORT}/docs`, (res) => {
    console.log('   ✅ Test request sent to worker');
    console.log('\n5. Dashboard should now show this request after ~30s');
    console.log('   Open: http://127.0.0.1:5100/admin');
  }).on('error', (err) => {
    console.log(`   ❌ Test request failed: ${err.message}`);
  });
}
