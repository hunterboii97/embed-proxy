'use strict';

const fs = require('node:fs');
const os = require('node:os');
const http = require('node:http');
const https = require('node:https');

function readSwapMB() {
  try {
    const text = fs.readFileSync('/proc/meminfo', 'utf8');
    const total = Number((text.match(/^SwapTotal:\s+(\d+)/m) || [])[1]) || 0;
    const free = Number((text.match(/^SwapFree:\s+(\d+)/m) || [])[1]) || 0;
    return Math.max(0, Math.round((total - free) / 1024));
  } catch {
    return 0;
  }
}

function readNetBytes() {
  try {
    const text = fs.readFileSync('/proc/net/dev', 'utf8');
    let rx = 0;
    let tx = 0;
    for (const line of text.split('\n')) {
      const colon = line.indexOf(':');
      if (colon === -1) continue;
      const name = line.slice(0, colon).trim();
      if (!name || name === 'lo') continue;
      const parts = line.slice(colon + 1).trim().split(/\s+/);
      rx += Number(parts[0]) || 0;
      tx += Number(parts[8]) || 0;
    }
    return { rx, tx };
  } catch {
    return null;
  }
}

function readDisk(path) {
  try {
    const stat = fs.statfsSync(path);
    const total = Number(stat.blocks) * Number(stat.bsize);
    const free = Number(stat.bavail) * Number(stat.bsize);
    return {
      totalGB: total / 1024 ** 3,
      usedGB: Math.max(0, (total - free) / 1024 ** 3)
    };
  } catch {
    return { totalGB: 0, usedGB: 0 };
  }
}

function cpuSnapshot() {
  const cpus = os.cpus();
  let idle = 0;
  let total = 0;
  for (const cpu of cpus) {
    const t = cpu.times;
    idle += t.idle;
    total += t.user + t.nice + t.sys + t.idle + t.irq;
  }
  return { idle, total };
}

function nginxStatus(url, timeoutMs = 1500) {
  return new Promise((resolve) => {
    if (!url) return resolve(null);
    let parsed;
    try { parsed = new URL(url); } catch { return resolve(null); }
    const lib = parsed.protocol === 'https:' ? https : http;
    const req = lib.get(parsed, { timeout: timeoutMs }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        if (body.length < 4096) body += chunk;
      });
      res.on('end', () => {
        const active = Number((body.match(/Active connections:\s*(\d+)/) || [])[1]);
        const numbers = (body.match(/^\s+(\d+)\s+(\d+)\s+(\d+)\s*$/m) || []).slice(1).map(Number);
        resolve({
          active: Number.isFinite(active) ? active : null,
          requests: numbers.length === 3 ? numbers[2] : null
        });
      });
    });
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.on('error', () => resolve(null));
  });
}

function createSystemSampler({ config, store, logger, workersSummary }) {
  let timer = null;
  let lastCpu = cpuSnapshot();
  let lastCpuAt = Date.now();
  let lastNet = readNetBytes();
  let lastNetAt = Date.now();
  let nginxPrev = null;
  let nginxPrevAt = 0;
  let last = null;
  let running = false;

  async function sample() {
    if (!running) return;
    const now = Date.now();
    const cpu = cpuSnapshot();
    const elapsed = now - lastCpuAt;
    const totalDelta = cpu.total - lastCpu.total;
    const idleDelta = cpu.idle - lastCpu.idle;
    const cpuPct = totalDelta > 0
      ? Math.min(100, Math.max(0, (1 - idleDelta / totalDelta) * 100))
      : 0;
    lastCpu = cpu;
    lastCpuAt = now;

    const net = readNetBytes();
    let netRxBps = 0;
    let netTxBps = 0;
    if (net && lastNet) {
      const seconds = Math.max(0.5, (now - lastNetAt) / 1000);
      netRxBps = Math.max(0, (net.rx - lastNet.rx) / seconds);
      netTxBps = Math.max(0, (net.tx - lastNet.tx) / seconds);
    }
    lastNet = net;
    lastNetAt = now;

    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const disk = readDisk(config.dataDir);
    const workers = typeof workersSummary === 'function' ? workersSummary() : { online: 0, rssMB: 0 };

    const status = await nginxStatus(config.nginxStatusUrl);
    let nginxRps = null;
    if (status && status.requests != null) {
      if (nginxPrev != null && now > nginxPrevAt) {
        nginxRps = Math.max(0, (status.requests - nginxPrev.requests) / ((now - nginxPrevAt) / 1000));
      }
      nginxPrev = status;
      nginxPrevAt = now;
    }

    const sample = {
      ts: now,
      cpuPct: Math.round(cpuPct * 10) / 10,
      load1: os.loadavg()[0],
      load5: os.loadavg()[1],
      load15: os.loadavg()[2],
      memUsedMB: Math.round((totalMem - freeMem) / 1024 / 1024),
      memTotalMB: Math.round(totalMem / 1024 / 1024),
      swapUsedMB: readSwapMB(),
      diskUsedGB: Math.round(disk.usedGB * 10) / 10,
      diskTotalGB: Math.round(disk.totalGB * 10) / 10,
      netRxBps: Math.round(netRxBps),
      netTxBps: Math.round(netTxBps),
      nginxActive: status ? status.active : null,
      nginxRps: nginxRps == null ? null : Math.round(nginxRps * 10) / 10,
      workersOnline: workers.online || 0,
      workerRssMB: workers.rssMB || 0
    };

    try {
      store.insertSystemSample(sample);
      last = sample;
      if (status) last.nginxActive = status.active;
    } catch (error) {
      logger(`[system] sample failed: ${error.message}`, 'error');
    }
  }

  function start() {
    if (running) return;
    running = true;
    lastCpu = cpuSnapshot();
    lastCpuAt = Date.now();
    lastNet = readNetBytes();
    lastNetAt = Date.now();
    sample().catch(() => {});
    timer = setInterval(() => sample().catch(() => {}), config.snapshotMs);
    timer.unref();
  }

  function stop() {
    running = false;
    if (timer) clearInterval(timer);
  }

  return {
    start,
    stop,
    sample,
    latest: () => last
  };
}

module.exports = { createSystemSampler };
