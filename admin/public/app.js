'use strict';

/* ============================================================================
 * Mikaza admin dashboard — renders the collector's JSON APIs.
 * Strict CSP: no inline scripts/styles, no external assets. All untrusted
 * values go through textContent (via the h() helper), never innerHTML.
 * Refresh cadence: SSE tick from the collector, 30 s fallback polling.
 * ==========================================================================*/

(function () {
  const AUTO_GAP_MS = 25000;
  const FALLBACK_MS = 15000;
  const LOG_LIMIT = 150;

  const PROVIDER_LABEL = { zoko: 'Naoka', kira: 'Kira', haiku: 'Haiku', other: 'Other' };
  const ROUTE_LABEL = {
    seg: 'Segments',
    playlist: 'Playlists',
    embed: 'Embeds',
    api: 'API',
    docs: 'Docs',
    asset: 'Assets',
    telemetry: 'Telemetry',
    download: 'Downloads',
    other: 'Other'
  };
  const ROW_LABELS = {
    snapshots: 'Worker snapshots',
    edgeMinute: 'Edge minute rollups',
    edgeHour: 'Edge hour rollups',
    edgeDay: 'Edge day rollups',
    viewersMinute: 'Viewer minute rollups',
    viewersDay: 'Viewer day rollups',
    originMinute: 'Origin minute rollups',
    origins: 'Embed origins',
    titles: 'Titles',
    events: 'Log events',
    systemSamples: 'System samples'
  };

  const PAGE_META = {
    overview: { title: 'Overview', subtitle: 'Live traffic, viewers and health', ranges: null },
    traffic: { title: 'Traffic', subtitle: 'Edge requests, bandwidth and cache', ranges: ['1h', '6h', '24h', '7d', '30d'] },
    sites: { title: 'Embed sites', subtitle: 'Where the player is embedded', ranges: ['1h', '6h', '24h', '7d', 'all'] },
    content: { title: 'Content', subtitle: 'Providers, titles and playback quality', ranges: ['1h', '6h', '24h', '7d', '30d'] },
    logs: { title: 'Logs', subtitle: 'Edge, player and collector events', ranges: null },
    workers: { title: 'Workers', subtitle: 'Per-process health and caches', ranges: null },
    system: { title: 'System', subtitle: 'Host resources, nginx and retention', ranges: null },
    security: { title: 'Security', subtitle: 'Errors, blocks and suspicious traffic', ranges: ['1h', '6h', '24h', '7d', '30d'] },
    data: { title: 'Data', subtitle: 'Storage, retention and ingestion', ranges: null }
  };

  const state = {
    page: 'overview',
    range: '24h',
    loading: false,
    lastLoad: 0,
    sseLive: false,
    overview: null,
    sites: null,
    content: null,
    filters: { sites: '', titles: '' },
    logs: {
      entries: [],
      nextBefore: null,
      level: 'all',
      source: 'all',
      q: '',
      pinned: false,
      levelCounts: { info: 0, warn: 0, error: 0 }
    }
  };

  const $ = (id) => document.getElementById(id);

  /* --------------------------------------------------------------------- *
   * DOM helpers
   * --------------------------------------------------------------------- */

  function h(tag, attrs, ...children) {
    const node = document.createElement(tag);
    if (attrs) {
      for (const [key, value] of Object.entries(attrs)) {
        if (value == null || value === false) continue;
        if (key === 'class') node.className = value;
        else if (key === 'text') node.textContent = value;
        else if (key === 'dataset') Object.assign(node.dataset, value);
        else if (key === 'onClick') node.addEventListener('click', value);
        else node.setAttribute(key, value);
      }
    }
    for (const child of children.flat(Infinity)) {
      if (child == null || child === false) continue;
      node.append(child.nodeType ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  function empty(text, title) {
    const node = h('div', { class: 'empty' });
    if (title) node.append(h('strong', { text: title }));
    node.append(text);
    return node;
  }

  function statGrid(container, items) {
    container.replaceChildren(...items.map((item) =>
      h('div', { class: 'stat' + (item.tone ? ' ' + item.tone : '') },
        h('div', { class: 'stat-label', text: item.label }),
        h('div', { class: 'stat-value', text: item.value }),
        item.sub ? h('div', { class: 'stat-sub', text: item.sub }) : null
      )
    ));
  }

  function miniGrid(container, items) {
    container.replaceChildren(...items.map((item) =>
      h('div', { class: 'mini' },
        h('div', { class: 'mini-label', text: item.label }),
        h('div', { class: 'mini-value' + (item.dim ? ' dim' : ''), text: item.value })
      )
    ));
  }

  function kvRow(label, value, sub) {
    return h('div', { class: 'list-row' },
      h('div', { class: 'list-main' },
        h('div', { class: 'list-title', text: label }),
        sub ? h('div', { class: 'list-sub', text: sub }) : null
      ),
      h('span', { class: 'list-value', text: value })
    );
  }

  function barRow(label, value, ratio, tone) {
    const track = h('div', { class: 'bar-track' });
    const fill = h('div', { class: 'bar-fill' + (tone ? ' ' + tone : '') });
    fill.style.width = Math.round(Math.min(1, Math.max(0, Number(ratio) || 0)) * 100) + '%';
    track.append(fill);
    return h('div', { class: 'bar-row' },
      h('span', { class: 'bar-label', text: label, title: label }),
      track,
      h('span', { class: 'bar-value', text: value })
    );
  }

  function buildTable(headers, rows) {
    if (!rows.length) return empty('No rows');
    return h('div', { class: 'table-wrap' },
      h('table', {},
        h('thead', {}, h('tr', {}, ...headers.map((header) =>
          h('th', { class: header.num ? 'num' : (header.mono ? 'mono' : ''), text: header.label })
        ))),
        h('tbody', {}, ...rows)
      )
    );
  }

  function td(text, cls) {
    return h('td', { class: cls || '', text });
  }

  function pill(text, tone) {
    return h('span', { class: 'pill' + (tone ? ' ' + tone : ''), text });
  }

  function qualityBlock(quality) {
    const parts = [
      ['SD', Number(quality.sd) || 0, '#6b7280'],
      ['HD', Number(quality.hd) || 0, '#22d3ee'],
      ['FHD', Number(quality.fhd) || 0, '#818cf8'],
      ['4K', Number(quality.uhd) || 0, '#10b981']
    ];
    const total = parts.reduce((sum, part) => sum + part[1], 0);
    if (!total) return h('div', { class: 'hint', text: 'No quality samples yet' });
    const bar = h('div', { class: 'qbar' });
    for (const [label, value, color] of parts) {
      if (!value) continue;
      const segment = h('span');
      segment.style.width = ((value / total) * 100).toFixed(2) + '%';
      segment.style.background = color;
      segment.title = `${label}: ${fmtNum(value)} samples`;
      bar.append(segment);
    }
    const legend = h('div', { class: 'qlegend' }, ...parts.map(([label, value, color]) => {
      const item = h('span');
      const dot = h('i');
      dot.style.background = color;
      item.append(dot, `${label} ${fmtNum(value)}`);
      return item;
    }));
    return h('div', {}, bar, legend);
  }

  /* --------------------------------------------------------------------- *
   * Formatting
   * --------------------------------------------------------------------- */

  const numberFormat = new Intl.NumberFormat('en-US');
  const KB = 1024;
  const MB = 1024 * 1024;
  const GB = 1024 * 1024 * 1024;

  function fmtNum(value) {
    const n = Number(value) || 0;
    if (Math.abs(n) >= 1e9) return (n / 1e9).toFixed(2) + 'B';
    if (Math.abs(n) >= 1e6) return (n / 1e6).toFixed(2) + 'M';
    if (Math.abs(n) >= 1e4) return (n / 1e3).toFixed(1) + 'k';
    return numberFormat.format(Math.round(n));
  }

  function fmtBytes(value) {
    const n = Math.max(0, Number(value) || 0);
    if (n < KB) return Math.round(n) + ' B';
    if (n < MB) return (n / KB).toFixed(n < 10 * KB ? 1 : 0) + ' KB';
    if (n < GB) return (n / MB).toFixed(n < 10 * MB ? 1 : 0) + ' MB';
    return (n / GB).toFixed(n < 10 * GB ? 2 : 1) + ' GB';
  }

  function fmtRate(value) {
    return fmtBytes(value) + '/s';
  }

  function fmtPct(value, digits) {
    const n = Number(value) || 0;
    return n.toFixed(digits == null ? 1 : digits) + '%';
  }

  function fmtMs(value) {
    const n = Math.max(0, Number(value) || 0);
    if (n < 1000) return Math.round(n) + ' ms';
    return (n / 1000).toFixed(n < 10000 ? 1 : 0) + ' s';
  }

  function fmtWatch(minutes) {
    const n = Math.max(0, Math.round(Number(minutes) || 0));
    if (n < 60) return n + ' min';
    if (n < 1440) {
      const hours = Math.floor(n / 60);
      const rest = n % 60;
      return rest ? `${hours}h ${rest}m` : `${hours}h`;
    }
    const days = Math.floor(n / 1440);
    const hours = Math.floor((n % 1440) / 60);
    return hours ? `${days}d ${hours}h` : `${days}d`;
  }

  function fmtDuration(totalSeconds) {
    const n = Math.max(0, Math.round(Number(totalSeconds) || 0));
    if (n < 60) return n + 's';
    if (n < 3600) return Math.floor(n / 60) + 'm';
    if (n < 86400) {
      const hours = Math.floor(n / 3600);
      const minutes = Math.floor((n % 3600) / 60);
      return minutes ? `${hours}h ${minutes}m` : `${hours}h`;
    }
    const days = Math.floor(n / 86400);
    const hours = Math.floor((n % 86400) / 3600);
    return hours ? `${days}d ${hours}h` : `${days}d`;
  }

  function fmtAgo(ts) {
    if (!ts) return '—';
    const seconds = Math.max(0, Math.round((Date.now() - Number(ts)) / 1000));
    if (seconds < 5) return 'just now';
    if (seconds < 60) return seconds + 's ago';
    const minutes = Math.round(seconds / 60);
    if (minutes < 60) return minutes + 'm ago';
    const hours = Math.round(minutes / 60);
    if (hours < 24) return hours + 'h ago';
    return Math.round(hours / 24) + 'd ago';
  }

  function fmtClock(ts) {
    const date = new Date(Number(ts) || 0);
    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  }

  function rangeLabel(range) {
    if (range === 'all') return 'all time';
    return 'last ' + range;
  }

  function xFormatter(range) {
    if (range === '7d' || range === '30d' || range === 'all') {
      return (ts) => new Date(ts).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    }
    return (ts) => new Date(ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
  }

  function providerLabel(code) {
    return PROVIDER_LABEL[code] || (code ? code[0].toUpperCase() + code.slice(1) : 'Unknown');
  }

  function sumOf(values) {
    return values.reduce((sum, value) => sum + (Number(value) || 0), 0);
  }

  /* --------------------------------------------------------------------- *
   * API + page loading
   * --------------------------------------------------------------------- */

  async function api(path) {
    const response = await fetch(path, { cache: 'no-store', headers: { Accept: 'application/json' } });
    if (!response.ok) {
      let detail = '';
      try { detail = (await response.text()).slice(0, 140); } catch { /* ignore */ }
      throw new Error(`${response.status}${detail ? ` — ${detail}` : ''}`);
    }
    return response.json();
  }

  function showError(message) {
    const banner = $('error-banner');
    banner.replaceChildren(
      h('span', { text: message }),
      h('button', { class: 'card-link', type: 'button', text: 'Retry', onClick: () => loadPage({ force: true }) })
    );
    banner.hidden = false;
  }

  function hideError() {
    $('error-banner').hidden = true;
  }

  function setRefreshing(on) {
    $('refresh-btn').classList.toggle('spinning', Boolean(on));
  }

  function markLoaded() {
    state.lastLoad = Date.now();
    updateUpdatedLabel();
  }

  function updateUpdatedLabel() {
    $('updated').textContent = state.lastLoad ? `updated ${fmtAgo(state.lastLoad)}` : '—';
  }

  function logQuery(reset) {
    const params = new URLSearchParams({ limit: String(LOG_LIMIT) });
    if (state.logs.level !== 'all') params.set('level', state.logs.level);
    if (state.logs.source !== 'all') params.set('source', state.logs.source);
    if (state.logs.q) params.set('q', state.logs.q);
    if (!reset && state.logs.nextBefore) params.set('before', String(state.logs.nextBefore));
    return '/admin/api/logs?' + params.toString();
  }

  async function fetchFor(page) {
    switch (page) {
      case 'overview':
        return api('/admin/api/overview');
      case 'traffic':
        return api(`/admin/api/traffic?range=${encodeURIComponent(state.range)}`);
      case 'sites':
        return api(`/admin/api/origins?range=${encodeURIComponent(state.range)}`);
      case 'content':
        return api(`/admin/api/providers?range=${encodeURIComponent(state.range)}`);
      case 'workers':
        return api('/admin/api/workers');
      case 'system':
        return api('/admin/api/system');
      case 'security':
        return api(`/admin/api/security?range=${encodeURIComponent(state.range)}`);
      case 'data':
        return api('/admin/api/data');
      default:
        throw new Error(`unknown page ${page}`);
    }
  }

  const RENDERERS = {
    overview: renderOverview,
    traffic: renderTraffic,
    sites: renderSites,
    content: renderContent,
    workers: renderWorkers,
    system: renderSystem,
    security: renderSecurity,
    data: renderData
  };

  async function loadPage(options) {
    const opts = options || {};
    const page = state.page;

    if (page === 'logs') {
      if (state.logs.pinned && !opts.force) return;
      if (opts.force) state.logs.pinned = false;
      await loadLogs(true, { silent: opts.silent });
      return;
    }

    if (state.loading) return;
    state.loading = true;
    if (!opts.silent) setRefreshing(true);

    try {
      const data = await fetchFor(page);
      if (state.page !== page) return;
      RENDERERS[page](data);
      markLoaded();
      hideError();
    } catch (error) {
      showError(`Could not load ${PAGE_META[page].title.toLowerCase()}: ${error.message}`);
    } finally {
      state.loading = false;
      setRefreshing(false);
    }
  }

  function maybeAutoRefresh() {
    if (document.hidden || state.loading) return;
    if (Date.now() - state.lastLoad < AUTO_GAP_MS) return;
    loadPage({ silent: true });
  }

  /* --------------------------------------------------------------------- *
   * Logs (filters, pagination, live tail)
   * --------------------------------------------------------------------- */

  async function loadLogs(reset, options) {
    const opts = options || {};
    if (state.loading && !reset) return;
    state.loading = true;
    if (!opts.silent) setRefreshing(true);
    try {
      const data = await api(logQuery(reset));
      if (state.page !== 'logs') return;
      state.logs.entries = reset ? data.entries : state.logs.entries.concat(data.entries);
      state.logs.nextBefore = data.nextBefore;
      state.logs.levelCounts = data.levelCounts24h || { info: 0, warn: 0, error: 0 };
      renderLogs();
      markLoaded();
      hideError();
    } catch (error) {
      showError(`Could not load logs: ${error.message}`);
    } finally {
      state.loading = false;
      setRefreshing(false);
    }
  }

  function logEntryRow(entry) {
    const row = h('div', { class: 'log-row', role: 'button', tabindex: '0' },
      h('span', { class: 'log-time', text: fmtClock(entry.ts) }),
      h('span', { class: 'log-level ' + entry.level, text: entry.level }),
      h('span', { class: 'log-source', text: entry.source }),
      h('span', { class: 'log-msg', text: entry.message })
    );
    if (entry.data) {
      const data = h('pre', { class: 'log-data', text: JSON.stringify(entry.data, null, 2) });
      data.hidden = true;
      row.append(data);
      const toggle = () => { data.hidden = !data.hidden; };
      row.addEventListener('click', toggle);
      row.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          toggle();
        }
      });
    }
    return row;
  }

  function renderLogs() {
    const counts = state.logs.levelCounts;
    $('log-count-info').textContent = fmtNum(counts.info || 0);
    $('log-count-warn').textContent = fmtNum(counts.warn || 0);
    $('log-count-error').textContent = fmtNum(counts.error || 0);

    for (const button of document.querySelectorAll('#logs-levels button')) {
      button.classList.toggle('active', button.dataset.level === state.logs.level);
    }

    $('logs-pinned').hidden = !state.logs.pinned;
    const total = sumOf([counts.info, counts.warn, counts.error]);
    $('logs-status').textContent = `${fmtNum(state.logs.entries.length)} shown · ${fmtNum(total)} in 24h`;

    const list = $('logs-list');
    list.replaceChildren();
    if (!state.logs.entries.length) {
      list.append(empty('No matching log events. Edge requests are sampled; errors and slow requests are always kept.', 'Nothing here yet'));
    } else {
      list.append(...state.logs.entries.map(logEntryRow));
    }

    const more = $('logs-more');
    more.replaceChildren();
    if (state.logs.pinned) {
      more.append(h('button', {
        class: 'btn primary',
        type: 'button',
        text: 'Resume live tail',
        onClick: () => {
          state.logs.pinned = false;
          loadLogs(true);
        }
      }));
    }
    if (state.logs.nextBefore) {
      if (state.logs.pinned) more.append(h('span', { class: 'hint', text: 'or' }));
      more.append(h('button', {
        class: 'btn',
        type: 'button',
        text: 'Load older',
        onClick: () => {
          state.logs.pinned = true;
          loadLogs(false);
        }
      }));
    }
    if (!state.logs.nextBefore) more.append(h('span', { class: 'hint', text: 'End of stored log.' }));
  }

  /* --------------------------------------------------------------------- *
   * Overview
   * --------------------------------------------------------------------- */

  function setChips(data) {
    const viewers = $('chip-viewers');
    viewers.textContent = `${fmtNum(data.activeViewers)} viewers`;
    viewers.hidden = false;

    const workers = $('chip-workers');
    workers.textContent = `${data.onlineWorkers}/${data.expectedWorkers} workers`;
    workers.hidden = false;
    workers.classList.toggle('warn', data.onlineWorkers < data.expectedWorkers);

    const alerts = $('chip-alerts');
    alerts.textContent = `${data.critical ? data.critical + ' critical · ' : ''}${data.alerts} alerts`;
    alerts.hidden = !data.alerts;
  }

  function renderOverview(data) {
    state.overview = data;
    const live = data.live;
    const meta = data.meta || {};

    statGrid($('ov-kpis'), [
      { label: 'Active viewers', value: fmtNum(live.activeViewers), sub: meta.telemetryEnabled ? 'telemetry sessions' : 'telemetry disabled', tone: live.activeViewers ? 'accent' : '' },
      { label: 'Requests / min', value: fmtNum(live.requestsPerMin), sub: live.liveEdge ? 'live edge window' : 'last 5 minutes', tone: '' },
      { label: 'Bandwidth', value: fmtRate(live.bytesPerSec), sub: 'current egress', tone: 'accent' },
      { label: 'Error rate', value: fmtPct(live.errorRate), sub: '5xx over requests', tone: live.errorRate > 5 ? 'bad' : live.errorRate > 1 ? 'warn' : 'good' },
      { label: 'P95 latency', value: fmtMs(live.p95Ms), sub: 'edge response time', tone: live.p95Ms > 2500 ? 'warn' : '' },
      { label: 'Cache hit', value: fmtPct(live.cacheHitPct), sub: 'nginx /p cache', tone: live.cacheHitPct >= 60 ? 'good' : live.cacheHitPct > 0 ? 'warn' : '' },
      { label: 'Workers', value: `${live.onlineWorkers}/${live.expectedWorkers}`, sub: 'reporting', tone: live.onlineWorkers >= live.expectedWorkers ? 'good' : live.onlineWorkers ? 'warn' : 'bad' },
      { label: 'In flight', value: fmtNum(live.inflight), sub: `${fmtNum(live.prefetch)} prefetch jobs`, tone: '' }
    ]);

    const series = data.series || [];
    const hasTraffic = series.some((point) => point.requests > 0);
    const x = series.map((point) => point.ts);
    const xFormat = xFormatter('1h');
    const liveLast = series.length > 0 && series[series.length - 1].live;

    Charts.line($('ov-requests'), {
      series: hasTraffic ? [{ values: series.map((point) => point.requests), color: Charts.palette.white, fill: true }] : [],
      x,
      xFormat,
      yFormat: fmtNum,
      live: liveLast,
      emptyText: 'No edge traffic yet'
    });
    Charts.line($('ov-bandwidth'), {
      series: hasTraffic ? [{ values: series.map((point) => point.bytes), color: Charts.palette.indigo, fill: true }] : [],
      x,
      xFormat,
      yFormat: fmtBytes,
      live: liveLast,
      emptyText: 'No edge traffic yet'
    });
    $('ov-requests-hint').textContent = hasTraffic
      ? `${fmtNum(sumOf(series.map((point) => point.requests)))} requests · last hour`
      : 'waiting for nginx log lines';
    $('ov-bandwidth-hint').textContent = hasTraffic
      ? `${fmtBytes(sumOf(series.map((point) => point.bytes)))} · last hour`
      : '—';

    const origins = data.origins || [];
    const originList = $('ov-origins');
    originList.replaceChildren();
    if (!origins.length) {
      originList.append(empty(
        'Embed requests with Referer headers will appear here. ' +
        'Visit an embed page from a different domain to generate data.',
        'No embedding sites yet'
      ));
    } else {
      originList.append(...origins.map((origin) => h('div', { class: 'site-row' },
        h('div', { class: 'site-head' },
          h('span', { class: 'site-name', text: origin.origin }),
          origin.active > 0 ? pill(`${origin.active} active`, 'good') : null
        ),
        h('div', { class: 'site-meta' },
          h('span', { text: `${fmtNum(origin.requests)} embeds` }),
          meta.telemetryEnabled ? h('span', { text: `${fmtNum(origin.plays)} plays` }) : null,
          meta.telemetryEnabled ? h('span', { text: `${fmtBytes(origin.bytesEst)} est. data` }) : null,
          h('span', { text: fmtAgo(origin.lastSeen) })
        )
      )));
    }

    const providers = (data.providers || []).slice().sort((a, b) => (b.bytes_est || 0) - (a.bytes_est || 0) || (b.active || 0) - (a.active || 0));
    const providerList = $('ov-providers');
    providerList.replaceChildren();
    for (const provider of providers) {
      providerList.append(h('div', { class: 'list-row' },
        h('div', { class: 'list-main' },
          h('div', { class: 'list-title', text: providerLabel(provider.provider) }),
          h('div', { class: 'list-sub', text: `${fmtNum(provider.embeds24h)} embeds · ${fmtNum(provider.plays)} plays · ${fmtBytes(provider.bytes_est)} est.` })
        ),
        provider.active > 0 ? pill(`${provider.active} active`, 'accent') : pill('idle', 'muted')
      ));
    }
    const quality = $('ov-quality');
    quality.replaceChildren(
      h('div', { class: 'section-label', text: 'Playback quality · 24h' }),
      qualityBlock(data.quality || {})
    );

    const totals = data.totals24h || {};
    $('ov-totals-hint').textContent = 'rolling window';
    miniGrid($('ov-totals'), [
      { label: 'Requests', value: fmtNum(totals.requests) },
      { label: 'Egress', value: fmtBytes(totals.bytes) },
      { label: 'Watch time', value: fmtWatch(totals.watchMinutes) },
      { label: 'Player boots', value: fmtNum(totals.boots) },
      { label: 'Plays', value: fmtNum(totals.plays) },
      { label: 'Est. viewer data', value: fmtBytes(totals.bytesEst) },
      { label: 'Stalls', value: fmtNum(totals.stalls) },
      { label: 'Player errors', value: fmtNum(totals.errors) }
    ]);

    const alerts = data.alerts || [];
    const alertsList = $('ov-alerts');
    alertsList.replaceChildren();
    $('ov-alerts-count').textContent = alerts.length ? `${alerts.length} active` : 'none';
    if (!alerts.length) {
      alertsList.append(empty('Workers, latency, cache, disk and ingestion are all inside thresholds.', 'All clear'));
    } else {
      for (const alert of alerts) {
        const tone = alert.level === 'critical' ? 'bad' : alert.level === 'warn' ? 'warn' : 'muted';
        alertsList.append(h('div', { class: 'list-row' },
          h('div', { class: 'list-main' },
            h('div', { class: 'list-title', text: alert.title }),
            h('div', { class: 'list-sub', text: alert.message })
          ),
          h('div', { class: 'list-main' },
            pill(alert.level, tone),
            h('span', { class: 'list-sub', text: fmtAgo(alert.since) })
          )
        ));
      }
    }

    const nonInfo = alerts.filter((alert) => alert.level !== 'info').length;
    const workers = data.workers || {};
    setChips({
      activeViewers: live.activeViewers,
      onlineWorkers: workers.online != null ? workers.online : live.onlineWorkers,
      expectedWorkers: workers.expected || live.expectedWorkers,
      alerts: nonInfo,
      critical: alerts.filter((alert) => alert.level === 'critical').length
    });

    $('sidebar-meta').textContent = `v${meta.version || '?'} · ${meta.node || ''} · up ${fmtDuration((meta.uptimeMs || 0) / 1000)}`;

    // Populate new overview sections
    const system = data.system || {};

    statGrid($('ov-system'), [
      { label: 'CPU', value: fmtPct(system.cpuPct || 0), sub: 'online workers', tone: (system.cpuPct || 0) >= 80 ? 'warn' : '' },
      { label: 'Memory', value: fmtBytes((system.rssMB || 0) * MB), sub: 'worker processes', tone: (system.rssMB || 0) >= 6000 ? 'warn' : '' },
      { label: 'Cache', value: fmtBytes((system.cacheMB || 0) * MB), sub: 'segment cache', tone: '' }
    ]);

    // Calculate cache stats from system data
    const cacheTotal = (system.cacheMB || 0) * MB;
    const cacheSize = data.live ? data.live.cacheHitPct || 0 : 0;

    statGrid($('ov-cache'), [
      { label: 'Hit rate', value: fmtPct(cacheSize), sub: 'from worker data', tone: cacheSize >= 80 ? 'good' : cacheSize >= 50 ? '' : 'warn' },
      { label: 'Size', value: fmtBytes(cacheTotal), sub: 'RAM used', tone: '' },
      { label: 'Workers', value: workers.online || 0, sub: `/${workers.expected || 1}`, tone: workers.online >= (workers.expected || 1) ? 'good' : 'warn' }
    ]);

    const db = data.db || {};
    statGrid($('ov-db'), [
      { label: 'Size', value: fmtBytes(db.size || 0), sub: 'on disk', tone: '' },
      { label: 'Retention', value: `${db.rawHours || 24}h`, sub: 'raw snapshots', tone: '' },
      { label: 'Pruned', value: db.overCap ? 'Yes' : 'No', sub: db.overCap ? 'over cap' : 'within limit', tone: db.overCap ? 'warn' : 'good' }
    ]);
  }

  /* --------------------------------------------------------------------- *
   * Traffic
   * --------------------------------------------------------------------- */

  function renderTraffic(data) {
    const totals = data.totals || {};
    const derived = data.derived || {};
    const x = (data.points || []).map((point) => point.ts);
    const xFormat = xFormatter(data.range);
    const hasData = (data.points || []).some((point) => point.requests > 0);
    const liveLast = (data.points || []).length > 0 && data.points[data.points.length - 1].live;

    statGrid($('tf-kpis'), [
      { label: 'Requests', value: fmtNum(totals.requests), sub: rangeLabel(data.range), tone: '' },
      { label: 'Egress', value: fmtBytes(totals.bytes), sub: 'body bytes sent', tone: 'accent' },
      { label: 'Avg latency', value: fmtMs(derived.avgMs), sub: 'whole request', tone: '' },
      { label: 'P95 latency', value: fmtMs(derived.p95Ms), sub: 'bucket estimate', tone: derived.p95Ms > 2500 ? 'warn' : '' },
      { label: 'Error rate', value: fmtPct(derived.errorRate), sub: `${fmtNum(totals.s5xx)} × 5xx`, tone: derived.errorRate > 5 ? 'bad' : derived.errorRate > 1 ? 'warn' : 'good' },
      { label: 'Cache hit', value: fmtPct(derived.cacheHitPct), sub: `${fmtNum(totals.cache_hit)} hits · ${fmtNum(totals.cache_miss)} misses`, tone: derived.cacheHitPct >= 60 ? 'good' : derived.cacheHitPct > 0 ? 'warn' : '' }
    ]);

    Charts.line($('tf-requests'), {
      series: hasData ? [
        { values: data.points.map((point) => point.requests), color: Charts.palette.white, fill: true },
        { values: data.points.map((point) => point.s5xx), color: Charts.palette.danger, fill: false, width: 1.4 },
        { values: data.points.map((point) => point.s4xx), color: Charts.palette.warn, fill: false, width: 1.2 }
      ] : [],
      x,
      xFormat,
      yFormat: fmtNum,
      live: liveLast,
      emptyText: 'No requests in this window'
    });
    $('tf-requests-hint').textContent = 'white requests · amber 4xx · red 5xx';

    Charts.line($('tf-bandwidth'), {
      series: hasData ? [{ values: data.points.map((point) => point.bytes), color: Charts.palette.indigo, fill: true }] : [],
      x,
      xFormat,
      yFormat: fmtBytes,
      live: liveLast,
      emptyText: 'No bandwidth recorded'
    });
    $('tf-bandwidth-hint').textContent = fmtBytes(totals.bytes);

    const cacheSamples = (totals.cache_hit || 0) + (totals.cache_miss || 0) + (totals.cache_bypass || 0);
    Charts.line($('tf-cache'), {
      series: cacheSamples ? [{
        values: data.points.map((point) => point.cacheHitPct),
        color: Charts.palette.cyan,
        fill: true
      }] : [],
      x,
      xFormat,
      yFormat: (value) => fmtPct(value, 0),
      max: 100,
      live: liveLast,
      emptyText: 'No cacheable /p requests'
    });
    $('tf-cache-hint').textContent = cacheSamples
      ? `${fmtNum(totals.cache_hit)} hit · ${fmtNum(totals.cache_miss)} miss · ${fmtNum(totals.cache_bypass)} bypass`
      : 'nginx cache not exercised';

    const requestTotal = totals.requests || 0;
    const status = $('tf-status');
    status.replaceChildren();
    const classes = [
      ['2xx', totals.s2xx || 0, 'success'],
      ['3xx', totals.s3xx || 0, 'muted'],
      ['4xx', totals.s4xx || 0, 'warn'],
      ['5xx', totals.s5xx || 0, 'danger']
    ];
    for (const [label, value, tone] of classes) {
      const ratio = requestTotal ? value / requestTotal : 0;
      status.append(barRow(label, `${fmtNum(value)} · ${fmtPct(ratio * 100)}`, ratio, tone));
    }
    status.append(h('div', { class: 'section-label', text: 'Error detail' }));
    const specifics = [
      ['403 Forbidden', totals.s403 || 0, 'warn'],
      ['404 Not found', totals.s404 || 0, 'warn'],
      ['429 Rate limited', totals.s429 || 0, 'warn'],
      ['499 Client closed', totals.s499 || 0, 'muted'],
      ['502 Bad gateway', totals.s502 || 0, 'danger']
    ];
    for (const [label, value, tone] of specifics) {
      const ratio = requestTotal ? value / requestTotal : 0;
      status.append(barRow(label, fmtNum(value), ratio, tone));
    }
    $('tf-status-hint').textContent = `${fmtNum(requestTotal)} responses`;

    const routes = data.routes || {};
    const routeTotal = sumOf(Object.values(routes));
    const routeList = $('tf-routes');
    routeList.replaceChildren();
    const entries = Object.entries(routes).sort((a, b) => b[1] - a[1]);
    for (const [key, value] of entries) {
      const ratio = routeTotal ? value / routeTotal : 0;
      routeList.append(barRow(ROUTE_LABEL[key] || key, `${fmtNum(value)} · ${fmtPct(ratio * 100, 0)}`, ratio, key === 'seg' ? 'indigo' : key === 'embed' ? 'success' : key === 'download' ? 'warn' : 'muted'));
    }
    const providers = data.providers || {};
    $('tf-routes-hint').textContent = `embeds: ${fmtNum(providers.zoko)} naoka · ${fmtNum(providers.kira)} kira · ${fmtNum(providers.haiku)} haiku`;
  }

  /* --------------------------------------------------------------------- *
   * Embed sites
   * --------------------------------------------------------------------- */

  function renderSites(data) {
    state.sites = data;
    const telemetry = data.telemetryEnabled;
    const totals = data.totals || {};

    statGrid($('sites-kpis'), [
      { label: 'Embedding sites', value: fmtNum((data.origins || []).length), sub: 'in this window', tone: '' },
      { label: 'Active viewers', value: fmtNum(data.activeViewers), sub: telemetry ? 'telemetry sessions' : 'telemetry disabled', tone: data.activeViewers ? 'accent' : '' },
      { label: 'Embeds', value: fmtNum(totals.requests), sub: 'player page loads', tone: '' },
      { label: 'Watch time', value: telemetry ? fmtWatch(totals.sessionMinutes) : '—', sub: 'session minutes', tone: '' },
      { label: 'Plays', value: telemetry ? fmtNum(totals.plays) : '—', sub: 'play events', tone: '' },
      { label: 'Est. viewer data', value: telemetry ? fmtBytes(totals.bytesEst) : '—', sub: 'reported by player', tone: '' }
    ]);

    $('sites-note').hidden = telemetry;
    $('sites-range-hint').textContent = rangeLabel(data.range);

    const filter = state.filters.sites;
    const all = data.origins || [];
    const list = filter ? all.filter((origin) => origin.origin.includes(filter)) : all;
    $('sites-count').textContent = filter ? `${list.length} of ${all.length} sites` : `${all.length} sites`;

    const container = $('sites-table');
    if (!list.length) {
      container.replaceChildren(empty(
        filter ? 'No site matches that filter.' : 'Embed requests appear here once nginx records a Referer.',
        filter ? 'No matches' : 'No embedding sites yet'
      ));
      return;
    }

    const rows = list.map((origin) => h('tr', {},
      td(origin.origin, 'mono strong'),
      h('td', {}, origin.active > 0 ? pill(String(origin.active), 'good') : h('span', { class: 'dim', text: '0' })),
      td(fmtNum(origin.requests), 'num'),
      td(telemetry ? fmtNum(origin.boots) : '—', 'num'),
      td(telemetry ? fmtWatch(origin.sessionMinutes) : '—', 'num'),
      td(telemetry ? fmtNum(origin.plays) : '—', 'num'),
      td(telemetry ? fmtBytes(origin.bytesEst) : '—', 'num'),
      h('td', {},
        h('span', { text: providerLabel(origin.lastProvider) }),
        origin.lastTier ? h('span', { class: 'sub', text: origin.lastTier }) : null
      ),
      td(fmtAgo(origin.lastSeen), 'num')
    ));

    container.replaceChildren(buildTable([
      { label: 'Site', mono: true },
      { label: 'Active', num: true },
      { label: 'Embeds', num: true },
      { label: 'Boots', num: true },
      { label: 'Watch', num: true },
      { label: 'Plays', num: true },
      { label: 'Est. data', num: true },
      { label: 'Provider' },
      { label: 'Last seen', num: true }
    ], rows));
  }

  /* --------------------------------------------------------------------- *
   * Content
   * --------------------------------------------------------------------- */

  function renderContent(data) {
    state.content = data;
    const telemetry = data.telemetryEnabled;
    $('content-note').hidden = telemetry;
    $('content-range-hint').textContent = rangeLabel(data.range);

    const providerGrid = $('content-providers');
    providerGrid.replaceChildren();
    const providers = (data.providers || []).slice().sort((a, b) => (b.active || 0) - (a.active || 0) || (b.bytes_est || 0) - (a.bytes_est || 0));
    for (const provider of providers) {
      const quality = provider.quality || {};
      providerGrid.append(h('div', { class: 'provider-card' },
        h('div', { class: 'provider-head' },
          h('span', { class: 'provider-name' },
            providerLabel(provider.provider),
            h('span', { class: 'provider-code', text: ' ' + provider.provider })
          ),
          provider.active > 0 ? pill(`${provider.active} active`, 'accent') : pill('idle', 'muted')
        ),
        h('div', { class: 'provider-stats' },
          mini('Embeds', fmtNum(provider.embeds)),
          mini('Player boots', telemetry ? fmtNum(provider.boots) : '—'),
          mini('Plays', telemetry ? fmtNum(provider.plays) : '—'),
          mini('Watch', telemetry ? fmtWatch(provider.session_minutes) : '—'),
          mini('Est. data', telemetry ? fmtBytes(provider.bytes_est) : '—'),
          mini('Session minutes', telemetry ? fmtNum(provider.session_minutes) : '—')
        ),
        h('div', { class: 'section-label', text: 'Quality samples' }),
        qualityBlock({
          sd: quality.sd,
          hd: quality.hd,
          fhd: quality.fhd,
          uhd: quality.uhd
        })
      ));
    }

    const filter = state.filters.titles;
    const titles = (data.titles || []).filter((title) => {
      if (!filter) return true;
      return String(title.content || '').toLowerCase().includes(filter) ||
        String(title.episode || '').toLowerCase().includes(filter) ||
        providerLabel(title.provider).toLowerCase().includes(filter);
    });
    $('content-count').textContent = filter
      ? `${titles.length} of ${(data.titles || []).length} titles`
      : `${(data.titles || []).length} titles`;

    const container = $('content-titles');
    if (!titles.length) {
      container.replaceChildren(empty(
        filter ? 'No title matches that filter.' : (telemetry ? 'No title telemetry in this window yet.' : 'Enable ADMIN_TELEMETRY to collect title stats.'),
        filter ? 'No matches' : 'No titles yet'
      ));
      return;
    }

    const rows = titles.map((title) => h('tr', {},
      td(providerLabel(title.provider)),
      td(title.content || '—', 'mono strong'),
      td(title.episode || '—', 'mono'),
      td(fmtNum(title.plays), 'num'),
      td(fmtWatch(title.sessionMinutes), 'num'),
      td(fmtBytes(title.bytesEst), 'num')
    ));

    container.replaceChildren(buildTable([
      { label: 'Provider' },
      { label: 'Title', mono: true },
      { label: 'Episode', mono: true },
      { label: 'Plays', num: true },
      { label: 'Watch', num: true },
      { label: 'Est. data', num: true }
    ], rows));
  }

  function mini(label, value) {
    return h('div', { class: 'mini' },
      h('div', { class: 'mini-label', text: label }),
      h('div', { class: 'mini-value', text: value })
    );
  }

  /* --------------------------------------------------------------------- *
   * Workers
   * --------------------------------------------------------------------- */

  function workerCard(worker) {
    const online = worker.online;
    const metric = (label, value, tone) => h('div', {},
      h('div', { class: 'metric-label', text: label }),
      h('div', { class: 'metric-value' + (tone ? ' ' + tone : ''), text: value })
    );

    const routes = Object.entries(worker.routes || {})
      .filter(([, count]) => count > 0)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6);
    const cacheSizes = worker.cacheSizes || {};

    return h('div', { class: 'worker-card' + (online ? '' : ' offline') },
      h('div', { class: 'worker-head' },
        h('div', { class: 'worker-name' },
          worker.worker,
          h('span', { class: 'worker-port', text: `${worker.port ? ':' + worker.port : ''}${worker.version ? ' · v' + worker.version : ''}` })
        ),
        pill(online ? 'online' : 'offline', online ? 'good' : 'bad')
      ),
      h('div', { class: 'metric-grid' },
        metric('CPU', fmtPct(worker.cpuPct), worker.cpuPct >= 85 ? 'bad' : worker.cpuPct >= 65 ? 'warn' : ''),
        metric('RSS', fmtBytes(worker.rssMB * MB), worker.rssMB >= 1500 ? 'warn' : ''),
        metric('Heap', fmtBytes(worker.heapMB * MB)),
        metric('Event loop', fmtMs(worker.elagMs), worker.elagMs >= 250 ? (worker.elagMs >= 1000 ? 'bad' : 'warn') : ''),
        metric('Requests / min', fmtNum(worker.requestsPerMin)),
        metric('In flight', fmtNum(worker.inflight)),
        metric('Prefetch', fmtNum(worker.prefetch)),
        metric('Client streams', fmtNum(worker.clientInflight)),
        metric('Cache hit', fmtPct(worker.cacheHitPct)),
        metric('RAM cache', fmtBytes(worker.cacheMB * MB)),
        metric('Slow requests', fmtNum(worker.slow), worker.slow > 0 ? 'warn' : ''),
        metric('Uptime', fmtDuration(worker.uptimeS))
      ),
      sparkBlock('CPU % · last 30 min', 'cpu'),
      sparkBlock('Event loop lag · last 30 min', 'lag'),
      routes.length ? h('div', { class: 'chip-row' }, ...routes.map(([key, count]) =>
        h('span', { class: 'chip' }, h('span', { text: `${ROUTE_LABEL[key] || key} ` }), h('span', { class: 'mono', text: fmtNum(count) }))
      )) : null,
      h('div', { class: 'chip-row' },
        h('span', { class: 'chip', text: `m3u8 ${fmtNum(cacheSizes.m3u8)}` }),
        h('span', { class: 'chip', text: `segments ${fmtNum(cacheSizes.segments)}` }),
        h('span', { class: 'chip', text: `abyss ${fmtNum(cacheSizes.abyssChunks)}` }),
        h('span', { class: 'chip', text: `index ${fmtNum(cacheSizes.segmentIndex)}` })
      ),
      worker.lastSeen ? h('div', { class: 'hint', text: `last snapshot ${fmtAgo(worker.lastSeen)}` }) : null
    );
  }

  function sparkBlock(label, key) {
    const canvas = h('canvas', { class: 'spark' });
    canvas.dataset.spark = key;
    return h('div', { class: 'spark-block' },
      h('div', { class: 'spark-label' }, h('span', { text: label })),
      canvas
    );
  }

  function renderWorkers(data) {
    const workers = data.workers || [];
    const online = workers.filter((worker) => worker.online);
    const requestRate = sumOf(workers.map((worker) => worker.requestsPerMin));
    const avgCpu = online.length ? sumOf(online.map((worker) => worker.cpuPct)) / online.length : 0;
    const totalRss = sumOf(online.map((worker) => worker.rssMB));
    const cacheHits = sumOf(online.map((worker) => worker.cacheHitPct));
    const prefetch = sumOf(online.map((worker) => worker.prefetch));

    statGrid($('workers-kpis'), [
      { label: 'Online', value: `${online.length}/${data.expected}`, sub: 'reporting workers', tone: online.length >= data.expected ? 'good' : online.length ? 'warn' : 'bad' },
      { label: 'Requests / min', value: fmtNum(requestRate), sub: 'sum across workers', tone: '' },
      { label: 'Avg CPU', value: fmtPct(avgCpu), sub: 'online workers', tone: avgCpu >= 80 ? 'warn' : '' },
      { label: 'Total RSS', value: fmtBytes(totalRss * MB), sub: 'worker processes', tone: totalRss >= 6000 ? 'warn' : '' },
      { label: 'Avg cache hit', value: online.length ? fmtPct(cacheHits / online.length) : '—', sub: 'segment cache', tone: '' },
      { label: 'Prefetch', value: fmtNum(prefetch), sub: 'in-flight jobs', tone: prefetch >= 48 ? 'warn' : '' }
    ]);

    $('workers-note').hidden = workers.length > 0;
    const grid = $('workers-grid');
    Charts.release(grid);
    grid.replaceChildren();
    if (!workers.length) {
      grid.append(empty(
        'Set ADMIN_METRICS=1 and ADMIN_INGEST_TOKEN in your worker .env, then restart the workers. ' +
        'Snapshots arrive every 30 s from workers reporting to the collector.',
        'No workers reporting'
      ));
      return;
    }

    const cards = [];
    for (const worker of workers) {
      const card = workerCard(worker);
      cards.push({ worker, card });
      grid.append(card);
    }
    for (const { worker, card } of cards) {
      const history = worker.history || [];
      Charts.spark(card.querySelector('canvas[data-spark="cpu"]'), {
        values: history.map((point) => point.cpuPct),
        color: Charts.palette.white
      });
      Charts.spark(card.querySelector('canvas[data-spark="lag"]'), {
        values: history.map((point) => point.elagMs),
        color: Charts.palette.warn
      });
    }
  }

  /* --------------------------------------------------------------------- *
   * System
   * --------------------------------------------------------------------- */

  function renderSystem(data) {
    const latest = data.latest;
    const points = data.points || [];
    const x = points.map((point) => point.ts);
    const xFormat = xFormatter('24h');
    const db = data.db || {};
    const edge = data.edge || {};
    const ingest = data.ingest || {};
    const rows = db.rows || {};

    const memPct = latest && latest.memTotalMB ? (latest.memUsedMB / latest.memTotalMB) * 100 : 0;
    const diskPct = latest && latest.diskTotalGB ? (latest.diskUsedGB / latest.diskTotalGB) * 100 : 0;

    statGrid($('sys-kpis'), [
      { label: 'CPU', value: latest ? fmtPct(latest.cpuPct) : '—', sub: latest ? `load ${latest.load1.toFixed(2)} / ${latest.load5.toFixed(2)} / ${latest.load15.toFixed(2)}` : 'no samples yet', tone: latest && latest.cpuPct >= 85 ? 'bad' : latest && latest.cpuPct >= 65 ? 'warn' : '' },
      { label: 'Memory', value: latest ? fmtPct(memPct, 0) : '—', sub: latest ? `${fmtBytes(latest.memUsedMB * MB)} / ${fmtBytes(latest.memTotalMB * MB)}` : '—', tone: memPct >= 93 ? 'bad' : memPct >= 85 ? 'warn' : '' },
      { label: 'Swap', value: latest ? fmtBytes(latest.swapUsedMB * MB) : '—', sub: 'used', tone: latest && latest.swapUsedMB > 512 ? 'warn' : '' },
      { label: 'Disk', value: latest ? fmtPct(diskPct, 0) : '—', sub: latest ? `${latest.diskUsedGB} / ${latest.diskTotalGB} GB` : '—', tone: diskPct >= 92 ? 'bad' : diskPct >= 85 ? 'warn' : '' },
      { label: 'Net RX', value: latest ? fmtRate(latest.netRxBps) : '—', sub: 'inbound', tone: '' },
      { label: 'Net TX', value: latest ? fmtRate(latest.netTxBps) : '—', sub: 'outbound', tone: 'accent' },
      { label: 'nginx conns', value: latest && latest.nginxActive != null ? fmtNum(latest.nginxActive) : '—', sub: 'active connections', tone: '' },
      { label: 'nginx RPS', value: latest && latest.nginxRps != null ? fmtNum(latest.nginxRps) : '—', sub: 'stub_status delta', tone: '' },
      { label: 'Workers online', value: latest ? fmtNum(latest.workersOnline) : '—', sub: 'at last sample', tone: '' },
      { label: 'Worker RSS', value: latest ? fmtBytes(latest.workerRssMB * MB) : '—', sub: 'sum of workers', tone: '' },
      { label: 'Database', value: fmtBytes(db.sizeMB * MB), sub: `cap ${db.maxMB} MB`, tone: db.sizeMB > db.maxMB * 0.8 ? 'warn' : '' },
      { label: 'DB rows', value: fmtNum(sumOf(Object.values(rows))), sub: 'all tables', tone: '' }
    ]);

    Charts.line($('sys-cpu'), {
      series: points.length ? [{ values: points.map((point) => point.cpuPct), color: Charts.palette.white, fill: true }] : [],
      x,
      xFormat,
      yFormat: (value) => fmtPct(value, 0),
      max: 100,
      emptyText: 'Waiting for the first system sample'
    });
    $('sys-cpu-hint').textContent = latest ? `${fmtPct(latest.cpuPct)} · load ${latest.load1.toFixed(2)}` : '—';

    Charts.line($('sys-mem'), {
      series: points.length ? [{
        values: points.map((point) => point.memTotalMB ? (point.memUsedMB / point.memTotalMB) * 100 : 0),
        color: Charts.palette.success,
        fill: true
      }] : [],
      x,
      xFormat,
      yFormat: (value) => fmtPct(value, 0),
      max: 100,
      emptyText: 'Waiting for samples'
    });
    $('sys-mem-hint').textContent = latest ? `${fmtBytes(latest.memUsedMB * MB)} used` : '—';

    Charts.line($('sys-net'), {
      series: points.length ? [
        { values: points.map((point) => point.netRxBps), color: Charts.palette.cyan, fill: true },
        { values: points.map((point) => point.netTxBps), color: Charts.palette.indigo, fill: false }
      ] : [],
      x,
      xFormat,
      yFormat: fmtRate,
      emptyText: 'Waiting for samples'
    });
    $('sys-net-hint').textContent = 'cyan inbound · indigo outbound';

    const sources = $('sys-sources');
    sources.replaceChildren();
    const edgeTone = edge.running ? 'good' : edge.enabled ? 'bad' : 'muted';
    sources.append(h('div', { class: 'list-row' },
      h('div', { class: 'list-main' },
        h('div', { class: 'list-title', text: 'nginx edge log' }),
        h('div', { class: 'list-sub', text: edge.path || 'ADMIN_EDGE_LOG not set' })
      ),
      pill(edge.running ? 'tailing' : edge.enabled ? 'stopped' : 'off', edgeTone)
    ));
    sources.append(kvRow('Edge lines', `${fmtNum(edge.parsed)} parsed · ${fmtNum(edge.bad)} bad`, edge.error || `last line ${fmtAgo(edge.lastLineAt)}`));
    sources.append(kvRow('Edge offset', fmtBytes(edge.offset), `${fmtNum(edge.droppedLogs)} sampled out`));
    sources.append(h('div', { class: 'list-row' },
      h('div', { class: 'list-main' },
        h('div', { class: 'list-title', text: 'Player telemetry' }),
        h('div', { class: 'list-sub', text: ingest.telemetryEnabled ? `${fmtNum(ingest.activeSessions)} active · ${fmtNum(ingest.sessionsTracked)} tracked` : 'ADMIN_TELEMETRY is off' })
      ),
      pill(ingest.telemetryEnabled ? 'on' : 'off', ingest.telemetryEnabled ? 'good' : 'muted')
    ));
    sources.append(kvRow('Last player beacon', fmtAgo(ingest.lastTelemetryAt), `${fmtNum(ingest.droppedEvents)} events dropped`));
    $('sys-sources-hint').textContent = `edge ${edge.enabled ? 'on' : 'off'} · telemetry ${ingest.telemetryEnabled ? 'on' : 'off'}`;

    const retention = data.retention || {};
    const retentionList = $('sys-retention');
    retentionList.replaceChildren(
      kvRow('Raw worker snapshots', `${retention.rawHours} h`, 'per-worker samples'),
      kvRow('Raw request events', `${retention.rawRequestHours} h`, 'sampled edge log'),
      kvRow('Minute rollups', `${retention.minuteDays} d`, 'edge + viewers'),
      kvRow('Hour rollups', `${retention.hourDays} d`),
      kvRow('Daily rollups', `${retention.dayDays} d`),
      kvRow('Event log', `${retention.eventDays} d`, 'errors, alerts, player events')
    );
  }

  /* --------------------------------------------------------------------- *
   * Security
   * --------------------------------------------------------------------- */

  function renderSecurity(data) {
    const status = data.status || {};
    statGrid($('sec-kpis'), [
      { label: 'Requests', value: fmtNum(status.requests), sub: rangeLabel(data.range), tone: '' },
      { label: '4xx', value: fmtNum(status.s4xx), sub: 'client errors', tone: status.s4xx ? 'warn' : '' },
      { label: '5xx', value: fmtNum(status.s5xx), sub: 'upstream / origin', tone: status.s5xx ? 'bad' : 'good' },
      { label: '403', value: fmtNum(status.s403), sub: 'blocked embeds', tone: status.s403 ? 'warn' : '' },
      { label: '404', value: fmtNum(status.s404), sub: 'not found / scans', tone: status.s404 ? 'warn' : '' },
      { label: '429', value: fmtNum(status.s429), sub: 'rate limited', tone: status.s429 ? 'warn' : '' },
      { label: '499', value: fmtNum(status.s499), sub: 'client closed', tone: '' },
      { label: 'Admin denied', value: fmtNum(status.adminDenied), sub: 'non-allowlisted IPs', tone: status.adminDenied ? 'warn' : 'good' }
    ]);

    const recent = data.recent || [];
    $('sec-events-hint').textContent = `${recent.length} events · ${rangeLabel(data.range)}`;
    const list = $('sec-events');
    list.replaceChildren();
    if (!recent.length) {
      list.append(empty('No player errors, collector warnings or blocked admin attempts in this window.', 'Quiet'));
      return;
    }
    for (const event of recent) {
      const tone = event.level === 'error' ? 'bad' : event.level === 'warn' ? 'warn' : 'muted';
      list.append(h('div', { class: 'list-row' },
        h('div', { class: 'list-main' },
          h('div', { class: 'list-title', text: event.message }),
          h('div', { class: 'list-sub', text: `${event.source} · ${event.kind} · ${fmtClock(event.ts)}` })
        ),
        h('div', { class: 'list-main' },
          pill(event.level, tone),
          h('span', { class: 'list-sub', text: fmtAgo(event.ts) })
        )
      ));
    }
  }

  /* --------------------------------------------------------------------- *
   * Data
   * --------------------------------------------------------------------- */

  function renderData(data) {
    const db = data.db || {};
    const rows = db.rows || {};
    const retention = data.retention || {};
    const edge = data.edge || {};
    const ingest = data.ingest || {};
    const lastPrune = data.lastPrune;
    const usage = db.maxMB ? (db.sizeMB / db.maxMB) * 100 : 0;
    const totalRows = sumOf(Object.values(rows));

    statGrid($('data-kpis'), [
      { label: 'Database size', value: fmtBytes(db.sizeMB * MB), sub: `cap ${db.maxMB} MB`, tone: usage >= 80 ? 'bad' : usage >= 60 ? 'warn' : 'good' },
      { label: 'Usage', value: fmtPct(usage), sub: 'of configured cap', tone: usage >= 80 ? 'bad' : usage >= 60 ? 'warn' : '' },
      { label: 'Stored rows', value: fmtNum(totalRows), sub: 'all tables', tone: '' },
      { label: 'Last prune', value: lastPrune && lastPrune.ts ? fmtAgo(lastPrune.ts) : '—', sub: 'runs every 15 minutes', tone: lastPrune && lastPrune.emergency ? 'warn' : '' }
    ]);

    const usageBlock = $('data-usage');
    usageBlock.replaceChildren(barRow('Database', `${db.sizeMB} MB / ${db.maxMB} MB`, usage / 100, usage >= 80 ? 'danger' : usage >= 60 ? 'warn' : 'success'));
    $('data-usage-hint').textContent = lastPrune && lastPrune.overCap ? 'over cap — emergency pruning active' : 'WAL mode · collector-only writes';

    const pruneItems = [];
    if (lastPrune) {
      const removable = Object.entries(lastPrune)
        .filter(([key, value]) => !['size', 'cap', 'overCap', 'emergency', 'ts'].includes(key) && typeof value === 'number')
        .reduce((sum, [, value]) => sum + value, 0);
      pruneItems.push({ label: 'Rows removed', value: fmtNum(removable) });
      pruneItems.push({ label: 'Size after', value: fmtBytes(lastPrune.size) });
      pruneItems.push({ label: 'Emergency mode', value: lastPrune.emergency ? 'yes' : 'no' });
      pruneItems.push({ label: 'Ran', value: lastPrune.ts ? fmtAgo(lastPrune.ts) : '—' });
    }
    miniGrid($('data-prune'), pruneItems.length ? pruneItems : [{ label: 'Prune', value: 'not yet run', dim: true }]);

    const rowEntries = Object.entries(rows);
    $('data-rows-hint').textContent = `${rowEntries.length} tables`;
    const rowsTable = buildTable(
      [{ label: 'Table' }, { label: 'Rows', num: true }],
      rowEntries.map(([key, value]) => h('tr', {}, td(ROW_LABELS[key] || key), td(fmtNum(value), 'num')))
    );
    $('data-rows').replaceChildren(rowsTable);

    const retentionTable = buildTable(
      [{ label: 'Data' }, { label: 'Kept' }],
      [
        ['Raw worker snapshots', `${retention.rawHours} h`],
        ['Raw request events', `${retention.rawRequestHours} h`],
        ['Minute rollups', `${retention.minuteDays} d`],
        ['Hour rollups', `${retention.hourDays} d`],
        ['Daily rollups', `${retention.dayDays} d`],
        ['Event log', `${retention.eventDays} d`]
      ].map(([label, value]) => h('tr', {}, td(label), td(value, 'num')))
    );
    $('data-retention').replaceChildren(retentionTable);

    $('data-edge-hint').textContent = edge.enabled ? (edge.running ? 'tailing' : 'stopped') : 'disabled';
    const edgeList = $('data-edge');
    edgeList.replaceChildren(
      kvRow('Log path', edge.path || 'ADMIN_EDGE_LOG not set', edge.error || 'nginx JSON access log'),
      kvRow('Running', edge.running ? 'yes' : 'no', `since ${fmtAgo(edge.startedAt)}`),
      kvRow('Lines read', fmtNum(edge.lines), `${fmtNum(edge.parsed)} parsed · ${fmtNum(edge.bad)} invalid`),
      kvRow('Read offset', fmtBytes(edge.offset), `last line ${fmtAgo(edge.lastLineAt)}`),
      kvRow('Sampled out', fmtNum(edge.droppedLogs), 'writer budget protection'),
      kvRow('Last poll', fmtAgo(edge.lastPollAt), edge.error || 'polling every 2 s')
    );

    $('data-ingest-hint').textContent = ingest.telemetryEnabled ? 'active' : 'telemetry off';
    const ingestList = $('data-ingest');
    ingestList.replaceChildren(
      kvRow('Player telemetry', ingest.telemetryEnabled ? 'enabled' : 'disabled', ingest.telemetryEnabled ? 'sendBeacon every 30 s' : 'set ADMIN_TELEMETRY=1'),
      kvRow('Active sessions', fmtNum(ingest.activeSessions), `${fmtNum(ingest.sessionsTracked)} tracked overall`),
      kvRow('Last boot', fmtAgo(ingest.lastBootAt), 'new player session'),
      kvRow('Last beacon', fmtAgo(ingest.lastTelemetryAt), 'heartbeat or event'),
      kvRow('Dropped events', fmtNum(ingest.droppedEvents), 'per-second budget'),
      kvRow('Worker ingest', ingest.telemetryEnabled ? 'token protected' : 'token protected', 'loopback snapshots')
    );

    $('data-settings-hint').textContent = 'from the collector environment';
    miniGrid($('data-settings'), [
      { label: 'Snapshot interval', value: `${Math.round(data.snapshotMs / 1000)} s` },
      { label: 'Log sample', value: `${(data.logSample * 100).toFixed(1)} %` },
      { label: 'Origin cap', value: fmtNum(data.originMax) },
      { label: 'Title cap', value: fmtNum(data.titleMax) },
      { label: 'DB cap', value: `${data.db.maxMB} MB` }
    ]);
  }

  /* --------------------------------------------------------------------- *
   * Navigation, SSE, wiring
   * --------------------------------------------------------------------- */

  function buildRangeSwitch(ranges) {
    const wrap = $('range-switch');
    wrap.replaceChildren();
    wrap.hidden = !ranges;
    if (!ranges) return;
    if (!ranges.includes(state.range)) {
      state.range = ranges.includes('24h') ? '24h' : ranges[0];
    }
    for (const range of ranges) {
      wrap.append(h('button', {
        class: 'range-btn' + (range === state.range ? ' active' : ''),
        type: 'button',
        text: range,
        onClick: () => {
          if (state.range === range) return;
          state.range = range;
          buildRangeSwitch(ranges);
          loadPage();
        }
      }));
    }
  }

  function setPage(name) {
    if (!PAGE_META[name]) return;
    state.page = name;
    for (const section of document.querySelectorAll('.page')) {
      section.hidden = section.id !== `page-${name}`;
    }
    for (const button of document.querySelectorAll('.nav-item')) {
      button.classList.toggle('active', button.dataset.page === name);
    }
    $('page-title').textContent = PAGE_META[name].title;
    $('page-subtitle').textContent = PAGE_META[name].subtitle;
    buildRangeSwitch(PAGE_META[name].ranges);
    if (location.hash !== `#${name}`) history.replaceState(null, '', `#${name}`);
    hideError();
    state.lastLoad = 0;
    loadPage();
  }

  function setConn(status) {
    $('conn').className = 'conn ' + status;
    $('conn-text').textContent = status === 'live' ? 'Live · 30 s' : status === 'down' ? 'Disconnected' : 'Reconnecting';
  }

  function applyTick(tick) {
    setChips({
      activeViewers: tick.activeViewers,
      onlineWorkers: tick.onlineWorkers,
      expectedWorkers: tick.expectedWorkers,
      alerts: tick.alerts,
      critical: tick.critical
    });
    state.sseLive = true;
    setConn('live');
  }

  function connectSse() {
    if (!window.EventSource) {
      setConn('down');
      return;
    }
    let source;
    try {
      source = new EventSource('/admin/api/events');
    } catch {
      setConn('down');
      return;
    }
    source.addEventListener('ready', () => {
      state.sseLive = true;
      setConn('live');
    });
    source.addEventListener('tick', (event) => {
      try {
        applyTick(JSON.parse(event.data));
      } catch { /* ignore malformed tick */ }
      maybeAutoRefresh();
    });
    source.onerror = () => {
      state.sseLive = false;
      setConn('pending');
    };
  }

  function wireStatic() {
    for (const button of document.querySelectorAll('.nav-item')) {
      button.addEventListener('click', () => setPage(button.dataset.page));
    }
    for (const link of document.querySelectorAll('[data-goto]')) {
      link.addEventListener('click', () => setPage(link.dataset.goto));
    }
    $('refresh-btn').addEventListener('click', () => loadPage({ force: true }));

    $('sites-search').addEventListener('input', (event) => {
      state.filters.sites = event.target.value.trim().toLowerCase();
      if (state.sites) renderSites(state.sites);
    });
    $('content-search').addEventListener('input', (event) => {
      state.filters.titles = event.target.value.trim().toLowerCase();
      if (state.content) renderContent(state.content);
    });

    for (const button of document.querySelectorAll('#logs-levels button')) {
      button.addEventListener('click', () => {
        if (state.logs.level === button.dataset.level) return;
        state.logs.level = button.dataset.level;
        state.logs.pinned = false;
        loadLogs(true);
      });
    }
    $('logs-source').addEventListener('change', (event) => {
      state.logs.source = event.target.value;
      state.logs.pinned = false;
      loadLogs(true);
    });
    let searchTimer = null;
    $('logs-search').addEventListener('input', (event) => {
      const value = event.target.value.trim();
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => {
        state.logs.q = value;
        state.logs.pinned = false;
        loadLogs(true);
      }, 350);
    });

    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) maybeAutoRefresh();
    });

    window.addEventListener('hashchange', () => {
      const name = location.hash.replace('#', '');
      if (PAGE_META[name] && name !== state.page) setPage(name);
    });
  }

  function init() {
    if (typeof window.Charts === 'undefined') {
      console.error('Charts library not loaded');
      $('error-banner').textContent = 'Charts library failed to load. Please refresh the page.';
      $('error-banner').hidden = false;
      return;
    }
    wireStatic();
    connectSse();
    setConn('pending');
    const initial = location.hash.replace('#', '');
    setPage(PAGE_META[initial] ? initial : 'overview');
    setInterval(updateUpdatedLabel, 5000);
    setInterval(maybeAutoRefresh, FALLBACK_MS);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
