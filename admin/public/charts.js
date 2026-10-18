'use strict';

/* ============================================================================
 * Admin dashboard charts — dependency-free canvas renderer.
 * Supplied by the collector at /admin/assets/charts.js under a strict CSP,
 * so everything here is self-contained: no fonts, no images, no inline HTML.
 * ==========================================================================*/

(function () {
  const MONO = '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
  const palette = {
    white: '#ffffff',
    accent: '#818cf8',
    success: '#10b981',
    warn: '#f59e0b',
    danger: '#ef4444',
    cyan: '#22d3ee',
    grid: 'rgba(255, 255, 255, 0.055)',
    axis: '#5f5f66',
    muted: '#6b6b72'
  };

  const nf = new Intl.NumberFormat('en-US');

  function niceMax(value) {
    if (!Number.isFinite(value) || value <= 0) return 1;
    const exp = Math.pow(10, Math.floor(Math.log10(value)));
    const norm = value / exp;
    const step = norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 2.5 ? 2.5 : norm <= 5 ? 5 : 10;
    return step * exp;
  }

  function alpha(color, a) {
    const hex = String(color).replace('#', '');
    if (hex.length !== 6) return color;
    const r = parseInt(hex.slice(0, 2), 16);
    const g = parseInt(hex.slice(2, 4), 16);
    const b = parseInt(hex.slice(4, 6), 16);
    return `rgba(${r}, ${g}, ${b}, ${a})`;
  }

  function surface(canvas, opts) {
    const dpr = Math.min(2.5, window.devicePixelRatio || 1);
    let cssW = canvas.clientWidth;
    let cssH = canvas.clientHeight;
    if (!cssW) cssW = Number(opts.width) || 320;
    if (!cssH) cssH = Number(opts.height) || 230;
    canvas.width = Math.max(1, Math.round(cssW * dpr));
    canvas.height = Math.max(1, Math.round(cssH * dpr));
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cssW, cssH);
    return { ctx, w: cssW, h: cssH };
  }

  function observe(canvas, draw) {
    canvas.__chartDraw = draw;
    if (canvas.__chartObserver) return;
    const observer = new ResizeObserver(() => {
      if (!canvas.__chartDraw) return;
      window.requestAnimationFrame(() => {
        if (canvas.isConnected && canvas.__chartDraw) canvas.__chartDraw();
      });
    });
    observer.observe(canvas);
    canvas.__chartObserver = observer;
  }

  function emptyState(ctx, w, h, text) {
    ctx.fillStyle = palette.muted;
    ctx.font = `11px ${MONO}`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(text || 'No data yet', w / 2, h / 2);
    ctx.textAlign = 'left';
  }

  function sanitize(values) {
    return (values || []).map((v) => {
      const n = Number(v);
      return Number.isFinite(n) && n >= 0 ? n : 0;
    });
  }

  /* --------------------------------------------------------------------- *
   * Line / area chart
   * opts: { series: [{ values, color, fill, width }], x: [], xFormat,
   *         yFormat, max, min, ticks, emptyText }
   * --------------------------------------------------------------------- */
  function renderLine(canvas, opts) {
    const { ctx, w, h } = surface(canvas, opts);
    const series = (opts.series || []).map((s) => ({
      values: sanitize(s.values),
      color: s.color || palette.white,
      fill: s.fill !== false,
      width: s.width || 1.6
    })).filter((s) => s.values.length);
    const pointCount = series.reduce((max, s) => Math.max(max, s.values.length), 0);
    if (!pointCount) {
      emptyState(ctx, w, h, opts.emptyText);
      return;
    }

    const yFormat = opts.yFormat || ((v) => nf.format(Math.round(v)));
    const xFormat = opts.xFormat || ((v) => String(v));
    const font = `10px ${MONO}`;

    ctx.font = font;
    let maxValue = Number.isFinite(opts.max) ? opts.max : 0;
    if (!Number.isFinite(opts.max)) {
      for (const s of series) {
        for (const v of s.values) if (v > maxValue) maxValue = v;
      }
      maxValue = niceMax(maxValue);
    }
    maxValue = maxValue > 0 ? maxValue : 1;
    const minValue = Number.isFinite(opts.min) ? opts.min : 0;

    const yLabels = [];
    const ticks = Math.max(2, opts.ticks || 4);
    for (let i = 0; i <= ticks; i++) {
      const value = minValue + ((maxValue - minValue) * i) / ticks;
      yLabels.push(yFormat(value));
    }
    const labelWidth = Math.max(...yLabels.map((label) => ctx.measureText(label).width));
    const padLeft = Math.ceil(labelWidth) + 14;
    const padRight = 12;
    const padTop = 12;
    const padBottom = 26;
    const plotW = Math.max(10, w - padLeft - padRight);
    const plotH = Math.max(10, h - padTop - padBottom);

    const xOf = (i) => padLeft + (pointCount <= 1 ? plotW / 2 : (i / (pointCount - 1)) * plotW);
    const yOf = (v) => padTop + (1 - (Math.min(maxValue, Math.max(minValue, v)) - minValue) / (maxValue - minValue)) * plotH;

    ctx.lineWidth = 1;
    ctx.strokeStyle = palette.grid;
    ctx.fillStyle = palette.axis;
    ctx.font = font;
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    for (let i = 0; i <= ticks; i++) {
      const y = padTop + (1 - i / ticks) * plotH;
      ctx.beginPath();
      ctx.moveTo(padLeft, Math.round(y) + 0.5);
      ctx.lineTo(padLeft + plotW, Math.round(y) + 0.5);
      ctx.stroke();
      ctx.fillText(yLabels[i], padLeft - 8, y);
    }

    const xValues = Array.isArray(opts.x) ? opts.x : [];
    if (xValues.length) {
      const maxTicks = Math.max(2, Math.min(7, Math.floor(plotW / 88)));
      const stride = Math.max(1, Math.ceil((pointCount - 1) / Math.max(1, maxTicks - 1)));
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      let lastRight = -Infinity;
      for (let i = 0; i < pointCount; i += stride) {
        const label = xFormat(xValues[i]);
        const x = xOf(i);
        const width = ctx.measureText(label).width;
        if (x - width / 2 > lastRight + 10) {
          ctx.fillText(label, x, padTop + plotH + 8);
          lastRight = x + width / 2;
        }
      }
      if (pointCount > 1) {
        const label = xFormat(xValues[pointCount - 1]);
        const x = xOf(pointCount - 1);
        const width = ctx.measureText(label).width;
        if (x - width / 2 > lastRight + 10) ctx.fillText(label, x, padTop + plotH + 8);
      }
    }

    for (const s of series) {
      const n = s.values.length;
      const offset = pointCount - n;
      ctx.beginPath();
      for (let i = 0; i < n; i++) {
        const x = xOf(i + offset);
        const y = yOf(s.values[i]);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      if (s.fill) {
        const gradient = ctx.createLinearGradient(0, padTop, 0, padTop + plotH);
        gradient.addColorStop(0, alpha(s.color, 0.16));
        gradient.addColorStop(1, alpha(s.color, 0));
        ctx.save();
        ctx.lineTo(xOf(pointCount - 1), padTop + plotH);
        ctx.lineTo(xOf(offset), padTop + plotH);
        ctx.closePath();
        ctx.fillStyle = gradient;
        ctx.fill();
        ctx.restore();
      }
      ctx.beginPath();
      for (let i = 0; i < n; i++) {
        const x = xOf(i + offset);
        const y = yOf(s.values[i]);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.strokeStyle = s.color;
      ctx.lineWidth = s.width;
      ctx.lineJoin = 'round';
      ctx.lineCap = 'round';
      ctx.stroke();

      if (n === 1) {
        ctx.beginPath();
        ctx.arc(xOf(offset), yOf(s.values[0]), 2.5, 0, Math.PI * 2);
        ctx.fillStyle = s.color;
        ctx.fill();
      }
    }

    if (opts.live && pointCount > 1) {
      const s = series[0];
      const x = xOf(pointCount - 1);
      const y = yOf(s.values[s.values.length - 1]);
      ctx.beginPath();
      ctx.arc(x, y, 3, 0, Math.PI * 2);
      ctx.fillStyle = s.color;
      ctx.fill();
      ctx.beginPath();
      ctx.arc(x, y, 7, 0, Math.PI * 2);
      ctx.strokeStyle = alpha(s.color, 0.25);
      ctx.lineWidth = 2;
      ctx.stroke();
    }
  }

  function line(canvas, opts) {
    if (!canvas) return;
    const draw = () => renderLine(canvas, opts);
    observe(canvas, draw);
    draw();
  }

  /* --------------------------------------------------------------------- *
   * Sparkline (worker cards)
   * --------------------------------------------------------------------- */
  function renderSpark(canvas, opts) {
    const { ctx, w, h } = surface(canvas, opts);
    const values = sanitize(opts.values);
    if (values.length < 2) {
      ctx.strokeStyle = palette.grid;
      ctx.beginPath();
      ctx.moveTo(0, h - 2.5);
      ctx.lineTo(w, h - 2.5);
      ctx.stroke();
      return;
    }
    const color = opts.color || palette.white;
    const max = niceMax(Math.max(...values, 0.001));
    const pad = 3;
    const xOf = (i) => (i / (values.length - 1)) * w;
    const yOf = (v) => pad + (1 - v / max) * (h - pad * 2);

    const gradient = ctx.createLinearGradient(0, 0, 0, h);
    gradient.addColorStop(0, alpha(color, 0.2));
    gradient.addColorStop(1, alpha(color, 0));
    ctx.beginPath();
    values.forEach((v, i) => {
      const x = xOf(i);
      const y = yOf(v);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    ctx.fillStyle = gradient;
    ctx.fill();

    ctx.beginPath();
    values.forEach((v, i) => {
      const x = xOf(i);
      const y = yOf(v);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.4;
    ctx.lineJoin = 'round';
    ctx.stroke();
  }

  function spark(canvas, opts) {
    if (!canvas) return;
    const draw = () => renderSpark(canvas, opts);
    observe(canvas, draw);
    draw();
  }

  function release(root) {
    if (!root || !root.querySelectorAll) return;
    for (const canvas of root.querySelectorAll('canvas')) {
      if (canvas.__chartObserver) canvas.__chartObserver.disconnect();
      delete canvas.__chartObserver;
      delete canvas.__chartDraw;
    }
  }

  window.Charts = { line, spark, release, palette };
})();
