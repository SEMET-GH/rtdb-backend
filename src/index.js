import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { secureHeaders } from 'hono/secure-headers';

/* ==================== CONFIG ==================== */
const ALLOW_ORIGINS = new Set([
  'https://radartambon.pages.dev',
  'https://www.radartambon.com',
  'https://sites.google.com/view/radartambon',
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:4321',
  'http://localhost:4173',
  'http://127.0.0.1:5500',
  'http://127.0.0.1:5501',
  'http://127.0.0.1:5502'
]);

const FRAME_ANCESTORS = [
  'https://www.radartambon.com',
  'https://sites.google.com/view/radartambon'
];

const VALID_API_TOKENS = new Set([
  'vtsc-48583-secure-proxy-token-2025'
]);

const ALLOWED_TARGET_DOMAINS = new Set([
  'weather.tmd.go.th',
  'file.royalrain.go.th',
  'weather.bangkok.go.th',
  'pub-0160c42dd9644410895efe9a57af188e.r2.dev'
]);

const ALLOW_RADAR_HOSTS = new Set([
  'weather.tmd.go.th',
  'weather.bangkok.go.th'
]);

/* ==================== APP ==================== */
const app = new Hono();

/* ========== Utilities: security & headers ========== */
function isAllowedOrigin(origin) {
  return !!origin && ALLOW_ORIGINS.has(origin);
}
function baseHeaders(origin) {
  const h = new Headers();
  h.set('Vary', 'Origin, Access-Control-Request-Headers, User-Agent');
  h.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  h.set('X-Content-Type-Options', 'nosniff');
  if (origin && isAllowedOrigin(origin)) {
    h.set('Access-Control-Allow-Origin', origin);
    h.set('Access-Control-Allow-Credentials', 'true');
  }
  return h;
}
function addCors(headers, req) {
  const allow = req.headers.get('Access-Control-Request-Headers') ||
    'Content-Type, X-Requested-With, X-API-Token, Authorization';
  headers.set('Access-Control-Allow-Methods', 'GET, HEAD, POST, OPTIONS');
  headers.set('Access-Control-Allow-Headers', allow);
  headers.set('Access-Control-Expose-Headers', 'Radar-Time, Latest-Fetch');
}
function addIframeHeaders(headers) {
  headers.set('X-Frame-Options', 'SAMEORIGIN');
  const allowedOriginsString = Array.from(FRAME_ANCESTORS).join(' ');
  headers.set('Content-Security-Policy', `frame-ancestors 'self' ${allowedOriginsString};`);
}
function denyHeaders() {
  const h = new Headers();
  h.set('Content-Type', 'application/json; charset=utf-8');
  h.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  h.set('X-Frame-Options', 'DENY');
  h.set('Vary', 'Origin, Access-Control-Request-Headers, User-Agent');
  return h;
}
function jerr(code, msg, hdrs) {
  const h = hdrs ? new Headers(hdrs) : denyHeaders();
  h.set('Content-Type', 'application/json; charset=utf-8');
  return new Response(JSON.stringify({ error: msg, timestamp: new Date().toISOString() }, null, 2), { status: code, headers: h });
}
function sanitizeRequestHeaders(headers) {
  const sanitized = new Headers();
  const allowed = ['accept', 'accept-encoding', 'accept-language', 'cache-control', 'content-type', 'user-agent'];
  for (const [k, v] of headers.entries()) {
    if (allowed.includes(k.toLowerCase())) sanitized.set(k, v);
  }
  return sanitized;
}
function validateTargetUrl(targetUrl) {
  try {
    const u = new URL(targetUrl);
    if (u.protocol !== 'https:' && u.hostname !== 'localhost' && u.hostname !== '127.0.0.1') {
      return { valid: false, reason: 'Only HTTPS URLs allowed' };
    }
    const blocked = [
      /^localhost$/i, /^127\./, /^192\.168\./, /^10\./, /^172\.(1[6-9]|2[0-9]|3[01])\./, /^169\.254\./, /^0\./
    ];
    const isDev = true;
    if (!isDev) {
      const host = u.hostname;
      if (blocked.some(re => re.test(host))) return { valid: false, reason: 'Private/local addresses not allowed' };
    }
    if (ALLOWED_TARGET_DOMAINS.size > 0) {
      const host = u.hostname.toLowerCase();
      const ok = Array.from(ALLOWED_TARGET_DOMAINS).some(d => host === d || host.endsWith('.' + d));
      if (!ok) return { valid: false, reason: 'Target domain not allowed' };
    }
    const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf'];
    if (suspiciousTlds.some(tld => u.hostname.toLowerCase().endsWith(tld))) {
      return { valid: false, reason: 'Suspicious domain detected' };
    }
    return { valid: true };
  } catch {
    return { valid: false, reason: 'Invalid URL format' };
  }
}

/* ========== Frame policy helpers ========== */
function getFrameMode(env, key, fallback) {
  const v = (env && env[key] ? String(env[key]) : '').toLowerCase();
  if (v === 'allow' || v === 'deny') return v;
  return fallback;
}
function framePolicy(mode, allowed) {
  return mode === 'allow'
    ? secureHeaders({
      xFrameOptions: 'SAMEORIGIN',
      contentSecurityPolicy: { 'frame-ancestors': `'self' ${allowed.join(' ')}` }
    })
    : secureHeaders({ xFrameOptions: 'DENY' });
}

/* ========== Radar helpers (เหมือนเดิม) ========== */
const stationDelayMin = {
  chn: 2.5, skm: 4.5, cri: 4, lmp: 4, phs: 4.5, tak: 6.5, kkn: 5.5, skn: 6.5,
  cmp: 6.5, pkt: 6.5, rng: 6.5, srt: 5.1, stp: 6.5, hyi: 5.1, trg: 6.5,
};
function getRadarPreset(kind, radarUrl = '') {
  const key = (kind || 'tmd').toLowerCase();
  switch (key) {
    case 'bkk': return { release: [0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55], delayMs: 2 * 60 * 1000 };
    case 'tmd120': return { release: [10, 20, 40, 50], delayMs: 5 * 60 * 1000 };
    case 'tmd':
    default: {
      const release = [0, 15, 30, 45];
      let delayMs = 6.5 * 60 * 1000;
      const urlL = String(radarUrl || '').toLowerCase();
      for (const st of Object.keys(stationDelayMin)) {
        if (urlL.includes(st)) { delayMs = stationDelayMin[st] * 60 * 1000; break; }
      }
      return { release, delayMs };
    }
  }
}
function getPeriodMinutes(release) {
  const s = [...release].sort((a, b) => a - b);
  if (s.length <= 1) return 0;
  let g = Infinity;
  for (let i = 1; i < s.length; i++) g = Math.min(g, s[i] - s[i - 1]);
  const wrap = (60 - s[s.length - 1]) + s[0];
  return Math.min(g, wrap);
}
function calcRadarTimeFlexible(lastModifiedRaw, release, delayMs) {
  const slots = [...release].sort((a, b) => a - b);
  let base = lastModifiedRaw ? new Date(lastModifiedRaw) : new Date(Date.now() - delayMs);
  if (isNaN(base.getTime())) return null;
  const cand = [];
  for (const off of [0, -1]) {
    const h = new Date(base); h.setHours(h.getHours() + off, 0, 0, 0);
    for (const m of slots) cand.push(new Date(h.getFullYear(), h.getMonth(), h.getDate(), h.getHours(), m, 0, 0));
  }
  let best = null;
  for (const mt of cand) if (mt <= base && (!best || mt > best)) best = mt;
  if (!best) return null;
  if (lastModifiedRaw) {
    const period = getPeriodMinutes(slots);
    if (period > 0) {
      const diff = (base.getTime() - best.getTime()) / 60000;
      if (diff >= period) best = new Date(best.getTime() - period * 60 * 1000);
    }
  }
  return best;
}

/* ========== RYRRadar helpers (เหมือนเดิม) ========== */
function getRadarStationKey(shortCode) {
  const map = {
    OMK: 'omkoi', RKG: 'rongkwang', RSL: 'rasisalai', SHN: 'singha', PMI: 'phimai',
    BPH: 'banphue', SAT: 'sattahip', PTH: 'pathio', PNM: 'phanom', INB: 'inburi',
    TKH: 'takhli', PDG: 'pluakdaeng'
  };
  return map[shortCode.toUpperCase()] || null;
}
function getRadarStationName(key, lang = "th") {
  const stations = {
    omkoi: { th: 'อมก๋อย', en: 'Omkoi' },
    rongkwang: { th: 'ร้องกวาง', en: 'Rong Kwang' },
    rasisalai: { th: 'ราษีไศล', en: 'Rasisalai' },
    singha: { th: 'สิงหนคร', en: 'Singhanakhon' },
    phimai: { th: 'พิมาย', en: 'Phimai' },
    banphue: { th: 'บ้านผือ', en: 'Ban Phue' },
    sattahip: { th: 'สัตหีบ', en: 'Sattahip' },
    pathio: { th: 'ปะทิว', en: 'Pathio' },
    phanom: { th: 'พนม', en: 'Phanom' },
    inburi: { th: 'อินทร์บุรี', en: 'In Buri' },
    takhli: { th: 'ตาคลี', en: 'Takhli' },
    pluakdaeng: { th: 'ปลวกแดง', en: 'Pluak Daeng' }
  };
  const s = stations[key];
  return s ? (s[lang] || s["th"]) : '';
}
async function fetchViaAccess(env, key) {
  const url = `${env.PROXY_BASE}/${key}`;
  const res = await fetch(url, {
    headers: {
      'CF-Access-Client-Id': env.CF_ACCESS_CLIENT_ID,
      'CF-Access-Client-Secret': env.CF_ACCESS_CLIENT_SECRET
    },
    cf: { cacheTtl: 30, cacheEverything: true }
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`HTTP ${res.status}: ${body || res.statusText}`);
  }
  const updated = res.headers.get('last-modified') || res.headers.get('x-amz-meta-last-modified');
  const json = await res.json();
  return { json, updated };
}

/* ==================== Global middlewares (Hono) ==================== */

// 1) Security headers (default DENY; ค่อย override per-route)
app.use('*', secureHeaders({
  xFrameOptions: 'DENY',
  referrerPolicy: 'strict-origin-when-cross-origin',
  xContentTypeOptions: 'nosniff'
}));

// 2) CORS (ตาม allowlist)
app.use('*', cors({
  origin: (origin) => isAllowedOrigin(origin) ? origin : '',
  allowMethods: ['GET', 'HEAD', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'X-Requested-With', 'X-API-Token', 'Authorization'],
  exposeHeaders: ['Radar-Time', 'Latest-Fetch'],
  credentials: true,
  maxAge: 86400
}));

// 3) Request guard (แทน validateRequest; คง API token bypass)
app.use('*', async (c, next) => {
  const req = c.req.raw;
  const origin = req.headers.get('Origin');
  const referer = req.headers.get('Referer') || '';
  const sSite = req.headers.get('Sec-Fetch-Site');
  const sMode = req.headers.get('Sec-Fetch-Mode');
  const apiToken = req.headers.get('X-API-Token');

  if (apiToken && VALID_API_TOKENS.has(apiToken)) return next();

  if (!origin) return c.body(jerr(403, 'Origin header required for browser requests').body, 403, jerr(403, '').headers);
  if (!isAllowedOrigin(origin)) return c.body(jerr(403, `Origin '${origin}' not allowed`).body, 403, jerr(403, '').headers);
  if (referer && !referer.startsWith(origin)) return c.body(jerr(403, 'Invalid referer header').body, 403, jerr(403, '').headers);
  if (!sSite || !sMode) return c.body(jerr(403, 'Missing required browser security headers').body, 403, jerr(403, '').headers);

  return next();
});

/* ==================== Common OPTIONS (เก็บพฤติกรรมเดิม) ==================== */
app.options('*', (c) => {
  const req = c.req.raw;
  const h = baseHeaders(req.headers.get('Origin'));
  addCors(h, req);
  h.set('Access-Control-Max-Age', '86400');
  h.set('X-Frame-Options', 'DENY');
  return new Response(null, { status: 204, headers: h });
});

/* ==================== 1) /proxy ==================== */
app.all('/proxy', async (c) => {
  const req = c.req.raw;
  if (req.method === 'OPTIONS') return c.notFound();

  const mode = getFrameMode(c.env, 'FRAME_PROXY', 'deny');
  await framePolicy(mode, Array.from(FRAME_ANCESTORS))(c, async () => { });

  const url = new URL(req.url);
  const targetUrl = url.searchParams.get('url');

  const headers = baseHeaders(req.headers.get('Origin'));
  addCors(headers, req);
  if (mode === 'allow') addIframeHeaders(headers); else headers.set('X-Frame-Options', 'DENY');

  if (!targetUrl) return jerr(400, "Missing 'url' query parameter", headers);

  const decoded = decodeURIComponent(targetUrl);
  const chk = validateTargetUrl(decoded);
  if (!chk.valid) return jerr(400, chk.reason, headers);

  const cache = caches.default;
  const cacheKey = new Request(req.url, { method: req.method, headers: req.headers });
  const hit = await cache.match(cacheKey);
  if (hit) {
    const h2 = new Headers(hit.headers);
    addCors(h2, req);
    if (mode === 'allow') addIframeHeaders(h2); else h2.set('X-Frame-Options', 'DENY');
    h2.set('X-Content-Type-Options', 'nosniff');
    return new Response(hit.body, { status: hit.status, statusText: hit.statusText, headers: h2 });
  }

  try {
    const upstream = await fetch(decoded, {
      method: req.method,
      headers: sanitizeRequestHeaders(req.headers),
      body: (req.method !== 'GET' && req.method !== 'HEAD') ? req.body : null
    });

    const respHeaders = new Headers(upstream.headers);
    addCors(respHeaders, req);
    if (mode === 'allow') addIframeHeaders(respHeaders); else respHeaders.set('X-Frame-Options', 'DENY');
    respHeaders.set('X-Content-Type-Options', 'nosniff');
    respHeaders.set('Cache-Control', 'public, max-age=0, s-maxage=30, must-revalidate');

    const proxied = new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers: respHeaders });

    if (req.method === 'GET') c.executionCtx.waitUntil(cache.put(cacheKey, proxied.clone()));
    return proxied;
  } catch (err) {
    return jerr(500, `Proxy error: ${err.message}`, headers);
  }
});

/* ==================== 2) /tmdradar ==================== */
app.all('/tmdradar', async (c) => {
  const req = c.req.raw;
  if (req.method === 'OPTIONS') return c.notFound();

  const mode = getFrameMode(c.env, 'FRAME_RADAR', 'allow');
  await framePolicy(mode, Array.from(FRAME_ANCESTORS))(c, async () => { });

  const url = new URL(req.url);
  const imageUrl = url.searchParams.get('radarurl');
  const radarKind = (url.searchParams.get('radar') || 'tmd').toLowerCase();

  const headers = baseHeaders(req.headers.get('Origin'));
  addCors(headers, req);
  if (mode === 'allow') addIframeHeaders(headers); else headers.set('X-Frame-Options', 'DENY');

  if (!imageUrl) return jerr(400, 'Incomplete parameters: use ?radarurl=...&radar=tmd|bkk|tmd120', headers);

  let radarUrl;
  try { radarUrl = new URL(imageUrl); }
  catch { return jerr(400, 'Invalid image URL format', headers); }

  if (!['http:', 'https:'].includes(radarUrl.protocol)) {
    return jerr(400, 'Unsupported protocol (only http/https)', headers);
  }
  if (!ALLOW_RADAR_HOSTS.has(radarUrl.hostname)) {
    return new Response(JSON.stringify({
      error: 'Image host not allowed',
      allowed_hosts: Array.from(ALLOW_RADAR_HOSTS)
    }, null, 2), { status: 400, headers });
  }

  const cache = caches.default;
  const cacheKeyUrl = new URL(req.url);
  const origin = req.headers.get('Origin');
  cacheKeyUrl.searchParams.set('__o', origin && isAllowedOrigin(origin) ? origin : 'no-origin');
  const cacheKey = new Request(cacheKeyUrl.toString(), { method: 'GET' });

  if (req.method === 'GET') {
    const hit = await cache.match(cacheKey);
    if (hit) return hit;
  }

  radarUrl.searchParams.set('cb', Date.now().toString());
  const upstream = await fetch(radarUrl.toString(), {
    cf: { cacheEverything: false, cacheTtl: 0 },
    headers: {
      'User-Agent': req.headers.get('User-Agent') ?? 'Mozilla/5.0 (compatible; RadarProxy/1.0)',
      'Accept': 'image/avif,image/webp,image/*,*/*;q=0.8',
      'Referer': url.origin
    }
  });

  if (!upstream.ok) {
    const body = await upstream.text().catch(() => '');
    const h = new Headers(headers); h.set('Cache-Control', 'no-store');
    return new Response(JSON.stringify({
      error: 'Upstream fetch failed',
      status: upstream.status,
      details: body || upstream.statusText
    }, null, 2), { status: upstream.status >= 400 ? upstream.status : 502, headers: h });
  }

  const preset = getRadarPreset(radarKind, imageUrl);
  const periodMin = getPeriodMinutes(preset.release);
  const lastModifiedRaw = upstream.headers.get('Last-Modified');
  const radarTime = calcRadarTimeFlexible(lastModifiedRaw, preset.release, preset.delayMs);

  const now = new Date();
  let ttlSeconds = 60;
  if (radarTime) {
    const base = lastModifiedRaw ? new Date(lastModifiedRaw) : new Date(now.getTime() - preset.delayMs);
    const offsetMs = base.getTime() - radarTime.getTime();
    const nextSlot = new Date(radarTime.getTime() + periodMin * 60 * 1000);
    const expireTime = new Date(nextSlot.getTime() + offsetMs - 1 * 60 * 1000);
    const TTL_CAP = Math.max(0, periodMin * 60 - 60);
    ttlSeconds = Math.min(TTL_CAP, Math.max(0, Math.floor((expireTime.getTime() - now.getTime()) / 1000)));
  }

  const respHeaders = new Headers(headers);
  respHeaders.set('Content-Type', upstream.headers.get('Content-Type') || 'application/octet-stream');
  respHeaders.set('Latest-Fetch', now.toISOString());
  if (radarTime) respHeaders.set('Radar-Time', radarTime.toISOString());
  respHeaders.set('Cache-Control', `public, max-age=10, s-maxage=${ttlSeconds}, must-revalidate`);

  if (req.method === 'HEAD') return new Response(null, { status: 200, headers: respHeaders });

  const body = await upstream.arrayBuffer();
  const resp = new Response(body, { status: 200, headers: respHeaders });

  if (req.method === 'GET' && ttlSeconds > 0) {
    try { c.executionCtx.waitUntil(cache.put(cacheKey, resp.clone())); } catch { }
  }
  return resp;
});

/* ==================== 3) /ryrradar & /ryrradar/:code ==================== */
app.get('/ryrradar', async (c) => {
  const req = c.req.raw;
  const mode = getFrameMode(c.env, 'FRAME_RYRRADAR', 'allow');
  await framePolicy(mode, Array.from(FRAME_ANCESTORS))(c, async () => { });

  const headers = baseHeaders(req.headers.get('Origin'));
  addCors(headers, req);
  if (mode === 'allow') addIframeHeaders(headers); else headers.set('X-Frame-Options', 'DENY');

  try {
    const { json, updated } = await fetchViaAccess(c.env, 'radar/ryrradar.json');
    const response = new Response(JSON.stringify({
      source: "https://catalog.royalrain.go.th/gl/dataset/drraa_12_01",
      updated: updated || new Date().toISOString(),
      data: json
    }, null, 2), { status: 200, headers });
    c.executionCtx.waitUntil(caches.default.put(req, response.clone()));
    return response;
  } catch (err) {
    return jerr(500, `Upstream fetch failed: ${err.message}`, headers);
  }
});

app.get('/ryrradar/:code', async (c) => {
  const req = c.req.raw;
  const mode = getFrameMode(c.env, 'FRAME_RYRRADAR', 'allow');
  await framePolicy(mode, Array.from(FRAME_ANCESTORS))(c, async () => { });

  const headers = baseHeaders(req.headers.get('Origin'));
  addCors(headers, req);
  if (mode === 'allow') addIframeHeaders(headers); else headers.set('X-Frame-Options', 'DENY');

  const shortCode = c.req.param('code').toUpperCase();
  const radarKey = getRadarStationKey(shortCode);
  if (!radarKey) return jerr(400, 'Invalid radar station code', headers);

  try {
    const { json, updated } = await fetchViaAccess(c.env, 'radar/ryrradar.json');
    if (!json || !json[radarKey]) return jerr(404, 'No radar data for this station', headers);

    const response = new Response(JSON.stringify({
      station_code: shortCode,
      station: { th: getRadarStationName(radarKey, "th"), en: getRadarStationName(radarKey, "en") },
      source: "https://catalog.royalrain.go.th/gl/dataset/drraa_12_01",
      updated: updated || new Date().toISOString(),
      data: json[radarKey]
    }, null, 2), { status: 200, headers });
    c.executionCtx.waitUntil(caches.default.put(req, response.clone()));
    return response;
  } catch (err) {
    return jerr(500, `Upstream fetch failed: ${err.message}`, headers);
  }
});

/* ==================== Export Worker ==================== */
export default {
  fetch: (request, env, ctx) => app.fetch(request, env, ctx)
};
