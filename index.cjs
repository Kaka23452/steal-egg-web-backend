'use strict';

const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const PORT = Number(process.env.PORT || 8080);
const JWT_SECRET = process.env.JWT_SECRET || '';
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || '';
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const DATABASE_URL = process.env.TIDB_DATABASE_URL || '';
const MAX_EVENTS = 100;
const sseClients = new Map();
const recentEvents = [];
const seenMessageIds = new Set();
let lastWebhookAt = null;
let lastMessage = null;
let dbPool = null;
let dbStatus = { connected: false, message: 'Database not initialized' };

app.disable('x-powered-by');
app.use(cors({
  origin(origin, callback) {
    if (!origin || ALLOWED_ORIGIN === '*' ||
        ALLOWED_ORIGIN.split(',').map(x => x.trim()).includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Origin not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type', 'Authorization', 'X-Webhook-Secret', 'X-API-Key'
  ]
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

// Wait for the one-time DB initialization before routes access dbPool.
app.use((req, res, next) => {
  ensureDatabaseInitialized().then(() => next()).catch((err) => {
    console.error('[request initialization]', err && err.message ? err.message : err);
    if (!res.headersSent) res.status(503).json({ success: false, error: 'Backend initialization failed' });
  });
});


function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''), 'utf8');
  const bb = Buffer.from(String(b || ''), 'utf8');
  return aa.length > 0 && aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function text(value) {
  if (value === undefined || value === null) return '';
  if (typeof value === 'string' || typeof value === 'number') {
    return String(value).trim();
  }
  return '';
}

function cleanText(value) {
  return text(value)
    .replace(/\[([^\]]+)\]\((?:https?:\/\/)?[^)]+\)/gi, '$1')
    .replace(/<@!?\d+>/g, '')
    .replace(/<#[0-9]+>/g, '')
    .replace(/<a?:[a-zA-Z0-9_]+:\d+>/g, '')
    .replace(/\*\*/g, '')
    .replace(/__/g, '')
    .replace(/~~/g, '')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/^\s{0,3}#{1,6}\s*/gm, '')
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .trim();
}

// Treat literal placeholders as missing values so they do not block fallback parsing.
function usableText(value) {
  const result = cleanText(value);
  if (!result || /^(unknown|none|n\/a|na|null|undefined)$/i.test(result)) {
    return '';
  }
  return result;
}

function labelValue(raw, labels) {
  const s = cleanText(raw).replace(/\r/g, '\n');

  for (const label of labels) {
    const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(
      '(?:^|\\n|\\s)' + escaped + '\\s*[:：-]\\s*([^\\n]+)',
      'i'
    );
    const m = s.match(re);

    if (m && m[1]) {
      return m[1].trim()
        .replace(/\s+(?:Location|Biome|Spawned|Time|Money|Tier|Rarity)\s*[:：-].*$/i, '')
        .trim();
    }
  }
  return '';
}

function inferTier(raw, explicit) {
  const known = [
    'SECRET', 'DIVINE', 'ETERNAL', 'COSMIC', 'TRANSCENDENT', 'MYTHIC',
    'LEGENDARY', 'EPIC', 'RARE', 'UNCOMMON', 'COMMON'
  ];
  const explicitText = usableText(explicit);

  if (explicitText) {
    const match = known.find(tier => tier.toLowerCase() === explicitText.toLowerCase());
    if (match) return match[0] + match.slice(1).toLowerCase();
  }

  const source = (text(explicit) + '\n' + cleanText(raw)).toUpperCase();
  for (const tier of known) {
    if (new RegExp('\\b' + tier + '\\b').test(source)) {
      return tier[0] + tier.slice(1).toLowerCase();
    }
  }
  return explicitText || 'Unknown';
}

function parseSpawn(body) {
  // Discord's embeds are also accepted directly, in addition to the raw text
  // sent by the Wispbyte bot. Prefer explicit, usable fields, then parse text.
  const embedParts = Array.isArray(body.embeds)
    ? body.embeds.flatMap(embed => [
        text(embed && embed.title),
        text(embed && embed.description),
        text(embed && embed.author && embed.author.name),
        text(embed && embed.footer && embed.footer.text),
        ...(Array.isArray(embed && embed.fields)
          ? embed.fields.flatMap(field => [
              text(field && field.name),
              text(field && field.value),
              field && field.name && field.value
                ? `${text(field.name)}: ${text(field.value)}`
                : ''
            ])
          : [])
      ])
    : [];

  const rawParts = [
    text(body.message),
    text(body.content),
    text(body.description),
    text(body.eggName),
    text(body.egg),
    text(body.petName),
    text(body.title),
    text(body.rawText),
    text(body.rawMessage),
    text(body.embedText),
    text(body.messageContent),
    ...embedParts
  ].filter(Boolean);

  const raw = cleanText(rawParts.join('\n'));
  const suppliedEgg = usableText(body.eggName) ||
    usableText(body.egg) ||
    usableText(body.petName);

  let eggName = labelValue(raw, [
    'Egg Name', 'Spawned Egg', 'Egg', 'Pet Name', 'Pet'
  ]);
  if (!usableText(eggName)) eggName = suppliedEgg;

  if (!usableText(eggName) && raw) {
    eggName = raw
      .replace(/^.*?\b(?:egg|pet)\s+(?:has\s+)?spawned\b\s*[:!—-]*/i, '')
      .replace(/^\s*(?:secret|divine|eternal|cosmic|transcendent|mythic|legendary|epic|rare|uncommon|common)\s+(?:egg\s+)?spawn(?:ed)?\s*[:!—-]*/i, '')
      .split(/\b(?:Location|Biome|Spawned|Time|Money|Tier|Rarity)\s*[:：-]/i)[0]
      .replace(/^\s*Egg\s*[:：-]\s*/i, '')
      .replace(/[|•]+\s*$/g, '')
      .trim();
  }

  // Unknown/blank supplied values must not suppress extraction from raw alert text.
  const location =
    usableText(body.location) ||
    usableText(body.biome) ||
    usableText(body.area) ||
    usableText(labelValue(raw, [
      'Location', 'Biome', 'Map', 'Area', 'Spawn Location', 'Spawned In',
      'Current Location', 'Current Biome', 'Biome Name', 'Location Name', 'Region'
    ])) ||
    'Unknown';

  const spawned =
    usableText(body.spawned) ||
    usableText(body.spawnedAgo) ||
    usableText(body.spawnedLabel) ||
    usableText(body.spawnTime) ||
    usableText(body.spawn_time_text) ||
    usableText(labelValue(raw, [
      'Spawned At', 'Spawned', 'Spawned Ago', 'Time Since Spawn', 'Spawn Time', 'Time'
    ])) ||
    'Unknown';

  const tier = inferTier(raw, body.tier || body.rarity);

  const discordUnix =
    spawned.match(/<t:(\d{9,12})(?::[tTdDfFR])?>/) ||
    raw.match(/<t:(\d{9,12})(?::[tTdDfFR])?>/);

  const elapsedMatch = spawned.match(
    /(\d+(?:\.\d+)?)\s*(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d)\s*ago/i
  );

  const explicitCandidate =
    body.spawnedAt ||
    body.spawned_at ||
    body.spawnTimestamp ||
    body.spawn_timestamp ||
    body.timestamp ||
    body.createdAt ||
    body.time;

  let parsedTimestamp;
  if (discordUnix) {
    parsedTimestamp = new Date(Number(discordUnix[1]) * 1000);
  } else if (elapsedMatch) {
    const n = Number(elapsedMatch[1]);
    const u = elapsedMatch[2].toLowerCase();
    const factor = /^(s|sec)/.test(u) ? 1000
      : /^(m|min)/.test(u) ? 60000
      : /^(h|hr|hour)/.test(u) ? 3600000
      : 86400000;
    parsedTimestamp = new Date(Date.now() - n * factor);
  } else {
    const candidate = explicitCandidate;
    parsedTimestamp = candidate
      ? new Date(
          typeof candidate === 'number' && candidate < 1e12
            ? candidate * 1000
            : candidate
        )
      : new Date();
  }

  const timestamp = Number.isFinite(parsedTimestamp.getTime())
    ? parsedTimestamp.toISOString()
    : new Date().toISOString();

  const messageId = text(body.messageId || body.message_id || '');
  const channelId = text(body.channelId || body.channel_id || '');
  const validEggName = usableText(eggName) || 'Unknown';

  return {
    eggName: validEggName,
    petName: validEggName,
    egg: validEggName,
    tier,
    location,
    biome: location,
    spawned,
    timestamp,
    time: timestamp,
    messageId,
    channelId,
    source: text(body.source || 'discord'),
    rawMessage: raw.slice(0, 4000),
    type: 'SPAWN',
    eventType: 'spawn',
    receivedAt: new Date().toISOString()
  };
}

function publishSpawn(body) {
  const event = parseSpawn(body || {});

  if (event.messageId && seenMessageIds.has(event.messageId)) {
    return {
      event,
      duplicate: true,
      connectedClients: sseClients.size
    };
  }

  if (event.messageId) {
    seenMessageIds.add(event.messageId);
    if (seenMessageIds.size > 2000) {
      seenMessageIds.delete(seenMessageIds.values().next().value);
    }
  }

  recentEvents.unshift(event);
  if (recentEvents.length > MAX_EVENTS) {
    recentEvents.length = MAX_EVENTS;
  }

  lastWebhookAt = new Date().toISOString();
  lastMessage = event;

  const eventTimestamp = new Date(event.timestamp).getTime();
  const packet = `data: ${JSON.stringify({
    ...event,
    type: 'SPAWN',
    id: event.messageId || crypto.randomUUID(),
    elapsedSeconds: Number.isFinite(eventTimestamp)
      ? Math.max(0, Math.floor((Date.now() - eventTimestamp) / 1000))
      : 0
  })}\n\n`;

  for (const [id, client] of sseClients) {
    try {
      client.res.write(packet);
    } catch (_) {
      sseClients.delete(id);
    }
  }

  return {
    event,
    duplicate: false,
    connectedClients: sseClients.size
  };
}

function getBearer(req) {
  const header = text(req.headers.authorization);
  return header.toLowerCase().startsWith('bearer ')
    ? header.slice(7).trim()
    : '';
}

function requireMaster(req, res, next) {
  const token = getBearer(req);

  if (!token || !JWT_SECRET) {
    return res.status(401).json({
      success: false,
      error: 'Master authentication required'
    });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== 'master') {
      return res.status(403).json({
        success: false,
        error: 'Master access required'
      });
    }
    req.auth = payload;
    return next();
  } catch (_) {
    return res.status(401).json({
      success: false,
      error: 'Invalid or expired token'
    });
  }
}

async function initDB() {
  if (!DATABASE_URL) {
    dbStatus = {
      connected: false,
      message: 'TIDB_DATABASE_URL is not configured'
    };
    return;
  }

  try {
    dbPool = mysql.createPool(
      DATABASE_URL +
      (DATABASE_URL.includes('?') ? '&' : '?') +
      'connectionLimit=5&waitForConnections=true&queueLimit=0'
    );

    await dbPool.query(`CREATE TABLE IF NOT EXISTS users (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(190) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      api_key VARCHAR(128) NULL UNIQUE,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`);

    dbStatus = {
      connected: true,
      message: 'Database connected'
    };
  } catch (err) {
    dbStatus = {
      connected: false,
      message: err.message || 'Database connection failed'
    };
    console.error('[database]', dbStatus.message);
    dbPool = null;
  }
}

app.get('/', (_req, res) => res.type('html').send(
  '<!doctype html><html><head><meta charset="utf-8"><title>Steal An Egg API</title></head><body><h1>Steal An Egg — Discord Spawn Tracker</h1><p>Backend is running.</p><ul><li><a href="/health">Health</a></li><li><a href="/health/database">Database health</a></li><li><a href="/api/schedule">Schedule API</a></li><li><a href="/master">Master login</a></li><li><a href="/generator">Buyer API key</a></li></ul></body></html>'
));

app.get('/health', (_req, res) => res.json({
  ok: true,
  service: 'steal-egg-saas-backend',
  timestamp: new Date().toISOString(),
  databaseConfigured: Boolean(DATABASE_URL),
  databaseConnected: dbStatus.connected,
  databaseMessage: dbStatus.message,
  webhookReceived: Boolean(lastWebhookAt),
  lastWebhookAt,
  activeSchedules: recentEvents.length,
  sseClients: sseClients.size,
  configured: {
    jwtSecret: Boolean(JWT_SECRET),
    masterPassword: Boolean(MASTER_PASSWORD),
    webhookSecret: Boolean(WEBHOOK_SECRET)
  }
}));

app.get('/health/database', async (_req, res) => {
  if (!dbPool) {
    return res.status(503).json({ ok: false, ...dbStatus });
  }

  try {
    await dbPool.query('SELECT 1');
    return res.json({
      ok: true,
      connected: true,
      message: 'Database connected'
    });
  } catch (err) {
    return res.status(503).json({
      ok: false,
      connected: false,
      message: err.message
    });
  }
});

// V290-compatible schedule API. These are received spawn events,
// not invented future countdowns.
app.get('/api/schedule', (_req, res) => {
  res.set('Cache-Control', 'no-store');

  res.json({
    success: true,
    schedules: recentEvents.map(e => {
      const eventMs = new Date(e.timestamp).getTime();
      return {
        type: 'SPAWN',
        id: e.messageId || e.timestamp,
        petName: e.eggName,
        eggName: e.eggName,
        tier: e.tier,
        location: e.location,
        biome: e.biome,
        spawned: e.spawned,
        spawnedAt: e.timestamp,
        timestamp: e.timestamp,
        time: e.timestamp,
        remainingSeconds: 0,
        elapsedSeconds: Number.isFinite(eventMs)
          ? Math.max(0, Math.floor((Date.now() - eventMs) / 1000))
          : 0,
        eventType: 'spawn',
        messageId: e.messageId
      };
    }),
    lastMessage,
    webhookReceived: Boolean(lastWebhookAt),
    lastWebhookAt,
    discordConnected: Boolean(lastWebhookAt),
    activeSchedules: recentEvents.length
  });
});

app.post('/api/bot-webhook', (req, res) => {
  if (!WEBHOOK_SECRET) {
    console.warn('[SECURITY WARNING] WEBHOOK_SECRET is not configured; webhook is unauthenticated.');
  } else if (!safeEqual(req.get('x-webhook-secret'), WEBHOOK_SECRET)) {
    return res.status(401).json({
      success: false,
      error: 'Invalid webhook secret'
    });
  }

  const result = publishSpawn(req.body || {});

  if (!result.event.eggName || result.event.eggName === 'Unknown') {
    console.warn(
      '[webhook] received spawn message but egg name could not be parsed:',
      result.event.rawMessage.slice(0, 300)
    );
  }

  console.log(
    `[webhook] ${result.duplicate ? 'duplicate' : 'spawn'}: ` +
    `${result.event.eggName} | ${result.event.tier} | ${result.event.location}`
  );

  return res.json({
    success: true,
    duplicate: result.duplicate,
    event: result.event,
    connectedClients: result.connectedClients
  });
});

app.get('/events', async (req, res) => {
  // V290 EventSource uses the apiKey query parameter.
  const apiKey = text(
    req.query.apiKey || req.query.key || req.get('x-api-key')
  );

  if (!apiKey) {
    return res.status(401).json({
      success: false,
      error: 'API key required'
    });
  }

  if (!dbPool) {
    return res.status(503).json({
      success: false,
      error: 'API-key database is unavailable'
    });
  }

  try {
    const [rows] = await dbPool.execute(
      'SELECT id FROM users WHERE api_key = ? LIMIT 1',
      [apiKey]
    );

    if (!rows.length) {
      return res.status(401).json({
        success: false,
        error: 'Invalid API key'
      });
    }
  } catch (err) {
    console.error('[events auth]', err.message || err);
    return res.status(503).json({
      success: false,
      error: 'Could not validate API key'
    });
  }

  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.flushHeaders?.();

  const id = crypto.randomUUID();
  sseClients.set(id, { res, apiKey });

  res.write(
    `event: connected\ndata: ${JSON.stringify({
      connected: true,
      timestamp: new Date().toISOString()
    })}\n\n`
  );

  if (lastMessage) {
    const eventMs = new Date(lastMessage.timestamp).getTime();
    res.write(`data: ${JSON.stringify({
      ...lastMessage,
      type: 'SPAWN',
      id: lastMessage.messageId || lastMessage.timestamp,
      elapsedSeconds: Number.isFinite(eventMs)
        ? Math.max(0, Math.floor((Date.now() - eventMs) / 1000))
        : 0
    })}\n\n`);
  }

  const heartbeat = setInterval(() => {
    try {
      res.write(': heartbeat\n\n');
    } catch (_) {
      clearInterval(heartbeat);
      sseClients.delete(id);
    }
  }, 25000);

  req.on('close', () => {
    clearInterval(heartbeat);
    sseClients.delete(id);
  });
});

app.post('/api/master/login', (req, res) => {
  if (!MASTER_PASSWORD || !JWT_SECRET) {
    return res.status(503).json({
      success: false,
      error: 'MASTER_PASSWORD and JWT_SECRET must be configured'
    });
  }

  const supplied = text(req.body && req.body.password);
  if (!safeEqual(supplied, MASTER_PASSWORD)) {
    return res.status(401).json({
      success: false,
      error: 'Invalid master password'
    });
  }

  const token = jwt.sign({ role: 'master' }, JWT_SECRET, {
    expiresIn: '12h'
  });

  return res.json({ success: true, token, expiresIn: 43200 });
});

app.post('/api/master/add-user', requireMaster, async (req, res) => {
  if (!dbPool) {
    return res.status(503).json({
      success: false,
      error: 'Database is not connected'
    });
  }

  const username = text(req.body && req.body.username);
  const password = text(req.body && req.body.password);

  if (!username || !password || username.length > 190 || password.length < 8) {
    return res.status(400).json({
      success: false,
      error: 'Username required; password must be at least 8 characters'
    });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    await dbPool.execute(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)',
      [username, passwordHash]
    );
    return res.json({ success: true, username });
  } catch (err) {
    return res.status(400).json({
      success: false,
      error: err.code === 'ER_DUP_ENTRY'
        ? 'Username already exists'
        : (err.message || 'Could not create user')
    });
  }
});

app.get('/api/master/users', requireMaster, async (_req, res) => {
  if (!dbPool) {
    return res.status(503).json({
      success: false,
      error: 'Database is not connected. Check TIDB_DATABASE_URL and backend startup logs.',
      databaseMessage: dbStatus.message
    });
  }

  try {
    const [rows] = await dbPool.execute(
      'SELECT id, username, api_key, created_at FROM users ORDER BY created_at DESC, id DESC LIMIT 500'
    );
    return res.json({
      success: true,
      users: rows.map(row => ({
        id: row.id,
        username: row.username,
        hasApiKey: Boolean(row.api_key),
        createdAt: row.created_at
      }))
    });
  } catch (err) {
    console.error('[master users]', err.message || err);
    return res.status(503).json({
      success: false,
      error: 'Could not load buyer list. Check database connectivity and users table.',
      databaseMessage: dbStatus.message
    });
  }
});

app.post('/api/buyer/login', async (req, res) => {
  if (!JWT_SECRET) {
    return res.status(503).json({ success: false, error: 'JWT_SECRET is not configured on the backend.' });
  }
  if (!dbPool) {
    return res.status(503).json({
      success: false,
      error: 'Database is not connected'
    });
  }

  const username = text(req.body && req.body.username);
  const password = text(req.body && req.body.password);

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      error: 'Username and password are required'
    });
  }

  try {
    const [rows] = await dbPool.execute(
      'SELECT id, username, password_hash FROM users WHERE username = ? LIMIT 1',
      [username]
    );

    if (!rows.length || !(await bcrypt.compare(password, rows[0].password_hash))) {
      return res.status(401).json({
        success: false,
        error: 'Invalid username or password'
      });
    }

    const token = jwt.sign({
      role: 'buyer',
      userId: rows[0].id,
      username: rows[0].username
    }, JWT_SECRET, { expiresIn: '12h' });

    return res.json({
      success: true,
      token,
      username: rows[0].username,
      expiresIn: 43200
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: err.message || 'Login failed'
    });
  }
});

app.post('/api/buyer/generate-key', async (req, res) => {
  if (!dbPool) {
    return res.status(503).json({
      success: false,
      error: 'Database is not connected'
    });
  }

  const token = getBearer(req);
  if (!token || !JWT_SECRET) {
    return res.status(401).json({
      success: false,
      error: 'Buyer login required'
    });
  }

  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch (_) {
    return res.status(401).json({
      success: false,
      error: 'Invalid or expired token'
    });
  }

  if (payload.role !== 'buyer' || !payload.userId) {
    return res.status(403).json({
      success: false,
      error: 'Buyer access required'
    });
  }

  try {
    const [existingRows] = await dbPool.execute(
      'SELECT api_key FROM users WHERE id = ? LIMIT 1',
      [payload.userId]
    );
    if (!existingRows.length) {
      return res.status(404).json({ success: false, error: 'Buyer account no longer exists.' });
    }
    if (existingRows[0].api_key) {
      return res.json({ success: true, apiKey: existingRows[0].api_key, reused: true });
    }
    const apiKey = 'sae_' + crypto.randomBytes(32).toString('hex');
    await dbPool.execute(
      'UPDATE users SET api_key = ? WHERE id = ?',
      [apiKey, payload.userId]
    );
    return res.json({ success: true, apiKey, reused: false });
  } catch (err) {
    console.error('[generate API key]', err.message || err);
    return res.status(500).json({
      success: false,
      error: 'Could not generate API key. Check database connectivity and backend logs.'
    });
  }
});

app.post('/api/buyer/regenerate-key', async (req, res) => {
  if (!dbPool) {
    return res.status(503).json({ success: false, error: 'Database is not connected. Check TIDB_DATABASE_URL.' });
  }
  const token = getBearer(req);
  if (!token || !JWT_SECRET) {
    return res.status(401).json({ success: false, error: 'Buyer login required.' });
  }
  let payload;
  try { payload = jwt.verify(token, JWT_SECRET); }
  catch (_) { return res.status(401).json({ success: false, error: 'Login expired. Please log in again.' }); }
  if (payload.role !== 'buyer' || !payload.userId) {
    return res.status(403).json({ success: false, error: 'Buyer access required.' });
  }
  try {
    const apiKey = 'sae_' + crypto.randomBytes(32).toString('hex');
    const [result] = await dbPool.execute(
      'UPDATE users SET api_key = ? WHERE id = ?',
      [apiKey, payload.userId]
    );
    if (!result.affectedRows) return res.status(404).json({ success: false, error: 'Buyer account no longer exists.' });
    return res.json({ success: true, apiKey, regenerated: true });
  } catch (err) {
    console.error('[regenerate API key]', err.message || err);
    return res.status(500).json({ success: false, error: 'Could not regenerate API key. Check database connectivity and backend logs.' });
  }
});

app.get('/master', (_req, res) => res.type('html').send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Steal An Egg · Master Console</title>
<style>
:root{color-scheme:dark;--bg:#061019;--panel:#0c1b28;--line:#204354;--cyan:#55e8ff;--muted:#9ab2bf;--text:#effaff;--red:#ff777e;--green:#75efb1}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(ellipse at 50% -20%,#12364a 0,transparent 55%),var(--bg);font:15px/1.5 system-ui,Segoe UI,sans-serif;color:var(--text);padding:28px 16px}.wrap{width:min(900px,100%);margin:auto}.brand{color:var(--cyan);font-size:12px;font-weight:900;letter-spacing:2px}.hero{margin:8px 0 22px}.hero h1{margin:2px 0;font-size:clamp(26px,4vw,38px);line-height:1.12}.sub{color:var(--muted);margin:8px 0}.panel{border:1px solid var(--line);background:linear-gradient(150deg,rgba(15,36,51,.97),rgba(7,20,30,.98));border-radius:15px;padding:22px;box-shadow:0 18px 50px #0005;margin:14px 0}.field{display:block;width:100%;min-height:43px;border:1px solid #315366;border-radius:8px;background:#05121c;color:var(--text);padding:10px 12px;margin:6px 0 12px;font:inherit}.field:focus{outline:2px solid #55e8ff70;border-color:var(--cyan)}label{font-size:13px;color:#c5d9e2;font-weight:750}.btn{border:1px solid #50ddeb;border-radius:8px;background:linear-gradient(180deg,#1b647b,#124154);color:white;padding:10px 15px;font-weight:850;cursor:pointer}.btn:hover{filter:brightness(1.15)}.btn.secondary{background:#102432;border-color:#345365}.status{margin:12px 0;padding:10px 12px;border:1px solid #25495a;border-radius:8px;color:#cce4ee;white-space:pre-wrap;overflow-wrap:anywhere}.status.error{color:#ffd1d3;border-color:#7d303a;background:#39141c55}.status.good{color:#c5ffe2;border-color:#28694d;background:#123b2c66}.hidden{display:none!important}.grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:12px}.table-wrap{overflow:auto;border:1px solid #1c3949;border-radius:9px;margin-top:14px}table{width:100%;border-collapse:collapse;min-width:480px}th,td{text-align:left;padding:11px 13px;border-bottom:1px solid #203a48}th{font-size:11px;letter-spacing:1px;color:var(--cyan);background:#0a1a25}td{color:#e0edf2}tbody tr:last-child td{border-bottom:0}.badge{display:inline-block;border:1px solid #28694d;color:#9dffce;border-radius:99px;padding:2px 8px;font-size:11px;font-weight:800}.badge.off{border-color:#7a5a28;color:#ffd891}.small{font-size:12px;color:var(--muted)}.row{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}.api-link{color:var(--cyan)}@media(max-width:600px){body{padding:18px 10px}.panel{padding:16px}.grid{grid-template-columns:1fr}.hero h1{font-size:28px}}
</style></head><body><main class="wrap"><div class="brand">STEAL AN EGG / BACKEND CONTROL</div><header class="hero"><h1>Master Console</h1><p class="sub">Master-only access. Create buyer accounts here; buyers generate their own API keys on the Generator page.</p></header>
<section id="loginPanel" class="panel"><h2 style="margin-top:0">Master Login</h2><form id="masterLogin"><label for="masterPassword">Master password</label><input class="field" id="masterPassword" type="password" autocomplete="current-password" required><button class="btn" type="submit">Unlock Master Console</button></form><div id="loginStatus" class="status hidden" role="status"></div><p class="small">Master password is checked by the backend and is never stored in this page.</p></section>
<section id="console" class="hidden"><div class="row"><div><h2 style="margin:0">Buyer Accounts</h2><p class="sub">Add buyer login details, view account status, and refresh the list.</p></div><button id="logout" class="btn secondary" type="button">Log out</button></div>
<div class="panel"><h3 style="margin-top:0">Add a buyer</h3><form id="addBuyer"><div class="grid"><div><label for="newUsername">Buyer username</label><input class="field" id="newUsername" maxlength="190" autocomplete="off" required></div><div><label for="newPassword">Temporary password (minimum 8 characters)</label><input class="field" id="newPassword" type="password" minlength="8" autocomplete="new-password" required></div></div><button class="btn" type="submit">＋ Create Buyer Account</button></form><div id="addStatus" class="status hidden" role="status"></div></div>
<div class="panel"><div class="row"><div><h3 style="margin:0">Existing buyers</h3><span id="count" class="small">Loading…</span></div><button class="btn secondary" id="reloadUsers" type="button">↻ Refresh</button></div><div id="usersStatus" class="status" role="status">Sign-in verified. Loading database status…</div><div class="table-wrap"><table><thead><tr><th>USERNAME</th><th>ACCOUNT CREATED</th><th>API KEY STATUS</th></tr></thead><tbody id="userRows"><tr><td colspan="3">No data loaded.</td></tr></tbody></table></div></div>
<div class="small">API key values are never shown in the master list. Share buyer credentials securely; buyers then open <a class="api-link" href="/generator">/generator</a>.</div></section><p class="small"><a class="api-link" href="/health">Backend health</a> · <a class="api-link" href="/health/database">Database health</a> · <a class="api-link" href="/generator">Buyer generator</a></p></main>
<script>
(()=>{const $=id=>document.getElementById(id);let masterToken=sessionStorage.getItem('seaMasterToken')||'';const visible=(el,on)=>el.classList.toggle('hidden',!on);function message(el,msg,kind=''){el.textContent=msg;el.className='status'+(kind?' '+kind:'');visible(el,true)}async function request(url,opts={}){let response,data;try{response=await fetch(url,{cache:'no-store',...opts,headers:{'Content-Type':'application/json',...(opts.headers||{})}});data=await response.json().catch(()=>({success:false,error:'Server returned a non-JSON response.'}));}catch(_){throw new Error('Cannot reach backend. Check host deployment/network.')}if(!response.ok||data.success===false)throw new Error(data.error||('Request failed ('+response.status+')'));return data}function authHeaders(){return{Authorization:'Bearer '+masterToken}}function showConsole(){visible($('loginPanel'),false);visible($('console'),true);loadUsers()}function logout(){masterToken='';sessionStorage.removeItem('seaMasterToken');visible($('console'),false);visible($('loginPanel'),true);$('masterPassword').value=''}async function loadUsers(){ $('userRows').innerHTML='<tr><td colspan="3">Loading buyers…</td></tr>';message($('usersStatus'),'Checking database and loading buyers…');try{const d=await request('/api/master/users',{headers:authHeaders()});$('count').textContent=d.users.length+' buyer account(s)';$('userRows').innerHTML='';if(!d.users.length){$('userRows').innerHTML='<tr><td colspan="3">No buyers created yet. Use Add a buyer above.</td></tr>'}d.users.forEach(u=>{const tr=document.createElement('tr');const a=document.createElement('td');a.textContent=u.username;const b=document.createElement('td');b.textContent=u.createdAt?new Date(u.createdAt).toLocaleString():'—';const c=document.createElement('td');const badge=document.createElement('span');badge.className='badge'+(u.hasApiKey?'':' off');badge.textContent=u.hasApiKey?'KEY GENERATED':'NO KEY YET';c.appendChild(badge);tr.append(a,b,c);$('userRows').appendChild(tr)});message($('usersStatus'),'Database query successful. Buyer list is up to date.','good')}catch(e){message($('usersStatus'),e.message+'\\nIf the message mentions TIDB_DATABASE_URL, set the real TiDB connection string in MS Host Environment Variables, then restart the service.','error');$('count').textContent='Unavailable';$('userRows').innerHTML='<tr><td colspan="3">Buyer list unavailable.</td></tr>';if(/authentication|expired|Master access/i.test(e.message))logout()}}
$('masterLogin').addEventListener('submit',async e=>{e.preventDefault();const button=e.submitter;button.disabled=true;try{const d=await request('/api/master/login',{method:'POST',body:JSON.stringify({password:$('masterPassword').value})});masterToken=d.token;sessionStorage.setItem('seaMasterToken',masterToken);message($('loginStatus'),'Master login successful.','good');showConsole()}catch(err){message($('loginStatus'),err.message,'error')}finally{button.disabled=false}});
$('addBuyer').addEventListener('submit',async e=>{e.preventDefault();const button=e.submitter;button.disabled=true;visible($('addStatus'),false);try{const d=await request('/api/master/add-user',{method:'POST',headers:authHeaders(),body:JSON.stringify({username:$('newUsername').value.trim(),password:$('newPassword').value})});$('newPassword').value='';message($('addStatus'),'Buyer account “'+d.username+'” created. You can now use these credentials on /generator.','good');await loadUsers()}catch(err){message($('addStatus'),err.message,'error')}finally{button.disabled=false}});$('reloadUsers').addEventListener('click',loadUsers);$('logout').addEventListener('click',logout);if(masterToken)showConsole();})();
</script></body></html>`));

app.get('/generator', (_req, res) => res.type('html').send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Steal An Egg · Buyer API Key</title>
<style>
:root{color-scheme:dark;--bg:#061019;--panel:#0c1b28;--line:#204354;--cyan:#55e8ff;--muted:#9ab2bf;--text:#effaff;--red:#ff777e;--green:#75efb1}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(ellipse at 50% -20%,#12364a 0,transparent 55%),var(--bg);font:15px/1.5 system-ui,Segoe UI,sans-serif;color:var(--text);padding:28px 16px}.wrap{width:min(580px,100%);margin:auto}.brand{color:var(--cyan);font-size:12px;font-weight:900;letter-spacing:2px}.hero{margin:8px 0 22px}.hero h1{margin:2px 0;font-size:clamp(26px,4vw,36px);line-height:1.12}.sub{color:var(--muted);margin:8px 0}.panel{border:1px solid var(--line);background:linear-gradient(150deg,rgba(15,36,51,.97),rgba(7,20,30,.98));border-radius:15px;padding:22px;box-shadow:0 18px 50px #0005;margin:14px 0}.field{display:block;width:100%;min-height:45px;border:1px solid #315366;border-radius:8px;background:#05121c;color:var(--text);padding:11px 12px;margin:6px 0 14px;font:inherit}.field:focus{outline:2px solid #55e8ff70;border-color:var(--cyan)}label{font-size:13px;color:#c5d9e2;font-weight:750}.btn{border:1px solid #50ddeb;border-radius:8px;background:linear-gradient(180deg,#1b647b,#124154);color:white;padding:11px 15px;font-weight:850;cursor:pointer}.btn:hover{filter:brightness(1.15)}.btn:disabled{opacity:.55;cursor:wait}.btn.secondary{background:#102432;border-color:#345365}.status{margin:12px 0;padding:10px 12px;border:1px solid #25495a;border-radius:8px;color:#cce4ee;white-space:pre-wrap;overflow-wrap:anywhere}.status.error{color:#ffd1d3;border-color:#7d303a;background:#39141c55}.status.good{color:#c5ffe2;border-color:#28694d;background:#123b2c66}.hidden{display:none!important}.api-key{width:100%;min-height:64px;display:block;background:#04111a;color:#9dffce;border:1px solid #28694d;border-radius:9px;padding:14px;font:13px/1.55 ui-monospace,Consolas,monospace;overflow-wrap:anywhere;user-select:all}.actions{display:flex;gap:9px;flex-wrap:wrap}.small{font-size:12px;color:var(--muted)}a{color:var(--cyan)}
</style></head><body><main class="wrap"><div class="brand">STEAL AN EGG / BUYER PORTAL</div><header class="hero"><h1>Buyer Login / API Key</h1><p class="sub">Sign in with the buyer account created by the Master Console. Generate your key, then paste it into Backend API Key in the OBS dashboard.</p></header>
<section id="loginPanel" class="panel"><h2 style="margin-top:0">Sign in</h2><form id="login"><label for="username">Buyer username</label><input class="field" id="username" autocomplete="username" required><label for="password">Password</label><input class="field" id="password" type="password" autocomplete="current-password" required><button class="btn" type="submit">Log in securely</button></form><div id="loginStatus" class="status hidden" role="status"></div></section>
<section id="keyPanel" class="panel hidden"><div style="color:var(--cyan);font-size:12px;font-weight:900;letter-spacing:1.5px">BUYER ACCESS</div><h2 style="margin:5px 0">Your API Key</h2><p id="welcome" class="sub"></p><p class="small">This key belongs to your buyer account. Keep it private. The Discord bot token is not needed here.</p><div id="keyStatus" class="status" role="status">Login successful. Click Generate API Key.</div><div id="keyOutput" class="hidden"><label for="apiKey">API key</label><textarea class="api-key" id="apiKey" rows="3" readonly spellcheck="false"></textarea><div class="actions" style="margin-top:10px"><button id="copyKey" class="btn" type="button">Copy API Key</button><button id="regenerate" class="btn secondary" type="button">Rotate Key</button></div><p class="small">Rotate Key immediately revokes the previous key. Update the dashboard after rotating.</p></div><div class="actions" style="margin-top:14px"><button id="generate" class="btn" type="button">Generate / Show API Key</button><button id="buyerLogout" class="btn secondary" type="button">Log out</button></div></section>
<p class="small"><a href="/health">Backend health</a> · <a href="/health/database">Database health</a> · Master Console: <a href="/master">/master</a></p></main>
<script>
(()=>{const $=id=>document.getElementById(id);let buyerToken=sessionStorage.getItem('seaBuyerToken')||'',buyerName=sessionStorage.getItem('seaBuyerName')||'';function visible(el,on){el.classList.toggle('hidden',!on)}function message(el,msg,kind=''){el.textContent=msg;el.className='status'+(kind?' '+kind:'');visible(el,true)}async function request(url,opts={}){let r,d;try{r=await fetch(url,{cache:'no-store',...opts,headers:{'Content-Type':'application/json',...(opts.headers||{})}});d=await r.json().catch(()=>({success:false,error:'Backend returned a non-JSON response.'}))}catch(_){throw new Error('Cannot reach backend. Check host deployment/network.')}if(!r.ok||d.success===false)throw new Error(d.error||('Request failed ('+r.status+')'));return d}function auth(){return{Authorization:'Bearer '+buyerToken}}function showBuyer(){visible($('loginPanel'),false);visible($('keyPanel'),true);$('welcome').textContent='Signed in as '+buyerName+'.';}
$('login').addEventListener('submit',async e=>{e.preventDefault();const b=e.submitter;b.disabled=true;try{const d=await request('/api/buyer/login',{method:'POST',body:JSON.stringify({username:$('username').value.trim(),password:$('password').value})});buyerToken=d.token;buyerName=d.username||$('username').value.trim();sessionStorage.setItem('seaBuyerToken',buyerToken);sessionStorage.setItem('seaBuyerName',buyerName);showBuyer();message($('keyStatus'),'Login successful. Click “Generate / Show API Key” to retrieve your key.','good')}catch(err){message($('loginStatus'),err.message+'\\nIf this says database is not connected, check /health/database and configure TIDB_DATABASE_URL in MS Host.','error')}finally{b.disabled=false}});
$('generate').addEventListener('click',async()=>{const b=$('generate');b.disabled=true;message($('keyStatus'),'Checking account and retrieving key…');try{const d=await request('/api/buyer/generate-key',{method:'POST',headers:auth()});$('apiKey').value=d.apiKey||'';visible($('keyOutput'),!!d.apiKey);message($('keyStatus'),d.reused?'Existing API key loaded. Repeated Generate clicks will not rotate it.':'API key generated successfully. Copy it into the OBS dashboard.','good')}catch(err){message($('keyStatus'),err.message+'\\nCheck /health/database if backend reports a database problem.','error')}finally{b.disabled=false}});
$('copyKey').addEventListener('click',async()=>{try{await navigator.clipboard.writeText($('apiKey').value);message($('keyStatus'),'API key copied. Paste it into Backend API Key in OBS.','good')}catch(_){$('apiKey').focus();$('apiKey').select();message($('keyStatus'),'Clipboard permission was blocked. The key is selected; press Ctrl+C to copy it.')}});
$('regenerate').addEventListener('click',async()=>{if(!confirm('Rotate this API key? The previous key will stop working. Update OBS after rotation.'))return;const b=$('regenerate');b.disabled=true;try{const d=await request('/api/buyer/regenerate-key',{method:'POST',headers:auth()});$('apiKey').value=d.apiKey||'';visible($('keyOutput'),!!d.apiKey);message($('keyStatus'),'API key rotated. The old key is revoked; update OBS now.','good')}catch(err){message($('keyStatus'),err.message,'error')}finally{b.disabled=false}});
$('buyerLogout').addEventListener('click',()=>{buyerToken='';buyerName='';sessionStorage.removeItem('seaBuyerToken');sessionStorage.removeItem('seaBuyerName');visible($('keyPanel'),false);visible($('loginPanel'),true);$('password').value='';visible($('keyOutput'),false);message($('loginStatus'),'You have logged out.','good')});if(buyerToken&&buyerName)showBuyer();})();
</script></body></html>`));

app.use((err, _req, res, _next) => {
  console.error('[request error]', err.message || err);
  if (res.headersSent) return;
  res.status(500).json({ success: false, error: 'Internal server error' });
});

// Initialize the database once per serverless instance. The Express app is
// exported so Vercel can invoke it as a function. Local hosts still use listen().
let dbInitPromise;
function ensureDatabaseInitialized() {
  if (!dbInitPromise) {
    dbInitPromise = initDB().catch((err) => {
      dbStatus = { connected: false, message: err && err.message ? err.message : 'Database initialization failed' };
      console.error('[database initialization]', dbStatus.message);
    });
  }
  return dbInitPromise;
}

if (!process.env.VERCEL) {
  ensureDatabaseInitialized().then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Steal An Egg backend listening on port ${PORT}; database: ${dbStatus.message}`);
      if (!WEBHOOK_SECRET) {
        console.warn('[SECURITY WARNING] Set WEBHOOK_SECRET and the same value on the Wispbyte bot.');
      }
    });
  });
} else {
  ensureDatabaseInitialized();
}

module.exports = app;
