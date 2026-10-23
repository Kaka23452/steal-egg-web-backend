'use strict';

// Steal An Egg backend — hardened version
// Compatible with the existing spawn webhook, /api/schedule, /events,
// master login, buyer login and API-key generation flows.

const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const PORT = Number.parseInt(process.env.PORT, 10) || 8080;
const JWT_SECRET = process.env.JWT_SECRET || '';
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || '';
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const GENERIC_DATABASE_URL = process.env.DATABASE_URL || '';
const DATABASE_URL = process.env.TIDB_DATABASE_URL ||
  process.env.MYSQL_URL ||
  (/^mysql(?:2)?:\/\//i.test(GENERIC_DATABASE_URL)
    ? GENERIC_DATABASE_URL
    : '');

const MAX_EVENTS = 100;
const MAX_SEEN_MESSAGE_IDS = 5000;
const RATE_WINDOW_MS = 15 * 60 * 1000;
const rateLimits = new Map();
const sseClients = new Map();
const recentEvents = [];
const seenMessageIds = new Set();

let lastWebhookAt = null;
let lastMessage = null;
let dbPool = null;
let dbInitPromise = null;
let lastDbInitAttemptAt = 0;

const DB_RETRY_INTERVAL_MS = 15000;

let dbStatus = {
  connected: false,
  message: 'Database not initialized',
  checkedAt: null
};

app.disable('x-powered-by');

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=()'
  );

  if (
    req.path === '/master' ||
    req.path === '/generator' ||
    req.path.startsWith('/api/')
  ) {
    res.setHeader('Cache-Control', 'no-store');
  }

  next();
});

const allowedOrigins = ALLOWED_ORIGIN
  .split(',')
  .map(v => v.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (
      !origin ||
      allowedOrigins.includes('*') ||
      allowedOrigins.includes(origin)
    ) {
      return callback(null, true);
    }

    const err = new Error('Origin not allowed by CORS');
    err.status = 403;
    return callback(err);
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Webhook-Secret',
    'X-API-Key'
  ],
  maxAge: 600
}));

app.use(express.json({ limit: '1mb', strict: true }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

function safeEqual(a, b) {
  const aa = Buffer.from(String(a == null ? '' : a), 'utf8');
  const bb = Buffer.from(String(b == null ? '' : b), 'utf8');

  return (
    aa.length > 0 &&
    aa.length === bb.length &&
    crypto.timingSafeEqual(aa, bb)
  );
}

function text(value) {
  if (value === undefined || value === null) return '';

  if (typeof value === 'string' || typeof value === 'number') {
    return String(value).trim();
  }

  return '';
}

// Passwords must not be trimmed:
// leading/trailing spaces are password characters.
function rawPassword(value) {
  return typeof value === 'string' ? value : '';
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

function usableText(value) {
  const result = cleanText(value);

  if (
    !result ||
    /^(unknown|none|n\/a|na|null|undefined|not reported|location not reported|biome not reported)$/i.test(result)
  ) {
    return '';
  }

  return result;
}

const EVENT_PET_BIOMES = new Map([
  ['graveyardbrute', 'Graveyard'],
  ['ghostreaper', 'Graveyard'],
  ['bloodbloom', 'Haunted Swamp'],
  ['shelltidevoyager', 'Haunted Swamp'],
  ['werewolf', 'Abandoned Manor'],
  ['abominationkong', 'Abandoned Manor'],
  ['voidseerpumpkin', 'Abandoned Manor']
]);

function normalizeEventLocation(value, eggName, rawText) {
  const supplied = usableText(value);
  const petKey = cleanText(eggName)
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '');

  const petBiome = EVENT_PET_BIOMES.get(petKey) || '';
  const key = supplied.toLowerCase().replace(/[^a-z0-9]/g, '');

  const zoneMap = {
    '1': 'Graveyard',
    '2': 'Haunted Swamp',
    '3': 'Abandoned Manor'
  };

  if (!supplied) return petBiome || '';
  if (key.includes('graveyard')) return 'Graveyard';
  if (key.includes('hauntedswamp')) return 'Haunted Swamp';
  if (key.includes('abandonedmanor')) return 'Abandoned Manor';

  const zone =
    key.match(/^(?:halloweendimension|halloweenzone|dimensionzone|dimension|zone|area)?([123])$/) ||
    key.match(/^(?:halloweendimension|halloweenzone|dimensionzone|dimension|zone|area)([123])$/);

  const eventContext =
    /halloween|dimension|graveyard|haunted swamp|abandoned manor/i.test(rawText || '') ||
    !!petBiome;

  if (zone && eventContext) {
    return zoneMap[zone[1]] || petBiome || supplied;
  }

  return supplied;
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
      return m[1]
        .trim()
        .replace(
          /\s+(?:Location|Biome|Spawned|Time|Money|Tier|Rarity)\s*[:：-].*$/i,
          ''
        )
        .trim();
    }
  }

  return '';
}

function inferTier(raw, explicit) {
  const known = [
    'SECRET',
    'DIVINE',
    'ETERNAL',
    'COSMIC',
    'TRANSCENDENT',
    'MYTHIC',
    'LEGENDARY',
    'EPIC',
    'RARE',
    'UNCOMMON',
    'COMMON'
  ];

  const explicitText = usableText(explicit);

  if (explicitText) {
    const match = known.find(
      tier => tier.toLowerCase() === explicitText.toLowerCase()
    );

    if (match) {
      return match[0] + match.slice(1).toLowerCase();
    }
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
  const input =
    body && typeof body === 'object' && !Array.isArray(body)
      ? body
      : {};

  const embedParts = Array.isArray(input.embeds)
    ? input.embeds.flatMap(embed => [
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
    text(input.message),
    text(input.content),
    text(input.description),
    text(input.eggName),
    text(input.egg),
    text(input.petName),
    text(input.title),
    text(input.rawText),
    text(input.rawMessage),
    text(input.embedText),
    text(input.messageContent),
    ...embedParts
  ].filter(Boolean);

  const raw = cleanText(rawParts.join('\n'));

  const suppliedEgg =
    usableText(input.eggName) ||
    usableText(input.egg) ||
    usableText(input.petName);

  let eggName = labelValue(raw, [
    'Egg Name',
    'Spawned Egg',
    'Egg',
    'Pet Name',
    'Pet'
  ]);

  if (!usableText(eggName)) eggName = suppliedEgg;

  if (!usableText(eggName) && raw) {
    // Avoid turning arbitrary chat messages into spawn events.
    const afterSpawnMarker =
      raw.match(
        /(?:egg|pet)\s+(?:has\s+)?spawned\b\s*[:!—-]?\s*([\s\S]*)/i
      ) ||
      raw.match(
        /(?:secret|divine|eternal|cosmic|transcendent|mythic|legendary|epic|rare|uncommon|common)\s+(?:egg\s+)?spawn(?:ed)?\s*[:!—-]?\s*([\s\S]*)/i
      ) ||
      raw.match(
        /^(.+?)\s+(?:has\s+)?spawned(?:\s+(?:in|at)\b.*)?$/i
      );

    if (afterSpawnMarker && afterSpawnMarker[1]) {
      eggName = afterSpawnMarker[1]
        .split(/\b(?:Location|Biome|Spawned|Time|Money|Tier|Rarity)\s*[:：-]/i)[0]
        .replace(/^\s*Egg\s*[:：-]\s*/i, '')
        .replace(/[|•]+\s*$/g, '')
        .trim();
    }
  }

  const extractedLocation =
    usableText(input.location) ||
    usableText(input.biome) ||
    usableText(input.area) ||
    usableText(labelValue(raw, [
      'Location',
      'Biome',
      'Map',
      'Area',
      'Spawn Location',
      'Spawned In',
      'Current Location',
      'Current Biome',
      'Biome Name',
      'Location Name',
      'Region',
      'Zone',
      'Zone Name',
      'Spawn Zone',
      'Dimension Zone',
      'Halloween Zone'
    ])) ||
    '';

  const location =
    normalizeEventLocation(extractedLocation, eggName, raw) || 'Unknown';

  const spawned =
    usableText(input.spawned) ||
    usableText(input.spawnedAgo) ||
    usableText(input.spawnedLabel) ||
    usableText(input.spawnTime) ||
    usableText(input.spawn_time_text) ||
    usableText(labelValue(raw, [
      'Spawned At',
      'Spawned',
      'Spawned Ago',
      'Time Since Spawn',
      'Spawn Time',
      'Time'
    ])) ||
    'Unknown';

  const tier = inferTier(raw, input.tier || input.rarity);

  const discordUnix =
    spawned.match(/<t:(\d{9,12})(?::[tTdDfFR])?>/) ||
    raw.match(/<t:(\d{9,12})(?::[tTdDfFR])?>/);

  const elapsedMatch = spawned.match(
    /(\d+(?:\.\d+)?)\s*(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d)\s*ago/i
  );

  const explicitCandidate =
    input.spawnedAt ||
    input.spawned_at ||
    input.spawnTimestamp ||
    input.spawn_timestamp ||
    input.timestamp ||
    input.createdAt ||
    input.time;

  let parsedTimestamp;

  if (discordUnix) {
    parsedTimestamp = new Date(Number(discordUnix[1]) * 1000);
  } else if (elapsedMatch) {
    const n = Number(elapsedMatch[1]);
    const u = elapsedMatch[2].toLowerCase();

    const factor =
      /^(s|sec)/.test(u) ? 1000 :
      /^(m|min)/.test(u) ? 60000 :
      /^(h|hr|hour)/.test(u) ? 3600000 :
      86400000;

    parsedTimestamp = new Date(Date.now() - n * factor);
  } else {
    parsedTimestamp = explicitCandidate
      ? new Date(
          typeof explicitCandidate === 'number' && explicitCandidate < 1e12
            ? explicitCandidate * 1000
            : explicitCandidate
        )
      : new Date();
  }

  const timestamp = Number.isFinite(parsedTimestamp.getTime())
    ? parsedTimestamp.toISOString()
    : new Date().toISOString();

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
    messageId: text(input.messageId || input.message_id || ''),
    channelId: text(input.channelId || input.channel_id || ''),
    source: text(input.source || 'discord'),
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

    if (seenMessageIds.size > MAX_SEEN_MESSAGE_IDS) {
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
      if (!client.res.write(packet)) {
        client.res.once('drain', () => {});
      }
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

function rateLimitKey(req, scope) {
  return `${scope}:${req.ip || (req.socket && req.socket.remoteAddress) || 'unknown'}`;
}

function isRateLimited(req, res, scope, maxAttempts) {
  const key = rateLimitKey(req, scope);
  const now = Date.now();

  let entry = rateLimits.get(key);

  if (!entry || now >= entry.resetAt) {
    entry = {
      count: 0,
      resetAt: now + RATE_WINDOW_MS
    };
  }

  entry.count += 1;
  rateLimits.set(key, entry);

  if (entry.count <= maxAttempts) return false;

  res.setHeader(
    'Retry-After',
    String(Math.max(1, Math.ceil((entry.resetAt - now) / 1000)))
  );

  res.status(429).json({
    success: false,
    error: 'Too many attempts. Try again later.'
  });

  return true;
}

function clearRateLimit(req, scope) {
  rateLimits.delete(rateLimitKey(req, scope));
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

function requireBuyer(req, res, next) {
  const token = getBearer(req);

  if (!token || !JWT_SECRET) {
    return res.status(401).json({
      success: false,
      error: 'Buyer login required'
    });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);

    if (payload.role !== 'buyer' || !payload.userId) {
      return res.status(403).json({
        success: false,
        error: 'Buyer access required'
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

async function initDB(force = false) {
  if (dbInitPromise) return dbInitPromise;

  if (
    !force &&
    !dbPool &&
    lastDbInitAttemptAt &&
    Date.now() - lastDbInitAttemptAt < DB_RETRY_INTERVAL_MS
  ) {
    return false;
  }

  lastDbInitAttemptAt = Date.now();

  dbInitPromise = (async () => {
    if (!DATABASE_URL) {
      dbStatus = {
        connected: false,
        message: 'TIDB_DATABASE_URL (or DATABASE_URL) is not configured',
        checkedAt: new Date().toISOString()
      };

      return false;
    }

    let candidate;

    try {
      const url = new URL(DATABASE_URL);

      url.searchParams.set('connectionLimit', '5');
      url.searchParams.set('waitForConnections', 'true');
      url.searchParams.set('queueLimit', '0');
      url.searchParams.set('connectTimeout', '10000');

      candidate = mysql.createPool(url.toString());

      await candidate.query(`
        CREATE TABLE IF NOT EXISTS users (
          id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
          username VARCHAR(190) NOT NULL UNIQUE,
          password_hash VARCHAR(255) NOT NULL,
          api_key VARCHAR(128) NULL UNIQUE,
          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
      `);

      const [columns] = await candidate.query('SHOW COLUMNS FROM users');

      if (!columns.some(col => col.Field === 'api_key')) {
        await candidate.query(
          'ALTER TABLE users ADD COLUMN api_key VARCHAR(128) NULL UNIQUE'
        );
      }

      await candidate.query('SELECT 1');

      if (dbPool && dbPool !== candidate) {
        await dbPool.end().catch(() => {});
      }

      dbPool = candidate;

      dbStatus = {
        connected: true,
        message: 'Database connected',
        checkedAt: new Date().toISOString()
      };

      return true;
    } catch (err) {
      if (candidate) await candidate.end().catch(() => {});

      dbPool = null;

      dbStatus = {
        connected: false,
        message: 'Database connection failed. Check database URL, TLS settings and user permissions.',
        checkedAt: new Date().toISOString(),
        code: err.code || 'DB_INIT_FAILED'
      };

      console.error(
        '[database] initialization failed:',
        err.code || '',
        err.message || err
      );

      return false;
    }
  })();

  try {
    return await dbInitPromise;
  } finally {
    dbInitPromise = null;
  }
}

async function requireDatabase(res) {
  if (dbPool && dbStatus.connected) return true;

  await initDB();

  if (dbPool && dbStatus.connected) return true;

  res.status(503).json({
    success: false,
    error: 'Database is unavailable. Check server database configuration.'
  });

  return false;
}

app.get('/', (_req, res) => res.type('html').send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Steal An Egg API</title>
<style>
body{font:16px system-ui;max-width:760px;margin:48px auto;padding:0 20px;background:#101620;color:#eaf0f8}
a{color:#8bd5ff}
li{margin:10px 0}
.muted{color:#a7b4c4}
</style>
</head>
<body>
<h1>Steal An Egg — Discord Spawn Tracker</h1>
<p class="muted">Backend API is running. Use the health endpoints to check server and database status.</p>
<ul>
<li><a href="/health">Service health</a></li>
<li><a href="/health/database">Database health</a></li>
<li><a href="/api/schedule">Recent spawn events</a></li>
<li><a href="/master">Master console</a></li>
<li><a href="/generator">Buyer login / API key</a></li>
</ul>
</body>
</html>`));

app.get('/health', (_req, res) => res.json({
  ok: true,
  status: dbStatus.connected ? 'ok' : 'degraded',
  service: 'steal-egg-saas-backend',
  timestamp: new Date().toISOString(),
  databaseConnected: dbStatus.connected,
  databaseMessage: dbStatus.message,
  databaseCheckedAt: dbStatus.checkedAt,
  webhookReceived: Boolean(lastWebhookAt),
  lastWebhookAt,
  activeSchedules: recentEvents.length,
  eventsPersisted: false,
  sseClients: sseClients.size,
  configured: {
    jwtSecret: Boolean(JWT_SECRET),
    masterPassword: Boolean(MASTER_PASSWORD),
    webhookSecret: Boolean(WEBHOOK_SECRET)
  }
}));

app.get('/health/database', async (_req, res) => {
  if (!dbPool) {
    await initDB();

    if (!dbPool) {
      return res.status(503).json({
        ok: false,
        ...dbStatus
      });
    }
  }

  try {
    await dbPool.query('SELECT 1');

    dbStatus = {
      connected: true,
      message: 'Database connected',
      checkedAt: new Date().toISOString()
    };

    return res.json({
      ok: true,
      connected: true,
      message: 'Database connected',
      checkedAt: dbStatus.checkedAt
    });
  } catch (err) {
    dbStatus = {
      connected: false,
      message: 'Database query failed. Check DB availability and credentials.',
      checkedAt: new Date().toISOString(),
      code: err.code || 'DB_QUERY_FAILED'
    };

    console.error(
      '[database] health check failed:',
      err.code || '',
      err.message || err
    );

    const brokenPool = dbPool;
    dbPool = null;

    if (brokenPool) await brokenPool.end().catch(() => {});

    return res.status(503).json({
      ok: false,
      ...dbStatus
    });
  }
});

// These schedules are real received spawn events,
// not fabricated future countdowns.
app.get('/api/schedule', (_req, res) => {
  res.set('Cache-Control', 'no-store');

  return res.json({
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
        rawMessage: String(e.rawMessage || '').slice(0, 4000),
        source: e.source || 'discord',
        channelId: e.channelId || '',
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
  // Fail closed: never accept unauthenticated webhook traffic.
  if (!WEBHOOK_SECRET) {
    return res.status(503).json({
      success: false,
      error: 'Webhook is disabled until WEBHOOK_SECRET is configured.'
    });
  }

  if (!safeEqual(req.get('x-webhook-secret'), WEBHOOK_SECRET)) {
    return res.status(401).json({
      success: false,
      error: 'Invalid webhook secret'
    });
  }

  const parsed = parseSpawn(req.body || {});

  if (!parsed.eggName || parsed.eggName === 'Unknown') {
    return res.status(422).json({
      success: false,
      error: 'Could not identify egg/pet name. Send eggName or a message/embed containing it.'
    });
  }

  const published = publishSpawn(req.body || {});

  console.log(
    `[webhook] ${published.duplicate ? 'duplicate' : 'spawn'}: ` +
    `${published.event.eggName} | ${published.event.tier} | ${published.event.location}`
  );

  return res.json({
    success: true,
    duplicate: published.duplicate,
    event: published.event,
    connectedClients: published.connectedClients
  });
});

app.get('/events', async (req, res) => {
  const apiKey = text(
    req.query.apiKey || req.query.key || req.get('x-api-key')
  );

  if (!apiKey) {
    return res.status(401).json({
      success: false,
      error: 'API key required'
    });
  }

  if (!await requireDatabase(res)) return;

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
    console.error('[events auth]', err.code || '', err.message || err);

    return res.status(503).json({
      success: false,
      error: 'Could not validate API key'
    });
  }

  res.set({
    'Content-Type': 'text/event-stream; charset=utf-8',
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
    if (res.destroyed || res.writableEnded) {
      clearInterval(heartbeat);
      sseClients.delete(id);
      return;
    }

    try {
      res.write(': heartbeat\n\n');
    } catch (_) {
      clearInterval(heartbeat);
      sseClients.delete(id);
    }
  }, 25000);

  heartbeat.unref?.();

  req.on('close', () => {
    clearInterval(heartbeat);
    sseClients.delete(id);
  });
});

app.post('/api/master/login', (req, res) => {
  if (isRateLimited(req, res, 'master-login', 8)) return;

  if (!MASTER_PASSWORD || !JWT_SECRET) {
    return res.status(503).json({
      success: false,
      error: 'MASTER_PASSWORD and JWT_SECRET must be configured on the host.'
    });
  }

  const supplied = rawPassword(req.body && req.body.password);

  if (!safeEqual(supplied, MASTER_PASSWORD)) {
    return res.status(401).json({
      success: false,
      error: 'Invalid master password'
    });
  }

  clearRateLimit(req, 'master-login');

  const token = jwt.sign(
    { role: 'master' },
    JWT_SECRET,
    { expiresIn: '12h' }
  );

  return res.json({
    success: true,
    token,
    expiresIn: 43200
  });
});

app.get('/api/master/users', requireMaster, async (_req, res) => {
  if (!await requireDatabase(res)) return;

  try {
    const [rows] = await dbPool.query(
      'SELECT id, username, created_at, (api_key IS NOT NULL) AS has_api_key FROM users ORDER BY id DESC LIMIT 200'
    );

    return res.json({
      success: true,
      users: rows.map(row => ({
        id: String(row.id),
        username: row.username,
        createdAt: row.created_at,
        hasApiKey: Boolean(row.has_api_key)
      }))
    });
  } catch (err) {
    console.error('[master users]', err.code || '', err.message || err);

    return res.status(500).json({
      success: false,
      error: 'Could not load buyer list.'
    });
  }
});

app.post('/api/master/add-user', requireMaster, async (req, res) => {
  if (!await requireDatabase(res)) return;

  const username = text(req.body && req.body.username);
  const password = rawPassword(req.body && req.body.password);

  if (
    !username ||
    username.length < 3 ||
    username.length > 190 ||
    !password ||
    password.length < 8 ||
    Buffer.byteLength(password, 'utf8') > 72
  ) {
    return res.status(400).json({
      success: false,
      error: 'Username must be 3–190 characters; password must be 8+ characters and no more than 72 UTF-8 bytes.'
    });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);

    await dbPool.execute(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)',
      [username, passwordHash]
    );

    return res.status(201).json({
      success: true,
      username
    });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        success: false,
        error: 'Username already exists.'
      });
    }

    console.error('[master add-user]', err.code || '', err.message || err);

    return res.status(500).json({
      success: false,
      error: 'Could not create buyer. Check server logs.'
    });
  }
});

app.post('/api/buyer/login', async (req, res) => {
  if (isRateLimited(req, res, 'buyer-login', 12)) return;

  if (!JWT_SECRET) {
    return res.status(503).json({
      success: false,
      error: 'JWT_SECRET is not configured on the host.'
    });
  }

  if (!await requireDatabase(res)) return;

  const username = text(req.body && req.body.username);
  const password = rawPassword(req.body && req.body.password);

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      error: 'Username and password are required.'
    });
  }

  try {
    const [rows] = await dbPool.execute(
      'SELECT id, username, password_hash FROM users WHERE username = ? LIMIT 1',
      [username]
    );

    if (
      !rows.length ||
      !(await bcrypt.compare(password, rows[0].password_hash))
    ) {
      return res.status(401).json({
        success: false,
        error: 'Invalid username or password.'
      });
    }

    clearRateLimit(req, 'buyer-login');

    const token = jwt.sign({
      role: 'buyer',
      userId: String(rows[0].id),
      username: rows[0].username
    }, JWT_SECRET, {
      expiresIn: '12h'
    });

    return res.json({
      success: true,
      token,
      username: rows[0].username,
      expiresIn: 43200
    });
  } catch (err) {
    console.error('[buyer login]', err.code || '', err.message || err);

    return res.status(500).json({
      success: false,
      error: 'Login failed due to a server error.'
    });
  }
});

async function sendApiKey(req, res, regenerate) {
  if (!await requireDatabase(res)) return;

  try {
    if (!regenerate) {
      const [rows] = await dbPool.execute(
        'SELECT api_key FROM users WHERE id = ? LIMIT 1',
        [req.auth.userId]
      );

      if (!rows.length) {
        return res.status(404).json({
          success: false,
          error: 'Buyer account no longer exists.'
        });
      }

      if (rows[0].api_key) {
        return res.json({
          success: true,
          apiKey: rows[0].api_key,
          existing: true
        });
      }
    }

    const apiKey = 'sae_' + crypto.randomBytes(32).toString('hex');

    if (regenerate) {
      const [result] = await dbPool.execute(
        'UPDATE users SET api_key = ? WHERE id = ?',
        [apiKey, req.auth.userId]
      );

      if (!result.affectedRows) {
        return res.status(404).json({
          success: false,
          error: 'Buyer account no longer exists.'
        });
      }

      return res.json({
        success: true,
        apiKey,
        regenerated: true
      });
    }

    // Conditional update prevents repeated clicks rotating the key.
    await dbPool.execute(
      'UPDATE users SET api_key = ? WHERE id = ? AND api_key IS NULL',
      [apiKey, req.auth.userId]
    );

    const [finalRows] = await dbPool.execute(
      'SELECT api_key FROM users WHERE id = ? LIMIT 1',
      [req.auth.userId]
    );

    if (!finalRows.length || !finalRows[0].api_key) {
      return res.status(404).json({
        success: false,
        error: 'Buyer account no longer exists.'
      });
    }

    return res.json({
      success: true,
      apiKey: finalRows[0].api_key,
      existing: finalRows[0].api_key !== apiKey
    });
  } catch (err) {
    console.error('[buyer API key]', err.code || '', err.message || err);

    return res.status(500).json({
      success: false,
      error: 'Could not generate API key. Check server logs.'
    });
  }
}

app.post(
  '/api/buyer/generate-key',
  requireBuyer,
  (req, res) => sendApiKey(req, res, false)
);

app.post(
  '/api/buyer/regenerate-key',
  requireBuyer,
  (req, res) => sendApiKey(req, res, true)
);

// Shared styles and full HTML for Master / Generator pages
// are kept inside these constants so the existing single-file
// deployment model continues to work.

const PAGE_STYLES = `
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2b;--line:#293750;--text:#edf3ff;--muted:#9cabbe;--blue:#75c8ff;--green:#76e0bb;--red:#ff9f9f}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:radial-gradient(ellipse at top,#152b45 0,#0b1020 52%);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;padding:28px 16px}
.wrap{width:min(860px,100%);margin:0 auto}
.top{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:22px}
.brand{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--blue);font-weight:800}
.tag{border:1px solid var(--line);padding:5px 10px;border-radius:999px;color:var(--muted);font-size:12px}
.card{background:rgba(18,26,43,.94);border:1px solid var(--line);border-radius:18px;padding:clamp(18px,4vw,30px);box-shadow:0 18px 60px #0004;margin:14px 0}
h1{font-size:clamp(26px,4vw,36px);line-height:1.14;margin:6px 0 10px;letter-spacing:-.03em}
h2{font-size:18px;margin:0 0 12px}
p{color:var(--muted);margin:0 0 20px}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
.field{display:flex;flex-direction:column;gap:6px;margin:12px 0}
.field label{font-size:13px;color:#c9d7e8}
.field input{width:100%;min-width:0;border:1px solid #3a4a64;border-radius:10px;background:#0a1120;color:var(--text);padding:12px 13px;font:inherit;outline:none}
.field input:focus{border-color:var(--blue);box-shadow:0 0 0 3px #75c8ff22}
button,.btn{border:0;border-radius:10px;background:var(--blue);color:#06111d;font-weight:800;padding:11px 15px;font:inherit;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;gap:8px}
button:disabled{opacity:.5;cursor:wait}
.secondary{background:#24344b;color:var(--text);border:1px solid #40536e}
.danger{background:#47272d;color:#ffd7dc;border:1px solid #78404a}
.actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:14px}
.status{margin-top:14px;padding:11px 13px;border-radius:10px;background:#0b1322;border:1px solid var(--line);white-space:pre-wrap;overflow-wrap:anywhere}
.status.good{border-color:#285e52;color:var(--green)}
.status.bad{border-color:#76404a;color:var(--red)}
.hidden{display:none!important}
.muted{color:var(--muted)}
.tablewrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:480px}
th,td{text-align:left;padding:11px 9px;border-bottom:1px solid var(--line);font-size:13px}
th{color:var(--muted);font-weight:600}
.pill{display:inline-block;border-radius:999px;padding:3px 8px;background:#203b37;color:var(--green);font-size:11px}
.pill.off{background:#342f26;color:#e6d0a1}
.key{font:13px/1.6 ui-monospace,SFMono-Regular,Consolas,monospace;background:#08101d;border:1px solid #3a4a64;border-radius:10px;padding:14px;overflow-wrap:anywhere;user-select:all}
.foot{font-size:12px;color:var(--muted);text-align:center;margin:22px 0}
.link{color:var(--blue)}
@media(max-width:620px){body{padding:18px 12px}.grid{grid-template-columns:1fr}.top{align-items:flex-start;flex-direction:column}.card{border-radius:14px}}
`;

// MASTER_PAGE_HTML and GENERATOR_PAGE_HTML contain the complete
// login / dashboard / buyer-key UI, inline page scripts included.
