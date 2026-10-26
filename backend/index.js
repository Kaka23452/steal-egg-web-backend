'use strict';

const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL =
  process.env.DATABASE_URL ||
  process.env.TIDB_DATABASE_URL ||
  '';

const JWT_SECRET = process.env.JWT_SECRET || '';
const BOT_INGEST_KEY = process.env.BOT_INGEST_KEY || '';
const ADMIN_USERNAME =
  process.env.ADMIN_USERNAME ||
  process.env.MASTER_USERNAME ||
  'Admin';
const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD ||
  process.env.MASTER_PASSWORD ||
  '';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';

const DEFAULT_TIER_TTL_MINUTES = Math.max(
  1,
  Number(process.env.DEFAULT_TIER_TTL_MINUTES || 45)
);

const MAX_EVENTS = 250;
const sseClients = new Map();
const recentEvents = [];
const seenMessageIds = new Set();

let pool = null;
let dbStatus = {
  connected: false,
  message: 'Database not initialized'
};
let lastIngestAt = null;

app.disable('x-powered-by');

app.use(cors({
  origin(origin, callback) {
    const allowed =
      ALLOWED_ORIGIN === '*' ||
      ALLOWED_ORIGIN
        .split(',')
        .map(value => value.trim())
        .includes(origin || '');

    callback(
      allowed ? null : new Error('Origin not allowed by CORS'),
      allowed
    );
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-API-Key',
    'X-Bot-Key',
    'X-Webhook-Secret'
  ],
  exposedHeaders: ['Content-Type']
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

app.use(express.static(path.join(__dirname, 'public'), {
  index: false,
  maxAge: '5m'
}));

const str = value =>
  value == null ? '' : String(value).trim();

const sha256 = value =>
  crypto.createHash('sha256').update(String(value)).digest('hex');

function safeEqual(a, b) {
  const first = Buffer.from(String(a || ''));
  const second = Buffer.from(String(b || ''));

  return (
    first.length > 0 &&
    first.length === second.length &&
    crypto.timingSafeEqual(first, second)
  );
}

function bearer(req) {
  const authorization = str(req.get('authorization'));

  return /^Bearer\s+/i.test(authorization)
    ? authorization.replace(/^Bearer\s+/i, '').trim()
    : '';
}

function signToken(payload, expiresIn = '12h') {
  if (!JWT_SECRET) {
    throw new Error('JWT_SECRET is not configured');
  }

  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

function verifySession(req, role) {
  const token = bearer(req);

  if (!token || !JWT_SECRET) {
    return null;
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);

    if (role && payload.role !== role) {
      return null;
    }

    return payload;
  } catch (_) {
    return null;
  }
}

function sendError(res, status, error, extra = {}) {
  return res.status(status).json({
    success: false,
    error,
    ...extra
  });
}

/* =========================================================
   DATABASE
   Supports DATABASE_URL or TIDB_DATABASE_URL.
   Required tables must already exist in schema.sql.
========================================================= */

async function initDb() {
  if (!DATABASE_URL) {
    dbStatus = {
      connected: false,
      message: 'DATABASE_URL / TIDB_DATABASE_URL is not configured'
    };
    return;
  }

  try {
    pool = mysql.createPool(DATABASE_URL);

    await pool.query('SELECT 1');

    const requiredTables = [
      'users',
      'api_keys',
      'egg_pet_map',
      'location_alias',
      'stocks',
      'processed_messages'
    ];

    for (const table of requiredTables) {
      const [rows] = await pool.execute(
        'SHOW TABLES LIKE ?',
        [table]
      );

      if (!rows.length) {
        throw new Error(
          `Required table "${table}" is missing. Run backend/schema.sql first.`
        );
      }
    }

    dbStatus = {
      connected: true,
      message: 'Database connected; required tables verified'
    };

    console.log('[database] Connected and required tables verified.');
  } catch (error) {
    dbStatus = {
      connected: false,
      message: error.message || 'Database connection failed'
    };

    console.error('[database]', dbStatus.message);

    if (pool) {
      try {
        await pool.end();
      } catch (_) {}
    }

    pool = null;
  }
}

function needDb(res) {
  if (!pool) {
    sendError(
      res,
      503,
      'Database is not connected. Check DATABASE_URL / TIDB_DATABASE_URL and schema.sql.',
      { databaseMessage: dbStatus.message }
    );

    return false;
  }

  return true;
}

/* =========================================================
   BUYER API KEY AUTHENTICATION
   ONE buyer key works for BOTH:
   GET /api/stocks
   GET /api/schedule
   GET /events?apiKey=...

   EventSource cannot set custom headers, so /events supports
   the apiKey query parameter as well as X-API-Key.
========================================================= */

async function findApiKey(rawKey) {
  if (!pool || !rawKey) {
    return null;
  }

  const keyHash = sha256(rawKey);

  const [rows] = await pool.execute(
    `SELECT
       k.id AS key_id,
       k.user_id,
       u.email
     FROM api_keys k
     INNER JOIN users u ON u.id = k.user_id
     WHERE k.key_hash = ?
       AND k.is_active = 1
       AND u.is_active = 1
       AND (
         k.expires_at IS NULL
         OR k.expires_at > CURRENT_TIMESTAMP
       )
     LIMIT 1`,
    [keyHash]
  );

  if (!rows.length) {
    return null;
  }

  pool.execute(
    'UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?',
    [rows[0].key_id]
  ).catch(() => {});

  return rows[0];
}

async function requireApiKey(req, res, next) {
  if (!needDb(res)) {
    return;
  }

  // Header first, then EventSource query string, then legacy query alias.
  const rawKey = str(
    req.get('x-api-key') ||
    req.query.apiKey ||
    req.query.key
  );

  if (!rawKey) {
    return sendError(res, 401, 'API key required');
  }

  try {
    const record = await findApiKey(rawKey);

    if (!record) {
      return sendError(
        res,
        401,
        'Invalid, disabled, expired, or unrecognized API key'
      );
    }

    req.apiKeyOwner = record;
    return next();
  } catch (error) {
    console.error(
      '[API key validation]',
      error.message || error
    );

    return sendError(res, 503, 'Could not validate API key');
  }
}

/* =========================================================
   SPAWN DATA HELPERS
========================================================= */

function normalizeTier(value) {
  const knownTiers = [
    'Secret',
    'Divine',
    'Eternal',
    'Cosmic',
    'Transcendent',
    'Mythic',
    'Legendary',
    'Epic',
    'Rare',
    'Uncommon',
    'Common'
  ];

  const match = knownTiers.find(
    tier => tier.toLowerCase() === str(value).toLowerCase()
  );

  return match || str(value) || 'Unknown';
}

function parseIngest(body) {
  const embeds = Array.isArray(body.embeds)
    ? body.embeds.flatMap(embed => [
        embed.title,
        embed.description,
        ...(Array.isArray(embed.fields)
          ? embed.fields.flatMap(field => [
              field.name,
              field.value
            ])
          : [])
      ])
    : [];

  const raw = [
    body.message,
    body.content,
    body.description,
    body.rawText,
    body.rawMessage,
    body.embedText,
    body.title,
    ...embeds
  ]
    .filter(Boolean)
    .map(String)
    .join('\n')
    .replace(/\*\*/g, '')
    .replace(/`/g, '')
    .trim();

  function findLabel(labels) {
    for (const label of labels) {
      const escaped = label.replace(
        /[.*+?^${}()|[\]\\]/g,
        '\\$&'
      );

      const regex = new RegExp(
        '(?:^|\\n|\\s)' +
          escaped +
          '\\s*[:：-]\\s*([^\\n]+)',
        'i'
      );

      const match = raw.match(regex);

      if (match && match[1]) {
        return match[1]
          .trim()
          .split(
            /\s+(?:Location|Biome|Spawned|Tier|Rarity)\s*[:：-]/i
          )[0]
          .trim();
      }
    }

    return '';
  }

  const eggName = str(
    body.eggName ||
    body.egg ||
    body.petName ||
    findLabel([
      'Egg Name',
      'Spawned Egg',
      'Egg',
      'Pet Name',
      'Pet'
    ])
  ) || 'Unknown';

  const location = str(
    body.location ||
    body.biome ||
    body.area ||
    findLabel([
      'Location',
      'Biome',
      'Map',
      'Area',
      'Region'
    ])
  ) || 'Unknown';

  const tier = normalizeTier(
    body.tier ||
    body.rarity ||
    (raw.match(/\b(Secret|Divine|Eternal)\b/i) || [])[1]
  );

  const explicitTime =
    body.spawnedAt ||
    body.spawned_at ||
    body.timestamp ||
    body.time;

  const parsedDate = explicitTime
    ? new Date(
        typeof explicitTime === 'number' &&
        explicitTime < 1e12
          ? explicitTime * 1000
          : explicitTime
      )
    : new Date();

  const spawnedAt = Number.isFinite(parsedDate.getTime())
    ? parsedDate
    : new Date();

  const messageId = str(
    body.messageId ||
    body.message_id ||
    body.id
  );

  return {
    eggName,
    petName: eggName,
    tier,
    location,
    biome: location,
    spawnedAt,
    messageId,
    rawMessage: raw.slice(0, 4000),
    spawned:
      str(body.spawned || body.spawnedAgo || body.spawnedLabel) ||
      'SPAWNED NOW'
  };
}

function publish(event) {
  const spawnedMs = new Date(event.spawnedAt).getTime();

  const packet = `data: ${JSON.stringify({
    ...event,
    type: 'SPAWN',
    eventType: 'spawn',
    timestamp: event.spawnedAt,
    time: event.spawnedAt,
    elapsedSeconds: Number.isFinite(spawnedMs)
      ? Math.max(0, Math.floor((Date.now() - spawnedMs) / 1000))
      : 0
  })}\n\n`;

  for (const [id, client] of sseClients) {
    try {
      client.write(packet);
    } catch (_) {
      sseClients.delete(id);
    }
  }
}

async function storeSpawn(parsed) {
  if (!pool) {
    return null;
  }

  const [mapping] = await pool.execute(
    `SELECT pet_name, pet_image_url
     FROM egg_pet_map
     WHERE LOWER(egg_name) = LOWER(?)
       AND is_active = 1
     LIMIT 1`,
    [parsed.eggName]
  );

  const petName =
    mapping[0]?.pet_name ||
    parsed.petName ||
    parsed.eggName;

  const petImageUrl =
    mapping[0]?.pet_image_url ||
    null;

  const expiry = new Date(
    parsed.spawnedAt.getTime() +
    DEFAULT_TIER_TTL_MINUTES * 60000
  );

  const [result] = await pool.execute(
    `INSERT INTO stocks (
       tier,
       egg_name,
       pet_name,
       pet_image_url,
       location_name,
       spawned_at,
       expires_at,
       source_message_id,
       created_at,
       updated_at
     )
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
    [
      parsed.tier,
      parsed.eggName,
      petName,
      petImageUrl,
      parsed.location,
      parsed.spawnedAt,
      expiry,
      parsed.messageId || null
    ]
  );

  const event = {
    id: result.insertId,
    tier: parsed.tier,
    eggName: parsed.eggName,
    petName,
    petImageUrl,
    location: parsed.location,
    biome: parsed.location,
    spawnedAt: parsed.spawnedAt.toISOString(),
    timestamp: parsed.spawnedAt.toISOString(),
    spawned: parsed.spawned,
    messageId: parsed.messageId || null,
    type: 'SPAWN',
    eventType: 'spawn'
  };

  recentEvents.unshift(event);

  if (recentEvents.length > MAX_EVENTS) {
    recentEvents.length = MAX_EVENTS;
  }

  publish(event);
  lastIngestAt = new Date().toISOString();

  return event;
}

/* =========================================================
   BASIC HEALTH / HOME
========================================================= */

app.get('/', (_req, res) => {
  res.type('html').send(
    '<!doctype html><meta charset="utf-8">' +
    '<title>Steal An Egg Backend</title>' +
    '<h1>Steal An Egg backend is running</h1>' +
    '<p><a href="/health">Health</a> · ' +
    '<a href="/get-key">Buyer key</a> · ' +
    '<a href="/admin">Admin</a></p>'
  );
});

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'steal-egg-saas-backend',
    timestamp: new Date().toISOString(),
    databaseConfigured: Boolean(DATABASE_URL),
    databaseConnected: dbStatus.connected,
    databaseMessage: dbStatus.message,
    lastIngestAt,
    sseClients: sseClients.size,
    configured: {
      jwtSecret: Boolean(JWT_SECRET),
      botIngestKey: Boolean(BOT_INGEST_KEY),
      adminPassword: Boolean(ADMIN_PASSWORD)
    }
  });
});

app.get('/health/database', async (_req, res) => {
  if (!pool) {
    return res.status(503).json({
      ok: false,
      ...dbStatus
    });
  }

  try {
    await pool.query('SELECT 1');

    return res.json({
      ok: true,
      connected: true,
      message: dbStatus.message
    });
  } catch (error) {
    return res.status(503).json({
      ok: false,
      connected: false,
      message: error.message
    });
  }
});

/* =========================================================
   DISCORD BOT INGEST
   Uses BOT_INGEST_KEY, NOT buyer API keys.
========================================================= */

app.post('/api/ingest', async (req, res) => {
  if (!BOT_INGEST_KEY) {
    return sendError(
      res,
      503,
      'BOT_INGEST_KEY is not configured'
    );
  }

  if (!safeEqual(req.get('x-bot-key'), BOT_INGEST_KEY)) {
    return sendError(res, 401, 'Invalid bot key');
  }

  if (!needDb(res)) {
    return;
  }

  const parsed = parseIngest(req.body || {});

  try {
    if (parsed.messageId) {
      if (seenMessageIds.has(parsed.messageId)) {
        return res.json({
          success: true,
          duplicate: true,
          event: null
        });
      }

      const [existing] = await pool.execute(
        'SELECT message_id FROM processed_messages WHERE message_id = ? LIMIT 1',
        [parsed.messageId]
      );

      if (existing.length) {
        seenMessageIds.add(parsed.messageId);

        return res.json({
          success: true,
          duplicate: true
        });
      }

      await pool.execute(
        'INSERT INTO processed_messages (message_id, processed_at) VALUES (?, CURRENT_TIMESTAMP)',
        [parsed.messageId]
      );

      seenMessageIds.add(parsed.messageId);
    }

    const event = await storeSpawn(parsed);

    return res.json({
      success: true,
      duplicate: false,
      event
    });
  } catch (error) {
    console.error('[ingest]', error.message || error);

    return sendError(
      res,
      500,
      'Could not save spawn event'
    );
  }
});

// Backward-compatible webhook route.
app.post('/api/bot-webhook', (req, res, next) => {
  const suppliedKey =
    req.get('x-bot-key') ||
    req.get('x-webhook-secret');

  if (
    !BOT_INGEST_KEY ||
    !safeEqual(suppliedKey, BOT_INGEST_KEY)
  ) {
    return sendError(res, 401, 'Invalid bot webhook key');
  }

  req.headers['x-bot-key'] = BOT_INGEST_KEY;

  return next();
}, async (req, res) => {
  if (!needDb(res)) {
    return;
  }

  const parsed = parseIngest(req.body || {});

  try {
    const event = await storeSpawn(parsed);

    return res.json({
      success: true,
      event
    });
  } catch (error) {
    console.error('[bot-webhook]', error.message || error);

    return sendError(
      res,
      500,
      'Could not save spawn event'
    );
  }
});

/* =========================================================
   CURRENT STOCK API
   V314 can use this same buyer API key.
========================================================= */

app.get('/api/stocks', requireApiKey, async (_req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT
         id,
         tier,
         egg_name AS eggName,
         pet_name AS petName,
         pet_image_url AS petImageUrl,
         location_name AS location,
         location_name AS biome,
         spawned_at AS spawnedAt,
         spawned_at AS timestamp,
         expires_at AS expiresAt,
         source_message_id AS messageId
       FROM stocks
       WHERE expires_at IS NULL
          OR expires_at > CURRENT_TIMESTAMP
       ORDER BY spawned_at DESC, id DESC
       LIMIT 250`
    );

    const stocks = rows.map(row => {
      const spawnedMs = new Date(row.spawnedAt).getTime();

      return {
        ...row,
        type: 'SPAWN',
        eventType: 'spawn',
        spawned: 'SPAWNED',
        elapsedSeconds: Number.isFinite(spawnedMs)
          ? Math.max(
              0,
              Math.floor((Date.now() - spawnedMs) / 1000)
            )
          : 0
      };
    });

    res.set('Cache-Control', 'no-store');

    return res.json({
      success: true,
      stocks,
      currentStocks: stocks,
      items: stocks,
      count: stocks.length,
      lastIngestAt
    });
  } catch (error) {
    console.error('[stocks]', error.message || error);

    return sendError(
      res,
      500,
      'Could not load current stocks'
    );
  }
});

/* =========================================================
   SCHEDULE / SPAWN HISTORY COMPATIBILITY
========================================================= */

app.get('/api/schedule', requireApiKey, async (_req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT
         id,
         tier,
         egg_name AS eggName,
         pet_name AS petName,
         pet_image_url AS petImageUrl,
         location_name AS location,
         location_name AS biome,
         spawned_at AS spawnedAt,
         spawned_at AS timestamp,
         source_message_id AS messageId
       FROM stocks
       ORDER BY spawned_at DESC, id DESC
       LIMIT 250`
    );

    const schedules = rows.map(row => {
      const spawnedMs = new Date(row.timestamp).getTime();

      return {
        ...row,
        type: 'SPAWN',
        eventType: 'spawn',
        time: row.timestamp,
        remainingSeconds: 0,
        elapsedSeconds: Number.isFinite(spawnedMs)
          ? Math.max(
              0,
              Math.floor((Date.now() - spawnedMs) / 1000)
            )
          : 0
      };
    });

    res.set('Cache-Control', 'no-store');

    return res.json({
      success: true,
      schedules,
      lastIngestAt,
      webhookReceived: Boolean(lastIngestAt),
      activeSchedules: schedules.length
    });
  } catch (error) {
    console.error('[schedule]', error.message || error);

    return sendError(
      res,
      500,
      'Could not load spawn history'
    );
  }
});

/* =========================================================
   LIVE SSE STREAM
   GET /events?apiKey=BUYER_KEY

   Same buyer key as /api/stocks.
   Sends connection event, recent events, and live events.
========================================================= */

app.get('/events', requireApiKey, (req, res) => {
  res.status(200).set({
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no'
  });

  if (typeof res.flushHeaders === 'function') {
    res.flushHeaders();
  }

  const clientId = crypto.randomUUID();

  sseClients.set(clientId, res);

  res.write(
    `event: connected\ndata: ${JSON.stringify({
      connected: true,
      timestamp: new Date().toISOString()
    })}\n\n`
  );

  // Replay recent in-memory events after a client connects.
  if (recentEvents.length) {
    for (const event of [...recentEvents].reverse()) {
      const spawnedMs = new Date(event.spawnedAt).getTime();

      res.write(
        `data: ${JSON.stringify({
          ...event,
          type: 'SPAWN',
          eventType: 'spawn',
          timestamp: event.spawnedAt,
          time: event.spawnedAt,
          elapsedSeconds: Number.isFinite(spawnedMs)
            ? Math.max(
                0,
                Math.floor((Date.now() - spawnedMs) / 1000)
              )
            : 0
        })}\n\n`
      );
    }
  }

  const heartbeat = setInterval(() => {
    try {
      res.write(': heartbeat\n\n');
    } catch (_) {
      clearInterval(heartbeat);
      sseClients.delete(clientId);
    }
  }, 20000);

  req.on('close', () => {
    clearInterval(heartbeat);
    sseClients.delete(clientId);
  });
});

/* =========================================================
   BUYER LOGIN AND API KEY GENERATION
========================================================= */

app.post('/api/buyer/login', async (req, res) => {
  if (!needDb(res)) {
    return;
  }

  const email = str(
    req.body?.email || req.body?.username
  ).toLowerCase();

  const password = str(req.body?.password);

  if (!email || !password) {
    return sendError(
      res,
      400,
      'Email and password are required'
    );
  }

  try {
    const [rows] = await pool.execute(
      `SELECT id, email, password_hash, is_active
       FROM users
       WHERE LOWER(email) = ?
       LIMIT 1`,
      [email]
    );

    if (
      !rows.length ||
      !rows[0].is_active ||
      !(await bcrypt.compare(
        password,
        rows[0].password_hash
      ))
    ) {
      return sendError(
        res,
        401,
        'Invalid email or password'
      );
    }

    const ttl = process.env.USER_SESSION_TTL
      ? Number(process.env.USER_SESSION_TTL)
      : '30m';

    const token = signToken({
      role: 'buyer',
      userId: rows[0].id,
      email: rows[0].email
    }, ttl);

    return res.json({
      success: true,
      token,
      email: rows[0].email
    });
  } catch (error) {
    console.error('[buyer login]', error.message || error);

    return sendError(
      res,
      500,
      'Buyer login failed'
    );
  }
});

app.post('/api/buyer/generate-key', async (req, res) => {
  if (!needDb(res)) {
    return;
  }

  const session = verifySession(req, 'buyer');

  if (!session?.userId) {
    return sendError(res, 401, 'Buyer login required');
  }

  try {
    const [oldKeys] = await pool.execute(
      `SELECT id
       FROM api_keys
       WHERE user_id = ?
         AND is_active = 1
         AND (
           expires_at IS NULL
           OR expires_at > CURRENT_TIMESTAMP
         )
       ORDER BY created_at DESC
       LIMIT 1`,
      [session.userId]
    );

    if (oldKeys.length) {
      return sendError(
        res,
        409,
        'An active API key already exists. Use the existing key or explicitly rotate it.'
      );
    }

    const rawKey =
      'sk_live_' + crypto.randomBytes(24).toString('hex');

    const expiresDays = Math.max(
      1,
      Number(process.env.API_KEY_TTL_DAYS || 90)
    );

    await pool.execute(
      `INSERT INTO api_keys (
         user_id,
         key_hash,
         key_prefix,
         is_active,
         expires_at,
         created_at
       )
       VALUES (
         ?,
         ?,
         ?,
         1,
         DATE_ADD(CURRENT_TIMESTAMP, INTERVAL ? DAY),
         CURRENT_TIMESTAMP
       )`,
      [
        session.userId,
        sha256(rawKey),
        rawKey.slice(0, 16),
        expiresDays
      ]
    );

    return res.json({
      success: true,
      apiKey: rawKey,
      reused: false,
      expiresInDays: expiresDays
    });
  } catch (error) {
    console.error('[generate key]', error.message || error);

    return sendError(
      res,
      500,
      'Could not generate API key'
    );
  }
});

app.post('/api/buyer/rotate-key', async (req, res) => {
  if (!needDb(res)) {
    return;
  }

  const session = verifySession(req, 'buyer');

  if (!session?.userId) {
    return sendError(res, 401, 'Buyer login required');
  }

  try {
    await pool.execute(
      'UPDATE api_keys SET is_active = 0 WHERE user_id = ? AND is_active = 1',
      [session.userId]
    );

    const rawKey =
      'sk_live_' + crypto.randomBytes(24).toString('hex');

    const expiresDays = Math.max(
      1,
      Number(process.env.API_KEY_TTL_DAYS || 90)
    );

    await pool.execute(
      `INSERT INTO api_keys (
         user_id,
         key_hash,
         key_prefix,
         is_active,
         expires_at,
         created_at
       )
       VALUES (
         ?,
         ?,
         ?,
         1,
         DATE_ADD(CURRENT_TIMESTAMP, INTERVAL ? DAY),
         CURRENT_TIMESTAMP
       )`,
      [
        session.userId,
        sha256(rawKey),
        rawKey.slice(0, 16),
        expiresDays
      ]
    );

    return res.json({
      success: true,
      apiKey: rawKey,
      rotated: true,
      expiresInDays: expiresDays
    });
  } catch (error) {
    console.error('[rotate key]', error.message || error);

    return sendError(
      res,
      500,
      'Could not rotate API key'
    );
  }
});

/* =========================================================
   ADMIN / MASTER LOGIN
========================================================= */

app.post('/api/admin/login', (req, res) => {
  if (!ADMIN_PASSWORD || !JWT_SECRET) {
    return sendError(
      res,
      503,
      'ADMIN_PASSWORD and JWT_SECRET must be configured'
    );
  }

  if (
    !safeEqual(str(req.body?.username), ADMIN_USERNAME) ||
    !safeEqual(str(req.body?.password), ADMIN_PASSWORD)
  ) {
    return sendError(
      res,
      401,
      'Invalid admin credentials'
    );
  }

  return res.json({
    success: true,
    token: signToken({ role: 'admin' }, '12h')
  });
});

function requireAdmin(req, res, next) {
  const session = verifySession(req, 'admin');

  if (!session) {
    return sendError(res, 401, 'Admin login required');
  }

  req.admin = session;

  return next();
}

app.post('/api/admin/users', requireAdmin, async (req, res) => {
  if (!needDb(res)) {
    return;
  }

  const email = str(req.body?.email).toLowerCase();
  const password = str(req.body?.password);

  if (
    !/^\S+@\S+\.\S+$/.test(email) ||
    password.length < 8
  ) {
    return sendError(
      res,
      400,
      'Valid email and password of at least 8 characters are required'
    );
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);

    await pool.execute(
      `INSERT INTO users (
         email,
         password_hash,
         is_active,
         created_at,
         updated_at
       )
       VALUES (?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
      [email, passwordHash]
    );

    return res.json({
      success: true,
      email
    });
  } catch (error) {
    return sendError(
      res,
      error.code === 'ER_DUP_ENTRY' ? 409 : 500,
      error.code === 'ER_DUP_ENTRY'
        ? 'Email already exists'
        : 'Could not create buyer'
    );
  }
});

app.get('/api/admin/users', requireAdmin, async (_req, res) => {
  if (!needDb(res)) {
    return;
  }

  try {
    const [rows] = await pool.execute(
      `SELECT
         u.id,
         u.email,
         u.created_at,
         COUNT(k.id) AS key_count
       FROM users u
       LEFT JOIN api_keys k
         ON k.user_id = u.id
        AND k.is_active = 1
       GROUP BY u.id, u.email, u.created_at
       ORDER BY u.created_at DESC
       LIMIT 500`
    );

    return res.json({
      success: true,
      users: rows
    });
  } catch (_) {
    return sendError(res, 500, 'Could not list buyers');
  }
});

app.post('/api/admin/egg-map', requireAdmin, async (req, res) => {
  if (!needDb(res)) {
    return;
  }

  const egg = str(req.body?.eggName);
  const pet = str(req.body?.petName);
  const image = str(req.body?.petImageUrl) || null;
  const tier = normalizeTier(req.body?.tier);

  if (!egg || !pet) {
    return sendError(
      res,
      400,
      'eggName and petName are required'
    );
  }

  try {
    await pool.execute(
      `INSERT INTO egg_pet_map (
         egg_name,
         pet_name,
         pet_image_url,
         tier,
         is_active,
         created_at,
         updated_at
       )
       VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
       ON DUPLICATE KEY UPDATE
         pet_name = VALUES(pet_name),
         pet_image_url = VALUES(pet_image_url),
         tier = VALUES(tier),
         is_active = 1,
         updated_at = CURRENT_TIMESTAMP`,
      [egg, pet, image, tier]
    );

    return res.json({ success: true });
  } catch (_) {
    return sendError(
      res,
      500,
      'Could not save egg/pet mapping'
    );
  }
});

/* =========================================================
   LEGACY MASTER ROUTE ALIASES
========================================================= */

app.post('/api/master/login', (req, res) => {
  if (!ADMIN_PASSWORD || !JWT_SECRET) {
    return sendError(
      res,
      503,
      'ADMIN_PASSWORD and JWT_SECRET must be configured'
    );
  }

  const suppliedUser = str(
    req.body?.username ||
    req.body?.email ||
    ADMIN_USERNAME
  );

  if (
    !safeEqual(suppliedUser, ADMIN_USERNAME) ||
    !safeEqual(str(req.body?.password), ADMIN_PASSWORD)
  ) {
    return sendError(
      res,
      401,
      'Invalid master credentials'
    );
  }

  return res.json({
    success: true,
    token: signToken({ role: 'admin' }, '12h')
  });
});

app.get('/api/master/users', requireAdmin, async (_req, res) => {
  if (!needDb(res)) {
    return;
  }

  try {
    const [rows] = await pool.execute(
      `SELECT
         u.id,
         u.email AS username,
         u.email,
         u.created_at AS createdAt,
         COUNT(k.id) AS key_count,
         MAX(k.is_active) AS hasApiKey
       FROM users u
       LEFT JOIN api_keys k ON k.user_id = u.id
       GROUP BY u.id, u.email, u.created_at
       ORDER BY u.created_at DESC
       LIMIT 500`
    );

    return res.json({
      success: true,
      users: rows.map(row => ({
        ...row,
        hasApiKey: Boolean(row.hasApiKey)
      }))
    });
  } catch (_) {
    return sendError(res, 500, 'Could not list buyers');
  }
});

app.post('/api/master/add-user', requireAdmin, async (req, res) => {
  if (!needDb(res)) {
    return;
  }

  const email = str(
    req.body?.email || req.body?.username
  ).toLowerCase();

  const password = str(req.body?.password);

  if (
    !/^\S+@\S+\.\S+$/.test(email) ||
    password.length < 8
  ) {
    return sendError(
      res,
      400,
      'Valid buyer email and password of at least 8 characters are required'
    );
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);

    await pool.execute(
      `INSERT INTO users (
         email,
         password_hash,
         is_active,
         created_at,
         updated_at
       )
       VALUES (?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
      [email, passwordHash]
    );

    return res.json({
      success: true,
      username: email,
      email
    });
  } catch (error) {
    return sendError(
      res,
      error.code === 'ER_DUP_ENTRY' ? 409 : 500,
      error.code === 'ER_DUP_ENTRY'
        ? 'Email already exists'
        : 'Could not create buyer'
    );
  }
});

/* =========================================================
   PAGE ROUTES
========================================================= */

app.get('/get-key', (_req, res) => {
  res.sendFile(
    path.join(__dirname, 'public', 'get-key.html'),
    error => {
      if (error && !res.headersSent) {
        res.status(404).type('text').send(
          'Create public/get-key.html or use the buyer login API.'
        );
      }
    }
  );
});

app.get('/generator', (_req, res) => {
  res.sendFile(
    path.join(__dirname, 'public', 'get-key.html'),
    error => {
      if (error && !res.headersSent) {
        res.status(404).type('text').send(
          'Create public/get-key.html or use the buyer login API.'
        );
      }
    }
  );
});

app.get('/admin', (_req, res) => {
  res.sendFile(
    path.join(__dirname, 'public', 'admin.html'),
    error => {
      if (error && !res.headersSent) {
        res.status(404).type('text').send(
          'Create public/admin.html or use the admin login API.'
        );
      }
    }
  );
});

app.get('/master', (_req, res) => {
  res.sendFile(
    path.join(__dirname, 'public', 'admin.html'),
    error => {
      if (error && !res.headersSent) {
        res.status(404).type('text').send(
          'Create public/admin.html or use the admin login API.'
        );
      }
    }
  );
});

app.get('/overlay', (req, res) => {
  const expectedToken = str(process.env.OVERLAY_TOKEN);

  if (
    expectedToken &&
    !safeEqual(str(req.query.token), expectedToken)
  ) {
    return res.status(403).type('text').send(
      'Invalid overlay token'
    );
  }

  return res.sendFile(
    path.join(__dirname, 'public', 'overlay.html'),
    error => {
      if (error && !res.headersSent) {
        res.status(404).type('text').send(
          'Create public/overlay.html.'
        );
      }
    }
  );
});

/* =========================================================
   FINAL ERROR HANDLER AND SERVER START
========================================================= */

app.use((error, _req, res, _next) => {
  console.error('[request error]', error.message || error);

  if (!res.headersSent) {
    sendError(res, 500, 'Internal server error');
  }
});

(async () => {
  await initDb();

  app.listen(PORT, '0.0.0.0', () => {
    console.log(
      `[backend] listening on ${PORT}; ` +
      `databaseConnected=${dbStatus.connected}; ` +
      dbStatus.message
    );

    if (!BOT_INGEST_KEY) {
      console.warn(
        '[config] BOT_INGEST_KEY missing: bot ingest is disabled.'
      );
    }

    if (!ADMIN_PASSWORD) {
      console.warn(
        '[config] ADMIN_PASSWORD missing: admin login is disabled.'
      );
    }
  });
})();
