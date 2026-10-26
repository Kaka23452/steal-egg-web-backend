
'use strict';

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const { rateLimit } = require('express-rate-limit');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = path.join(__dirname, 'public');

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

// ==========================================================
// 1. CORS CONFIGURATION
// ==========================================================

const allowedOrigins = (process.env.ALLOWED_ORIGIN || '*')
  .split(',')
  .map(value => value.trim())
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

    return callback(null, false);
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-API-Key',
    'X-Bot-Key',
    'X-Admin-Username',
    'X-Admin-Password',
    'X-Overlay-Token'
  ],
  maxAge: 600
}));

// ==========================================================
// 2. MYSQL CONNECTION
// ==========================================================

function createDatabasePool() {
  const connectionString = process.env.DATABASE_URL;

  if (!connectionString) {
    throw new Error('DATABASE_URL is missing from backend/.env');
  }

  const url = new URL(connectionString);

  if (url.protocol !== 'mysql:') {
    throw new Error('DATABASE_URL must use the mysql:// protocol');
  }

  const databaseName = decodeURIComponent(
    url.pathname.replace(/^\/+/, '')
  );

  if (!url.hostname || !url.username || !databaseName) {
    throw new Error(
      'DATABASE_URL must contain host, username and database name'
    );
  }

  const options = {
    host: url.hostname,
    port: Number(url.port || 3306),
    user: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
    database: databaseName,
    waitForConnections: true,
    connectionLimit: Number(process.env.DB_CONNECTION_LIMIT || 10),
    maxIdle: 5,
    idleTimeout: 60000,
    queueLimit: 100,
    timezone: 'Z',
    dateStrings: false
  };

  if (process.env.DB_SSL === 'true') {
    options.ssl = { rejectUnauthorized: true };
  }

  return mysql.createPool(options);
}

let pool;

try {
  pool = createDatabasePool();
} catch (error) {
  console.error('[database] Configuration error:', error.message);
  process.exit(1);
}

pool.on('connection', connection => {
  connection.query("SET time_zone = '+00:00'")
    .catch(error => {
      console.error('[database] Timezone setup failed:', error.message);
    });
});

// ==========================================================
// 3. GENERAL HELPERS
// ==========================================================

function httpError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function wrap(handler) {
  return function wrappedHandler(req, res, next) {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

function safeEqual(first, second) {
  if (first == null || second == null) return false;

  const a = Buffer.from(String(first));
  const b = Buffer.from(String(second));

  if (a.length !== b.length || a.length === 0) {
    return false;
  }

  return crypto.timingSafeEqual(a, b);
}

function sha256(value) {
  return crypto
    .createHash('sha256')
    .update(value, 'utf8')
    .digest('hex');
}

function normalizeText(value, maxLength = 191) {
  if (typeof value !== 'string') return '';

  return value
    .trim()
    .replace(/\s+/g, ' ')
    .slice(0, maxLength);
}

function normalizeEmail(value) {
  return normalizeText(value, 254).toLowerCase();
}

function validEmail(value) {
  return (
    typeof value === 'string' &&
    value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)
  );
}

function validId(value) {
  return /^\d+$/.test(String(value)) &&
    Number(value) > 0 &&
    Number.isSafeInteger(Number(value));
}

function requireSecret(name) {
  const value = process.env[name];

  if (!value || value.startsWith('REPLACE_WITH_')) {
    throw httpError(503, `${name} is not configured`);
  }

  return value;
}

function getBearerToken(req) {
  const header = req.get('authorization') || '';
  const match = header.match(/^Bearer\s+(.+)$/i);

  return match ? match[1].trim() : '';
}

function sendOk(res, data = {}) {
  return res.json({ ok: true, ...data });
}

// ==========================================================
// 4. RATE LIMITERS
// ==========================================================

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    ok: false,
    error: 'Too many login attempts. Please try again later.'
  }
});

const keyGenerationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: Math.max(
    1,
    Number(process.env.KEY_GEN_RATE_LIMIT || 5)
  ),
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    ok: false,
    error: 'Key generation limit reached. Try again later.'
  }
});

const ingestLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: Math.max(
    1,
    Number(process.env.INGEST_RATE_LIMIT_PER_MIN || 120)
  ),
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    ok: false,
    error: 'Ingest rate limit reached.'
  }
});

// ==========================================================
// 5. USER SESSION AUTHENTICATION
// ==========================================================

const requireUserSession = wrap(async (req, res, next) => {
  const token = getBearerToken(req) ||
    req.get('x-session-token');

  if (!token) {
    throw httpError(401, 'Login session required');
  }

  const secret = requireSecret('JWT_SECRET');

  let payload;

  try {
    payload = jwt.verify(token, secret);
  } catch {
    throw httpError(401, 'Session expired or invalid');
  }

  if (payload.role !== 'user' || !validId(payload.sub)) {
    throw httpError(401, 'Invalid user session');
  }

  const [rows] = await pool.execute(
    'SELECT id, email, status FROM users WHERE id = ? LIMIT 1',
    [Number(payload.sub)]
  );

  const user = rows[0];

  if (!user || user.status !== 'active') {
    throw httpError(401, 'User account is unavailable');
  }

  req.sessionUser = user;
  next();
});

// ==========================================================
// 6. API KEY AUTHENTICATION
// ==========================================================

const requireApiKey = wrap(async (req, res, next) => {
  const apiKey = normalizeText(
    req.get('x-api-key') || getBearerToken(req),
    200
  );

  if (!apiKey || !/^sk_live_[a-f0-9]{48}$/.test(apiKey)) {
    throw httpError(401, 'A valid API key is required');
  }

  const [rows] = await pool.execute(
    `SELECT
       k.id AS key_id,
       k.user_id,
       u.email,
       u.status
     FROM api_keys k
     INNER JOIN users u ON u.id = k.user_id
     WHERE k.key_hash = ?
       AND k.revoked_at IS NULL
       AND k.expires_at > UTC_TIMESTAMP(3)
     LIMIT 1`,
    [sha256(apiKey)]
  );

  const record = rows[0];

  if (!record || record.status !== 'active') {
    throw httpError(401, 'API key is invalid, expired or revoked');
  }

  await pool.execute(
    'UPDATE api_keys SET last_used_at = UTC_TIMESTAMP(3) WHERE id = ?',
    [record.key_id]
  );

  req.apiKeyUser = {
    id: record.user_id,
    email: record.email
  };

  req.apiKeyId = record.key_id;

  next();
});

// ==========================================================
// 7. DISCORD BOT AUTHENTICATION
// ==========================================================

function requireBotKey(req, res, next) {
  let configuredKey;

  try {
    configuredKey = requireSecret('BOT_INGEST_KEY');
  } catch (error) {
    return res.status(error.status).json({
      ok: false,
      error: error.message
    });
  }

  if (!safeEqual(req.get('x-bot-key'), configuredKey)) {
    return res.status(401).json({
      ok: false,
      error: 'Invalid bot authentication'
    });
  }

  next();
}

// ==========================================================
// 8. ADMIN AUTHENTICATION
// Headers are sent by the Admin Panel on every request.
// ==========================================================

function requireAdmin(req, res, next) {
  const expectedUsername = process.env.ADMIN_USERNAME;
  const expectedPassword = process.env.ADMIN_PASSWORD;

  if (
    !expectedUsername ||
    !expectedPassword ||
    expectedPassword === 'Admin123' ||
    expectedPassword.startsWith('REPLACE_WITH_')
  ) {
    return res.status(503).json({
      ok: false,
      error: 'Admin credentials are not securely configured'
    });
  }

  const username = req.get('x-admin-username');
  const password = req.get('x-admin-password');

  if (
    !safeEqual(username, expectedUsername) ||
    !safeEqual(password, expectedPassword)
  ) {
    return res.status(401).json({
      ok: false,
      error: 'Admin authentication failed'
    });
  }

  next();
}

// ==========================================================
// 9. OBS OVERLAY AUTHENTICATION
// ==========================================================

function requireOverlayToken(req, res, next) {
  let expectedToken;

  try {
    expectedToken = requireSecret('OVERLAY_TOKEN');
  } catch (error) {
    return res.status(error.status).json({
      ok: false,
      error: error.message
    });
  }

  const token = req.get('x-overlay-token');

  if (!safeEqual(token, expectedToken)) {
    return res.status(401).json({
      ok: false,
      error: 'Invalid overlay token'
    });
  }

  next();
}

// ==========================================================
// 10. STOCK AND MESSAGE HELPERS
// ==========================================================

function parseSpawnedAt(value) {
  if (value == null || value === '') {
    return new Date();
  }

  if (value instanceof Date && !Number.isNaN(value.getTime())) {
    return value;
  }

  if (typeof value === 'number' && Number.isFinite(value)) {
    const date = new Date(value);

    if (!Number.isNaN(date.getTime())) return date;
  }

  const raw = String(value).trim();

  if (/^(just now|now)$/i.test(raw)) {
    return new Date();
  }

  const relative = raw.match(
    /^(\d+)\s*(s|sec|seconds?|m|min|minutes?|h|hours?|d|days?)\s+ago$/i
  );

  if (relative) {
    const amount = Number(relative[1]);
    const unit = relative[2].toLowerCase();

    let milliseconds;

    if (unit.startsWith('s')) {
      milliseconds = amount * 1000;
    } else if (unit.startsWith('m')) {
      milliseconds = amount * 60 * 1000;
    } else if (unit.startsWith('h')) {
      milliseconds = amount * 60 * 60 * 1000;
    } else {
      milliseconds = amount * 24 * 60 * 60 * 1000;
    }

    return new Date(Date.now() - milliseconds);
  }

  const parsed = new Date(raw);

  if (!Number.isNaN(parsed.getTime())) {
    return parsed;
  }

  throw httpError(400, 'Invalid spawn time. Use an ISO date or "2 minutes ago".');
}

async function resolveLocation(location) {
  let current = normalizeText(location);

  if (!current) {
    throw httpError(400, 'Location is required');
  }

  const visited = new Set();

  // Follow a maximum of five alias links.
  for (let i = 0; i < 5; i++) {
    const key = current.toLowerCase();

    if (visited.has(key)) break;
    visited.add(key);

    const [rows] = await pool.execute(
      `SELECT to_name
       FROM location_alias
       WHERE from_name = ?
       LIMIT 1`,
      [current]
    );

    if (!rows.length) break;

    const next = normalizeText(rows[0].to_name);

    if (!next || next.toLowerCase() === key) break;

    current = next;
  }

  return current;
}

async function resolvePetName(eggName) {
  const egg = normalizeText(eggName);

  const [rows] = await pool.execute(
    `SELECT pet_name
     FROM egg_pet_map
     WHERE egg_name = ?
     LIMIT 1`,
    [egg]
  );

  if (rows.length && normalizeText(rows[0].pet_name)) {
    return normalizeText(rows[0].pet_name);
  }

  // Automatic fallback: "Shadow Wolf Egg" -> "Shadow Wolf".
  return egg.replace(/\s+Egg$/i, '').trim() || egg;
}

async function getActiveStocks(limit = 200) {
  const safeLimit = Math.min(
    500,
    Math.max(1, Number(limit) || 200)
  );

  const [rows] = await pool.query(
    `SELECT
       id,
       tier,
       egg_name,
       pet_name,
       location,
       DATE_FORMAT(
         spawned_at,
         '%Y-%m-%dT%H:%i:%s.%fZ'
       ) AS spawned_at,
       DATE_FORMAT(
         expires_at,
         '%Y-%m-%dT%H:%i:%s.%fZ'
       ) AS expires_at,
       GREATEST(
         TIMESTAMPDIFF(SECOND, UTC_TIMESTAMP(3), expires_at),
         0
       ) AS remaining_seconds
     FROM stocks
     WHERE expires_at > UTC_TIMESTAMP(3)
     ORDER BY spawned_at DESC, id DESC
     LIMIT ${safeLimit}`
  );

  return rows;
}

// ==========================================================
// 11. SERVER-SENT EVENTS — DASHBOARD AND OBS
// ==========================================================

const sseClients = new Set();

function writeSse(client, payload) {
  if (!client || client.res.writableEnded || client.res.destroyed) {
    return false;
  }

  try {
    client.res.write(`data: ${JSON.stringify(payload)}\n\n`);
    return true;
  } catch {
    return false;
  }
}

function removeSseClient(client) {
  if (!client) return;

  sseClients.delete(client);

  if (client.heartbeat) {
    clearInterval(client.heartbeat);
  }

  if (!client.res.writableEnded) {
    client.res.end();
  }
}

function registerSseClient(req, res, type, initialStocks, userId = null) {
  res.status(200);
  res.set({
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no'
  });

  res.flushHeaders();

  const client = {
    res,
    type,
    userId,
    heartbeat: null
  };

  sseClients.add(client);

  writeSse(client, {
    type: 'stocks',
    stocks: type === 'overlay'
      ? initialStocks.slice(0, 5)
      : initialStocks
  });

  client.heartbeat = setInterval(() => {
    if (res.writableEnded || res.destroyed) {
      removeSseClient(client);
      return;
    }

    try {
      res.write(`: heartbeat ${Date.now()}\n\n`);
    } catch {
      removeSseClient(client);
    }
  }, 25000);

  if (client.heartbeat.unref) {
    client.heartbeat.unref();
  }

  req.on('close', () => {
    if (sseClients.has(client)) {
      sseClients.delete(client);

      if (client.heartbeat) {
        clearInterval(client.heartbeat);
      }
    }
  });
}

async function broadcastStocks() {
  const stocks = await getActiveStocks(200);

  for (const client of sseClients) {
    const visibleStocks = client.type === 'overlay'
      ? stocks.slice(0, 5)
      : stocks;

    if (!writeSse(client, {
      type: 'stocks',
      stocks: visibleStocks
    })) {
      removeSseClient(client);
    }
  }
}

function closeUserConnections(userId) {
  for (const client of sseClients) {
    if (
      client.type === 'dashboard' &&
      Number(client.userId) === Number(userId)
    ) {
      removeSseClient(client);
    }
  }
}

// ==========================================================
// 12. HEALTH CHECK
// ==========================================================

app.get('/health', wrap(async (req, res) => {
  try {
    await pool.query('SELECT 1');

    return res.json({
      ok: true,
      db: 'up'
    });
  } catch {
    return res.status(503).json({
      ok: false,
      db: 'down'
    });
  }
}));

// ==========================================================
// 13. USER LOGIN AND SESSION
// ==========================================================

app.post('/api/auth/login', loginLimiter, wrap(async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = req.body.password;

  if (
    !validEmail(email) ||
    typeof password !== 'string' ||
    password.length === 0 ||
    password.length > 200
  ) {
    throw httpError(400, 'Enter a valid email and password');
  }

  const [rows] = await pool.execute(
    `SELECT id, email, password_hash, status
     FROM users
     WHERE email = ?
     LIMIT 1`,
    [email]
  );

  const user = rows[0];

  // Use the same external error message for missing users
  // and incorrect passwords.
  if (!user || user.status !== 'active') {
    throw httpError(401, 'Invalid email or password');
  }

  const passwordMatches = await bcrypt.compare(
    password,
    user.password_hash
  );

  if (!passwordMatches) {
    throw httpError(401, 'Invalid email or password');
  }

  const sessionSecret = requireSecret('JWT_SECRET');
  const sessionTtl = Math.max(
    60,
    Number(process.env.USER_SESSION_TTL || 1800)
  );

  const token = jwt.sign(
    {
      sub: String(user.id),
      role: 'user'
    },
    sessionSecret,
    { expiresIn: sessionTtl }
  );

  await pool.execute(
    'UPDATE users SET last_login_at = UTC_TIMESTAMP(3) WHERE id = ?',
    [user.id]
  );

  return sendOk(res, {
    token,
    expiresIn: sessionTtl,
    user: {
      id: user.id,
      email: user.email
    }
  });
}));

app.post('/api/auth/logout', (req, res) => {
  // The frontend must discard its session token.
  // API keys are independent of this login session.
  return sendOk(res, {
    message: 'Session cleared on the client'
  });
});

// ==========================================================
// 14. USER API KEY MANAGEMENT
// ==========================================================

app.get('/api/auth/keys', requireUserSession, wrap(async (req, res) => {
  const [rows] = await pool.execute(
    `SELECT
       id,
       label,
       key_prefix,
       key_suffix,
       created_at,
       expires_at,
       last_used_at,
       revoked_at
     FROM api_keys
     WHERE user_id = ?
     ORDER BY id DESC`,
    [req.sessionUser.id]
  );

  return sendOk(res, { keys: rows });
}));

app.post(
  '/api/auth/keys',
  requireUserSession,
  keyGenerationLimiter,
  wrap(async (req, res) => {
    const label = normalizeText(req.body.label || 'Default device', 100);

    const [countRows] = await pool.execute(
      `SELECT COUNT(*) AS total
       FROM api_keys
       WHERE user_id = ?
         AND revoked_at IS NULL
         AND expires_at > UTC_TIMESTAMP(3)`,
      [req.sessionUser.id]
    );

    if (Number(countRows[0].total) >= 20) {
      throw httpError(409, 'Maximum of 20 active API keys reached');
    }

    const apiKey = `sk_live_${crypto.randomBytes(24).toString('hex')}`;
    const keyHash = sha256(apiKey);
    const keyPrefix = apiKey.slice(0, 24);
    const keySuffix = apiKey.slice(-4);

    await pool.execute(
      `INSERT INTO api_keys
         (user_id, label, key_hash, key_prefix, key_suffix, expires_at)
       VALUES (
         ?, ?, ?, ?, ?,
         DATE_ADD(UTC_TIMESTAMP(3), INTERVAL 90 DAY)
       )`,
      [
        req.sessionUser.id,
        label || 'Default device',
        keyHash,
        keyPrefix,
        keySuffix
      ]
    );

    // The full key is returned once only.
    return res.status(201).json({
      ok: true,
      key: apiKey,
      message: 'Copy this API key now. It will not be shown again.'
    });
  })
);

app.delete(
  '/api/auth/keys/:id',
  requireUserSession,
  wrap(async (req, res) => {
    if (!validId(req.params.id)) {
      throw httpError(400, 'Invalid API key ID');
    }

    const [result] = await pool.execute(
      `UPDATE api_keys
       SET revoked_at = UTC_TIMESTAMP(3)
       WHERE id = ?
         AND user_id = ?
         AND revoked_at IS NULL`,
      [Number(req.params.id), req.sessionUser.id]
    );

    if (!result.affectedRows) {
      throw httpError(404, 'Active API key not found');
    }

    closeUserConnections(req.sessionUser.id);

    return sendOk(res, { message: 'API key revoked' });
  })
);

// ==========================================================
// 15. USER DASHBOARD STOCK APIs
// ==========================================================

app.get('/api/stocks', requireApiKey, wrap(async (req, res) => {
  const stocks = await getActiveStocks(200);

  return sendOk(res, { stocks });
}));

app.get('/api/stream', requireApiKey, wrap(async (req, res) => {
  const stocks = await getActiveStocks(200);

  registerSseClient(
    req,
    res,
    'dashboard',
    stocks,
    req.apiKeyUser.id
  );
}));

// ==========================================================
// 16. DISCORD INGESTION
// Expected data:
// { messageId, tier, eggName, location, spawnedAt }
// ==========================================================

let lastIngestAt = null;

app.post(
  '/api/ingest',
  ingestLimiter,
  requireBotKey,
  wrap(async (req, res) => {
    const body = req.body || {};

    const tier = normalizeText(body.tier, 64);
    const eggName = normalizeText(
      body.eggName || body.egg_name,
      191
    );
    const locationInput = normalizeText(
      body.location,
      191
    );

    const spawnedValue =
      body.spawnedAt ??
      body.spawned_at ??
      body.spawned ??
      body.timestamp;

    if (!tier || !eggName || !locationInput) {
      throw httpError(
        400,
        'Missing required fields: tier, eggName, location'
      );
    }

    const spawnedAt = parseSpawnedAt(spawnedValue);
    const location = await resolveLocation(locationInput);
    const petName = await resolvePetName(eggName);

    const ttlMinutes = Math.min(
      10080,
      Math.max(
        1,
        Number(process.env.DEFAULT_TIER_TTL_MINUTES || 45)
      )
    );

    const expiresAt = new Date(
      spawnedAt.getTime() + ttlMinutes * 60 * 1000
    );

    // Discord snowflake IDs are preferred for deduplication.
    // A generated ID keeps manual testing possible without one.
    const providedId =
      body.messageId ||
      body.message_id ||
      body.discordMessageId;

    const messageId = providedId
      ? String(providedId).trim()
      : crypto.randomBytes(16).toString('hex');

    if (!/^\d{1,32}$/.test(messageId) && providedId) {
      throw httpError(400, 'Invalid Discord message ID');
    }

    const conn = await pool.getConnection();

    let stockId;

    try {
      await conn.beginTransaction();

      // Remove this exact ID if its deduplication record has expired.
      await conn.execute(
        `DELETE FROM processed_messages
         WHERE message_id = ?
           AND expires_at <= UTC_TIMESTAMP(3)`,
        [messageId]
      );

      try {
        await conn.execute(
          `INSERT INTO processed_messages
             (message_id, expires_at)
           VALUES (
             ?,
             DATE_ADD(UTC_TIMESTAMP(3), INTERVAL 24 HOUR)
           )`,
          [messageId]
        );
      } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
          await conn.rollback();

          return res.json({
            ok: true,
            duplicate: true,
            message: 'Message was already processed'
          });
        }

        throw error;
      }

      const [insertResult] = await conn.execute(
        `INSERT INTO stocks
           (tier, egg_name, pet_name, location, spawned_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
          tier,
          eggName,
          petName,
          location,
          spawnedAt,
          expiresAt
        ]
      );

      stockId = insertResult.insertId;

      await conn.commit();
    } catch (error) {
      await conn.rollback().catch(() => {});
      throw error;
    } finally {
      conn.release();
    }

    lastIngestAt = new Date().toISOString();

    await broadcastStocks();

    return res.status(201).json({
      ok: true,
      duplicate: false,
      stockId,
      tier,
      eggName,
      petName,
      location,
      spawnedAt: spawnedAt.toISOString(),
      expiresAt: expiresAt.toISOString()
    });
  })
);

// ==========================================================
// 17. OBS OVERLAY APIs
// ==========================================================

app.get(
  '/api/overlay/stocks',
  requireOverlayToken,
  wrap(async (req, res) => {
    const stocks = await getActiveStocks(5);

    return sendOk(res, { stocks });
  })
);

app.get(
  '/api/overlay/stream',
  requireOverlayToken,
  wrap(async (req, res) => {
    const stocks = await getActiveStocks(5);

    registerSseClient(req, res, 'overlay', stocks);
  })
);

// ==========================================================
// 18. ADMIN OVERVIEW
// ==========================================================

app.get(
  '/api/admin/overview',
  requireAdmin,
  wrap(async (req, res) => {
    const [userRows] = await pool.query(
      `SELECT
         COUNT(*) AS total,
         SUM(status = 'active') AS active
       FROM users`
    );

    const [stockRows] = await pool.query(
      `SELECT COUNT(*) AS total
       FROM stocks
       WHERE expires_at > UTC_TIMESTAMP(3)`
    );

    const [keyRows] = await pool.query(
      `SELECT COUNT(*) AS total
       FROM api_keys
       WHERE revoked_at IS NULL
         AND expires_at > UTC_TIMESTAMP(3)`
    );

    return sendOk(res, {
      users: {
        total: Number(userRows[0].total || 0),
        active: Number(userRows[0].active || 0)
      },
      activeStocks: Number(stockRows[0].total || 0),
      activeApiKeys: Number(keyRows[0].total || 0),
      dashboardClients: [...sseClients]
        .filter(client => client.type === 'dashboard').length,
      overlayClients: [...sseClients]
        .filter(client => client.type === 'overlay').length,
      lastIngestAt
    });
  })
);

// ==========================================================
// 19. ADMIN USER MANAGEMENT
// ==========================================================

app.get(
  '/api/admin/users',
  requireAdmin,
  wrap(async (req, res) => {
    const [rows] = await pool.query(
      `SELECT
         u.id,
         u.email,
         u.status,
         u.last_login_at,
         u.created_at,
         (
           SELECT COUNT(*)
           FROM api_keys k
           WHERE k.user_id = u.id
             AND k.revoked_at IS NULL
             AND k.expires_at > UTC_TIMESTAMP(3)
         ) AS active_key_count
       FROM users u
       ORDER BY u.id DESC`
    );

    return sendOk(res, { users: rows });
  })
);

app.post(
  '/api/admin/users',
  requireAdmin,
  wrap(async (req, res) => {
    const email = normalizeEmail(req.body.email);
    const password = req.body.password;

    if (!validEmail(email)) {
      throw httpError(400, 'Enter a valid email address');
    }

    if (
      typeof password !== 'string' ||
      password.length < 8 ||
      password.length > 200 ||
      !/[A-Za-z]/.test(password) ||
      !/[0-9]/.test(password)
    ) {
      throw httpError(
        400,
        'Password must be 8+ characters and include a letter and a digit'
      );
    }

    const passwordHash = await bcrypt.hash(password, 12);

    try {
      const [result] = await pool.execute(
        `INSERT INTO users (email, password_hash)
         VALUES (?, ?)`,
        [email, passwordHash]
      );

      return res.status(201).json({
        ok: true,
        user: {
          id: result.insertId,
          email,
          status: 'active'
        }
      });
    } catch (error) {
      if (error.code === 'ER_DUP_ENTRY') {
        throw httpError(409, 'A user with this email already exists');
      }

      throw error;
    }
  })
);

app.patch(
  '/api/admin/users/:id',
  requireAdmin,
  wrap(async (req, res) => {
    if (!validId(req.params.id)) {
      throw httpError(400, 'Invalid user ID');
    }

    const status = normalizeText(req.body.status, 20);

    if (!['active', 'disabled'].includes(status)) {
      throw httpError(400, 'Status must be active or disabled');
    }

    const [result] = await pool.execute(
      'UPDATE users SET status = ? WHERE id = ?',
      [status, Number(req.params.id)]
    );

    if (!result.affectedRows) {
      const [check] = await pool.execute(
        'SELECT id FROM users WHERE id = ? LIMIT 1',
        [Number(req.params.id)]
      );

      if (!check.length) {
        throw httpError(404, 'User not found');
      }
    }

    if (status === 'disabled') {
      closeUserConnections(Number(req.params.id));
    }

    return sendOk(res, {
      message: `User ${status}`,
      status
    });
  })
);

app.post(
  '/api/admin/users/:id/reset-password',
  requireAdmin,
  wrap(async (req, res) => {
    if (!validId(req.params.id)) {
      throw httpError(400, 'Invalid user ID');
    }

    const password = req.body.password;

    if (
      typeof password !== 'string' ||
      password.length < 8 ||
      password.length > 200 ||
      !/[A-Za-z]/.test(password) ||
      !/[0-9]/.test(password)
    ) {
      throw httpError(
        400,
        'Password must be 8+ characters and include a letter and a digit'
      );
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const [result] = await pool.execute(
      'UPDATE users SET password_hash = ? WHERE id = ?',
      [passwordHash, Number(req.params.id)]
    );

    if (!result.affectedRows) {
      const [check] = await pool.execute(
        'SELECT id FROM users WHERE id = ? LIMIT 1',
        [Number(req.params.id)]
      );

      if (!check.length) {
        throw httpError(404, 'User not found');
      }
    }

    closeUserConnections(Number(req.params.id));

    return sendOk(res, {
      message: 'User password updated'
    });
  })
);

app.delete(
  '/api/admin/users/:id',
  requireAdmin,
  wrap(async (req, res) => {
    if (!validId(req.params.id)) {
      throw httpError(400, 'Invalid user ID');
    }

    const [result] = await pool.execute(
      'DELETE FROM users WHERE id = ?',
      [Number(req.params.id)]
    );

    if (!result.affectedRows) {
      throw httpError(404, 'User not found');
    }

    closeUserConnections(Number(req.params.id));

    return sendOk(res, { message: 'User deleted' });
  })
);

// ==========================================================
// 20. ADMIN EGG-PET MAPPING
// ==========================================================

app.get(
  '/api/admin/egg-pet',
  requireAdmin,
  wrap(async (req, res) => {
    const [mappings] = await pool.query(
      'SELECT id, egg_name, pet_name, updated_at FROM egg_pet_map ORDER BY egg_name'
    );

    return sendOk(res, { mappings });
  })
);

app.post(
  '/api/admin/egg-pet',
  requireAdmin,
  wrap(async (req, res) => {
    const eggName = normalizeText(
      req.body.eggName || req.body.egg_name,
      191
    );

    const petName = normalizeText(
      req.body.petName || req.body.pet_name,
      191
    );

    if (!eggName || !petName) {
      throw httpError(400, 'Both egg name and pet name are required');
    }

    await pool.execute(
      `INSERT INTO egg_pet_map (egg_name, pet_name)
       VALUES (?, ?)
       ON DUPLICATE KEY UPDATE pet_name = VALUES(pet_name)`,
      [eggName, petName]
    );

    return sendOk(res, {
      message: 'Egg-pet mapping saved',
      eggName,
      petName
    });
  })
);

app.post(
  '/api/admin/egg-pet/sync',
  requireAdmin,
  wrap(async (req, res) => {
    const mappings = req.body.mappings;

    if (!Array.isArray(mappings) || mappings.length > 500) {
      throw httpError(400, 'mappings must be an array of at most 500 rows');
    }

    const conn = await pool.getConnection();

    try {
      await conn.beginTransaction();

      for (const item of mappings) {
        const eggName = normalizeText(
          item.eggName || item.egg_name,
          191
        );

        const petName = normalizeText(
          item.petName || item.pet_name,
          191
        );

        if (!eggName || !petName) {
          throw httpError(400, 'Every mapping needs an egg and pet name');
        }

        await conn.execute(
          `INSERT INTO egg_pet_map (egg_name, pet_name)
           VALUES (?, ?)
           ON DUPLICATE KEY UPDATE pet_name = VALUES(pet_name)`,
          [eggName, petName]
        );
      }

      await conn.commit();
    } catch (error) {
      await conn.rollback().catch(() => {});
      throw error;
    } finally {
      conn.release();
    }

    return sendOk(res, {
      message: 'Egg-pet mappings synchronized',
      count: mappings.length
    });
  })
);

app.delete(
  '/api/admin/egg-pet/:id',
  requireAdmin,
  wrap(async (req, res) => {
    if (!validId(req.params.id)) {
      throw httpError(400, 'Invalid mapping ID');
    }

    const [result] = await pool.execute(
      'DELETE FROM egg_pet_map WHERE id = ?',
      [Number(req.params.id)]
    );

    if (!result.affectedRows) {
      throw httpError(404, 'Mapping not found');
    }

    return sendOk(res, { message: 'Mapping deleted' });
  })
);

// ==========================================================
// 21. ADMIN LOCATION ALIASES
// ==========================================================

app.get(
  '/api/admin/aliases',
  requireAdmin,
  wrap(async (req, res) => {
    const [aliases] = await pool.query(
      'SELECT id, from_name, to_name, updated_at FROM location_alias ORDER BY from_name'
    );

    return sendOk(res, { aliases });
  })
);

app.post(
  '/api/admin/aliases',
  requireAdmin,
  wrap(async (req, res) => {
    const fromName = normalizeText(
      req.body.fromName || req.body.from_name,
      191
    );

    const toName = normalizeText(
      req.body.toName || req.body.to_name,
      191
    );

    if (!fromName || !toName) {
      throw httpError(400, 'Both source and destination locations are required');
    }

    if (fromName.toLowerCase() === toName.toLowerCase()) {
      throw httpError(400, 'Source and destination cannot be identical');
    }

    await pool.execute(
      `INSERT INTO location_alias (from_name, to_name)
       VALUES (?, ?)
       ON DUPLICATE KEY UPDATE to_name = VALUES(to_name)`,
      [fromName, toName]
    );

    return sendOk(res, {
      message: 'Location alias saved',
      fromName,
      toName
    });
  })
);

app.post(
  '/api/admin/aliases/sync',
  requireAdmin,
  wrap(async (req, res) => {
    const aliases = req.body.aliases;

    if (!Array.isArray(aliases) || aliases.length > 500) {
      throw httpError(400, 'aliases must be an array of at most 500 rows');
    }

    const conn = await pool.getConnection();

    try {
      await conn.beginTransaction();

      for (const item of aliases) {
        const fromName = normalizeText(
          item.fromName || item.from_name,
          191
        );

        const toName = normalizeText(
          item.toName || item.to_name,
          191
        );

        if (
          !fromName ||
          !toName ||
          fromName.toLowerCase() === toName.toLowerCase()
        ) {
          throw httpError(400, 'Every alias must have different source and destination');
        }

        await conn.execute(
          `INSERT INTO location_alias (from_name, to_name)
           VALUES (?, ?)
           ON DUPLICATE KEY UPDATE to_name = VALUES(to_name)`,
          [fromName, toName]
        );
      }

      await conn.commit();
    } catch (error) {
      await conn.rollback().catch(() => {});
      throw error;
    } finally {
      conn.release();
    }

    return sendOk(res, {
      message: 'Location aliases synchronized',
      count: aliases.length
    });
  })
);

app.delete(
  '/api/admin/aliases/:id',
  requireAdmin,
  wrap(async (req, res) => {
    if (!validId(req.params.id)) {
      throw httpError(400, 'Invalid alias ID');
    }

    const [result] = await pool.execute(
      'DELETE FROM location_alias WHERE id = ?',
      [Number(req.params.id)]
    );

    if (!result.affectedRows) {
      throw httpError(404, 'Alias not found');
    }

    return sendOk(res, { message: 'Alias deleted' });
  })
);

// ==========================================================
// 22. ADMIN OBS OVERLAY CONFIGURATION
// ==========================================================

app.get(
  '/api/admin/overlay',
  requireAdmin,
  wrap(async (req, res) => {
    const token = requireSecret('OVERLAY_TOKEN');

    const baseUrl = (
      process.env.PUBLIC_BASE_URL ||
      `${req.protocol}://${req.get('host')}`
    ).replace(/\/+$/, '');

    const overlayUrl =
      `${baseUrl}/overlay?token=${encodeURIComponent(token)}`;

    return sendOk(res, {
      url: overlayUrl,
      token,
      dashboardClients: [...sseClients]
        .filter(client => client.type === 'dashboard').length,
      overlayClients: [...sseClients]
        .filter(client => client.type === 'overlay').length,
      lastIngestAt
    });
  })
);

// ==========================================================
// 23. HTML PAGES
// ==========================================================

app.use(express.static(PUBLIC_DIR, {
  index: false,
  dotfiles: 'deny',
  fallthrough: true,
  maxAge: process.env.NODE_ENV === 'production' ? '1h' : 0
}));

app.get('/', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'dashboard.html'));
});

app.get('/get-key', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'get-key.html'));
});

app.get('/x-admin-panel-7q2', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'admin.html'));
});

app.get('/overlay', (req, res) => {
  let expectedToken;

  try {
    expectedToken = requireSecret('OVERLAY_TOKEN');
  } catch (error) {
    return res.status(error.status).send('Overlay is not configured.');
  }

  if (!safeEqual(req.query.token, expectedToken)) {
    return res.status(401).send('Invalid or missing overlay token.');
  }

  return res.sendFile(path.join(PUBLIC_DIR, 'overlay.html'));
});

// ==========================================================
// 24. NOT FOUND AND ERROR HANDLERS
// ==========================================================

app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({
      ok: false,
      error: 'API endpoint not found'
    });
  }

  return res.status(404).send('Page not found');
});

app.use((error, req, res, next) => {
  if (res.headersSent) {
    return next(error);
  }

  const status = Number(error.status) || 500;

  if (status >= 500) {
    console.error('[server] Request failed:', error.message);
  }

  return res.status(status).json({
    ok: false,
    error: status >= 500 && status !== 503
      ? 'Internal server error'
      : error.message
  });
});

// ==========================================================
// 25. AUTOMATIC CLEANUP
// ==========================================================

async function cleanupExpiredRecords() {
  try {
    await pool.query(
      'DELETE FROM stocks WHERE expires_at <= UTC_TIMESTAMP(3)'
    );

    await pool.query(
      'DELETE FROM processed_messages WHERE expires_at <= UTC_TIMESTAMP(3)'
    );

    // Remove expired, revoked or otherwise inactive API keys.
    await pool.query(
      `DELETE FROM api_keys
       WHERE expires_at <= UTC_TIMESTAMP(3)
          OR revoked_at IS NOT NULL`
    );

    await broadcastStocks();
  } catch (error) {
    console.error('[cleanup] Failed:', error.message);
  }
}

// ==========================================================
// 26. START SERVER
// ==========================================================

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`[backend] Listening on port ${PORT}`);
  console.log(`[backend] Environment: ${process.env.NODE_ENV || 'development'}`);

  pool.query('SELECT 1')
    .then(() => {
      console.log('[database] Connection successful');
    })
    .catch(error => {
      console.error('[database] Initial connection failed:', error.message);
      console.error('[database] Check DATABASE_URL and database availability');
    });
});

const cleanupTimer = setInterval(cleanupExpiredRecords, 60 * 1000);

if (cleanupTimer.unref) {
  cleanupTimer.unref();
}

// ==========================================================
// 27. GRACEFUL SHUTDOWN
// ==========================================================

let shuttingDown = false;

async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;

  console.log(`[backend] Received ${signal}; shutting down`);

  clearInterval(cleanupTimer);

  for (const client of sseClients) {
    removeSseClient(client);
  }

  server.close(async () => {
    try {
      await pool.end();
      console.log('[backend] Shutdown complete');
      process.exit(0);
    } catch (error) {
      console.error('[backend] Shutdown error:', error.message);
      process.exit(1);
    }
  });

  setTimeout(() => {
    console.error('[backend] Forced shutdown after timeout');
    process.exit(1);
  }, 10000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
