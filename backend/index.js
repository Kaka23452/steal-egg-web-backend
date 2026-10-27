**File: `backend/index.js`**

```js
'use strict';

/*
 * Steal An Egg SaaS Backend
 * Node.js 20+
 *
 * Supports:
 * - TiDB / MySQL connection through DATABASE_URL or TIDB_DATABASE_URL
 * - Admin login and buyer management
 * - Buyer email/password login
 * - API key generation and rotation
 * - API-key protected schedule and stock endpoints
 * - Discord webhook spawn events
 * - Server-Sent Events (SSE) at /events
 * - Static pages in backend/public
 *
 * IMPORTANT:
 * Verify SQL column names against backend/schema.sql before deployment.
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();

const PORT = Number(process.env.PORT || 4000);
const JWT_SECRET = process.env.JWT_SECRET;
const MASTER_USERNAME = process.env.MASTER_USERNAME;
const MASTER_PASSWORD = process.env.MASTER_PASSWORD;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';
const DISCORD_CHANNEL_ID = process.env.DISCORD_CHANNEL_ID || '';

const PUBLIC_DIR = path.join(__dirname, 'public');
const SPAWN_STORE =
  process.env.SPAWN_STORE ||
  path.join(__dirname, 'spawn-events.json');

const MAX_EVENTS = 100;
const HEARTBEAT_MS = 25000;
const CLIENTS = new Set();
const recentEvents = [];
const seenMessageIds = new Set();

let pool = null;
let databaseConnected = false;
let lastWebhookAt = null;
let lastMessage = null;
let serverStartedAt = new Date().toISOString();

/* -------------------- BASIC CONFIGURATION -------------------- */

app.disable('x-powered-by');

app.use(cors({
  origin: process.env.CORS_ORIGIN
    ? process.env.CORS_ORIGIN.split(',').map(x => x.trim())
    : true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-API-Key',
    'X-Webhook-Secret'
  ]
}));

app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));

function str(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function sendError(res, status, message) {
  return res.status(status).json({
    success: false,
    error: message
  });
}

function needDb(res) {
  if (!pool || !databaseConnected) {
    sendError(res, 503, 'Database is not available');
    return false;
  }

  return true;
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));

  return left.length === right.length &&
    crypto.timingSafeEqual(left, right);
}

function hashApiKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

function createApiKey() {
  return 'sae_' + crypto.randomBytes(32).toString('hex');
}

function getBearerToken(req) {
  const header = str(req.headers.authorization);
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : '';
}

function signToken(payload) {
  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET must be configured with at least 32 characters');
  }

  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '12h',
    issuer: 'steal-egg-backend'
  });
}

function verifyToken(token) {
  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET is not configured securely');
  }

  return jwt.verify(token, JWT_SECRET, {
    issuer: 'steal-egg-backend'
  });
}

/* -------------------- DATABASE -------------------- */

function createDatabasePool() {
  const databaseUrl =
    process.env.DATABASE_URL ||
    process.env.TIDB_DATABASE_URL;

  if (databaseUrl) {
    const uri = new URL(databaseUrl);

    const sslEnabled =
      uri.searchParams.get('ssl') === 'true' ||
      uri.searchParams.get('ssl-mode') === 'REQUIRED' ||
      uri.searchParams.get('ssl-mode') === 'VERIFY_IDENTITY' ||
      process.env.DB_SSL === 'true';

    return mysql.createPool({
      host: uri.hostname,
      port: Number(uri.port || 4000),
      user: decodeURIComponent(uri.username),
      password: decodeURIComponent(uri.password),
      database: decodeURIComponent(uri.pathname.replace(/^\//, '')),
      waitForConnections: true,
      connectionLimit: Number(process.env.DB_CONNECTION_LIMIT || 10),
      queueLimit: 0,
      connectTimeout: 10000,
      enableKeepAlive: true,
      ssl: sslEnabled ? { rejectUnauthorized: true } : undefined,
      charset: 'utf8mb4'
    });
  }

  const host = process.env.DB_HOST;
  const user = process.env.DB_USER;
  const database = process.env.DB_NAME;

  if (!host || !user || !database) {
    console.warn(
      '[Database] Configure DATABASE_URL, TIDB_DATABASE_URL, ' +
      'or DB_HOST, DB_USER and DB_NAME.'
    );
    return null;
  }

  return mysql.createPool({
    host,
    port: Number(process.env.DB_PORT || 3306),
    user,
    password: process.env.DB_PASSWORD || '',
    database,
    waitForConnections: true,
    connectionLimit: Number(process.env.DB_CONNECTION_LIMIT || 10),
    queueLimit: 0,
    connectTimeout: 10000,
    enableKeepAlive: true,
    ssl: process.env.DB_SSL === 'true'
      ? { rejectUnauthorized: true }
      : undefined,
    charset: 'utf8mb4'
  });
}

async function checkDatabase() {
  if (!pool) {
    databaseConnected = false;
    return false;
  }

  try {
    await pool.query('SELECT 1');
    databaseConnected = true;
    return true;
  } catch (error) {
    databaseConnected = false;
    console.error('[Database health]', error.message);
    return false;
  }
}

/* -------------------- SPAWN EVENT STORAGE -------------------- */

function loadSpawnEvents() {
  try {
    if (!fs.existsSync(SPAWN_STORE)) return;

    const parsed = JSON.parse(fs.readFileSync(SPAWN_STORE, 'utf8'));

    if (Array.isArray(parsed)) {
      recentEvents.splice(
        0,
        recentEvents.length,
        ...parsed.slice(-MAX_EVENTS)
      );
    }
  } catch (error) {
    console.error('[Spawn store load]', error.message);
  }
}

function persistSpawnEvents() {
  try {
    const dir = path.dirname(SPAWN_STORE);
    fs.mkdirSync(dir, { recursive: true });

    const temp = SPAWN_STORE + '.tmp';
    fs.writeFileSync(temp, JSON.stringify(recentEvents, null, 2));
    fs.renameSync(temp, SPAWN_STORE);
  } catch (error) {
    console.error('[Spawn store save]', error.message);
  }
}

function normalizeTier(value) {
  const tier = str(value).toLowerCase();

  const allowed = {
    secret: 'Secret',
    divine: 'Divine',
    eternal: 'Eternal'
  };

  return allowed[tier] || '';
}

function broadcastEvent(event) {
  const packet = `data: ${JSON.stringify(event)}\n\n`;

  for (const client of CLIENTS) {
    try {
      client.write(packet);
    } catch {
      CLIENTS.delete(client);
    }
  }
}

function publishSpawn(input) {
  const tier = normalizeTier(input.tier);
  const eggName = str(input.eggName || input.egg_name);
  const petName = str(input.petName || input.pet_name);
  const timestamp = input.time || input.timestamp || new Date().toISOString();

  if (!tier || !eggName) {
    return {
      ok: false,
      error: 'A supported tier and eggName are required'
    };
  }

  const event = {
    type: 'SPAWN',
    tier,
    eggName,
    petName: petName || null,
    time: timestamp,
    receivedAt: new Date().toISOString()
  };

  recentEvents.push(event);

  while (recentEvents.length > MAX_EVENTS) {
    recentEvents.shift();
  }

  lastWebhookAt = new Date().toISOString();
  lastMessage = event;

  persistSpawnEvents();
  broadcastEvent(event);

  return { ok: true, event };
}

loadSpawnEvents();

/* -------------------- AUTHENTICATION -------------------- */

function requireAdmin(req, res, next) {
  const token = getBearerToken(req);

  if (!token) {
    return sendError(res, 401, 'Admin login required');
  }

  try {
    const payload = verifyToken(token);

    if (payload.role !== 'admin') {
      return sendError(res, 403, 'Admin access required');
    }

    req.admin = payload;
    next();
  } catch {
    return sendError(res, 401, 'Invalid or expired admin session');
  }
}

function requireBuyer(req, res, next) {
  const token = getBearerToken(req);

  if (!token) {
    return sendError(res, 401, 'Buyer login required');
  }

  try {
    const payload = verifyToken(token);

    if (payload.role !== 'buyer' || !payload.id) {
      return sendError(res, 403, 'Buyer access required');
    }

    req.buyer = payload;
    next();
  } catch {
    return sendError(res, 401, 'Invalid or expired buyer session');
  }
}

async function requireApiKey(req, res, next) {
  if (!needDb(res)) return;

  const apiKey =
    str(req.headers['x-api-key']) ||
    str(req.query.apiKey);

  if (!apiKey) {
    return sendError(res, 401, 'API key required');
  }

  try {
    const keyHash = hashApiKey(apiKey);

    const [rows] = await pool.execute(
      `SELECT id, user_id
       FROM api_keys
       WHERE key_hash = ?
         AND is_active = 1
       LIMIT 1`,
      [keyHash]
    );

    if (!rows.length) {
      return sendError(res, 401, 'Invalid or inactive API key');
    }

    req.apiKeyRecord = rows[0];

    next();
  } catch (error) {
    console.error('[API key auth]', error.message);
    return sendError(res, 500, 'Could not validate API key');
  }
}

/* -------------------- HEALTH -------------------- */

app.get('/health', async (req, res) => {
  const dbOk = await checkDatabase();

  res.status(dbOk ? 200 : 503).json({
    success: dbOk,
    status: dbOk ? 'ok' : 'degraded',
    service: 'steal-egg-saas-backend',
    databaseConnected: dbOk,
    webhookReceived: Boolean(lastWebhookAt),
    lastWebhookAt,
    activeSchedules: recentEvents.length,
    activeSseClients: CLIENTS.size,
    uptimeSeconds: Math.floor(process.uptime()),
    startedAt: serverStartedAt
  });
});

app.get('/health/database', async (req, res) => {
  const dbOk = await checkDatabase();

  res.status(dbOk ? 200 : 503).json({
    success: dbOk,
    databaseConnected: dbOk
  });
});

/* -------------------- ADMIN LOGIN -------------------- */

app.post('/api/admin/login', async (req, res) => {
  const username = str(req.body?.username);
  const password = str(req.body?.password);

  if (!MASTER_USERNAME || !MASTER_PASSWORD) {
    return sendError(res, 503, 'Admin credentials are not configured');
  }

  if (
    !safeEqual(username, MASTER_USERNAME) ||
    !safeEqual(password, MASTER_PASSWORD)
  ) {
    return sendError(res, 401, 'Invalid admin credentials');
  }

  try {
    const token = signToken({
      role: 'admin',
      username: MASTER_USERNAME
    });

    return res.json({
      success: true,
      token,
      accessToken: token
    });
  } catch (error) {
    console.error('[Admin login]', error.message);
    return sendError(res, 500, 'Could not create admin session');
  }
});

/* -------------------- BUYER LOGIN -------------------- */

app.post('/api/buyer/login', async (req, res) => {
  if (!needDb(res)) return;

  const email = str(req.body?.email).toLowerCase();
  const password = str(req.body?.password);

  if (!email || !password) {
    return sendError(res, 400, 'Email and password are required');
  }

  try {
    const [rows] = await pool.execute(
      `SELECT id, email, password_hash, is_active
       FROM users
       WHERE email = ?
       LIMIT 1`,
      [email]
    );

    if (!rows.length) {
      return sendError(res, 401, 'Invalid email or password');
    }

    const user = rows[0];

    if (
      user.is_active === 0 ||
      user.is_active === false ||
      String(user.is_active) === '0'
    ) {
      return sendError(res, 403, 'This buyer account is inactive');
    }

    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return sendError(res, 401, 'Invalid email or password');
    }

    const token = signToken({
      role: 'buyer',
      id: Number(user.id),
      email: user.email
    });

    return res.json({
      success: true,
      token,
      accessToken: token,
      user: {
        id: Number(user.id),
        email: user.email
      }
    });
  } catch (error) {
    console.error('[Buyer login]', error.message);
    return sendError(res, 500, 'Could not log in');
  }
});

/* -------------------- BUYER: GENERATE API KEY -------------------- */

app.post(
  '/api/buyer/generate-key',
  requireBuyer,
  async (req, res) => {
    if (!needDb(res)) return;

    const key = createApiKey();
    const keyHash = hashApiKey(key);
    const prefix = key.slice(0, 12);

    try {
      const [users] = await pool.execute(
        'SELECT id, is_active FROM users WHERE id = ? LIMIT 1',
        [Number(req.buyer.id)]
      );

      if (
        !users.length ||
        users[0].is_active === 0 ||
        String(users[0].is_active) === '0'
      ) {
        return sendError(res, 403, 'Buyer account is inactive');
      }

      const [existing] = await pool.execute(
        `SELECT id FROM api_keys
         WHERE user_id = ? AND is_active = 1
         LIMIT 1`,
        [Number(req.buyer.id)]
      );

      if (existing.length) {
        return sendError(
          res,
          409,
          'An active API key already exists. Use rotate-key instead.'
        );
      }

      await pool.execute(
        `INSERT INTO api_keys
          (user_id, key_hash, key_prefix, is_active, created_at)
         VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)`,
        [Number(req.buyer.id), keyHash, prefix]
      );

      return res.status(201).json({
        success: true,
        apiKey: key,
        api_key: key,
        key,
        message: 'Save this key securely. It will not be shown again.'
      });
    } catch (error) {
      console.error('[Generate API key]', error.message);
      return sendError(res, 500, 'Could not generate API key');
    }
  }
);

/* -------------------- BUYER: ROTATE API KEY -------------------- */

app.post(
  '/api/buyer/rotate-key',
  requireBuyer,
  async (req, res) => {
    if (!needDb(res)) return;

    const connection = await pool.getConnection();

    try {
      await connection.beginTransaction();

      await connection.execute(
        `UPDATE api_keys
         SET is_active = 0
         WHERE user_id = ? AND is_active = 1`,
        [Number(req.buyer.id)]
      );

      const key = createApiKey();
      const keyHash = hashApiKey(key);
      const prefix = key.slice(0, 12);

      await connection.execute(
        `INSERT INTO api_keys
          (user_id, key_hash, key_prefix, is_active, created_at)
         VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)`,
        [Number(req.buyer.id), keyHash, prefix]
      );

      await connection.commit();

      return res.json({
        success: true,
        apiKey: key,
        api_key: key,
        key,
        message: 'API key rotated. Save the new key securely.'
      });
    } catch (error) {
      await connection.rollback();
      console.error('[Rotate API key]', error.message);
      return sendError(res, 500, 'Could not rotate API key');
    } finally {
      connection.release();
    }
  }
);

/* -------------------- ADMIN: LIST BUYERS -------------------- */

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  if (!needDb(res)) return;

  try {
    const [rows] = await pool.execute(
      `SELECT
         u.id,
         u.email,
         u.is_active,
         u.created_at,
         u.updated_at,
         EXISTS (
           SELECT 1
           FROM api_keys k
           WHERE k.user_id = u.id AND k.is_active = 1
         ) AS has_active_key
       FROM users u
       ORDER BY u.id DESC
       LIMIT 500`
    );

    return res.json({
      success: true,
      users: rows.map(user => ({
        ...user,
        id: Number(user.id),
        is_active:
          user.is_active === 1 ||
          user.is_active === true ||
          String(user.is_active) === '1',
        has_active_key:
          user.has_active_key === 1 ||
          user.has_active_key === true ||
          String(user.has_active_key) === '1'
      }))
    });
  } catch (error) {
    console.error('[List buyers]', error.message);
    return sendError(res, 500, 'Could not load buyers');
  }
});

/* -------------------- ADMIN: CREATE BUYER -------------------- */

app.post('/api/admin/users', requireAdmin, async (req, res) => {
  if (!needDb(res)) return;

  const email = str(req.body?.email).toLowerCase();
  const password = str(req.body?.password);

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return sendError(res, 400, 'A valid email address is required');
  }

  if (password.length < 8 || password.length > 128) {
    return sendError(
      res,
      400,
      'Password must be between 8 and 128 characters'
    );
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);

    const [result] = await pool.execute(
      `INSERT INTO users
        (email, password_hash, is_active, created_at, updated_at)
       VALUES (?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
      [email, passwordHash]
    );

    return res.status(201).json({
      success: true,
      user: {
        id: Number(result.insertId),
        email,
        is_active: true
      }
    });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return sendError(res, 409, 'A buyer with this email already exists');
    }

    console.error('[Create buyer]', error.message);
    return sendError(res, 500, 'Could not create buyer');
  }
});

/* -------------------- ADMIN: ACTIVATE / DEACTIVATE BUYER -------------------- */

app.patch(
  '/api/admin/users/:id/status',
  requireAdmin,
  async (req, res) => {
    if (!needDb(res)) return;

    const userId = Number(req.params.id);
    const active = req.body?.is_active;

    if (!Number.isSafeInteger(userId) || userId < 1) {
      return sendError(res, 400, 'Invalid buyer ID');
    }

    if (typeof active !== 'boolean') {
      return sendError(res, 400, 'is_active must be true or false');
    }

    try {
      const [result] = await pool.execute(
        `UPDATE users
         SET is_active = ?, updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`,
        [active ? 1 : 0, userId]
      );

      if (!result.affectedRows) {
        return sendError(res, 404, 'Buyer not found');
      }

      if (!active) {
        await pool.execute(
          `UPDATE api_keys
           SET is_active = 0
           WHERE user_id = ?`,
          [userId]
        );
      }

      return res.json({
        success: true,
        message: active ? 'Buyer activated' : 'Buyer deactivated'
      });
    } catch (error) {
      console.error('[Buyer status]', error.message);
      return sendError(res, 500, 'Could not update buyer status');
    }
  }
);

/* -------------------- ADMIN: RESET BUYER PASSWORD -------------------- */

app.post(
  '/api/admin/users/:id/reset-password',
  requireAdmin,
  async (req, res) => {
    if (!needDb(res)) return;

    const userId = Number(req.params.id);
    const newPassword = str(req.body?.password);

    if (!Number.isSafeInteger(userId) || userId < 1) {
      return sendError(res, 400, 'Invalid buyer ID');
    }

    if (newPassword.length < 8 || newPassword.length > 128) {
      return sendError(
        res,
        400,
        'Password must be between 8 and 128 characters'
      );
    }

    try {
      const [users] = await pool.execute(
        'SELECT id FROM users WHERE id = ? LIMIT 1',
        [userId]
      );

      if (!users.length) {
        return sendError(res, 404, 'Buyer not found');
      }

      const passwordHash = await bcrypt.hash(newPassword, 12);

      await pool.execute(
        `UPDATE users
         SET password_hash = ?,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`,
        [passwordHash, userId]
      );

      return res.json({
        success: true,
        message: 'Buyer password reset successfully'
      });
    } catch (error) {
      console.error('[Reset buyer password]', error.message);
      return sendError(res, 500, 'Could not reset buyer password');
    }
  }
);

/* -------------------- ADMIN: DELETE / DISABLE BUYER -------------------- */

app.delete(
  '/api/admin/users/:id',
  requireAdmin,
  async (req, res) => {
    if (!needDb(res)) return;

    const userId = Number(req.params.id);

    if (!Number.isSafeInteger(userId) || userId < 1) {
      return sendError(res, 400, 'Invalid buyer ID');
    }

    try {
      const [result] = await pool.execute(
        `UPDATE users
         SET is_active = 0, updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`,
        [userId]
      );

      if (!result.affectedRows) {
        return sendError(res, 404, 'Buyer not found');
      }

      await pool.execute(
        'UPDATE api_keys SET is_active = 0 WHERE user_id = ?',
        [userId]
      );

      return res.json({
        success: true,
        message: 'Buyer deactivated and API keys disabled'
      });
    } catch (error) {
      console.error('[Deactivate buyer]', error.message);
      return sendError(res, 500, 'Could not deactivate buyer');
    }
  }
);

/* -------------------- API KEY: CURRENT BUYER -------------------- */

app.get(
  '/api/buyer/me',
  requireBuyer,
  async (req, res) => {
    if (!needDb(res)) return;

    try {
      const [rows] = await pool.execute(
        `SELECT id, email, is_active, created_at
         FROM users WHERE id = ? LIMIT 1`,
        [Number(req.buyer.id)]
      );

      if (!rows.length) {
        return sendError(res, 404, 'Buyer not found');
      }

      return res.json({ success: true, user: rows[0] });
    } catch (error) {
      console.error('[Buyer profile]', error.message);
      return sendError(res, 500, 'Could not load buyer profile');
    }
  }
);

/* -------------------- STOCK / SCHEDULE API -------------------- */

app.get('/api/schedule', requireApiKey, async (req, res) => {
  if (!needDb(res)) return;

  try {
    const [rows] = await pool.execute(
      'SELECT * FROM stocks ORDER BY id ASC LIMIT 500'
    );

    return res.json({
      success: true,
      schedule: rows,
      stocks: rows,
      recentSpawns: recentEvents
    });
  } catch (error) {
    console.error('[Schedule]', error.message);
    return sendError(res, 500, 'Could not load schedule');
  }
});

app.get('/api/stocks', requireApiKey, async (req, res) => {
  if (!needDb(res)) return;

  try {
    const [rows] = await pool.execute(
      'SELECT * FROM stocks ORDER BY id ASC LIMIT 500'
    );

    return res.json({
      success: true,
      stocks: rows
    });
  } catch (error) {
    console.error('[Stocks]', error.message);
    return sendError(res, 500, 'Could not load stocks');
  }
});

/* -------------------- EGG / PET MAP -------------------- */

app.get('/api/admin/egg-map', requireAdmin, async (req, res) => {
  if (!needDb(res)) return;

  try {
    const [rows] = await pool.execute(
      'SELECT * FROM egg_pet_map ORDER BY id ASC LIMIT 1000'
    );

    return res.json({
      success: true,
      eggMap: rows,
      items: rows
    });
  } catch (error) {
    console.error('[Egg map read]', error.message);
    return sendError(res, 500, 'Could not load egg map');
  }
});

app.post('/api/admin/egg-map', requireAdmin, async (req, res) => {
  if (!needDb(res)) return;

  const items = req.body?.items || req.body?.eggMap;

  if (!Array.isArray(items) || items.length > 500) {
    return sendError(res, 400, 'items must be an array of up to 500 entries');
  }

  /*
   * The schema shared earlier did not establish the exact egg_pet_map
   * columns or its unique key. Do not silently delete/rebuild the table.
   * Configure the column mapping here after checking schema.sql.
   */
  return sendError(
    res,
    501,
    'Egg map saving needs the exact egg_pet_map schema and column mapping'
  );
});

/* -------------------- DISCORD WEBHOOK -------------------- */

app.post('/api/bot-webhook', async (req, res) => {
  if (!WEBHOOK_SECRET) {
    return sendError(res, 503, 'Webhook secret is not configured');
  }

  const suppliedSecret =
    str(req.headers['x-webhook-secret']) ||
    str(req.headers['x-api-key']) ||
    str(req.query.secret);

  if (!safeEqual(suppliedSecret, WEBHOOK_SECRET)) {
    return sendError(res, 401, 'Invalid webhook secret');
  }

  const body = req.body || {};
  const messageId = str(body.messageId || body.message_id || body.id);

  if (messageId && seenMessageIds.has(messageId)) {
    return res.json({
      success: true,
      duplicate: true
    });
  }

  const payload = body.data && typeof body.data === 'object'
    ? body.data
    : body;

  const result = publishSpawn({
    tier: payload.tier || payload.rarity,
    eggName: payload.eggName || payload.egg_name || payload.egg,
    petName: payload.petName || payload.pet_name || payload.pet,
    time: payload.time || payload.timestamp
  });

  if (!result.ok) {
    return sendError(res, 400, result.error);
  }

  if (messageId) {
    seenMessageIds.add(messageId);

    if (seenMessageIds.size > 5000) {
      const first = seenMessageIds.values().next().value;
      seenMessageIds.delete(first);
    }
  }

  return res.json({
    success: true,
    event: result.event
  });
});

/* -------------------- DISCORD CHANNEL CHECK -------------------- */

app.get('/api/config', (req, res) => {
  res.json({
    success: true,
    service: 'steal-egg-saas-backend',
    discordChannelConfigured: Boolean(DISCORD_CHANNEL_ID),
    supportedTiers: ['Secret', 'Divine', 'Eternal']
  });
});

/* -------------------- SERVER-SENT EVENTS -------------------- */

app.get('/events', async (req, res) => {
  if (!needDb(res)) return;

  /*
   * EventSource cannot set arbitrary headers in browsers.
   * This endpoint accepts apiKey in the query string for OBS/browser use.
   * Query parameters can appear in logs, so use HTTPS and avoid logging
   * full request URLs. Header-based auth is preferable where supported.
   */
  const apiKey = str(req.query.apiKey);

  if (!apiKey) {
    return sendError(res, 401, 'API key required');
  }

  try {
    const keyHash = hashApiKey(apiKey);

    const [rows] = await pool.execute(
      `SELECT k.id, k.user_id
       FROM api_keys k
       INNER JOIN users u ON u.id = k.user_id
       WHERE k.key_hash = ?
         AND k.is_active = 1
         AND u.is_active = 1
       LIMIT 1`,
      [keyHash]
    );

    if (!rows.length) {
      return sendError(res, 401, 'Invalid API key or inactive buyer');
    }
  } catch (error) {
    console.error('[SSE auth]', error.message);
    return sendError(res, 500, 'Could not authenticate event stream');
  }

  res.status(200);
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();

  res.write('retry: 3000\n\n');

  // Send recent events to a newly connected client.
  for (const event of recentEvents) {
    res.write(`data: ${JSON.stringify(event)}\n\n`);
  }

  CLIENTS.add(res);

  const heartbeat = setInterval(() => {
    try {
      res.write(`: heartbeat ${Date.now()}\n\n`);
    } catch {
      clearInterval(heartbeat);
      CLIENTS.delete(res);
    }
  }, HEARTBEAT_MS);

  req.on('close', () => {
    clearInterval(heartbeat);
    CLIENTS.delete(res);
  });
});

/* -------------------- RECENT SPAWN EVENTS -------------------- */

app.get('/api/spawn-events', requireApiKey, (req, res) => {
  res.json({
    success: true,
    events: recentEvents,
    lastWebhookAt,
    lastMessage
  });
});

/* -------------------- STATIC PAGES -------------------- */

app.use(express.static(PUBLIC_DIR, {
  extensions: ['html'],
  index: 'index.html',
  fallthrough: true,
  maxAge: process.env.NODE_ENV === 'production' ? '1h' : 0
}));

app.get('/', (req, res, next) => {
  const file = path.join(PUBLIC_DIR, 'index.html');

  if (fs.existsSync(file)) {
    return res.sendFile(file);
  }

  next();
});

app.get('/login', (req, res, next) => {
  const file = path.join(PUBLIC_DIR, 'login.html');
  if (fs.existsSync(file)) return res.sendFile(file);
  next();
});

app.get('/get-key', (req, res, next) => {
  const file = path.join(PUBLIC_DIR, 'get-key.html');
  if (fs.existsSync(file)) return res.sendFile(file);
  next();
});

app.get('/generator', (req, res, next) => {
  const file = path.join(PUBLIC_DIR, 'generator.html');
  if (fs.existsSync(file)) return res.sendFile(file);
  next();
});

app.get('/master', (req, res, next) => {
  const file = path.join(PUBLIC_DIR, 'master.html');
  if (fs.existsSync(file)) return res.sendFile(file);
  next();
});

app.get('/admin', (req, res, next) => {
  const file = path.join(PUBLIC_DIR, 'admin.html');
  if (fs.existsSync(file)) return res.sendFile(file);
  next();
});

/* -------------------- 404 AND ERROR HANDLING -------------------- */

app.use((req, res) => {
  if (req.path.startsWith('/api/') || req.path === '/events') {
    return sendError(res, 404, 'Endpoint not found');
  }

  const errorPage = path.join(PUBLIC_DIR, '404.html');

  if (fs.existsSync(errorPage)) {
    return res.status(404).sendFile(errorPage);
  }

  return res.status(404).send('404 - Not Found');
});

app.use((error, req, res, next) => {
  console.error('[Unhandled request error]', error.message || error);

  if (res.headersSent) {
    return next(error);
  }

  if (req.path.startsWith('/api/') || req.path === '/events') {
    return sendError(res, 500, 'Internal server error');
  }

  const errorPage = path.join(PUBLIC_DIR, '500.html');

  if (fs.existsSync(errorPage)) {
    return res.status(500).sendFile(errorPage);
  }

  return res.status(500).send('500 - Internal Server Error');
});

/* -------------------- STARTUP / SHUTDOWN -------------------- */

async function start() {
  try {
    pool = createDatabasePool();

    if (pool) {
      await checkDatabase();

      if (databaseConnected) {
        console.log('[Database] Connection successful');
      } else {
        console.error('[Database] Connection failed; check DB settings');
      }
    }

    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`[Backend] Listening on port ${PORT}`);
      console.log(`[Backend] Node ${process.version}`);
      console.log(`[Backend] Public directory: ${PUBLIC_DIR}`);
      console.log(`[Backend] Database connected: ${databaseConnected}`);
      console.log(`[Backend] Discord channel configured: ${Boolean(DISCORD_CHANNEL_ID)}`);

      if (!JWT_SECRET || JWT_SECRET.length < 32) {
        console.warn('[Security] Set a strong JWT_SECRET (32+ characters)');
      }

      if (!MASTER_USERNAME || !MASTER_PASSWORD) {
        console.warn('[Security] MASTER_USERNAME / MASTER_PASSWORD not configured');
      }

      if (!WEBHOOK_SECRET) {
        console.warn('[Security] WEBHOOK_SECRET not configured');
      }
    });

    const shutdown = signal => {
      console.log(`[Backend] ${signal} received; shutting down`);

      for (const client of CLIENTS) {
        try {
          client.end();
        } catch {}
      }

      CLIENTS.clear();

      server.close(async () => {
        try {
          if (pool) await pool.end();
        } catch (error) {
          console.error('[Database shutdown]', error.message);
        }

        process.exit(0);
      });

      setTimeout(() => process.exit(1), 10000).unref();
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  } catch (error) {
    console.error('[Startup error]', error.message || error);
    process.exitCode = 1;
  }
}

start();

module.exports = {
  app,
  publishSpawn
};
```

