
'use strict';

/*
 * Steal An Egg SaaS Backend
 * Node.js 20+
 *
 * Uses the existing schema:
 * users, api_keys, egg_pet_map, location_alias,
 * stocks, processed_messages
 *
 * Do not put Discord bot tokens or database credentials in frontend HTML.
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
const JWT_SECRET = process.env.JWT_SECRET || '';
const MASTER_USERNAME = process.env.MASTER_USERNAME || '';
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || '';
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';
const DISCORD_CHANNEL_ID = process.env.DISCORD_CHANNEL_ID || '';

const PUBLIC_DIR = path.join(__dirname, 'public');
const SPAWN_STORE =
  process.env.SPAWN_STORE || path.join(__dirname, 'spawn-events.json');

const MAX_EVENTS = 100;
const HEARTBEAT_MS = 25000;
const CLIENTS = new Set();
const recentEvents = [];
const seenMessageIds = new Set();

let pool = null;
let databaseConnected = false;
let lastWebhookAt = null;
let lastMessage = null;
const serverStartedAt = new Date().toISOString();

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
  return res.status(status).json({ success: false, error: message });
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
  const match = str(req.headers.authorization)
    .match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : '';
}

function signToken(payload) {
  if (JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters');
  }
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '12h',
    issuer: 'steal-egg-backend'
  });
}

function verifyToken(token) {
  if (JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET is not configured securely');
  }
  return jwt.verify(token, JWT_SECRET, {
    issuer: 'steal-egg-backend'
  });
}

/* -------------------- DATABASE -------------------- */

function createDatabasePool() {
  const connectionString =
    process.env.TIDB_DATABASE_URL ||
    process.env.DATABASE_URL;

  const commonOptions = {
    waitForConnections: true,
    connectionLimit: Number(process.env.DB_CONNECTION_LIMIT || 5),
    queueLimit: 0,
    enableKeepAlive: true,
    connectTimeout: 15000,
    decimalNumbers: true
  };

  if (connectionString) {
    const url = new URL(connectionString);
    if (!['mysql:', 'mysql2:'].includes(url.protocol)) {
      throw new Error('Database URL must use mysql://');
    }

    const options = {
      ...commonOptions,
      host: url.hostname,
      port: Number(url.port || 3306),
      user: decodeURIComponent(url.username),
      password: decodeURIComponent(url.password),
      database: decodeURIComponent(url.pathname.replace(/^\//, '')),
      charset: 'utf8mb4'
    };

    if (url.searchParams.get('ssl') ||
        url.searchParams.get('sslaccept')) {
      options.ssl = { minVersion: 'TLSv1.2' };
    }

    return mysql.createPool(options);
  }

  const host = process.env.DB_HOST;
  const user = process.env.DB_USER;
  const database = process.env.DB_NAME;

  if (!host || !user || !database) {
    console.error(
      '[Database] Set TIDB_DATABASE_URL / DATABASE_URL ' +
      'or DB_HOST, DB_USER, DB_NAME'
    );
    return null;
  }

  return mysql.createPool({
    ...commonOptions,
    host,
    port: Number(process.env.DB_PORT || 4000),
    user,
    password: process.env.DB_PASSWORD || '',
    database,
    charset: 'utf8mb4',
    ssl: process.env.DB_SSL === 'false'
      ? undefined
      : { minVersion: 'TLSv1.2' }
  });
}

async function checkDatabase() {
  if (!pool) {
    databaseConnected = false;
    return false;
  }

  try {
    const connection = await pool.getConnection();
    await connection.query('SELECT 1');
    connection.release();
    databaseConnected = true;
  } catch (error) {
    databaseConnected = false;
    console.error('[Database check]', error.message);
  }

  return databaseConnected;
}

/* -------------------- SESSION AUTH -------------------- */

function verifySession(req, expectedRole) {
  try {
    const token = getBearerToken(req);
    if (!token) return null;

    const payload = verifyToken(token);
    if (!payload || payload.role !== expectedRole) return null;

    if (expectedRole === 'buyer') {
      const userId = Number(payload.userId ?? payload.id ?? payload.sub);
      if (!Number.isSafeInteger(userId) || userId < 1) return null;
      return { ...payload, userId, id: userId };
    }

    return payload;
  } catch {
    return null;
  }
}

function requireBuyer(req, res, next) {
  const session = verifySession(req, 'buyer');
  if (!session || !session.userId) {
    return sendError(res, 401, 'Buyer login required');
  }

  req.buyer = { id: session.userId, email: str(session.email) };
  req.auth = session;
  next();
}

function requireAdmin(req, res, next) {
  const session = verifySession(req, 'admin');
  if (!session) return sendError(res, 401, 'Admin login required');
  req.admin = session;
  req.auth = session;
  next();
}

async function findValidApiKey(apiKey) {
  if (!pool || !apiKey) return null;

  const [rows] = await pool.execute(
    `SELECT k.id, k.user_id
       FROM api_keys k
       INNER JOIN users u ON u.id = k.user_id
      WHERE k.key_hash = ?
        AND k.is_active = 1
        AND (k.expires_at IS NULL OR k.expires_at > UTC_TIMESTAMP())
        AND u.is_active = 1
      LIMIT 1`,
    [hashApiKey(apiKey)]
  );

  if (!rows.length) return null;

  await pool.execute(
    'UPDATE api_keys SET last_used_at = UTC_TIMESTAMP() WHERE id = ?',
    [rows[0].id]
  );

  return rows[0];
}

async function requireApiKey(req, res, next) {
  if (!needDb(res)) return;

  const key = str(req.headers['x-api-key']) || str(req.query.apiKey);
  if (!key) return sendError(res, 401, 'API key required');

  try {
    const record = await findValidApiKey(key);
    if (!record) {
      return sendError(res, 401, 'Invalid, expired, or inactive API key');
    }

    req.apiKeyRecord = record;
    next();
  } catch (error) {
    console.error('[API key auth]', error.message);
    return sendError(res, 500, 'Could not validate API key');
  }
}

/* -------------------- SPAWN EVENT STORAGE -------------------- */

function loadSpawnEvents() {
  try {
    if (!fs.existsSync(SPAWN_STORE)) return;
    const parsed = JSON.parse(fs.readFileSync(SPAWN_STORE, 'utf8'));
    if (Array.isArray(parsed)) {
      recentEvents.push(...parsed.slice(-MAX_EVENTS));
    }
  } catch (error) {
    console.error('[Spawn store load]', error.message);
  }
}

function persistSpawnEvents() {
  try {
    fs.mkdirSync(path.dirname(SPAWN_STORE), { recursive: true });
    const temp = SPAWN_STORE + '.tmp';
    fs.writeFileSync(temp, JSON.stringify(recentEvents, null, 2));
    fs.renameSync(temp, SPAWN_STORE);
  } catch (error) {
    console.error('[Spawn store save]', error.message);
  }
}

function normalizeTier(value) {
  const tiers = {
    secret: 'Secret',
    divine: 'Divine',
    eternal: 'Eternal'
  };
  return tiers[str(value).toLowerCase()] || '';
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
  const tier = normalizeTier(input.tier || input.rarity);
  const eggName = str(input.eggName || input.egg_name || input.egg);
  const petName = str(input.petName || input.pet_name || input.pet);
  const location = str(
    input.location || input.spawnLocation || input.spawn_location
  );
  const time = input.time || input.timestamp || input.spawnedAt ||
    new Date().toISOString();

  let spawned = str(
    input.spawned || input.spawnedLabel || input.spawned_label
  );

  // If no human-readable label was supplied, derive it from the spawn time.
  if (!spawned) {
    const parsedTime = new Date(time);
    if (!Number.isNaN(parsedTime.getTime())) {
      const elapsedSeconds = Math.max(
        0, Math.floor((Date.now() - parsedTime.getTime()) / 1000)
      );

      if (elapsedSeconds < 60) {
        spawned = elapsedSeconds <= 5
          ? 'Just now'
          : `${elapsedSeconds} seconds ago`;
      } else if (elapsedSeconds < 3600) {
        const minutes = Math.floor(elapsedSeconds / 60);
        spawned = `${minutes} minute${minutes === 1 ? '' : 's'} ago`;
      } else if (elapsedSeconds < 86400) {
        const hours = Math.floor(elapsedSeconds / 3600);
        spawned = `${hours} hour${hours === 1 ? '' : 's'} ago`;
      } else {
        const days = Math.floor(elapsedSeconds / 86400);
        spawned = `${days} day${days === 1 ? '' : 's'} ago`;
      }
    }
  }

  if (!tier || !eggName) {
    return {
      ok: false,
      error: 'Supported tier and eggName are required'
    };
  }

  const event = {
    type: 'SPAWN',
    tier,
    eggName,
    petName: petName || null,
    location: location || null,
    spawned: spawned || null,
    time,
    receivedAt: new Date().toISOString()
  };

  recentEvents.push(event);
  while (recentEvents.length > MAX_EVENTS) recentEvents.shift();

  lastWebhookAt = new Date().toISOString();
  lastMessage = event;
  persistSpawnEvents();
  broadcastEvent(event);

  return { ok: true, event };
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
  const ok = await checkDatabase();
  res.status(ok ? 200 : 503).json({
    success: ok,
    databaseConnected: ok
  });
});

/* -------------------- ADMIN LOGIN -------------------- */

app.post('/api/admin/login', (req, res) => {
  const username = str(req.body?.username);
  const password = str(req.body?.password);

  if (!MASTER_USERNAME || !MASTER_PASSWORD) {
    return sendError(res, 503, 'Admin credentials are not configured');
  }

  if (!safeEqual(username, MASTER_USERNAME) ||
      !safeEqual(password, MASTER_PASSWORD)) {
    return sendError(res, 401, 'Invalid admin credentials');
  }

  try {
    const token = signToken({ role: 'admin', username: MASTER_USERNAME });
    return res.json({ success: true, token, accessToken: token });
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
      'SELECT id, email, password_hash, is_active FROM users WHERE email = ? LIMIT 1',
      [email]
    );

    if (!rows.length) return sendError(res, 401, 'Invalid email or password');
    const user = rows[0];

    if (Number(user.is_active) !== 1) {
      return sendError(res, 403, 'This buyer account is inactive');
    }

    if (!await bcrypt.compare(password, user.password_hash)) {
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
      user: { id: Number(user.id), email: user.email }
    });
  } catch (error) {
    console.error('[Buyer login]', error.message);
    return sendError(res, 500, 'Could not log in');
  }
});

/* -------------------- BUYER API KEYS -------------------- */

app.post('/api/buyer/generate-key', requireBuyer, async (req, res) => {
  if (!needDb(res)) return;

  const key = createApiKey();
  const hash = hashApiKey(key);
  const prefix = key.slice(0, 12);

  try {
    const [users] = await pool.execute(
      'SELECT id, is_active FROM users WHERE id = ? LIMIT 1',
      [req.buyer.id]
    );

    if (!users.length || Number(users[0].is_active) !== 1) {
      return sendError(res, 403, 'Buyer account is inactive');
    }

    const [existing] = await pool.execute(
      'SELECT id FROM api_keys WHERE user_id = ? AND is_active = 1 LIMIT 1',
      [req.buyer.id]
    );

    if (existing.length) {
      return sendError(res, 409, 'An active key exists. Use rotate-key.');
    }

    await pool.execute(
      `INSERT INTO api_keys
       (user_id, key_hash, key_prefix, is_active, expires_at, created_at)
       VALUES (?, ?, ?, 1, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 365 DAY), UTC_TIMESTAMP())`,
      [req.buyer.id, hash, prefix]
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
});

app.post('/api/buyer/rotate-key', requireBuyer, async (req, res) => {
  if (!needDb(res)) return;

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();

    const key = createApiKey();
    const hash = hashApiKey(key);
    const prefix = key.slice(0, 12);
    const parsedDays = Number(process.env.API_KEY_TTL_DAYS || 365);
    const days = Number.isFinite(parsedDays)
      ? Math.min(3650, Math.max(1, Math.floor(parsedDays)))
      : 365;

    const [users] = await connection.execute(
      'SELECT id, is_active FROM users WHERE id = ? LIMIT 1 FOR UPDATE',
      [req.buyer.id]
    );

    if (!users.length || Number(users[0].is_active) !== 1) {
      await connection.rollback();
      return sendError(res, 403, 'Buyer account is inactive');
    }

    await connection.execute(
      'UPDATE api_keys SET is_active = 0 WHERE user_id = ? AND is_active = 1',
      [req.buyer.id]
    );

    await connection.execute(
      `INSERT INTO api_keys
       (user_id, key_hash, key_prefix, is_active, expires_at, created_at)
       VALUES (?, ?, ?, 1, DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? DAY), UTC_TIMESTAMP())`,
      [req.buyer.id, hash, prefix, days]
    );

    await connection.commit();
    return res.json({
      success: true,
      apiKey: key,
      api_key: key,
      key,
      rotated: true,
      expiresInDays: days
    });
  } catch (error) {
    if (connection) {
      try { await connection.rollback(); } catch {}
    }
    console.error('[Rotate API key]', error.message);
    return sendError(res, 500, 'Could not rotate API key');
  } finally {
    if (connection) connection.release();
  }
});

/* -------------------- ADMIN: BUYER MANAGEMENT -------------------- */

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  if (!needDb(res)) return;

  try {
    const [rows] = await pool.execute(
      `SELECT u.id, u.email, u.is_active, u.created_at, u.updated_at,
       EXISTS (
         SELECT 1 FROM api_keys k
         WHERE k.user_id = u.id AND k.is_active = 1
       ) AS has_active_key
       FROM users u ORDER BY u.id DESC LIMIT 500`
    );

    return res.json({
      success: true,
      users: rows.map(u => ({
        ...u,
        id: Number(u.id),
        is_active: Number(u.is_active) === 1,
        has_active_key: Number(u.has_active_key) === 1
      }))
    });
  } catch (error) {
    console.error('[List buyers]', error.message);
    return sendError(res, 500, 'Could not load buyers');
  }
});

app.post('/api/admin/users', requireAdmin, async (req, res) => {
  if (!needDb(res)) return;

  const email = str(req.body?.email).toLowerCase();
  const password = str(req.body?.password);

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return sendError(res, 400, 'A valid email is required');
  }
  if (password.length < 8 || password.length > 128) {
    return sendError(res, 400, 'Password must be 8–128 characters');
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const [result] = await pool.execute(
      `INSERT INTO users
       (email, password_hash, is_active, created_at, updated_at)
       VALUES (?, ?, 1, UTC_TIMESTAMP(), UTC_TIMESTAMP())`,
      [email, passwordHash]
    );

    return res.status(201).json({
      success: true,
      user: { id: Number(result.insertId), email, is_active: true }
    });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return sendError(res, 409, 'Buyer email already exists');
    }
    console.error('[Create buyer]', error.message);
    return sendError(res, 500, 'Could not create buyer');
  }
});

app.patch('/api/admin/users/:id/status', requireAdmin, async (req, res) => {
  if (!needDb(res)) return;

  const id = Number(req.params.id);
  const active = req.body?.is_active;

  if (!Number.isSafeInteger(id) || id < 1) {
    return sendError(res, 400, 'Invalid buyer ID');
  }
  if (typeof active !== 'boolean') {
    return sendError(res, 400, 'is_active must be true or false');
  }

  try {
    const [result] = await pool.execute(
      'UPDATE users SET is_active = ?, updated_at = UTC_TIMESTAMP() WHERE id = ?',
      [active ? 1 : 0, id]
    );
    if (!result.affectedRows) return sendError(res, 404, 'Buyer not found');

    if (!active) {
      await pool.execute(
        'UPDATE api_keys SET is_active = 0 WHERE user_id = ?',
        [id]
      );
    }
    return res.json({ success: true, message: active ? 'Buyer activated' : 'Buyer deactivated' });
  } catch (error) {
    console.error('[Buyer status]', error.message);
    return sendError(res, 500, 'Could not update buyer status');
  }
});

app.post('/api/admin/users/:id/reset-password', requireAdmin, async (req, res) => {
  if (!needDb(res)) return;

  const id = Number(req.params.id);
  const password = str(req.body?.password);
  if (!Number.isSafeInteger(id) || id < 1) return sendError(res, 400, 'Invalid buyer ID');
  if (password.length < 8 || password.length > 128) {
    return sendError(res, 400, 'Password must be 8–128 characters');
  }

  try {
    const hash = await bcrypt.hash(password, 12);
    const [result] = await pool.execute(
      'UPDATE users SET password_hash = ?, updated_at = UTC_TIMESTAMP() WHERE id = ?',
      [hash, id]
    );
    if (!result.affectedRows) return sendError(res, 404, 'Buyer not found');
    return res.json({ success: true, message: 'Buyer password reset successfully' });
  } catch (error) {
    console.error('[Reset password]', error.message);
    return sendError(res, 500, 'Could not reset buyer password');
  }
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  if (!needDb(res)) return;

  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return sendError(res, 400, 'Invalid buyer ID');

  try {
    const [result] = await pool.execute(
      'UPDATE users SET is_active = 0, updated_at = UTC_TIMESTAMP() WHERE id = ?',
      [id]
    );
    if (!result.affectedRows) return sendError(res, 404, 'Buyer not found');
    await pool.execute('UPDATE api_keys SET is_active = 0 WHERE user_id = ?', [id]);
    return res.json({ success: true, message: 'Buyer deactivated and API keys disabled' });
  } catch (error) {
    console.error('[Deactivate buyer]', error.message);
    return sendError(res, 500, 'Could not deactivate buyer');
  }
});

app.get('/api/buyer/me', requireBuyer, async (req, res) => {
  if (!needDb(res)) return;

  try {
    const [rows] = await pool.execute(
      'SELECT id, email, is_active, created_at FROM users WHERE id = ? LIMIT 1',
      [req.buyer.id]
    );
    if (!rows.length) return sendError(res, 404, 'Buyer not found');
    return res.json({ success: true, user: rows[0] });
  } catch (error) {
    console.error('[Buyer profile]', error.message);
    return sendError(res, 500, 'Could not load buyer profile');
  }
});

/* -------------------- STOCK / SCHEDULE -------------------- */

app.get('/api/schedule', requireApiKey, async (req, res) => {
  if (!needDb(res)) return;
  try {
    const [rows] = await pool.execute('SELECT * FROM stocks ORDER BY id ASC LIMIT 500');
    return res.json({ success: true, schedule: rows, stocks: rows, recentSpawns: recentEvents });
  } catch (error) {
    console.error('[Schedule]', error.message);
    return sendError(res, 500, 'Could not load schedule');
  }
});

app.get('/api/stocks', requireApiKey, async (req, res) => {
  if (!needDb(res)) return;
  try {
    const [rows] = await pool.execute('SELECT * FROM stocks ORDER BY id ASC LIMIT 500');
    return res.json({ success: true, stocks: rows });
  } catch (error) {
    console.error('[Stocks]', error.message);
    return sendError(res, 500, 'Could not load stocks');
  }
});


/* -------------------- EGG / PET MAP -------------------- */

// GET: Load existing egg/pet mappings
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

// POST: Create or bulk-save egg/pet mappings
app.post('/api/admin/egg-map', requireAdmin, async (req, res) => {
  if (!needDb(res)) return;

  const items = req.body?.items || req.body?.eggMap;

  if (!Array.isArray(items) || items.length > 500) {
    return sendError(
      res,
      400,
      'items must be an array of up to 500 entries'
    );
  }

  let connection;

  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();

    for (const item of items) {
      const eggName = str(item.egg_name || item.eggName);
      const petName = str(item.pet_name || item.petName);
      const image = str(item.pet_image_url || item.petImageUrl);
      const tier = str(item.tier);
      const active =
  item.is_active === false ||
  item.is_active === 0 ||
  item.is_active === '0'
    ? 0
    : 1;

      if (!eggName || !petName) {
        throw new Error(
          'Each egg-map item requires egg_name and pet_name'
        );
      }

      await connection.execute(
        `INSERT INTO egg_pet_map
         (egg_name, pet_name, pet_image_url, tier, is_active,
          created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP())
         ON DUPLICATE KEY UPDATE
           pet_name = VALUES(pet_name),
           pet_image_url = VALUES(pet_image_url),
           tier = VALUES(tier),
           is_active = VALUES(is_active),
           updated_at = UTC_TIMESTAMP()`,
        [eggName, petName, image || null, tier || null, active]
      );
    }

    await connection.commit();

    return res.json({
      success: true,
      saved: items.length
    });
  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch {}
    }

    console.error('[Egg map save]', error.message);

    return sendError(
      res,
      400,
      'Could not save egg map. Check schema and item fields.'
    );
  } finally {
    if (connection) connection.release();
  }
});

// PUT: Edit one existing egg/pet mapping by its database ID
app.put('/api/admin/egg-map/:id', requireAdmin, async (req, res) => {
  if (!needDb(res)) return;

  const id = Number(req.params.id);

  if (!Number.isSafeInteger(id) || id < 1) {
    return sendError(res, 400, 'Invalid mapping ID');
  }

  const body = req.body || {};

  const eggName = str(body.egg_name || body.eggName);
  const petName = str(body.pet_name || body.petName);
  const image = str(body.pet_image_url || body.petImageUrl);
  const tier = str(body.tier);

  const active =
    body.is_active === false ||
    body.is_active === 0 ||
    body.is_active === '0'
      ? 0
      : 1;

  if (!eggName || !petName) {
    return sendError(
      res,
      400,
      'egg_name and pet_name are required'
    );
  }

  try {
    const [existing] = await pool.execute(
      'SELECT id FROM egg_pet_map WHERE id = ? LIMIT 1',
      [id]
    );

    if (!existing.length) {
      return sendError(res, 404, 'Egg mapping not found');
    }

    await pool.execute(
      `UPDATE egg_pet_map
       SET egg_name = ?,
           pet_name = ?,
           pet_image_url = ?,
           tier = ?,
           is_active = ?,
           updated_at = UTC_TIMESTAMP()
       WHERE id = ?`,
      [
        eggName,
        petName,
        image || null,
        tier || null,
        active,
        id
      ]
    );

    return res.json({
      success: true,
      updated: 1,
      id
    });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return sendError(
        res,
        409,
        'An egg mapping with this egg name already exists'
      );
    }

    console.error('[Egg map update]', error.message);

    return sendError(res, 500, 'Could not update egg mapping');
  }
});

/* -------------------- END EGG / PET MAP -------------------- */

/* -------------------- DISCORD WEBHOOK -------------------- */

// Is comment ke baad apna original Discord webhook code
// bilkul unchanged rehne dein.


app.get('/api/bot-webhook', (req, res) => {
  res.json({
    success: true,
    endpoint: '/api/bot-webhook',
    methodRequired: 'POST'
  });
});

app.post('/api/bot-webhook', async (req, res) => {
  if (!WEBHOOK_SECRET) {
    return sendError(res, 503, 'Webhook secret is not configured');
  }

  const supplied =
    str(req.headers['x-webhook-secret']) ||
    str(req.headers['x-api-key']) ||
    str(req.query.secret);

  if (!safeEqual(supplied, WEBHOOK_SECRET)) {
    return sendError(res, 401, 'Invalid webhook secret');
  }

  const body = req.body || {};
  const payload = body.data && typeof body.data === 'object' ? body.data : body;
  const messageId = str(
    payload.messageId || payload.message_id || body.messageId || body.message_id || body.id
  );

  if (messageId && seenMessageIds.has(messageId)) {
    return res.json({ success: true, duplicate: true });
  }

  // Persist the message ID when a database is available, so duplicates
  // can be rejected across process restarts.
  if (messageId && pool && databaseConnected) {
    try {
      await pool.execute(
        'INSERT INTO processed_messages (message_id, processed_at) VALUES (?, UTC_TIMESTAMP())',
        [messageId]
      );
    } catch (error) {
      if (error.code === 'ER_DUP_ENTRY') {
        seenMessageIds.add(messageId);
        return res.json({ success: true, duplicate: true });
      }
      console.error('[Webhook deduplication]', error.message);
      return sendError(res, 500, 'Could not record webhook message');
    }
  }

  const result = publishSpawn({
    tier: payload.tier || payload.rarity,
    eggName: payload.eggName || payload.egg_name || payload.egg,
    petName: payload.petName || payload.pet_name || payload.pet,
    time: payload.time || payload.timestamp || payload.spawnedAt
  });

  if (!result.ok) {
    if (messageId && pool && databaseConnected) {
      try {
        await pool.execute('DELETE FROM processed_messages WHERE message_id = ?', [messageId]);
      } catch {}
    }
    return sendError(res, 400, result.error);
  }

  if (messageId) {
    seenMessageIds.add(messageId);
    if (seenMessageIds.size > 5000) {
      seenMessageIds.delete(seenMessageIds.values().next().value);
    }
  }

  return res.json({ success: true, event: result.event });
});

/* -------------------- CONFIG / SPAWN EVENTS -------------------- */

app.get('/api/config', (req, res) => {
  res.json({
    success: true,
    service: 'steal-egg-saas-backend',
    discordChannelConfigured: Boolean(DISCORD_CHANNEL_ID),
    supportedTiers: ['Secret', 'Divine', 'Eternal']
  });
});

app.get('/api/spawn-events', requireApiKey, (req, res) => {
  res.json({
    success: true,
    events: recentEvents,
    lastWebhookAt,
    lastMessage
  });
});

/* -------------------- SERVER-SENT EVENTS -------------------- */

app.get('/events', async (req, res) => {
  if (!needDb(res)) return;

  const apiKey = str(req.query.apiKey);
  if (!apiKey) return sendError(res, 401, 'API key required');

  try {
    const record = await findValidApiKey(apiKey);
    if (!record) return sendError(res, 401, 'Invalid or inactive API key');
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

/* -------------------- STATIC PAGES -------------------- */

app.use(express.static(PUBLIC_DIR, {
  extensions: ['html'],
  index: 'index.html',
  fallthrough: true,
  maxAge: process.env.NODE_ENV === 'production' ? '1h' : 0
}));

const pageRoutes = {
  '/': 'index.html',
  '/login': 'generator.html',
  '/get-key': 'generator.html',
  '/generator': 'generator.html',
  '/master': 'master.html',
  '/admin': 'admin.html'
};

for (const [route, filename] of Object.entries(pageRoutes)) {
  app.get(route, (req, res, next) => {
    const file = path.join(PUBLIC_DIR, filename);
    if (fs.existsSync(file)) return res.sendFile(file);
    next();
  });
}

/* -------------------- 404 / ERROR HANDLING -------------------- */

app.use((req, res) => {
  if (req.path.startsWith('/api/') || req.path === '/events') {
    return sendError(res, 404, 'Endpoint not found');
  }

  const file = path.join(PUBLIC_DIR, '404.html');
  if (fs.existsSync(file)) return res.status(404).sendFile(file);
  return res.status(404).send('404 - Not Found');
});

app.use((error, req, res, next) => {
  console.error('[Unhandled request error]', error.message || error);
  if (res.headersSent) return next(error);

  if (req.path.startsWith('/api/') || req.path === '/events') {
    return sendError(res, 500, 'Internal server error');
  }

  const file = path.join(PUBLIC_DIR, '500.html');
  if (fs.existsSync(file)) return res.status(500).sendFile(file);
  return res.status(500).send('500 - Internal Server Error');
});

/* -------------------- STARTUP / SHUTDOWN -------------------- */

async function start() {
  try {
    pool = createDatabasePool();

    if (pool) {
      await checkDatabase();
      console.log(`[Database] Connected: ${databaseConnected}`);
    }

    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`[Backend] Listening on port ${PORT}`);
      console.log(`[Backend] Node ${process.version}`);
      console.log(`[Backend] Public directory: ${PUBLIC_DIR}`);
      console.log(`[Backend] Database connected: ${databaseConnected}`);

      if (JWT_SECRET.length < 32) {
        console.warn('[Security] Configure JWT_SECRET with 32+ characters');
      }
      if (!MASTER_USERNAME || !MASTER_PASSWORD) {
        console.warn('[Security] Configure MASTER_USERNAME and MASTER_PASSWORD');
      }
      if (!WEBHOOK_SECRET) {
        console.warn('[Security] WEBHOOK_SECRET is not configured');
      }
    });

    function shutdown(signal) {
      console.log(`[Backend] ${signal} received`);

      for (const client of CLIENTS) {
        try { client.end(); } catch {}
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
    }

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  } catch (error) {
    console.error('[Startup error]', error.stack || error.message || error);
    process.exitCode = 1;
  }
}

start();

module.exports = {
  app,
  publishSpawn,
  checkDatabase
};
