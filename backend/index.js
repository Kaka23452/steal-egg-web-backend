const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
const BOT_INGEST_KEY = process.env.BOT_INGEST_KEY;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const OVERLAY_TOKEN = process.env.OVERLAY_TOKEN;
const DEFAULT_TTL_MINUTES = Math.max(
  1,
  Number(process.env.DEFAULT_TIER_TTL_MINUTES || 45)
);

if (!JWT_SECRET || !BOT_INGEST_KEY || !ADMIN_USERNAME ||
    !ADMIN_PASSWORD || !OVERLAY_TOKEN) {
  throw new Error(
    'Missing required environment variables: JWT_SECRET, BOT_INGEST_KEY, ADMIN_USERNAME, ADMIN_PASSWORD, OVERLAY_TOKEN'
  );
}

app.disable('x-powered-by');
app.use(express.json({ limit: '256kb' }));

const allowedOrigins = (process.env.ALLOWED_ORIGIN || '')
  .split(',')
  .map(value => value.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Origin not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Bot-Key',
    'X-API-Key'
  ]
}));

let pool = null;
const sseClients = new Set();

function sendJsonError(res, status, message) {
  return res.status(status).json({ error: message });
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length &&
    crypto.timingSafeEqual(left, right);
}

function createToken(payload, expiresIn) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

async function getDb() {
  if (!pool) throw new Error('Database is not configured');
  return pool;
}

async function initDatabase() {
  const connectionString = process.env.DATABASE_URL;

  if (!connectionString) {
    console.warn('[Database] DATABASE_URL is missing; database routes will be unavailable.');
    return;
  }

  pool = mysql.createPool({
    uri: connectionString,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    timezone: 'Z',
    enableKeepAlive: true
  });

  try {
    const connection = await pool.getConnection();
    await connection.ping();
    connection.release();
    console.log('[Database] Connected successfully.');
  } catch (error) {
    console.error('[Database] Connection failed:', error.message);
    await pool.end().catch(() => {});
    pool = null;
  }
}

function requireBuyer(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ')
    ? header.slice(7)
    : '';

  if (!token) return sendJsonError(res, 401, 'Buyer login required');

  try {
    const payload = verifyToken(token);
    if (payload.role !== 'buyer' || !payload.userId) {
      return sendJsonError(res, 403, 'Buyer access required');
    }
    req.user = payload;
    next();
  } catch {
    return sendJsonError(res, 401, 'Session expired or invalid');
  }
}

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ')
    ? header.slice(7)
    : '';

  if (!token) return sendJsonError(res, 401, 'Admin login required');

  try {
    const payload = verifyToken(token);
    if (payload.role !== 'admin') {
      return sendJsonError(res, 403, 'Admin access required');
    }
    req.admin = payload;
    next();
  } catch {
    return sendJsonError(res, 401, 'Admin session expired or invalid');
  }
}

function requireBot(req, res, next) {
  const supplied = req.get('X-Bot-Key') || '';
  if (!safeEqual(supplied, BOT_INGEST_KEY)) {
    return sendJsonError(res, 401, 'Invalid bot key');
  }
  next();
}

function requireOverlay(req, res, next) {
  const supplied = req.query.token;
  if (typeof supplied !== 'string' ||
      !safeEqual(supplied, OVERLAY_TOKEN)) {
    return sendJsonError(res, 401, 'Invalid overlay token');
  }
  next();
}

async function requireApiKey(req, res, next) {
  const supplied = req.get('X-API-Key') || '';
  if (!supplied || supplied.length > 256) {
    return sendJsonError(res, 401, 'API key required');
  }

  try {
    const db = await getDb();
    const [rows] = await db.execute(
      `SELECT ak.id, ak.user_id
       FROM api_keys ak
       JOIN users u ON u.id = ak.user_id
       WHERE ak.key_hash = ?
         AND ak.is_active = 1
         AND ak.expires_at > UTC_TIMESTAMP()
         AND u.is_active = 1
       LIMIT 1`,
      [sha256(supplied)]
    );

    if (!rows.length) {
      return sendJsonError(res, 401, 'API key is invalid or expired');
    }

    req.apiKey = rows[0];
    await db.execute(
      'UPDATE api_keys SET last_used_at = UTC_TIMESTAMP() WHERE id = ?',
      [req.apiKey.id]
    );
    next();
  } catch (error) {
    console.error('[API key auth]', error.message);
    return sendJsonError(res, 503, 'Database unavailable');
  }
}

function broadcast(event) {
  const payload = `event: spawn\ndata: ${JSON.stringify(event)}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(payload);
    } catch {
      sseClients.delete(client);
    }
  }
}

function parseDate(value) {
  if (!value) return new Date();
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

app.get('/health', async (req, res) => {
  let databaseConnected = false;

  if (pool) {
    try {
      await pool.query('SELECT 1');
      databaseConnected = true;
    } catch {}
  }

  res.json({
    ok: true,
    service: 'steal-egg-saas-backend',
    databaseConfigured: Boolean(pool),
    databaseConnected,
    activeSseClients: sseClients.size,
    time: new Date().toISOString()
  });
});

app.get('/api/schedule', async (req, res) => {
  if (!pool) return sendJsonError(res, 503, 'Database unavailable');

  try {
    const [rows] = await pool.execute(
      `SELECT id, tier, egg_name AS eggName, pet_name AS petName,
              pet_image_url AS petImageUrl, location_name AS location,
              spawned_at AS spawnedAt, expires_at AS expiresAt
       FROM stocks
       WHERE expires_at > UTC_TIMESTAMP()
       ORDER BY spawned_at DESC
       LIMIT 100`
    );
    res.json({ stocks: rows });
  } catch (error) {
    console.error('[Schedule]', error.message);
    sendJsonError(res, 500, 'Could not load current stocks');
  }
});

app.post('/api/auth/register', async (req, res) => {
  if (!pool) return sendJsonError(res, 503, 'Database unavailable');

  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      password.length < 10 || password.length > 128) {
    return sendJsonError(
      res,
      400,
      'Enter a valid email and a password of 10–128 characters'
    );
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const [result] = await pool.execute(
      'INSERT INTO users (email, password_hash) VALUES (?, ?)',
      [email, passwordHash]
    );

    res.status(201).json({
      ok: true,
      userId: result.insertId,
      message: 'Account created. You can now log in.'
    });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return sendJsonError(res, 409, 'Email already registered');
    }
    console.error('[Register]', error.message);
    sendJsonError(res, 500, 'Could not create account');
  }
});

app.post('/api/auth/login', async (req, res) => {
  if (!pool) return sendJsonError(res, 503, 'Database unavailable');

  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  try {
    const [rows] = await pool.execute(
      'SELECT id, email, password_hash, is_active FROM users WHERE email = ? LIMIT 1',
      [email]
    );

    if (!rows.length || !rows[0].is_active ||
        !(await bcrypt.compare(password, rows[0].password_hash))) {
      return sendJsonError(res, 401, 'Invalid email or password');
    }

    const token = createToken(
      { role: 'buyer', userId: rows[0].id, email: rows[0].email },
      process.env.USER_SESSION_TTL || '1800s'
    );

    res.json({
      ok: true,
      token,
      expiresIn: process.env.USER_SESSION_TTL || 1800,
      user: { id: rows[0].id, email: rows[0].email }
    });
  } catch (error) {
    console.error('[Login]', error.message);
    sendJsonError(res, 503, 'Login service unavailable');
  }
});

app.post('/api/keys/generate', requireBuyer, async (req, res) => {
  if (!pool) return sendJsonError(res, 503, 'Database unavailable');

  try {
    const rawKey = `sae_${crypto.randomBytes(32).toString('hex')}`;
    const expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);

    await pool.execute(
      `INSERT INTO api_keys
       (user_id, key_hash, key_prefix, expires_at)
       VALUES (?, ?, ?, ?)`,
      [
        req.user.userId,
        sha256(rawKey),
        rawKey.slice(0, 12),
        expiresAt.toISOString().slice(0, 19).replace('T', ' ')
      ]
    );

    res.status(201).json({
      ok: true,
      apiKey: rawKey,
      expiresAt: expiresAt.toISOString(),
      warning: 'Copy this key now. It will not be shown again.'
    });
  } catch (error) {
    console.error('[Generate key]', error.message);
    sendJsonError(res, 500, 'Could not generate API key');
  }
});

app.get('/api/keys', requireBuyer, async (req, res) => {
  if (!pool) return sendJsonError(res, 503, 'Database unavailable');

  try {
    const [rows] = await pool.execute(
      `SELECT id, key_prefix AS keyPrefix, is_active AS isActive,
              expires_at AS expiresAt, last_used_at AS lastUsedAt,
              created_at AS createdAt
       FROM api_keys WHERE user_id = ? ORDER BY created_at DESC`,
      [req.user.userId]
    );
    res.json({ keys: rows });
  } catch (error) {
    console.error('[List keys]', error.message);
    sendJsonError(res, 500, 'Could not list API keys');
  }
});

app.post('/api/admin/login', (req, res) => {
  const username = String(req.body.username || '');
  const password = String(req.body.password || '');

  if (!safeEqual(username, ADMIN_USERNAME) ||
      !safeEqual(password, ADMIN_PASSWORD)) {
    return sendJsonError(res, 401, 'Invalid admin credentials');
  }

  const token = createToken({ role: 'admin' }, '1h');
  res.json({ ok: true, token, expiresIn: 3600 });
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  if (!pool) return sendJsonError(res, 503, 'Database unavailable');

  try {
    const [rows] = await pool.execute(
      `SELECT u.id, u.email, u.is_active AS isActive,
              u.created_at AS createdAt,
              COUNT(ak.id) AS apiKeyCount
       FROM users u
       LEFT JOIN api_keys ak ON ak.user_id = u.id
       GROUP BY u.id
       ORDER BY u.created_at DESC`
    );
    res.json({ users: rows });
  } catch (error) {
    console.error('[Admin users]', error.message);
    sendJsonError(res, 500, 'Could not list users');
  }
});

app.post('/api/admin/users', requireAdmin, async (req, res) => {
  if (!pool) return sendJsonError(res, 503, 'Database unavailable');

  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      password.length < 10 || password.length > 128) {
    return sendJsonError(
      res, 400, 'Valid email and password (10–128 characters) required'
    );
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const [result] = await pool.execute(
      'INSERT INTO users (email, password_hash) VALUES (?, ?)',
      [email, passwordHash]
    );
    res.status(201).json({ ok: true, userId: result.insertId, email });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return sendJsonError(res, 409, 'Email already exists');
    }
    console.error('[Admin create user]', error.message);
    sendJsonError(res, 500, 'Could not create user');
  }
});

app.put('/api/admin/users/:id/status', requireAdmin, async (req, res) => {
  if (!pool) return sendJsonError(res, 503, 'Database unavailable');

  const active = req.body.isActive;
  if (typeof active !== 'boolean') {
    return sendJsonError(res, 400, 'isActive must be true or false');
  }

  try {
    const [result] = await pool.execute(
      'UPDATE users SET is_active = ? WHERE id = ?',
      [active ? 1 : 0, req.params.id]
    );
    if (!result.affectedRows) {
      return sendJsonError(res, 404, 'User not found');
    }
    if (!active) {
      await pool.execute(
        'UPDATE api_keys SET is_active = 0 WHERE user_id = ?',
        [req.params.id]
      );
    }
    res.json({ ok: true });
  } catch (error) {
    console.error('[Admin user status]', error.message);
    sendJsonError(res, 500, 'Could not update user');
  }
});

app.get('/api/admin/egg-pet-map', requireAdmin, async (req, res) => {
  if (!pool) return sendJsonError(res, 503, 'Database unavailable');
  try {
    const [rows] = await pool.execute(
      'SELECT * FROM egg_pet_map ORDER BY tier, egg_name'
    );
    res.json({ mappings: rows });
  } catch (error) {
    console.error('[Egg map]', error.message);
    sendJsonError(res, 500, 'Could not load egg-pet mappings');
  }
});

app.post('/api/admin/egg-pet-map', requireAdmin, async (req, res) => {
  if (!pool) return sendJsonError(res, 503, 'Database unavailable');

  const eggName = String(req.body.eggName || '').trim();
  const petName = String(req.body.petName || '').trim();
  const tier = String(req.body.tier || '').trim();
  const imageUrl = req.body.petImageUrl
    ? String(req.body.petImageUrl).trim()
    : null;

  if (!eggName || !petName || !tier ||
      eggName.length > 191 || petName.length > 191 ||
      tier.length > 32 || (imageUrl && imageUrl.length > 1024)) {
    return sendJsonError(res, 400, 'Invalid egg, pet, tier or image URL');
  }

  try {
    await pool.execute(
      `INSERT INTO egg_pet_map (egg_name, pet_name, tier, pet_image_url)
       VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         pet_name = VALUES(pet_name),
         tier = VALUES(tier),
         pet_image_url = VALUES(pet_image_url),
         is_active = 1`,
      [eggName, petName, tier, imageUrl]
    );
    res.json({ ok: true });
  } catch (error) {
    console.error('[Save egg map]', error.message);
    sendJsonError(res, 500, 'Could not save mapping');
  }
});

app.get('/api/admin/location-aliases', requireAdmin, async (req, res) => {
  if (!pool) return sendJsonError(res, 503, 'Database unavailable');
  try {
    const [rows] = await pool.execute(
      'SELECT * FROM location_alias ORDER BY alias_name'
    );
    res.json({ aliases: rows });
  } catch (error) {
    console.error('[Aliases]', error.message);
    sendJsonError(res, 500, 'Could not load aliases');
  }
});

app.post('/api/admin/location-aliases', requireAdmin, async (req, res) => {
  if (!pool) return sendJsonError(res, 503, 'Database unavailable');

  const alias = String(req.body.aliasName || '').trim();
  const canonical = String(req.body.canonicalName || '').trim();

  if (!alias || !canonical || alias.length > 191 ||
      canonical.length > 191) {
    return sendJsonError(res, 400, 'Valid alias and canonical name required');
  }

  try {
    await pool.execute(
      `INSERT INTO location_alias (alias_name, canonical_name)
       VALUES (?, ?)
       ON DUPLICATE KEY UPDATE canonical_name = VALUES(canonical_name)`,
      [alias, canonical]
    );
    res.json({ ok: true });
  } catch (error) {
    console.error('[Save alias]', error.message);
    sendJsonError(res, 500, 'Could not save alias');
  }
});

app.post('/api/ingest', requireBot, async (req, res) => {
  if (!pool) return sendJsonError(res, 503, 'Database unavailable');

  const body = req.body || {};
  const messageId = String(body.messageId || '').trim();
  const eggName = String(body.eggName || '').trim();
  const tier = String(body.tier || '').trim();
  const locationInput = String(body.location || '').trim();

  if (!messageId || !eggName || !tier ||
      messageId.length > 64 || eggName.length > 191 ||
      tier.length > 32) {
    return sendJsonError(res, 400, 'messageId, eggName and tier are required');
  }

  const spawnedAt = parseDate(body.spawnedAt || body.time);
  if (!spawnedAt) return sendJsonError(res, 400, 'Invalid spawn time');

  const expiresAt = new Date(
    spawnedAt.getTime() + DEFAULT_TTL_MINUTES * 60 * 1000
  );

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const [existing] = await connection.execute(
      'SELECT id FROM processed_messages WHERE message_id = ? LIMIT 1',
      [messageId]
    );

    if (existing.length) {
      await connection.rollback();
      return res.json({ ok: true, duplicate: true });
    }

    const [maps] = await connection.execute(
      `SELECT pet_name, pet_image_url
       FROM egg_pet_map
       WHERE egg_name = ? AND is_active = 1 LIMIT 1`,
      [eggName]
    );

    let location = locationInput || null;
    if (location) {
      const [aliases] = await connection.execute(
        'SELECT canonical_name FROM location_alias WHERE alias_name = ? LIMIT 1',
        [location]
      );
      if (aliases.length) location = aliases[0].canonical_name;
    }

    await connection.execute(
      `INSERT INTO stocks
       (tier, egg_name, pet_name, pet_image_url, location_name,
        spawned_at, expires_at, source_message_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         tier = VALUES(tier),
         pet_name = VALUES(pet_name),
         pet_image_url = VALUES(pet_image_url),
         location_name = VALUES(location_name),
         spawned_at = VALUES(spawned_at),
         expires_at = VALUES(expires_at)`,
      [
        tier,
        eggName,
        maps[0]?.pet_name || body.petName || null,
        maps[0]?.pet_image_url || body.petImageUrl || null,
        location,
        spawnedAt.toISOString().slice(0, 19).replace('T', ' '),
        expiresAt.toISOString().slice(0, 19).replace('T', ' '),
        messageId
      ]
    );

    await connection.execute(
      'INSERT INTO processed_messages (message_id) VALUES (?)',
      [messageId]
    );

    await connection.commit();

    const event = {
      type: 'SPAWN',
      tier,
      eggName,
      petName: maps[0]?.pet_name || body.petName || null,
      petImageUrl: maps[0]?.pet_image_url || body.petImageUrl || null,
      location,
      time: spawnedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
      messageId
    };

    broadcast(event);
    res.status(201).json({ ok: true, event });
  } catch (error) {
    await connection.rollback().catch(() => {});
    if (error.code === 'ER_DUP_ENTRY') {
      return res.json({ ok: true, duplicate: true });
    }
    console.error('[Ingest]', error.message);
    sendJsonError(res, 500, 'Could not process spawn event');
  } finally {
    connection.release();
  }
});

function startSse(req, res) {
  res.status(200);
  res.set({
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.flushHeaders?.();
  res.write('retry: 3000\n\n');
  res.write(`event: connected\ndata: ${JSON.stringify({
    ok: true,
    time: new Date().toISOString()
  })}\n\n`);

  sseClients.add(res);

  const heartbeat = setInterval(() => {
    try {
      res.write(`: heartbeat ${Date.now()}\n\n`);
    } catch {
      clearInterval(heartbeat);
      sseClients.delete(res);
    }
  }, 25000);

  req.on('close', () => {
    clearInterval(heartbeat);
    sseClients.delete(res);
  });
}

app.get('/events', requireApiKey, startSse);

app.get('/overlay/events', requireOverlay, startSse);

app.get('/api/overlay/stocks', requireOverlay, async (req, res) => {
  if (!pool) return sendJsonError(res, 503, 'Database unavailable');

  try {
    const [rows] = await pool.execute(
      `SELECT tier, egg_name AS eggName, pet_name AS petName,
              pet_image_url AS petImageUrl, location_name AS location,
              spawned_at AS spawnedAt, expires_at AS expiresAt
       FROM stocks
       WHERE expires_at > UTC_TIMESTAMP()
       ORDER BY spawned_at DESC LIMIT 5`
    );
    res.json({ stocks: rows });
  } catch (error) {
    console.error('[Overlay stocks]', error.message);
    sendJsonError(res, 500, 'Could not load overlay stocks');
  }
});

app.use('/dashboard', express.static(path.join(__dirname, 'public')));
app.use('/public', express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.json({
    service: 'steal-egg-saas-backend',
    status: 'running',
    health: '/health'
  });
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err.type === 'entity.parse.failed') {
    return sendJsonError(res, 400, 'Invalid JSON body');
  }
  if (err.message === 'Origin not allowed by CORS') {
    return sendJsonError(res, 403, err.message);
  }
  console.error('[Server error]', err.message);
  sendJsonError(res, 500, 'Internal server error');
});

async function main() {
  await initDatabase();

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Server] Listening on port ${PORT}`);
  });

  server.keepAliveTimeout = 65000;
  server.headersTimeout = 66000;

  function shutdown(signal) {
    console.log(`[Server] ${signal} received; shutting down`);
    for (const client of sseClients) client.end();
    server.close(async () => {
      if (pool) await pool.end().catch(() => {});
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10000).unref();
  }

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch(error => {
  console.error('[Startup]', error);
  process.exit(1);
});
