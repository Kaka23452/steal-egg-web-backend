
'use strict';

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

const PORT = Number(process.env.PORT || 8080);
const MAX_EVENTS = 100;
const SPAWN_STORE =
  process.env.SPAWN_STORE ||
  path.join(__dirname, 'spawn-events.json');

const JWT_SECRET = process.env.JWT_SECRET || '';
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || '';
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';
const MASTER_USERNAME = process.env.MASTER_USERNAME || 'master';

const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const DISCORD_CHANNEL_ID = process.env.DISCORD_CHANNEL_ID || '';

let pool = null;
let dbReady = false;
let dbMessage = 'Database is not configured';

const recentEvents = [];
const seenMessageIds = new Set();

let lastWebhookAt = null;
let lastMessage = null;

app.use(cors({
  origin: ALLOWED_ORIGIN === '*'
    ? '*'
    : ALLOWED_ORIGIN.split(',').map(x => x.trim()),
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Webhook-Secret',
    'X-API-Key'
  ]
}));

app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));

  return left.length === right.length &&
    crypto.timingSafeEqual(left, right);
}

function createApiKey() {
  return 'sae_' + crypto.randomBytes(32).toString('hex');
}

function loadSpawnEvents() {
  try {
    if (!fs.existsSync(SPAWN_STORE)) return;

    const data = JSON.parse(fs.readFileSync(SPAWN_STORE, 'utf8'));

    if (!Array.isArray(data)) {
      throw new Error('Spawn store must contain an array');
    }

    recentEvents.length = 0;
    seenMessageIds.clear();

    for (const event of data.slice(0, MAX_EVENTS)) {
      if (!event || typeof event !== 'object' ||
          Array.isArray(event)) continue;

      recentEvents.push(event);

      if (event.messageId != null) {
        seenMessageIds.add(String(event.messageId));
      }
    }

    lastMessage = recentEvents[0] || null;
    lastWebhookAt = lastMessage
      ? (lastMessage.receivedAt || lastMessage.timestamp || null)
      : null;

    console.log('[Spawn persistence] Restored', recentEvents.length, 'events');
  } catch (err) {
    console.error('[Spawn persistence] Load failed:', err.message);
  }
}

function saveSpawnEvents() {
  const tempPath = SPAWN_STORE + '.tmp';

  try {
    fs.mkdirSync(path.dirname(SPAWN_STORE), { recursive: true });

    fs.writeFileSync(
      tempPath,
      JSON.stringify(recentEvents.slice(0, MAX_EVENTS), null, 2),
      'utf8'
    );

    fs.renameSync(tempPath, SPAWN_STORE);
  } catch (err) {
    console.error('[Spawn persistence] Save failed:', err.message);

    try {
      if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath);
    } catch (_) {}
  }
}

function addSpawnEvent(input) {
  const event = input && typeof input === 'object' ? input : {};

  const messageId = event.messageId != null
    ? String(event.messageId)
    : '';

  if (messageId && seenMessageIds.has(messageId)) {
    return { added: false, duplicate: true };
  }

  const record = {
    ...event,
    messageId: messageId || undefined,
    receivedAt: new Date().toISOString()
  };

  recentEvents.unshift(record);

  while (recentEvents.length > MAX_EVENTS) {
    const removed = recentEvents.pop();
    if (removed && removed.messageId) {
      seenMessageIds.delete(String(removed.messageId));
    }
  }

  if (messageId) seenMessageIds.add(messageId);

  lastMessage = record;
  lastWebhookAt = record.receivedAt;
  saveSpawnEvents();

  return { added: true, event: record };
}

function requireJwt(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ')
    ? header.slice(7)
    : '';

  if (!token || !JWT_SECRET) {
    return res.status(401).json({ ok: false, error: 'Authentication required' });
  }

  try {
    req.auth = jwt.verify(token, JWT_SECRET);
    return next();
  } catch (_) {
    return res.status(401).json({ ok: false, error: 'Invalid or expired token' });
  }
}

function requireMaster(req, res, next) {
  if (!req.auth || req.auth.role !== 'master') {
    return res.status(403).json({ ok: false, error: 'Master access required' });
  }
  next();
}

function requireDatabase(req, res, next) {
  if (!pool || !dbReady) {
    return res.status(503).json({
      ok: false,
      error: 'Database unavailable',
      detail: dbMessage
    });
  }
  next();
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function initializeDatabase() {
  const host = process.env.DB_HOST || process.env.MYSQL_HOST;
  const user = process.env.DB_USER || process.env.MYSQL_USER;
  const password = process.env.DB_PASSWORD || process.env.MYSQL_PASSWORD;
  const database = process.env.DB_NAME || process.env.MYSQL_DATABASE;
  const port = Number(process.env.DB_PORT || process.env.MYSQL_PORT || 3306);

  if (!host || !user || !database) {
    dbReady = false;
    dbMessage = 'Missing DB_HOST, DB_USER or DB_NAME environment variable';
    console.warn('[Database]', dbMessage);
    return;
  }

  pool = mysql.createPool({
    host,
    port,
    user,
    password: password || '',
    database,
    waitForConnections: true,
    connectionLimit: 5,
    queueLimit: 0,
    connectTimeout: 10000,
    ssl: process.env.DB_SSL === 'true'
      ? { rejectUnauthorized: true }
      : undefined
  });

  try {
    await pool.query('SELECT 1');

    /*
     * Existing installations may already have a users table.
     * Do not drop or recreate it. Review its schema before applying
     * any migration for email or is_active columns.
     */
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(190) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        api_key VARCHAR(255) NULL UNIQUE,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        email VARCHAR(255) NULL UNIQUE,
        is_active TINYINT(1) NOT NULL DEFAULT 1
      )
    `);

    /*
     * CREATE TABLE IF NOT EXISTS does not alter an existing table.
     * Check columns and add only missing columns; keep existing rows.
     */
    const [columns] = await pool.query('SHOW COLUMNS FROM users');
    const names = new Set(columns.map(c => c.Field));

    if (!names.has('email')) {
      await pool.query('ALTER TABLE users ADD COLUMN email VARCHAR(255) NULL');
    }

    if (!names.has('is_active')) {
      await pool.query(
        'ALTER TABLE users ADD COLUMN is_active TINYINT(1) NOT NULL DEFAULT 1'
      );
    }

    const [indexes] = await pool.query('SHOW INDEX FROM users');
    const emailUnique = indexes.some(
      x => x.Column_name === 'email' && x.Non_unique === 0
    );

    if (!emailUnique) {
      try {
        await pool.query(
          'ALTER TABLE users ADD UNIQUE INDEX users_email_unique (email)'
        );
      } catch (err) {
        console.error(
          '[Database] Could not add unique email index. Check existing duplicate emails:',
          err.message
        );
      }
    }

    dbReady = true;
    dbMessage = 'Database connected';
    console.log('[Database]', dbMessage);
  } catch (err) {
    dbReady = false;
    dbMessage = err.message;
    console.error('[Database] Initialization failed:', err.message);
  }
}

app.get('/', (req, res) => {
  res.type('html').send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Steal An Egg Backend</title>
<style>
body{font:16px system-ui;background:#10131b;color:#f4f5fa;max-width:760px;margin:50px auto;padding:20px}
section{background:#1a2030;padding:20px;border-radius:14px;margin:14px 0}
a{color:#91baff}code{color:#a8e6c0}
</style>
</head>
<body>
<h1>Steal An Egg — Backend</h1>
<section>Service is running.</section>
<section><a href="/health">Health status</a></section>
<section><a href="/master">Master Console</a></section>
<section><a href="/generator">Buyer Generator</a></section>
</body></html>`);
});

app.get('/health', (req, res) => {
  res.status(200).json({
    ok: true,
    service: 'steal-egg-saas-backend',
    timestamp: new Date().toISOString(),
    databaseConfigured: Boolean(pool),
    databaseConnected: dbReady,
    databaseMessage: dbMessage,
    webhookReceived: Boolean(lastWebhookAt),
    lastWebhookAt,
    activeSchedules: recentEvents.length,
    configured: {
      jwtSecret: Boolean(JWT_SECRET),
      masterPassword: Boolean(MASTER_PASSWORD),
      webhookSecret: Boolean(WEBHOOK_SECRET),
      discordChannelId: Boolean(DISCORD_CHANNEL_ID)
    }
  });
});

app.get('/health/database', async (req, res) => {
  if (!pool || !dbReady) {
    return res.status(503).json({
      ok: false,
      connected: false,
      message: dbMessage
    });
  }

  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, connected: true, message: 'Database connected' });
  } catch (err) {
    dbReady = false;
    dbMessage = err.message;
    res.status(503).json({ ok: false, connected: false, message: err.message });
  }
});

/* Master login */
app.post('/api/master/login', (req, res) => {
  if (!JWT_SECRET || !MASTER_PASSWORD) {
    return res.status(503).json({
      ok: false,
      error: 'Set JWT_SECRET and MASTER_PASSWORD in environment variables'
    });
  }

  const username = String(req.body.username || '');
  const password = String(req.body.password || '');

  if (
    !safeEqual(username, MASTER_USERNAME) ||
    !safeEqual(password, MASTER_PASSWORD)
  ) {
    return res.status(401).json({ ok: false, error: 'Invalid master credentials' });
  }

  const token = jwt.sign(
    { role: 'master', username: MASTER_USERNAME },
    JWT_SECRET,
    { expiresIn: '8h' }
  );

  res.json({ ok: true, token, expiresIn: 28800 });
});

/* Buyer login: email or legacy username */
app.post('/api/generator/login', requireDatabase, async (req, res) => {
  const identity = String(req.body.email || req.body.username || '')
    .trim()
    .toLowerCase();
  const password = String(req.body.password || '');

  if (!identity || !password) {
    return res.status(400).json({ ok: false, error: 'Email/username and password are required' });
  }

  try {
    const [rows] = await pool.query(
      `SELECT id, username, email, password_hash, api_key, is_active
       FROM users WHERE LOWER(email) = ? OR LOWER(username) = ?
       LIMIT 1`,
      [identity, identity]
    );

    const user = rows[0];

    if (!user || !user.is_active ||
        !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ ok: false, error: 'Invalid credentials or inactive account' });
    }

    if (!JWT_SECRET) {
      return res.status(503).json({ ok: false, error: 'JWT_SECRET is not configured' });
    }

    const token = jwt.sign(
      { role: 'buyer', userId: String(user.id) },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    res.json({
      ok: true,
      token,
      buyer: {
        id: String(user.id),
        email: user.email || null,
        username: user.username,
        apiKey: user.api_key || null
      }
    });
  } catch (err) {
    console.error('[Buyer login]', err.message);
    res.status(500).json({ ok: false, error: 'Login failed; check users table schema' });
  }
});

/* Master: list buyers */
app.get('/api/master/buyers', requireJwt, requireMaster, requireDatabase, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, username, email, api_key, is_active, created_at
       FROM users ORDER BY id DESC LIMIT 500`
    );

    res.json({
      ok: true,
      buyers: rows.map(row => ({
        ...row,
        id: String(row.id),
        api_key: row.api_key || null,
        is_active: Boolean(row.is_active)
      }))
    });
  } catch (err) {
    console.error('[Buyer list]', err.message);
    res.status(500).json({ ok: false, error: 'Could not load buyer list' });
  }
});

/* Master: create a buyer */
app.post('/api/master/buyers', requireJwt, requireMaster, requireDatabase, async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || '');

  if (!validateEmail(email)) {
    return res.status(400).json({ ok: false, error: 'Enter a valid email address' });
  }

  if (password.length < 8 || password.length > 200) {
    return res.status(400).json({ ok: false, error: 'Password must be 8–200 characters' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const apiKey = createApiKey();

    /*
     * username is also populated for compatibility with the legacy
     * NOT NULL username column. Existing buyer rows are not deleted.
     */
    const [result] = await pool.query(
      `INSERT INTO users (username, email, password_hash, api_key, is_active)
       VALUES (?, ?, ?, ?, 1)`,
      [email, email, passwordHash, apiKey]
    );

    res.status(201).json({
      ok: true,
      buyer: {
        id: String(result.insertId),
        email,
        username: email,
        apiKey
      }
    });
  } catch (err) {
    console.error('[Create buyer]', err.message);

    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ ok: false, error: 'A buyer with this email/username already exists' });
    }

    res.status(500).json({
      ok: false,
      error: 'Could not create buyer; verify the existing users table schema'
    });
  }
});

/* Master: generate or regenerate buyer API key */
app.post('/api/master/buyers/:id/api-key', requireJwt, requireMaster, requireDatabase, async (req, res) => {
  const id = String(req.params.id || '');

  if (!/^\d+$/.test(id)) {
    return res.status(400).json({ ok: false, error: 'Invalid buyer ID' });
  }

  try {
    const apiKey = createApiKey();

    const [result] = await pool.query(
      'UPDATE users SET api_key = ? WHERE id = ?',
      [apiKey, id]
    );

    if (!result.affectedRows) {
      return res.status(404).json({ ok: false, error: 'Buyer not found' });
    }

    res.json({ ok: true, id, apiKey });
  } catch (err) {
    console.error('[API key]', err.message);
    res.status(500).json({ ok: false, error: 'Could not update API key' });
  }
});

/* Master: activate/deactivate buyer */
app.post('/api/master/buyers/:id/status', requireJwt, requireMaster, requireDatabase, async (req, res) => {
  const id = String(req.params.id || '');
  const isActive = req.body.isActive;

  if (!/^\d+$/.test(id) || typeof isActive !== 'boolean') {
    return res.status(400).json({ ok: false, error: 'Valid buyer ID and boolean isActive are required' });
  }

  try {
    const [result] = await pool.query(
      'UPDATE users SET is_active = ? WHERE id = ?',
      [isActive ? 1 : 0, id]
    );

    if (!result.affectedRows) {
      return res.status(404).json({ ok: false, error: 'Buyer not found' });
    }

    res.json({ ok: true, id, isActive });
  } catch (err) {
    console.error('[Buyer status]', err.message);
    res.status(500).json({ ok: false, error: 'Could not update buyer status' });
  }
});

/* Buyer: retrieve their own API key */
app.get('/api/generator/me', requireJwt, requireDatabase, async (req, res) => {
  if (req.auth.role !== 'buyer') {
    return res.status(403).json({ ok: false, error: 'Buyer access required' });
  }

  try {
    const [rows] = await pool.query(
      'SELECT id, username, email, api_key, is_active FROM users WHERE id = ? LIMIT 1',
      [req.auth.userId]
    );

    const user = rows[0];

    if (!user || !user.is_active) {
      return res.status(403).json({ ok: false, error: 'Buyer account is inactive or missing' });
    }

    res.json({
      ok: true,
      buyer: {
        id: String(user.id),
        username: user.username,
        email: user.email || null,
        apiKey: user.api_key || null
      }
    });
  } catch (err) {
    console.error('[Generator profile]', err.message);
    res.status(500).json({ ok: false, error: 'Could not load buyer profile' });
  }
});

/* Discord or trusted backend webhook: add spawn event */
app.post('/api/spawn/webhook', (req, res) => {
  if (!WEBHOOK_SECRET) {
    return res.status(503).json({ ok: false, error: 'WEBHOOK_SECRET is not configured' });
  }

  const supplied = req.headers['x-webhook-secret'] ||
    req.headers.authorization?.replace(/^Bearer\s+/i, '');

  if (!safeEqual(supplied, WEBHOOK_SECRET)) {
    return res.status(401).json({ ok: false, error: 'Invalid webhook secret' });
  }

  const body = req.body || {};

  if (!body.messageId && !body.timestamp && !body.spawnTime &&
      !body.name && !body.content) {
    return res.status(400).json({ ok: false, error: 'Spawn event data is required' });
  }

  const result = addSpawnEvent(body);
  res.status(result.duplicate ? 200 : 201).json({
    ok: true,
    ...result
  });
});

/* Frontend spawn schedule endpoint */
app.get('/api/schedule', (req, res) => {
  res.set('Cache-Control', 'no-store');

  res.json({
    ok: true,
    channelId: DISCORD_CHANNEL_ID || null,
    activeSchedules: recentEvents.length,
    lastWebhookAt,
    lastMessage,
    events: recentEvents
  });
});

/* Optional API-key access for dashboard clients */
app.get('/api/spawn/events', async (req, res) => {
  const key = String(req.headers['x-api-key'] || req.query.apiKey || '');

  if (!key || !pool || !dbReady) {
    return res.status(401).json({ ok: false, error: 'Valid X-API-Key required' });
  }

  try {
    const [rows] = await pool.query(
      'SELECT id FROM users WHERE api_key = ? AND is_active = 1 LIMIT 1',
      [key]
    );

    if (!rows.length) {
      return res.status(401).json({ ok: false, error: 'Invalid API key' });
    }

    res.set('Cache-Control', 'no-store');
    res.json({
      ok: true,
      events: recentEvents,
      lastWebhookAt
    });
  } catch (err) {
    console.error('[Spawn events]', err.message);
    res.status(500).json({ ok: false, error: 'Could not load spawn events' });
  }
});

/* Minimal functional login pages; these are not the old branded UI */
app.get('/master', (req, res) => {
  res.type('html').send(`<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Master Console</title><style>
body{font:16px system-ui;max-width:760px;margin:35px auto;padding:16px;background:#10131b;color:#f5f6fa}
input,button{padding:11px;margin:5px 0;max-width:100%;box-sizing:border-box}
input{display:block;width:100%}button{cursor:pointer}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#1b2030;padding:12px}
</style></head><body><h1>Master Console</h1>
<form id="login"><input name="username" placeholder="Master username" required>
<input name="password" type="password" placeholder="Master password" required>
<button>Login</button></form>
<section id="panel" hidden><h2>Create buyer</h2>
<form id="create"><input name="email" type="email" placeholder="Buyer email" required>
<input name="password" type="password" minlength="8" placeholder="Temporary password (8+ characters)" required>
<button>Create buyer</button></form>
<button id="refresh">Refresh buyer list</button></section>
<pre id="out">Sign in to continue.</pre>
<script>
let token='';
const out=document.getElementById('out');
async function call(url,options={}) {
 const r=await fetch(url,{...options,headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{}),...(options.headers||{})}});
 const d=await r.json().catch(()=>({error:'Invalid server response'}));
 if(!r.ok) throw new Error(d.error||('HTTP '+r.status));
 return d;
}
document.getElementById('login').onsubmit=async e=>{
 e.preventDefault();const f=new FormData(e.target);
 try{const d=await call('/api/master/login',{method:'POST',body:JSON.stringify({username:f.get('username'),password:f.get('password')})});token=d.token;document.getElementById('panel').hidden=false;out.textContent='Login successful';await refresh();}
 catch(err){out.textContent=err.message;}
};
async function refresh(){try{out.textContent=JSON.stringify(await call('/api/master/buyers'),null,2);}catch(err){out.textContent=err.message;}}
document.getElementById('refresh').onclick=refresh;
document.getElementById('create').onsubmit=async e=>{
 e.preventDefault();const f=new FormData(e.target);
 try{out.textContent=JSON.stringify(await call('/api/master/buyers',{method:'POST',body:JSON.stringify({email:f.get('email'),password:f.get('password')})}),null,2);await refresh();}
 catch(err){out.textContent=err.message;}
};
</script></body></html>`);
});

app.get('/generator', (req, res) => {
  res.type('html').send(`<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Buyer Generator</title><style>
body{font:16px system-ui;max-width:700px;margin:35px auto;padding:16px;background:#10131b;color:#f5f6fa}
input,button{padding:11px;margin:5px 0;max-width:100%;box-sizing:border-box}
input{display:block;width:100%}button{cursor:pointer}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#1b2030;padding:12px}
</style></head><body><h1>Buyer Generator</h1>
<form id="login"><input name="email" placeholder="Email or legacy username" required>
<input name="password" type="password" placeholder="Password" required>
<button>Login</button></form>
<button id="load" hidden>Load account / API key</button>
<pre id="out">Log in with the buyer credentials supplied by the master.</pre>
<script>
let token='';const out=document.getElementById('out');
document.getElementById('login').onsubmit=async e=>{
 e.preventDefault();const f=new FormData(e.target);
 try{
  const r=await fetch('/api/generator/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:f.get('email'),password:f.get('password')})});
  const d=await r.json();if(!r.ok)throw new Error(d.error||'Login failed');
  token=d.token;out.textContent=JSON.stringify(d.buyer,null,2);
  document.getElementById('load').hidden=false;
 }catch(err){out.textContent=err.message;}
};
document.getElementById('load').onclick=async()=>{
 try{const r=await fetch('/api/generator/me',{headers:{Authorization:'Bearer '+token}});const d=await r.json();if(!r.ok)throw new Error(d.error||'Could not load account');out.textContent=JSON.stringify(d,null,2);}
 catch(err){out.textContent=err.message;}
};
</script></body></html>`);
});

app.use((req, res) => {
  res.status(404).json({ ok: false, error: 'Route not found' });
});

async function start() {
  loadSpawnEvents();
  await initializeDatabase();

  if (!JWT_SECRET) {
    console.warn('[Security] JWT_SECRET is not set; login tokens cannot be issued.');
  }

  if (!MASTER_PASSWORD) {
    console.warn('[Security] MASTER_PASSWORD is not set; master login is disabled.');
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log('Steal An Egg backend listening on port', PORT);
  });
}

process.on('unhandledRejection', err => {
  console.error('[Unhandled rejection]', err);
});

process.on('SIGTERM', async () => {
  console.log('SIGTERM received; shutting down');
  try {
    if (pool) await pool.end();
  } catch (_) {}
  process.exit(0);
});

start().catch(err => {
  console.error('[Startup failure]', err);
  process.exit(1);
});
