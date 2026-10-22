```js
'use strict';

const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();

// ==================== CONFIG ====================
const PORT = Number(process.env.PORT) || 3000;
const DB_URL = process.env.TIDB_DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || '';
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || '';
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';

const MAX_EVENTS = 500;
const MAX_EVENT_AGE_MS = 24 * 60 * 60 * 1000;

let pool;
let dbReady = false;

const sseClients = new Map();
const spawnEvents = new Map();

// ==================== MIDDLEWARE ====================
app.use(cors({
  origin: ALLOWED_ORIGIN === '*'
    ? '*'
    : ALLOWED_ORIGIN.split(',').map(s => s.trim()).filter(Boolean)
}));

app.use(express.json({ limit: '100kb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-store');
  next();
});

// ==================== HELPERS ====================
function requireDatabase(req, res, next) {
  if (!dbReady || !pool) {
    return res.status(503).json({
      error: 'Database is not ready. Please try again shortly.'
    });
  }
  next();
}

function safeError(error) {
  console.error(error);
  return 'An internal server error occurred.';
}

function clean(value) {
  return String(value ?? '')
    .replace(/\r\n?/g, '\n')
    .replace(/\u200B/g, '')
    .trim();
}

function normalizeName(value) {
  return clean(value)
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/__([^_]+)__/g, '$1')
    .replace(/~~([^~]+)~~/g, '$1')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/^[*_~\s]+|[*_~\s]+$/g, '')
    .trim();
}

function parseLabel(text, labels) {
  const escaped = labels.map(label =>
    label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  );

  const regex = new RegExp(
    `(?:^|\\n)\\s*(?:${escaped.join('|')})\\s*[:：\\-–—]\\s*([^\\n]+)`,
    'im'
  );

  const match = String(text || '').match(regex);
  return match ? normalizeName(match[1]) : '';
}

const KNOWN_TIERS = [
  'Common',
  'Uncommon',
  'Rare',
  'Epic',
  'Legendary',
  'Mythic',
  'Secret',
  'Divine',
  'Eternal',
  'Cosmic',
  'Transcendent'
];

function canonicalTier(value) {
  const found = KNOWN_TIERS.find(
    tier => tier.toLowerCase() === String(value || '').toLowerCase()
  );
  return found || 'Unknown';
}

function parseTier(text, suppliedTier) {
  const explicit = canonicalTier(suppliedTier);
  if (explicit !== 'Unknown') return explicit;

  const labeled = parseLabel(text, ['Tier', 'Rarity', 'Egg Tier']);
  if (labeled) {
    const match = labeled.match(
      /\b(Common|Uncommon|Rare|Epic|Legendary|Mythic|Secret|Divine|Eternal|Cosmic|Transcendent)\b/i
    );
    if (match) return canonicalTier(match[1]);
  }

  const alert = String(text || '').match(
    /\b(Common|Uncommon|Rare|Epic|Legendary|Mythic|Secret|Divine|Eternal|Cosmic|Transcendent)\s+Egg\s+(?:Spawned|Spawn)\b/i
  );

  return alert ? canonicalTier(alert[1]) : 'Unknown';
}

function parseSpawnedSeconds(value) {
  if (Number.isFinite(Number(value)) && value !== null && value !== '') {
    return Math.max(0, Math.floor(Number(value)));
  }

  const text = String(value || '').toLowerCase();
  let total = 0;
  let found = false;

  const units = [
    [/(\d+(?:\.\d+)?)\s*(?:d|days?)\b/g, 86400],
    [/(\d+(?:\.\d+)?)\s*(?:h|hrs?|hours?)\b/g, 3600],
    [/(\d+(?:\.\d+)?)\s*(?:m|mins?|minutes?)\b/g, 60],
    [/(\d+(?:\.\d+)?)\s*(?:s|secs?|seconds?)\b/g, 1]
  ];

  for (const [regex, factor] of units) {
    for (const match of text.matchAll(regex)) {
      total += Number(match[1]) * factor;
      found = true;
    }
  }

  return found ? Math.max(0, Math.floor(total)) : null;
}

function parseTimestamp(body) {
  const value = body.time ?? body.timestamp ?? body.createdAt;

  if (typeof value === 'number' && Number.isFinite(value)) {
    // Accept Unix seconds or milliseconds.
    return value < 100000000000 ? value * 1000 : value;
  }

  if (typeof value === 'string') {
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed)) return parsed;
  }

  // Discord message timestamp is the fallback.
  return Date.now();
}

function parseSpawn(body) {
  const rawText = [
    body.content,
    body.message,
    body.description,
    body.eggName,
    body.egg,
    body.location,
    body.biome,
    body.tier,
    body.rarity,
    body.spawned
  ].filter(Boolean).join('\n');

  const eggCandidate = normalizeName(
    body.eggName || body.egg ||
    parseLabel(rawText, [
      'Egg Name', 'Egg', 'Spawned Egg', 'Pet Name', 'Pet', 'Name'
    ])
  );

  const eggName = eggCandidate
    .replace(/^[\s:*_~]+|[\s*_~]+$/g, '')
    .trim();

  const tier = parseTier(rawText, body.tier || body.rarity);

  const location = normalizeName(
    body.location || body.biome ||
    parseLabel(rawText, ['Location', 'Biome', 'Area', 'Spawn Location'])
  ) || 'Unknown';

  const spawned = normalizeName(
    body.spawned ||
    parseLabel(rawText, [
      'Spawned Ago', 'Spawned', 'Spawn Time', 'Time Since Spawn', 'Elapsed'
    ])
  ) || 'Unknown';

  const elapsedSeconds = parseSpawnedSeconds(
    body.elapsedSeconds ?? body.spawnedSeconds ?? spawned
  );

  if (!eggName || /^(unknown|none|n\/a)$/i.test(eggName)) {
    return null;
  }

  const timestampMs = parseTimestamp(body);

  return {
    type: 'SPAWN',
    tier,
    eggName,
    egg: eggName,
    location,
    biome: location,
    spawned,
    elapsedSeconds,
    time: timestampMs,
    timestamp: new Date(timestampMs).toISOString(),
    source: body.source || 'Discord',
    messageId: body.messageId || null,
    channelId: body.channelId || null
  };
}

function pruneEvents() {
  const cutoff = Date.now() - MAX_EVENT_AGE_MS;

  for (const [id, event] of spawnEvents) {
    if (event.time < cutoff) spawnEvents.delete(id);
  }

  while (spawnEvents.size > MAX_EVENTS) {
    const firstKey = spawnEvents.keys().next().value;
    spawnEvents.delete(firstKey);
  }
}

function scheduleRecord(event) {
  const elapsedSinceReceipt = Math.max(
    0,
    Math.floor((Date.now() - event.receivedAt) / 1000)
  );

  const elapsedSeconds = event.elapsedSeconds === null
    ? null
    : event.elapsedSeconds + elapsedSinceReceipt;

  return {
    petName: event.eggName,
    eggName: event.eggName,
    tier: event.tier,
    location: event.location,
    biome: event.biome,
    spawned: event.spawned,
    timestamp: event.timestamp,
    time: event.time,
    elapsedSeconds,

    // Existing V290 tracker requires remainingSeconds >= 0.
    // A past spawn is represented as zero, never as a fake future timer.
    remainingSeconds: 0,

    source: event.source,
    messageId: event.messageId,
    channelId: event.channelId
  };
}

function sendSSE(event) {
  const payload = `data: ${JSON.stringify(event)}\n\n`;
  let delivered = 0;

  for (const [id, client] of sseClients) {
    try {
      if (client.res.destroyed || client.res.writableEnded) {
        clearInterval(client.heartbeat);
        sseClients.delete(id);
        continue;
      }

      client.res.write(payload);
      delivered++;
    } catch (_) {
      clearInterval(client.heartbeat);
      sseClients.delete(id);
    }
  }

  return delivered;
}

// ==================== DATABASE SETUP ====================
async function initDB() {
  if (!DB_URL) {
    throw new Error('TIDB_DATABASE_URL environment variable is missing.');
  }

  pool = mysql.createPool({
    uri: DB_URL,
    waitForConnections: true,
    connectionLimit: 10,
    enableKeepAlive: true,
    connectTimeout: 10000
  });

  await pool.query('SELECT 1');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      api_key VARCHAR(255) UNIQUE,
      is_active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  dbReady = true;
  console.log('Database connected and users table is ready.');
}

// ==================== 1. MASTER ADMIN ====================
app.post('/api/master/add-user', requireDatabase, async (req, res) => {
  if (!MASTER_PASSWORD) {
    return res.status(503).json({
      error: 'MASTER_PASSWORD is not configured on the server.'
    });
  }

  const supplied = Buffer.from(String(req.get('masterpassword') || ''));
  const expected = Buffer.from(MASTER_PASSWORD);

  if (
    supplied.length !== expected.length ||
    !crypto.timingSafeEqual(supplied, expected)
  ) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Enter a valid email address.' });
  }

  if (password.length < 8 || password.length > 200) {
    return res.status(400).json({
      error: 'Password must be 8–200 characters long.'
    });
  }

  try {
    const hash = await bcrypt.hash(password, 10);

    await pool.query(
      'INSERT INTO users (email, password_hash) VALUES (?, ?)',
      [email, hash]
    );

    return res.json({ success: true, message: 'User added successfully' });
  } catch (error) {
    console.error('Add user failed:', error.message);

    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Email already exists.' });
    }

    return res.status(500).json({ error: safeError(error) });
  }
});

// ==================== 2. BUYER LOGIN ====================
app.post('/api/buyer/login', requireDatabase, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (!email || !password) {
    return res.status(400).json({
      error: 'Email and password are required.'
    });
  }

  if (JWT_SECRET.length < 32) {
    return res.status(503).json({
      error: 'Server authentication is not configured securely.'
    });
  }

  try {
    const [rows] = await pool.query(
      'SELECT email, password_hash FROM users WHERE email = ? AND is_active = TRUE',
      [email]
    );

    if (!rows.length) {
      return res.status(401).json({ error: 'Invalid or blocked account' });
    }

    const matches = await bcrypt.compare(password, rows[0].password_hash);

    if (!matches) {
      return res.status(401).json({ error: 'Wrong password' });
    }

    const token = jwt.sign(
      { email: rows[0].email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    return res.json({ success: true, token });
  } catch (error) {
    console.error('Buyer login failed:', error.message);
    return res.status(500).json({ error: safeError(error) });
  }
});

// ==================== 3. GENERATE API KEY ====================
app.post('/api/buyer/generate-key', requireDatabase, async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Login required.' });
  }

  if (JWT_SECRET.length < 32) {
    return res.status(503).json({
      error: 'Server authentication is not configured securely.'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const newApiKey =
      'EGG-' + crypto.randomBytes(24).toString('hex').toUpperCase();

    const [result] = await pool.query(
      'UPDATE users SET api_key = ? WHERE email = ? AND is_active = TRUE',
      [newApiKey, decoded.email]
    );

    if (!result.affectedRows) {
      return res.status(401).json({
        error: 'Account is missing or blocked.'
      });
    }

    return res.json({ success: true, apiKey: newApiKey });
  } catch (error) {
    if (
      error.name === 'JsonWebTokenError' ||
      error.name === 'TokenExpiredError'
    ) {
      return res.status(401).json({ error: 'Invalid or expired token.' });
    }

    console.error('API key generation failed:', error.message);
    return res.status(500).json({ error: safeError(error) });
  }
});

// ==================== API KEY AUTH HELPER ====================
async function findActiveApiKey(apiKey) {
  if (!apiKey || !pool || !dbReady) return false;

  const [rows] = await pool.query(
    'SELECT email FROM users WHERE api_key = ? AND is_active = TRUE LIMIT 1',
    [apiKey]
  );

  return rows.length > 0;
}

// ==================== 4. V290 SCHEDULE API ====================
app.get('/api/schedule', requireDatabase, async (req, res) => {
  try {
    const apiKey = String(
      req.query.apiKey || req.get('x-api-key') || ''
    );

    // API key is required for this endpoint.
    if (!apiKey || !(await findActiveApiKey(apiKey))) {
      return res.status(401).json({ error: 'Missing or invalid API key.' });
    }

    pruneEvents();

    const schedules = [...spawnEvents.values()]
      .sort((a, b) => b.time - a.time)
      .map(scheduleRecord);

    const latest = schedules[0] || null;

    return res.json({
      success: true,
      discordConnected: true,
      lastMessage: latest ? {
        eggName: latest.eggName,
        tier: latest.tier,
        location: latest.location,
        spawned: latest.spawned,
        timestamp: latest.timestamp
      } : null,
      schedules
    });
  } catch (error) {
    console.error('Schedule API failed:', error.message);
    return res.status(500).json({ error: 'Could not load schedules.' });
  }
});

// ==================== 5. SSE STREAM FOR OBS ====================
app.get('/events', requireDatabase, async (req, res) => {
  const apiKey = String(req.query.apiKey || '');

  if (!apiKey) {
    return res.status(401).send('API Key required');
  }

  try {
    if (!(await findActiveApiKey(apiKey))) {
      return res.status(401).send('Invalid API Key');
    }

    res.status(200);
    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();

    res.write(': connected\n\n');

    const clientId = crypto.randomUUID();

    const heartbeat = setInterval(() => {
      if (!res.destroyed && !res.writableEnded) {
        res.write(': ping\n\n');
      }
    }, 15000);

    sseClients.set(clientId, { res, heartbeat });

    // Send recent events to a newly connected client.
    for (const event of spawnEvents.values()) {
      res.write(`data: ${JSON.stringify(event)}\n\n`);
    }

    req.on('close', () => {
      const client = sseClients.get(clientId);
      if (client) clearInterval(client.heartbeat);
      sseClients.delete(clientId);
    });
  } catch (error) {
    console.error('SSE authentication failed:', error.message);

    if (!res.headersSent) {
      return res.status(500).send('Could not authenticate event stream');
    }

    res.end();
  }
});

// ==================== 6. WISPB YTE BOT WEBHOOK ====================
app.post('/api/bot-webhook', (req, res) => {
  if (WEBHOOK_SECRET) {
    const supplied = Buffer.from(req.get('x-webhook-secret') || '');
    const expected = Buffer.from(WEBHOOK_SECRET);

    if (
      supplied.length !== expected.length ||
      !crypto.timingSafeEqual(supplied, expected)
    ) {
      return res.status(401).json({ error: 'Invalid webhook secret.' });
    }
  } else {
    console.warn(
      '[SECURITY WARNING] WEBHOOK_SECRET is not configured; webhook is unauthenticated.'
    );
  }

  try {
    const event = parseSpawn(req.body || {});

    if (!event) {
      return res.status(400).json({
        error: 'Could not parse egg name from spawn payload.'
      });
    }

    // Prevent duplicate Discord message deliveries.
    const id = event.messageId
      ? `${event.channelId || ''}:${event.messageId}`
      : crypto.randomUUID();

    if (!spawnEvents.has(id)) {
      event.receivedAt = Date.now();
      spawnEvents.set(id, event);
    }

    pruneEvents();

    const delivered = sendSSE(event);

    console.log('[SPAWN WEBHOOK]', JSON.stringify({
      eggName: event.eggName,
      tier: event.tier,
      location: event.location,
      spawned: event.spawned,
      messageId: event.messageId,
      delivered
    }));

    return res.json({
      success: true,
      event: {
        eggName: event.eggName,
        tier: event.tier,
        location: event.location,
        spawned: event.spawned,
        timestamp: event.timestamp
      },
      connectedClients: delivered
    });
  } catch (error) {
    console.error('Webhook processing failed:', error.message);
    return res.status(500).json({ error: 'Could not process spawn event.' });
  }
});

// ==================== 7. HEALTH ====================
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Backend is running',
    databaseReady: dbReady,
    connectedClients: sseClients.size,
    activeSchedules: spawnEvents.size,
    webhookSecretConfigured: Boolean(WEBHOOK_SECRET)
  });
});

// ==================== 8. DATABASE HEALTH ====================
app.get('/health/database', async (req, res) => {
  const started = Date.now();

  if (!pool || !dbReady) {
    return res.status(503).json({
      status: 'error',
      databaseConnected: false
    });
  }

  try {
    await pool.query('SELECT 1');

    return res.json({
      status: 'ok',
      databaseConnected: true,
      latencyMs: Date.now() - started
    });
  } catch (error) {
    console.error('Database health check failed:', error.message);

    return res.status(503).json({
      status: 'error',
      databaseConnected: false
    });
  }
});

// ==================== 9. MASTER ADMIN PAGE ====================
app.get('/master', (req, res) => {
  res.send(`<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Master Admin</title>
<style>
body{font-family:sans-serif;background:#111;color:#fff;padding:30px;text-align:center}
input,button{padding:10px;margin:5px;border-radius:5px;border:none}
input{width:min(250px,80%)}button{background:#0f0;color:#000;font-weight:bold;cursor:pointer}
</style></head><body>
<h2>Master Admin: Add New Buyer</h2>
<form id="addForm">
<input type="password" id="masterpass" placeholder="Master Password" required><br>
<input type="email" id="email" placeholder="Buyer Email" required><br>
<input type="password" id="password" placeholder="Buyer Password" minlength="8" required><br>
<button type="submit">Add User</button>
</form><p id="msg" role="status"></p>
<script>
document.getElementById('addForm').addEventListener('submit',async e=>{
 e.preventDefault();
 const msg=document.getElementById('msg');msg.textContent='Please wait...';
 try{
  const r=await fetch('/api/master/add-user',{method:'POST',
   headers:{'Content-Type':'application/json','masterpassword':document.getElementById('masterpass').value},
   body:JSON.stringify({email:document.getElementById('email').value,password:document.getElementById('password').value})});
  const d=await r.json();msg.textContent=r.ok?'User added successfully.':(d.error||'Could not add user.');
 }catch(_){msg.textContent='Network error. Please try again.';}
});
</script></body></html>`);
});

// ==================== 10. BUYER KEY GENERATOR ====================
app.get('/generator', (req, res) => {
  res.send(`<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Buyer Login - API Key Generator</title>
<style>
body{font-family:sans-serif;background:#111;color:#fff;padding:30px;text-align:center}
input,button{padding:10px;margin:5px;border-radius:5px;border:none}
input{width:min(250px,80%)}button{background:#00e5ff;color:#000;font-weight:bold;cursor:pointer}
.key-box{background:#222;padding:15px;border:1px solid #0f0;font-size:18px;margin-top:15px;word-break:break-all;display:none}
</style></head><body>
<h2>Buyer Login &amp; Generate Key</h2>
<form id="loginForm">
<input type="email" id="email" placeholder="Email" required><br>
<input type="password" id="password" placeholder="Password" required><br>
<button type="submit">Login</button>
</form>
<div id="genBox" style="display:none">
<button id="generateButton" type="button">Generate API Key</button>
<div id="keyBox" class="key-box"></div>
</div>
<p id="msg" role="status"></p>
<script>
let userToken='';
document.getElementById('loginForm').addEventListener('submit',async e=>{
 e.preventDefault();const msg=document.getElementById('msg');msg.textContent='Logging in...';
 try{
  const r=await fetch('/api/buyer/login',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({email:document.getElementById('email').value,password:document.getElementById('password').value})});
  const d=await r.json();
  if(!r.ok||!d.success){msg.textContent=d.error||'Login failed.';return;}
  userToken=d.token;document.getElementById('loginForm').style.display='none';
  document.getElementById('genBox').style.display='block';msg.textContent='Login successful.';
 }catch(_){msg.textContent='Network error. Please try again.';}
});
document.getElementById('generateButton').addEventListener('click',async()=>{
 const msg=document.getElementById('msg');msg.textContent='Generating key...';
 try{
  const r=await fetch('/api/buyer/generate-key',{method:'POST',
   headers:{'Authorization':'Bearer '+userToken}});
  const d=await r.json();
  if(!r.ok||!d.success){msg.textContent=d.error||'Could not generate key.';return;}
  const box=document.getElementById('keyBox');box.style.display='block';box.textContent=d.apiKey;
  msg.textContent='Keep this API key private.';
 }catch(_){msg.textContent='Network error. Please try again.';}
});
</script></body></html>`);
});

// ==================== START SERVER ====================
async function startServer() {
  try {
    await initDB();

    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Backend listening on port ${PORT}`);
      console.log('Health: /health');
      console.log('Database health: /health/database');
      console.log('Schedule API: /api/schedule?apiKey=YOUR_KEY');
      console.log('SSE endpoint: /events?apiKey=YOUR_KEY');
    });
  } catch (error) {
    console.error('Startup failed:', error.message);
    process.exit(1);
  }
}

startServer();
```
