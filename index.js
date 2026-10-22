
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

let pool = null;
let dbReady = false;

// Latest spawn events kept in memory.
// Events reset when the service restarts.
const spawnEvents = new Map();
const sseClients = new Map();

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

// ==================== COMMON HELPERS ====================
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

function timingSafeStringEqual(a, b) {
  const left = Buffer.from(String(a || ''), 'utf8');
  const right = Buffer.from(String(b || ''), 'utf8');

  if (left.length !== right.length || left.length === 0) {
    return false;
  }

  return crypto.timingSafeEqual(left, right);
}

function cleanText(value) {
  return String(value ?? '')
    .replace(/\r\n?/g, '\n')
    .replace(/\[([^\]]+)\]\(https?:\/\/[^)]+\)/g, '$1')
    .replace(/<https?:\/\/[^>]+>/g, '')
    .replace(/<a?:\w+:\d+>/g, '')
    .replace(/<@!?\d+>|<@&\d+>|<#\d+>/g, '')
    .replace(/\*\*/g, '')
    .replace(/__/g, '')
    .replace(/`/g, '')
    .trim();
}

function extractLabel(text, labels) {
  const escaped = labels.map(label =>
    label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  );

  const regex = new RegExp(
    '^\\s*(?:' + escaped.join('|') +
    ')\\s*[:：\\-–—]\\s*(.*?)\\s*$',
    'im'
  );

  const match = String(text || '').match(regex);
  return match ? cleanText(match[1]).replace(/\n/g, ' ').trim() : '';
}

const TIERS = [
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

function normalizeTier(value, text) {
  const supplied = String(value || '').trim();

  if (supplied) {
    const found = TIERS.find(t =>
      t.toLowerCase() === supplied.toLowerCase()
    );
    if (found) return found;
  }

  // Prefer explicit tier/rarity labels.
  const labeled = extractLabel(text, ['Tier', 'Rarity']);
  if (labeled) {
    const found = TIERS.find(t =>
      t.toLowerCase() === labeled.toLowerCase()
    );
    if (found) return found;
  }

  // Only accept a tier used in a spawn heading.
  const heading = String(text || '').match(
    /^\s*(Common|Uncommon|Rare|Epic|Legendary|Mythic|Secret|Divine|Eternal|Cosmic|Transcendent)\s+Egg\s+(?:Spawned|Spawn)\b/im
  );

  if (heading) {
    return TIERS.find(t =>
      t.toLowerCase() === heading[1].toLowerCase()
    ) || 'Unknown';
  }

  return 'Unknown';
}

function parseElapsedSeconds(value) {
  const text = String(value || '').trim().toLowerCase();

  if (!text || /unknown|n\/a|none/.test(text)) return null;

  // Example: "Spawned: 5 minutes ago"
  const ago = text.match(
    /(\d+(?:\.\d+)?)\s*(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d)\s*ago/
  );

  if (ago) {
    const n = Number(ago[1]);
    const unit = ago[2];

    const multiplier =
      /^s/.test(unit) ? 1 :
      /^m/.test(unit) ? 60 :
      /^h/.test(unit) ? 3600 : 86400;

    return Math.max(0, Math.floor(n * multiplier));
  }

  // Example: "5m ago", "2h ago", or "30s ago"
  const compact = text.match(/(\d+)\s*(s|m|h|d)\s*ago/);

  if (compact) {
    const n = Number(compact[1]);
    const multiplier = { s: 1, m: 60, h: 3600, d: 86400 }[compact[2]];
    return n * multiplier;
  }

  // An unqualified value such as "16:10" is not elapsed duration.
  return null;
}

function parseFutureSeconds(value) {
  const text = String(value || '').trim().toLowerCase();

  const match = text.match(
    /(?:in\s+)?(\d+(?:\.\d+)?)\s*(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h)\b/
  );

  if (!match || !/\bin\b/.test(text)) return null;

  const n = Number(match[1]);
  const unit = match[2];

  const multiplier =
    /^s/.test(unit) ? 1 :
    /^m/.test(unit) ? 60 : 3600;

  return Math.max(0, Math.floor(n * multiplier));
}

function normalizeSpawn(body) {
  const rawEgg = cleanText(body.eggName ?? body.egg ?? '');
  const rawLocation = cleanText(body.location ?? body.biome ?? '');
  const rawSpawned = cleanText(body.spawned ?? body.spawnTime ?? '');

  // Some older bot versions send the entire Discord message in eggName.
  const rawText = [
    typeof body.message === 'string' ? body.message : '',
    typeof body.content === 'string' ? body.content : '',
    typeof body.description === 'string' ? body.description : '',
    rawEgg
  ].filter(Boolean).join('\n');

  let eggName = rawEgg;
  let location = rawLocation;
  let spawned = rawSpawned;

  if (!location || location.toLowerCase() === 'unknown') {
    location = extractLabel(rawText, ['Location', 'Biome', 'Area']) || location;
  }

  if (!spawned || spawned.toLowerCase() === 'unknown') {
    spawned = extractLabel(rawText, [
      'Spawned',
      'Time Since Spawn',
      'Spawn Time'
    ]) || spawned;
  }

  // Extract egg from a full multiline/Markdown alert if needed.
  if (
    !eggName ||
    eggName.length > 120 ||
    /(?:location|biome|spawned|recommended speed|join game)\s*:/i.test(eggName)
  ) {
    const labeledEgg = extractLabel(rawText, [
      'Egg Name',
      'Spawned Egg',
      'Egg',
      'Pet Name'
    ]);

    if (labeledEgg && labeledEgg.length <= 120) {
      eggName = labeledEgg;
    } else {
      const lines = rawText.split('\n').map(cleanText).filter(Boolean);

      const candidate = lines.find(line => {
        if (line.length > 100) return false;
        if (/^\d{1,2}:\d{2}(?::\d{2})?$/.test(line)) return false;
        if (/^(?:Common|Uncommon|Rare|Epic|Legendary|Mythic|Secret|Divine|Eternal|Cosmic|Transcendent)\s+Egg\s+(?:Spawned|Spawn)!*$/i.test(line)) return false;
        if (/^(?:tier|rarity|location|biome|area|spawned|spawn time|time since spawn|time|money|recommended speed|join game)\s*:/i.test(line)) return false;
        if (/^https?:\/\//i.test(line)) return false;
        if (/^(?:unknown|none|n\/a)$/i.test(line)) return false;
        return true;
      });

      if (candidate) eggName = candidate;
    }
  }

  eggName = cleanText(eggName).replace(/\n/g, ' ').trim();

  // Never use a clock time or generic label as a pet name.
  if (
    !eggName ||
    eggName.length > 120 ||
    /^\d{1,2}:\d{2}(?::\d{2})?$/.test(eggName) ||
    /^(?:unknown|none|n\/a|spawned|yes|true)$/i.test(eggName)
  ) {
    return null;
  }

  const tier = normalizeTier(body.tier ?? body.rarity, rawText);

  const eventTimestamp = Date.now();
  const elapsedSeconds = parseElapsedSeconds(spawned);
  const futureSeconds = parseFutureSeconds(spawned);

  // Use a valid supplied timestamp only as event metadata.
  let messageTimestamp = eventTimestamp;
  const suppliedTime = body.timestamp ?? body.time;

  if (suppliedTime !== undefined && suppliedTime !== null) {
    const parsed = typeof suppliedTime === 'number'
      ? suppliedTime
      : Date.parse(String(suppliedTime));

    if (Number.isFinite(parsed) && parsed > 0) {
      messageTimestamp = parsed;
    }
  }

  return {
    id: String(body.messageId || crypto.randomUUID()),
    type: 'SPAWN',
    petName: eggName,
    eggName,
    egg: eggName,
    tier,
    location: location || 'Unknown',
    biome: location || 'Unknown',
    spawned: spawned || 'Unknown',
    elapsedSeconds,
    futureSeconds,
    timestamp: messageTimestamp,
    receivedAt: eventTimestamp,
    source: body.source || 'Discord',
    messageId: body.messageId ? String(body.messageId) : null,
    channelId: body.channelId ? String(body.channelId) : null
  };
}

function pruneEvents() {
  const cutoff = Date.now() - MAX_EVENT_AGE_MS;

  for (const [id, event] of spawnEvents) {
    if (event.receivedAt < cutoff) spawnEvents.delete(id);
  }

  while (spawnEvents.size > MAX_EVENTS) {
    const oldestId = spawnEvents.keys().next().value;
    spawnEvents.delete(oldestId);
  }
}

function publicScheduleEvent(event) {
  const ageSeconds = Math.max(
    0,
    Math.floor((Date.now() - event.receivedAt) / 1000)
  );

  // Existing V290 expects remainingSeconds.
  // This field is only a compatibility value; it is NOT the elapsed timer.
  const remainingSeconds = event.futureSeconds !== null
    ? Math.max(0, event.futureSeconds - ageSeconds)
    : 0;

  const elapsedSeconds = event.elapsedSeconds !== null
    ? event.elapsedSeconds + ageSeconds
    : null;

  return {
    id: event.id,
    petName: event.petName,
    eggName: event.eggName,
    egg: event.egg,
    tier: event.tier,
    location: event.location,
    biome: event.biome,
    spawned: event.spawned,
    timestamp: event.timestamp,
    receivedAt: event.receivedAt,
    source: event.source,
    messageId: event.messageId,
    channelId: event.channelId,
    remainingSeconds,
    elapsedSeconds,
    timerMode: event.elapsedSeconds !== null
      ? 'elapsed'
      : event.futureSeconds !== null
        ? 'countdown'
        : 'unknown'
  };
}

function broadcastEvent(event) {
  const payload = `data: ${JSON.stringify({
    type: 'SPAWN',
    event: publicScheduleEvent(event)
  })}\n\n`;

  for (const [id, client] of sseClients) {
    try {
      client.res.write(payload);
    } catch (_) {
      clearInterval(client.heartbeat);
      sseClients.delete(id);
    }
  }
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

// ==================== MASTER ADMIN ====================
app.post('/api/master/add-user', requireDatabase, async (req, res) => {
  if (!MASTER_PASSWORD) {
    return res.status(503).json({
      error: 'MASTER_PASSWORD is not configured on the server.'
    });
  }

  const suppliedPassword = req.get('masterpassword') || '';

  if (!timingSafeStringEqual(suppliedPassword, MASTER_PASSWORD)) {
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

// ==================== BUYER LOGIN ====================
app.post('/api/buyer/login', requireDatabase, async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
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

    if (JWT_SECRET.length < 32) {
      return res.status(503).json({
        error: 'Server authentication is not configured securely.'
      });
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

// ==================== GENERATE API KEY ====================
app.post('/api/buyer/generate-key', requireDatabase, async (req, res) => {
  const authorization = req.headers.authorization || '';
  const token = authorization.startsWith('Bearer ')
    ? authorization.slice(7)
    : '';

  if (!token) {
    return res.status(401).json({ error: 'Login required.' });
  }

  try {
    if (JWT_SECRET.length < 32) {
      return res.status(503).json({
        error: 'Server authentication is not configured securely.'
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    const newApiKey =
      'EGG-' + crypto.randomBytes(24).toString('hex').toUpperCase();

    const [result] = await pool.query(
      'UPDATE users SET api_key = ? WHERE email = ? AND is_active = TRUE',
      [newApiKey, decoded.email]
    );

    if (!result.affectedRows) {
      return res.status(401).json({ error: 'Account is missing or blocked.' });
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

// ==================== SPAWN WEBHOOK ====================
app.post('/api/bot-webhook', (req, res) => {
  if (WEBHOOK_SECRET) {
    const supplied = req.get('x-webhook-secret') || '';

    if (!timingSafeStringEqual(supplied, WEBHOOK_SECRET)) {
      return res.status(401).json({ error: 'Invalid webhook secret.' });
    }
  } else {
    console.warn(
      '[SECURITY WARNING] WEBHOOK_SECRET is not configured; webhook is unauthenticated.'
    );
  }

  const body = req.body || {};

  if (!body.eggName && !body.egg && !body.message && !body.content &&
      !body.description) {
    return res.status(400).json({
      error: 'Missing spawn data. Provide eggName/egg or message content.'
    });
  }

  try {
    const event = normalizeSpawn(body);

    if (!event) {
      return res.status(400).json({
        error: 'Could not extract a valid egg/pet name from the spawn alert.'
      });
    }

    // De-duplicate repeated delivery of the same Discord message.
    const id = event.messageId || event.id;
    if (spawnEvents.has(id)) {
      return res.json({
        success: true,
        duplicate: true,
        connectedClients: sseClients.size
      });
    }

    spawnEvents.set(id, event);
    pruneEvents();
    broadcastEvent(event);

    console.log('[SPAWN RECEIVED]', JSON.stringify({
      tier: event.tier,
      eggName: event.eggName,
      location: event.location,
      spawned: event.spawned,
      messageId: event.messageId,
      connectedClients: sseClients.size
    }));

    return res.json({
      success: true,
      connectedClients: sseClients.size,
      parsed: {
        petName: event.petName,
        tier: event.tier,
        location: event.location,
        spawned: event.spawned,
        timerMode: event.elapsedSeconds !== null
          ? 'elapsed'
          : event.futureSeconds !== null
            ? 'countdown'
            : 'unknown'
      }
    });
  } catch (error) {
    console.error('Webhook processing failed:', error.message);
    return res.status(500).json({ error: 'Could not process spawn event.' });
  }
});

// ==================== SCHEDULE API FOR V290 ====================
// Public schedule data contains game spawn alerts only, never API keys.
app.get('/api/schedule', (req, res) => {
  pruneEvents();

  const schedules = [...spawnEvents.values()]
    .sort((a, b) => b.receivedAt - a.receivedAt)
    .map(publicScheduleEvent);

  const latest = schedules[0] || null;

  return res.json({
    success: true,
    discordConnected: true,
    lastMessage: latest
      ? `${latest.petName} · ${latest.tier} · ${latest.location}`
      : null,
    schedules
  });
});

// ==================== AUTHENTICATED SSE STREAM ====================
app.get('/events', requireDatabase, async (req, res) => {
  const apiKey = String(req.query.apiKey || '');

  if (!apiKey) return res.status(401).send('API Key required');

  try {
    const [rows] = await pool.query(
      'SELECT email FROM users WHERE api_key = ? AND is_active = TRUE LIMIT 1',
      [apiKey]
    );

    if (!rows.length) return res.status(401).send('Invalid API Key');

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

    // Send recent events when a client first connects.
    for (const event of [...spawnEvents.values()].slice(-50)) {
      res.write(`data: ${JSON.stringify({
        type: 'SPAWN',
        event: publicScheduleEvent(event)
      })}\n\n`);
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

// ==================== HEALTH ====================
app.get('/health', (req, res) => {
  pruneEvents();

  res.json({
    status: 'ok',
    message: 'Backend is running',
    databaseReady: dbReady,
    connectedClients: sseClients.size,
    activeSchedules: spawnEvents.size,
    webhookSecretConfigured: Boolean(WEBHOOK_SECRET)
  });
});

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

// ==================== MASTER ADMIN PAGE ====================
app.get('/master', (req, res) => {
  res.send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Master Admin - Add User</title>
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
const response=await fetch('/api/master/add-user',{method:'POST',headers:{
'Content-Type':'application/json',
'masterpassword':document.getElementById('masterpass').value
},body:JSON.stringify({
email:document.getElementById('email').value,
password:document.getElementById('password').value
})});
const data=await response.json();
msg.textContent=response.ok?'User added successfully.':(data.error||'Could not add user.');
}catch(_){msg.textContent='Network error. Please try again.';}
});
</script></body></html>`);
});

// ==================== BUYER LOGIN / KEY GENERATOR ====================
app.get('/generator', (req, res) => {
  res.send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
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
const response=await fetch('/api/buyer/login',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({email:document.getElementById('email').value,password:document.getElementById('password').value})});
const data=await response.json();
if(!response.ok||!data.success){msg.textContent=data.error||'Login failed.';return;}
userToken=data.token;document.getElementById('loginForm').style.display='none';
document.getElementById('genBox').style.display='block';msg.textContent='Login successful.';
}catch(_){msg.textContent='Network error. Please try again.';}
});
document.getElementById('generateButton').addEventListener('click',async()=>{
const msg=document.getElementById('msg');msg.textContent='Generating key...';
try{
const response=await fetch('/api/buyer/generate-key',{method:'POST',
headers:{'Authorization':'Bearer '+userToken}});
const data=await response.json();
if(!response.ok||!data.success){msg.textContent=data.error||'Could not generate key.';return;}
const box=document.getElementById('keyBox');box.style.display='block';box.textContent=data.apiKey;
msg.textContent='Keep this API key private.';
}catch(_){msg.textContent='Network error. Please try again.';}
});
</script></body></html>`);
});

// ==================== START SERVER ====================
async function startServer() {
  try {
    if (JWT_SECRET.length < 32) {
      console.warn('[SECURITY WARNING] JWT_SECRET should contain at least 32 characters.');
    }

    if (!WEBHOOK_SECRET) {
      console.warn('[SECURITY WARNING] Configure WEBHOOK_SECRET before production use.');
    }

    await initDB();

    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Backend listening on port ${PORT}`);
      console.log('Health: /health');
      console.log('Database health: /health/database');
      console.log('Schedule API: /api/schedule');
      console.log('SSE endpoint: /events');
      console.log('Webhook endpoint: /api/bot-webhook');
    });
  } catch (error) {
    console.error('Startup failed:', error.message);
    process.exit(1);
  }
}

startServer();
