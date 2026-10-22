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

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''), 'utf8');
  const bb = Buffer.from(String(b || ''), 'utf8');
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
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
    'SECRET', 'DIVINE', 'ETERNAL', 'COSMIC', 'MYTHIC',
    'LEGENDARY', 'EPIC', 'RARE', 'UNCOMMON', 'COMMON'
  ];
  const source = (text(explicit) + ' ' + cleanText(raw)).toUpperCase();

  for (const tier of known) {
    if (new RegExp('\\b' + tier + '\\b').test(source)) {
      return tier[0] + tier.slice(1).toLowerCase();
    }
  }
  return text(explicit) || 'Unknown';
}

function parseSpawn(body) {
  const embedFields = Array.isArray(body.embeds)
    ? body.embeds.flatMap(e => [
        text(e.title),
        text(e.description),
        ...(Array.isArray(e.fields)
          ? e.fields.flatMap(f => [text(f.name), text(f.value)])
          : [])
      ])
    : [];

  const rawParts = [
    text(body.message),
    text(body.content),
    text(body.description),
    text(body.eggName),
    text(body.egg),
    text(body.title),
    text(body.rawText),
    text(body.embedText),
    text(body.messageContent),
    ...embedFields
  ].filter(Boolean);

  const raw = cleanText(rawParts.join('\n'));
  const providedEgg = cleanText(
    body.eggName || body.egg || body.petName || ''
  );

  let eggName = labelValue(raw, [
    'Egg Name', 'Egg', 'Pet Name', 'Pet', 'Spawn'
  ]);

  if (!eggName && providedEgg) eggName = providedEgg;

  if (!eggName && raw) {
    eggName = raw
      .replace(/^.*?\b(?:egg|pet)\s+(?:has\s+)?spawned\b\s*[:!—-]*/i, '')
      .replace(/^\s*(?:secret|divine|eternal|cosmic|mythic|legendary|epic|rare|uncommon|common)\s+(?:egg\s+)?spawn(?:ed)?\s*[:!—-]*/i, '')
      .split(/\b(?:Location|Biome|Spawned|Time|Money|Tier|Rarity)\s*[:：-]/i)[0]
      .replace(/^\s*Egg\s*[:：-]\s*/i, '')
      .replace(/[|•]+\s*$/g, '')
      .trim();
  }

  const location = cleanText(
    body.location ||
    body.biome ||
    body.area ||
    labelValue(raw, [
      'Location', 'Biome', 'Map', 'Area', 'Spawn Location'
    ]) ||
    ''
  );

  const spawned = cleanText(
    body.spawned ||
    body.spawnedAgo ||
    body.spawnedLabel ||
    body.spawnTime ||
    body.spawn_time_text ||
    labelValue(raw, [
      'Spawned At', 'Spawned', 'Spawned Ago',
      'Time Since Spawn', 'Spawn Time', 'Time'
    ]) ||
    ''
  );

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

  return {
    eggName: eggName || 'Unknown',
    petName: eggName || 'Unknown',
    egg: eggName || 'Unknown',
    tier,
    location: location || 'Unknown',
    biome: location || 'Unknown',
    spawned: spawned || 'Unknown',
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

  const packet = `data: ${JSON.stringify({
    ...event,
    type: 'SPAWN',
    id: event.messageId || crypto.randomUUID(),
    elapsedSeconds: Math.max(
      0,
      Math.floor((Date.now() - new Date(event.timestamp).getTime()) / 1000)
    )
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

// V290-compatible schedule API. These are past spawn events,
// not invented future countdowns.
app.get('/api/schedule', (_req, res) => {
  res.set('Cache-Control', 'no-store');

  res.json({
    success: true,
    schedules: recentEvents.map(e => ({
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
      elapsedSeconds: Math.max(
        0,
        Math.floor((Date.now() - new Date(e.timestamp).getTime()) / 1000)
      ) || 0,
      eventType: 'spawn',
      messageId: e.messageId
    })),
    lastMessage,
    webhookReceived: Boolean(lastWebhookAt),
    lastWebhookAt,
    discordConnected: Boolean(lastWebhookAt),
    activeSchedules: recentEvents.length
  });
});

app.post('/api/bot-webhook', (req, res) => {
  if (
    WEBHOOK_SECRET &&
    !safeEqual(req.get('x-webhook-secret'), WEBHOOK_SECRET)
  ) {
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
    res.write(`data: ${JSON.stringify({
      ...lastMessage,
      type: 'SPAWN',
      id: lastMessage.messageId || lastMessage.timestamp,
      elapsedSeconds: Math.max(
        0,
        Math.floor(
          (Date.now() - new Date(lastMessage.timestamp).getTime()) / 1000
        )
      )
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

  return res.json({
    success: true,
    token,
    expiresIn: 43200
  });
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

app.post('/api/buyer/login', async (req, res) => {
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

    if (
      !rows.length ||
      !(await bcrypt.compare(password, rows[0].password_hash))
    ) {
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
    const apiKey = 'sae_' + crypto.randomBytes(32).toString('hex');
    await dbPool.execute(
      'UPDATE users SET api_key = ? WHERE id = ?',
      [apiKey, payload.userId]
    );
    return res.json({ success: true, apiKey });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: err.message || 'Could not generate API key'
    });
  }
});

app.get('/master', (_req, res) => res.type('html').send(
  `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Master Login</title></head><body style="font:16px system-ui;max-width:480px;margin:50px auto;padding:20px"><h1>Master Login</h1><form id="f"><input id="p" type="password" placeholder="Master password" required style="width:100%;padding:12px;box-sizing:border-box"><button style="margin-top:12px;padding:10px 16px">Login</button></form><pre id="o"></pre><script>document.getElementById('f').onsubmit=async e=>{e.preventDefault();const r=await fetch('/api/master/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('p').value})});const d=await r.json();document.getElementById('o').textContent=JSON.stringify(d,null,2);if(d.token)sessionStorage.setItem('masterToken',d.token)};</script></body></html>`
));

app.get('/generator', (_req, res) => res.type('html').send(
  `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Buyer API Key</title></head><body style="font:16px system-ui;max-width:480px;margin:40px auto;padding:20px"><h1>Buyer Login / API Key</h1><form id="login"><input id="u" placeholder="Username" required style="width:100%;padding:10px;box-sizing:border-box;margin:5px 0"><input id="p" type="password" placeholder="Password" required style="width:100%;padding:10px;box-sizing:border-box;margin:5px 0"><button>Login</button></form><button id="key" style="margin-top:12px">Generate API key</button><pre id="o" style="white-space:pre-wrap;overflow-wrap:anywhere"></pre><script>let token='';const out=document.getElementById('o');document.getElementById('login').onsubmit=async e=>{e.preventDefault();const r=await fetch('/api/buyer/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});const d=await r.json();token=d.token||'';out.textContent=JSON.stringify(d,null,2)};document.getElementById('key').onclick=async()=>{if(!token){out.textContent='Please log in first.';return}const r=await fetch('/api/buyer/generate-key',{method:'POST',headers:{Authorization:'Bearer '+token}});out.textContent=JSON.stringify(await r.json(),null,2)};</script></body></html>`
));

app.use((err, _req, res, _next) => {
  console.error('[request error]', err.message || err);
  if (res.headersSent) return;
  res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
});

(async () => {
  await initDB();
  app.listen(PORT, '0.0.0.0', () => {
    console.log(
      `Steal An Egg backend listening on port ${PORT}; database: ${dbStatus.message}`
    );
  });
})();
