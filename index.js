
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
const JWT_SECRET = process.env.JWT_SECRET;
const MASTER_PASSWORD = process.env.MASTER_PASSWORD;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';

let pool;
let dbReady = false;
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

function sendSpawnEvent(body) {
  const eggName = body.eggName ?? body.egg ?? 'Unknown';
  const tier = body.tier ?? body.rarity ?? 'Unknown';
  const location = body.location ?? body.biome ?? null;
  const rawTime = body.time ?? body.timestamp ?? body.spawned ?? Date.now();

  let time = rawTime;
  if (typeof rawTime === 'string' && !Number.isNaN(Date.parse(rawTime))) {
    time = Date.parse(rawTime);
  }

  const event = {
    type: 'SPAWN',
    tier,
    eggName,
    egg: eggName,
    location,
    biome: location,
    spawned: body.spawned ?? null,
    time,
    source: body.source ?? null,
    messageId: body.messageId ?? null,
    channelId: body.channelId ?? null
  };

  const payload = `data: ${JSON.stringify(event)}\n\n`;
  let delivered = 0;

  for (const [id, client] of sseClients) {
    try {
      client.res.write(payload);
      delivered++;
    } catch (error) {
      clearInterval(client.heartbeat);
      sseClients.delete(id);
    }
  }

  return { event, delivered };
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

  // Verify the database connection first.
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

  const suppliedPassword = req.get('masterpassword');

  if (!suppliedPassword ||
      !crypto.timingSafeEqual(
        Buffer.from(String(suppliedPassword)),
        Buffer.from(String(MASTER_PASSWORD))
      )) {
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

    return res.json({
      success: true,
      message: 'User added successfully'
    });
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
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    const [rows] = await pool.query(
      'SELECT email, password_hash FROM users WHERE email = ? AND is_active = TRUE',
      [email]
    );

    if (!rows.length) {
      return res.status(401).json({
        error: 'Invalid or blocked account'
      });
    }

    const user = rows[0];
    const matches = await bcrypt.compare(password, user.password_hash);

    if (!matches) {
      return res.status(401).json({ error: 'Wrong password' });
    }

    if (!JWT_SECRET || JWT_SECRET.length < 32) {
      console.error('JWT_SECRET must be configured with at least 32 characters.');
      return res.status(503).json({
        error: 'Server authentication is not configured securely.'
      });
    }

    const token = jwt.sign(
      { email: user.email },
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

  try {
    if (!JWT_SECRET || JWT_SECRET.length < 32) {
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
    if (error.name === 'JsonWebTokenError' ||
        error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Invalid or expired token.' });
    }

    console.error('API key generation failed:', error.message);
    return res.status(500).json({ error: safeError(error) });
  }
});

// ==================== 4. SSE STREAM FOR OBS ====================
app.get('/events', requireDatabase, async (req, res) => {
  const apiKey = String(req.query.apiKey || '');

  if (!apiKey) {
    return res.status(401).send('API Key required');
  }

  try {
    const [rows] = await pool.query(
      'SELECT email FROM users WHERE api_key = ? AND is_active = TRUE LIMIT 1',
      [apiKey]
    );

    if (!rows.length) {
      return res.status(401).send('Invalid API Key');
    }

    res.status(200);
    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();

    // Let the browser know the stream is open.
    res.write(': connected\n\n');

    const clientId = crypto.randomUUID();

    const heartbeat = setInterval(() => {
      if (!res.destroyed && !res.writableEnded) {
        res.write(': ping\n\n');
      }
    }, 15000);

    sseClients.set(clientId, { res, heartbeat });

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

// ==================== 5. WISBYTE BOT WEBHOOK ====================
app.post('/api/bot-webhook', (req, res) => {
  // Configure WEBHOOK_SECRET on MS Host and send the same secret
  // from your bot in the X-Webhook-Secret request header.
  // Until configured, this endpoint remains backward-compatible,
  // but it is NOT authenticated. Configure the secret before production use.
  if (WEBHOOK_SECRET) {
    const supplied = req.get('x-webhook-secret') || '';

    const expectedBuffer = Buffer.from(WEBHOOK_SECRET);
    const suppliedBuffer = Buffer.from(supplied);

    if (
      expectedBuffer.length !== suppliedBuffer.length ||
      !crypto.timingSafeEqual(expectedBuffer, suppliedBuffer)
    ) {
      return res.status(401).json({ error: 'Invalid webhook secret.' });
    }
  }

  const body = req.body || {};

  if (!body.eggName && !body.egg && !body.tier && !body.rarity) {
    return res.status(400).json({
      error: 'Missing spawn data. Provide eggName/egg or tier/rarity.'
    });
  }

  try {
    const { event, delivered } = sendSpawnEvent(body);

    console.log('Spawn webhook received:', JSON.stringify(event));

    return res.json({
      success: true,
      connectedClients: delivered
    });
  } catch (error) {
    console.error('Webhook processing failed:', error.message);
    return res.status(500).json({ error: 'Could not process spawn event.' });
  }
});

// ==================== 6. BACKEND HEALTH ====================
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Backend is running',
    databaseReady: dbReady,
    connectedClients: sseClients.size
  });
});

// ==================== 7. REAL DATABASE HEALTH ====================
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

// ==================== 8. MASTER ADMIN WEB PAGE ====================
app.get('/master', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Master Admin - Add User</title>
      <style>
        body{font-family:sans-serif;background:#111;color:#fff;padding:30px;text-align:center}
        input,button{padding:10px;margin:5px;border-radius:5px;border:none}
        input{width:min(250px,80%)}
        button{background:#0f0;color:#000;font-weight:bold;cursor:pointer}
      </style>
    </head>
    <body>
      <h2>Master Admin: Add New Buyer</h2>
      <form id="addForm">
        <input type="password" id="masterpass" placeholder="Master Password" required><br>
        <input type="email" id="email" placeholder="Buyer Email" required><br>
        <input type="password" id="password" placeholder="Buyer Password" minlength="8" required><br>
        <button type="submit">Add User</button>
      </form>
      <p id="msg" role="status"></p>
      <script>
        document.getElementById('addForm').addEventListener('submit', async (e) => {
          e.preventDefault();
          const msg = document.getElementById('msg');
          msg.textContent = 'Please wait...';

          try {
            const response = await fetch('/api/master/add-user', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'masterpassword': document.getElementById('masterpass').value
              },
              body: JSON.stringify({
                email: document.getElementById('email').value,
                password: document.getElementById('password').value
              })
            });

            const data = await response.json();
            msg.textContent = response.ok
              ? 'User added successfully.'
              : (data.error || 'Could not add user.');
          } catch (_) {
            msg.textContent = 'Network error. Please try again.';
          }
        });
      </script>
    </body>
    </html>
  `);
});

// ==================== 9. BUYER LOGIN / KEY GENERATOR ====================
app.get('/generator', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Buyer Login - API Key Generator</title>
      <style>
        body{font-family:sans-serif;background:#111;color:#fff;padding:30px;text-align:center}
        input,button{padding:10px;margin:5px;border-radius:5px;border:none}
        input{width:min(250px,80%)}
        button{background:#00e5ff;color:#000;font-weight:bold;cursor:pointer}
        .key-box{background:#222;padding:15px;border:1px solid #0f0;font-size:18px;margin-top:15px;word-break:break-all;display:none}
      </style>
    </head>
    <body>
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
        let userToken = '';

        document.getElementById('loginForm').addEventListener('submit', async (e) => {
          e.preventDefault();
          const msg = document.getElementById('msg');
          msg.textContent = 'Logging in...';

          try {
            const response = await fetch('/api/buyer/login', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({
                email: document.getElementById('email').value,
                password: document.getElementById('password').value
              })
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
              msg.textContent = data.error || 'Login failed.';
              return;
            }

            userToken = data.token;
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('genBox').style.display = 'block';
            msg.textContent = 'Login successful.';
          } catch (_) {
            msg.textContent = 'Network error. Please try again.';
          }
        });

        document.getElementById('generateButton').addEventListener('click', async () => {
          const msg = document.getElementById('msg');
          msg.textContent = 'Generating key...';

          try {
            const response = await fetch('/api/buyer/generate-key', {
              method: 'POST',
              headers: {'Authorization': 'Bearer ' + userToken}
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
              msg.textContent = data.error || 'Could not generate key.';
              return;
            }

            const keyBox = document.getElementById('keyBox');
            keyBox.style.display = 'block';
            keyBox.textContent = data.apiKey;
            msg.textContent = 'Keep this API key private.';
          } catch (_) {
            msg.textContent = 'Network error. Please try again.';
          }
        });
      </script>
    </body>
    </html>
  `);
});

// ==================== START SERVER ====================
async function startServer() {
  try {
    await initDB();

    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Backend listening on port ${PORT}`);
      console.log('Health: /health');
      console.log('Database health: /health/database');
      console.log('SSE endpoint: /events');
    });
  } catch (error) {
    console.error('Startup failed:', error.message);
    process.exit(1);
  }
}

startServer();
