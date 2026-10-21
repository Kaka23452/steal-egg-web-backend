const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

// 🔐 CONFIG
const DB_URL = process.env.TIDB_DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key';
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || 'admin123';

let pool;

// ==================== DATABASE SETUP ====================
async function initDB() {
  try {
    pool = mysql.createPool(DB_URL);
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
    console.log('✅ Database Connected & Table Ready');
  } catch (err) {
    console.error('❌ DB Init Error:', err.message);
  }
}
initDB();

// ==================== API ROUTES ====================
// 1. Master Admin (Add User)
app.post('/api/master/add-user', async (req, res) => {
  if (req.headers.masterpassword !== MASTER_PASSWORD) return res.status(401).json({ error: 'Unauthorized' });
  const { email, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (email, password_hash) VALUES (?, ?)', [email, hash]);
    res.json({ success: true, message: 'User added successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Email already exists or DB error' });
  }
});

// 2. Buyer Login
app.post('/api/buyer/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ? AND is_active = TRUE', [email]);
    if (rows.length === 0) return res.status(401).json({ error: 'Invalid or blocked account' });
    
    const user = rows[0];
    if (!(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Wrong password' });

    const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Generate API Key
app.post('/api/buyer/generate-key', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).send('No token');
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const newApiKey = 'EGG-' + crypto.randomBytes(16).toString('hex').toUpperCase();
    await pool.query('UPDATE users SET api_key = ? WHERE email = ?', [newApiKey, decoded.email]);
    res.json({ success: true, apiKey: newApiKey });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// 4. SSE Endpoint for OBS
let sseClients = new Map();
app.get('/events', async (req, res) => {
  const { apiKey } = req.query;
  if (!apiKey) return res.status(401).send('API Key required');

  const [rows] = await pool.query('SELECT email FROM users WHERE api_key = ? AND is_active = TRUE', [apiKey]);
  if (rows.length === 0) return res.status(401).send('Invalid Key');

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const clientId = crypto.randomUUID();
  sseClients.set(clientId, { res });
  const heartbeat = setInterval(() => res.write(': ping\n\n'), 15000);

  req.on('close', () => {
    clearInterval(heartbeat);
    sseClients.delete(clientId);
  });
});

// 5. Bot Webhook (Wispbyte Bot se data aayega)
app.post('/api/bot-webhook', (req, res) => {
  const { tier, eggName, time } = req.body;
  console.log(`📡 Received from Bot: [${tier}] - ${eggName}`); // 👈 Log add kiya
  
  const payload = `data: ${JSON.stringify({ type: 'SPAWN', tier, eggName, time })}\n\n`;
  sseClients.forEach(client => { try { client.res.write(payload); } catch (e) {} });
  res.json({ success: true });
});

// 6. Health Check Endpoint (Test karne ke liye)
app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'Backend is running smoothly' });
});

// ==================== WEB UI PAGES ====================
// Master Page (Aapke liye)
app.get('/master', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Master Admin - Add User</title>
    <style>body{font-family:sans-serif;background:#111;color:#fff;padding:50px;text-align:center;} input,button{padding:10px;margin:5px;border-radius:5px;border:none;} input{width:250px;} button{background:#0f0;color:#000;font-weight:bold;cursor:pointer;}</style>
    </head>
    <body>
      <h2>Master Admin: Add New Buyer</h2>
      <input type="password" id="masterpass" placeholder="Master Password"><br>
      <input type="email" id="email" placeholder="Buyer Email"><br>
      <input type="password" id="password" placeholder="Buyer Password"><br>
      <button onclick="addUser()">Add User</button>
      <p id="msg"></p>
      <script>
        async function addUser() {
          const masterpass = document.getElementById('masterpass').value;
          const email = document.getElementById('email').value;
          const password = document.getElementById('password').value;
          const res = await fetch('/api/master/add-user', {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'masterpassword': masterpass},
            body: JSON.stringify({email, password})
          });
          const data = await res.json();
          document.getElementById('msg').innerText = data.success ? '✅ User Added!' : '❌ ' + (data.error || 'Error');
        }
      </script>
    </body>
    </html>
  `);
});

// Generator Page (Buyer ke liye)
app.get('/generator', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Generator - Get API Key</title>
    <style>body{font-family:sans-serif;background:#111;color:#fff;padding:50px;text-align:center;} input,button{padding:10px;margin:5px;border-radius:5px;border:none;} input{width:250px;} button{background:#00e5ff;color:#000;font-weight:bold;cursor:pointer;} .key-box{background:#222;padding:15px;border:1px solid #0f0;font-size:20px;margin-top:15px;word-break:break-all; display:none;}</style>
    </head>
    <body>
      <h2>Buyer Login & Generate Key</h2>
      <div id="loginBox">
        <input type="email" id="email" placeholder="Email"><br>
        <input type="password" id="password" placeholder="Password"><br>
        <button onclick="login()">Login</button>
      </div>
      <div id="genBox" style="display:none;">
        <button onclick="generateKey()">Generate API Key</button>
        <div id="keyBox" class="key-box"></div>
      </div>
      <p id="msg"></p>
      <script>
        let userToken = '';
        async function login() {
          const email = document.getElementById('email').value;
          const password = document.getElementById('password').value;
          const res = await fetch('/api/buyer/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({email, password})
          });
          const data = await res.json();
          if(data.success) {
            userToken = data.token;
            document.getElementById('loginBox').style.display = 'none';
            document.getElementById('genBox').style.display = 'block';
          } else {
            document.getElementById('msg').innerText = '❌ ' + data.error;
          }
        }
        async function generateKey() {
          const res = await fetch('/api/buyer/generate-key', {
            method: 'POST',
            headers: {'Authorization': 'Bearer ' + userToken}
          });
          const data = await res.json();
          if(data.success) {
            document.getElementById('keyBox').style.display = 'block';
            document.getElementById('keyBox').innerText = data.apiKey;
          } else {
            document.getElementById('msg').innerText = '❌ ' + data.error;
          }
        }
      </script>
    </body>
    </html>
  `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Running on ${PORT}`));
