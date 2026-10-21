const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

// Config
const DB_URL = process.env.TIDB_DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key';
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || 'admin123';

let pool;

// Database Setup
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

// Master Admin Route (Add User)
app.post('/api/master/add-user', async (req, res) => {
  if (req.headers.masterpassword !== MASTER_PASSWORD) return res.status(401).send('Unauthorized');
  const { email, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (email, password_hash) VALUES (?, ?)', [email, hash]);
    res.json({ success: true, message: 'User added' });
  } catch (err) {
    res.status(500).json({ error: 'Email already exists or DB error' });
  }
});

// Buyer Login
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

// Generate API Key
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

// SSE Endpoint for OBS
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

// Bot Webhook (Wispbyte se data aayega)
app.post('/api/bot-webhook', (req, res) => {
  const { tier, eggName, time } = req.body;
  const payload = `data: ${JSON.stringify({ type: 'SPAWN', tier, eggName, time })}\n\n`;
  sseClients.forEach(client => { try { client.res.write(payload); } catch (e) {} });
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Running on ${PORT}`));
