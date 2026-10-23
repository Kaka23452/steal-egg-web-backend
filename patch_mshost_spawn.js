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

let dbStatus = {
  connected: false,
  message: 'Database not initialized'
};

app.disable('x-powered-by');

app.use(cors({
  origin(origin, callback) {
    if (
      !origin ||
      ALLOWED_ORIGIN === '*' ||
      ALLOWED_ORIGIN.split(',').map(x => x.trim()).includes(origin)
    ) {
      return callback(null, true);
    }

    return callback(new Error('Origin not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Webhook-Secret',
    'X-API-Key'
  ]
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''), 'utf8');
  const bb = Buffer.from(String(b || ''), 'utf8');

  return aa.length > 0 &&
    aa.length === bb.length &&
    crypto.timingSafeEqual(aa, bb);
}

function text(value) {
  if (value === undefined || value === null) return '';

  if (typeof value === 'string' || typeof value === 'number') {
    return String(value).trim();
  }

  return '';
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

    await dbPool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(190) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        api_key VARCHAR(128) NULL UNIQUE,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

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
