
'use strict';

// Targeted, backup-first patch for the existing MS Host index.js.
// Upload this beside index.js in /app, then run:
// node patch_mshost_spawn.js

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const file = path.resolve(process.cwd(), 'index.js');

if (!fs.existsSync(file)) {
  console.error('ERROR: index.js not found in current folder.');
  process.exit(1);
}

let src = fs.readFileSync(file, 'utf8');
let changes = 0;

function replaceBetween(start, end, replacement, label) {
  const a = src.indexOf(start);

  if (a < 0) {
    throw new Error(`Could not find start marker for ${label}`);
  }

  const b = src.indexOf(end, a + start.length);

  if (b < 0) {
    throw new Error(`Could not find end marker for ${label}`);
  }

  src = src.slice(0, a) + replacement + '\n\n' + src.slice(b);
  changes++;
}

const tierHelpers = String.raw`function extractLabel(text, labels) {
  const escaped = labels.map(label =>
    label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  );

  // Read a single line only, so the next field is never swallowed.
  const regex = new RegExp(
    '^[\\t ]*(?:' + escaped.join('|') +
    ')[\\t ]*[:：][\\t ]*([^\\r\\n]*?)[\\t ]*$',
    'im'
  );

  const match = String(text || '').match(regex);
  return match ? cleanText(match[1]).trim() : '';
}

// Only the three spawn tiers used by this dashboard.
const TIERS = ['Secret', 'Divine', 'Eternal'];

function normalizeTier(value, text) {
  const source = String(text || '');
  const heading = source.match(
    /^[\\t ]*(Secret|Divine|Eternal)[\\t ]+Egg[\\t ]+Spawned\\b[^\\r\\n]*$/im
  );

  const supplied = String(value || '').trim();
  const normalizedSupplied = TIERS.find(
    t => t.toLowerCase() === supplied.toLowerCase()
  ) || '';

  if (heading) {
    const fromHeading = TIERS.find(
      t => t.toLowerCase() === heading[1].toLowerCase()
    );

    if (normalizedSupplied && normalizedSupplied !== fromHeading) {
      return 'Unknown';
    }

    return fromHeading || 'Unknown';
  }

  if (source.trim()) return 'Unknown';
  return normalizedSupplied || 'Unknown';
}`;

const elapsedFunction = String.raw`function parseElapsedSeconds(value) {
  const text = String(value || '').trim().toLowerCase();

  if (!text || /unknown|n\/a|none/.test(text)) return null;

  // Discord timestamp: <t:1792676411:R>
  const discordTs = text.match(/<t:(\d{9,13})(?::[tTdDfFR])?>/i);

  if (discordTs) {
    let targetMs = Number(discordTs[1]);
    if (targetMs < 1e12) targetMs *= 1000;

    if (Number.isFinite(targetMs) && targetMs > 0) {
      return Math.max(0, Math.floor((Date.now() - targetMs) / 1000));
    }
  }

  const ago = text.match(
    /(\d+(?:\.\d+)?)\s*(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d)\s*ago/i
  );

  if (ago) {
    const n = Number(ago[1]);
    const unit = ago[2].toLowerCase();

    const multiplier =
      /^(?:s|sec)/.test(unit) ? 1 :
      /^(?:m|min)/.test(unit) ? 60 :
      /^(?:h|hr|hour)/.test(unit) ? 3600 : 86400;

    return Math.max(0, Math.floor(n * multiplier));
  }

  const compact = text.match(/(\d+)\s*(s|m|h|d)\s*ago/i);

  if (compact) {
    return Number(compact[1]) *
      ({ s: 1, m: 60, h: 3600, d: 86400 })[compact[2]];
  }

  return null;
}`;

const normalizeSpawnFunction = String.raw`function collectSpawnText(body) {
  const parts = [];

  const add = value => {
    if (typeof value === 'string' && value.trim()) {
      parts.push(cleanText(value));
    }
  };

  for (const key of [
    'message', 'content', 'description', 'title',
    'messageText', 'message_text', 'rawMessage',
    'raw_message', 'raw_text'
  ]) {
    add(body[key]);
  }

  const addEmbed = embed => {
    if (!embed || typeof embed !== 'object') return;

    add(embed.title);
    add(embed.description);

    if (Array.isArray(embed.fields)) {
      for (const field of embed.fields) {
        if (field && (field.name || field.value)) {
          add(
            (field.name || '') +
            (field.name ? ': ' : '') +
            (field.value || '')
          );
        }
      }
    }

    if (embed.author && typeof embed.author.name === 'string') {
      add(embed.author.name);
    }
  };

  if (Array.isArray(body.embeds)) body.embeds.forEach(addEmbed);
  if (body.embed && typeof body.embed === 'object') addEmbed(body.embed);

  return [...new Set(parts)].join('\n').trim();
}

function parseMessageTimestamp(value) {
  if (value === undefined || value === null || value === '') return null;

  if (typeof value === 'number' || /^\d{10,13}$/.test(String(value).trim())) {
    let n = Number(value);

    if (!Number.isFinite(n) || n <= 0) return null;
    if (n < 1e12) n *= 1000;

    return n;
  }

  const discord = String(value).match(/<t:(\d{9,13})(?::[tTdDfFR])?>/i);

  if (discord) {
    let n = Number(discord[1]);
    if (n < 1e12) n *= 1000;
    return Number.isFinite(n) && n > 0 ? n : null;
  }

  const parsed = Date.parse(String(value));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

function normalizeSpawn(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return null;
  }

  const rawText = collectSpawnText(body);
  const heading = rawText.match(
    /^[\\t ]*(Secret|Divine|Eternal)[\\t ]+Egg[\\t ]+Spawned\\b[^\\r\\n]*$/im
  );

  const suppliedTier = body.tier ?? body.rarity ?? body.eggTier ?? '';

  // Raw alert text must have a valid heading.
  if (rawText && !heading) return null;

  const tier = normalizeTier(suppliedTier, rawText);
  if (!TIERS.includes(tier)) return null;

  const pickText = (...values) => {
    for (const value of values) {
      const text = cleanText(value);

      if (
        text &&
        !/^(unknown(?: egg)?|none|n\/a|null|undefined)$/i.test(text)
      ) {
        return text;
      }
    }

    return '';
  };

  let eggName = pickText(
    body.eggName, body.petName, body.egg, body.name
  );

  let location = pickText(body.location, body.biome, body.area);

  let spawned = pickText(
    body.spawnedLabel,
    body.spawned,
    body.spawnTime,
    body.spawn_time_text,
    body.spawnTimeText,
    body.timeSinceSpawn,
    body.time_since_spawn
  );

  const eggLooksLikeMessage =
    !eggName ||
    eggName.length > 120 ||
    /(?:^|\n)(?:location|biome|spawned|recommended speed|join game)\s*:/i.test(eggName) ||
    /Egg Spawned/i.test(eggName);

  if (eggLooksLikeMessage) {
    eggName = extractLabel(
      rawText, ['Egg', 'Egg Name', 'Spawned Egg', 'Pet Name']
    ) || '';
  }

  if (!location || /^(unknown|n\/a)$/i.test(location)) {
    location = extractLabel(rawText, ['Location', 'Biome', 'Area']) || location;
  }

  if (!spawned || /^(unknown|n\/a)$/i.test(spawned)) {
    spawned = extractLabel(
      rawText,
      ['Spawned', 'Spawned At', 'Time Since Spawn', 'Spawn Time']
    ) || spawned;
  }

  eggName = cleanText(eggName).replace(/[\r\n]+/g, ' ').trim();
  location = cleanText(location).replace(/[\r\n]+/g, ' ').trim();
  spawned = cleanText(spawned).replace(/[\r\n]+/g, ' ').trim();

  if (
    !eggName ||
    eggName.length > 120 ||
    /^\d{1,2}:\d{2}(?::\d{2})?$/.test(eggName) ||
    /^(unknown|none|n\/a|spawned|yes|true|secret egg spawned|divine egg spawned|eternal egg spawned)$/i.test(eggName) ||
    /^(money|recommended speed|join game|location|biome|spawned|time since spawn|spawn time)\s*:/i.test(eggName)
  ) {
    return null;
  }

  const now = Date.now();
  const elapsedSeconds = parseElapsedSeconds(spawned);
  const futureSeconds = parseFutureSeconds(spawned);

  const messageId = pickText(
    body.messageId,
    body.message_id,
    body.discordMessageId,
    body.discord_message_id,
    body.message && typeof body.message === 'object' ? body.message.id : ''
  );

  const channelId = pickText(
    body.channelId,
    body.channel_id,
    body.message && typeof body.message === 'object' ? body.message.channelId : ''
  );

  const messageTimestamp = parseMessageTimestamp(
    body.timestamp ??
    body.time ??
    body.createdAt ??
    body.created_at ??
    (body.message && typeof body.message === 'object'
      ? body.message.timestamp : null)
  ) || now;

  const spawnedAtMs = elapsedSeconds !== null
    ? messageTimestamp - elapsedSeconds * 1000
    : null;

  return {
    id: messageId || crypto.randomUUID(),
    type: 'SPAWN',
    petName: eggName,
    eggName,
    egg: eggName,
    tier,
    location: location || 'Unknown',
    biome: location || 'Unknown',
    spawned: spawned || 'Unknown',
    spawnedLabel: spawned || 'Unknown',
    elapsedSeconds,
    futureSeconds,
    timerMode: elapsedSeconds !== null
      ? 'elapsed'
      : futureSeconds !== null ? 'countdown' : 'unknown',
    timestamp: messageTimestamp,
    time: new Date(messageTimestamp).toISOString(),
    spawnedAt: spawnedAtMs !== null
      ? new Date(spawnedAtMs).toISOString()
      : null,
    receivedAt: now,
    source: pickText(body.source) || 'Discord',
    messageId: messageId || null,
    channelId: channelId || null
  };
}`;

const eventTransport = String.raw`function publicScheduleEvent(event) {
  const ageSeconds = Math.max(
    0, Math.floor((Date.now() - event.receivedAt) / 1000)
  );

  const remainingSeconds = event.futureSeconds !== null
    ? Math.max(0, event.futureSeconds - ageSeconds)
    : 0;

  const elapsedSeconds = event.elapsedSeconds !== null
    ? event.elapsedSeconds + ageSeconds
    : null;

  return {
    id: event.id,
    type: 'SPAWN',
    petName: event.petName,
    eggName: event.eggName,
    egg: event.egg,
    tier: event.tier,
    rarity: event.tier,
    location: event.location,
    biome: event.biome,
    spawned: event.spawned,
    spawnedLabel: event.spawnedLabel || event.spawned,
    timestamp: event.timestamp,
    time: event.time || new Date(event.timestamp).toISOString(),
    spawnedAt: event.spawnedAt,
    receivedAt: event.receivedAt,
    source: event.source,
    messageId: event.messageId,
    channelId: event.channelId,
    remainingSeconds,
    elapsedSeconds,
    futureSeconds: event.futureSeconds,
    timerMode: elapsedSeconds !== null
      ? 'elapsed'
      : event.futureSeconds !== null ? 'countdown' : 'unknown'
  };
}

function sseEventFrame(event) {
  const normalized = publicScheduleEvent(event);

  // Flat fields serve V290; nested event supports older receivers.
  return 'data: ' + JSON.stringify({
    ...normalized,
    type: 'SPAWN',
    event: normalized
  }) + '\n\n';
}

function broadcastEvent(event) {
  const payload = sseEventFrame(event);

  for (const [id, client] of sseClients) {
    try {
      client.res.write(payload);
    } catch (_) {
      clearInterval(client.heartbeat);
      sseClients.delete(id);
    }
  }
}`;

const webhookRoute = String.raw`// ==================== SPAWN WEBHOOK ====================
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

  try {
    const event = normalizeSpawn(req.body || {});

    if (!event) {
      return res.status(200).json({
        success: true,
        ignored: true,
        reason: 'Not a valid Secret, Divine, or Eternal Egg Spawned alert.',
        connectedClients: sseClients.size
      });
    }

    const dedupeKey = event.messageId || event.id;

    if (spawnEvents.has(dedupeKey)) {
      return res.json({
        success: true,
        duplicate: true,
        connectedClients: sseClients.size
      });
    }

    spawnEvents.set(dedupeKey, event);
    pruneEvents();
    broadcastEvent(event);

    console.log('[SPAWN RECEIVED]', JSON.stringify({
      tier: event.tier,
      eggName: event.eggName,
      location: event.location,
      spawned: event.spawned,
      timerMode: event.timerMode,
      messageId: event.messageId,
      connectedClients: sseClients.size
    }));

    return res.json({
      success: true,
      ignored: false,
      duplicate: false,
      connectedClients: sseClients.size,
      parsed: publicScheduleEvent(event)
    });
  } catch (error) {
    console.error('Webhook processing failed:', error.message);
    return res.status(500).json({
      error: 'Could not process spawn event.'
    });
  }
});`;

const scheduleRoute = String.raw`// ==================== SCHEDULE API FOR V290 ====================
app.get('/api/schedule', (req, res) => {
  pruneEvents();

  const schedules = [...spawnEvents.values()]
    .sort((a, b) => b.receivedAt - a.receivedAt)
    .map(publicScheduleEvent);

  const latest = schedules[0] || null;

  return res.json({
    success: true,
    // A webhook cannot confirm the bot's live Discord connection.
    discordConnected: null,
    receiverReady: true,
    sourceStatus: latest
      ? 'spawn-events-received'
      : 'waiting-for-first-spawn',
    lastEventReceivedAt: latest ? latest.receivedAt : null,
    activeSchedules: schedules.length,
    lastMessage: latest
      ? latest.petName + ' · ' + latest.tier + ' · ' + latest.location
      : null,
    schedules
  });
});`;

replaceBetween(
  'function extractLabel(text, labels) {',
  'function parseElapsedSeconds(value) {',
  tierHelpers,
  'tier allowlist and label parser'
);

replaceBetween(
  'function parseElapsedSeconds(value) {',
  'function parseFutureSeconds(value) {',
  elapsedFunction,
  'elapsed timer parser'
);

replaceBetween(
  'function normalizeSpawn(body) {',
  'function pruneEvents() {',
  normalizeSpawnFunction,
  'spawn normalization'
);

replaceBetween(
  'function publicScheduleEvent(event) {',
  '// ==================== DATABASE SETUP ====================',
  eventTransport,
  'flat and nested SSE payload'
);

replaceBetween(
  '// ==================== SPAWN WEBHOOK ====================',
  '// ==================== AUTHENTICATED SSE STREAM ====================',
  webhookRoute + '\n\n' + scheduleRoute + '\n\n',
  'webhook and schedule routes'
);

const replayMarker = '    // Send recent events when';

if (src.includes(replayMarker)) {
  replaceBetween(
    replayMarker,
    "    req.on('close', () => {",
    `    // Replay recent events with the same format as live events.
    for (const event of [...spawnEvents.values()].slice(-50)) {
      res.write(sseEventFrame(event));
    }

`,
    'SSE replay format'
  );
} else if (
  !src.includes('Replay recent events with the same format as live events.')
) {
  throw new Error('SSE replay block not found; refusing unknown version.');
}

for (const marker of [
  "app.post('/api/bot-webhook'",
  "app.get('/api/schedule'",
  "app.get('/events'",
  "app.get('/health'",
  "app.post('/api/master/add-user'",
  "app.post('/api/buyer/login'"
]) {
  if (!src.includes(marker)) {
    throw new Error(`Validation failed: missing preserved route ${marker}`);
  }
}

if (!src.includes("const TIERS = ['Secret', 'Divine', 'Eternal'];")) {
  throw new Error('Tier allowlist was not installed.');
}

if ((src.match(/function normalizeSpawn\(/g) || []).length !== 1) {
  throw new Error('normalizeSpawn must appear exactly once.');
}

const backup = file + '.before-spawn-fix-' +
  new Date().toISOString().replace(/[:.]/g, '-') + '.bak';

fs.copyFileSync(file, backup);
fs.writeFileSync(file, src, 'utf8');

const check = spawnSync(process.execPath, ['--check', file], {
  encoding: 'utf8'
});

if (check.status !== 0) {
  fs.copyFileSync(backup, file);
  console.error('Syntax check FAILED. Original index.js restored.');
  process.stderr.write(check.stderr || check.stdout || 'Unknown syntax error.');
  process.exit(1);
}

console.log(`Patch applied: ${changes} sections updated.`);
console.log(`Backup created: ${path.basename(backup)}`);
console.log('PASS: node --check index.js');
console.log('Updated: tier filter, field extraction, elapsed timers, SSE format, replay, schedule status.');
console.log('Preserved: database, login, API-key and admin routes.');
console.log('Restart the MS Host service after this command.');
