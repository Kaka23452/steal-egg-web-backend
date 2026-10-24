
const fs = require('fs');
const path = require('path');

const MAX_EVENTS = 100;
const SPAWN_STORE =
  process.env.SPAWN_STORE ||
  path.join(__dirname, 'spawn-events.json');

const recentEvents = [];
const seenMessageIds = new Set();

let lastWebhookAt = null;
let lastMessage = null;

// SPAWN_PERSISTENCE_PATCH_V1
function loadSpawnEvents() {
  try {
    if (!fs.existsSync(SPAWN_STORE)) return;

    const raw = fs.readFileSync(SPAWN_STORE, 'utf8');
    const data = JSON.parse(raw);

    if (!Array.isArray(data)) {
      throw new Error('Spawn store must contain an array');
    }

    recentEvents.length = 0;
    seenMessageIds.clear();

    for (const event of data.slice(0, MAX_EVENTS)) {
      if (!event || typeof event !== 'object' || Array.isArray(event)) {
        continue;
      }

      recentEvents.push(event);

      if (event.messageId != null) {
        seenMessageIds.add(String(event.messageId));
      }
    }

    lastMessage = recentEvents[0] || null;

    lastWebhookAt = recentEvents.length
      ? (
          recentEvents[0].receivedAt ||
          recentEvents[0].timestamp ||
          null
        )
      : null;

    console.log(
      '[Spawn persistence] Restored',
      recentEvents.length,
      'events'
    );
  } catch (err) {
    console.error(
      '[Spawn persistence] Could not load events:',
      err.message || err
    );
  }
}

function saveSpawnEvents() {
  const tempPath = SPAWN_STORE + '.tmp';

  try {
    const dir = path.dirname(SPAWN_STORE);
    fs.mkdirSync(dir, { recursive: true });

    fs.writeFileSync(
      tempPath,
      JSON.stringify(recentEvents.slice(0, MAX_EVENTS), null, 2),
      'utf8'
    );

    fs.renameSync(tempPath, SPAWN_STORE);
  } catch (err) {
    console.error(
      '[Spawn persistence] Could not save events:',
      err.message || err
    );

    try {
      if (fs.existsSync(tempPath)) {
        fs.unlinkSync(tempPath);
      }
    } catch (_) {}
  }
}
