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

    const data = JSON.parse(
      fs.readFileSync(SPAWN_STORE, 'utf8')
    );

    if (!Array.isArray(data)) {
      throw new Error('Spawn store must contain an array');
    }

    recentEvents.splice(
      0,
      recentEvents.length,
      ...data.slice(0, MAX_EVENTS)
    );

    for (const event of recentEvents) {
      if (event.messageId) {
        seenMessageIds.add(String(event.messageId));
      }
    }

    lastMessage = recentEvents[0] || null;

    lastWebhookAt = recentEvents.length
      ? (
          recentEvents[0].receivedAt ||
          recentEvents[0].timestamp ||
          new Date().toISOString()
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
    fs.writeFileSync(
      tempPath,
      JSON.stringify(recentEvents, null, 2),
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
