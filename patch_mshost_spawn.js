
'use strict';

/**
 * Steal An Egg SaaS — Manual Spawn Testing CLI
 *
 * Node.js 20+ required.
 *
 * Example:
 * BOT_INGEST_KEY=your_bot_secret node patch_mshost_spawn.js \
 *   --egg "RazorFang" \
 *   --location "Demons" \
 *   --tier "Secret" \
 *   --spawned "2 minutes ago"
 *
 * Windows PowerShell:
 * $env:BOT_INGEST_KEY="your_bot_secret"
 * node .\patch_mshost_spawn.js --egg "RazorFang" --location "Demons" --tier "Secret" --spawned "2 minutes ago"
 */

const crypto = require('node:crypto');

const DEFAULT_BACKEND_URL = 'http://127.0.0.1:3000';
const REQUEST_TIMEOUT_MS = 15000;

function printUsage() {
  console.log(`
Steal An Egg — Manual Spawn Test

Usage:
  node patch_mshost_spawn.js --egg "RazorFang" --location "Demons" --tier "Secret" --spawned "2 minutes ago"

Required options:
  --egg         Egg name
  --location    Spawn location
  --tier        Egg rarity/tier

Optional options:
  --spawned     Spawn time (default: now)
  --message-id  Numeric Discord-style message ID for deduplication testing
  --url         Backend base URL
  --help        Display this help

Environment:
  BOT_INGEST_KEY  Must match the backend BOT_INGEST_KEY
  BACKEND_URL     Backend URL (default: http://127.0.0.1:3000)

Examples:
  node patch_mshost_spawn.js --egg "RazorFang" --location "Demons" --tier "Secret"

  node patch_mshost_spawn.js --egg "Starry Fox Egg" --location "Forest" --tier "Legendary" --spawned "2 minutes ago"
`);
}

function parseArguments(argv) {
  const result = {};
  const options = new Set([
    '--egg',
    '--location',
    '--tier',
    '--spawned',
    '--message-id',
    '--url'
  ]);

  for (let i = 0; i < argv.length; i++) {
    const option = argv[i];

    if (option === '--help' || option === '-h') {
      result.help = true;
      continue;
    }

    if (!options.has(option)) {
      throw new Error(`Unknown option: ${option}`);
    }

    const values = [];

    i++;

    while (i < argv.length && !argv[i].startsWith('--')) {
      values.push(argv[i]);
      i++;
    }

    i--;

    const value = values.join(' ').trim();

    if (!value) {
      throw new Error(`Missing value for ${option}`);
    }

    switch (option) {
      case '--egg':
        result.eggName = value;
        break;
      case '--location':
        result.location = value;
        break;
      case '--tier':
        result.tier = value;
        break;
      case '--spawned':
        result.spawnedAt = value;
        break;
      case '--message-id':
        result.messageId = value;
        break;
      case '--url':
        result.backendUrl = value;
        break;
    }
  }

  return result;
}

function validateText(value, name, maxLength = 191) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`${name} is required`);
  }

  if (value.trim().length > maxLength) {
    throw new Error(`${name} cannot exceed ${maxLength} characters`);
  }

  return value.trim();
}

function buildMessageId(value) {
  if (value !== undefined) {
    const id = validateText(value, 'message-id', 32);

    if (!/^\d{1,32}$/.test(id)) {
      throw new Error('--message-id must contain 1–32 digits');
    }

    return id;
  }

  // Numeric, unique ID compatible with the backend's validation.
  return `${Date.now()}${crypto.randomInt(100000, 999999)}`;
}

async function main() {
  let args;

  try {
    args = parseArguments(process.argv.slice(2));
  } catch (error) {
    console.error(`Argument error: ${error.message}`);
    console.error('Run with --help to see usage.');
    process.exitCode = 1;
    return;
  }

  if (args.help) {
    printUsage();
    return;
  }

  let botKey = process.env.BOT_INGEST_KEY;

  if (!botKey || botKey.startsWith('REPLACE_WITH_')) {
    console.error(
      'Error: Set BOT_INGEST_KEY to the same secret used by the backend.'
    );
    process.exitCode = 1;
    return;
  }

  let eggName;
  let location;
  let tier;

  try {
    eggName = validateText(args.eggName, '--egg');
    location = validateText(args.location, '--location');
    tier = validateText(args.tier, '--tier', 64);
  } catch (error) {
    console.error(`Validation error: ${error.message}`);
    console.error('Run with --help to see usage.');
    process.exitCode = 1;
    return;
  }

  const spawnedAt = args.spawnedAt || new Date().toISOString();
  const messageId = buildMessageId(args.messageId);

  const baseUrl = (
    args.backendUrl ||
    process.env.BACKEND_URL ||
    DEFAULT_BACKEND_URL
  ).replace(/\/+$/, '');

  let parsedUrl;

  try {
    parsedUrl = new URL(baseUrl);
  } catch {
    console.error('Error: The backend URL is invalid.');
    process.exitCode = 1;
    return;
  }

  if (
    !['http:', 'https:'].includes(parsedUrl.protocol) ||
    parsedUrl.username ||
    parsedUrl.password ||
    parsedUrl.search ||
    parsedUrl.hash
  ) {
    console.error('Error: Provide a valid HTTP(S) base URL without credentials, query or fragment.');
    process.exitCode = 1;
    return;
  }

  const endpoint = `${baseUrl}/api/ingest`;

  const payload = {
    messageId,
    tier,
    eggName,
    location,
    spawnedAt
  };

  console.log('');
  console.log('======================================');
  console.log(' STEAL AN EGG — SPAWN TEST');
  console.log('======================================');
  console.log(`Backend:  ${baseUrl}`);
  console.log(`Egg:      ${eggName}`);
  console.log(`Location: ${location}`);
  console.log(`Tier:     ${tier}`);
  console.log(`Spawned:  ${spawnedAt}`);
  console.log(`Message:  ${messageId}`);
  console.log('======================================');
  console.log('Sending test spawn...');

  let response;

  try {
    response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Bot-Key': botKey
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
    });
  } catch (error) {
    console.error('');
    console.error('Request failed.');

    if (error.name === 'TimeoutError') {
      console.error('The backend did not respond within 15 seconds.');
    } else {
      console.error(error.message);
    }

    console.error('Check that the backend is running and the URL is correct.');
    process.exitCode = 1;
    return;
  } finally {
    // Avoid accidental reuse of the secret within this script.
    botKey = '';
  }

  let result;

  try {
    result = await response.json();
  } catch {
    console.error(`Backend returned HTTP ${response.status} with a non-JSON response.`);
    process.exitCode = 1;
    return;
  }

  if (!response.ok || result.ok !== true) {
    console.error('');
    console.error(`Spawn test failed: HTTP ${response.status}`);
    console.error(`Reason: ${result.error || 'Unknown backend error'}`);
    process.exitCode = 1;
    return;
  }

  if (result.duplicate) {
    console.log('');
    console.log('Duplicate message detected.');
    console.log('The backend did not create another stock record.');
    return;
  }

  console.log('');
  console.log('Spawn ingestion successful.');
  console.log(`Stock ID: ${result.stockId}`);
  console.log(`Egg:      ${result.eggName}`);
  console.log(`Pet:      ${result.petName}`);
  console.log(`Location: ${result.location}`);
  console.log(`Expires:  ${result.expiresAt}`);
  console.log('');
  console.log('Check the dashboard and OBS overlay for the new stock.');
}

main().catch(error => {
  console.error(`Unexpected error: ${error.message}`);
  process.exitCode = 1;
});
