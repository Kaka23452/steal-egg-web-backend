#!/usr/bin/env node

'use strict';

require('dotenv').config();

const crypto = require('crypto');

function readArguments(argv) {
  const result = {};
  const valueFlags = new Set([
    '--egg',
    '--location',
    '--tier',
    '--spawned',
    '--url'
  ]);

  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];

    if (!valueFlags.has(flag)) {
      throw new Error(`Unknown argument: ${flag}`);
    }

    const value = argv[i + 1];
    if (!value || value.startsWith('--')) {
      throw new Error(`Missing value for ${flag}`);
    }

    result[flag.slice(2)] = value;
    i += 1;
  }

  return result;
}

function parseSpawnTime(input) {
  if (!input || input.trim().toLowerCase() === 'now') {
    return new Date();
  }

  const value = input.trim();
  const relative = value.match(
    /^(\d+)\s+(second|seconds|sec|minute|minutes|min|hour|hours|hr|day|days)\s+ago$/i
  );

  if (relative) {
    const amount = Number(relative[1]);
    const unit = relative[2].toLowerCase();

    const unitMs = {
      second: 1000,
      seconds: 1000,
      sec: 1000,
      minute: 60 * 1000,
      minutes: 60 * 1000,
      min: 60 * 1000,
      hour: 60 * 60 * 1000,
      hours: 60 * 60 * 1000,
      hr: 60 * 60 * 1000,
      day: 24 * 60 * 60 * 1000,
      days: 24 * 60 * 60 * 1000
    };

    return new Date(Date.now() - amount * unitMs[unit]);
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new Error(
      'Invalid --spawned value. Use "now", "2 minutes ago", or an ISO date.'
    );
  }

  return date;
}

async function main() {
  const args = readArguments(process.argv.slice(2));

  const eggName = args.egg;
  const location = args.location || '';
  const tier = args.tier;
  const spawnedAt = parseSpawnTime(args.spawned || 'now');

  if (!eggName || !tier) {
    throw new Error(
      'Usage: node patch_mshost_spawn.js --egg "RazorFang" --location "Demons" --tier "Secret" --spawned "2 minutes ago"'
    );
  }

  const botKey = process.env.BOT_INGEST_KEY;
  if (!botKey) {
    throw new Error(
      'BOT_INGEST_KEY is missing. Set it in the backend environment before running this test.'
    );
  }

  const baseUrl = (
    args.url ||
    process.env.BACKEND_URL ||
    `http://127.0.0.1:${process.env.PORT || 3000}`
  ).replace(/\/+$/, '');

  const endpoint = `${baseUrl}/api/ingest`;

  const payload = {
    messageId: `manual-test-${crypto.randomUUID()}`,
    eggName,
    location,
    tier,
    spawnedAt: spawnedAt.toISOString()
  };

  console.log(`[Test] Sending sample spawn to ${endpoint}`);
  console.log(
    `[Test] ${tier} | ${eggName} | ${location || 'Location not specified'}`
  );

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Bot-Key': botKey
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(15000)
  });

  const responseText = await response.text();

  let responseBody;
  try {
    responseBody = JSON.parse(responseText);
  } catch {
    responseBody = responseText;
  }

  if (!response.ok) {
    console.error(`[Test] Backend returned HTTP ${response.status}`);
    console.error(responseBody);
    process.exitCode = 1;
    return;
  }

  console.log('[Test] Backend accepted the request:');
  console.log(JSON.stringify(responseBody, null, 2));
}

main().catch(error => {
  console.error(`[Test failed] ${error.message}`);
  process.exitCode = 1;
});
