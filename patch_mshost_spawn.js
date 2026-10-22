**`patch_mshost_spawn.js` — complete file**

```js
'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const file = path.resolve(process.cwd(), 'index.js');

if (!fs.existsSync(file)) {
  console.error('ERROR: index.js not found in current folder.');
  process.exit(1);
}

let src = fs.readFileSync(file, 'utf8');
const original = src;
let changes = 0;

function replaceFunction(functionName, replacement, nextMarker) {
  const startMarker = `function ${functionName}(`;
  const start = src.indexOf(startMarker);

  if (start < 0) {
    throw new Error(`Could not find function ${functionName}()`);
  }

  const end = src.indexOf(nextMarker, start);

  if (end < 0) {
    throw new Error(
      `Could not find end marker after ${functionName}()`
    );
  }

  src = src.slice(0, start) + replacement + '\n\n' + src.slice(end);
  changes++;
}

try {
  const elapsedFunction = String.raw`function parseElapsedSeconds(value) {
  const text = String(value || '').trim().toLowerCase();

  if (!text || /unknown|n\/a|none/.test(text)) return null;

  // Discord timestamp: <t:1792698008:R>
  const discordTs = text.match(/<t:(\d{9,13})(?::[tTdDfFR])?>/i);

  if (discordTs) {
    const rawTimestamp = Number(discordTs[1]);
    const targetMs = rawTimestamp < 1e12
      ? rawTimestamp * 1000
      : rawTimestamp;

    if (Number.isFinite(targetMs) && targetMs > 0) {
      return Math.max(
        0,
        Math.floor((Date.now() - targetMs) / 1000)
      );
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
    const multipliers = { s: 1, m: 60, h: 3600, d: 86400 };
    return Number(compact[1]) * multipliers[compact[2]];
  }

  return null;
}`;

  replaceFunction(
    'parseElapsedSeconds',
    elapsedFunction,
    'function parseFutureSeconds('
  );

  // Validate the patched source before writing.
  const check = spawnSync(
    process.execPath,
    ['--check', file],
    { encoding: 'utf8' }
  );

  // Check the candidate in a temporary file without changing index.js.
  const tempFile = path.join(
    path.dirname(file),
    `.index-check-${process.pid}.js`
  );

  fs.writeFileSync(tempFile, src, 'utf8');

  const candidateCheck = spawnSync(
    process.execPath,
    ['--check', tempFile],
    { encoding: 'utf8' }
  );

  fs.rmSync(tempFile, { force: true });

  if (candidateCheck.status !== 0) {
    throw new Error(
      'Patched source failed syntax check:\n' +
      (candidateCheck.stderr || candidateCheck.stdout || '')
    );
  }

  if (src === original) {
    console.log('No changes needed.');
    process.exit(0);
  }

  const backup = `${file}.before-timestamp-${Date.now()}.bak`;
  fs.copyFileSync(file, backup);

  try {
    fs.writeFileSync(file, src, 'utf8');

    const finalCheck = spawnSync(
      process.execPath,
      ['--check', file],
      { encoding: 'utf8' }
    );

    if (finalCheck.status !== 0) {
      fs.writeFileSync(file, original, 'utf8');

      throw new Error(
        'Final syntax check failed; original index.js restored.\n' +
        (finalCheck.stderr || finalCheck.stdout || '')
      );
    }
  } catch (error) {
    if (fs.existsSync(backup) && fs.readFileSync(file, 'utf8') !== original) {
      fs.writeFileSync(file, original, 'utf8');
    }
    throw error;
  }

  console.log(`Patch applied: ${changes} function updated.`);
  console.log(`Backup: ${backup}`);
  console.log('PASS: node --check index.js');
  console.log('Updated: Discord relative timestamp parsing.');
  console.log('Not changed: database, login, API-key, webhook and admin routes.');
} catch (error) {
  console.error('PATCH FAILED:', error.message);
  console.error('index.js was not intentionally changed if validation failed.');
  process.exit(1);
}
```
