
'use strict';

// Targeted, backup-first patch for the existing MS Host index.js.
// Upload beside index.js in /app, then run:
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
  if (a < 0) throw new Error(`Could not find start marker for ${label}`);

  const b = src.indexOf(end, a + start.length);
  if (b < 0) throw new Error(`Could not find end marker for ${label}`);

  src = src.slice(0, a) + replacement + '\n\n' + src.slice(b);
  changes++;
}

// IMPORTANT FIX:
// Escape the "$" in ${ so String.raw does not treat it as interpolation.
const tierHelpers = String.raw`function extractLabel(text, labels) {
  const escaped = labels.map(label =>
    label.replace(/[.*+?^\${}()|[\]\\]/g, '\\$&')
  );

  const regex = new RegExp(
    '^[\\t ]*(?:' + escaped.join('|') +
    ')[\\t ]*[:：][\\t ]*([^\\r\\n]*?)[\\t ]*$',
    'im'
  );

  const match = String(text || '').match(regex);
  return match ? cleanText(match[1]).trim() : '';
}

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

console.log('Fixed patcher syntax section is ready.');
console.log('This is not the complete patch application logic.');
console.log('Do not run this shortened snippet as the full patcher.');
