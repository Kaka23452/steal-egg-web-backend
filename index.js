node <<'NODE'
const fs = require('fs');
const { spawnSync } = require('child_process');

const file = 'index.js';
const source = fs.readFileSync(file, 'utf8');
const start = source.indexOf('function parseElapsedSeconds(value) {');
const end = source.indexOf('\nfunction parseFutureSeconds(', start);

if (start < 0 || end < 0) {
  console.error('ERROR: Parser boundaries not found. File unchanged.');
  process.exit(1);
}

const replacement = String.raw`function parseElapsedSeconds(value) {
  const text = String(value || '').trim().toLowerCase();

  if (!text || /unknown|n\/a|none/.test(text)) return null;

  // Discord timestamp: <t:UNIX:R>, <t:UNIX>, etc.
  const discordTs = text.match(/<t:(\d{9,13})(?::[tTdDfFR])?>/i);
  if (discordTs) {
    const raw = Number(discordTs[1]);
    const targetMs = raw < 1e12 ? raw * 1000 : raw;

    if (Number.isFinite(targetMs) && targetMs > 0) {
      return Math.max(0, Math.floor((Date.now() - targetMs) / 1000));
    }
  }

  // Human-readable elapsed duration: "5 minutes ago", "30s ago".
  const ago = text.match(
    /(\d+(?:\.\d+)?)\s*(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d)\s*ago/i
  );

  if (ago) {
    const n = Number(ago[1]);
    const unit = ago[2].toLowerCase();
    const multiplier = /^s/.test(unit) ? 1 :
      /^m/.test(unit) ? 60 :
      /^h/.test(unit) ? 3600 : 86400;
    return Math.max(0, Math.floor(n * multiplier));
  }

  const compact = text.match(/(\d+(?:\.\d+)?)\s*(s|m|h|d)\s*ago/i);
  if (compact) {
    const n = Number(compact[1]);
    const multiplier = { s: 1, m: 60, h: 3600, d: 86400 }[compact[2]];
    return Math.max(0, Math.floor(n * multiplier));
  }

  return null;
}`;

const updated = source.slice(0, start) + replacement + source.slice(end);
const checkFile = '.index-timer-check.js';
fs.writeFileSync(checkFile, updated);

const check = spawnSync(process.execPath, ['--check', checkFile], {
  encoding: 'utf8'
});

fs.unlinkSync(checkFile);

if (check.status !== 0) {
  console.error('SYNTAX CHECK FAILED. Original file was not changed.');
  console.error(check.stderr || check.stdout);
  process.exit(1);
}

const backup = file + '.before-timer-fix-' + Date.now() + '.bak';
fs.copyFileSync(file, backup);
fs.writeFileSync(file, updated);

const finalCheck = spawnSync(process.execPath, ['--check', file], {
  encoding: 'utf8'
});

if (finalCheck.status !== 0) {
  fs.copyFileSync(backup, file);
  console.error('Final syntax check failed. Original file restored.');
  console.error(finalCheck.stderr || finalCheck.stdout);
  process.exit(1);
}

console.log('PASS: Discord timestamp parser fixed.');
console.log('PASS: node --check index.js');
console.log('Backup:', backup);
NODE
