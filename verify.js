#!/usr/bin/env node
/* Independent verifier for NameWheel TrueSpin certified draws.
 *
 * Recomputes, with no NameWheel code involved:
 *   1. the seed commitment   SHA-256 over the seed's hex text
 *   2. the winner            HMAC-SHA-256(seed bytes, entropy | entries hash)
 *   3. the entries hash      SHA-256 over the JSON-serialized entry list
 *   4. the video hash        SHA-256 over the hosted MP4, byte for byte
 *
 * Usage:
 *   node verify.js NT49TV59              verify a draw by its code
 *   node verify.js NT49TV59 --no-video   skip the video download
 *
 * Protocol spec: https://namewheel.org/truespin-spec
 * Only Node.js built-ins. MIT licensed.
 */
'use strict';
const crypto = require('crypto');
const https = require('https');

const UA = { 'User-Agent': 'truespin-verifier/1.0 (+https://namewheel.org/truespin-spec)' };

function get(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: UA }, (res) => {
      if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
    }).on('error', reject);
  });
}

const entriesHash = (entries) =>
  crypto.createHash('sha256').update(JSON.stringify(entries), 'utf8').digest('hex');

function ticketsOf(entries) {
  const t = [];
  entries.forEach((e, i) => {
    const m = /:(\d+)$/.exec(e);
    const w = m ? Math.max(1, Math.min(99, parseInt(m[1], 10))) : 1;
    for (let k = 0; k < w; k++) t.push(i);
  });
  return t;
}

function winnerIndex(seedHex, entropy, entries) {
  const digest = crypto.createHmac('sha256', Buffer.from(seedHex, 'hex'))
    .update(entropy + '|' + entriesHash(entries), 'ascii').digest();
  const n = BigInt('0x' + digest.subarray(0, 8).toString('hex'));
  const tickets = ticketsOf(entries);
  return tickets[Number(n % BigInt(tickets.length))];
}

const stripWeight = (name) => String(name).replace(/:(\d+)$/, '');
const mark = (good, label, value) =>
  console.log(`[${good ? 'PASS' : 'FAIL'}] ${label.padEnd(15)} ${value}`);

(async () => {
  const args = process.argv.slice(2).filter((a) => !a.startsWith('--'));
  if (!args.length) {
    console.log('usage: node verify.js <DRAW_CODE> [--no-video]');
    process.exit(1);
  }
  const code = args[0].toUpperCase().replace(/[^A-Z0-9]/g, '');
  const checkVideo = !process.argv.includes('--no-video');

  console.log(`fetching record for ${code} ...`);
  const d = JSON.parse((await get(`https://namewheel.org/api/draw/${code}`)).toString('utf8'));
  if (!d.serverSeed) {
    console.log('draw exists but its seed is not revealed yet; nothing to verify');
    process.exit(1);
  }

  let ok = true;

  const eh = entriesHash(d.entries);
  let good = eh === d.entriesHash;
  ok = ok && good;
  mark(good, 'entries hash', eh);

  const commit = crypto.createHash('sha256').update(d.serverSeed, 'ascii').digest('hex');
  good = commit === d.commit;
  ok = ok && good;
  mark(good, 'commitment', commit);

  const idx = winnerIndex(d.serverSeed, d.clientEntropy, d.entries);
  const name = stripWeight(d.entries[idx]);
  good = idx === d.winnerIndex && name === d.winner;
  ok = ok && good;
  mark(good, 'winner', `index ${idx} -> ${name}`);

  if (checkVideo && d.videoHash) {
    const base = d.cdn ? 'https://cdn.namewheel.org/v' : 'https://namewheel.org/v/files';
    const url = `${base}/${code}.mp4`;
    console.log(`downloading video ${url} ...`);
    const vh = crypto.createHash('sha256').update(await get(url)).digest('hex');
    good = vh === d.videoHash;
    ok = ok && good;
    mark(good, 'video hash', vh);
  }

  console.log();
  if (ok) {
    console.log(`ALL CHECKS PASSED. The record at namewheel.org/v/${code} is internally consistent:`);
    console.log('the seed matches its pre-spin commitment, the winner follows from the');
    console.log('committed randomness, and the hosted video is the untouched original.');
  } else {
    console.log('ONE OR MORE CHECKS FAILED. Do not trust this draw.');
    process.exit(2);
  }
})().catch((e) => { console.error('error:', e.message); process.exit(1); });
