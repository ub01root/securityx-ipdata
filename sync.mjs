#!/usr/bin/env node
// Builds the IP block lists that securityx-guard refreshes from.
//
// Pulls two open datasets, normalizes them into plain CIDR text files (one per
// category and IP version), and writes a manifest with counts + fetch metadata
// so a bad run is visible in the release notes.
//
//   node sync.mjs            # write to ./out
//   node sync.mjs --out=dist # custom output dir
//
// No dependencies: runs on stock Node 20+. Sources are fetched with fetch().

import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const OUT_DIR = (() => {
  const arg = process.argv.find((a) => a.startsWith('--out='));
  return arg ? arg.slice('--out='.length) : 'out';
})();

const USER_AGENT = 'securityx-ipdata/1.0 (+https://github.com/ub01root)';
const TIMEOUT_MS = 120_000;
const MAX_BYTES = 64 * 1024 * 1024;

const X4B_RAW = 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output';
const OPENPROXYDB_CSV =
  'https://github.com/NetworkCats/OpenProxyDB/releases/latest/download/proxy_blocks.csv';

// Datasets we merge. `vpn`/`datacenter` come from X4BNet's lists_vpn (MIT),
// which already folds in Apple Private Relay, Mullvad, PIA and ProtonVPN.
// `proxy`/`tor`/`webhost` come from OpenProxyDB (CC0), a daily crawl of
// Wikipedia's proxy-related block lists.
const X4B_SOURCES = [
  { file: 'vpn-ipv4.txt', url: `${X4B_RAW}/vpn/ipv4.txt` },
  { file: 'vpn-ipv6.txt', url: `${X4B_RAW}/vpn/ipv6.txt` },
  { file: 'datacenter-ipv4.txt', url: `${X4B_RAW}/datacenter/ipv4.txt` },
  { file: 'datacenter-ipv6.txt', url: `${X4B_RAW}/datacenter/ipv6.txt` },
];

async function fetchText(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: { 'User-Agent': USER_AGENT, Accept: 'text/plain,text/csv,*/*' },
      signal: ctrl.signal,
      redirect: 'follow',
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const len = Number(res.headers.get('content-length') ?? '0');
    if (len > MAX_BYTES) throw new Error(`too large: ${len} bytes`);
    const body = await res.text();
    if (body.length > MAX_BYTES) throw new Error(`too large: ${body.length} bytes`);
    return {
      text: body,
      meta: {
        url,
        status: res.status,
        bytes: body.length,
        etag: res.headers.get('etag'),
        lastModified: res.headers.get('last-modified'),
      },
    };
  } finally {
    clearTimeout(timer);
  }
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV6 = /^[0-9a-fA-F:]+$/;

function classify(token) {
  const value = token.trim();
  if (!value) return null;
  const bare = value.includes('/') ? value.split('/')[0] : value;
  if (IPV4.test(bare)) return 4;
  if (bare.includes(':') && IPV6.test(bare)) return 6;
  return null;
}

// Returns { lines, invalid } — invalid lines are counted, never silently kept.
function cleanList(text) {
  const lines = new Set();
  let invalid = 0;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    if (classify(line) === null) {
      invalid += 1;
      continue;
    }
    lines.add(line);
  }
  return { lines: [...lines].sort(), invalid };
}

const TRUTHY = new Set(['true', '1', 'yes', 'y']);

// OpenProxyDB CSV: ip,anonblock,proxy,vpn,cdn,public-wifi,rangeblock,school-block,tor,webhost
// Returns { buckets, invalid } where buckets[category][ipv4|ipv6] is a Set of
// entries, and invalid counts rows whose ip we could not parse.
function parseOpenProxyDb(text) {
  const keys = ['proxy', 'vpn', 'tor', 'webhost', 'cdn'];
  const buckets = new Map(
    keys.map((key) => [key, { ipv4: new Set(), ipv6: new Set() }]),
  );
  let invalid = 0;

  const rows = text.split(/\r?\n/);
  const header = (rows.shift() ?? '').split(',').map((h) => h.trim().toLowerCase());
  const cols = Object.fromEntries(keys.map((key) => [key, header.indexOf(key)]));
  const colIp = header.indexOf('ip');
  if (colIp < 0 || Object.values(cols).some((i) => i < 0)) {
    throw new Error(`unexpected OpenProxyDB header: ${header.join(',')}`);
  }

  for (const row of rows) {
    if (!row.trim()) continue;
    const cells = row.split(',');
    const raw = (cells[colIp] ?? '').trim();
    const version = classify(raw);
    if (version === null) {
      invalid += 1;
      continue;
    }
    for (const key of keys) {
      if (TRUTHY.has((cells[cols[key]] ?? '').trim().toLowerCase())) {
        buckets.get(key)[version === 4 ? 'ipv4' : 'ipv6'].add(raw);
      }
    }
  }
  return { buckets, invalid };
}

function sorted(set) {
  return [...set].sort();
}

async function main() {
  await mkdir(OUT_DIR, { recursive: true });
  const manifest = {
    generatedAt: new Date().toISOString(),
    generator: 'securityx-ipdata sync.mjs',
    sources: [],
    files: {},
  };

  // Union of every upstream contribution, keyed by output file. X4BNet owns
  // vpn/datacenter; OpenProxyDB's `vpn` column is unioned into the vpn list
  // (never a replacement) and it owns proxy/tor/webhost/cdn.
  const merged = new Map();
  const bucket = (file) => {
    let entry = merged.get(file);
    if (!entry) {
      entry = { ipv4: new Set(), ipv6: new Set(), invalid: 0, contributors: [] };
      merged.set(file, entry);
    }
    return entry;
  };

  for (const source of X4B_SOURCES) {
    process.stdout.write(`fetching ${source.url} ... `);
    const { text, meta } = await fetchText(source.url);
    const { lines, invalid } = cleanList(text);
    const entry = bucket(source.file);
    for (const line of lines) {
      (classify(line) === 4 ? entry.ipv4 : entry.ipv6).add(line);
    }
    entry.invalid += invalid;
    entry.contributors.push(meta.url);
    manifest.sources.push({ ...meta, invalidLines: invalid });
    console.log(`${lines.length} ranges${invalid ? ` (${invalid} invalid skipped)` : ''}`);
  }

  process.stdout.write(`fetching ${OPENPROXYDB_CSV} ... `);
  const opdb = await fetchText(OPENPROXYDB_CSV);
  const { buckets, invalid } = parseOpenProxyDb(opdb.text);
  let opdbTotal = 0;
  for (const [key, sets] of buckets) {
    for (const version of ['ipv4', 'ipv6']) {
      const entry = bucket(`${key}-${version}.txt`);
      for (const line of sets[version]) {
        (version === 'ipv4' ? entry.ipv4 : entry.ipv6).add(line);
      }
      entry.contributors.push(`${OPENPROXYDB_CSV}#${key}.${version}`);
      opdbTotal += sets[version].size;
    }
  }
  for (const entry of merged.values()) entry.invalid += invalid;
  manifest.sources.push({ ...opdb.meta, invalidLines: invalid });
  console.log(`${opdbTotal} categorized ranges`);

  for (const [file, entry] of merged) {
    const lines = sorted(entry.ipv4).concat(sorted(entry.ipv6));
    await writeFile(join(OUT_DIR, file), lines.length ? `${lines.join('\n')}\n` : '');
    manifest.files[file] = {
      lines: lines.length,
      ipv4: entry.ipv4.size,
      ipv6: entry.ipv6.size,
      invalidLines: entry.invalid,
      contributors: entry.contributors,
    };
  }

  manifest.files['manifest.json'] = { generatedAt: manifest.generatedAt };
  await writeFile(join(OUT_DIR, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);

  console.log(`\nwrote ${merged.size} list files + manifest.json to ${OUT_DIR}/`);
}

main().catch((err) => {
  console.error(`sync failed: ${err.message}`);
  process.exit(1);
});
