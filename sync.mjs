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

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const OUT_DIR = (() => {
  const arg = process.argv.find((a) => a.startsWith('--out='));
  return arg ? arg.slice('--out='.length) : 'out';
})();

const USER_AGENT = 'GuardSecurityX-AntiVPN/2.0 (+https://github.com/ub01root/securityx-ipdata)';
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

// Cloudflare publishes its anycast proxy/WARP egress ranges as plain CIDR
// lists, updated whenever their anycast network changes. We fetch them
// directly on every run so the guard always has fresh ranges without a
// manual release.
const CLOUDFLARE_SOURCES = [
  { file: 'cloudflare-ipv4.txt', url: 'https://www.cloudflare.com/ips-v4' },
  { file: 'cloudflare-ipv6.txt', url: 'https://www.cloudflare.com/ips-v6' },
];

// Human-curated lists, copied through verbatim. They have no upstream to
// fetch, but they ship in the same release so the guard has exactly one
// refresh URL per dataset. `minEntries` is a regression guard: a truncated or
// mangled file fails the run instead of silently emptying a blocklist.
const CURATED_FILES = [
  { src: 'curated/proxy-asns.txt', out: 'proxy-asns.txt', minEntries: 1, type: 'asn' },
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

// Vendor feeds: direct, authoritative exit-IP data from the VPN providers
// themselves. Each vendor becomes its own output list (and its own provider
// in the guard, for attribution). They are NOT merged into vpn-*.txt: the
// X4BNet ∪ OpenProxyDB union keeps its existing semantics.
const NORD_URL = 'https://api.nordvpn.com/v1/servers?limit=99999';
const PIA_URL = 'https://serverlist.piaservers.net/vpninfo/servers/v6?format=json';

function parseNordServers(text) {
  const ipv4 = new Set();
  const ipv6 = new Set();
  let invalid = 0;
  const arr = JSON.parse(text);
  if (!Array.isArray(arr)) {
    throw new Error('nordvpn: expected a JSON array');
  }

  for (const server of arr) {
    const station = (server?.station ?? '').trim();
    const v6 = (server?.ipv6_station ?? '').trim();

    if (station) {
      if (classify(station) === 4) ipv4.add(station);
      else invalid += 1;
    }
    if (v6 && classify(v6) === 6) ipv6.add(v6);
  }

  return { ipv4, ipv6, invalid };
}

// PIA appends an RSA signature block after the JSON payload (two newlines,
// then base64). We do not verify it — same trust level as every other
// upstream — but we do note its presence in the manifest for later audits.
function parsePiaServers(text) {
  const cut = text.indexOf('\n\n');
  const jsonPart = cut >= 0 ? text.slice(0, cut) : text;
  const signature = cut >= 0 ? 'present' : 'missing';

  const data = JSON.parse(jsonPart);
  const ipv4 = new Set();
  let invalid = 0;

  const regions = data?.regions ?? [];
  for (const region of regions) {
    const groups = region?.servers ?? {};
    for (const group of Object.values(groups)) {
      for (const server of group) {
        const ip = (server?.ip ?? '').trim();
        if (!ip) continue;
        if (classify(ip) === 4) ipv4.add(ip);
        else invalid += 1;
      }
    }
  }

  return { ipv4, ipv6: new Set(), invalid, signature };
}

// Kind of the same contract as X4B_SOURCES: fetch + parse + write one file
// per IP version, min entries enforced so a truncated upstream fails the run.
const VENDOR_FEEDS = [
  { id: 'nordvpn', url: NORD_URL, out: 'vpn-nordvpn', parse: parseNordServers, minEntries: 100 },
  { id: 'pia', url: PIA_URL, out: 'vpn-pia', parse: parsePiaServers, minEntries: 100 },
];

async function main() {
  await mkdir(OUT_DIR, { recursive: true });
  const manifest = {
    generatedAt: new Date().toISOString(),
    generator: 'guard-securityx sync.mjs',
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

  for (const feed of VENDOR_FEEDS) {
    process.stdout.write(`fetching ${feed.url} ... `);
    const { text, meta } = await fetchText(feed.url);
    const { ipv4, ipv6, invalid, signature } = feed.parse(text);

    if (ipv4.size < feed.minEntries) {
      throw new Error(
        `${feed.id}: only ${ipv4.size} IPv4 entries (need >= ${feed.minEntries})`,
      );
    }

    for (const [version, set] of [['ipv4', ipv4], ['ipv6', ipv6]]) {
      const file = `${feed.out}-${version}.txt`;
      const lines = sorted(set);
      // GitHub does not like 0-byte release assets; the guard's txt parser
      // skips comment lines, so an explanatory placeholder is equivalent to
      // an empty list.
      const body = lines.length
        ? `${lines.join('\n')}\n`
        : `# intentionally empty: ${feed.id} exposes no IPv${version === 'ipv4' ? '4' : '6'} addresses\n`;
      await writeFile(join(OUT_DIR, file), body);
      manifest.files[file] = {
        lines: lines.length,
        ipv4: ipv4.size,
        ipv6: ipv6.size,
        invalidLines: invalid,
        contributors: [feed.url],
        ...(signature ? { signature } : {}),
      };
    }

    manifest.sources.push({ ...meta, invalidLines: invalid, ...(signature ? { signature } : {}) });
    console.log(
      `${ipv4.size} ipv4 / ${ipv6.size} ipv6 ranges${invalid ? ` (${invalid} invalid skipped)` : ''}`,
    );
  }

  // Cloudflare publishes its proxy/WARP egress ranges as plain CIDR lists.
  // Fetch directly so the guard always has fresh ranges without a manual release.
  for (const source of CLOUDFLARE_SOURCES) {
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

  for (const file of CURATED_FILES) {
    const text = await readFile(file.src, 'utf8');
    const kept = [];
    const seen = new Set();
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue;
      if (file.type === 'asn') {
        const token = line.replace(/#.*$/, '').trim();
        if (!/^AS\d{1,10}$/i.test(token)) continue;
        const key = token.toUpperCase();
        if (seen.has(key)) continue;
        seen.add(key);
      }
      kept.push(line);
    }
    if (kept.length < file.minEntries) {
      throw new Error(
        `${file.src}: only ${kept.length} valid entries (need >= ${file.minEntries})`,
      );
    }
    await writeFile(join(OUT_DIR, file.out), `${kept.join('\n')}\n`);
    manifest.files[file.out] = {
      lines: kept.length,
      contributors: [file.src],
    };
    console.log(`curated ${file.out}: ${kept.length} entries`);
  }

  manifest.files['manifest.json'] = { generatedAt: manifest.generatedAt };
  await writeFile(join(OUT_DIR, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);

  console.log(`\nwrote ${merged.size} list files + manifest.json to ${OUT_DIR}/`);
}

main().catch((err) => {
  console.error(`sync failed: ${err.message}`);
  process.exit(1);
});
