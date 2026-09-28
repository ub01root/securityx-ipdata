# securityx-ipdata

Self-hosted IP block lists for [securityx-guard](../securityx-guard). A daily
GitHub Action merges open datasets into plain CIDR text files and publishes them
as a release, so the guard never has to scrape anyone's website.

## How it works

`node sync.mjs --out=out` fetches every source, normalizes it, and writes one
file per category + IP version. The workflow then validates the result,
publishes it as a release, and records the manifest in `history/`.

| Output | Category | Source | License |
| --- | --- | --- | --- |
| `vpn-ipv4.txt`, `vpn-ipv6.txt` | vpn | [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn) `output/vpn/` **∪** OpenProxyDB `vpn` column | MIT + CC0-1.0 |
| `datacenter-ipv4.txt`, `datacenter-ipv6.txt` | datacenter | [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn) `output/datacenter/` | MIT |
| `proxy-ipv4.txt`, `proxy-ipv6.txt` | proxy | [NetworkCats/OpenProxyDB](https://github.com/NetworkCats/OpenProxyDB) | CC0-1.0 |
| `tor-ipv4.txt`, `tor-ipv6.txt` | tor | NetworkCats/OpenProxyDB | CC0-1.0 |
| `webhost-ipv4.txt`, `webhost-ipv6.txt` | datacenter | NetworkCats/OpenProxyDB `webhost` column | CC0-1.0 |
| `cdn-ipv4.txt`, `cdn-ipv6.txt` | — (published, not consumed yet) | NetworkCats/OpenProxyDB `cdn` column | CC0-1.0 |
| `proxy-asns.txt` | proxy-asn | curated (`curated/proxy-asns.txt`) | — |
| `manifest.json` | — | generated | — |

Contributions are **unioned, never replaced**: a category present in two
datasets (only `vpn` today) ends up as the union of both. `manifest.json`
records the per-file v4/v6 split and which sources fed each file.

`vpn`/`datacenter` come from X4BNet's `lists_vpn`, which already folds in Apple
Private Relay, Mullvad, PIA and ProtonVPN. `proxy`/`tor`/`webhost` come from
OpenProxyDB, a daily crawl of Wikipedia's proxy-related block lists — treat
`webhost` as noisier than `datacenter`.

`proxy-asns.txt` is the odd one out: it is not ranges but origin AS numbers,
maintained by hand in `curated/proxy-asns.txt` as `AS<number>   # note`, one per
line. It backs the Guard's `proxy-asn` category, which catches proxy pools that
rotate inside a reseller's announcement — the range feeds cannot see those.
Curated, not scraped: a vendor has to be added deliberately.

Related upstream datasets (kept in mind for future categories):
[NetworkCats/IPinfoLite-Download](https://github.com/NetworkCats/IPinfoLite-Download),
[bgp.tools/anycast-prefixes](https://github.com/bgptools/anycast-prefixes),
[NetworkCats/Merged-IP-Data](https://github.com/NetworkCats/Merged-IP-Data)
(the Go merger behind the combined MMDB; we take the block lists instead of its
93 MB `Merged-IP.mmdb` because the guard only needs ranges).

## Consuming

Stable URL — always the newest successful run:

```
https://github.com/ub01root/securityx-ipdata/releases/latest/download/vpn-ipv4.txt
```

Pinned to an exact run:

```
https://github.com/ub01root/securityx-ipdata/releases/download/data-2026.09.27/vpn-ipv4.txt
```

In securityx-guard, each file is one `provider_source` row; the guard's `txt`
parser takes plain CIDR lines, v4 and v6 files are separate rows.

## Guardrails in the workflow

- Every expected list must exist, or the run fails without publishing.
- A list that loses more than half its ranges vs. the previous run is treated
  as an upstream incident (catches truncated downloads / upstream outages).
- `manifest.json` records per-source HTTP status, bytes, ETag, Last-Modified and
  the count of invalid lines that were skipped.

## Running locally

```bash
node sync.mjs            # writes ./out
node sync.mjs --out=/tmp/ipdata
```

Requires Node 20+ and no dependencies.
