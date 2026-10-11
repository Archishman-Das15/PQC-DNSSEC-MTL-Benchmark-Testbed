# PS-036 — Full Technical Manual
## PQC DNSSEC MTL Benchmark Testbed

**Version:** 1.0 | **Authors:** PS-036 team | **Spec:** AIORI-3 Hackathon Cybersecurity

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture & Topology](#2-architecture--topology)
3. [File Structure](#3-file-structure)
4. [Configuration Files](#4-configuration-files)
5. [How MTL Mode Works Here](#5-how-mtl-mode-works-here)
6. [Wire Format: Condensed Signature & Reference Value](#6-wire-format-condensed-signature--reference-value)
7. [Source Module Reference](#7-source-module-reference)
8. [tb.sh — Complete Command Reference](#8-tbsh--complete-command-reference)
9. [Benchmark Analyses](#9-benchmark-analyses)
10. [Validator Deep Dive](#10-validator-deep-dive)
11. [Zone Signer Deep Dive](#11-zone-signer-deep-dive)
12. [Key & State Management](#12-key--state-management)
13. [Verification Commands Cheatsheet](#13-verification-commands-cheatsheet)
14. [Expected Results & Interpretation](#14-expected-results--interpretation)
15. [Scope Boundaries](#15-scope-boundaries)

---

## 1. Project Overview

This testbed benchmarks two approaches to post-quantum DNSSEC zone signing:

| Mode | Algorithm | ZSK alg# | RRSIG size | Signs per zone |
|---|---|---|---|---|
| `mldsa44` | ML-DSA-44 (FIPS 204) | 200 (lab) | 2420 bytes each | N (one per RRset) |
| `mtl` | ML-DSA-44-MTL-SHAKE-128 | 201 (lab) | ~190 bytes each | 1 (one for the zone) |

Both modes use **ECDSAP256SHA256 (alg 13)** for the KSK — the KSK only signs the DNSKEY RRset. Every DS record linking zones is signed by the PQC ZSK.

The MTL implementation follows:
- **draft-harvey-cfrg-mtl-mode-09** (Verisign Labs, March 2026) — core MTL algorithm
- **draft-fregly-dnsop-slh-dsa-mtl-dnssec-06** (Verisign Labs, March 2026) — DNSSEC encoding

Lab-only algorithm numbers 200/201 are used because IANA has not yet assigned numbers for ML-DSA in DNSSEC.

---

## 2. Architecture & Topology

### Network

All containers share a Docker bridge network: `172.30.53.0/24`

```
┌─────────────────────────────────────────────────────────────────────┐
│                     labnet  172.30.53.0/24                          │
│                                                                     │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐                      │
│  │  root    │    │ tld-lab  │    │ sld-aiori  │                      │
│  │ .10      │    │ .20      │    │ .30      │   PowerDNS Auth 5.0  │
│  │ zone "." │    │ "lab."   │    │"aiori3.test."│   gsqlite3 backend   │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘   presigned mode    │
│       │               │               │                             │
│       └───────────────┴───────────────┘                             │
│                          iterative queries (DO=1)                   │
│                    ┌─────────────┐                                  │
│                    │  resolver   │  PowerDNS Recursor 5.3           │
│                    │  .53        │  process-no-validate              │
│                    │             │  lab root hints                   │
│                    └──────┬──────┘                                  │
│                           │  RD=1                                   │
│                    ┌──────┴──────┐                                  │
│                    │   client    │  pqcdns validator + benchmarks   │
│                    │   .100      │  dig, Python 3.12, liboqs        │
│                    └─────────────┘                                  │
│                                                                     │
│  tools (--profile tools) — one-shot signing, offline benchmarks    │
└─────────────────────────────────────────────────────────────────────┘
```

### Why PowerDNS cannot validate PQC

PowerDNS Authoritative and Recursor do not implement ML-DSA-44 or MTL. This is expected — no production DNS software does yet. The design follows the PS-036 constraint of "no resolver written from scratch":

- **PowerDNS Auth** serves the pre-signed zones exactly as provided (presigned mode)
- **PowerDNS Recursor** does full iterative resolution with DO=1 and caches RRSIG/DNSKEY/DS/NSEC, but runs `process-no-validate` — it fetches DNSSEC records but does not cryptographically validate them
- **pqcdns.validator** (Python, in the client container) performs the full PQC chain-of-trust validation using liboqs for ML-DSA-44 and the custom MTL implementation for path verification

### Delegation chain

```
. (root)
├── DNSKEY: KSK alg 13 (ECDSA) + ZSK alg 200/201 (ML-DSA-44/MTL)
├── NS lab.  →  ns1.nic.lab / 172.30.53.20
└── DS lab.  (signed by root ZSK alg 200/201)

lab.
├── DNSKEY: KSK alg 13 + ZSK alg 200/201
├── NS aiori3.test.  →  ns1.aiori3.test / 172.30.53.30
└── DS aiori3.test.  (signed by lab ZSK alg 200/201)

aiori3.test.
├── DNSKEY: KSK alg 13 + ZSK alg 200/201
├── A records: host00001–hostN, www, mail
├── _mtlladder.aiori3.test TXT  (MTL mode only — carries the signed ladder)
└── All RRSIGs signed by ZSK alg 200/201
```

---

## 3. File Structure

```
pqc-dnssec-mtl-testbed/
├── tb.sh                        ← main orchestration script
├── docker-compose.yml           ← 5-container topology
├── .env                         ← CPU pinning + PowerDNS repo versions
├── requirements.txt             ← Python package pins
│
├── pqcdns/                      ← the PQC library (Python package)
│   ├── __init__.py
│   ├── topology.py              ← IP addresses, zone names, dataset sizes
│   ├── mtl.py                   ← MTL mode core: node set, ladders, auth paths
│   ├── dnssec.py                ← DNSSEC primitives: signing data, key handling
│   ├── signer.py                ← offline zone builder + signer (both modes)
│   ├── validator.py             ← online PQC chain-of-trust validator
│   ├── hints.py                 ← lab root hints generator (from IANA named.root)
│   ├── bench_crypto.py          ← offline sign/verify benchmark (pinned CPU)
│   ├── bench_dns.py             ← live DNS workload benchmark
│   ├── bench_endurance.py       ← ladder endurance: measured vs analytical
│   └── report.py                ← report + figures generator
│
├── docker/
│   ├── auth/
│   │   ├── Dockerfile           ← PowerDNS Auth 5.0 from repo.powerdns.com
│   │   └── entrypoint.sh        ← load-zone, set-presigned, rectify, serve
│   ├── recursor/
│   │   ├── Dockerfile           ← PowerDNS Recursor 5.3
│   │   └── recursor.yml         ← YAML config: process-no-validate, lab hints
│   └── tools/
│       └── Dockerfile           ← Python 3.12 + liboqs 0.16.0 + pqcdns
│
├── scripts/
│   └── env_capture.sh           ← captures hardware + software environment
│
├── docs/
│   ├── DESIGN.md                ← architecture, MTL mapping, pseudocode
│   └── DEMO.md                  ← 10-minute mentor demo script
│
├── zones/                       ← generated zone files (gitignored except .gitkeep)
├── keys/                        ← persistent keys + MTL node set state (gitignored)
├── config/                      ← lab-root.hints (generated by tb.sh setup)
└── results/                     ← benchmark outputs, report, figures
```

---

## 4. Configuration Files

### `.env` — environment and CPU pinning

```bash
# Each value is a Linux cpuset string (passed to docker --cpuset-cpus)
AUTH_CPUS=1       # all 3 auth servers share this core
RESOLVER_CPUS=2   # PowerDNS Recursor
CLIENT_CPUS=3     # client container (dig, validator, live benchmarks)
BENCH_CPUS=3      # offline benchmark (tools container)

# PowerDNS package repository tags (repo.powerdns.com/debian bookworm-<X>)
PDNS_AUTH_REPO=auth-50   # PowerDNS Authoritative 5.0.x
PDNS_REC_REPO=rec-53     # PowerDNS Recursor 5.3.x
```

Why CPU pinning matters: ML-DSA-44 sign takes ~74 µs per operation. With 2011 RRsets in a medium zone, background noise of even 5% adds hundreds of ms to signing time. Pinning eliminates scheduler interference between the benchmark process and the resolver/auth servers.

### `docker-compose.yml` key settings

```yaml
services:
  root:
    cpuset: "${AUTH_CPUS:-1}"       # pinned to one core
    volumes: ["./zones:/zones:ro"]  # read-only: zones are signed offline

  resolver:
    volumes:
      - "./config/lab-root.hints:/etc/powerdns/lab-root.hints:ro"
    depends_on: [root, tld-lab, sld-aiori]   # auth servers must be up first

  client:
    environment:
      RESOLVER_IP: 172.30.53.53
      TRUST_ANCHOR: /zones/root.anchor      # DS record of the root KSK
      ZONES_DIR: /zones
      RESULTS_DIR: /results
      BENCH_CPU: "${CLIENT_CPUS:-3}"

networks:
  labnet:
    ipam: { config: [{ subnet: 172.30.53.0/24 }] }
```

### `docker/recursor/recursor.yml` — critical settings

```yaml
outgoing:
  dont_query: []        # MUST be empty — lab uses RFC1918 IPs
                        # default blocks 10.0.0.0/8, 172.16.0.0/12, etc.
  edns_bufsize: 1232    # DNS Flag Day 2020; forces TCP for large PQC answers

dnssec:
  validation: process-no-validate
  # Fetches and caches RRSIG/DNSKEY/DS/NSEC with DO=1 but does NOT
  # validate — PowerDNS has no ML-DSA implementation.

recursor:
  hint_file: /etc/powerdns/lab-root.hints
  # Primes the cache by querying ". NS" to the lab root server,
  # then walks the real delegation chain root -> lab -> aiori3.test.
```

### `docker/auth/entrypoint.sh` key logic

```bash
# Every auth container does this at startup:
pdnsutil load-zone    "$ZONE_NAME" "$ZONE_FILE"   # import pre-signed zone into SQLite
pdnsutil set-presigned "$ZONE_NAME"               # tell PDNS: use RRSIGs as-is
pdnsutil rectify-zone  "$ZONE_NAME"               # fix NSEC ordering in DB
exec pdns_server --config-dir="$CONF_DIR"         # start the DNS server
```

Pre-signed mode means PowerDNS serves RRSIG/NSEC/DNSKEY records exactly as written in the zone file. It does not attempt to sign with its own keys.

---

## 5. How MTL Mode Works Here

### 5.1 Core concept

Instead of signing each DNS RRset individually with ML-DSA-44 (N signatures for N RRsets), MTL mode:

1. Hashes each RRset's signing data into a **leaf node** of a Merkle tree
2. Builds the tree incrementally (the **node set**)
3. Extracts a **ladder** — the set of subtree roots covering all leaves
4. Signs the ladder **once** with ML-DSA-44
5. For each RRset, stores only the **authentication path** (log2(N) hashes from the leaf to the ladder rung)

A verifier recomputes the leaf hash from the RRset, walks the authentication path, reaches the rung, and compares it to the cached signed ladder — without touching ML-DSA-44 again.

### 5.2 Parameters in this implementation

| Parameter | Value | Source |
|---|---|---|
| Security parameter n | 16 bytes | draft-harvey-cfrg-mtl-mode-09 §4.1 (level I) |
| SID length | 32 bytes (= 2n) | draft §6.1 |
| Hash function | cSHAKE128 | draft §11.1 (SHAKE instantiation) |
| Context string (OID_MTL) | `MTL-MODE:ML-DSA-44-MTL-SHAKE-128` | lab-defined (draft leaves abstract) |
| ADRS(L,R) | L (8 bytes BE) \|\| R (8 bytes BE) | draft §6.2 |
| Rung strategy | binary rung | draft §6.6 |
| Underlying signature | ML-DSA-44 (FIPS 204) | draft §10 |

### 5.3 Hash functions

**H_leaf** (for leaf nodes):
```
H_leaf(SID, L, R, Rand, ctx, msg) =
    cSHAKE128(SID || ADRS(L,R) || Rand || OLEN(ctx) || ctx || msg,
              outputlen=128 bits,
              customization=OID_MTL)
```

**H_int** (for internal nodes):
```
H_int(SID, L, R, H_left, H_right) =
    cSHAKE128(SID || ADRS(L,R) || H_left || H_right,
              outputlen=128 bits,
              customization=OID_MTL)
```

The customization string `OID_MTL` is fed into cSHAKE's built-in domain separation — every MTL hash is cryptographically separated from every non-MTL use of cSHAKE128.

### 5.4 What goes into each leaf

The "message" signed into a leaf is the **RFC 4034 §3.1.8.1 signing data**:

```
signing_data = RRSIG_header_wire || canonical_RRset_wire

RRSIG_header_wire =
    type_covered (2B) || algorithm (1B) || labels (1B) ||
    original_ttl (4B) || expiration (4B) || inception (4B) ||
    key_tag (2B) || signer_name (wire)

canonical_RRset_wire =
    for each RR (sorted, deduped):
        owner_name (canonical wire) || type (2B) || class (2B) ||
        original_ttl (4B) || rdlength (2B) || rdata (canonical wire)
```

This is the same data that would be signed directly in plain DNSSEC. MTL just hashes it into a leaf and signs the tree root instead of signing each one individually.

### 5.5 Binary rung strategy

The ladder for N messages uses the binary representation of N to decide rung positions:

```
N = 14 = 8 + 4 + 2 = 2³ + 2² + 2¹

Ladder Λ₁₄ has 3 rungs:
  rung[0]: V[0:7]   (root of left-most perfect binary tree, 8 leaves)
  rung[1]: V[8:11]  (root of next tree, 4 leaves)
  rung[2]: V[12:13] (root of last tree, 2 leaves)
```

Maximum rung count = ⌈log₂(N)⌉. For small dataset (100 host records + 13 infrastructure = 213 leaves), the ladder has at most 8 rungs.

### 5.6 Backward compatibility

When the zone evolves (new records added, N increases), the authentication path for an **old** leaf (index i) can still be verified against the **old** ladder Λ_N₀ even though the path was computed relative to the **new** ladder Λ_N, provided:

```
i < N₀ ≤ N
```

This is because the authentication path recomputes intermediate nodes on its way up to the rung. If the target rung of the new path is an **ancestor** of a rung in the old ladder, the path verification naturally recomputes that old rung as an intermediate step — and the old ladder can verify it.

In practice: after `./tb.sh evolve 25` adds 25 new records, all existing records' condensed signatures remain valid against the old cached ladders. Only records with indices beyond N₀ need a new ladder fetch. This is demonstrated live by `./tb.sh demo-evolve`.

### 5.7 Signing flow (MTL mode)

```
signer.py: sign_zone(..., mode='mtl')

1. Build the zone: add DNSKEY, DS, NSEC chain
2. Load MTL state (node set + leaf map) from keys/<zone>/mtl-state.json
   OR create a fresh node set with a random SID
3. For each RRset R that is new or changed:
      leaf_index = node_set.append(signing_data(R))
      leaf_map[R] = {leaf: leaf_index, digest: sha256(R)}
4. Also append the signing data for _mtlladder.<zone> TXT
5. Compute the ladder Λ = node_set.ladder()
6. Sign the ladder: σΛ = ML-DSA-44.sign(sk, Λ.to_bytes(), ctx=OID_MTL)
7. For each RRset R:
      auth_path = node_set.authpath(leaf_map[R].leaf)
      if R == _mtlladder TXT:
          rrsig.signature = 0x01 || SID || auth_path || Λ || len(σΛ) || σΛ  (FULL)
      else:
          rrsig.signature = 0x00 || SID || auth_path                         (CONDENSED)
8. KSK signs DNSKEY with ECDSA P-256
9. Save updated node_set + leaf_map to keys/<zone>/mtl-state.json
```

### 5.8 Verification flow (MTL mode)

```
validator.py: Validator._verify_pqc(rrset, sig, zsk)

sig.signature[0] == 0x00 → CONDENSED:
    parse: SID, auth_path
    search cached ladders[SID] for a compatible rung
    if found:
        mtl_verify(signing_data(rrset), auth_path, rung)  → True/False
    else:
        fetch _mtlladder.<zone> TXT (FULL signature) over TCP
        verify the ladder with ML-DSA-44
        cache the ladder in self.ladders[SID]
        retry

sig.signature[0] == 0x01 → FULL:
    parse: SID, auth_path, signed_ladder (Λ + σΛ)
    ML-DSA-44.verify(zsk.key, Λ.to_bytes(), σΛ, ctx=OID_MTL)
    cache Λ in self.ladders[SID]
    mtl_verify(signing_data(rrset), auth_path, rung from Λ)
```

---

## 6. Wire Format: Condensed Signature & Reference Value

### How to see them live

```bash
# Switch to MTL mode first
./tb.sh sign mtl small && ./tb.sh reload

# Run the hexdump decoder
docker compose exec client bash -c "
python3 << 'EOF'
import dns.query, dns.message, dns.rdatatype as T

ZONE = '172.30.53.30'

def query(name, rdtype, tcp=False):
    q = dns.message.make_query(name, rdtype, want_dnssec=True, payload=1232)
    fn = dns.query.tcp if tcp else dns.query.udp
    return fn(q, ZONE, timeout=5, ignore_trailing=True)

def hexdump(data, label):
    print(f'\n=== {label} ({len(data)} bytes) ===')
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        asc_part = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
        print(f'  {i:04x}  {hex_part:<47}  {asc_part}')

for section in query('host00001.aiori3.test', T.A).answer + query('host00001.aiori3.test', T.A).authority:
    for rd in section:
        if hasattr(rd, 'algorithm') and rd.algorithm == 201:
            hexdump(rd.signature, 'CONDENSED SIGNATURE (RRSIG host00001.aiori3.test A)')

for section in query('_mtlladder.aiori3.test', T.TXT, tcp=True).answer + query('_mtlladder.aiori3.test', T.TXT, tcp=True).authority:
    for rd in section:
        if hasattr(rd, 'algorithm') and rd.algorithm == 201:
            hexdump(rd.signature, 'FULL SIGNATURE / REFERENCE VALUE (_mtlladder.aiori3.test TXT)')
EOF
"
```

### 6.1 Condensed Signature wire layout (~189 bytes)

```
Byte offset  Size   Field
──────────────────────────────────────────────────────────────────────
0x0000       1 B    MTL-Type = 0x00   ← CONDENSED (0 = condensed, 1 = full)
0x0001      32 B    SID               ← Series Identifier (random 32 bytes)
                                         uniquely identifies this signing series
0x0021       2 B    flags = 0x0000    ← reserved, always zero
0x0023      16 B    Randomizer        ← random salt used when this RRset
                                         was hashed into the node set
0x0033       8 B    leaf_index        ← which leaf this RRset occupies
                                         (big-endian uint64, 0-based)
0x003B       8 B    rung_left         ← left index of the target rung
0x0043       8 B    rung_right        ← right index of the target rung
                                         rung covers leaves [rung_left..rung_right]
0x004B       2 B    sibling_hash_count← number of hashes in the auth path
                                         = bit_width(rung_right - rung_left)
                                         = log2(rung span) for a perfect binary tree
0x004D  N×16 B    sibling_hashes     ← authentication path
                                         sibling[0] = sibling of the leaf
                                         sibling[k] = sibling of the node
                                           spanning 2^k leaves including leaf_index
                                         each hash is 16 bytes (cSHAKE128, n=16)
──────────────────────────────────────────────────────────────────────
TOTAL: 1 + 32 + 2 + 16 + 8 + 8 + 8 + 2 + (N × 16) bytes
       For small dataset (128-leaf rung, N=7):  1+32+2+16+24+2+112 = 189 bytes
```

Annotated example (small dataset, leaf_index=0, rung [0:127]):
```
  0000  00                                              ← MTL-Type: CONDENSED
  0001  92 b6 40 08 6f 3a 5a 59  b4 cc ef bf 16 f7 aa  ← SID bytes 0-15
  0011  aa 34 af 32 ae 25 fa 4c  4d 2e de 32 b7 b5 1a  ← SID bytes 16-30
  0021  f4 15                                           ← SID bytes 31-32 + flags start
  0021  f4 15 00 00                                     ← last 2 of SID, then flags=0x0000
  0025  a3 f2 1c 8d 9b 4e 7f 2a  1d 6c 8e 3b c2 11 d4  ← Randomizer (16 bytes)
  0035  5e
  0036  00 00 00 00 00 00 00 00                         ← leaf_index = 0
  003e  00 00 00 00 00 00 00 00                         ← rung_left  = 0
  0046  00 00 00 00 00 00 00 7f                         ← rung_right = 127
  004e  00 07                                           ← 7 sibling hashes
  0050  3d 4a 8c 1f 9b 2e 7a 3c  d1 5f 8e 2a 4b 9c 1d  ← sibling[0] 16 bytes
  0060  6f 3e ...                                       ← sibling[1] 16 bytes
  ...                                                   ← siblings[2..6]
  00b8  [last sibling, 16 bytes]                        ← sibling[6]
  0000: total 189 bytes
```

### 6.2 Full Signature / Reference Value wire layout (~2910 bytes)

```
Byte offset  Size   Field
──────────────────────────────────────────────────────────────────────
             ── Auth path section (same layout as condensed) ──
0x0000       1 B    MTL-Type = 0x01   ← FULL
0x0001      32 B    SID
0x0021       2 B    flags
0x0023      16 B    Randomizer        ← for the _mtlladder TXT leaf itself
0x0033       8 B    leaf_index        ← leaf index of _mtlladder TXT RRset
0x003B       8 B    rung_left
0x0043       8 B    rung_right
0x004B       2 B    sibling_hash_count
0x004D  N×16 B    sibling_hashes

             ── Signed Ladder section (appended after auth path) ──
xxxx         2 B    ladder.flags = 0x0000
xxxx        32 B    ladder.SID         ← same SID as above
xxxx         2 B    ladder.rung_count  ← number of rungs (= bit_width(N))

             ── Per rung (repeated rung_count times) ──
             8 B    rung.left_index    ← uint64 BE
             8 B    rung.right_index   ← uint64 BE
            16 B    rung.hash          ← cSHAKE128 hash of the subtree root
             ── (48 bytes per rung) ──

             ── ML-DSA-44 signature (the ONE underlying PQC sig) ──
xxxx         4 B    sig_length = 2420  ← uint32 BE
xxxx      2420 B    ML-DSA-44 signature bytes
                    (signs the entire ladder wire encoding above)
──────────────────────────────────────────────────────────────────────
TOTAL (small, 4 rungs, N=7 auth path):
  auth path: 1+32+2+16+24+2+(7×16) = 189 bytes
  ladder:    2+32+2+(4×48) = 228 bytes
  sig:       4+2420 = 2424 bytes
  GRAND TOTAL: ~2841–2910 bytes (varies with rung count)
```

Annotated example (4-rung ladder for small dataset):
```
  0000  01                           ← MTL-Type: FULL
  0001  92 b6 40 ...                 ← SID (32 bytes)
  ... [auth path for _mtlladder leaf, same as condensed] ...

  [at offset ~0x00be]
  ── LADDER STARTS ──
  00 00                              ← ladder.flags = 0
  92 b6 40 08 6f 3a ...             ← ladder.SID (32 bytes, same as above)
  00 04                              ← rung_count = 4 rungs

  ── rung[0]: covers leaves 0–127 ──
  00 00 00 00 00 00 00 00           ← left_index  = 0
  00 00 00 00 00 00 00 7f           ← right_index = 127
  4a 2b 3c 1d 9e 8f 2a 7b          ← hash (16 bytes, cSHAKE128 of subtree)
  c3 5d 4e 1a 8b 9f 2c 6d

  ── rung[1]: covers leaves 128–191 ──
  00 00 00 00 00 00 00 80           ← left  = 128
  00 00 00 00 00 00 00 bf           ← right = 191
  7f 3c 1a 9b 4e 8d 2f 6c          ← hash (16 bytes)
  a1 5e 3b 9d 7f 2a 4c 8e

  ── rung[2]: covers leaves 192–207 ──
  00 00 00 00 00 00 00 c0           ← left  = 192
  00 00 00 00 00 00 00 cf           ← right = 207
  1d 8a 9e 4f 2b 7c 3a 5d          ← hash (16 bytes)
  6e 2b 8f 1a 9c 4d 7e 3b

  ── rung[3]: covers leaves 208–212 ──
  00 00 00 00 00 00 00 d0           ← left  = 208
  00 00 00 00 00 00 00 d4           ← right = 212
  9e 4f 2b 7c 1d 8a 3e 6b          ← hash (16 bytes)
  5a 2c 9f 4d 1e 7b 3a 8c

  ── ML-DSA-44 SIGNATURE ON THE LADDER ──
  00 00 09 74                       ← sig_length = 2420 bytes (0x0974)
  [2420 bytes of ML-DSA-44 signature]
  ← This is the ONE PQC signature for the entire aiori3.test zone.
     Every condensed RRSIG in the zone is verifiable via this single signature.
```

---

## 7. Source Module Reference

### `pqcdns/topology.py` (16 lines)
Defines all IP addresses, nameserver names, TTL, and dataset sizes. All other modules import from here. Override with environment variables for testing.

```python
ROOT_IP    = "172.30.53.10"    DATASETS = {
TLD_IP     = "172.30.53.20"      "small":  100,    # host RRsets in aiori3.test
SLD_IP     = "172.30.53.30"      "medium": 1000,
RESOLVER_IP = "172.30.53.53"     "large":  10000
}
```

### `pqcdns/mtl.py` (278 lines)
Core MTL implementation. Implements draft-harvey-cfrg-mtl-mode-09 Algorithms 1–8 exactly.

| Function/Class | Draft Algo | Purpose |
|---|---|---|
| `H_leaf()` | Alg 1 | Hash RRset signing data into leaf node |
| `H_int()` | Alg 2 | Hash two child nodes into internal node |
| `MTLNS.append()` | Alg 4 | Add message to node set, update tree |
| `MTLNS.authpath()` | Alg 5 | Compute authentication path to current ladder |
| `MTLNS.ladder()` | Alg 6 | Extract binary rung strategy ladder |
| `mtl_rung()` | Alg 7 | Find compatible rung in a ladder for an auth path |
| `mtl_verify()` | Alg 8 | Verify auth path against a rung |
| `encode_condensed()` | §9.2 | Serialize condensed signature |
| `encode_full()` | §9.1 | Serialize full signature (with signed ladder) |
| `decode_signature()` | §9.1/9.2 | Parse either type |
| `Ladder`, `Rung`, `AuthPath`, `SignedLadder` | §7.1-7.3, §9.3 | Wire format data structures |

`HASH_COUNTER` is a module-level dict that counts leaf and internal hash operations for benchmark instrumentation. It is reset between benchmark trials.

### `pqcdns/dnssec.py` (144 lines)
DNSSEC building blocks shared between signer and validator.

```python
ALG_ECDSAP256 = 13     # RFC 6605, classical KSK
ALG_MLDSA44   = 200    # lab-only, ML-DSA-44 plain
ALG_MLDSA44_MTL = 201  # lab-only, ML-DSA-44-MTL-SHAKE-128
```

Key functions:
- `signing_data(rrset, ...)` — RFC 4034 §3.1.8.1 canonical signing data
- `MLDSA44.sign(msg, ctx)` — calls `oqs.Signature.sign_with_ctx_str()` (liboqs 0.12+ API)
- `MLDSA44.verify(pk, msg, sig, ctx)` — same
- `ecdsa_sign(priv, data)` / `ecdsa_verify(key, data, sig)` — P-256 via cryptography library
- `make_dnskey(flags, alg, key)` / `make_rrsig(...)` — create DNS resource records

### `pqcdns/signer.py` (349 lines)
Offline zone builder and signer.

**Zone builders:**
- `build_root(serial)` — builds the root zone (NS, SOA, DS for lab)
- `build_lab(serial)` — builds lab zone (NS, SOA, DS for aiori3.test, glue)
- `build_aiori(serial, hosts)` — builds aiori3.test with N host A records

**Zone model (class `Zone`):**
- `Zone.auth_names()` — returns owner names in canonical order (for NSEC)
- `Zone.occluded(name)` — true if name is below a delegation cut (glue)
- `Zone.zsk_signable(name, rdtype)` — true if ZSK should sign this RRset

**`sign_zone(z, mode, ks, now, fresh)`:**
In `mldsa44` mode: iterates every signable RRset, calls `zsk.sign(signing_data(R))` for each.
In `mtl` mode: appends all RRsets to the node set, calls `zsk.sign()` exactly once on the ladder, then writes condensed/full RRSIGs.

**`KeyStore` class:**
- `ksk()` — generates or loads ECDSA P-256 private key from `keys/<zone>/ksk.pem`
- `zsk()` — generates or loads ML-DSA-44 key from `keys/<zone>/zsk-mldsa44.json`
- `load_state()` / `save_state()` — MTL node set + leaf map in `keys/<zone>/mtl-state.json`

### `pqcdns/validator.py` (299 lines)
Online PQC chain-of-trust validator.

**`Validator` class:**

Constructor:
```python
v = Validator(
    resolver="172.30.53.53",   # PowerDNS Recursor IP
    anchor_text="...",          # content of root.anchor (DS record)
    ladder_cache=True,          # cache verified ladders between queries
    timeout=5.0,                # DNS query timeout
    edns_payload=1232           # EDNS buffer size
)
```

Key methods:
- `v.resolve(qname, rdtype)` — full end-to-end: DNS query + PQC validation
- `v.zone_keys_for(zone)` — fetches + validates the DNSKEY RRset for a zone, recursively validating up to the trust anchor
- `v.validate_rrset(rrset, rrsigs)` — validates one RRset's signature
- `v._verify_pqc(rrset, sig, zsk)` — dispatches to ML-DSA-44 or MTL verification
- `v.drop_ladders()` — clears the ladder cache (simulates worst-case with no reuse)
- `v.save_state(path)` / `v.load_state(path)` — persist/restore verified ladders
- `v.reset_stats()` — clear all counters
- `v.cache_footprint()` — returns exact byte sizes of cached ladders and keys

Statistics tracked per query (all additive across calls):
```python
v.s = {
  "queries":           # total DNS queries sent
  "udp_queries":       # UDP attempts
  "tcp_fallbacks":     # queries retried over TCP (TC=1 in UDP response)
  "bytes_tx":          # wire bytes sent
  "bytes_rx":          # wire bytes received
  "ladder_fetches":    # times a new signed ladder was fetched
  "ladder_fetch_bytes":# bytes received for ladder fetches
  "ladder_cache_hits": # times a cached ladder was reused
  "mldsa_verifies":    # ML-DSA-44 verify operations
  "ecdsa_verifies":    # ECDSA P-256 verify operations
  "mtl_path_verifies": # MTL authentication path checks
  "rrsets_validated":  # RRsets whose signatures passed
  "t_mldsa":           # seconds spent in ML-DSA-44 verify
  "t_ecdsa":           # seconds spent in ECDSA verify
  "t_mtl_path":        # seconds spent in MTL path verification
  "t_network":         # seconds spent waiting for DNS responses
}
```

### `pqcdns/bench_crypto.py` (150 lines)
Offline benchmark that does NOT use the network.

For each (dataset, mode) combination across N trials:
1. Builds the aiori3.test zone in memory (no files written)
2. Creates fresh keys in a temp directory
3. Signs the zone (measuring wall time, hash op counts, signature sizes)
4. Verifies every RRSIG as a cold verifier would (measuring wall time, ML-DSA op count)
5. Records per-trial results and computes mean ± stdev

Also runs primitive micro-benchmarks (500 iterations each):
- ML-DSA-44 sign, verify
- ECDSA P-256 sign, verify
- MTL cSHAKE128 node hash

### `pqcdns/bench_dns.py` (149 lines)
Live workload benchmark through the real DNS stack.

Per trial:
1. Flushes the PowerDNS Recursor cache via the REST API
2. Creates a fresh `Validator` (cold start, no cached ladders)
3. Sends Q queries for random `hostNNNNN.aiori3.test` A records (deterministic RNG, same seed = same sequence across modes)
4. For each query: records answer bytes, TCP fallback, latency, crypto time breakdown, ladder fetches
5. Reads recursor statistics via API (cache entries, memory, TCP outqueries)

Key design: the random seed is `seed * 1000 + trial_number`. Across mldsa44 and mtl runs, the same hosts are queried in the same order — "equivalent workloads" as required by PS-036.

With `--no-ladder-cache`: calls `v.drop_ladders()` after every query, forcing a fresh ladder fetch every time. This is the worst-case scenario (K=1, no ladder reuse).

### `pqcdns/bench_endurance.py` (111 lines)
Implements the ladder endurance model from the paper (Section 7.1–7.2).

For each combination of N₀ (initial messages), α (new signs per iteration), ρ (requests per iteration):

**Analytical formula** (from the paper):
```
K_analytic = sqrt(2 ln 2) × sqrt(N₀ × ρ / α)
phi(K,1) = |condensed| + |reference_value| / K
```

**Measured** (using the real implementation):
1. Build a node set with N₀ + (max_iter × α) messages
2. For each of `runs` random trials:
   - The verifier holds the ladder at N₀
   - Each iteration: sign α new messages (advance node set count), then check ρ random condensed signatures against the old ladder using `mtl_rung()`
   - Count iterations until a condensed signature fails (needs a new ladder)
   - That count × ρ = K

Produces: K_measured_median, K_measured_mean, K_measured_p10, K_measured_p90, compared to K_analytic.

### `pqcdns/hints.py` (52 lines)
Downloads IANA `named.root` and produces `config/lab-root.hints` with a single NS record pointing to `a.root-servers.lab / 172.30.53.10`. The file keeps the IANA header comments for traceability. If download fails (firewalled), a built-in template is used.

### `pqcdns/report.py` (190 lines)
Reads all JSON results and writes `results/REPORT.md` plus figures in `results/figures/`.

Strictly separates:
- **Directly measured** (§3): all numbers from actual measurements
- **Analytical estimates** (§4): paper formulas and cache footprint projections

Figures generated (PNG via matplotlib):
- `sign_time.png` — zone signing time per dataset, both modes
- `verify_time.png` — cold verification time per dataset, both modes
- `rrsig_bytes.png` — total RRSIG bytes per zone (log scale)
- `dns_bytes.png` — bytes received per trial in live workload
- `dns_tcp.png` — UDP→TCP fallbacks per trial
- `endurance.png` — K_measured vs K_analytic scatter (log-log)

---

## 8. `tb.sh` — Complete Command Reference

```bash
./tb.sh <command> [args]
```

### `setup`
Checks for Docker, builds all images (tools, auth, recursor), generates `config/lab-root.hints`.
First build compiles liboqs 0.16.0 from source (~5 min). Subsequent builds use Docker cache (~10 sec).

### `sign <mode> <dataset>`
```bash
./tb.sh sign mtl small       # MTL mode, 100 hosts
./tb.sh sign mldsa44 medium  # ML-DSA-44, 1000 hosts
./tb.sh sign mtl large       # MTL mode, 10000 hosts
```
Runs the signer in the `tools` container. Writes signed zones to `zones/`. Stores keys + MTL state in `keys/`. The MTL node set is **stateful** — `sign` with the same mode and existing keys appends to the existing series. Use `evolve` to extend. The `sign` command starts fresh (flag `fresh=True`) — it always creates a new series.

### `up`
Starts root, tld-lab, sld-aiori (auth servers), waits for all three to respond to SOA queries (polls every 2 seconds, 180-second timeout), then starts resolver and client, flushes resolver cache.

### `reload`
Force-recreates just the auth containers (re-imports zones from `zones/`), waits for them, flushes resolver cache. Use after `sign` or `evolve` without restarting the resolver/client.

### `test`
Runs 3 checks from the client container:
1. `dig +dnssec +multi host00001.aiori3.test A` — answer + RRSIG
2. `dig +trace @172.30.53.10 www.aiori3.test A` — full delegation trace
3. `python -m pqcdns.validator host00001.aiori3.test www.aiori3.test` — PQC chain validation

### `validate <names...>`
```bash
./tb.sh validate host00042.aiori3.test www.aiori3.test aiori3.test
./tb.sh validate host00001.aiori3.test --load-state results/verifier-state.json
./tb.sh validate host00001.aiori3.test --save-state results/verifier-state.json
```
Runs `pqcdns.validator` directly. `--load-state` / `--save-state` persist the verified ladder cache to disk (used by `demo-evolve`).

### `dig <args>`
Passes args to `dig` inside the client container. Examples:
```bash
./tb.sh dig +dnssec host00001.aiori3.test A
./tb.sh dig +dnssec +tcp _mtlladder.aiori3.test TXT @172.30.53.30
./tb.sh dig +trace @172.30.53.10 aiori3.test NS
./tb.sh dig +dnssec aiori3.test DS @172.30.53.10
./tb.sh dig +dnssec lab. DNSKEY @172.30.53.20
```

### `evolve [N]`
```bash
./tb.sh evolve 50    # add 50 new host RRsets to the MTL series
```
Extends the zone: reads the current MTL node set state, appends N new records, signs the new (larger) ladder with one ML-DSA-44 operation. Old condensed signatures are refreshed (new auth paths relative to the new ladder, still verifiable against old ladders). Calls `reload` automatically.

### `demo-evolve`
Live backward-compatibility demonstration (requires MTL mode):
1. Validates two records, saves the verified ladders to disk
2. Calls `evolve 25` to add records
3. Validates the same two OLD records — `ladder_fetches=0` (backward compatibility)
4. Validates a NEW record beyond the old ladder — exactly 1 ladder fetch

### `bench-crypto [trials]`
```bash
./tb.sh bench-crypto 5
```
Offline benchmark, no network. Runs in the `tools` container pinned to `BENCH_CPUS`. Tests all 3 dataset sizes × 2 modes × `trials` repetitions. Outputs to `results/crypto/crypto.json`.

### `bench-dns [trials] [queries] [--no-ladder-cache]`
```bash
./tb.sh bench-dns 5 300
./tb.sh bench-dns 5 300 --no-ladder-cache
```
Live workload through the real DNS stack. Zones currently loaded determine the mode. Outputs to `results/dns/<mode>_<dataset>/`.

### `bench-endurance [runs]`
```bash
./tb.sh bench-endurance 200
```
Ladder endurance experiment. No network needed. Outputs to `results/endurance/endurance.json`.

### `bench-all`
Runs everything in sequence: env capture, crypto benchmark for all 3 sizes × 2 modes, DNS benchmark for all sizes × 2 modes (+ no-cache variant), endurance experiment, report generation. Controlled by:
```bash
TRIALS=5 QUERIES=300 RUNS=200 ./tb.sh bench-all
```

### `report`
Reads all JSON results and generates `results/REPORT.md` + `results/figures/*.png`.

### `env`
Captures the pinned environment: CPU model, governor, kernel, Docker version, PowerDNS versions, liboqs version, image IDs. Writes `results/env/environment.json`.

### `shell`
Opens a bash shell inside the client container.

### `flush`
Flushes the PowerDNS Recursor cache via REST API.

### `status`
Shows current zones mode + dataset and `docker compose ps`.

### `logs [service] [lines]`
```bash
./tb.sh logs sld-aiori 50
./tb.sh logs resolver 100
```

### `down` / `clean`
`down`: stops containers. `clean`: stops containers, removes volumes, deletes `zones/` and `keys/` (results kept).

---

## 9. Benchmark Analyses

### 9.1 What can be measured

| Analysis | Command | Output |
|---|---|---|
| Primitive crypto costs | `bench-crypto` | ML-DSA-44 sign/verify µs, ECDSA µs, cSHAKE128 µs |
| Zone signing time | `bench-crypto` | ms per zone, mean ± stdev |
| Cold verify-all time | `bench-crypto` | ms to verify every RRSIG |
| Number of underlying signatures | `bench-crypto` | 1 vs N |
| Mean RRSIG signature size | `bench-crypto` | bytes |
| Total RRSIG bytes per zone | `bench-crypto` | bytes (proxy for zone file size) |
| Hash operations per sign | `bench-crypto` | leaf + internal hash counts |
| Live bytes received per query | `bench-dns` | bytes (wire) |
| UDP→TCP fallback rate | `bench-dns` | per trial |
| Ladder fetches per trial | `bench-dns` | per trial |
| Per-query latency | `bench-dns` | p50, p95 ms |
| Crypto time per query | `bench-dns` | ms split by ML-DSA / ECDSA / MTL path |
| Recursor cache pressure | `bench-dns` | entries Δ, memory Δ |
| Validator cache size | `bench-dns` | ladder bytes, key bytes |
| MTL worst case (no reuse) | `bench-dns --no-ladder-cache` | all metrics with K=1 |
| Ladder endurance K | `bench-endurance` | measured median vs paper formula |
| Effective signature size φ | `bench-endurance` | bytes |

### 9.2 Comparing modes

Always sign and benchmark in this sequence for a fair comparison:

```bash
./tb.sh sign mldsa44 small && ./tb.sh reload && ./tb.sh bench-dns 5 300
./tb.sh sign mtl small     && ./tb.sh reload && ./tb.sh bench-dns 5 300
./tb.sh sign mldsa44 medium && ./tb.sh reload && ./tb.sh bench-dns 5 300
./tb.sh sign mtl medium    && ./tb.sh reload && ./tb.sh bench-dns 5 300
./tb.sh sign mldsa44 large  && ./tb.sh reload && ./tb.sh bench-dns 5 300
./tb.sh sign mtl large     && ./tb.sh reload && ./tb.sh bench-dns 5 300
```

The benchmark seed is fixed so both modes see identical query sequences (same hosts in same order).

### 9.3 What the numbers mean

**`bytes_rx` (live benchmark)**
Wire bytes received by the client per trial. Dominated by RRSIG sizes. MTL is dramatically lower (condensed signatures + 3 ladder fetches) vs ML-DSA-44 (full 2420-byte signatures on every answer via TCP).

**`tcp_fallbacks`**
How many UDP answers hit the 1232-byte limit and had to be retried over TCP. ML-DSA-44: every answer forces TCP (2420-byte RRSIG alone exceeds 1232). MTL: only ladder fetches force TCP (3 per cold start).

**`mldsa_verifies` vs `mtl_path_verifies`**
In ML-DSA-44 mode: one ML-DSA verify per validated RRset. In MTL mode: one ML-DSA verify per zone per session (for the ladder), then only cSHAKE128 hash operations per RRset (counted in `mtl_path_verifies`). This shows ML-DSA-44 verify cost dominates in ML-DSA mode; in MTL mode it appears only at the session start.

**`t_network` vs `t_mldsa`**
In both modes, network latency (DNS round trips) dominates total validation time. The PQC crypto itself is fast (ML-DSA-44 verify ≈ 0.19 ms per operation on a modern CPU).

**`ladder_cache_hits`**
Run two queries back to back (same validator instance):
```python
v.resolve("host00001.aiori3.test")  # fetches 3 ladders
v.resolve("host00002.aiori3.test")  # reuses all 3 → cache_hits=3, mldsa_verifies=0
```
The ladder endurance experiment measures how long this continues before a new ladder is needed.

**`underlying_signs` in signing stats**
```
mldsa44 mode:  underlying_signs = 2013  (one per RRset)
mtl     mode:  underlying_signs = 1     (one for the whole zone)
```
This is the core MTL advantage: the expensive lattice-based operation scales to O(1) per zone signing regardless of zone size.

### 9.4 Cache-use measurements

**Recursor cache** (measured via API):
```bash
# Before benchmark:
curl -s -H 'X-API-Key: labkey' http://172.30.53.53:8082/api/v1/servers/localhost/statistics | \
  python3 -c "import json,sys; d={x['name']:x['value'] for x in json.load(sys.stdin)}; \
  print('cache:', d['cache-entries'], 'packetcache:', d['packetcache-entries'], 'mem:', d['real-memory-usage'])"
```

The recursor caches RRSIG records (including the 2420-byte ML-DSA-44 signatures) in its record cache. ML-DSA-44 mode results in much higher memory consumption per cached record.

**Validator cache** (exact bytes):
```python
v.cache_footprint()
# Returns:
# validator_ladders:       number of distinct cached ladders
# validator_ladder_bytes:  total bytes (just the rung hash values, no ML-DSA sigs)
# validator_key_bytes:     total DNSKEY bytes cached
```
MTL ladders are tiny (just hash values, ~50–200 bytes per zone). ML-DSA-44 mode has no ladder cache because there are no ladders.

---

## 10. Validator Deep Dive

### Chain of trust construction

```
Trust anchor (root.anchor file):
  ". IN DS <tag> 13 2 <digest>"
        ↓
STEP 1: Fetch root DNSKEY → find KSK (flags=257, alg=13)
        Compute DS of the KSK → compare to trust anchor digest
        Verify ECDSA signature on DNSKEY RRset using KSK → proves DNSKEY integrity
        Extract ZSK (flags=256, alg=200 or 201)
        ↓
STEP 2: Fetch lab. DS (from the root zone)
        Verify the DS RRSIG using the root's PQC ZSK
        Fetch lab. DNSKEY → find KSK → compute DS → compare to the DS record above
        Verify ECDSA signature on lab. DNSKEY using lab. KSK
        Extract lab. ZSK
        ↓
STEP 3: Fetch aiori3.test. DS (from the lab. zone)
        Verify the DS RRSIG using lab.'s PQC ZSK
        Fetch aiori3.test. DNSKEY → find KSK → compute DS → compare
        Verify ECDSA signature on aiori3.test. DNSKEY using aiori3.test. KSK
        Extract aiori3.test. ZSK
        ↓
STEP 4: Fetch the answer RRset (e.g., host00001.aiori3.test A)
        Verify the RRSIG:
          ML-DSA-44 mode: directly verify the 2420-byte signature
          MTL mode:
            parse condensed signature (SID + auth_path)
            find a compatible rung in cached ladders[SID]
            if none: fetch _mtlladder.aiori3.test TXT, verify the ML-DSA-44 sig on the ladder
            walk the authentication path up to the rung → SECURE
```

### Run the validator standalone (inside client container)

```bash
docker compose exec client bash

# Basic validation
python -m pqcdns.validator host00042.aiori3.test

# Multiple names (ladder is cached after first)
python -m pqcdns.validator host00001.aiori3.test host00002.aiori3.test host00003.aiori3.test

# Save ladder cache to disk
python -m pqcdns.validator host00001.aiori3.test --save-state /results/ladders.json

# Load saved cache (skips ladder fetches for zones already seen)
python -m pqcdns.validator host00002.aiori3.test --load-state /results/ladders.json

# Query a different record type
python -m pqcdns.validator aiori3.test --qtype MX
python -m pqcdns.validator aiori3.test --qtype TXT

# Use a specific resolver
python -m pqcdns.validator host00001.aiori3.test --resolver 172.30.53.53
```

### Test tamper detection

```bash
docker compose exec client python3 << 'EOF'
import copy, dns.rdata, dns.rdatatype as T
from pqcdns.validator import Validator, ValidationError
import dns.query, dns.message

v = Validator("172.30.53.53", open("/zones/root.anchor").read())

# Get a real answer
msg = dns.query.udp(
    dns.message.make_query("host00001.aiori3.test", T.A, want_dnssec=True),
    "172.30.53.53", timeout=5)

rrs  = next(r for r in msg.answer if r.rdtype == T.A)
sigs = next(r for r in msg.answer if r.rdtype == T.RRSIG)

# Tamper with the A record
bad = copy.deepcopy(rrs)
bad.clear()
bad.add(dns.rdata.from_text(1, T.A, "6.6.6.6"), 3600)

try:
    v.validate_rrset(bad, sigs)
    print("ERROR: tamper not detected")
except ValidationError as e:
    print(f"GOOD: tamper detected → {e}")
EOF
```

---

## 11. Zone Signer Deep Dive

### NSEC chain
Every authoritative name gets an NSEC record pointing to the next name in canonical order. Types covered include `RRSIG` and `NSEC` (always) plus the types actually present at that name. Delegation names get only `NS` and `DS` (no other types are authoritative at a cut).

### Signable RRsets
The signer signs with the ZSK:
- All authoritative RRsets **except** RRSIG and DNSKEY
- DS records at delegation points (authoritative in the parent zone)
- NSEC records

The KSK signs only DNSKEY.

### Serial numbers
The zone serial is the Unix timestamp at signing time. On `evolve`, serial increments by 1.

### Inspect a zone file directly

```bash
# See all record types in the signed zone
grep -v "^;" zones/aiori3.test.zone | awk '{print $4}' | sort | uniq -c | sort -rn

# Count RRSIGs
grep -c "RRSIG" zones/aiori3.test.zone

# See the MTL ladder TXT record
grep "_mtlladder" zones/aiori3.test.zone

# Compare zone sizes
ls -lh zones/*.zone

# See first RRSIG
grep "RRSIG" zones/aiori3.test.zone | head -1

# Check sign stats
cat zones/sign_stats.json | python3 -m json.tool
```

---

## 12. Key & State Management

### Directory structure

```
keys/
├── root/               ← root zone keys
│   ├── ksk.pem         ← ECDSA P-256 private key (keep secret)
│   ├── zsk-mldsa44.json ← ML-DSA-44 keypair {"pk": hex, "sk": hex}
│   └── mtl-state.json  ← MTL node set state (only for MTL mode)
├── lab./
│   ├── ksk.pem
│   ├── zsk-mldsa44.json
│   └── mtl-state.json
├── aiori3.test./
│   ├── ksk.pem
│   ├── zsk-mldsa44.json
│   └── mtl-state.json
└── series.json         ← metadata: mode, dataset, generation, serial
```

### MTL state file (`mtl-state.json`)

```json
{
  "zsk_pk": "hexencoded public key",
  "nodeset": {
    "sid": "32 bytes hex",
    "count": 213,
    "hashes": {
      "0:0": "hash hex",
      "1:1": "hash hex",
      "0:1": "hash hex",
      ...
    },
    "randomizers": {
      "0": "16 bytes hex",
      "1": "16 bytes hex",
      ...
    }
  },
  "leafmap": {
    "host00001.aiori3.test.|A": {
      "leaf": 0,
      "digest": "sha256 of canonical RRset",
      "inc": 1727565016,
      "exp": 1730157016
    },
    ...
  }
}
```

**Critical:** the MTL node set must never be reset or reused with a different SID for the same key. The `evolve` command loads the existing state and appends to it. The `sign` command starts fresh (new SID, new series) — this is correct for a new benchmark run but would break backward compatibility with any cached ladders from a previous series.

### Inspect keys

```bash
# See ML-DSA-44 public key size
cat keys/aiori3.test./zsk-mldsa44.json | python3 -c "import json,sys; d=json.load(sys.stdin); print('pk', len(bytes.fromhex(d['pk'])), 'bytes', 'sk', len(bytes.fromhex(d['sk'])), 'bytes')"

# See MTL series info
cat keys/series.json

# Count leaves in MTL node set
cat keys/aiori3.test./mtl-state.json | python3 -c "import json,sys; d=json.load(sys.stdin); print('leaves:', d['nodeset']['count'], 'hashes stored:', len(d['nodeset']['hashes']))"
```

---

## 13. Verification Commands Cheatsheet

```bash
# ── DNS queries ────────────────────────────────────────────────────────

# Answer + RRSIG for a host
./tb.sh dig +dnssec host00001.aiori3.test A

# Delegation: root signs DS for lab.
./tb.sh dig +dnssec lab. DS @172.30.53.10

# DNSKEY set (KSK alg 13 + ZSK alg 200/201)
./tb.sh dig +dnssec aiori3.test. DNSKEY @172.30.53.30

# Full delegation trace from the lab root
./tb.sh dig +trace @172.30.53.10 host00001.aiori3.test A

# See the signed MTL ladder (FULL signature, large → must use TCP)
./tb.sh dig +dnssec +tcp _mtlladder.aiori3.test TXT @172.30.53.30

# See NSEC record (denial of existence)
./tb.sh dig +dnssec nonexistent.aiori3.test A

# ── Wire format hexdump ────────────────────────────────────────────────

docker compose exec client bash -c "
python3 << 'EOF'
import dns.query, dns.message, dns.rdatatype as T

ZONE = '172.30.53.30'

def query(name, rdtype, tcp=False):
    q = dns.message.make_query(name, rdtype, want_dnssec=True, payload=1232)
    fn = dns.query.tcp if tcp else dns.query.udp
    return fn(q, ZONE, timeout=5, ignore_trailing=True)

def hexdump(data, label):
    print(f'\n=== {label} ({len(data)} bytes) ===')
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        asc_part = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
        print(f'  {i:04x}  {hex_part:<47}  {asc_part}')

for section in query('host00001.aiori3.test', T.A).answer + query('host00001.aiori3.test', T.A).authority:
    for rd in section:
        if hasattr(rd, 'algorithm') and rd.algorithm == 201:
            hexdump(rd.signature, 'CONDENSED SIGNATURE (RRSIG host00001.aiori3.test A)')

for section in query('_mtlladder.aiori3.test', T.TXT, tcp=True).answer + query('_mtlladder.aiori3.test', T.TXT, tcp=True).authority:
    for rd in section:
        if hasattr(rd, 'algorithm') and rd.algorithm == 201:
            hexdump(rd.signature, 'FULL SIGNATURE / REFERENCE VALUE (_mtlladder.aiori3.test TXT)')
EOF
"

# ── PQC chain validation ───────────────────────────────────────────────

./tb.sh validate host00001.aiori3.test
./tb.sh validate host00001.aiori3.test host00002.aiori3.test host00050.aiori3.test

# ── Zone file inspection ───────────────────────────────────────────────

grep -c "RRSIG" zones/aiori3.test.zone
grep "_mtlladder" zones/aiori3.test.zone
cat zones/sign_stats.json | python3 -m json.tool

# ── MTL state inspection ───────────────────────────────────────────────

cat keys/aiori3.test./mtl-state.json | python3 -c "
import json,sys; d=json.load(sys.stdin)
print('SID:', d['nodeset']['sid'][:32], '...')
print('Leaves:', d['nodeset']['count'])
print('Hash nodes stored:', len(d['nodeset']['hashes']))
print('RRsets tracked:', len(d['leafmap']))
"

# ── Recursor stats ─────────────────────────────────────────────────────

curl -s -H 'X-API-Key: labkey' \
  http://172.30.53.53:8082/api/v1/servers/localhost/statistics | \
  python3 -c "
import json,sys
d = {x['name']:x.get('value') for x in json.load(sys.stdin)}
for k in ['cache-entries','packetcache-entries','real-memory-usage',
          'tcp-outqueries','all-outqueries','cache-hits','cache-misses']:
    print(f'{k}: {d.get(k,\"?\")}')"
```

---

## 14. Expected Results & Interpretation

### Signing (offline benchmark)

| Metric | ML-DSA-44 | MTL + ML-DSA-44 |
|---|---|---|
| ML-DSA sign operations | N (one per RRset) | 1 (one per zone) |
| Sign time (small, ~210 RRsets) | ~30 ms | ~30 ms |
| Sign time (large, ~20k RRsets) | ~3000 ms | ~2900 ms |
| Mean RRSIG signature bytes | 2420 B | ~190–290 B |
| Total RRSIG bytes (medium) | ~4.87 MB | ~450 KB |
| Zone file size (large) | ~66 MB | ~10 MB |

Note: sign time is similar because both modes still need to compute the same canonical signing data and hash the RRsets. The difference is N vs 1 ML-DSA-44 operations — but ML-DSA-44 sign (~74 µs) is fast enough that it is not the bottleneck for small/medium zones.

### Verification (offline benchmark)

| Metric | ML-DSA-44 | MTL + ML-DSA-44 |
|---|---|---|
| ML-DSA verify operations | N (per RRset) | 1 (for the ladder) |
| MTL path verifies | 0 | N (log₂ hash ops each) |
| Verify time (small) | ~10 ms | ~24 ms |
| Verify time (large) | ~500 ms | ~2000 ms |

MTL cold-verification is slower because verifying N authentication paths with cSHAKE128 takes more wall time than N ML-DSA-44 verifications when run directly (Python overhead). In practice (live DNS), verification is dominated by network latency, not crypto.

### Live DNS workload

| Metric | ML-DSA-44 | MTL (with cache) | MTL (no cache) |
|---|---|---|---|
| Mean answer bytes | 2521 B (TCP) | 281 B (UDP) | 281 B (UDP) |
| UDP→TCP fallback rate | 100% | ~1% | ~3% |
| Ladder fetches / trial (300 queries) | 0 | 3 | ~303 |
| Bytes received / trial | ~260 KB | ~41 KB | ~342 KB |
| ML-DSA verifies / trial | ~900 | 3 | ~303 |

### Ladder endurance (N₀=10000, α=10, ρ=10)

```
K_measured_median ≈ 133   (a verifier can process ~133 condensed sigs before needing a new ladder)
K_analytic        ≈ 118   (paper formula, good approximation)
phi(K,1)          ≈ 305 B (effective signature size including amortized ladder overhead)
ML-DSA-44 alone   = 2420 B (for comparison)
```

---

## 15. Scope Boundaries

Per PS-036 requirements, this testbed explicitly does NOT:

- **No new cryptography**: ML-DSA-44 is FIPS 204 from liboqs 0.16.0. MTL is draft-harvey-cfrg-mtl-mode-09 from Verisign Labs. No custom cryptographic primitives.
- **No resolver written from scratch**: PowerDNS Recursor handles all DNS resolution. The Python validator handles only PQC signature verification.
- **No Internet deployment**: The lab network (`172.30.53.0/24`) is isolated. Lab-only algorithm numbers 200 and 201 are used (not registered with IANA).
- **No claimed security proof**: Results show operational performance, not security proofs. MTL's security proof is in the Verisign CT-RSA 2023 paper.
- **No new implementation of MTL from scratch for DNSSEC**: The implementation follows the published IETF drafts exactly. Every design decision can be traced to a specific section of the draft.
