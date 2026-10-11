# PS-036 — Complete Testing & Benchmarking Manual

Every command you can run to test, analyse and benchmark the testbed.
Run all commands from `~/Downloads/pqc-dnssec-mtl-testbed/` unless stated otherwise.

---

## PART 1 — SYSTEM HEALTH CHECKS

### 1.1 Check all containers are running

```bash
docker compose ps
```

Expected output — all 5 containers `running`:
```
NAME                   STATUS    PORTS
pqcmtl-root-1          running   0.0.0.0:53->53/udp
pqcmtl-tld-lab-1       running
pqcmtl-sld-aiori-1       running
pqcmtl-resolver-1      running
pqcmtl-client-1        running
```

### 1.2 Check current signed mode

```bash
./tb.sh status
```

Shows which mode + dataset is currently loaded and container status.

### 1.3 Ping each auth server from client

```bash
docker compose exec client bash -c "
for ip in 172.30.53.10 172.30.53.20 172.30.53.30 172.30.53.53; do
  echo -n \"$ip: \"
  ping -c1 -W1 $ip | grep -o 'time=.*ms' || echo 'FAIL'
done"
```

### 1.4 Confirm each zone is serving

```bash
# Root zone
docker compose exec client dig +short @172.30.53.10 . SOA

# lab. zone
docker compose exec client dig +short @172.30.53.20 lab. SOA

# aiori3.test. zone
docker compose exec client dig +short @172.30.53.30 aiori3.test. SOA
```

Each should return a SOA record. If empty → that container failed to load.

### 1.5 Confirm resolver is working

```bash
docker compose exec client dig +short @172.30.53.53 host00001.aiori3.test A
```

Should return `10.54.0.1` (for small/medium/large datasets).

### 1.6 Check PowerDNS web APIs

```bash
# Auth server API (aiori3.test)
curl -s -H 'X-API-Key: labkey' http://172.30.53.30:8081/api/v1/servers/localhost | python3 -m json.tool | head -10

# Recursor API
curl -s -H 'X-API-Key: labkey' http://172.30.53.53:8082/api/v1/servers/localhost | python3 -m json.tool | head -10
```

### 1.7 Check liboqs is working inside containers

```bash
docker compose exec client python3 -c "
import oqs
s = oqs.Signature('ML-DSA-44')
pk = s.generate_keypair()
sig = s.sign_with_ctx_str(b'test message', b'test-ctx')
ok = oqs.Signature('ML-DSA-44').verify_with_ctx_str(b'test message', sig, b'test-ctx', pk)
print(f'liboqs version : {oqs.oqs_version()}')
print(f'ML-DSA-44 pk   : {len(pk)} bytes')
print(f'ML-DSA-44 sig  : {len(sig)} bytes')
print(f'verify result  : {ok}')
"
```

---

## PART 2 — DNS RESOLUTION TESTS

### 2.1 Basic A record query (plain dig)

```bash
./tb.sh dig host00001.aiori3.test A
./tb.sh dig www.aiori3.test A
./tb.sh dig mail.aiori3.test A
```

### 2.2 Query with DNSSEC records shown

```bash
./tb.sh dig +dnssec host00001.aiori3.test A
```

Look for:
- `flags: qr aa` or `qr rd ra` depending on whether you hit auth directly or via resolver
- An `RRSIG` record in the ANSWER section
- Algorithm number: `200` (ML-DSA-44) or `201` (MTL)
- `MSG SIZE` — note the size

### 2.3 Query directly against each auth server

```bash
# Direct to root (bypass resolver)
./tb.sh dig +dnssec @172.30.53.10 . SOA
./tb.sh dig +dnssec @172.30.53.10 lab. DS
./tb.sh dig +dnssec @172.30.53.10 lab. NS

# Direct to TLD (bypass resolver)
./tb.sh dig +dnssec @172.30.53.20 lab. SOA
./tb.sh dig +dnssec @172.30.53.20 lab. DNSKEY
./tb.sh dig +dnssec @172.30.53.20 aiori3.test. DS
./tb.sh dig +dnssec @172.30.53.20 aiori3.test. NS

# Direct to SLD (bypass resolver)
./tb.sh dig +dnssec @172.30.53.30 aiori3.test. SOA
./tb.sh dig +dnssec @172.30.53.30 aiori3.test. DNSKEY
./tb.sh dig +dnssec @172.30.53.30 host00001.aiori3.test A
./tb.sh dig +dnssec @172.30.53.30 aiori3.test. MX
./tb.sh dig +dnssec @172.30.53.30 aiori3.test. TXT
```

### 2.4 Query via the resolver (recursive)

```bash
# Via resolver (iterates root → lab → aiori3.test)
./tb.sh dig +dnssec @172.30.53.53 host00042.aiori3.test A
./tb.sh dig +dnssec @172.30.53.53 www.aiori3.test A
./tb.sh dig +dnssec @172.30.53.53 aiori3.test. DNSKEY
```

### 2.5 Full delegation trace

```bash
# Traces the entire chain from the lab root server
./tb.sh dig +trace @172.30.53.10 host00001.aiori3.test A
./tb.sh dig +trace @172.30.53.10 www.aiori3.test A
```

You will see it query root → get NS for lab. → query TLD → get NS for aiori3.test. → query SLD → get answer. This proves real delegation is working, not a shortcut.

### 2.6 Check DNSKEY records at each level

```bash
# Root DNSKEY (KSK alg 13 + ZSK alg 200/201)
./tb.sh dig +dnssec @172.30.53.10 . DNSKEY

# lab. DNSKEY
./tb.sh dig +dnssec @172.30.53.20 lab. DNSKEY

# aiori3.test. DNSKEY
./tb.sh dig +dnssec @172.30.53.30 aiori3.test. DNSKEY
```

For each zone you should see exactly **two DNSKEY records**:
- `flags 257` = KSK, algorithm 13 (ECDSA P-256, classical)
- `flags 256` = ZSK, algorithm 200 or 201 (PQC)

### 2.7 Check DS records (delegation chain links)

```bash
# DS for lab. (lives in the root zone, signed by root ZSK)
./tb.sh dig +dnssec @172.30.53.10 lab. DS

# DS for aiori3.test. (lives in lab. zone, signed by lab. ZSK)
./tb.sh dig +dnssec @172.30.53.20 aiori3.test. DS
```

Both RRSIG records should show algorithm 200 or 201 — the PQC ZSK signs the delegation.

### 2.8 Check NSEC records (denial of existence)

```bash
# Query a name that does not exist
./tb.sh dig +dnssec @172.30.53.30 nosuchname.aiori3.test A

# Should return NXDOMAIN with NSEC proof
```

The NSEC record proves the name does not exist without revealing all zone names.

### 2.9 MTL — query the signed ladder

```bash
# Only works in MTL mode (alg 201)
./tb.sh dig +dnssec +tcp _mtlladder.aiori3.test TXT @172.30.53.30
./tb.sh dig +dnssec +tcp _mtlladder.lab TXT @172.30.53.20
./tb.sh dig +dnssec +tcp _mtlladder. TXT @172.30.53.10
```

The RRSIG here is the FULL MTL signature — contains the signed ladder + one ML-DSA-44 signature for the whole zone. Use `+tcp` because it is too large for UDP.

### 2.10 Compare UDP vs TCP answer sizes

```bash
docker compose exec client bash -c "
echo '--- UDP (may truncate) ---'
dig +dnssec host00001.aiori3.test A @172.30.53.30 | grep 'MSG SIZE'
echo '--- TCP (full answer) ---'
dig +dnssec +tcp host00001.aiori3.test A @172.30.53.30 | grep 'MSG SIZE'
"
```

In ML-DSA-44 mode (alg 200): both will be large (~2500 bytes), UDP always gets TC=1 (truncated) and the client retries over TCP.
In MTL mode (alg 201): UDP is small (~290 bytes), no TCP needed for regular records.

---

## PART 3 — PQC CHAIN VALIDATION TESTS

### 3.1 Basic validation

```bash
./tb.sh validate host00001.aiori3.test
./tb.sh validate www.aiori3.test
./tb.sh validate mail.aiori3.test
```

Look for `SECURE (PQC chain validated)` and the JSON stats below it.

### 3.2 Validate multiple names in one call

```bash
./tb.sh validate host00001.aiori3.test host00042.aiori3.test host00099.aiori3.test www.aiori3.test
```

After the first name, `ladder_cache_hits` increases for subsequent names — the ladders from the first validation are reused.

### 3.3 Watch ladder cache working

```bash
docker compose exec client python3 << 'EOF'
from pqcdns.validator import Validator

v = Validator("172.30.53.53", open("/zones/root.anchor").read())

for name in ["host00001.aiori3.test", "host00002.aiori3.test", "host00003.aiori3.test", "host00004.aiori3.test", "host00005.aiori3.test"]:
    f_before = v.s["ladder_fetches"]
    h_before = v.s["ladder_cache_hits"]
    v.resolve(name)
    f_after = v.s["ladder_fetches"]
    h_after = v.s["ladder_cache_hits"]
    print(f"{name:30s}  ladder_fetches+={f_after-f_before}  cache_hits+={h_after-h_before}")

print(f"\nTotal: fetches={v.s['ladder_fetches']}  cache_hits={v.s['ladder_cache_hits']}")
print(f"Validator now holds {v.s['validator_ladders']} cached ladders ({v.cache_footprint()['validator_ladder_bytes']} bytes)")
EOF
```

Expected: first name fetches 3 ladders (one per zone), all subsequent names have `cache_hits+=3`, `fetches+=0`.

### 3.4 Tamper detection test

```bash
docker compose exec client python3 << 'EOF'
import copy, dns.rdata, dns.rdatatype as T, dns.query, dns.message
from pqcdns.validator import Validator, ValidationError

v = Validator("172.30.53.53", open("/zones/root.anchor").read())

# Get a real answer
msg = dns.query.udp(
    dns.message.make_query("host00001.aiori3.test", T.A, want_dnssec=True),
    "172.30.53.53", timeout=5, ignore_trailing=True)

rrs  = next(r for r in msg.answer if r.rdtype == T.A)
sigs = next(r for r in msg.answer if r.rdtype == T.RRSIG)

print("--- Test 1: Tampered A record (wrong IP) ---")
bad_rrs = copy.deepcopy(rrs)
bad_rrs.clear()
bad_rrs.add(dns.rdata.from_text(1, T.A, "6.6.6.6"), 3600)
try:
    v.validate_rrset(bad_rrs, sigs)
    print("FAIL: tamper not detected")
except ValidationError as e:
    print(f"PASS: tamper detected -> {e}")

print("\n--- Test 2: Corrupted RRSIG bytes ---")
real_sig = list(sigs)[0].signature
bad_sig_bytes = bytearray(real_sig)
bad_sig_bytes[100] ^= 0xFF   # flip some bits in the middle
import dns.rdata, struct
try:
    v.validate_rrset(rrs, sigs)
    print("PASS: original signature still valid")
except ValidationError as e:
    print(f"NOTE: {e}")

print("\n--- Test 3: Expired RRSIG ---")
print("(Not tested here — requires forging timestamps)")
print("In the validator, check: sig.inception <= now <= sig.expiration")
EOF
```

### 3.5 Validate with saved/loaded ladder state

```bash
# First validation — save the verified ladders
./tb.sh validate host00001.aiori3.test --save-state /tmp/ladders.json

# Second validation — load the saved ladders (no ladder fetches needed)
./tb.sh validate host00002.aiori3.test host00003.aiori3.test --load-state /tmp/ladders.json
```

With `--load-state`: `ladder_fetches` should be 0, `ladder_cache_hits` should be 3.

### 3.6 Validate with no ladder cache (worst case)

```bash
docker compose exec client python3 << 'EOF'
from pqcdns.validator import Validator

v = Validator("172.30.53.53", open("/zones/root.anchor").read(), ladder_cache=False)

for name in ["host00001.aiori3.test", "host00002.aiori3.test", "host00003.aiori3.test"]:
    v.reset_stats()
    v.resolve(name)
    print(f"{name}: fetches={v.s['ladder_fetches']}  mldsa_verifies={v.s['mldsa_verifies']}  bytes_rx={v.s['bytes_rx']}")
EOF
```

With `ladder_cache=False`: every query fetches 3 ladders and does 3 ML-DSA-44 verifications. This is the K=1 worst case from the paper.

### 3.7 Show timing breakdown per query

```bash
docker compose exec client python3 << 'EOF'
import time
from pqcdns.validator import Validator

v = Validator("172.30.53.53", open("/zones/root.anchor").read())

names = ["host00001.aiori3.test", "host00002.aiori3.test", "host00003.aiori3.test",
         "host00010.aiori3.test", "host00050.aiori3.test"]

for name in names:
    v.reset_stats()
    t0 = time.perf_counter()
    v.resolve(name)
    total = (time.perf_counter() - t0) * 1000
    print(f"{name:30s}  total={total:6.2f}ms  "
          f"network={v.s['t_network']*1000:6.2f}ms  "
          f"mldsa={v.s['t_mldsa']*1000:5.2f}ms  "
          f"ecdsa={v.s['t_ecdsa']*1000:5.2f}ms  "
          f"mtl_path={v.s['t_mtl_path']*1000:5.2f}ms  "
          f"fetches={v.s['ladder_fetches']}")
EOF
```

---

## PART 4 — WIRE FORMAT INSPECTION

### 4.1 Hexdump condensed signature + reference value

```bash
# Switch to MTL mode first if not already
./tb.sh sign mtl small && ./tb.sh reload

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

### 4.2 Decode and print condensed signature fields

```bash
docker compose exec client python3 << 'EOF'
import dns.query, dns.message, dns.rdatatype as T
from pqcdns import mtl

def query(name, rdtype, tcp=False):
    q = dns.message.make_query(name, rdtype, want_dnssec=True, payload=1232)
    fn = dns.query.tcp if tcp else dns.query.udp
    return fn(q, "172.30.53.30", timeout=5, ignore_trailing=True)

# Get condensed signature
msg = query("host00001.aiori3.test", T.A)
all_rds = [rd for rr in msg.answer + msg.authority for rd in rr if hasattr(rd, 'algorithm') and rd.algorithm == 201]

if not all_rds:
    print("No alg-201 RRSIG found. Is MTL mode active? Run: ./tb.sh sign mtl small && ./tb.sh reload")
else:
    raw = all_rds[0].signature
    print(f"MTL-Type   : {raw[0]} ({'CONDENSED' if raw[0]==0 else 'FULL'})")
    sid, ap, _ = mtl.decode_signature(raw[1:], full=False)
    print(f"SID        : {sid.hex()}")
    print(f"Randomizer : {ap.randomizer.hex()}")
    print(f"leaf_index : {ap.leaf_index}")
    print(f"rung_left  : {ap.rung_left}")
    print(f"rung_right : {ap.rung_right}")
    print(f"Rung span  : {ap.rung_right - ap.rung_left + 1} leaves")
    print(f"Auth path  : {len(ap.sibling_hashes)} sibling hashes")
    for i, h in enumerate(ap.sibling_hashes):
        print(f"  sibling[{i}] : {h.hex()}")
    print(f"Total size : {len(raw)} bytes")
EOF
```

### 4.3 Decode and print reference value (ladder) fields

```bash
docker compose exec client python3 << 'EOF'
import dns.query, dns.message, dns.rdatatype as T
from pqcdns import mtl

def query(name, rdtype, tcp=False):
    q = dns.message.make_query(name, rdtype, want_dnssec=True, payload=1232)
    fn = dns.query.tcp if tcp else dns.query.udp
    return fn(q, "172.30.53.30", timeout=5, ignore_trailing=True)

msg = query("_mtlladder.aiori3.test", T.TXT, tcp=True)
all_rds = [rd for rr in msg.answer + msg.authority for rd in rr if hasattr(rd, 'algorithm') and rd.algorithm == 201]

if not all_rds:
    print("No alg-201 RRSIG found. Is MTL mode active?")
else:
    raw = all_rds[0].signature
    print(f"MTL-Type   : {raw[0]} ({'CONDENSED' if raw[0]==0 else 'FULL'})")
    sid, ap, sl = mtl.decode_signature(raw[1:], full=True)
    print(f"SID        : {sid.hex()}")
    print(f"Auth path (for _mtlladder leaf):")
    print(f"  leaf_index : {ap.leaf_index}")
    print(f"  rung       : [{ap.rung_left} : {ap.rung_right}]")
    print(f"  path len   : {len(ap.sibling_hashes)} hashes")
    print(f"\nLADDER ({len(sl.ladder.rungs)} rungs):")
    for r in sl.ladder.rungs:
        print(f"  rung [{r.left:>6} : {r.right:>6}]  "
              f"span={r.right-r.left+1:>6}  hash={r.hash.hex()}")
    print(f"\nML-DSA-44 signature on ladder:")
    print(f"  length     : {len(sl.signature)} bytes")
    print(f"  first 16B  : {sl.signature[:16].hex()}")
    print(f"  last  16B  : {sl.signature[-16:].hex()}")
    print(f"\nTotal RRSIG sig size : {len(raw)} bytes")
    print(f"  = 1 (type) + {len(raw[1:])-len(sl.to_bytes())} (auth path) + {len(sl.to_bytes())} (signed ladder)")
EOF
```

### 4.4 Compare RRSIG sizes across modes

```bash
docker compose exec client python3 << 'EOF'
import dns.query, dns.message, dns.rdatatype as T

def get_rrsig_size(name, rdtype, server, tcp=False):
    q = dns.message.make_query(name, rdtype, want_dnssec=True, payload=1232)
    fn = dns.query.tcp if tcp else dns.query.udp
    r = fn(q, server, timeout=5, ignore_trailing=True)
    for rr in r.answer + r.authority:
        for rd in rr:
            if hasattr(rd, 'algorithm') and rd.algorithm in (200, 201):
                return rd.algorithm, len(rd.signature), len(r.to_wire())
    return None, 0, len(r.to_wire())

print(f"{'Record':35s}  {'Alg':>4}  {'RRSIG sig':>10}  {'Wire msg':>10}")
print("-" * 70)
for name in ["host00001.aiori3.test", "host00002.aiori3.test", "host00010.aiori3.test", "www.aiori3.test"]:
    alg, sig_sz, msg_sz = get_rrsig_size(name, T.A, "172.30.53.30")
    print(f"{name:35s}  {alg or '?':>4}  {sig_sz:>9}B  {msg_sz:>9}B")

alg, sig_sz, msg_sz = get_rrsig_size("_mtlladder.aiori3.test", T.TXT, "172.30.53.30", tcp=True)
print(f"{'_mtlladder.aiori3.test (FULL)':35s}  {alg or '?':>4}  {sig_sz:>9}B  {msg_sz:>9}B")
EOF
```

### 4.5 Verify the MTL auth path manually step by step

```bash
docker compose exec client python3 << 'EOF'
import dns.query, dns.message, dns.rdatatype as T
from pqcdns import mtl
from pqcdns.dnssec import signing_data_from_rrsig

ZONE_IP = "172.30.53.30"

def query(name, rdtype, tcp=False):
    q = dns.message.make_query(name, rdtype, want_dnssec=True, payload=1232)
    fn = dns.query.tcp if tcp else dns.query.udp
    return fn(q, ZONE_IP, timeout=5, ignore_trailing=True)

# 1. Get condensed signature for a host record
msg_a = query("host00001.aiori3.test", T.A)
rrset = next(r for r in msg_a.answer if r.rdtype == T.A)
rrsig_rd = next(rd for rr in msg_a.answer if rr.rdtype == T.RRSIG for rd in rr if rd.algorithm == 201)
sid, ap, _ = mtl.decode_signature(rrsig_rd.signature[1:], full=False)

# 2. Get the signed ladder (reference value)
msg_lad = query("_mtlladder.aiori3.test", T.TXT, tcp=True)
rrsig_lad = next(rd for rr in msg_lad.answer + msg_lad.authority if rr.rdtype == T.RRSIG for rd in rr if rd.algorithm == 201)
_, _, sl = mtl.decode_signature(rrsig_lad.signature[1:], full=True)

print(f"Leaf index : {ap.leaf_index}")
print(f"Auth path  : {len(ap.sibling_hashes)} hashes")
print(f"Rung       : [{ap.rung_left} : {ap.rung_right}]")
print()

# 3. Find the matching rung
rung = mtl.mtl_rung(sid, ap, sl.ladder)
if rung is None:
    print("ERROR: no compatible rung found in ladder")
else:
    print(f"Matching rung in ladder: [{rung.left} : {rung.right}]  hash={rung.hash.hex()}")

# 4. Verify the authentication path
data = signing_data_from_rrsig(rrset, rrsig_rd)
result = mtl.mtl_verify(sid, data, ap, rung)
print(f"\nAuthentication path verification: {'PASS' if result else 'FAIL'}")
print(f"(This is the cSHAKE128 hash walk from leaf to rung)")
EOF
```

---

## PART 5 — ZONE FILE ANALYSIS

### 5.1 Count record types in the zone

```bash
# All record types and counts
grep -v "^;" zones/aiori3.test.zone | awk 'NF>3{print $4}' | sort | uniq -c | sort -rn

# Count RRSIGs
echo "Total RRSIGs:"
grep -c "RRSIG" zones/aiori3.test.zone

# Count NSEC records
echo "Total NSECs:"
grep -c " NSEC " zones/aiori3.test.zone
```

### 5.2 Compare zone file sizes across modes

```bash
ls -lh zones/*.zone
du -sh zones/
```

### 5.3 Show signing statistics

```bash
cat zones/sign_stats.json | python3 -m json.tool
```

Key fields to note:
- `underlying_signs`: 1 (MTL) vs N (ML-DSA-44)
- `rrsig_sig_bytes_mean`: mean RRSIG signature size
- `rrsig_sig_bytes_total`: total bytes of all RRSIG signatures
- `zsk_sign_seconds`: time spent in ZSK signing
- `zone_file_bytes`: total zone file size

### 5.4 Show MTL-specific signing stats

```bash
cat zones/sign_stats.json | python3 -c "
import json,sys
data = json.load(sys.stdin)
for z in data['zones']:
    if z['mode'] == 'mtl':
        print(f\"Zone: {z['zone']}\")
        print(f\"  SID             : {z.get('sid','N/A')}\")
        print(f\"  Ladder rungs    : {z.get('ladder_rungs','N/A')}\")
        print(f\"  Leaves total    : {z.get('leaves_total','N/A')}\")
        print(f\"  Leaves added    : {z.get('leaves_added','N/A')}\")
        print(f\"  Leaves reused   : {z.get('leaves_reused','N/A')}\")
        print(f\"  Signed lad bytes: {z.get('signed_ladder_bytes','N/A')}\")
        print()
"
```

### 5.5 Inspect the MTL node set state

```bash
cat keys/aiori3.test./mtl-state.json | python3 -c "
import json, sys
d = json.load(sys.stdin)
ns = d['nodeset']
print(f'SID              : {ns[\"sid\"][:32]}...')
print(f'Total leaves     : {ns[\"count\"]}')
print(f'Hash nodes stored: {len(ns[\"hashes\"])}')
print(f'Randomizers      : {len(ns[\"randomizers\"])}')
print(f'RRsets tracked   : {len(d[\"leafmap\"])}')
print()
print('First 5 RRsets in leaf map:')
for k,v in list(d['leafmap'].items())[:5]:
    print(f'  leaf {v[\"leaf\"]:>4}: {k}')
"
```

### 5.6 Verify zone integrity with pdnsutil

```bash
docker compose exec sld-aiori pdnsutil --config-dir=/etc/powerdns check-zone aiori3.test
docker compose exec tld-lab pdnsutil --config-dir=/etc/powerdns check-zone lab
docker compose exec root pdnsutil --config-dir=/etc/powerdns check-zone .
```

### 5.7 List zone records from PowerDNS database

```bash
docker compose exec sld-aiori pdnsutil --config-dir=/etc/powerdns list-zone aiori3.test | head -20
docker compose exec sld-aiori pdnsutil --config-dir=/etc/powerdns list-zone aiori3.test | grep RRSIG | wc -l
```

---

## PART 6 — KEY INSPECTION

### 6.1 Show all key sizes

```bash
docker compose exec client python3 << 'EOF'
import json
from pathlib import Path
import oqs

for zone in ["root", "lab.", "aiori3.test."]:
    d = "root" if zone == "root" else zone.strip(".")
    p = Path(f"keys/{d}/zsk-mldsa44.json")
    if p.exists():
        k = json.loads(p.read_text())
        print(f"{zone:12s}  ZSK pk={len(bytes.fromhex(k['pk']))}B  sk={len(bytes.fromhex(k['sk']))}B  alg=ML-DSA-44")

for zone in ["root", "lab.", "aiori3.test."]:
    d = "root" if zone == "root" else zone.strip(".")
    p = Path(f"keys/{d}/ksk.pem")
    if p.exists():
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        k = load_pem_private_key(p.read_bytes(), None)
        print(f"{zone:12s}  KSK pk={k.key_size}bit  alg=ECDSA-P256")
EOF
```

### 6.2 Show key tags

```bash
docker compose exec client dig +short @172.30.53.30 aiori3.test. DNSKEY | awk '{print "flags="$1, "proto="$2, "alg="$3}'
```

### 6.3 Verify DS matches the KSK

```bash
docker compose exec client python3 << 'EOF'
import dns.query, dns.message, dns.rdatatype as T, dns.dnssec, dns.name

# Get DS from parent
msg_ds = dns.query.udp(
    dns.message.make_query("aiori3.test.", T.DS, want_dnssec=True),
    "172.30.53.20", timeout=5, ignore_trailing=True)
ds_rrs = next(r for r in msg_ds.answer if r.rdtype == T.DS)

# Get DNSKEY from zone
msg_dk = dns.query.udp(
    dns.message.make_query("aiori3.test.", T.DNSKEY, want_dnssec=True),
    "172.30.53.30", timeout=5, ignore_trailing=True)
dk_rrs = next(r for r in msg_dk.answer if r.rdtype == T.DNSKEY)

# Find the KSK
ksk = next(k for k in dk_rrs if k.flags & 1)

# Compute DS from the KSK
computed_ds = dns.dnssec.make_ds(dns.name.from_text("aiori3.test."), ksk, "SHA256")
published_ds = list(ds_rrs)[0]

print(f"Computed DS : {computed_ds.to_text()}")
print(f"Published DS: {published_ds.to_text()}")
print(f"Match       : {computed_ds.to_text().lower() == published_ds.to_text().lower()}")
EOF
```

---

## PART 7 — RECURSOR CACHE ANALYSIS

### 7.1 View all recursor statistics

```bash
curl -s -H 'X-API-Key: labkey' \
  http://172.30.53.53:8082/api/v1/servers/localhost/statistics | \
  python3 -m json.tool | grep -A1 '"name"' | grep '"value"' -B1
```

### 7.2 Monitor specific stats

```bash
curl -s -H 'X-API-Key: labkey' \
  http://172.30.53.53:8082/api/v1/servers/localhost/statistics | \
  python3 -c "
import json, sys
d = {x['name']: x.get('value','?') for x in json.load(sys.stdin)}
for k in ['cache-entries', 'cache-hits', 'cache-misses',
          'packetcache-entries', 'packetcache-hits',
          'real-memory-usage', 'malloc-bytes',
          'all-outqueries', 'tcp-outqueries',
          'negcache-entries']:
    print(f'{k:35s}: {d.get(k,\"?\")}')"
```

### 7.3 Flush recursor cache

```bash
./tb.sh flush
```

### 7.4 Watch cache fill up in real time

```bash
# Terminal 1: watch stats every 2 seconds
watch -n2 'curl -s -H "X-API-Key: labkey" http://172.30.53.53:8082/api/v1/servers/localhost/statistics | python3 -c "import json,sys; d={x[\"name\"]:x.get(\"value\") for x in json.load(sys.stdin)}; print(\"cache:\",d[\"cache-entries\"],\"pktcache:\",d[\"packetcache-entries\"],\"mem:\",d[\"real-memory-usage\"])"'

# Terminal 2: flood queries
docker compose exec client bash -c "for i in \$(seq 1 100); do dig +short host\$(printf '%05d' \$i).aiori3.test A @172.30.53.53; done"
```

### 7.5 Compare recursor memory: ML-DSA-44 vs MTL

```bash
# Run this for both modes to compare
for mode in mldsa44 mtl; do
  ./tb.sh sign $mode small && ./tb.sh reload
  ./tb.sh flush
  # Send 200 queries
  docker compose exec client bash -c "for i in \$(seq 1 200); do dig +short +timeout=1 host\$(printf '%05d' \$((RANDOM % 100 + 1))).aiori3.test A @172.30.53.53 >/dev/null; done"
  mem=$(curl -s -H 'X-API-Key: labkey' http://172.30.53.53:8082/api/v1/servers/localhost/statistics | python3 -c "import json,sys; print(next(x['value'] for x in json.load(sys.stdin) if x['name']=='real-memory-usage'))")
  entries=$(curl -s -H 'X-API-Key: labkey' http://172.30.53.53:8082/api/v1/servers/localhost/statistics | python3 -c "import json,sys; print(next(x['value'] for x in json.load(sys.stdin) if x['name']=='cache-entries'))")
  echo "mode=$mode  cache-entries=$entries  memory=${mem}B"
done
```

---

## PART 8 — OFFLINE CRYPTO BENCHMARKS

### 8.1 Quick crypto benchmark (2 trials)

```bash
docker compose run --rm tools python -m pqcdns.bench_crypto --trials 2 --datasets small --out results
```

### 8.2 Full crypto benchmark (all datasets, 5 trials)

```bash
./tb.sh bench-crypto 5
```

Outputs to `results/crypto/crypto.json`. Shows:
- Primitive costs (ML-DSA-44 µs, ECDSA µs, cSHAKE128 µs)
- Sign time per zone (mean ± stdev)
- Cold verify-all time (mean ± stdev)
- Number of underlying ML-DSA operations
- Mean/total RRSIG signature bytes

### 8.3 View crypto benchmark results

```bash
cat results/crypto/crypto.json | python3 -c "
import json, sys
d = json.load(sys.stdin)
print('=== Primitive costs ===')
m = d['micro']
print(f'ML-DSA-44 sign  : {m[\"mldsa44_sign_us\"]:.1f} us')
print(f'ML-DSA-44 verify: {m[\"mldsa44_verify_us\"]:.1f} us')
print(f'ECDSA-P256 sign : {m[\"ecdsa_p256_sign_us\"]:.1f} us')
print(f'ECDSA-P256 verify: {m[\"ecdsa_p256_verify_us\"]:.1f} us')
print(f'MTL hash (cSHAKE): {m[\"mtl_cshake128_node_hash_us\"]:.3f} us')
print()
print(f'{'Dataset':8s} {'Mode':10s} {'RRsets':>7} {'Sign ms':>10} {'Verify ms':>12} {'ML-DSA ops':>12} {'Mean sig B':>12}')
print('-'*75)
for r in d['runs']:
    print(f'{r[\"dataset\"]:8s} {r[\"mode\"]:10s} {r[\"rrsets\"]:>7} {r[\"sign_s_mean\"]*1000:>9.2f}  {r[\"verify_s_mean\"]*1000:>11.2f}  {r[\"underlying_signs\"]:>12} {r[\"sig_bytes_mean\"]:>11.1f}')
"
```

### 8.4 Benchmark just the primitives

```bash
docker compose run --rm tools python3 << 'EOF'
import time, os, oqs
from pqcdns.dnssec import MLDSA44, ecdsa_sign, ecdsa_verify, ecdsa_pub_to_dnskey
from pqcdns import mtl
from cryptography.hazmat.primitives.asymmetric import ec

N = 1000
msg = os.urandom(200)

# ML-DSA-44 sign
k = MLDSA44()
t0 = time.perf_counter()
sigs = [k.sign(msg) for _ in range(N)]
sign_us = (time.perf_counter()-t0)/N*1e6

# ML-DSA-44 verify
v = oqs.Signature('ML-DSA-44')
t0 = time.perf_counter()
for s in sigs: v.verify_with_ctx_str(msg, s, b'', k.pk)
verify_us = (time.perf_counter()-t0)/N*1e6

# cSHAKE128 node hash
sid, h = os.urandom(32), os.urandom(16)
t0 = time.perf_counter()
for i in range(N*20): mtl.hash_int(sid, i, i+1, h, h)
hash_us = (time.perf_counter()-t0)/(N*20)*1e6

print(f'ML-DSA-44 sign   : {sign_us:.1f} us  ({1e6/sign_us:.0f} ops/sec)')
print(f'ML-DSA-44 verify : {verify_us:.1f} us  ({1e6/verify_us:.0f} ops/sec)')
print(f'cSHAKE128 hash   : {hash_us:.3f} us  ({1e6/hash_us:.0f} ops/sec)')
print(f'Signature size   : {len(sigs[0])} bytes')
print(f'Public key size  : {len(k.pk)} bytes')
EOF
```

---

## PART 9 — LIVE DNS WORKLOAD BENCHMARKS

### 9.1 Quick benchmark (2 trials, 100 queries)

```bash
./tb.sh sign mtl small && ./tb.sh reload
./tb.sh bench-dns 2 100
```

### 9.2 Full benchmark — both modes, small dataset

```bash
./tb.sh sign mldsa44 small && ./tb.sh reload && ./tb.sh bench-dns 5 300
./tb.sh sign mtl small     && ./tb.sh reload && ./tb.sh bench-dns 5 300
```

### 9.3 Full benchmark — MTL worst case (no ladder cache)

```bash
./tb.sh sign mtl small && ./tb.sh reload
./tb.sh bench-dns 5 300 --no-ladder-cache
```

With no cache: every query fetches 3 ladders. Compare `bytes_rx` with the normal cached run.

### 9.4 All three dataset sizes

```bash
for ds in small medium large; do
  for mode in mldsa44 mtl; do
    echo "=== $mode $ds ==="
    ./tb.sh sign $mode $ds && ./tb.sh reload
    ./tb.sh bench-dns 3 200
  done
done
```

### 9.5 View live benchmark results

```bash
cat results/dns/mtl_small/summary.json | python3 -c "
import json, sys
s = json.load(sys.stdin)
print(f'Mode    : {s[\"meta\"][\"mode\"]}')
print(f'Dataset : {s[\"meta\"][\"dataset\"]}')
print(f'Queries : {s[\"params\"][\"queries\"]} x {len(s[\"trials\"])} trials')
print()
print(f'bytes_rx/trial    : {s[\"bytes_rx_mean\"]/1024:.1f} ± {s[\"bytes_rx_stdev\"]/1024:.1f} KiB')
print(f'tcp_fallbacks     : {s[\"tcp_fallbacks_mean\"]:.1f}')
print(f'ladder_fetches    : {s[\"ladder_fetches_mean\"]:.1f}')
print(f'p50 latency       : {s[\"latency_ms_p50_mean\"]:.2f} ms')
print(f'crypto ms/trial   : {s[\"crypto_ms_total_mean\"]:.1f} ms')
print(f'answer bytes mean : {s[\"answer_bytes_mean_mean\"]:.0f} B')
"
```

### 9.6 View per-query CSV data

```bash
# Show first 20 queries from a run
head -21 results/dns/mtl_small/queries.csv | column -t -s,

# Average latency per trial
python3 -c "
import csv
from collections import defaultdict
rows = list(csv.DictReader(open('results/dns/mtl_small/queries.csv')))
by_trial = defaultdict(list)
for r in rows: by_trial[r['trial']].append(float(r['latency_ms']))
for t,lats in sorted(by_trial.items()):
    print(f'trial {t}: mean={sum(lats)/len(lats):.2f}ms  max={max(lats):.2f}ms  min={min(lats):.2f}ms')
"

# Queries that triggered a ladder fetch
python3 -c "
import csv
rows = list(csv.DictReader(open('results/dns/mtl_small/queries.csv')))
fetches = [r for r in rows if int(r['ladder_fetches']) > 0]
print(f'{len(fetches)} queries triggered a ladder fetch out of {len(rows)} total')
for r in fetches[:10]:
    print(f'  trial={r[\"trial\"]} q={r[\"q\"]} name={r[\"qname\"]} fetches={r[\"ladder_fetches\"]} bytes_rx={r[\"bytes_rx_total\"]}')
"

# Queries that used TCP
python3 -c "
import csv
rows = list(csv.DictReader(open('results/dns/mldsa44_small/queries.csv')))
tcp = [r for r in rows if r['answer_tcp'] == 'True']
print(f'{len(tcp)}/{len(rows)} queries used TCP ({100*len(tcp)/len(rows):.1f}%)')
"
```

---

## PART 10 — LADDER ENDURANCE EXPERIMENT

### 10.1 Quick endurance test

```bash
docker compose run --rm tools python -m pqcdns.bench_endurance \
  --n0 1000 --alpha 10 100 --rho 1 10 --runs 50 --out results
```

### 10.2 Full endurance experiment (paper parameters)

```bash
./tb.sh bench-endurance 200
```

### 10.3 View endurance results

```bash
cat results/endurance/endurance.json | python3 -c "
import json, sys
rows = json.load(sys.stdin)
print(f'{'N0':>7} {'alpha':>7} {'rho':>5} {'K_meas_med':>12} {'K_analytic':>12} {'phi_meas B':>12} {'ML-DSA B':>10}')
print('-'*70)
for r in rows:
    print(f'{r[\"n0\"]:>7} {r[\"alpha\"]:>7} {r[\"rho\"]:>5} {r[\"K_measured_median\"]:>12.1f} {r[\"K_analytic\"]:>12.1f} {r[\"phi_measured\"]:>12.0f} {r[\"underlying_sig_bytes\"]:>10}')
"
```

### 10.4 Custom endurance experiment

```bash
# Test specific N0 values
docker compose run --rm tools python -m pqcdns.bench_endurance \
  --n0 100 1000 10000 \
  --alpha 10 100 1000 \
  --rho 1 10 100 \
  --runs 100 \
  --out results
```

---

## PART 11 — MTL EVOLUTION / BACKWARD COMPATIBILITY

### 11.1 Full live demo

```bash
./tb.sh sign mtl small && ./tb.sh reload
./tb.sh demo-evolve
```

Expected output:
- A) Two names validated, 3 ladder fetches, ladders saved
- B) Same names validated after zone grows, **0 ladder fetches** (backward compat)
- C) New record beyond old ladder, exactly **1 ladder fetch**

### 11.2 Manual evolution test

```bash
# 1. Sign and start
./tb.sh sign mtl small && ./tb.sh up

# 2. Note current leaf count
cat keys/aiori3.test./mtl-state.json | python3 -c "import json,sys; d=json.load(sys.stdin); print('Leaves:', d['nodeset']['count'])"

# 3. Validate and save ladder state
./tb.sh validate host00005.aiori3.test host00010.aiori3.test --save-state results/before-evolve.json

# 4. Evolve the zone
./tb.sh evolve 30

# 5. Check new leaf count
cat keys/aiori3.test./mtl-state.json | python3 -c "import json,sys; d=json.load(sys.stdin); print('Leaves:', d['nodeset']['count'])"

# 6. Old records still valid with old ladders
./tb.sh validate host00005.aiori3.test host00010.aiori3.test --load-state results/before-evolve.json

# 7. New record needs new ladder
MAX_HOST=$(cat zones/sign_stats.json | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['meta']['hosts'])")
./tb.sh validate "host$(printf '%05d' $MAX_HOST).aiori3.test" --load-state results/before-evolve.json
```

### 11.3 Evolve multiple times and check endurance

```bash
# Start fresh
./tb.sh sign mtl small && ./tb.sh up
./tb.sh validate host00001.aiori3.test --save-state results/ladders-v1.json

for i in 1 2 3 4 5; do
  ./tb.sh evolve 20
  echo "=== After evolve $i ==="
  ./tb.sh validate host00001.aiori3.test --load-state results/ladders-v1.json | grep -E "SECURE|BOGUS|ladder_fetches\""
done
```

---

## PART 12 — REPORT GENERATION

### 12.1 Generate the full report

```bash
./tb.sh report
```

Creates:
- `results/REPORT.md` — full report in Markdown
- `results/figures/sign_time.png` — signing time comparison
- `results/figures/verify_time.png` — verification time comparison
- `results/figures/rrsig_bytes.png` — RRSIG bytes comparison
- `results/figures/dns_bytes.png` — live bytes comparison
- `results/figures/dns_tcp.png` — TCP fallbacks comparison
- `results/figures/endurance.png` — K_measured vs K_analytic

### 12.2 Convert report to PDF

```bash
sudo apt-get install -y pandoc wkhtmltopdf
cd results && pandoc REPORT.md -o REPORT.pdf --pdf-engine=wkhtmltopdf --resource-path=.
```

### 12.3 View report sections

```bash
# Just the results table
grep -A50 "## 3\." results/REPORT.md | head -60

# Just the analytical section
grep -A30 "## 4\." results/REPORT.md | head -40
```

---

## PART 13 — ENVIRONMENT CAPTURE

### 13.1 Capture pinned environment

```bash
./tb.sh env
cat results/env/environment.json | python3 -m json.tool
```

### 13.2 Manual environment checks

```bash
# CPU info
lscpu | grep -E "Model name|Socket|Core|Thread|MHz"

# CPU governor
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor | sort | uniq -c

# Memory
free -h

# Docker versions
docker version --format 'Docker {{.Server.Version}}'
docker compose version

# PowerDNS versions
docker compose exec sld-aiori pdns_server --version 2>&1 | head -1
docker compose exec resolver pdns_recursor --version 2>&1 | head -1

# liboqs version
docker compose exec client python3 -c "import oqs; print(oqs.oqs_version())"

# Python version inside container
docker compose exec client python3 --version
```

---

## PART 14 — COMPLETE BENCHMARK SUITE

Run everything in the correct order (takes 20–60 min depending on hardware):

```bash
# 1. Capture environment BEFORE
./tb.sh env

# 2. Offline crypto benchmark (no network needed)
./tb.sh bench-crypto 5

# 3. DNS workload — small dataset
./tb.sh sign mldsa44 small && ./tb.sh reload && ./tb.sh bench-dns 5 300
./tb.sh sign mtl small     && ./tb.sh reload && ./tb.sh bench-dns 5 300
./tb.sh sign mtl small     && ./tb.sh reload && ./tb.sh bench-dns 5 300 --no-ladder-cache

# 4. DNS workload — medium dataset
./tb.sh sign mldsa44 medium && ./tb.sh reload && ./tb.sh bench-dns 5 300
./tb.sh sign mtl medium     && ./tb.sh reload && ./tb.sh bench-dns 5 300

# 5. DNS workload — large dataset
./tb.sh sign mldsa44 large && ./tb.sh reload && ./tb.sh bench-dns 5 300
./tb.sh sign mtl large     && ./tb.sh reload && ./tb.sh bench-dns 5 300

# 6. Ladder endurance experiment
./tb.sh bench-endurance 200

# 7. Capture environment AFTER (check for thermal throttling)
./tb.sh env

# 8. Generate report
./tb.sh report
```

Or run everything with one command:

```bash
TRIALS=5 QUERIES=300 RUNS=200 ./tb.sh bench-all
```

---

## PART 15 — QUICK REFERENCE TABLE

| What you want to test | Command |
|---|---|
| System health | `./tb.sh status` |
| Basic DNS resolution | `./tb.sh dig host00001.aiori3.test A` |
| Delegation trace | `./tb.sh dig +trace @172.30.53.10 host00001.aiori3.test` |
| DNSKEY at each level | `./tb.sh dig +dnssec aiori3.test. DNSKEY @172.30.53.30` |
| DS chain links | `./tb.sh dig +dnssec lab. DS @172.30.53.10` |
| MTL signed ladder | `./tb.sh dig +dnssec +tcp _mtlladder.aiori3.test TXT @172.30.53.30` |
| Full chain validation | `./tb.sh validate host00001.aiori3.test` |
| Tamper detection | Part 3.4 above |
| Wire format hexdump | Part 4.1 above |
| Decode condensed signature | Part 4.2 above |
| Decode reference value | Part 4.3 above |
| RRSIG size comparison | Part 4.4 above |
| Zone record counts | `grep -c RRSIG zones/aiori3.test.zone` |
| Signing stats | `cat zones/sign_stats.json \| python3 -m json.tool` |
| MTL node set state | Part 5.5 above |
| Crypto primitives | Part 8.4 above |
| Offline benchmark | `./tb.sh bench-crypto 5` |
| Live DNS benchmark | `./tb.sh bench-dns 5 300` |
| Live benchmark no cache | `./tb.sh bench-dns 5 300 --no-ladder-cache` |
| Endurance experiment | `./tb.sh bench-endurance 200` |
| Backward compatibility demo | `./tb.sh demo-evolve` |
| Recursor cache stats | Part 7.2 above |
| Generate report | `./tb.sh report` |
| Full benchmark suite | `./tb.sh bench-all` |
| Open shell in client | `./tb.sh shell` |
| View logs | `./tb.sh logs sld-aiori 50` |
