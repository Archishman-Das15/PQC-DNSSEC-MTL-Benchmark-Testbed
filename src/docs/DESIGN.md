# PS-036 — Design, MTL mapping, and pseudocode

## 1. Topology (every component is its own container)

```
                       ┌─────────────────────────────── labnet 172.30.53.0/24 ───────────────────────────────┐
  dig / validator      │                                                                                      │
  ┌────────────┐  RD=1 │  ┌──────────────────────┐  iterative, DO=1   ┌──────────────────────────┐           │
  │ client .100│──────────▶│ resolver .53          │──────────────────▶│ root  "."   (PDNS Auth) .10│          │
  │ (pqcdns)   │◀──────────│ PowerDNS Recursor 5.3 │  hints: lab root  └───────────┬──────────────┘           │
  └────────────┘       │  │ process-no-validate   │                    NS+DS lab. │ glue                      │
                       │  └──────────┬────────────┘                   ┌───────────▼──────────────┐           │
                       │             │                                │ tld  "lab." (PDNS Auth) .20│          │
                       │             │                                └───────────┬──────────────┘           │
                       │             │                         NS+DS aiori3.test.     │ glue                      │
                       │             │                                ┌───────────▼──────────────┐           │
                       │             └───────────────────────────────▶│ sld "aiori3.test." (PDNS Auth).30│         │
                       │                                              └──────────────────────────┘           │
                       └──────────────────────────────────────────────────────────────────────────────────────┘
  tools (one-shot): offline signer, crypto benchmark, endurance experiment, report
```

* **Root hints**: `pqcdns.hints` downloads IANA `named.root` and derives `config/lab-root.hints`
  (same format) pointing at `a.root-servers.lab / 172.30.53.10`. The recursor primes (`. NS`) and
  walks root → lab → aiori3.test exactly as on the Internet.
* **Keys**: KSK = ECDSAP256SHA256 (alg 13, classical) signs only the DNSKEY RRset.
  ZSK = ML-DSA-44 (lab alg 200) **or** ML-DSA-44-MTL-SHAKE-128 (lab alg 201) signs everything else,
  including the DS records that link each level. The chain of trust therefore depends on the PQC
  ZSK at every level.
* **Why PowerDNS runs "presigned" and the recursor runs `process-no-validate`**: neither PowerDNS
  product implements ML-DSA or MTL. The PS forbids writing a resolver from scratch, so PowerDNS
  does all real DNS work (authoritative serving, iterative resolution, caching, UDP→TCP) and the
  PQC-specific verification is done by `pqcdns.validator` on the client, walking the chain of trust
  from the trust anchor.

## 2. How the MTL mode maps onto DNSSEC (following Verisign Labs)

| Verisign concept (paper / drafts) | In this testbed |
|---|---|
| message *m_i* | RFC 4034 §3.1.8.1 signing data of one RRset (RRSIG header ‖ canonical RRset) |
| node set, SID (32 B), n = 16, cSHAKE128, ADRS(L,R) | `pqcdns/mtl.py`, Algorithms 1–8 of draft-harvey-cfrg-mtl-mode-09 |
| batch signing (DNSSEC draft §7) | all RRsets of a zone are appended, then **one** ML-DSA-44 signature on the ladder |
| condensed signature Π<sub>i,N</sub> (+SID) | RRSIG signature field = `0x00 ‖ SID ‖ auth-path` |
| full signature / reference value (ladder + σ(Λ)) | RRSIG of `_mtlladder.<zone> TXT` = `0x01 ‖ SID ‖ auth-path ‖ signed ladder` |
| "request full signature" (mtl-mode-full EDNS option) | validator queries `_mtlladder.<zone> TXT` over TCP (unmodified PowerDNS cannot switch on an EDNS option) |
| backward compatibility (Λ<sub>N'</sub> verifies Π<sub>i,N</sub>, i < N' ≤ N) | `mtl_rung()` compatibility check; `./tb.sh demo-evolve` shows it live |
| series evolution (α new messages/iteration) | `./tb.sh evolve N`: unchanged RRsets keep their leaf; condensed sigs are refreshed against the new ladder |
| endurance K, effective size φ(K,1) | `pqcdns.bench_endurance` — measured with the real code vs the paper's formula |

Lab-only choices (documented so nobody mistakes them for standards): algorithm numbers 200/201,
`OID_MTL` context string value (the draft leaves it abstract), OLEN(ctx) encoded as 1 octet, and the
`_mtlladder` owner name.

## 3. Pseudocode snippet (for the mentor demonstration)

```text
# ---------------- SIGNER (per zone, batch mode) ----------------
SIGN_ZONE(zone, mode):
    add DNSKEY {KSK(ECDSA-P256, flags 257), ZSK(ML-DSA-44, flags 256)}
    add DS for each child (digest of child KSK), add NSEC chain
    if mode == mldsa44:
        for each RRset R (except DNSKEY):
            RRSIG(R) = ML-DSA-44.Sign(sk, SigData(R))            # N underlying signatures
    if mode == mtl:
        NS = state.nodeset or InitNodeSet(SID = random(32 B))  # stateful, never reused
        for each new/changed RRset R:  leaf[R] = NS.Append(SigData(R))   # cSHAKE128 leaf + internal nodes
        leaf[LADDER_TXT] = NS.Append(SigData(_mtlladder TXT))
        Λ  = NS.Ladder()                                        # binary rung strategy
        σΛ = ML-DSA-44.Sign(sk, Λ, ctx = OID_MTL)                # ONE underlying signature
        for each RRset R:   RRSIG(R) = 0x00 || SID || NS.AuthPath(leaf[R])          # condensed
        RRSIG(_mtlladder TXT) = 0x01 || SID || NS.AuthPath(..) || Λ || σΛ            # full
    RRSIG(DNSKEY) = ECDSA-P256.Sign(KSK, SigData(DNSKEY))

# ---------------- VERIFIER (client, via PowerDNS Recursor) ----------------
VALIDATE(R, RRSIG):
    keys = ZONE_KEYS(RRSIG.signer)          # DNSKEY via KSK sig, KSK via parent DS (recursive) or trust anchor
    if alg == ML-DSA-44:  return ML-DSA-44.Verify(keys.zsk, SigData(R), sig)
    type, SID, path = parse(sig)
    if type == FULL:  verify σΛ once with ML-DSA-44 (ctx OID_MTL); cache Λ[SID]
    rung = MTL_RUNG(path, cached Λ[SID])    # compatible rung in ANY previously verified ladder?
    if rung is None:                          # cache miss -> fetch reference value
        FETCH(_mtlladder.<zone> TXT) over TCP; VALIDATE it (FULL); rung = MTL_RUNG(...)
    return MTL_VERIFY(SigData(R), path, rung) # ~log2(N) cSHAKE128 hashes, no lattice op
```

## 4. What is measured and how (maps to "Expected Outcome")

| Expected outcome (PS-036) | Where |
|---|---|
| Pinned benchmark environment | `docker-compose.yml` cpusets, pinned image/package versions, `results/env/environment.json` |
| Benchmark harness | `pqcdns/bench_crypto.py`, `bench_dns.py`, `bench_endurance.py`, `./tb.sh bench-all` |
| MTL and non-MTL workload configurations | `./tb.sh sign mldsa44|mtl <dataset>`; same seeds → identical query sequences |
| Three dataset-size test cases | small = 100, medium = 1 000, large = 10 000 host RRsets (plus infrastructure + NSEC) |
| Repeated-trial measurements | `--trials` (default 5) everywhere; mean ± sd reported |
| Signing and verification performance | offline pinned benchmark (per-zone sign, cold verify-all, primitive costs) + live per-query crypto time |
| Transmitted-byte comparison | client-side wire bytes per query/trial, answer sizes, UDP→TCP fallbacks, ladder-fetch bytes |
| Cache-use measurements and analytical estimates | §3.3 (recursor API stats + validator's exact cache bytes) vs §4 (paper formulas) in REPORT.md |
| Reproducible results report | `results/REPORT.md` + figures + raw CSV/JSON |
| Technical demonstration | `./tb.sh test`, `./tb.sh demo-evolve`, `docs/DEMO.md` |
