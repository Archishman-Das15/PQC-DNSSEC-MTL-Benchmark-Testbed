"""
Offline zone signer for the testbed hierarchy  .  ->  test.  ->  aiori3.test.

  python -m pqcdns.signer sign   --mode {mldsa44,mtl} --dataset {small,medium,large} [--size N]
  python -m pqcdns.signer evolve --add 50          # MTL series grows (paper Sec. 6/7)

Outputs (default ./zones):  root.zone  test.zone  aiori3.test.zone  root.anchor  sign_stats.json
Keys + MTL state (default ./keys) are persistent: the MTL signer is STATEFUL, the SID
and node set must never be reset while the same series is in use.

MTL mode follows Verisign Labs' model:
  * every RRset (except DNSKEY, KSK-signed) becomes a leaf ("message") in the node set,
    the message being the RFC 4034 signing data of the RRset;
  * the zone is batch-signed: ONE ML-DSA-44 signature over the resulting ladder;
  * each RRSIG carries MTL-Type 0 (condensed signature = SID + authentication path);
  * the signed ladder ("reference value") is published as a FULL signature (MTL-Type 1)
    on the RRSIG of the well-known RRset  _mtlladder.<zone>. TXT ;
  * on evolve, unchanged RRsets keep their leaf index; their condensed signatures are
    re-computed relative to the new ladder (condensation) and stay verifiable with the
    OLD ladder (backward compatibility).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from pathlib import Path

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype as T
import dns.rrset
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import mtl
from .dnssec import (ALG_ECDSAP256, LADDER_LABEL, MODE_TO_ALG, MLDSA44, ecdsa_pub_to_dnskey,
                     ecdsa_sign, key_tag, label_count, make_dnskey, make_rrsig, signing_data)
from .topology import (DATASETS, ROOT_IP, ROOT_NS, SLD_IP, SLD_NS, TLD_IP, TLD_NS, TTL)

N = dns.name.from_text
SIG_VALIDITY = 30 * 86400


# ======================================================================= zone model
class Zone:
    def __init__(self, origin: str):
        self.origin = N(origin)
        self.rrsets: dict = {}
        self.cuts: set = set()

    def add(self, name, rdtype, *texts, ttl=TTL):
        name = N(name) if isinstance(name, str) else name
        key = (name, rdtype)
        rrs = self.rrsets.get(key) or dns.rrset.RRset(name, dns.rdataclass.IN, rdtype)
        for t in texts:
            rrs.add(dns.rdata.from_text(dns.rdataclass.IN, rdtype, t) if isinstance(t, str) else t, ttl)
        self.rrsets[key] = rrs
        if rdtype == T.NS and name != self.origin:
            self.cuts.add(name)

    def occluded(self, name) -> bool:              # strictly below a delegation -> glue
        return any(name != c and name.is_subdomain(c) for c in self.cuts)

    def auth_names(self):
        return sorted({n for (n, _) in self.rrsets if not self.occluded(n)})

    def zsk_signable(self, name, rdtype) -> bool:
        if self.occluded(name) or rdtype in (T.RRSIG, T.DNSKEY):
            return False
        if name in self.cuts:
            return rdtype in (T.DS, T.NSEC)
        return True


def soa(zone_ns, serial):
    return f"{zone_ns} hostmaster.aiori3.test. {serial} 7200 3600 1209600 3600"


def build_root(serial):
    z = Zone(".")
    z.add(".", T.SOA, soa(ROOT_NS, serial))
    z.add(".", T.NS, ROOT_NS)
    z.add("test.", T.NS, TLD_NS)
    z.add("lab.", T.NS, TLD_NS)
    z.add(ROOT_NS, T.A, ROOT_IP)           # glue
    z.add(TLD_NS, T.A, TLD_IP)             # glue
    return z


def build_test(serial):
    z = Zone("test.")
    z.add("test.", T.SOA, soa(TLD_NS, serial))
    z.add("test.", T.NS, TLD_NS)
    z.add(TLD_NS, T.A, TLD_IP)
    z.add("www.test.", T.A, "10.20.0.80")
    z.add("aiori3.test.", T.NS, SLD_NS)
    z.add(SLD_NS, T.A, SLD_IP)            # glue
    return z


def build_lab(serial):
    z = Zone("lab.")
    z.add("lab.", T.SOA, soa(TLD_NS, serial))
    z.add("lab.", T.NS, TLD_NS)
    z.add(TLD_NS, T.A, TLD_IP)
    z.add(ROOT_NS, T.A, ROOT_IP)
    z.add("www.lab.", T.A, "10.20.0.80")
    z.add("aiori3.test.", T.NS, SLD_NS)
    z.add(SLD_NS, T.A, SLD_IP)            # glue
    return z


def build_aiori(serial, hosts):
    z = Zone("aiori3.test.")
    z.add("aiori3.test.", T.SOA, soa(SLD_NS, serial))
    z.add("aiori3.test.", T.NS, SLD_NS)
    z.add(SLD_NS, T.A, SLD_IP)
    z.add("aiori3.test.", T.MX, "10 mail.aiori3.test.")
    z.add("aiori3.test.", T.TXT, '"AIORI testbed zone - PQC DNSSEC MTL"')
    z.add("www.aiori3.test.", T.A, "10.53.0.80")
    z.add("mail.aiori3.test.", T.A, "10.53.0.25")
    for i in range(1, hosts + 1):
        z.add(f"host{i:05d}.aiori3.test.", T.A, f"10.{54 + i // 65536}.{(i // 256) % 256}.{i % 256}")
    return z



# ======================================================================= keys / state
class KeyStore:
    def __init__(self, root: Path, zone: str):
        self.dir = root / (zone.strip(".") or "root")
        self.dir.mkdir(parents=True, exist_ok=True)

    def ksk(self):
        p = self.dir / "ksk.pem"
        if not p.exists():
            k = ec.generate_private_key(ec.SECP256R1())
            p.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
            os.chmod(p, 0o600)
        return serialization.load_pem_private_key(p.read_bytes(), None)

    def zsk(self):
        p = self.dir / "zsk-mldsa44.json"
        if p.exists():
            d = json.loads(p.read_text())
            return MLDSA44(bytes.fromhex(d["pk"]), bytes.fromhex(d["sk"]))
        k = MLDSA44()
        p.write_text(json.dumps({"alg": "ML-DSA-44", "pk": k.pk.hex(), "sk": k.sk.hex()}))
        os.chmod(p, 0o600)
        return k

    def load_state(self):
        p = self.dir / "mtl-state.json"
        return json.loads(p.read_text()) if p.exists() else None

    def save_state(self, st):
        (self.dir / "mtl-state.json").write_text(json.dumps(st))


# ======================================================================= signing
def rrset_digest(rrs) -> str:
    from .dnssec import canonical_rrset_wire
    return hashlib.sha256(canonical_rrset_wire(rrs, rrs.ttl)).hexdigest()


def add_nsec_chain(z: Zone):
    names = z.auth_names()
    by_name: dict = {}
    for (nn, t) in z.rrsets:
        by_name.setdefault(nn, set()).add(t)
    for i, n in enumerate(names):
        nxt = names[(i + 1) % len(names)]
        types = set(by_name.get(n, ())) - {T.NSEC}
        if n in z.cuts:
            types &= {T.NS, T.DS}
        types |= {T.RRSIG, T.NSEC}
        bitmap = " ".join(sorted(T.to_text(t) for t in types))
        z.rrsets.pop((n, T.NSEC), None)
        z.add(n, T.NSEC, f"{nxt.to_text()} {bitmap}", ttl=TTL)


def sign_zone(z: Zone, mode: str, ks: KeyStore, now: int, fresh: bool, child_ds=None):
    alg = MODE_TO_ALG[mode]
    ksk, zsk = ks.ksk(), ks.zsk()
    ksk_key = make_dnskey(257, ALG_ECDSAP256, ecdsa_pub_to_dnskey(ksk.public_key()))
    zsk_key = make_dnskey(256, alg, zsk.pk)
    z.add(z.origin, T.DNSKEY, ksk_key, zsk_key)
    if child_ds:
        for cname, ds in child_ds:
            z.add(cname, T.DS, ds)
    ladder_name = dns.name.Name((LADDER_LABEL.encode(),) + z.origin.labels)
    if mode == "mtl":
        z.add(ladder_name, T.TXT, '"placeholder"')
    add_nsec_chain(z)

    ztag, ktag = key_tag(zsk_key), key_tag(ksk_key)
    inception, expiration = now - 3600, now + SIG_VALIDITY
    signed = {}          # (name,type) -> rrsig rdata
    stats = {"zone": z.origin.to_text(), "mode": mode, "alg": alg}

    todo = sorted(k for k in z.rrsets if z.zsk_signable(*k) and k != (ladder_name, T.TXT))

    def hdr(rrs, inc, exp):
        return (rrs.rdtype, alg, label_count(rrs.name), rrs.ttl, exp, inc, ztag, z.origin)

    t0 = time.perf_counter()
    if mode == "mldsa44":
        for k in todo:
            rrs = z.rrsets[k]
            h = hdr(rrs, inception, expiration)
            sig = zsk.sign(signing_data(rrs, *h))
            signed[k] = make_rrsig(*h, sig)
        stats.update(underlying_signs=len(todo), leaves_added=0)
    else:
        st = None if fresh else ks.load_state()
        if st and st.get("zsk_pk") != zsk.pk.hex():
            raise SystemExit("MTL state belongs to another ZSK - refusing (use sign, not evolve)")
        if st:
            ns = mtl.MTLNS.from_json(st["nodeset"])
            leafmap = st["leafmap"]
        else:
            ns = mtl.MTLNS(os.urandom(mtl.SID_LEN))        # fresh SID for a fresh series
            leafmap = {}
        start_count = ns.count
        reuse, new = [], []
        for k in todo:
            key = f"{k[0].to_text()}|{T.to_text(k[1])}"
            e = leafmap.get(key)
            if e and e["digest"] == rrset_digest(z.rrsets[k]):
                reuse.append((k, e))
            else:
                new.append(k)
        final_count = ns.count + len(new) + 1                        # +1 = ladder TXT
        z.rrsets.pop((ladder_name, T.TXT))
        z.add(ladder_name, T.TXT, f'"v=MTL1" "alg=ML-DSA-44-MTL-SHAKE-128" '
                                  f'"sid={ns.sid.hex()}" "leaves={final_count}"')
        leaf_of = {}
        for k in new + [(ladder_name, T.TXT)]:
            rrs = z.rrsets[k]
            h = hdr(rrs, inception, expiration)
            i = ns.append(signing_data(rrs, *h))
            leaf_of[k] = (i, inception, expiration)
            leafmap[f"{k[0].to_text()}|{T.to_text(k[1])}"] = {
                "leaf": i, "digest": rrset_digest(rrs), "inc": inception, "exp": expiration}
        for k, e in reuse:
            leaf_of[k] = (e["leaf"], e["inc"], e["exp"])
        assert ns.count == final_count
        ladder = ns.ladder()
        lsig = zsk.sign(ladder.to_bytes(), ctx=mtl.OID_MTL)          # the ONE underlying signature
        signed_ladder = mtl.SignedLadder(ladder, lsig)
        for k, (i, inc, exp) in leaf_of.items():
            rrs = z.rrsets[k]
            ap = ns.authpath(i)
            if k == (ladder_name, T.TXT):
                body = bytes([mtl.MTL_TYPE_FULL]) + mtl.encode_full(ns.sid, ap, signed_ladder)
            else:
                body = bytes([mtl.MTL_TYPE_CONDENSED]) + mtl.encode_condensed(ns.sid, ap)
            signed[k] = make_rrsig(*hdr(rrs, inc, exp), body)
        ks.save_state({"zsk_pk": zsk.pk.hex(), "nodeset": ns.to_json(), "leafmap": leafmap})
        stats.update(underlying_signs=1, leaves_added=ns.count - start_count, leaves_total=ns.count,
                     leaves_reused=len(reuse), ladder_rungs=len(ladder.rungs),
                     signed_ladder_bytes=len(signed_ladder.to_bytes()), sid=ns.sid.hex())
    stats["zsk_sign_seconds"] = time.perf_counter() - t0

    # KSK (classical) signs the DNSKEY RRset
    t1 = time.perf_counter()
    dk = z.rrsets[(z.origin, T.DNSKEY)]
    h = (T.DNSKEY, ALG_ECDSAP256, label_count(z.origin), dk.ttl, expiration, inception, ktag, z.origin)
    signed[(z.origin, T.DNSKEY)] = make_rrsig(*h, ecdsa_sign(ksk, signing_data(dk, *h)))
    stats["ksk_sign_seconds"] = time.perf_counter() - t1

    sigsizes = [len(r.signature) for k, r in signed.items() if k[1] != T.DNSKEY]
    stats.update(rrsets_zsk_signed=len(sigsizes), rrsig_sig_bytes_total=sum(sigsizes),
                 rrsig_sig_bytes_mean=sum(sigsizes) / len(sigsizes),
                 rrsig_sig_bytes_max=max(sigsizes), zsk_keytag=ztag, ksk_keytag=ktag)
    return signed, ksk_key, stats


def write_zone(z: Zone, signed, path: Path):
    lines = [f"$ORIGIN {z.origin.to_text()}", f"$TTL {TTL}"]
    order = sorted(z.rrsets, key=lambda k: (k[0], 0 if k[1] == T.SOA else 1, k[1]))
    for k in order:
        rrs = z.rrsets[k]
        for rd in rrs:
            lines.append(f"{rrs.name.to_text()} {rrs.ttl} IN {T.to_text(rrs.rdtype)} "
                         f"{rd.to_text(chunksize=0) if rrs.rdtype == T.DNSKEY else rd.to_text()}")
        if k in signed:
            lines.append(f"{rrs.name.to_text()} {rrs.ttl} IN RRSIG {signed[k].to_text(chunksize=0)}")
    path.write_text("\n".join(lines) + "\n")
    return path.stat().st_size


def ds_of(zone_name, ksk_key):
    return dns.dnssec.make_ds(N(zone_name), ksk_key, "SHA256")


# ======================================================================= CLI
def run(mode, hosts, out: Path, keys: Path, fresh: bool, meta: dict):
    import dns.dnssec  # noqa
    out.mkdir(parents=True, exist_ok=True)
    now = int(time.time())
    serial = meta.get("serial", now)
    all_stats = []
    # 1. Sign SLD: aiori3.test.
    aiori = build_aiori(serial, hosts)
    s_aiori, k_aiori, st = sign_zone(aiori, mode, KeyStore(keys, "aiori3.test."), now, fresh)
    st["zone_file_bytes"] = write_zone(aiori, s_aiori, out / "aiori3.test.zone")
    all_stats.append(st)

    # 2. Sign TLD: test. (delegates aiori3.test.)
    test_z = build_test(serial)
    s_test, k_test, st_test = sign_zone(test_z, mode, KeyStore(keys, "test."), now, fresh,
                                        child_ds=[(N("aiori3.test."), ds_of("aiori3.test.", k_aiori))])
    st_test["zone_file_bytes"] = write_zone(test_z, s_test, out / "test.zone")
    all_stats.append(st_test)

    # 3. Sign TLD: lab. (also delegates aiori3.test. for compatibility)
    lab = build_lab(serial)
    s_lab, k_lab, st_lab = sign_zone(lab, mode, KeyStore(keys, "lab."), now, fresh,
                                     child_ds=[(N("aiori3.test."), ds_of("aiori3.test.", k_aiori))])
    st_lab["zone_file_bytes"] = write_zone(lab, s_lab, out / "lab.zone")
    all_stats.append(st_lab)

    # 4. Sign Root: . (delegates test. and lab.)
    root = build_root(serial)
    s_root, k_root, st_root = sign_zone(root, mode, KeyStore(keys, "."), now, fresh,
                                        child_ds=[(N("test."), ds_of("test.", k_test)),
                                                  (N("lab."), ds_of("lab.", k_lab))])
    st_root["zone_file_bytes"] = write_zone(root, s_root, out / "root.zone")
    all_stats.append(st_root)

    (out / "root.anchor").write_text(f". IN DS {ds_of('.', k_root).to_text()}\n")
    meta.update(mode=mode, hosts=hosts, serial=serial, signed_at=now)
    (out / "sign_stats.json").write_text(json.dumps({"meta": meta, "zones": all_stats}, indent=2))
    (keys / "series.json").write_text(json.dumps(meta, indent=2))
    return all_stats


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sign")
    s.add_argument("--mode", choices=["mldsa44", "mtl"], required=True)
    s.add_argument("--dataset", choices=list(DATASETS), default="small")
    s.add_argument("--size", type=int, help="override host count")
    e = sub.add_parser("evolve")
    e.add_argument("--add", type=int, default=50, help="new host RRsets (alpha) to add")
    for p in (s, e):
        p.add_argument("--out", type=Path, default=Path("zones"))
        p.add_argument("--keys", type=Path, default=Path("keys"))
    a = ap.parse_args()
    a.keys.mkdir(parents=True, exist_ok=True)
    if a.cmd == "sign":
        hosts = a.size or DATASETS[a.dataset]
        stats = run(a.mode, hosts, a.out, a.keys, True,
                    {"dataset": a.dataset if not a.size else f"custom{a.size}", "base_hosts": hosts,
                     "generation": 0})
    else:
        meta = json.loads((a.keys / "series.json").read_text())
        meta["generation"] += 1
        meta["serial"] = meta["serial"] + 1
        hosts = meta["hosts"] + a.add
        stats = run(meta["mode"], hosts, a.out, a.keys, False, meta)
    for st in stats:
        print(f"{st['zone']:10s} mode={st['mode']:8s} rrsets={st['rrsets_zsk_signed']:6d} "
              f"underlying_signs={st['underlying_signs']:6d} zsk_sign={st['zsk_sign_seconds']*1000:9.2f} ms "
              f"mean_sig={st['rrsig_sig_bytes_mean']:7.1f} B zonefile={st['zone_file_bytes']/1024:9.1f} KiB")


if __name__ == "__main__":
    main()
