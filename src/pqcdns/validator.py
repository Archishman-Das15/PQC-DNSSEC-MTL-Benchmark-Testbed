"""
PQC DNSSEC chain validator (verifier side), used by the client container.

PowerDNS Recursor does the iterative resolution (root -> test -> aiori3.test) with DO=1 in
`process-no-validate` mode, i.e. it fetches and caches RRSIG/DNSKEY/DS/NSEC but does not
validate (it has no ML-DSA / MTL implementation, and writing a resolver from scratch is
out of scope for PS-036).  This module validates the complete chain of trust the way a
validating stub / resolver would:

   trust anchor (root KSK DS, ECDSA)  ->  root DNSKEY (KSK sig)  ->  root ZSK (PQC)
   -> test DS (PQC)  ->  test DNSKEY  ->  test ZSK  ->  aiori3.test DS  -> ... -> answer RRset

MTL verification follows draft-harvey-cfrg-mtl-mode-09 Sec. 9.5 and Verisign's DNSSEC draft:
condensed RRSIG -> look for a compatible rung in cached, already-verified ladders
(mtl_rung); if none, request the signed ladder (full signature at _mtlladder.<zone>),
verify its ML-DSA-44 signature once, cache it, then verify the authentication path.
"""
from __future__ import annotations

import time

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype as T

from . import mtl
from .dnssec import (ALG_ECDSAP256, ALG_MLDSA44, ALG_MLDSA44_MTL, LADDER_LABEL, PQC_ALGS,
                     MLDSAVerifier, ecdsa_verify, key_tag, signing_data_from_rrsig)


class ValidationError(Exception):
    pass


class Validator:
    def __init__(self, resolver: str, anchor_text: str, ladder_cache: bool = True,
                 timeout: float = 5.0, edns_payload: int = 1232):
        self.resolver = resolver
        self.anchor = anchor_text.split()          # ". IN DS tag alg dt digest"
        self.ladder_cache_enabled = ladder_cache
        self.timeout = timeout
        self.payload = edns_payload
        self.zone_keys: dict = {}                   # zone -> {"zsk": rdata}
        self.ladders: dict = {}                     # sid -> [Ladder]  (verified)
        self.verified_ladder_bytes: set = set()
        self.mv = MLDSAVerifier()
        self.reset_stats()

    # ------------------------------------------------------------------ stats
    def reset_stats(self):
        self.s = {k: 0 for k in (
            "queries", "udp_queries", "tcp_fallbacks", "bytes_tx", "bytes_rx",
            "ladder_fetches", "ladder_fetch_bytes", "ladder_cache_hits",
            "mldsa_verifies", "ecdsa_verifies", "mtl_path_verifies", "rrsets_validated")}
        self.s.update({k: 0.0 for k in ("t_mldsa", "t_ecdsa", "t_mtl_path", "t_network")})

    def cache_footprint(self) -> dict:
        lad = sum(len(l.to_bytes()) for ls in self.ladders.values() for l in ls)
        keys = sum(len(v["zsk"].key) + len(v["ksk"].key) for v in self.zone_keys.values())
        return {"validator_ladders": sum(len(v) for v in self.ladders.values()),
                "validator_ladder_bytes": lad, "validator_key_bytes": keys}

    # ------------------------------------------------------------------ transport
    def query(self, qname, rdtype, force_tcp=False):
        q = dns.message.make_query(qname, rdtype, want_dnssec=True, payload=self.payload)
        q.flags |= dns.flags.RD
        wire = q.to_wire()
        t0 = time.perf_counter()
        self.s["queries"] += 1
        tcp = force_tcp
        if not force_tcp:
            self.s["udp_queries"] += 1
            r = dns.query.udp(q, self.resolver, timeout=self.timeout, ignore_trailing=True)
            self.s["bytes_tx"] += len(wire)
            if r.flags & dns.flags.TC:
                self.s["bytes_rx"] += len(r.to_wire())
                self.s["tcp_fallbacks"] += 1
                tcp = True
        if tcp:
            r = dns.query.tcp(q, self.resolver, timeout=self.timeout)
            self.s["bytes_tx"] += len(wire) + 2
        size = len(r.to_wire())
        self.s["bytes_rx"] += size
        self.s["t_network"] += time.perf_counter() - t0
        return r, size, tcp

    @staticmethod
    def _find(msg, name, rdtype):
        rrs = sigs = None
        for rr in msg.answer:
            if rr.name == name and rr.rdtype == rdtype:
                rrs = rr
            if rr.name == name and rr.rdtype == T.RRSIG and rr.covers == rdtype:
                sigs = rr
        return rrs, sigs

    # ------------------------------------------------------------------ chain of trust
    def zone_keys_for(self, zone: dns.name.Name):
        if zone in self.zone_keys:
            return self.zone_keys[zone]
        msg, _, _ = self.query(zone, T.DNSKEY)
        dnskeys, sigs = self._find(msg, zone, T.DNSKEY)
        if dnskeys is None or sigs is None:
            raise ValidationError(f"no DNSKEY/RRSIG for {zone}")
        ksks = [k for k in dnskeys if k.flags & 1 and k.algorithm == ALG_ECDSAP256]
        ok_ksk = None
        for sig in sigs:
            for k in ksks:
                if sig.algorithm == ALG_ECDSAP256 and sig.key_tag == key_tag(k):
                    t0 = time.perf_counter()
                    good = ecdsa_verify(k.key, signing_data_from_rrsig(dnskeys, sig), sig.signature)
                    self.s["t_ecdsa"] += time.perf_counter() - t0
                    self.s["ecdsa_verifies"] += 1
                    if good:
                        ok_ksk = k
        if ok_ksk is None:
            raise ValidationError(f"DNSKEY RRset of {zone} not signed by a KSK")
        # authenticate the KSK: trust anchor (root) or DS from the parent (validated by parent ZSK)
        ds_mine = dns.dnssec.make_ds(zone, ok_ksk, "SHA256")
        if zone == dns.name.root:
            anchor_ds = " ".join(self.anchor[3:])
            if ds_mine.to_text().lower() != anchor_ds.lower():
                raise ValidationError("root KSK does not match trust anchor")
        else:
            dmsg, _, _ = self.query(zone, T.DS)
            ds_rrs, ds_sigs = self._find(dmsg, zone, T.DS)
            if ds_rrs is None:
                raise ValidationError(f"no DS for {zone}")
            self.validate_rrset(ds_rrs, ds_sigs)            # signed by the parent's PQC ZSK
            if not any(d.to_text().lower() == ds_mine.to_text().lower() for d in ds_rrs):
                raise ValidationError(f"DS mismatch for {zone}")
        zsks = [k for k in dnskeys if not (k.flags & 1) and k.algorithm in PQC_ALGS]
        if not zsks:
            raise ValidationError(f"no PQC ZSK in {zone}")
        self.zone_keys[zone] = {"zsk": zsks[0], "ksk": ok_ksk}
        return self.zone_keys[zone]

    # ------------------------------------------------------------------ RRset validation
    def validate_rrset(self, rrset, rrsigs):
        if rrsigs is None:
            raise ValidationError(f"unsigned RRset {rrset.name} {T.to_text(rrset.rdtype)}")
        for sig in rrsigs:
            if sig.algorithm not in PQC_ALGS:
                continue
            keys = self.zone_keys_for(sig.signer)
            zsk = keys["zsk"]
            if sig.key_tag != key_tag(zsk) or sig.algorithm != zsk.algorithm:
                continue
            now = int(time.time())
            if not (sig.inception <= now <= sig.expiration):
                raise ValidationError("RRSIG outside validity period")
            if self._verify_pqc(rrset, sig, zsk):
                self.s["rrsets_validated"] += 1
                return True
            raise ValidationError(f"bad PQC signature on {rrset.name} {T.to_text(rrset.rdtype)}")
        raise ValidationError(f"no usable PQC RRSIG on {rrset.name}")

    def _verify_pqc(self, rrset, sig, zsk) -> bool:
        data = signing_data_from_rrsig(rrset, sig)
        if sig.algorithm == ALG_MLDSA44:
            t0 = time.perf_counter()
            ok = self.mv.verify(zsk.key, data, sig.signature)
            self.s["t_mldsa"] += time.perf_counter() - t0
            self.s["mldsa_verifies"] += 1
            return ok
        assert sig.algorithm == ALG_MLDSA44_MTL
        mtype, body = sig.signature[0], sig.signature[1:]
        if mtype == mtl.MTL_TYPE_FULL:
            sid, ap, sl = mtl.decode_signature(body, full=True)
            if not self._accept_ladder(sid, sl, zsk):
                return False
            return self._verify_path(sid, data, ap, [sl.ladder])
        if mtype != mtl.MTL_TYPE_CONDENSED:
            return False
        sid, ap, _ = mtl.decode_signature(body, full=False)
        rung_ok = self._verify_path(sid, data, ap, self.ladders.get(sid, []))
        if rung_ok is not None:
            self.s["ladder_cache_hits"] += 1
            return rung_ok
        # no compatible ladder -> fetch the signed ladder (reference value) of this zone
        self._fetch_ladder(sig.signer)
        rung_ok = self._verify_path(sid, data, ap, self.ladders.get(sid, []))
        return bool(rung_ok)

    def _verify_path(self, sid, data, ap, ladders):
        for lad in ladders:
            rung = mtl.mtl_rung(sid, ap, lad)
            if rung is not None:
                t0 = time.perf_counter()
                ok = mtl.mtl_verify(sid, data, ap, rung)
                self.s["t_mtl_path"] += time.perf_counter() - t0
                self.s["mtl_path_verifies"] += 1
                return ok
        return None

    def _accept_ladder(self, sid, sl: mtl.SignedLadder, zsk) -> bool:
        lb = sl.ladder.to_bytes()
        if sl.ladder.sid != sid:
            return False
        if lb not in self.verified_ladder_bytes:
            t0 = time.perf_counter()
            ok = self.mv.verify(zsk.key, lb, sl.signature, mtl.OID_MTL)
            self.s["t_mldsa"] += time.perf_counter() - t0
            self.s["mldsa_verifies"] += 1
            if not ok:
                return False
            self.verified_ladder_bytes.add(lb)
            if self.ladder_cache_enabled:
                self.ladders.setdefault(sid, []).append(sl.ladder)
        return True

    def _fetch_ladder(self, zone: dns.name.Name):
        name = dns.name.Name((LADDER_LABEL.encode(),) + zone.labels)
        msg, size, _ = self.query(name, T.TXT, force_tcp=True)   # large answer -> TCP (draft Sec. 6.2)
        self.s["ladder_fetches"] += 1
        self.s["ladder_fetch_bytes"] += size
        rrs, sigs = self._find(msg, name, T.TXT)
        if rrs is None or sigs is None:
            raise ValidationError(f"no signed ladder at {name}")
        keep = self.ladder_cache_enabled
        self.ladder_cache_enabled = True           # must hold it at least for this validation
        try:
            self.validate_rrset(rrs, sigs)
        finally:
            self.ladder_cache_enabled = keep

    def drop_ladders(self):
        self.ladders.clear()
        self.verified_ladder_bytes.clear()

    # ------------------------------------------------------------------ verifier state
    def save_state(self, path):
        import json
        json.dump({"ladders": {sid.hex(): [l.to_bytes().hex() for l in ls]
                               for sid, ls in self.ladders.items()}}, open(path, "w"))

    def load_state(self, path):
        """Re-load previously VERIFIED ladders (the verifier's reference-value cache)."""
        import json
        d = json.load(open(path))
        for sid, ls in d["ladders"].items():
            for h in ls:
                lad, _ = mtl.Ladder.from_bytes(bytes.fromhex(h))
                self.ladders.setdefault(bytes.fromhex(sid), []).append(lad)
                self.verified_ladder_bytes.add(lad.to_bytes())

    # ------------------------------------------------------------------ public API
    def resolve(self, qname: str, rdtype=T.A):
        name = dns.name.from_text(qname)
        msg, size, tcp = self.query(name, rdtype)
        rrs, sigs = self._find(msg, name, rdtype)
        if rrs is None:
            raise ValidationError(f"no answer for {qname}")
        self.validate_rrset(rrs, sigs)
        sig_bytes = sum(len(s.signature) for s in sigs) if sigs else 0
        return rrs, {"answer_bytes": size, "tcp": tcp, "rrsig_sig_bytes": sig_bytes}


def main():
    import argparse
    import json
    import os
    from .topology import RESOLVER_IP
    ap = argparse.ArgumentParser(description="Validate a PQC-signed answer end-to-end")
    ap.add_argument("qnames", nargs="+", help="names to resolve+validate (type A unless --qtype)")
    ap.add_argument("--qtype", default="A")
    ap.add_argument("--load-state", help="load cached verified ladders (MTL reference values)")
    ap.add_argument("--save-state", help="save cached verified ladders after the run")
    ap.add_argument("--resolver", default=os.environ.get("RESOLVER_IP", RESOLVER_IP))
    ap.add_argument("--anchor", default=os.environ.get("TRUST_ANCHOR", "/zones/root.anchor"))
    a = ap.parse_args()
    v = Validator(a.resolver, open(a.anchor).read())
    if a.load_state and os.path.exists(a.load_state):
        v.load_state(a.load_state)
        print(f";; loaded {sum(len(x) for x in v.ladders.values())} cached verified ladder(s)")
    t0 = time.perf_counter()
    rc = 0
    for q in a.qnames:
        f0 = v.s["ladder_fetches"]
        try:
            rrs, info = v.resolve(q, T.from_text(a.qtype))
            print(f";; SECURE (PQC chain validated)  ladder_fetches+={v.s['ladder_fetches']-f0}  "
                  f"answer={info['answer_bytes']}B tcp={info['tcp']}")
            print(rrs.to_text())
        except ValidationError as e:
            rc = 1
            print(f";; BOGUS {q}: {e}")
    dt = time.perf_counter() - t0
    if a.save_state:
        v.save_state(a.save_state)
    print(json.dumps({"elapsed_ms": round(dt * 1000, 3), **v.s, **v.cache_footprint()}, indent=1))
    raise SystemExit(rc)


if __name__ == "__main__":
    main()
