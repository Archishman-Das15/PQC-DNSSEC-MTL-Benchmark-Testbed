"""
Offline, network-free signing / verification benchmark (pinned CPU, repeated trials).

For each dataset size and each mode, every trial:
  * builds the aiori3.test zone (N host RRsets + infrastructure + NSEC chain),
  * signs it with fresh keys  (mldsa44: one ML-DSA-44 signature per RRset;
                               mtl: node set + ONE ML-DSA-44 signature on the ladder),
  * verifies every RRSIG as a cold verifier would (mtl: verify the signed ladder once,
    then one authentication path per RRset).
Also runs primitive micro-benchmarks (ML-DSA-44 sign/verify, ECDSA P-256, cSHAKE128 node hash).
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import tempfile
import time
from pathlib import Path

import dns.rdatatype as T

from . import mtl
from .dnssec import (MLDSA44, MLDSAVerifier, ecdsa_sign, ecdsa_verify, ecdsa_pub_to_dnskey,
                     signing_data_from_rrsig)
from .signer import KeyStore, build_aiori, sign_zone
from .topology import DATASETS


def pin():
    cpu = os.environ.get("BENCH_CPU", "").split(",")[0].split("-")[0].strip()
    if cpu.isdigit() and hasattr(os, "sched_setaffinity"):
        try:
            os.sched_setaffinity(0, {int(cpu)})
        except OSError as e:
            print(f"   (could not pin to CPU {cpu}: {e})")
    return sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None


def verify_zone(z, signed, zsk_pk):
    mv = MLDSAVerifier()
    items = [(k, r) for k, r in signed.items() if k[1] != T.DNSKEY]
    t0 = time.perf_counter()
    ladders, ml_verifies = [], 0
    # a cold MTL verifier first obtains + verifies the signed ladder (full signature)
    for k, sig in items:
        if sig.algorithm == 201 and sig.signature[0] == mtl.MTL_TYPE_FULL:
            sid, ap, sl = mtl.decode_signature(sig.signature[1:], True)
            assert mv.verify(zsk_pk, sl.ladder.to_bytes(), sl.signature, mtl.OID_MTL)
            ml_verifies += 1
            ladders.append(sl.ladder)
    t_ladder = time.perf_counter() - t0
    for k, sig in items:
        data = signing_data_from_rrsig(z.rrsets[k], sig)
        if sig.algorithm == 200:
            assert mv.verify(zsk_pk, data, sig.signature)
            ml_verifies += 1
        else:
            full = sig.signature[0] == mtl.MTL_TYPE_FULL
            sid, ap, _ = mtl.decode_signature(sig.signature[1:], full)
            rung = next(r for r in (mtl.mtl_rung(sid, ap, l) for l in ladders) if r)
            assert mtl.mtl_verify(sid, data, ap, rung)
    return time.perf_counter() - t0, t_ladder, ml_verifies, len(items)


def micro(n=500):
    k = MLDSA44()
    mv = MLDSAVerifier()
    msg = os.urandom(200)
    t0 = time.perf_counter()
    sigs = [k.sign(msg) for _ in range(n)]
    t_s = (time.perf_counter() - t0) / n
    t0 = time.perf_counter()
    for s in sigs:
        mv.verify(k.pk, msg, s)
    t_v = (time.perf_counter() - t0) / n
    from cryptography.hazmat.primitives.asymmetric import ec
    e = ec.generate_private_key(ec.SECP256R1())
    ek = ecdsa_pub_to_dnskey(e.public_key())
    t0 = time.perf_counter()
    es = [ecdsa_sign(e, msg) for _ in range(n)]
    t_es = (time.perf_counter() - t0) / n
    t0 = time.perf_counter()
    for s in es:
        ecdsa_verify(ek, msg, s)
    t_ev = (time.perf_counter() - t0) / n
    sid, h = os.urandom(32), os.urandom(16)
    t0 = time.perf_counter()
    for i in range(20 * n):
        mtl.hash_int(sid, i, i + 1, h, h)
    t_h = (time.perf_counter() - t0) / (20 * n)
    return {"mldsa44_sign_us": t_s * 1e6, "mldsa44_verify_us": t_v * 1e6,
            "ecdsa_p256_sign_us": t_es * 1e6, "ecdsa_p256_verify_us": t_ev * 1e6,
            "mtl_cshake128_node_hash_us": t_h * 1e6, "iterations": n}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--datasets", nargs="+", default=list(DATASETS))
    ap.add_argument("--modes", nargs="+", default=["mldsa44", "mtl"])
    ap.add_argument("--out", default=os.environ.get("RESULTS_DIR", "/results"))
    a = ap.parse_args()
    cpus = pin()
    out = Path(a.out, "crypto")
    out.mkdir(parents=True, exist_ok=True)
    print(f">> offline crypto benchmark  pinned_cpus={cpus}")
    res = {"cpus": cpus, "micro": micro(), "runs": []}
    print("   primitives:", {k: round(v, 2) for k, v in res["micro"].items()})
    for ds in a.datasets:
        hosts = DATASETS[ds]
        for mode in a.modes:
            per = []
            for t in range(a.trials):
                with tempfile.TemporaryDirectory() as td:
                    mtl.HASH_COUNTER.update(leaf=0, int=0)
                    z = build_aiori(1, hosts)
                    ks = KeyStore(Path(td), "aiori3.test.")
                    signed, _, st = sign_zone(z, mode, ks, int(time.time()), True)
                    hashes_sign = dict(mtl.HASH_COUNTER)
                    mtl.HASH_COUNTER.update(leaf=0, int=0)
                    tv, tl, mlv, n = verify_zone(z, signed, ks.zsk().pk)
                    per.append({"trial": t, "rrsets": n, "sign_s": st["zsk_sign_seconds"],
                                "underlying_signs": st["underlying_signs"], "verify_s": tv,
                                "ladder_verify_s": tl, "underlying_verifies": mlv,
                                "hash_ops_sign": hashes_sign, "hash_ops_verify": dict(mtl.HASH_COUNTER),
                                "sig_bytes_total": st["rrsig_sig_bytes_total"],
                                "sig_bytes_mean": st["rrsig_sig_bytes_mean"],
                                "signed_ladder_bytes": st.get("signed_ladder_bytes", 0)})
            agg = {"dataset": ds, "hosts": hosts, "mode": mode, "trials": per}
            for k in ("sign_s", "verify_s"):
                xs = [p[k] for p in per]
                agg[k + "_mean"], agg[k + "_stdev"] = statistics.mean(xs), (statistics.stdev(xs) if len(xs) > 1 else 0)
            agg["rrsets"] = per[0]["rrsets"]
            agg["sig_bytes_mean"] = per[0]["sig_bytes_mean"]
            agg["sig_bytes_total"] = per[0]["sig_bytes_total"]
            agg["signed_ladder_bytes"] = per[0]["signed_ladder_bytes"]
            agg["underlying_signs"] = per[0]["underlying_signs"]
            agg["underlying_verifies"] = per[0]["underlying_verifies"]
            res["runs"].append(agg)
            print(f"   {ds:6s} {mode:8s} rrsets={agg['rrsets']:6d} sign={agg['sign_s_mean']*1000:9.2f}±{agg['sign_s_stdev']*1000:6.2f} ms "
                  f"verify={agg['verify_s_mean']*1000:9.2f}±{agg['verify_s_stdev']*1000:6.2f} ms "
                  f"ML-DSA signs={agg['underlying_signs']:6d} mean_sig={agg['sig_bytes_mean']:7.1f} B")
    Path(out, "crypto.json").write_text(json.dumps(res, indent=2))
    print(f">> wrote {out}/crypto.json")


if __name__ == "__main__":
    main()
