"""
Reference-value (ladder) endurance: measured vs. analytical  (Fregly et al., Sec. 7.1-7.2).

Model (paper): signer has N0 initial messages, verifier holds the ladder for N0.
Each iteration the signer signs alpha new messages (new ladder); the verifier requests rho
condensed signatures on messages chosen uniformly among all signed so far, each relative to
the CURRENT ladder.  K = number of condensed signatures the verifier can verify before it
needs a new reference value.

  analytical:  K ~= sqrt(2 ln 2) * sqrt(N0 * rho / alpha)      (median, birthday-style)
  effective signature size:  phi(K,1) = |condensed| + |reference value| / K

"Measured" uses the real MTL implementation (node set, authentication paths, mtl_rung
compatibility check) - not a formula - over many randomised runs.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random
import statistics
from pathlib import Path

from . import mtl


def build(total: int) -> mtl.MTLNS:
    ns = mtl.MTLNS(os.urandom(mtl.SID_LEN))
    for i in range(total):
        ns.append(i.to_bytes(8, "big"))
    return ns


def one_run(ns, n0, alpha, rho, rng, max_iter):
    held = [ns_ladder_at(ns, n0)]
    k = 0
    for it in range(1, max_iter + 1):
        count = n0 + it * alpha
        for _ in range(rho):
            i = rng.randrange(count)
            ap = authpath_at(ns, i, count)
            if not any(mtl.mtl_rung(ns.sid, ap, l) for l in held):
                return k
            k += 1
    return k


def ns_ladder_at(ns, count):
    c, ns.count = ns.count, count
    try:
        return ns.ladder()
    finally:
        ns.count = c


def authpath_at(ns, i, count):
    c, ns.count = ns.count, count
    try:
        return ns.authpath(i)
    finally:
        ns.count = c


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n0", type=int, nargs="+", default=[100, 1000, 10000])
    ap.add_argument("--alpha", type=int, nargs="+", default=[10, 100, 1000])
    ap.add_argument("--rho", type=int, nargs="+", default=[1, 10, 100])
    ap.add_argument("--runs", type=int, default=200)
    ap.add_argument("--condensed-bytes", type=float, default=None,
                    help="|condensed| (default: computed from the auth-path size at N0)")
    ap.add_argument("--underlying-sig", type=int, default=2420)
    ap.add_argument("--out", default=os.environ.get("RESULTS_DIR", "/results"))
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    out = Path(a.out, "endurance")
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(a.seed)
    rows = []
    for n0 in a.n0:
        max_iter = 2000
        for alpha in a.alpha:
            ns = build(n0 + alpha * min(max_iter, 4 * int(math.sqrt(n0 / alpha) * 3 + 10)))
            iters = (ns.count - n0) // alpha
            lad = ns_ladder_at(ns, n0)
            ref_bytes = len(lad.to_bytes()) + 4 + a.underlying_sig  # signed ladder = reference value
            for rho in a.rho:
                ks = [one_run(ns, n0, alpha, rho, rng, iters) for _ in range(a.runs)]
                analytic = math.sqrt(2 * math.log(2)) * math.sqrt(n0 * rho / alpha)
                cond = a.condensed_bytes or (1 + mtl.SID_LEN + 2 + mtl.N_BYTES + 26
                                             + mtl.N_BYTES * math.floor(math.log2(n0)))
                kmed = statistics.median(ks)
                row = {"n0": n0, "alpha": alpha, "rho": rho, "runs": a.runs,
                       "K_measured_median": kmed, "K_measured_mean": statistics.mean(ks),
                       "K_measured_p10": sorted(ks)[len(ks) // 10], "K_measured_p90": sorted(ks)[9 * len(ks) // 10],
                       "K_analytic": analytic, "condensed_bytes": cond, "reference_value_bytes": ref_bytes,
                       "phi_measured": cond + ref_bytes / max(kmed, 1),
                       "phi_analytic": cond + ref_bytes / max(analytic, 1),
                       "underlying_sig_bytes": a.underlying_sig}
                rows.append(row)
                print(f"N0={n0:6d} alpha={alpha:5d} rho={rho:4d}  K measured median={kmed:8.1f} "
                      f"analytic={analytic:8.1f}   phi measured={row['phi_measured']:7.1f} B "
                      f"(ML-DSA-44 alone: {a.underlying_sig} B)")
    Path(out, "endurance.json").write_text(json.dumps(rows, indent=2))
    print(f">> wrote {out}/endurance.json")


if __name__ == "__main__":
    main()
