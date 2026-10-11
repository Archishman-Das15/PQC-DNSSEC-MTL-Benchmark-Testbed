"""
Live DNSSEC workload benchmark (runs in the client container, through the PowerDNS recursor).

Per trial:  flush recursor cache  ->  fresh (cold) validator  ->  Q random queries for
host RRsets of aiori3.test  ->  full PQC chain validation of every answer.
The query sequence depends only on (seed, trial), so mldsa44 and mtl runs see IDENTICAL
workloads ("equivalent workloads with and without MTL").

Directly measured: response bytes (wire), UDP->TCP fallbacks, per-query latency,
crypto time split (ML-DSA / ECDSA / MTL path), ladder fetches, validator cache bytes,
recursor cache entries / packet-cache entries / real memory (via the recursor API).
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import statistics
import time
import urllib.request
from pathlib import Path

from .topology import RESOLVER_API, RESOLVER_API_KEY, RESOLVER_IP
from .validator import ValidationError, Validator

REC_STATS = ("cache-entries", "packetcache-entries", "real-memory-usage", "malloc-bytes",
             "all-outqueries", "tcp-outqueries", "cache-hits", "cache-misses", "negcache-entries")


def api(path, method="GET"):
    req = urllib.request.Request(RESOLVER_API + path, method=method,
                                 headers={"X-API-Key": RESOLVER_API_KEY})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def rec_stats():
    try:
        d = {x["name"]: x.get("value") for x in api("/api/v1/servers/localhost/statistics")}
        return {k: int(d[k]) for k in REC_STATS if k in d}
    except Exception as e:                     # noqa
        return {"error": str(e)}


def flush():
    return api("/api/v1/servers/localhost/cache/flush?domain=.&subtree=true", "PUT")


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zones", default=os.environ.get("ZONES_DIR", "/zones"))
    ap.add_argument("--out", default=os.environ.get("RESULTS_DIR", "/results"))
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--queries", type=int, default=300)
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--no-ladder-cache", action="store_true",
                    help="MTL: forget ladders after every query (worst case, K=1)")
    a = ap.parse_args()

    meta = json.loads(Path(a.zones, "sign_stats.json").read_text())["meta"]
    anchor = Path(a.zones, "root.anchor").read_text()
    mode, hosts = meta["mode"], meta["hosts"]
    tag = f"{mode}_{meta['dataset']}" + ("_nocache" if a.no_ladder_cache else "")
    out = Path(a.out, "dns", tag)
    out.mkdir(parents=True, exist_ok=True)
    rows, trials = [], []
    print(f">> DNS workload: mode={mode} dataset={meta['dataset']} hosts={hosts} "
          f"trials={a.trials} queries/trial={a.queries}")
    for t in range(a.trials):
        flush()
        time.sleep(0.2)
        before = rec_stats()
        v = Validator(os.environ.get("RESOLVER_IP", RESOLVER_IP), anchor,
                      ladder_cache=not a.no_ladder_cache)
        rng = random.Random(a.seed * 1000 + t)
        fails = 0
        t_trial = time.perf_counter()
        for q in range(a.queries):
            qname = f"host{rng.randint(1, hosts):05d}.aiori3.test."
            s0 = dict(v.s)
            t0 = time.perf_counter()
            try:
                _, info = v.resolve(qname)
                ok = True
            except ValidationError as e:
                ok, info = False, {"error": str(e)}
                fails += 1
            dt = time.perf_counter() - t0
            d = {k: v.s[k] - s0[k] for k in v.s}
            rows.append({"trial": t, "q": q, "qname": qname, "ok": ok, "latency_ms": dt * 1000,
                         "answer_bytes": info.get("answer_bytes", 0), "answer_tcp": info.get("tcp", False),
                         "rrsig_sig_bytes": info.get("rrsig_sig_bytes", 0),
                         "bytes_rx_total": d["bytes_rx"], "bytes_tx_total": d["bytes_tx"],
                         "queries_sent": d["queries"], "tcp_fallbacks": d["tcp_fallbacks"],
                         "ladder_fetches": d["ladder_fetches"], "mldsa_verifies": d["mldsa_verifies"],
                         "mtl_path_verifies": d["mtl_path_verifies"],
                         "t_crypto_ms": (d["t_mldsa"] + d["t_ecdsa"] + d["t_mtl_path"]) * 1000,
                         "t_mldsa_ms": d["t_mldsa"] * 1000, "t_mtl_path_ms": d["t_mtl_path"] * 1000})
            if a.no_ladder_cache:
                v.drop_ladders()
        wall = time.perf_counter() - t_trial
        after = rec_stats()
        tr = [r for r in rows if r["trial"] == t]
        trials.append({
            "trial": t, "queries": a.queries, "failures": fails, "wall_s": wall,
            "qps": a.queries / wall,
            "bytes_rx": sum(r["bytes_rx_total"] for r in tr),
            "bytes_tx": sum(r["bytes_tx_total"] for r in tr),
            "answer_bytes_mean": statistics.mean(r["answer_bytes"] for r in tr),
            "answer_tcp_rate": sum(r["answer_tcp"] for r in tr) / len(tr),
            "tcp_fallbacks": sum(r["tcp_fallbacks"] for r in tr),
            "ladder_fetches": sum(r["ladder_fetches"] for r in tr),
            "mldsa_verifies": sum(r["mldsa_verifies"] for r in tr),
            "latency_ms_p50": pct([r["latency_ms"] for r in tr], 50),
            "latency_ms_p95": pct([r["latency_ms"] for r in tr], 95),
            "crypto_ms_total": sum(r["t_crypto_ms"] for r in tr),
            "validator_cache": v.cache_footprint(),
            "recursor_before": before, "recursor_after": after,
            "recursor_delta": {k: after.get(k, 0) - before.get(k, 0) for k in after if k != "error"},
        })
        tt = trials[-1]
        print(f"   trial {t}: fail={fails} rx={tt['bytes_rx']/1024:8.1f} KiB "
              f"tcp_fallbacks={tt['tcp_fallbacks']:4d} ladder_fetches={tt['ladder_fetches']:3d} "
              f"p50={tt['latency_ms_p50']:6.2f} ms crypto={tt['crypto_ms_total']:8.2f} ms "
              f"rec_mem_delta={tt['recursor_delta'].get('real-memory-usage', 0)/1024:8.1f} KiB")

    with open(out / "queries.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    summary = {"meta": meta, "params": vars(a), "trials": trials}
    for k in ("bytes_rx", "tcp_fallbacks", "ladder_fetches", "latency_ms_p50", "crypto_ms_total",
              "answer_bytes_mean", "qps"):
        xs = [t[k] for t in trials]
        summary[f"{k}_mean"] = statistics.mean(xs)
        summary[f"{k}_stdev"] = statistics.stdev(xs) if len(xs) > 1 else 0.0
    Path(out, "summary.json").write_text(json.dumps(summary, indent=2))
    print(f">> wrote {out}")


if __name__ == "__main__":
    main()
