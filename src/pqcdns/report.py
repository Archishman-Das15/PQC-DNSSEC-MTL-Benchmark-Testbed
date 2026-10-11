"""
Build results/REPORT.md (+ PNG figures) from results/{crypto,dns,endurance,env}.
Directly measured values and analytical estimates are kept in separate sections.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from .topology import DATASETS  # noqa: E402

MODES = ["mldsa44", "mtl"]
LBL = {"mldsa44": "ML-DSA-44", "mtl": "MTL + ML-DSA-44"}


def load(p):
    return json.loads(Path(p).read_text()) if Path(p).exists() else None


def fig_bar(path, title, ylabel, groups, series, log=False):
    fig, ax = plt.subplots(figsize=(7, 4))
    w = 0.38
    for j, (name, vals, errs) in enumerate(series):
        xs = [i + (j - 0.5) * w for i in range(len(groups))]
        ax.bar(xs, vals, w, yerr=errs, capsize=3, label=name)
    ax.set_xticks(range(len(groups)))
    ax.set_xticklabels(groups)
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    if log:
        ax.set_yscale("log")
    ax.legend()
    ax.grid(axis="y", alpha=.3)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=os.environ.get("RESULTS_DIR", "/results"))
    a = ap.parse_args()
    R = Path(a.results)
    figs = R / "figures"
    figs.mkdir(parents=True, exist_ok=True)
    md = ["# PS-036 - PQC DNSSEC MTL Benchmark: Results Report", ""]

    env = load(R / "env" / "environment.json")
    md += ["## 1. Pinned benchmark environment", ""]
    if env:
        md += ["| Item | Value |", "|---|---|"] + [f"| {k} | {v} |" for k, v in env.items()]
    else:
        md.append("_run `./tb.sh env` to capture the environment_")
    md += ["", "## 2. Benchmark configuration and workload parameters", "",
           "| Parameter | Value |", "|---|---|",
           "| PQC signature algorithm | ML-DSA-44 (FIPS 204, liboqs), ZSK only |",
           "| MTL instantiation | ML-DSA-44-MTL-SHAKE-128 (draft-harvey-cfrg-mtl-mode-09, n=16, SID=32 B) |",
           "| KSK | ECDSAP256SHA256 (alg 13, classical) |",
           "| Lab DNSSEC algorithm numbers | 200 = ML-DSA-44, 201 = ML-DSA-44-MTL (lab-only) |",
           "| RRSIG encoding (MTL) | MTL-Type octet (0 condensed / 1 full) + MTL signature (draft-fregly-dnsop-slh-dsa-mtl-dnssec) |",
           "| Signed-ladder retrieval | full signature on `_mtlladder.<zone> TXT` (lab stand-in for the mtl-mode-full EDNS option) |",
           "| Batch signing | one ladder signature per zone signing run |",
           "| Denial of existence | NSEC |",
           "| UDP payload | 1232 B (auth truncation threshold and client EDNS size) |",
           f"| Dataset sizes (host RRsets in aiori3.test) | {DATASETS} |", ""]

    # ------------------------------------------------------------- measured: crypto
    cr = load(R / "crypto" / "crypto.json")
    md += ["## 3. Directly measured results", "", "### 3.1 Signing and verification (offline, pinned CPU)", ""]
    if cr:
        m = cr["micro"]
        md += [f"Pinned CPUs: `{cr['cpus']}`. Primitive costs (mean of {m['iterations']}): "
               f"ML-DSA-44 sign {m['mldsa44_sign_us']:.1f} µs, verify {m['mldsa44_verify_us']:.1f} µs; "
               f"ECDSA P-256 sign {m['ecdsa_p256_sign_us']:.1f} µs, verify {m['ecdsa_p256_verify_us']:.1f} µs; "
               f"MTL cSHAKE128 node hash {m['mtl_cshake128_node_hash_us']:.2f} µs.", "",
               "| Dataset | Mode | RRsets | Zone sign ms (mean±sd) | Cold verify-all ms (mean±sd) | ML-DSA signs | ML-DSA verifies | Mean RRSIG sig bytes | Total RRSIG sig bytes |",
               "|---|---|---|---|---|---|---|---|---|"]
        runs = {(r["dataset"], r["mode"]): r for r in cr["runs"]}
        for ds in DATASETS:
            for mo in MODES:
                r = runs.get((ds, mo))
                if r:
                    md.append(f"| {ds} | {LBL[mo]} | {r['rrsets']} | {r['sign_s_mean']*1e3:.1f} ± {r['sign_s_stdev']*1e3:.1f} "
                              f"| {r['verify_s_mean']*1e3:.1f} ± {r['verify_s_stdev']*1e3:.1f} | {r['underlying_signs']} "
                              f"| {r['underlying_verifies']} | {r['sig_bytes_mean']:.1f} | {r['sig_bytes_total']} |")
        dss = [d for d in DATASETS if (d, "mtl") in runs and (d, "mldsa44") in runs]
        if dss:
            for key, title, yl, fn in (("sign_s", "Zone signing time", "ms", "sign_time.png"),
                                       ("verify_s", "Cold verification of all RRSIGs", "ms", "verify_time.png")):
                fig_bar(figs / fn, title, yl, dss,
                        [(LBL[mo], [runs[(d, mo)][key + "_mean"] * 1e3 for d in dss],
                          [runs[(d, mo)][key + "_stdev"] * 1e3 for d in dss]) for mo in MODES])
                md.append(f"\n![{title}](figures/{fn})")
            fig_bar(figs / "rrsig_bytes.png", "Total RRSIG signature bytes per zone", "bytes (log)", dss,
                    [(LBL[mo], [runs[(d, mo)]["sig_bytes_total"] for d in dss], None) for mo in MODES], log=True)
            md.append("\n![RRSIG bytes](figures/rrsig_bytes.png)")
        md += ["", "> Implementation note: ML-DSA-44 runs in C (liboqs); the MTL node-set / path hashing is "
               "driven from Python (cSHAKE128 via pycryptodome, ~one interpreter round-trip per node hash). "
               "Per-RRset MTL time is therefore dominated by interpreter overhead, not by the hash itself. "
               "The *operation counts* (1 vs N underlying signatures) are implementation-independent.", ""]
    # ------------------------------------------------------------- measured: DNS
    md += ["### 3.2 Live DNS workload (client -> PowerDNS Recursor -> root / test / aiori3.test)", "",
           "| Dataset | Mode | Queries/trial x trials | Bytes received / trial (mean±sd) | Mean answer bytes | Answer TCP rate | TCP fallbacks / trial | Ladder fetches / trial | p50 latency ms | Crypto ms / trial | Failures |",
           "|---|---|---|---|---|---|---|---|---|---|---|"]
    dns_s = {}
    for p in sorted((R / "dns").glob("*/summary.json")) if (R / "dns").exists() else []:
        s = load(p)
        dns_s[p.parent.name] = s
        tr = s["trials"]
        md.append(f"| {s['meta']['dataset']} | {LBL[s['meta']['mode']]}{' (no ladder cache)' if 'nocache' in p.parent.name else ''} "
                  f"| {s['params']['queries']} x {len(tr)} | {s['bytes_rx_mean']/1024:.1f} ± {s['bytes_rx_stdev']/1024:.1f} KiB "
                  f"| {s['answer_bytes_mean_mean']:.0f} | {sum(t['answer_tcp_rate'] for t in tr)/len(tr):.2f} "
                  f"| {s['tcp_fallbacks_mean']:.1f} | {s['ladder_fetches_mean']:.1f} | {s['latency_ms_p50_mean']:.2f} "
                  f"| {s['crypto_ms_total_mean']:.1f} | {sum(t['failures'] for t in tr)} |")
    pairs = [d for d in DATASETS if f"mldsa44_{d}" in dns_s and f"mtl_{d}" in dns_s]
    if pairs:
        fig_bar(figs / "dns_bytes.png", "Transmitted bytes per trial (client side)", "KiB", pairs,
                [(LBL[mo], [dns_s[f"{mo}_{d}"]["bytes_rx_mean"] / 1024 for d in pairs],
                  [dns_s[f"{mo}_{d}"]["bytes_rx_stdev"] / 1024 for d in pairs]) for mo in MODES])
        fig_bar(figs / "dns_tcp.png", "UDP->TCP fallbacks per trial", "count", pairs,
                [(LBL[mo], [dns_s[f"{mo}_{d}"]["tcp_fallbacks_mean"] for d in pairs], None) for mo in MODES])
        md += ["", "![bytes](figures/dns_bytes.png)", "", "![tcp](figures/dns_tcp.png)"]

    md += ["", "### 3.3 Cache usage - directly measured", "",
           "Recursor values come from the PowerDNS Recursor statistics API (after a full cache flush at trial start); "
           "validator values are the exact serialized sizes of the ladders/keys the validator holds.", "",
           "| Run | Recursor cache entries (Δ) | Packet-cache entries (Δ) | Recursor RSS Δ (KiB) | Validator ladders | Validator ladder bytes | Validator key bytes |",
           "|---|---|---|---|---|---|---|"]
    for name, s in dns_s.items():
        n = len(s["trials"])
        avg = lambda k: sum(t["recursor_delta"].get(k, 0) for t in s["trials"]) / n  # noqa: E731
        vc = s["trials"][-1]["validator_cache"]
        md.append(f"| {name} | {avg('cache-entries'):.0f} | {avg('packetcache-entries'):.0f} | "
                  f"{avg('real-memory-usage')/1024:.0f} | {vc['validator_ladders']} | {vc['validator_ladder_bytes']} | {vc['validator_key_bytes']} |")
    md += ["", "> RSS deltas are page-granular and include allocator behaviour; treat them as indicative. "
           "Signature-byte cache estimates are in Section 4.2.", ""]

    # ------------------------------------------------------------- analytical
    md += ["## 4. Analytical estimates (kept separate from measurements)", "",
           "### 4.1 Reference-value endurance and effective signature size (paper Sec. 7.1-7.2)", "",
           "K_analytic = sqrt(2 ln 2) * sqrt(N0 * rho / alpha);  phi(K,1) = |condensed| + |reference value| / K.",
           "K_measured comes from the real MTL implementation (mtl_rung compatibility checks) over randomised runs.", "",
           "| N0 | alpha | rho | K measured (median) | K analytic | phi measured B | phi analytic B | ML-DSA-44 B |",
           "|---|---|---|---|---|---|---|---|"]
    en = load(R / "endurance" / "endurance.json") or []
    for r in en:
        md.append(f"| {r['n0']} | {r['alpha']} | {r['rho']} | {r['K_measured_median']:.1f} | {r['K_analytic']:.1f} "
                  f"| {r['phi_measured']:.0f} | {r['phi_analytic']:.0f} | {r['underlying_sig_bytes']} |")
    if en:
        fig, ax = plt.subplots(figsize=(6, 5))
        ax.scatter([r["K_analytic"] for r in en], [r["K_measured_median"] for r in en])
        mx = max(max(r["K_analytic"] for r in en), max(r["K_measured_median"] for r in en)) * 1.2
        ax.plot([1, mx], [1, mx], "--", color="grey", label="measured = analytic")
        ax.set_xscale("log"); ax.set_yscale("log")
        ax.set_xlabel("K analytic"); ax.set_ylabel("K measured (median)")
        ax.set_title("Ladder endurance: measured vs analytic"); ax.legend(); ax.grid(alpha=.3)
        fig.tight_layout(); fig.savefig(figs / "endurance.png", dpi=130); plt.close(fig)
        md += ["", "![endurance](figures/endurance.png)", "",
               "> The approximation assumes N0 >> alpha*rho; rows where alpha*rho approaches N0 are expected to deviate."]

    md += ["", "### 4.2 Cache footprint of signatures - analytical", "",
           "Estimated signature bytes a resolver must cache to hold C distinct validated RRsets of the zone "
           "(ML-DSA-44: C x 2420; MTL: C x mean condensed size + one signed ladder per zone).", "",
           "| Dataset | C (distinct RRsets) | ML-DSA-44 bytes | MTL bytes | Reduction |", "|---|---|---|---|---|"]
    if cr:
        runs = {(r["dataset"], r["mode"]): r for r in cr["runs"]}
        for ds in DATASETS:
            a_, b_ = runs.get((ds, "mldsa44")), runs.get((ds, "mtl"))
            if a_ and b_:
                for C in (100, a_["rrsets"]):
                    x = C * a_["sig_bytes_mean"]
                    y = C * b_["sig_bytes_mean"] + b_["signed_ladder_bytes"]
                    md.append(f"| {ds} | {C} | {x:,.0f} | {y:,.0f} | {100*(1-y/x):.1f}% |")
    md += ["", "## 5. Reproducibility", "",
           "All numbers in this report are regenerated by `./tb.sh bench-all` (see README). Raw data: "
           "`results/crypto/crypto.json`, `results/dns/*/queries.csv`, `results/dns/*/summary.json`, "
           "`results/endurance/endurance.json`, `results/env/environment.json`.", ""]
    (R / "REPORT.md").write_text("\n".join(md))
    print(f">> wrote {R/'REPORT.md'}")


if __name__ == "__main__":
    main()
