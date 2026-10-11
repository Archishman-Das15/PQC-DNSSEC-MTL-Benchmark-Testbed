"""
Root hints for the lab.

Downloads the authoritative IANA root hints file (named.root) and derives the lab hints
file from it: same format and header, but the root NS set points to the lab root server
(a.root-servers.lab / 172.30.53.10). The resolver primes exactly as on the Internet
(". NS" priming query to the hinted server) but stays inside the isolated lab.
"""
import os
import sys
import urllib.request
from pathlib import Path

from .topology import ROOT_IP, ROOT_NS

IANA_URLS = ["https://www.internic.net/domain/named.root",
             "https://www.iana.org/domains/root/files/named.root"]


def main(outdir="config"):
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    iana = None
    for u in IANA_URLS:
        try:
            iana = urllib.request.urlopen(u, timeout=15).read().decode()
            print(f">> downloaded IANA root hints from {u}")
            break
        except Exception as e:  # noqa
            print(f"   could not fetch {u}: {e}")
    if iana:
        (out / "iana-named.root").write_text(iana)
        header = [l for l in iana.splitlines() if l.startswith(";")]
        n_real = sum(1 for l in iana.splitlines() if " NS " in l or "\tNS\t" in l)
        print(f"   IANA file has {n_real} root NS records (kept for reference in config/iana-named.root)")
    else:
        header = ["; IANA named.root could not be downloaded - built-in template used"]
    lab = header[:6] + [
        ";",
        "; ---- PS-036 LAB ROOT HINTS (derived from the IANA file above) ----",
        "; The lab root server replaces the 13 Internet root servers so that the",
        "; resolver performs real priming + iterative resolution inside the testbed.",
        ";",
        f".                        3600000      NS    {ROOT_NS.upper()}",
        f"{ROOT_NS.upper():24s} 3600000      A     {ROOT_IP}",
        "; End of file", ""]
    (out / "lab-root.hints").write_text("\n".join(lab))
    print(f">> wrote {out/'lab-root.hints'}  ({ROOT_NS} -> {ROOT_IP})")


if __name__ == "__main__":
    main(*sys.argv[1:])
