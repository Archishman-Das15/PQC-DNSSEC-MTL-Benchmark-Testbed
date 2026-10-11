# Mentor demonstration (~10 minutes)

1. **Topology** – `docker compose ps` (5 containers, separate IPs). Show `config/lab-root.hints`.
2. **ML-DSA-44 baseline**
   ```bash
   ./tb.sh sign mldsa44 small && ./tb.sh reload
   ./tb.sh dig +dnssec host00001.aiori3.test A      # RRSIG alg 200, ~2.5 kB answer -> TCP
   ./tb.sh validate host00001.aiori3.test            # SECURE, bytes_rx, tcp_fallbacks
   ```
3. **MTL + ML-DSA-44**
   ```bash
   ./tb.sh sign mtl small && ./tb.sh reload
   ./tb.sh dig +dnssec host00001.aiori3.test A      # RRSIG alg 201, condensed (~200 B), UDP
   ./tb.sh dig +dnssec +tcp _mtlladder.aiori3.test TXT   # full signature = signed ladder
   ./tb.sh validate host00001.aiori3.test host00002.aiori3.test   # 3 ladder fetches, then cache hits
   ```
4. **Backward compatibility** – `./tb.sh demo-evolve`
5. **Pseudocode** – `docs/DESIGN.md` §3. **Code** – `pqcdns/mtl.py` (Algorithms 1–8).
6. **Results** – `results/REPORT.md` and `results/figures/`.
