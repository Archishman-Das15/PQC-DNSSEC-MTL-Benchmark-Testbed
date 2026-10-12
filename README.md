# PS-036 — PQC DNSSEC MTL Benchmark Using a Reference Implmentation

Benchmarks **ML-DSA-44** vs **MTL + ML-DSA-44** (Merkle Tree Ladder mode, Verisign Labs) for DNSSEC
zone signing, on a full, containerised delegation chain: **root → test. → aiori3.test.**, a PowerDNS
recursive resolver, and a separate client container.

- KSK: ECDSAP256SHA256 (classical). ZSK: ML-DSA-44 (lab alg 200) or ML-DSA-44-MTL-SHAKE-128 (lab alg 201).
- MTL implemented per draft-harvey-cfrg-mtl-mode-09; RRSIG encoding per draft-fregly-dnsop-slh-dsa-mtl-dnssec.
- Architecture, MTL mapping and pseudocode: [`docs/DESIGN.md`](docs/DESIGN.md). Mentor demo script: [`docs/DEMO.md`](docs/DEMO.md).

| Container | IP | Role |
|---|---|---|
| `root` | 172.30.53.10 | PowerDNS Auth, zone `.` |
| `tld-lab` | 172.30.53.20 | PowerDNS Auth, zone `test.` & `lab.` |
| `sld-aiori` | 172.30.53.30 | PowerDNS Auth, zone `aiori3.test.` |
| `resolver` | 172.30.53.53 | PowerDNS Recursor 5.3, lab root hints |
| `client` | 172.30.53.100 | dig, PQC validator, benchmarks |
| `ui` | 172.30.53.80 | Web Workbench console (port 8080) |
| `tools` | — | one-shot: signer, offline benchmarks, report |

---

## ⚡ Universal Quickstart (Linux: Ubuntu / Debian / Kali) — Zero Compilation

The testbed is fully containerized and pre-packaged with offline Docker images (`pqc_docker_images.tar.gz`), eliminating manual C library compilation (`liboqs`) and host Python dependency installs.

### Prerequisites
- **Ubuntu / Debian / Kali / Linux**: Install Docker & Compose (`sudo apt-get install -y docker.io docker-compose-plugin`).

---

### Universal 2-Step Setup

#### Option 1: 1-Click Script (Recommended)
- Run `./import_images.sh`

#### Option 2: Command Line
```bash
# 1. Load the pre-compiled Docker images (takes ~20 seconds, no compilation needed)
docker load -i pqc_docker_images.tar.gz

# 2. Launch the entire testbed hierarchy and containerized Workbench UI
./tb.sh sign mtl small
./tb.sh up
# Or simply run: ./run_ui.sh
```

Open your browser at **http://localhost:8080/** to access the interactive Workbench UI!

---

## Manual / Developer Setup (Build from Source)

## Step 1 — Install Docker on Linux (Ubuntu / Debian / Kali / Any Linux)

### Method A: Universal Automated Installer (Works on ANY Linux Distribution)
This is the official, distribution-agnostic Docker installer that automatically detects your kernel, architecture, and distribution (Ubuntu, Debian, Kali Linux, Fedora, CentOS, Arch, openSUSE, etc.):

```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker            # or log out and back in
docker run --rm hello-world
docker compose version
```

### Method B: Native Distro Package Manager (Debian / Ubuntu / Kali / Mint)
Zero external repository dependencies; uses official distribution-vetted packages directly:

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker            # or log out and back in
docker run --rm hello-world
docker compose version
```

### Method C: Official Docker CE Repositories

#### For Debian (Debian 11 Bullseye / 12 Bookworm / Kali Linux / Debian Derivatives):
```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git python3 util-linux
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Detect codename (rolling distributions like Kali Linux use the Debian bookworm upstream):
DEB_CODENAME=$(. /etc/os-release && ([ "$ID" = "debian" ] && echo "$VERSION_CODENAME" || echo "bookworm"))
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/debian ${DEB_CODENAME} stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker
```

#### For Ubuntu (20.04 / 22.04 / 24.04):
```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git python3 util-linux
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker
```

## Step 2 — Get the project

```bash
unzip pqc-dnssec-mtl-testbed.zip && cd pqc-dnssec-mtl-testbed
chmod +x tb.sh scripts/*.sh docker/auth/entrypoint.sh run_ui.sh stop_ui.sh import_images.sh ui/*.sh
```

## Step 3 — (Recommended) pin the machine for stable numbers

```bash
nproc                                    # need >= 4 for separate cores

# On Debian / Kali:
sudo apt-get install -y linux-cpupower || true
# On Ubuntu:
sudo apt-get install -y linux-tools-common linux-tools-$(uname -r) || true

# Set CPU governor to performance:
sudo cpupower frequency-set -g performance || true
```
Edit `.env` so `AUTH_CPUS`, `RESOLVER_CPUS`, `CLIENT_CPUS/BENCH_CPUS` are different cores. Close other heavy apps.

## Step 4 — Build everything

```bash
./tb.sh setup
```
Builds the images (liboqs 0.16.0 compiled from source, PowerDNS from repo.powerdns.com) and creates
`config/lab-root.hints` from IANA `named.root`. Takes ~5–10 min the first time.

## Step 5 — Run the Workbench UI (Interactive Web Console)

The Workbench UI is fully containerized (service `ui`), requiring zero host Python packages or compilation. You can start it via Docker or run directly:

```bash
# Recommended: Run inside Docker (zero host dependencies)
./tb.sh ui             # or 1-click: ./run_ui.sh

# Stop the Workbench UI:
./stop_ui.sh

# Alternative: Run on host with local Python (requires fastapi & uvicorn)
# On Debian / Ubuntu:
sudo apt-get install -y python3-fastapi python3-uvicorn
# Or via pip:
# pip install fastapi uvicorn
./ui/run.sh
```

Open your browser at **http://localhost:8080/** (or `http://<machine-ip>:8080/`).

The workbench provides:
- Live container topology and status of the DNS delegation chain (`aiori3.test.`).
- Controls to sign zones (MTL vs ML-DSA-44 baseline) and reload servers.
- Interactive DNS query runner (`dig`, PQC validator) and benchmark executors.
- Real-time interactive terminal session with quick action commands.
- Visualization of benchmark metrics and generated figures.

*(Note: Requires `fastapi` and `uvicorn`. If running outside a pre-configured environment, install via `pip install fastapi uvicorn`.)*

## Step 6 — Bring up the hierarchy (choose a mode)

```bash
./tb.sh sign mtl small        # or: ./tb.sh sign mldsa44 small     (datasets: small | medium | large)
./tb.sh up
./tb.sh test
```
`test` shows: a `dig +dnssec` answer from the client (via the recursor), a `dig +trace` from the lab root
down to `aiori3.test`, and a full PQC chain validation ending in `SECURE`.

### Dig from the client container yourself
```bash
docker compose exec client bash
dig +dnssec host00001.aiori3.test A          # answer + RRSIG (alg 200 or 201)
dig +dnssec aiori3.test DNSKEY               # KSK alg 13 + PQC ZSK
dig +dnssec aiori3.test DS                   # DS signed by test.'s PQC ZSK
dig +trace @172.30.53.10 www.aiori3.test     # delegation root -> test -> aiori3.test
dig +dnssec +tcp _mtlladder.aiori3.test TXT  # (MTL) full signature = signed ladder
python -m pqcdns.validator host00042.aiori3.test www.aiori3.test   # full chain-of-trust validation
```

### Switch modes
```bash
./tb.sh sign mldsa44 medium && ./tb.sh reload && ./tb.sh test
```

## Step 7 — Run the benchmarks

Everything at once (≈ 20–40 min, all 3 sizes × 2 modes, 5 trials each):
```bash
./tb.sh bench-all                      # TRIALS=5 QUERIES=300 RUNS=200 by default
```
Or piece by piece:
```bash
./tb.sh env                            # record pinned environment
./tb.sh bench-crypto 5                 # offline sign/verify, 3 sizes, both modes, pinned CPU
./tb.sh sign mtl large && ./tb.sh reload
./tb.sh bench-dns 5 300                # live workload for the zones currently loaded
./tb.sh bench-dns 5 300 --no-ladder-cache   # MTL worst case (no ladder reuse)
./tb.sh bench-endurance 200            # ladder endurance: measured vs analytical
./tb.sh report                         # -> results/REPORT.md + results/figures/*.png
```

## Step 8 — Evolution / backward-compatibility demo (MTL)
```bash
./tb.sh sign mtl small && ./tb.sh reload
./tb.sh demo-evolve
```

## Outputs
| Path | Content |
|---|---|
| `results/REPORT.md` | full report: config, measured results, analytical estimates (separate) |
| `results/figures/` | sign/verify time, RRSIG bytes, DNS bytes, TCP fallbacks, endurance |
| `results/crypto/crypto.json` | offline benchmark raw data (per trial) |
| `results/dns/<mode>_<dataset>/queries.csv` | every query: bytes, TCP, latency, crypto time, ladder fetches |
| `results/endurance/endurance.json` | K measured vs analytic, φ(K,1) |
| `results/env/environment.json` | pinned environment |

Make a PDF of the report (for the hackathon upload):
```bash
sudo apt-get install -y pandoc wkhtmltopdf
cd results && pandoc REPORT.md -o REPORT.pdf --pdf-engine=wkhtmltopdf --resource-path=.
```

## Troubleshooting
| Symptom | Fix |
|---|---|
| `bookworm-auth-50` / `rec-53` not found during build | set `PDNS_AUTH_REPO=auth-49` or `PDNS_REC_REPO=rec-52` in `.env`, rerun `./tb.sh setup` |
| `authoritative servers not ready` | `./tb.sh logs sld-aiori`; large ML-DSA zone (~66 MB) needs time to load |
| validator says BOGUS after switching mode | stale resolver cache → `./tb.sh flush` (reload does this automatically) |
| IANA hints download fails | a built-in template is used; lab behaviour is identical |
| `cpuset` errors | your CPU has fewer cores than `.env` asks; edit `.env` |
| Permission denied on `zones/` | `sudo chown -R $USER zones keys results config` |

## Scope notes (as required by PS-036)
No new cryptography (ML-DSA-44 = liboqs, MTL = published Verisign spec), no resolver written from scratch
(PowerDNS Recursor resolves/caches; only PQC signature checks run in the client), no Internet deployment
(isolated lab network, lab-only algorithm numbers 200/201), no security proof claimed.


## Authors
### Team RootOps
Archishman Das &
Sampurnaa Nag