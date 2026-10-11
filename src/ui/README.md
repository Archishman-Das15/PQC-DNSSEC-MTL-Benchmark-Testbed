# PQC-DNSSEC MTL Benchmark Workbench UI

A utilitarian, engineering-focused web console and interactive terminal workbench for the **PS-036 PQC DNSSEC MTL Benchmark Testbed**.

## Architecture

- **Backend**: `ui/server.py`
  - Python 3 FastAPI application with Uvicorn.
  - WebSocket `/ws/terminal` providing bidirectional PTY streaming with raw ANSI escape sequence support, window resizing, and `SIGINT` interruption.
  - REST endpoints:
    - `GET /api/status`: Real-time Docker container topology, active zone signing mode, and CPU pinning.
    - `GET /api/metrics`: Parsed comparison tables from `results/REPORT.md`.
    - `GET /api/figures-list`: Directory listing of generated PNG charts in `results/figures/`.
    - `GET /api/figures/{filename}`: Secure image serving.
    - `GET /api/report-markdown`: Raw markdown reader for `results/REPORT.md`.
- **Frontend**: `ui/static/`
  - Self-contained HTML5, CSS3, and Vanilla JavaScript.
  - Vendored `xterm.js` and `xterm-addon-fit` in `ui/static/vendor/` for 100% offline functionality.
  - Split layout: Left pane for topology, zone signing, DNS diagnostics, benchmark suite, and figures; Right pane for the interactive PTY terminal.

## Quick Start

To launch the workbench UI:

```bash
# Using the run script (default port: 8080)
./ui/run.sh

# Or directly with Python
python3 ui/server.py

# Or with a custom port
PORT=9000 ./ui/run.sh
```

Open your browser at:
`http://localhost:8080/` (or `http://<machine-ip>:8080/`)

## Features

1. **Interactive Terminal (Right Pane)**:
   - Authentic PTY session rooted at the project directory.
   - Quick command buttons for common tasks (`tb.sh status`, `test`, `sign`, `dig`, `bench-*`, etc.).
   - Interactive command input with command history (Up/Down arrow keys).
   - Interrupt running tasks with the `Interrupt (Ctrl+C)` button.
2. **Container Topology (Left Pane)**:
   - Live status of `root`, `tld-lab`, `sld-aiori`, `resolver`, and `client`.
   - Cluster lifecycle actions (`tb.sh up`, `down`, `reload`, `flush`).
3. **Zone Signing & Series Evolution**:
   - Configure algorithm (`ML-DSA-44` vs `MTL + ML-DSA-44`) and dataset size (`small`, `medium`, `large`).
   - Run zone evolution and the backward-compatibility demo.
4. **Live DNSSEC Diagnostics**:
   - Compose `dig` queries with flags (`+dnssec`, `+multi`, `+trace`, `+tcp`) and execute in the client container.
   - Run the PQC chain-of-trust validator.
5. **Benchmark Suite**:
   - Trigger offline crypto benchmarks, live DNS workload tests, and endurance benchmarks.
6. **Results & Figures**:
   - Tabular comparison of directly measured metrics.
   - Interactive viewer for generated plots in `results/figures/`.
