#!/usr/bin/env python3
"""
PQC DNSSEC MTL Benchmark Testbed - Workbench & Terminal Server
Provides:
  - WebSocket /ws/terminal for bidirectional interactive PTY shell streaming
  - REST API /api/status for live container topology and zone signing state
  - REST API /api/metrics for parsed benchmark results and analytical data
  - REST API /api/figures/{name} for serving generated benchmark charts
  - Static file serving for the Workbench UI (ui/static/)
"""

import os
import sys
import struct
import select
import signal
import asyncio
import threading
import subprocess
import json
import re
from pathlib import Path
from typing import Dict, Any, List

try:
    import pty
    import fcntl
    import termios
    HAS_PTY = True
except ImportError:
    pty = None
    fcntl = None
    termios = None
    HAS_PTY = False

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse
import uvicorn

# Base directory is the project directory
PROJECT_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = PROJECT_DIR / "ui" / "static"
LOGOS_DIR = PROJECT_DIR / "logos"
RESULTS_DIR = PROJECT_DIR / "results"
FIGURES_DIR = RESULTS_DIR / "figures"
ZONES_DIR = PROJECT_DIR / "zones"
ENV_FILE = PROJECT_DIR / ".env"

app = FastAPI(title="PQC-DNSSEC MTL Benchmark Workbench")

def ensure_host_dir():
    """Detect and persist the host project directory for Docker bind mounts."""
    host_dir = os.environ.get("HOST_DIR")
    if not host_dir:
        if Path("/.dockerenv").exists():
            try:
                hostname = os.environ.get("HOSTNAME", "pqcmtl-ui")
                res = subprocess.run(
                    ["docker", "inspect", hostname, "--format", '{{range .Mounts}}{{if eq .Destination "/work"}}{{.Source}}{{end}}{{end}}'],
                    capture_output=True, text=True, timeout=3
                )
                if res.returncode == 0 and res.stdout.strip():
                    host_dir = res.stdout.strip()
            except Exception:
                pass
        if not host_dir:
            host_dir = str(PROJECT_DIR)
        os.environ["HOST_DIR"] = host_dir

    if ENV_FILE.exists():
        try:
            content = ENV_FILE.read_text()
            if "HOST_DIR=" in content:
                new_content = re.sub(r"^HOST_DIR=.*$", f"HOST_DIR={host_dir}", content, flags=re.MULTILINE)
            else:
                new_content = content.rstrip() + f"\nHOST_DIR={host_dir}\n"
            ENV_FILE.write_text(new_content)
        except Exception:
            pass

ensure_host_dir()

def set_pty_size(fd: int, rows: int, cols: int):
    """Resize PTY window dimensions."""
    if not HAS_PTY or not fcntl or not termios:
        return
    try:
        winsize = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)
    except Exception as e:
        print(f"[PTY] resize error: {e}", file=sys.stderr)

def get_current_zone_mode() -> Dict[str, Any]:
    """Parse current signing mode from zones/sign_stats.json."""
    stats_file = ZONES_DIR / "sign_stats.json"
    if stats_file.exists():
        try:
            with open(stats_file, "r") as f:
                data = json.load(f)
            meta = data.get("meta", {})
            zones_val = data.get("zones", [])
            if isinstance(zones_val, list):
                zone_names = [z.get("zone", "") for z in zones_val if isinstance(z, dict)]
            elif isinstance(zones_val, dict):
                zone_names = list(zones_val.keys())
            else:
                zone_names = []
            return {
                "configured": True,
                "mode": meta.get("mode", "unknown"),
                "dataset": meta.get("dataset", "unknown"),
                "hosts": meta.get("hosts", 0),
                "timestamp": meta.get("signed_at", meta.get("timestamp_utc", "")),
                "zones": zone_names
            }
        except Exception as e:
            print(f"[ZoneStats] Error parsing sign_stats: {e}", file=sys.stderr)
    return {"configured": False, "mode": "none", "dataset": "none", "hosts": 0, "zones": []}

def get_env_pinning() -> Dict[str, str]:
    """Parse CPU pinning configurations from .env."""
    pins = {
        "AUTH_CPUS": "0",
        "RESOLVER_CPUS": "1",
        "CLIENT_CPUS": "2",
        "BENCH_CPUS": "3",
        "PDNS_AUTH_REPO": "auth-50",
        "PDNS_REC_REPO": "rec-53"
    }
    if ENV_FILE.exists():
        try:
            with open(ENV_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        pins[k.strip()] = v.strip()
        except Exception:
            pass
    return pins

def get_container_status() -> List[Dict[str, Any]]:
    """Inspect docker containers in the testbed."""
    containers = [
        {"name": "root", "container": "pqcmtl-root-1", "ip": "172.30.53.10", "role": "PowerDNS Auth, root zone .", "status": "unknown"},
        {"name": "tld-lab", "container": "pqcmtl-tld-lab-1", "ip": "172.30.53.20", "role": "PowerDNS Auth, zone test. & lab.", "status": "unknown"},
        {"name": "sld-aiori", "container": "pqcmtl-sld-aiori-1", "ip": "172.30.53.30", "role": "PowerDNS Auth, zone aiori3.test.", "status": "unknown"},
        {"name": "resolver", "container": "pqcmtl-resolver-1", "ip": "172.30.53.53", "role": "PowerDNS Recursor 5.3", "status": "unknown"},
        {"name": "client", "container": "pqcmtl-client-1", "ip": "172.30.53.100", "role": "dig, PQC validator, bench", "status": "unknown"}
    ]
    
    try:
        res = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Status}}\t{{.State}}"],
            capture_output=True, text=True, timeout=3
        )
        running_map = {}
        if res.returncode == 0:
            for line in res.stdout.strip().splitlines():
                parts = line.split("\t")
                if len(parts) >= 3:
                    cname, cstatus, cstate = parts[0], parts[1], parts[2]
                    running_map[cname] = {"status_text": cstatus, "state": cstate}
        
        for item in containers:
            cname = item["container"]
            match = running_map.get(cname)
            if not match and item.get("alt_container"):
                match = running_map.get(item["alt_container"])
            if match:
                item["state"] = match["state"]
                item["status"] = match["status_text"]
            else:
                item["state"] = "not_found"
                item["status"] = "Not created"
    except Exception as e:
        for item in containers:
            item["status"] = f"Error: {e}"
            item["state"] = "error"
            
    return containers

@app.get("/api/status")
def api_status():
    """System health, container states, current zone mode, and CPU pinning."""
    return {
        "zone_mode": get_current_zone_mode(),
        "containers": get_container_status(),
        "pinning": get_env_pinning(),
        "project_dir": "pqc-dnssec-mtl-testbed",
        "results_exist": (RESULTS_DIR / "REPORT.md").exists()
    }

@app.get("/api/figures-list")
def api_figures_list():
    """List available plot images in results/figures/."""
    figures = []
    if FIGURES_DIR.exists():
        for p in FIGURES_DIR.glob("*.png"):
            figures.append({
                "id": p.stem,
                "filename": p.name,
                "url": f"/api/figures/{p.name}",
                "size_kb": round(p.stat().st_size / 1024, 1)
            })
    figures.sort(key=lambda x: x["filename"])
    return {"figures": figures}

@app.get("/api/figures/{filename}")
def api_figure(filename: str):
    """Serve a figure image."""
    safe_name = Path(filename).name
    img_path = FIGURES_DIR / safe_name
    if not img_path.exists() or not img_path.is_file():
        raise HTTPException(status_code=404, detail="Figure not found")
    return FileResponse(img_path, media_type="image/png")

@app.get("/api/report-markdown")
def api_report_markdown():
    """Return raw REPORT.md if present."""
    report_path = RESULTS_DIR / "REPORT.md"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="REPORT.md not generated yet")
    with open(report_path, "r", encoding="utf-8") as f:
        return PlainTextResponse(f.read())

@app.get("/api/metrics")
def api_metrics():
    """Parse structured tables from REPORT.md and JSON files."""
    report_path = RESULTS_DIR / "REPORT.md"
    if not report_path.exists():
        return {"available": False, "message": "Run ./tb.sh bench-all or ./tb.sh report to generate metrics."}
    
    with open(report_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Parse markdown tables
    tables = {}
    sections = content.split("## ")
    for sec in sections:
        lines = sec.strip().splitlines()
        if not lines:
            continue
        title = lines[0].strip()
        # Find markdown tables
        table_rows = []
        for line in lines:
            if line.startswith("|") and line.endswith("|"):
                cells = [c.strip() for c in line.split("|")[1:-1]]
                # Skip divider row |---|---|
                if any("---" in c for c in cells):
                    continue
                table_rows.append(cells)
        if len(table_rows) > 1:
            tables[title] = {
                "headers": table_rows[0],
                "rows": table_rows[1:]
            }
            
    return {
        "available": True,
        "tables": tables,
        "crypto_raw_exists": (RESULTS_DIR / "crypto" / "crypto.json").exists(),
        "endurance_raw_exists": (RESULTS_DIR / "endurance" / "endurance.json").exists()
    }

@app.websocket("/ws/terminal")
async def websocket_terminal(websocket: WebSocket):
    """
    Bidirectional interactive PTY WebSocket streaming.
    Spawns /bin/bash in PROJECT_DIR and forwards bytes directly.
    """
    await websocket.accept()
    
    if not HAS_PTY:
        await websocket.send_text("PTY pseudo-terminal is required (Linux environment).")
        await websocket.close()
        return

    # Create pseudo-terminal pair (Linux / POSIX)
    master_fd, slave_fd = pty.openpty()
    
    # Initial terminal size: 95 cols x 26 rows
    set_pty_size(master_fd, 26, 95)
    
    env = os.environ.copy()
    env["TERM"] = "xterm-256color"
    env["PAGER"] = "cat"
    env["LANG"] = "C.UTF-8"
    env["LC_ALL"] = "C.UTF-8"
    env["COLORTERM"] = "truecolor"
    env["PATH"] = f"{PROJECT_DIR}:" + env.get("PATH", "")
    env["HOST_DIR"] = os.environ.get("HOST_DIR", str(PROJECT_DIR))
    env["PS1"] = r"\[\033[01;32m\]rootops\[\033[00m\]\$ "
    
    # Spawn bash process attached to slave PTY
    pid = os.fork()
    if pid == 0:
        # Child process
        os.close(master_fd)
        os.setsid()
        # Set controlling terminal
        fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
        os.dup2(slave_fd, 0)
        os.dup2(slave_fd, 1)
        os.dup2(slave_fd, 2)
        if slave_fd > 2:
            os.close(slave_fd)
        os.chdir(str(PROJECT_DIR))
        os.execvpe("/bin/bash", ["/bin/bash", "--norc"], env)
        sys.exit(1)
        
    # Parent process
    os.close(slave_fd)
    
    loop = asyncio.get_event_loop()
    
    # Welcome banner sent to terminal
    welcome_banner = (
        b"\r\n\x1b[1;36m========================================================================\x1b[0m\r\n"
        b"\x1b[1;32m  PS-036: PQC DNSSEC MTL BENCHMARK WORKBENCH - INTERACTIVE TERMINAL  \x1b[0m\r\n"
        b"\x1b[0;37m  Team: RootOps (A3-PS036-TC023) | DNSSEC PQC Verification Stack         \x1b[0m\r\n"
        b"\x1b[0;33m  Type commands or trigger actions from the Workbench controls on the left.\x1b[0m\r\n"
        b"\x1b[1;36m========================================================================\x1b[0m\r\n\r\n"
    )
    
    try:
        await websocket.send_bytes(welcome_banner)
    except Exception:
        pass
        
    pty_queue = asyncio.Queue()
    
    stop_event = threading.Event()

    def pty_reader_thread():
        """Read stdout/stderr from PTY master using select polling."""
        while not stop_event.is_set():
            try:
                r, _, _ = select.select([master_fd], [], [], 0.1)
                if not r:
                    continue
                data = os.read(master_fd, 8192)
                if not data:
                    break
                loop.call_soon_threadsafe(pty_queue.put_nowait, data)
            except (OSError, ValueError):
                break
        loop.call_soon_threadsafe(pty_queue.put_nowait, None)

    reader_thread = threading.Thread(target=pty_reader_thread, daemon=True)
    reader_thread.start()

    async def pty_forwarder():
        """Stream chunks from queue to WebSocket."""
        try:
            while True:
                chunk = await pty_queue.get()
                if chunk is None:
                    break
                await websocket.send_bytes(chunk)
        except (asyncio.CancelledError, WebSocketDisconnect):
            pass

    sender_task = asyncio.create_task(pty_forwarder())
    
    try:
        while True:
            # Receive input from WebSocket (keystrokes, commands, resize events)
            message = await websocket.receive()
            if "bytes" in message and message["bytes"]:
                os.write(master_fd, message["bytes"])
            elif "text" in message and message["text"]:
                text_data = message["text"]
                # Check if it's a JSON control command
                if text_data.startswith("{") and text_data.endswith("}"):
                    try:
                        cmd_obj = json.loads(text_data)
                        msg_type = cmd_obj.get("type")
                        if msg_type == "resize":
                            cols = int(cmd_obj.get("cols", 80))
                            rows = int(cmd_obj.get("rows", 24))
                            set_pty_size(master_fd, rows, cols)
                            continue
                        elif msg_type in ("sigint", "terminate"):
                            # Send Ctrl+C / SIGINT directly to master_fd and process group
                            try:
                                os.write(master_fd, b"\x03\x03\n")
                            except Exception:
                                pass
                            try:
                                os.killpg(os.getpgid(pid), signal.SIGINT)
                            except Exception:
                                pass
                            continue
                        elif msg_type == "command":
                            cmd_str = cmd_obj.get("command", "")
                            if cmd_str:
                                if not cmd_str.endswith("\n"):
                                    cmd_str += "\n"
                                os.write(master_fd, cmd_str.encode("utf-8"))
                            continue
                    except json.JSONDecodeError:
                        pass
                
                # Default text payload to stdin
                os.write(master_fd, text_data.encode("utf-8"))
                
    except (WebSocketDisconnect, asyncio.CancelledError, RuntimeError):
        pass
    finally:
        stop_event.set()
        sender_task.cancel()
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except Exception:
            pass
        try:
            os.close(master_fd)
        except Exception:
            pass
        try:
            os.waitpid(pid, os.WNOHANG)
        except Exception:
            pass

# Mount static files at /logos and / for the UI frontend
if LOGOS_DIR.exists():
    app.mount("/logos", StaticFiles(directory=str(LOGOS_DIR)), name="logos")

if STATIC_DIR.exists():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"[*] Starting PQC DNSSEC MTL Workbench Server on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="warning")
