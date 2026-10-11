/**
 * PQC DNSSEC MTL Benchmark Workbench - Client Logic
 * Terminal WebSocket handler, testbed command dispatch, and live status polling.
 */

// Global State
let term = null;
let fitAddon = null;
let ws = null;
let cmdHistory = [];
let historyIndex = -1;
let currentFigures = [];
let isTerminalCollapsed = false;

// Initialize Workbench on DOM Load
document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initTerminal();
  initTabs();
  initCLIInput();
  initStatusPolling();
  loadFiguresList();
  loadMetricsData();
  initFullscreenDefault();
});

/* ==========================================================================
   THEME (DARK / LIGHT MODE) ENGINE
   ========================================================================== */
function initTheme() {
  const saved = localStorage.getItem("pqc_theme") || "light";
  applyTheme(saved);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
  applyTheme(current);
}

function applyTheme(theme) {
  if (theme === "dark") {
    document.documentElement.setAttribute("data-theme", "dark");
    localStorage.setItem("pqc_theme", "dark");
    const icon = document.getElementById("theme-icon");
    const text = document.getElementById("theme-text");
    if (icon) icon.textContent = "☀️";
    if (text) text.textContent = "Light Mode";
  } else {
    document.documentElement.removeAttribute("data-theme");
    localStorage.setItem("pqc_theme", "light");
    const icon = document.getElementById("theme-icon");
    const text = document.getElementById("theme-text");
    if (icon) icon.textContent = "🌙";
    if (text) text.textContent = "Dark Mode";
  }
}

/* ==========================================================================
   TERMINAL COLLAPSE / EXPAND ENGINE
   ========================================================================== */
function setTerminalCollapsed(collapsed) {
  const container = document.getElementById("workbench-container");
  const expandStrip = document.getElementById("terminal-expand-strip");
  const termPanel = document.getElementById("terminal-panel");
  if (!container || !expandStrip || !termPanel) return;

  isTerminalCollapsed = collapsed;
  if (collapsed) {
    container.classList.add("terminal-collapsed");
    expandStrip.style.display = "flex";
    termPanel.style.display = "none";
  } else {
    container.classList.remove("terminal-collapsed");
    expandStrip.style.display = "none";
    termPanel.style.display = "flex";
    if (fitAddon) {
      setTimeout(() => {
        fitAddon.fit();
        sendResize();
      }, 100);
    }
  }
}

function toggleTerminalCollapse() {
  setTerminalCollapsed(!isTerminalCollapsed);
}

/* ==========================================================================
   TERMINAL & WEBSOCKET ENGINE
   ========================================================================== */
function initTerminal() {
  const container = document.getElementById("terminal-viewport");
  if (!container || !window.Terminal) return;

  term = new window.Terminal({
    theme: {
      background: "#0d1117",
      foreground: "#e6edf3",
      cursor: "#58a6ff",
      selectionBackground: "rgba(56, 139, 253, 0.4)",
      black: "#484f58",
      brightBlack: "#6e7681",
      red: "#ff7b72",
      brightRed: "#ffa198",
      green: "#3fb950",
      brightGreen: "#56d364",
      yellow: "#d29922",
      brightYellow: "#e3b341",
      blue: "#58a6ff",
      brightBlue: "#79c0ff",
      magenta: "#bc8cff",
      brightMagenta: "#d2a8ff",
      cyan: "#39c5cf",
      brightCyan: "#56d4dd",
      white: "#b1bac4",
      brightWhite: "#f0f6fc",
    },
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: 14,
    lineHeight: 1.35,
    cursorBlink: true,
    convertEol: true,
    scrollback: 10000,
  });

  if (window.FitAddon && window.FitAddon.FitAddon) {
    fitAddon = new window.FitAddon.FitAddon();
    term.loadAddon(fitAddon);
  }

  term.open(container);
  if (fitAddon) {
    setTimeout(() => fitAddon.fit(), 100);
  }

  window.addEventListener("resize", () => {
    if (fitAddon) {
      fitAddon.fit();
      sendResize();
    }
  });

  // Direct keyboard input to terminal
  term.onData((data) => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(data);
    }
  });

  connectWebSocket();
}

function connectWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws/terminal`;
  const statusEl = document.getElementById("term-status");

  if (statusEl) statusEl.textContent = "[CONNECTING...]";

  ws = new WebSocket(wsUrl);
  ws.binaryType = "arraybuffer";

  ws.onopen = () => {
    if (statusEl) {
      statusEl.textContent = "[READY]";
      statusEl.style.color = "#3fb950";
    }
    sendResize();
  };

  ws.onmessage = (event) => {
    if (term) {
      if (event.data instanceof ArrayBuffer) {
        term.write(new Uint8Array(event.data));
      } else {
        term.write(event.data);
      }
    }
  };

  ws.onclose = () => {
    if (statusEl) {
      statusEl.textContent = "[DISCONNECTED]";
      statusEl.style.color = "#f85149";
    }
    // Attempt reconnect after 2 seconds
    setTimeout(connectWebSocket, 2000);
  };

  ws.onerror = () => {
    if (statusEl) {
      statusEl.textContent = "[ERROR]";
      statusEl.style.color = "#f85149";
    }
  };
}

function sendResize() {
  if (ws && ws.readyState === WebSocket.OPEN && term) {
    ws.send(JSON.stringify({
      type: "resize",
      cols: term.cols,
      rows: term.rows
    }));
  }
}

function sendCmd(command) {
  if (!command) return;
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      type: "command",
      command: command
    }));
    term.focus();
  } else {
    alert("Terminal connection is not ready. Reconnecting...");
  }
}

function sendSigint() {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: "sigint" }));
  }
}

function terminateRunningProcess() {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: "terminate" }));
    // Also dispatch raw ETX (Ctrl+C, 0x03) bytes directly to the PTY stream
    const ctrlC = new Uint8Array([3, 3, 10]);
    ws.send(ctrlC.buffer);
    if (term) {
      term.write("\r\n\x1b[1;41;37m [PROCESS TERMINATED BY USER] \x1b[0m\r\n");
      term.focus();
    }
  } else {
    alert("Terminal connection is not ready. Reconnecting...");
  }
}

/* ==========================================================================
   FULLSCREEN TOGGLE ENGINE (DEFAULT FULLSCREEN ON LAUNCH)
   ========================================================================== */
let userExitedFullscreen = false;

function isFullScreenActive() {
  return !!(
    document.fullscreenElement ||
    document.webkitFullscreenElement ||
    document.mozFullScreenElement ||
    document.msFullscreenElement
  );
}

function enterFullScreen() {
  if (isFullScreenActive()) return;
  const docEl = document.documentElement;
  const req = docEl.requestFullscreen ||
              docEl.webkitRequestFullscreen ||
              docEl.mozRequestFullScreen ||
              docEl.msRequestFullscreen;
  if (req) {
    try {
      const p = req.call(docEl);
      if (p && typeof p.catch === "function") {
        p.catch(() => {
          // Handled gracefully: browsers may require user interaction gesture first
        });
      }
    } catch (_) {}
  }
}

function exitFullScreen() {
  userExitedFullscreen = true;
  if (!isFullScreenActive()) return;
  const ex = document.exitFullscreen ||
            document.webkitExitFullscreen ||
            document.mozCancelFullScreen ||
            document.msExitFullscreen;
  if (ex) {
    try {
      const p = ex.call(document);
      if (p && typeof p.catch === "function") {
        p.catch(() => {});
      }
    } catch (_) {}
  }
}

function toggleFullScreen() {
  if (isFullScreenActive()) {
    exitFullScreen();
  } else {
    userExitedFullscreen = false;
    enterFullScreen();
  }
}

function handleFullscreenChange() {
  const active = isFullScreenActive();
  const icon = document.getElementById("fullscreen-icon");
  const text = document.getElementById("fullscreen-text");
  const btn = document.getElementById("fullscreen-toggle");
  const introBtn = document.getElementById("intro-fullscreen-btn");

  if (active) {
    if (icon) icon.textContent = "⤢";
    if (text) text.textContent = "Exit Fullscreen";
    if (btn) btn.classList.add("active");
    if (introBtn) {
      introBtn.textContent = "⤢ Exit Fullscreen";
      introBtn.classList.add("active");
    }
  } else {
    if (icon) icon.textContent = "⛶";
    if (text) text.textContent = "Fullscreen";
    if (btn) btn.classList.remove("active");
    if (introBtn) {
      introBtn.textContent = "⛶ Fullscreen";
      introBtn.classList.remove("active");
    }
  }
}

document.addEventListener("fullscreenchange", handleFullscreenChange);
document.addEventListener("webkitfullscreenchange", handleFullscreenChange);
document.addEventListener("mozfullscreenchange", handleFullscreenChange);
document.addEventListener("MSFullscreenChange", handleFullscreenChange);

function initFullscreenDefault() {
  // 1. Attempt immediate fullscreen right on load
  enterFullScreen();

  // 2. Browser user-activation policy: enter fullscreen on first user interaction if not exited
  const onFirstGesture = () => {
    if (!userExitedFullscreen && !isFullScreenActive()) {
      enterFullScreen();
    }
  };

  window.addEventListener("pointerdown", onFirstGesture, { passive: true });
  window.addEventListener("keydown", onFirstGesture, { passive: true });
}

/* ==========================================================================
   INTRO / WELCOME SCREEN ENGINE (PS-036)
   ========================================================================== */
function dismissIntroScreen() {
  if (!userExitedFullscreen && !isFullScreenActive()) {
    enterFullScreen();
  }
  const intro = document.getElementById("intro-screen");
  if (!intro) return;
  intro.classList.add("fade-out");
  setTimeout(() => {
    intro.style.display = "none";
    if (fitAddon) {
      fitAddon.fit();
      sendResize();
    }
  }, 250);
}

function openIntroScreen() {
  const intro = document.getElementById("intro-screen");
  if (!intro) return;
  intro.style.display = "flex";
  intro.classList.remove("fade-out");
  handleFullscreenChange();
}

document.addEventListener("keydown", (e) => {
  const intro = document.getElementById("intro-screen");
  if (intro && intro.style.display !== "none" && !intro.classList.contains("fade-out")) {
    if (e.key === "Escape" || e.key === "Enter") {
      dismissIntroScreen();
    }
  }
});

function clearTerminal() {
  if (term) term.clear();
}

function copyTerminalText() {
  if (!term) return;
  term.selectAll();
  const text = term.getSelection();
  term.clearSelection();
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(() => {
      const statusEl = document.getElementById("term-status");
      const orig = statusEl.textContent;
      statusEl.textContent = "[COPIED BUFFER]";
      setTimeout(() => statusEl.textContent = orig, 1500);
    });
  }
}

/* ==========================================================================
   CLI INPUT BAR (COMMAND HISTORY)
   ========================================================================== */
function initCLIInput() {
  const inputEl = document.getElementById("cli-input");
  if (!inputEl) return;

  inputEl.addEventListener("keydown", (e) => {
    if (e.key === "ArrowUp") {
      e.preventDefault();
      if (cmdHistory.length > 0 && historyIndex < cmdHistory.length - 1) {
        historyIndex++;
        inputEl.value = cmdHistory[cmdHistory.length - 1 - historyIndex];
      }
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (historyIndex > 0) {
        historyIndex--;
        inputEl.value = cmdHistory[cmdHistory.length - 1 - historyIndex];
      } else if (historyIndex === 0) {
        historyIndex = -1;
        inputEl.value = "";
      }
    }
  });
}

function submitCliInput() {
  const inputEl = document.getElementById("cli-input");
  if (!inputEl) return;
  const cmd = inputEl.value.trim();
  if (cmd) {
    cmdHistory.push(cmd);
    historyIndex = -1;
    sendCmd(cmd);
    inputEl.value = "";
  }
}

/* ==========================================================================
   TAB NAVIGATION
   ========================================================================== */
function initTabs() {
  const tabButtons = document.querySelectorAll(".tab-btn");
  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-tab");
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const targetPane = document.getElementById(targetId);
      if (targetPane) targetPane.classList.add("active");

      // Auto-collapse terminal for sections that do not actively require it (metrics, figures, about)
      if (targetId === "tab-metrics" || targetId === "tab-figures" || targetId === "tab-about") {
        setTerminalCollapsed(true);
      } else {
        // Restore terminal for sections that do actively use the terminal
        setTerminalCollapsed(false);
      }

      // Dynamic load on tab view
      if (targetId === "tab-metrics") loadMetricsData();
      if (targetId === "tab-figures") loadFiguresList();
    });
  });
}

/* ==========================================================================
   WORKBENCH DISPATCH HELPERS
   ========================================================================== */
function triggerSigning() {
  const mode = document.querySelector('input[name="sign_mode"]:checked')?.value || "mtl";
  const ds = document.querySelector('input[name="sign_ds"]:checked')?.value || "small";
  sendCmd(`./tb.sh sign ${mode} ${ds} && ./tb.sh reload && ./tb.sh test`);
}

function triggerEvolve() {
  const count = document.getElementById("evolve-count")?.value || "50";
  sendCmd(`./tb.sh evolve ${count}`);
}

function runDigQuery() {
  const name = document.getElementById("diag-name")?.value.trim() || "host00001.aiori3.test";
  const type = document.getElementById("diag-type")?.value || "A";
  let flags = [];
  if (document.getElementById("flag-dnssec")?.checked) flags.push("+dnssec");
  if (document.getElementById("flag-multi")?.checked) flags.push("+multi");
  if (document.getElementById("flag-tcp")?.checked) flags.push("+tcp");
  if (document.getElementById("flag-trace")?.checked) flags.push("+trace @172.30.53.10");

  const flagStr = flags.join(" ");
  sendCmd(`./tb.sh dig ${flagStr} ${name} ${type}`);
}

function runValidateChain() {
  const name = document.getElementById("diag-name")?.value.trim() || "host00001.aiori3.test";
  sendCmd(`./tb.sh validate ${name}`);
}

function triggerBenchCrypto() {
  const trials = document.getElementById("crypto-trials")?.value || "5";
  sendCmd(`./tb.sh bench-crypto ${trials}`);
}

function triggerBenchDns() {
  const trials = document.getElementById("dns-trials")?.value || "5";
  const queries = document.getElementById("dns-queries")?.value || "300";
  const noCache = document.getElementById("dns-nocache")?.checked ? " --no-ladder-cache" : "";
  sendCmd(`./tb.sh bench-dns ${trials} ${queries}${noCache}`);
}

function triggerBenchEndurance() {
  const runs = document.getElementById("endurance-runs")?.value || "200";
  sendCmd(`./tb.sh bench-endurance ${runs}`);
}

/* ==========================================================================
   STATUS & TOPOLOGY POLLING
   ========================================================================== */
function initStatusPolling() {
  fetchStatus();
  setInterval(fetchStatus, 3500);
}

async function fetchStatus() {
  try {
    const res = await fetch("/api/status");
    if (!res.ok) return;
    const data = await res.json();
    renderStatus(data);
  } catch (e) {
    console.error("Status polling failed:", e);
  }
}

function renderStatus(data) {
  // Top Header Mode
  const hdrMode = document.getElementById("hdr-mode");
  const zm = data.zone_mode || {};
  if (zm.configured) {
    hdrMode.textContent = `${zm.mode.toUpperCase()} / ${zm.dataset} (${zm.hosts} hosts)`;
  } else {
    hdrMode.textContent = "UNCONFIGURED";
  }

  // Auth & Recursor health in header
  let authUp = 0;
  let recState = "DOWN";
  let clientState = "DOWN";

  const containers = data.containers || [];
  containers.forEach(c => {
    const isUp = c.state === "running";
    if (["root", "tld-lab", "sld-aiori"].includes(c.name) && isUp) {
      authUp++;
    }
    if (c.name === "resolver" && isUp) recState = "UP (53/8082)";
    if (c.name === "client" && isUp) clientState = "READY";
  });

  const hdrAuth = document.getElementById("hdr-auth");
  if (hdrAuth) hdrAuth.textContent = `${authUp} / 3 UP`;

  const hdrRec = document.getElementById("hdr-recursor");
  if (hdrRec) hdrRec.textContent = recState;

  const hdrClient = document.getElementById("hdr-client");
  if (hdrClient) hdrClient.textContent = clientState;

  // Topology Table
  const tbody = document.getElementById("topology-tbody");
  if (tbody && containers.length > 0) {
    tbody.innerHTML = containers.map(c => {
      const isUp = c.state === "running";
      const tagClass = isUp ? "up" : (c.state === "exited" ? "exited" : "down");
      const stateLabel = isUp ? "[RUNNING]" : `[${c.state.toUpperCase()}]`;
      return `
        <tr>
          <td><strong>${escapeHtml(c.name)}</strong></td>
          <td><code>${escapeHtml(c.ip)}</code></td>
          <td>${escapeHtml(c.role)}</td>
          <td><span class="status-tag ${tagClass}">${stateLabel}</span></td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="sendCmd('./tb.sh logs ${c.name} 30')">Logs</button>
          </td>
        </tr>
      `;
    }).join("");
  }

  // CPU Pinning
  const pin = data.pinning || {};
  if (document.getElementById("pin-auth")) document.getElementById("pin-auth").textContent = pin.AUTH_CPUS || "-";
  if (document.getElementById("pin-rec")) document.getElementById("pin-rec").textContent = pin.RESOLVER_CPUS || "-";
  if (document.getElementById("pin-client")) document.getElementById("pin-client").textContent = pin.CLIENT_CPUS || "-";
  if (document.getElementById("pin-bench")) document.getElementById("pin-bench").textContent = pin.BENCH_CPUS || "-";

  // Signing Metadata
  if (document.getElementById("meta-mode")) document.getElementById("meta-mode").textContent = zm.mode || "none";
  if (document.getElementById("meta-ds")) document.getElementById("meta-ds").textContent = zm.dataset || "none";
  if (document.getElementById("meta-hosts")) document.getElementById("meta-hosts").textContent = zm.hosts || 0;
  if (document.getElementById("meta-zones")) {
    document.getElementById("meta-zones").textContent = Array.isArray(zm.zones) ? zm.zones.join(", ") : "-";
  }
}

/* ==========================================================================
   METRICS & REPORT TABLES
   ========================================================================== */
async function loadMetricsData() {
  const container = document.getElementById("metrics-tables-container");
  if (!container) return;

  try {
    const res = await fetch("/api/metrics");
    const data = await res.json();
    if (!data.available) {
      container.innerHTML = `<div class="text-muted">${escapeHtml(data.message)}</div>`;
      return;
    }

    const tables = data.tables || {};
    let html = "";
    for (const [title, tbl] of Object.entries(tables)) {
      if (!tbl.headers || !tbl.rows) continue;
      html += `
        <div style="margin-bottom: 24px;">
          <div class="section-title">${escapeHtml(title)}</div>
          <table class="data-table">
            <thead>
              <tr>${tbl.headers.map(h => `<th>${escapeHtml(h)}</th>`).join("")}</tr>
            </thead>
            <tbody>
              ${tbl.rows.map(row => `
                <tr>${row.map((cell, idx) => {
                  const isNum = !isNaN(parseFloat(cell)) && isFinite(cell);
                  return `<td class="${isNum ? 'numeric' : ''}">${escapeHtml(cell)}</td>`;
                }).join("")}</tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      `;
    }
    container.innerHTML = html || '<div class="text-muted">No parsed tables found in report.</div>';
  } catch (e) {
    container.innerHTML = `<div class="text-muted">Error loading metrics: ${escapeHtml(e.message)}</div>`;
  }
}

/* ==========================================================================
   FIGURES & PLOTS VIEWER
   ========================================================================== */
async function loadFiguresList() {
  const selectorEl = document.getElementById("figure-selector-buttons");
  if (!selectorEl) return;

  try {
    const res = await fetch("/api/figures-list");
    const data = await res.json();
    currentFigures = data.figures || [];

    if (currentFigures.length === 0) {
      selectorEl.innerHTML = '<span class="text-muted">No figures found in results/figures/. Run ./tb.sh report.</span>';
      return;
    }

    selectorEl.innerHTML = currentFigures.map((fig, idx) => `
      <button class="figure-btn ${idx === 0 ? 'active' : ''}" onclick="selectFigure('${escapeHtml(fig.filename)}')">
        ${escapeHtml(fig.id)} (${fig.size_kb} KB)
      </button>
    `).join("");

    if (currentFigures.length > 0) {
      selectFigure(currentFigures[0].filename);
    }
  } catch (e) {
    console.error("Failed to load figures list:", e);
  }
}

function selectFigure(filename) {
  document.querySelectorAll(".figure-btn").forEach(btn => {
    btn.classList.toggle("active", btn.textContent.includes(filename.replace(".png", "")));
  });

  const imgEl = document.getElementById("figure-active-img");
  const emptyMsg = document.getElementById("figure-empty-msg");
  if (imgEl) {
    imgEl.src = `/api/figures/${filename}?t=${Date.now()}`;
    imgEl.style.display = "block";
    if (emptyMsg) emptyMsg.style.display = "none";
  }
}

async function toggleReportMarkdown() {
  const pre = document.getElementById("report-md-pre");
  if (!pre) return;

  if (pre.style.display === "none") {
    try {
      const res = await fetch("/api/report-markdown");
      if (res.ok) {
        pre.textContent = await res.text();
        pre.style.display = "block";
      } else {
        alert("REPORT.md is not generated yet. Run ./tb.sh report first.");
      }
    } catch (e) {
      alert("Error loading report: " + e.message);
    }
  } else {
    pre.style.display = "none";
  }
}

// Utility
function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
