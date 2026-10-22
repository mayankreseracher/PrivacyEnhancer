/**
 * TrackerControl PC — Reactive Dashboard Engine
 * WebSocket streaming, app privacy matrix, and Windows OS debloater.
 */

// Base API configuration for REST and WebSockets
const API_BASE = (window.location.protocol === "file:" || !window.location.host) 
  ? "http://127.0.0.1:8000" 
  : "";

let wsReconnectTimeout = null;
let wsAttemptCount = 0;

function showToast(title, message, type = "info", duration = 4000) {
  const container = document.getElementById("toastContainer");
  if (!container) return;

  const icons = {
    success: "✅",
    error: "❌",
    warn: "⚠️",
    info: "ℹ️",
    shield: "🛡️",
    vpn: "🔒"
  };

  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <span class="toast-icon">${icons[type] || "⚡"}</span>
    <div class="toast-body">
      <div class="toast-title">${escapeHtml(title)}</div>
      <div class="toast-msg">${escapeHtml(message)}</div>
    </div>
    <button class="toast-close" onclick="this.parentElement.remove()">&times;</button>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add("toast-fadeout");
    setTimeout(() => toast.remove(), 280);
  }, duration);
}

// Application State
const state = {
  ws: null,
  isPaused: false,
  connections: [],
  apps: [],
  rules: [],
  currentTab: 'graphTab',
  filter: 'all',
  searchQuery: '',
  bandwidthHistory: [],
  alerts: [],
  unreadAlertsCount: 0,
  graphPaused: false,
  graphWindowSeconds: 60,
  alertFilter: 'all',
  stats: {
    total_requests: 0,
    blocked_trackers: 0,
    monitored_apps: 0,
    top_companies: []
  },
  updater: {
    status: "idle",
    current_version: "1.0.6",
    latest_version: null,
    update_available: false,
    release_name: "",
    release_notes: "",
    html_url: "https://github.com/mayankreseracher/PrivacyEnhancer/releases",
    published_at: "",
    asset_name: "",
    asset_size: 0,
    download_progress: 0,
    download_speed_kbps: 0,
    downloaded_bytes: 0,
    total_bytes: 0,
    auto_check_enabled: true,
    error_message: null
  }
};

// Corporation Directory
const CORPORATE_PROFILES = [
  {
    name: "Alphabet Inc.",
    hq: "Mountain View, CA, USA",
    risk: "Extreme",
    badge: "#EA4335",
    desc: "Monopolizes cross-app advertising via DoubleClick, Firebase, Google Analytics, and Tag Manager.",
    domains: ["google-analytics.com", "doubleclick.net", "googlesyndication.com", "app-measurement.com"]
  },
  {
    name: "Microsoft Corporation",
    hq: "Redmond, WA, USA",
    risk: "High",
    badge: "#00A4EF",
    desc: "Collects system-level diagnostic telemetry, Windows Advertising IDs, and background Edge activity.",
    domains: ["v10.events.data.microsoft.com", "telemetry.microsoft.com", "watson.telemetry.microsoft.com"]
  },
  {
    name: "Meta Platforms Inc.",
    hq: "Menlo Park, CA, USA",
    risk: "Extreme",
    badge: "#1877F2",
    desc: "Tracks desktop browser activity and embedded webviews via Facebook Graph API and tracking pixels.",
    domains: ["graph.facebook.com", "pixel.facebook.com", "connect.facebook.net"]
  },
  {
    name: "ByteDance Ltd.",
    hq: "Beijing, China",
    risk: "High",
    badge: "#25F4EE",
    desc: "Cross-platform behavioral analytics and targeted advertising through Pangle and TikTok SDKs.",
    domains: ["byteoversea.com", "tiktokv.com", "pangolin-sdk-toutiao.com"]
  },
  {
    name: "Adobe Systems Inc.",
    hq: "San Jose, CA, USA",
    risk: "Medium",
    badge: "#FF0000",
    desc: "Embedded telemetry in Creative Cloud apps, user behavioral heatmaps, and Demdex DMP sync.",
    domains: ["demdex.net", "omtrdc.net", "cc-api-data.adobe.io"]
  },
  {
    name: "Twilio Inc. (Segment)",
    hq: "San Francisco, CA, USA",
    risk: "High",
    badge: "#F22F46",
    desc: "Customer Data Platform that ingests granular click and event streams from desktop software.",
    domains: ["segment.io", "api.segment.io"]
  }
];

// Helper: Format Time
function formatTime(timestamp) {
  const date = new Date(timestamp * 1000);
  return date.toTimeString().split(' ')[0];
}

// Helper: App Icon Identifier
function getAppIcon(name) {
  const n = (name || "").toLowerCase();
  if (n.includes("discord")) return "🎮";
  if (n.includes("spotify")) return "🎵";
  if (n.includes("chrome") || n.includes("brave") || n.includes("firefox")) return "🌐";
  if (n.includes("edge") || n.includes("msedge")) return "🌊";
  if (n.includes("steam")) return "🕹️";
  if (n.includes("code") || n.includes("cursor") || n.includes("devenv")) return "💻";
  if (n.includes("system") || n.includes("svchost") || n.includes("ntoskrnl")) return "⚙️";
  if (n.includes("vpn") || n.includes("proton")) return "🔒";
  if (n.includes("nvcontainer") || n.includes("nvidia")) return "⚡";
  return "📦";
}

// Helper: Category Badge Class
function getCategoryBadge(category) {
  const cat = (category || "").toLowerCase();
  if (cat.includes("ad")) return "badge badge-ad";
  if (cat.includes("telemetry") || cat.includes("windows")) return "badge badge-telemetry";
  if (cat.includes("analytics")) return "badge badge-analytics";
  if (cat.includes("social")) return "badge badge-social";
  return "badge badge-functional";
}

// ==================== WebSocket Initialization & Heartbeat ====================
let wsHeartbeatTimer = null;
let wsLastMessageTime = Date.now();

function getCandidateWsUrls() {
  const isHttps = window.location.protocol === "https:";
  const wsProto = isHttps ? "wss:" : "ws:";
  const host = window.location.host;
  
  const urls = [];
  // 1. Prefer current host that loaded the UI
  if (host && window.location.protocol !== "file:") {
    urls.push(`${wsProto}//${host}/ws`);
  }
  // 2. IPv4 loopback (primary for local desktop engine)
  urls.push(`${wsProto}//127.0.0.1:8000/ws`);
  // 3. Fallback hostname
  if (host !== "localhost:8000") {
    urls.push(`${wsProto}//localhost:8000/ws`);
  }
  return [...new Set(urls)];
}

function ensureRadarStatusOnline() {
  const pulse = document.getElementById("enginePulse");
  const status = document.getElementById("engineStatus");
  if (pulse && pulse.style.backgroundColor !== "rgb(0, 255, 157)") {
    pulse.style.backgroundColor = "#00ff9d";
  }
  if (status && status.textContent !== "RADAR ONLINE") {
    status.textContent = "RADAR ONLINE";
    status.style.color = "#00ff9d";
  }
}

function startWsHeartbeat() {
  if (wsHeartbeatTimer) clearInterval(wsHeartbeatTimer);
  wsHeartbeatTimer = setInterval(() => {
    if (state.ws && state.ws.readyState === WebSocket.OPEN) {
      try {
        state.ws.send(JSON.stringify({ type: "PING", timestamp: Date.now() }));
      } catch (e) {}
    }
    // Watchdog check: If no message has arrived for 35 seconds, force reconnect
    const elapsed = Date.now() - wsLastMessageTime;
    if (elapsed > 35000) {
      console.warn("[Radar] Watchdog timeout: No heartbeat for 35s. Reconnecting socket...");
      if (state.ws) {
        try { state.ws.close(); } catch (e) {}
      }
    }
  }, 4000);
}

function initWebSocket() {
  if (wsReconnectTimeout) {
    clearTimeout(wsReconnectTimeout);
    wsReconnectTimeout = null;
  }

  if (state.ws && (state.ws.readyState === WebSocket.OPEN || state.ws.readyState === WebSocket.CONNECTING)) {
    return;
  }

  const candidates = getCandidateWsUrls();
  const wsUrl = candidates[wsAttemptCount % candidates.length];

  try {
    state.ws = new WebSocket(wsUrl);
  } catch (err) {
    console.warn(`[Radar] WebSocket initialization error for ${wsUrl}:`, err);
    scheduleWsReconnect();
    return;
  }

  state.ws.onopen = () => {
    wsAttemptCount = 0;
    wsLastMessageTime = Date.now();
    ensureRadarStatusOnline();
    startWsHeartbeat();
    // Immediate handshake ping
    try {
      state.ws.send(JSON.stringify({ type: "PING", timestamp: Date.now() }));
    } catch (e) {}
  };

  state.ws.onmessage = (event) => {
    wsLastMessageTime = Date.now();
    ensureRadarStatusOnline();
    try {
      const msg = JSON.parse(event.data);
      if (msg.type === "PONG") {
        wsLastMessageTime = Date.now();
        ensureRadarStatusOnline();
        return;
      }
      if (msg.type === "INIT_STATE") {
        updateStats(msg.data.stats);
        if (msg.data.recent_connections) {
          state.connections = msg.data.recent_connections;
          renderWaterfall();
        }
        if (msg.data.bandwidth_history && Array.isArray(msg.data.bandwidth_history)) {
          state.bandwidthHistory = msg.data.bandwidth_history;
          if (state.bandwidthHistory.length > 0) {
            updateSpeedometers(state.bandwidthHistory[state.bandwidthHistory.length - 1]);
          }
        }
        if (msg.data.recent_alerts && Array.isArray(msg.data.recent_alerts)) {
          state.alerts = msg.data.recent_alerts;
          state.unreadAlertsCount = state.alerts.length;
          updateAlertsBadge();
          renderAlertsFeed();
        }
        if (msg.data.shield_active !== undefined) {
          const masterToggle = document.getElementById("masterShieldToggle");
          if (masterToggle) masterToggle.checked = !!msg.data.shield_active;
        }
        if (msg.data.protection_mode) {
          const modeSelect = document.getElementById("shieldModeSelect");
          if (modeSelect) modeSelect.value = msg.data.protection_mode;
        }
        if (msg.data.system_summary && msg.data.system_summary.os) {
          const hostBadge = document.getElementById("hostOsBadge");
          if (hostBadge) {
            const os = msg.data.system_summary.os.toLowerCase();
            const osIcons = { windows: "🪟 Windows", linux: "🐧 Linux", darwin: "🍎 macOS" };
            hostBadge.textContent = osIcons[os] || `🖥️ ${msg.data.system_summary.os}`;
          }
        }
        if (msg.data.updater) {
          updateUpdaterState(msg.data.updater);
        }
      } else if (msg.type === "NEW_CONNECTION") {
        handleNewConnection(msg.data);
      } else if (msg.type === "BANDWIDTH_TICK") {
        handleBandwidthTick(msg.data);
      } else if (msg.type === "SECURITY_ALERT") {
        handleSecurityAlert(msg.data);
      } else if (msg.type === "UPDATE_AVAILABLE") {
        handleUpdateAvailable(msg.data);
      } else if (msg.type === "UPDATE_PROGRESS") {
        handleUpdateProgress(msg.data);
      } else if (msg.type === "UPDATE_READY") {
        handleUpdateReady(msg.data);
      } else if (msg.type === "UPDATE_STATUS") {
        handleUpdateStatus(msg.data);
      }
    } catch (err) {
      console.error("WS Parse error:", err);
    }
  };

  state.ws.onerror = (err) => {
    console.warn("[Radar] WebSocket error:", err);
  };

  state.ws.onclose = () => {
    if (wsHeartbeatTimer) {
      clearInterval(wsHeartbeatTimer);
      wsHeartbeatTimer = null;
    }
    const pulse = document.getElementById("enginePulse");
    const status = document.getElementById("engineStatus");
    if (pulse) pulse.style.backgroundColor = "#ffaa00";
    if (status) {
      status.textContent = "RADAR RECONNECTING...";
      status.style.color = "#ffaa00";
    }
    scheduleWsReconnect();
  };
}

function startFallbackPoller() {
  if (window._fallbackPoller) return;
  window._fallbackPoller = setInterval(async () => {
    if (!state.ws || state.ws.readyState !== WebSocket.OPEN) {
      try {
        await bootstrapInitialState();
        ensureRadarStatusOnline();
      } catch (e) {}
    }
  }, 2500);
}

function scheduleWsReconnect() {
  if (wsReconnectTimeout) return;
  wsAttemptCount++;
  // Quick initial retry (500ms), backing off smoothly up to max 3000ms
  const delay = Math.min(500 + (wsAttemptCount * 300), 3000);
  wsReconnectTimeout = setTimeout(() => {
    wsReconnectTimeout = null;
    initWebSocket();
  }, delay);
}

// Bootstrap initial metrics via REST to guarantee immediate hydration
async function bootstrapInitialState() {
  startFallbackPoller();
  try {
    const [statsRes, connsRes, alertsRes, bwRes] = await Promise.allSettled([
      fetch(`${API_BASE}/api/stats`).then(r => r.json()),
      fetch(`${API_BASE}/api/connections?limit=50`).then(r => r.json()),
      fetch(`${API_BASE}/api/alerts`).then(r => r.json()),
      fetch(`${API_BASE}/api/bandwidth`).then(r => r.json())
    ]);

    if (statsRes.status === "fulfilled" && statsRes.value) {
      updateStats(statsRes.value);
    }
    if (connsRes.status === "fulfilled" && Array.isArray(connsRes.value)) {
      state.connections = connsRes.value;
      renderWaterfall();
    }
    if (alertsRes.status === "fulfilled" && Array.isArray(alertsRes.value)) {
      state.alerts = alertsRes.value;
      state.unreadAlertsCount = state.alerts.length;
      updateAlertsBadge();
      renderAlertsFeed();
    }
    if (bwRes.status === "fulfilled" && Array.isArray(bwRes.value)) {
      state.bandwidthHistory = bwRes.value;
      if (state.bandwidthHistory.length > 0) {
        updateSpeedometers(state.bandwidthHistory[state.bandwidthHistory.length - 1]);
      }
    }

    loadUpdaterStatus();
  } catch (err) {
    console.warn("Bootstrap initial state fetch error:", err);
  }
}

function handleNewConnection(conn) {
  // Update internal counters
  state.stats.total_requests++;
  if (conn.status === "blocked") {
    state.stats.blocked_trackers++;
  }
  updateStatsDisplay();

  if (state.isPaused) return;

  state.connections.unshift(conn);
  if (state.connections.length > 250) {
    state.connections.pop();
  }

  // Prepend row to table if it matches current filter
  if (matchesFilter(conn)) {
    const tbody = document.getElementById("waterfallBody");
    const tr = createConnectionRow(conn);
    
    // If placeholder row exists, remove it
    if (tbody.children.length === 1 && tbody.children[0].innerText.includes("Listening")) {
      tbody.innerHTML = "";
    }

    tbody.insertBefore(tr, tbody.firstChild);
    if (tbody.children.length > 150) {
      tbody.removeChild(tbody.lastChild);
    }
  }
}

// ==================== GlassWire Bandwidth & Speedometers ====================
function handleBandwidthTick(point) {
  if (!point) return;
  state.bandwidthHistory.push(point);
  if (state.bandwidthHistory.length > 600) {
    state.bandwidthHistory.shift();
  }
  updateSpeedometers(point);
}

function updateSpeedometers(point) {
  if (!point) return;
  const rxEl = document.getElementById("graphRxSpeed");
  const txEl = document.getElementById("graphTxSpeed");
  const totRxEl = document.getElementById("graphTotalRx");
  const totTxEl = document.getElementById("graphTotalTx");
  const dropEl = document.getElementById("graphDroppedCount");
  const socksEl = document.getElementById("graphActiveSocketsCount");

  if (rxEl) rxEl.textContent = (point.rx_kbps || 0).toFixed(2);
  if (txEl) txEl.textContent = (point.tx_kbps || 0).toFixed(2);
  if (totRxEl) totRxEl.textContent = `${(point.total_rx_mb || 0).toFixed(2)} MB`;
  if (totTxEl) totTxEl.textContent = `${(point.total_tx_mb || 0).toFixed(2)} MB`;
  if (dropEl) dropEl.textContent = state.stats.blocked_trackers.toLocaleString();
  if (socksEl) socksEl.textContent = (state.stats.monitored_apps || state.apps.length || 0).toString();
}

// ==================== GlassWire Security Alerts ====================
function handleSecurityAlert(alertItem) {
  if (!alertItem) return;
  state.alerts.unshift(alertItem);
  if (state.alerts.length > 200) {
    state.alerts.pop();
  }
  state.unreadAlertsCount++;
  updateAlertsBadge();
  renderAlertsFeed();
}

function updateAlertsBadge() {
  const badge = document.getElementById("alertsNavBadge");
  if (!badge) return;
  if (state.unreadAlertsCount > 0) {
    badge.textContent = state.unreadAlertsCount > 99 ? "99+" : state.unreadAlertsCount.toString();
    badge.style.display = "inline-block";
  } else {
    badge.style.display = "none";
  }
}

function renderAlertsFeed() {
  const container = document.getElementById("alertsFeedContainer");
  if (!container) return;

  const countAll = document.getElementById("alertCountAll");
  const countNewApp = document.getElementById("alertCountNewApp");
  const countBlocked = document.getElementById("alertCountBlocked");

  const totalAll = state.alerts.length;
  const totalNewApps = state.alerts.filter(a => a.type === "NEW_APP").length;
  const totalBlocked = state.alerts.filter(a => a.type === "TRACKER_BLOCKED").length;

  if (countAll) countAll.textContent = totalAll;
  if (countNewApp) countNewApp.textContent = totalNewApps;
  if (countBlocked) countBlocked.textContent = totalBlocked;

  let filtered = state.alerts;
  if (state.alertFilter === "NEW_APP") {
    filtered = state.alerts.filter(a => a.type === "NEW_APP");
  } else if (state.alertFilter === "TRACKER_BLOCKED") {
    filtered = state.alerts.filter(a => a.type === "TRACKER_BLOCKED");
  } else if (state.alertFilter === "warning") {
    filtered = state.alerts.filter(a => a.severity === "warning" || a.severity === "critical");
  }

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="glass-panel" style="padding: 40px; text-align: center; color: var(--text-muted);">
        No security alerts found in current filter. All network sockets are safe!
      </div>
    `;
    return;
  }

  container.innerHTML = "";
  filtered.forEach(alert => {
    const card = document.createElement("div");
    card.className = `alert-card severity-${alert.severity || 'info'}`;
    const pName = alert.process_name || 'App';
    const isNewApp = alert.type === "NEW_APP";

    card.innerHTML = `
      <div class="alert-left-content">
        <div class="alert-icon-avatar">
          ${isNewApp ? getAppIcon(pName) : '🛡️'}
        </div>
        <div class="alert-details">
          <h4>
            <span>${escapeHtml(alert.title || 'Security Notification')}</span>
            <span class="badge ${alert.severity === 'warning' ? 'badge-blocked' : 'badge-allowed'}">
              ${isNewApp ? '✨ First Network Access' : '🚫 Threat Blocked'}
            </span>
          </h4>
          <p>${escapeHtml(alert.message || '')}</p>
          <div class="alert-tag-row">
            <span class="alert-chip">📦 ${escapeHtml(pName)}</span>
            ${alert.domain ? `<span class="alert-chip">🌐 ${escapeHtml(alert.domain)}</span>` : ''}
            ${alert.ip ? `<span class="alert-chip">📍 ${escapeHtml(alert.ip)}</span>` : ''}
            ${alert.company ? `<span class="alert-chip">🏢 ${escapeHtml(alert.company)}</span>` : ''}
            ${alert.category ? `<span class="alert-chip">🏷️ ${escapeHtml(alert.category)}</span>` : ''}
            <span class="alert-time">🕒 ${formatTime(alert.timestamp || (Date.now()/1000))}</span>
          </div>
        </div>
      </div>
      <div class="alert-right-actions">
        ${isNewApp ? `
          <button class="btn-action" onclick="setAppPolicy('${escapeHtml(pName)}', 'block_trackers'); showToast('Shield Armed', 'Shield armed for ${escapeHtml(pName)}! Trackers will be dropped.', 'shield')">
            🛡️ Shield Trackers
          </button>
          <button class="btn-action btn-danger" onclick="setAppPolicy('${escapeHtml(pName)}', 'block_all'); showToast('Firewalled', '${escapeHtml(pName)} outbound network access firewalled.', 'error')">
            🛑 Block All
          </button>
        ` : `
          <span class="badge badge-blocked" style="padding: 6px 12px; font-weight: 700;">Neutralized 🛡️</span>
        `}
      </div>
    `;
    container.appendChild(card);
  });
}

// ==================== Live Network Activity Wave Graph (GlassWire Canvas) ====================
let graphAnimFrameId = null;

function initNetworkGraph() {
  const canvas = document.getElementById("networkGraphCanvas");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");

  // Handle Resize & DPI Scaling
  function resizeCanvas() {
    if (!canvas.parentElement) return;
    const rect = canvas.parentElement.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);
  }

  window.addEventListener("resize", resizeCanvas);
  resizeCanvas();

  // Time buttons setup
  document.querySelectorAll(".time-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".time-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      state.graphWindowSeconds = parseInt(btn.getAttribute("data-seconds")) || 60;
    });
  });

  // Pause / Resume graph
  const pauseBtn = document.getElementById("toggleGraphPauseBtn");
  if (pauseBtn) {
    pauseBtn.addEventListener("click", () => {
      state.graphPaused = !state.graphPaused;
      pauseBtn.textContent = state.graphPaused ? "▶️ Resume" : "⏸️ Pause";
      pauseBtn.classList.toggle("btn-danger", state.graphPaused);
    });
  }

  // Alerts Clear Button
  const clearAlertsBtn = document.getElementById("clearAlertsBtn");
  if (clearAlertsBtn) {
    clearAlertsBtn.addEventListener("click", async () => {
      try {
        await fetch(`${API_BASE}/api/alerts/clear`, { method: "POST" });
        state.alerts = [];
        state.unreadAlertsCount = 0;
        updateAlertsBadge();
        renderAlertsFeed();
      } catch (e) {
        console.error("Error clearing alerts:", e);
      }
    });
  }

  // Alerts filter buttons
  document.querySelectorAll(".alert-filter-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".alert-filter-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      state.alertFilter = btn.getAttribute("data-alert-filter");
      renderAlertsFeed();
    });
  });

  // Render Loop
  function drawGraph() {
    if (!canvas.parentElement) return;
    const rect = canvas.parentElement.getBoundingClientRect();
    const width = rect.width;
    const height = rect.height;
    if (width === 0 || height === 0) {
      graphAnimFrameId = requestAnimationFrame(drawGraph);
      return;
    }

    ctx.clearRect(0, 0, width, height);

    // Filter points in selected window
    const now = Date.now() / 1000;
    const windowSecs = state.graphWindowSeconds || 60;
    const minTime = now - windowSecs;

    // Use current history or mock baseline if starting empty
    let points = state.bandwidthHistory.filter(p => p.timestamp >= minTime);
    if (points.length < 2) {
      points = [
        { timestamp: minTime, rx_kbps: 0, tx_kbps: 0, blocked_recent: 0 },
        { timestamp: now, rx_kbps: 0, tx_kbps: 0, blocked_recent: 0 }
      ];
    }

    // Determine max peak for auto-scaling
    let maxKbps = 20; // baseline floor
    points.forEach(p => {
      if (p.rx_kbps > maxKbps) maxKbps = p.rx_kbps;
      if (p.tx_kbps > maxKbps) maxKbps = p.tx_kbps;
    });
    maxKbps = Math.ceil(maxKbps * 1.25); // 25% headroom

    const paddingLeft = 50;
    const paddingBottom = 26;
    const paddingTop = 16;
    const paddingRight = 18;

    const plotW = Math.max(10, width - paddingLeft - paddingRight);
    const plotH = Math.max(10, height - paddingTop - paddingBottom);

    // Draw horizontal grid lines & scale labels
    ctx.font = "10px 'JetBrains Mono', monospace";
    ctx.textAlign = "right";
    ctx.textBaseline = "middle";

    const gridLines = 4;
    for (let i = 0; i <= gridLines; i++) {
      const yVal = (maxKbps / gridLines) * i;
      const yPos = paddingTop + plotH - (plotH * (i / gridLines));

      ctx.beginPath();
      ctx.strokeStyle = "rgba(255, 255, 255, 0.06)";
      ctx.lineWidth = 1;
      ctx.setLineDash([4, 4]);
      ctx.moveTo(paddingLeft, yPos);
      ctx.lineTo(width - paddingRight, yPos);
      ctx.stroke();
      ctx.setLineDash([]);

      ctx.fillStyle = "rgba(160, 174, 192, 0.7)";
      const label = yVal >= 1024 ? `${(yVal/1024).toFixed(1)}M` : `${Math.round(yVal)}K`;
      ctx.fillText(label, paddingLeft - 8, yPos);
    }

    // Coordinates mapping
    function getX(ts) {
      const ratio = (ts - minTime) / windowSecs;
      return paddingLeft + Math.max(0, Math.min(1, ratio)) * plotW;
    }

    function getY(kbps) {
      const ratio = kbps / maxKbps;
      return paddingTop + plotH - (Math.max(0, Math.min(1, ratio)) * plotH);
    }

    // Function to draw smooth wave path with gradient fill
    function drawWave(key, strokeColor, fillColorTop, fillColorBottom) {
      if (points.length < 2) return;

      const pathPoints = points.map(p => ({ x: getX(p.timestamp), y: getY(p[key] || 0) }));

      ctx.save();
      // Wave outline
      ctx.beginPath();
      ctx.moveTo(pathPoints[0].x, pathPoints[0].y);

      for (let i = 1; i < pathPoints.length; i++) {
        const xc = (pathPoints[i - 1].x + pathPoints[i].x) / 2;
        const yc = (pathPoints[i - 1].y + pathPoints[i].y) / 2;
        ctx.quadraticCurveTo(pathPoints[i - 1].x, pathPoints[i - 1].y, xc, yc);
      }
      ctx.lineTo(pathPoints[pathPoints.length - 1].x, pathPoints[pathPoints.length - 1].y);

      // Save stroke for glowing line
      ctx.strokeStyle = strokeColor;
      ctx.lineWidth = 2.5;
      ctx.shadowColor = strokeColor;
      ctx.shadowBlur = 10;
      ctx.stroke();

      // Fill area under curve
      const gradient = ctx.createLinearGradient(0, paddingTop, 0, paddingTop + plotH);
      gradient.addColorStop(0, fillColorTop);
      gradient.addColorStop(1, fillColorBottom);

      ctx.lineTo(pathPoints[pathPoints.length - 1].x, paddingTop + plotH);
      ctx.lineTo(pathPoints[0].x, paddingTop + plotH);
      ctx.closePath();
      ctx.fillStyle = gradient;
      ctx.shadowBlur = 0;
      ctx.fill();
      ctx.restore();
    }

    // Draw Cyan Download (Rx) Wave
    drawWave("rx_kbps", "#00e5ff", "rgba(0, 229, 255, 0.35)", "rgba(0, 229, 255, 0.0)");

    // Draw Magenta Upload (Tx) Wave
    drawWave("tx_kbps", "#ff007f", "rgba(255, 0, 127, 0.30)", "rgba(255, 0, 127, 0.0)");

    // Draw Blocked Tracker Drop Markers
    points.forEach(p => {
      if (p.blocked_recent && p.blocked_recent > 0) {
        const x = getX(p.timestamp);
        const y = Math.min(getY(p.rx_kbps || 0), getY(p.tx_kbps || 0)) - 10;
        ctx.save();
        ctx.beginPath();
        ctx.arc(x, Math.max(paddingTop + 6, y), 5, 0, Math.PI * 2);
        ctx.fillStyle = "#ff9100";
        ctx.shadowColor = "#ff9100";
        ctx.shadowBlur = 12;
        ctx.fill();
        ctx.restore();
      }
    });

    // Draw Right-Edge Pulsing Playhead
    const lastP = points[points.length - 1];
    if (lastP) {
      const rxX = getX(lastP.timestamp);
      const rxY = getY(lastP.rx_kbps || 0);
      const txY = getY(lastP.tx_kbps || 0);

      // Cyan pulse dot
      ctx.save();
      ctx.beginPath();
      ctx.arc(rxX, rxY, 4, 0, Math.PI * 2);
      ctx.fillStyle = "#00e5ff";
      ctx.shadowColor = "#00e5ff";
      ctx.shadowBlur = 14;
      ctx.fill();

      // Magenta pulse dot
      ctx.beginPath();
      ctx.arc(rxX, txY, 4, 0, Math.PI * 2);
      ctx.fillStyle = "#ff007f";
      ctx.shadowColor = "#ff007f";
      ctx.shadowBlur = 14;
      ctx.fill();
      ctx.restore();
    }

    if (!state.graphPaused) {
      graphAnimFrameId = requestAnimationFrame(drawGraph);
    } else {
      setTimeout(() => {
        graphAnimFrameId = requestAnimationFrame(drawGraph);
      }, 500);
    }
  }

  // Start graph loop
  if (graphAnimFrameId) cancelAnimationFrame(graphAnimFrameId);
  graphAnimFrameId = requestAnimationFrame(drawGraph);
}

function matchesFilter(conn) {
  const query = state.searchQuery.toLowerCase();
  if (query) {
    const searchable = `${conn.process_name || ""} ${conn.domain || ""} ${conn.company || ""} ${conn.category || ""}`.toLowerCase();
    if (!searchable.includes(query)) return false;
  }

  const cat = conn.category || "";
  if (state.filter === "blocked") return conn.status === "blocked";
  if (state.filter === "trackers") return cat !== "Functional" && cat !== "Infrastructure";
  if (state.filter === "telemetry") return cat.includes("Telemetry") || cat.includes("Windows");

  return true;
}

function createConnectionRow(conn) {
  const tr = document.createElement("tr");
  if (conn.status === "blocked") {
    tr.className = "row-blocked";
  }

  const isBlocked = conn.status === "blocked";
  const statusBadge = isBlocked 
    ? `<span class="badge badge-blocked">🛑 Neutralized</span>`
    : `<span class="badge badge-allowed">🟢 Allowed</span>`;

  tr.innerHTML = `
    <td style="font-family: var(--font-mono); color: var(--text-muted); font-size: 0.8rem;">${formatTime(conn.timestamp)}</td>
    <td>
      <div style="display: flex; align-items: center; gap: 8px;">
        <span style="font-size: 1.1rem;">${getAppIcon(conn.process_name)}</span>
        <div>
          <div style="font-weight: 700; color: #fff;">${escapeHtml(conn.process_name)}</div>
          <div style="font-size: 0.7rem; color: var(--text-muted);">PID: ${conn.pid || 'N/A'}</div>
        </div>
      </div>
    </td>
    <td>
      <div style="font-weight: 600; color: ${isBlocked ? '#ff7096' : '#fff'}; word-break: break-all;">
        ${escapeHtml(conn.domain || conn.ip)}
      </div>
      <div style="font-size: 0.7rem; color: var(--text-muted);">${conn.ip}:${conn.port}</div>
    </td>
    <td>
      <div style="font-size: 0.85rem; font-weight: 600; color: #e2e8f0;">
        ${escapeHtml(conn.company || 'Unknown')}
      </div>
    </td>
    <td>
      <span class="${getCategoryBadge(conn.category)}">${escapeHtml(conn.category)}</span>
    </td>
    <td>
      <span style="font-size: 0.75rem; font-weight: 700; color: ${conn.risk === 'High' || conn.risk === 'Extreme' ? 'var(--accent-block)' : 'var(--text-muted)'};">
        ${escapeHtml(conn.risk || 'Clean')}
      </span>
    </td>
    <td>
      ${statusBadge}
    </td>
  `;
  return tr;
}

function renderWaterfall() {
  const tbody = document.getElementById("waterfallBody");
  tbody.innerHTML = "";

  const filtered = state.connections.filter(matchesFilter);
  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 30px;">No matching connections recorded yet.</td></tr>`;
    return;
  }

  filtered.slice(0, 100).forEach(conn => {
    tbody.appendChild(createConnectionRow(conn));
  });
}

// ==================== App Matrix Renderer ====================
async function loadApps() {
  try {
    const res = await fetch(`${API_BASE}/api/apps`);
    state.apps = await res.json();
    renderAppMatrix();
  } catch (err) {
    console.error("Error loading apps:", err);
  }
}

function renderAppMatrix() {
  const container = document.getElementById("appMatrixGrid");
  container.innerHTML = "";

  if (state.apps.length === 0) {
    container.innerHTML = `<div class="glass-panel" style="grid-column: 1/-1; padding: 40px; text-align: center; color: var(--text-muted);">Scanning desktop applications... Keep browsing or using desktop apps to populate the matrix.</div>`;
    return;
  }

  state.apps.forEach(app => {
    const card = document.createElement("div");
    card.className = "glass-panel app-card";

    const cleanRate = app.total_requests > 0 
      ? Math.max(0, Math.round(((app.total_requests - app.trackers_detected) / app.total_requests) * 100))
      : 100;

    card.innerHTML = `
      <div>
        <div class="app-card-header">
          <div class="app-title-group">
            <div class="app-icon">${getAppIcon(app.process_name)}</div>
            <div>
              <div class="app-name">${escapeHtml(app.process_name)}</div>
              <div class="app-path" title="${escapeHtml(app.exe_path)}">${escapeHtml(app.exe_path)}</div>
            </div>
          </div>
        </div>

        <div class="app-stats-row">
          <div>
            <div style="color: var(--text-muted);">Total Requests</div>
            <div style="font-weight: 700; color: #fff;">${app.total_requests}</div>
          </div>
          <div>
            <div style="color: var(--accent-block);">Trackers Caught</div>
            <div style="font-weight: 700; color: var(--accent-block);">${app.trackers_detected}</div>
          </div>
          <div>
            <div style="color: var(--accent-safe);">Privacy Health</div>
            <div style="font-weight: 700; color: var(--accent-safe);">${cleanRate}%</div>
          </div>
        </div>
      </div>

      <div>
        <label style="font-size: 0.75rem; color: var(--text-muted); display: block; margin-bottom: 4px;">GlassWire Firewall & Tracker Policy:</label>
        <div class="app-firewall-buttons">
          <button class="app-fw-btn ${app.control_mode === 'allow_all' ? 'active-allow' : ''}" onclick="setAppPolicy('${escapeHtml(app.process_name)}', 'allow_all')">
            🟢 Allow All
          </button>
          <button class="app-fw-btn ${app.control_mode === 'block_trackers' ? 'active-trackers' : ''}" onclick="setAppPolicy('${escapeHtml(app.process_name)}', 'block_trackers')">
            🛡️ Drop Trackers
          </button>
          <button class="app-fw-btn ${app.control_mode === 'block_all' ? 'active-block' : ''}" onclick="setAppPolicy('${escapeHtml(app.process_name)}', 'block_all')">
            🚫 Firewall App
          </button>
        </div>
      </div>
    `;
    container.appendChild(card);
  });
}

async function setAppPolicy(appName, mode) {
  try {
    await fetch(`${API_BASE}/api/apps/${encodeURIComponent(appName)}/mode`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode })
    });
    const found = state.apps.find(a => a.process_name === appName);
    if (found) {
      found.control_mode = mode;
      renderAppMatrix();
    }
  } catch (err) {
    console.error("Error setting app policy:", err);
  }
}

// ==================== Corporate Surveillance Matrix ====================
function renderSurveillanceMatrix() {
  const container = document.getElementById("companyProfilesContainer");
  container.innerHTML = "";

  CORPORATE_PROFILES.forEach(comp => {
    const card = document.createElement("div");
    card.className = "glass-panel";
    card.style.padding = "20px";

    const domainList = comp.domains.map(d => `<code style="background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px; font-size: 0.75rem;">${d}</code>`).join(" ");

    card.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
        <h3 style="font-size: 1.1rem; color: #fff; font-weight: 700;">${comp.name}</h3>
        <span class="badge" style="background: rgba(255,0,85,0.15); color: var(--accent-block); border: 1px solid rgba(255,0,85,0.3);">${comp.risk} Risk</span>
      </div>
      <p style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 8px;">📍 ${comp.hq}</p>
      <p style="font-size: 0.85rem; color: #cbd5e1; margin-bottom: 14px; line-height: 1.4;">${comp.desc}</p>
      <div>
        <div style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 6px;">Key Intercepted Endpoints:</div>
        <div style="display: flex; flex-wrap: wrap; gap: 6px;">${domainList}</div>
      </div>
    `;
    container.appendChild(card);
  });
}

// ==================== Rules Management ====================
async function loadRules() {
  try {
    const res = await fetch(`${API_BASE}/api/rules`);
    state.rules = await res.json();
    renderRules();
  } catch (err) {
    console.error("Error loading rules:", err);
  }
}

function renderRules() {
  const tbody = document.getElementById("rulesTableBody");
  tbody.innerHTML = "";

  if (state.rules.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 20px;">No custom rules configured yet.</td></tr>`;
    return;
  }

  state.rules.forEach(rule => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><span class="badge badge-functional">${rule.target_type.toUpperCase()}</span></td>
      <td style="font-family: var(--font-mono); font-weight: 700;">${escapeHtml(rule.target_value)}</td>
      <td>
        <span class="badge ${rule.action === 'block' ? 'badge-blocked' : 'badge-allowed'}">
          ${rule.action === 'block' ? '🚫 Block' : '🟢 Allow'}
        </span>
      </td>
      <td style="color: var(--text-muted); font-size: 0.8rem;">${formatTime(rule.created_at)}</td>
      <td>
        <button class="btn-action btn-danger" onclick="deleteRule(${rule.id})">Delete</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

async function addCustomRule() {
  const type = document.getElementById("ruleTargetType").value;
  const value = document.getElementById("ruleTargetValue").value.trim();
  const action = document.getElementById("ruleAction").value;

  if (!value) {
    showToast("Validation", "Please enter a domain or IP target.", "warn");
    return;
  }

  try {
    await fetch(`${API_BASE}/api/rules`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_type: type, target_value: value, action })
    });
    document.getElementById("ruleTargetValue").value = "";
    showToast("Rule Enforced", `Custom rule added for ${value}!`, "success");
    loadRules();
  } catch (err) {
    showToast("Rule Error", "Error adding rule: " + err, "error");
  }
}

async function deleteRule(id) {
  try {
    await fetch(`${API_BASE}/api/rules/${id}`, { method: "DELETE" });
    showToast("Rule Removed", "Custom rule deleted.", "info");
    loadRules();
  } catch (err) {
    showToast("Rule Error", "Error deleting rule: " + err, "error");
  }
}

// ==================== Cross-Platform OS Info & Privacy Controls ====================
async function loadOsInfoAndPrivacy() {
  try {
    const [osRes, privRes] = await Promise.all([
      fetch(`${API_BASE}/api/os-info`),
      fetch(`${API_BASE}/api/telemetry/status`)
    ]);
    const osInfo = await osRes.json();
    const privStatus = await privRes.json();
    renderOsPrivacy(osInfo, privStatus);
  } catch (err) {
    console.error("Error loading OS privacy info:", err);
  }
}

function renderOsPrivacy(osInfo, privStatus) {
  const badge = document.getElementById("hostOsBadge");
  const tabIcon = document.getElementById("osTabIcon");
  const tabTitle = document.getElementById("osTabTitle");
  const debloaterTitle = document.getElementById("osDebloaterTitle");
  const debloaterSubtitle = document.getElementById("osDebloaterSubtitle");
  const listContainer = document.getElementById("osPrivacyList");

  if (!listContainer) return;
  listContainer.innerHTML = "";

  const isLinux = osInfo.is_linux;
  const isWindows = osInfo.is_windows;
  const isMac = osInfo.is_macos || (osInfo.platform_name && osInfo.platform_name.toLowerCase().includes("mac"));

  if (badge) {
    if (isLinux) {
      badge.textContent = `🐧 ${osInfo.platform_name || 'Linux'}`;
    } else if (isWindows) {
      badge.textContent = `🖥️ ${osInfo.platform_name || 'Windows'}`;
    } else if (isMac) {
      badge.textContent = `🍎 ${osInfo.platform_name || 'macOS'}`;
    } else {
      badge.textContent = `💻 ${osInfo.platform_name || 'Host OS'}`;
    }
  }

  if (isMac) {
    if (tabIcon) tabIcon.textContent = "🍎";
    if (tabTitle) tabTitle.textContent = "macOS Privacy & Telemetry";
    if (debloaterTitle) debloaterTitle.textContent = `macOS Privacy & Telemetry Neutralizer (${osInfo.platform_name || 'macOS'})`;
    if (debloaterSubtitle) debloaterSubtitle.textContent = `BSD Packet Filter: ${osInfo.firewall_backend || 'pfctl'}. Block background Apple telemetry, crash collectors, personalized ad profiling, and Siri search leaks.`;

    const services = privStatus.services || {};
    const serviceKeys = Object.keys(services);

    if (serviceKeys.length === 0) {
      listContainer.innerHTML = `<div class="glass-panel" style="padding: 20px; text-align: center; color: var(--text-muted);">macOS telemetry status loaded. System is hardened!</div>`;
      return;
    }

    serviceKeys.forEach(sKey => {
      const s = services[sKey];
      const card = document.createElement("div");
      card.className = "glass-panel os-item";
      const isRunning = s.running;

      card.innerHTML = `
        <div class="os-item-info">
          <div style="display: flex; align-items: center; gap: 8px;">
            <h4>${escapeHtml(s.name || sKey)}</h4>
            <span class="badge ${isRunning ? 'badge-blocked' : 'badge-allowed'}">
              ${isRunning ? '⚠️ Telemetry Active' : '🛡️ Neutralized & Silenced'}
            </span>
          </div>
          <p>${escapeHtml(s.description)}</p>
        </div>
        <div>
          ${isRunning ? `
            <button class="btn-action btn-danger" onclick="toggleTelemetryService('${sKey}', true)">
              🚫 Neutralize Telemetry
            </button>
          ` : `
            <button class="btn-action" onclick="toggleTelemetryService('${sKey}', false)">
              🔄 Re-enable
            </button>
          `}
        </div>
      `;
      listContainer.appendChild(card);
    });

  } else if (isLinux) {
    if (tabIcon) tabIcon.textContent = "🐧";
    if (tabTitle) tabTitle.textContent = "Linux Telemetry Neutralizer";
    if (debloaterTitle) debloaterTitle.textContent = `Linux OS Telemetry & Privacy Shield (${osInfo.platform_name || 'Universal Linux'})`;
    if (debloaterSubtitle) debloaterSubtitle.textContent = `Kernel packet filter: ${osInfo.firewall_backend || 'iptables/nftables'}. Disable background crash collectors, package surveys, and metrics submitters.`;

    const services = privStatus.services || {};
    const serviceKeys = Object.keys(services);

    if (serviceKeys.length === 0) {
      listContainer.innerHTML = `<div class="glass-panel" style="padding: 20px; text-align: center; color: var(--text-muted);">No active proprietary telemetry daemons detected on this Linux distribution. Clean system!</div>`;
      return;
    }

    serviceKeys.forEach(sName => {
      const s = services[sName];
      const card = document.createElement("div");
      card.className = "glass-panel os-item";
      const isRunning = s.running;

      card.innerHTML = `
        <div class="os-item-info">
          <div style="display: flex; align-items: center; gap: 8px;">
            <h4>${escapeHtml(sName)}</h4>
            <span class="badge ${isRunning ? 'badge-blocked' : 'badge-allowed'}">
              ${isRunning ? '⚠️ Running / Active' : (s.installed ? '🛡️ Disabled & Masked' : '○ Not Installed')}
            </span>
          </div>
          <p>${escapeHtml(s.description)}</p>
        </div>
        <div>
          ${isRunning ? `
            <button class="btn-action btn-danger" onclick="toggleTelemetryService('${sName}', true)">
              🚫 Stop & Mask Service
            </button>
          ` : (s.installed ? `
            <button class="btn-action" onclick="toggleTelemetryService('${sName}', false)">
              🔄 Re-enable
            </button>
          ` : `
            <span class="badge" style="background: rgba(255,255,255,0.05); color: var(--text-muted);">Not Installed</span>
          `)}
        </div>
      `;
      listContainer.appendChild(card);
    });

  } else {
    // Windows OS Debloater
    if (tabIcon) tabIcon.textContent = "🪟";
    if (tabTitle) tabTitle.textContent = "Windows OS Debloater";
    if (debloaterTitle) debloaterTitle.textContent = "Windows OS Telemetry Neutralizer";
    if (debloaterSubtitle) debloaterSubtitle.textContent = "One-click kernel and service-level privacy controls for Windows 10 & 11 diagnostic logging.";

    const diagRunning = privStatus.diagtrack_running;
    const dmwapRunning = privStatus.dmwappushservice_running;
    const adEnabled = privStatus.advertising_id_enabled;

    listContainer.innerHTML = `
      <div class="glass-panel os-item">
        <div class="os-item-info">
          <div style="display: flex; align-items: center; gap: 8px;">
            <h4>Connected User Experiences and Telemetry (DiagTrack)</h4>
            <span class="badge ${diagRunning ? 'badge-blocked' : 'badge-allowed'}">
              ${diagRunning ? '⚠️ Running' : '🛡️ Disabled'}
            </span>
          </div>
          <p>Windows core diagnostic data collection service that sends hardware, usage, and crash data to Microsoft.</p>
        </div>
        <button class="btn-action ${diagRunning ? 'btn-danger' : ''}" onclick="toggleOsFeature('diagtrack', ${diagRunning})">
          ${diagRunning ? '🚫 Disable Service' : '🔄 Enable Service'}
        </button>
      </div>

      <div class="glass-panel os-item">
        <div class="os-item-info">
          <div style="display: flex; align-items: center; gap: 8px;">
            <h4>Device Management WAP Push Routing Service (dmwappushservice)</h4>
            <span class="badge ${dmwapRunning ? 'badge-blocked' : 'badge-allowed'}">
              ${dmwapRunning ? '⚠️ Running' : '🛡️ Silenced'}
            </span>
          </div>
          <p>Secondary Microsoft push routing and enterprise telemetry conduit.</p>
        </div>
        <button class="btn-action ${dmwapRunning ? 'btn-danger' : ''}" onclick="toggleOsFeature('dmwappushservice', ${dmwapRunning})">
          ${dmwapRunning ? '🚫 Silence Service' : '🔄 Enable Service'}
        </button>
      </div>

      <div class="glass-panel os-item">
        <div class="os-item-info">
          <div style="display: flex; align-items: center; gap: 8px;">
            <h4>Windows Advertising ID</h4>
            <span class="badge ${adEnabled ? 'badge-blocked' : 'badge-allowed'}">
              ${adEnabled ? '⚠️ Enabled' : '🛡️ Disabled'}
            </span>
          </div>
          <p>Unique hardware-bound identifier used by Windows Store apps and desktop advertisers to profile user activity.</p>
        </div>
        <button class="btn-action ${adEnabled ? 'btn-danger' : ''}" onclick="toggleOsFeature('advertising_id', ${adEnabled})">
          ${adEnabled ? '🚫 Disable Advertising ID' : '🔄 Enable Advertising ID'}
        </button>
      </div>

      <div class="glass-panel os-item">
        <div class="os-item-info">
          <div style="display: flex; align-items: center; gap: 8px;">
            <h4>Microsoft Edge Background Telemetry & Tab Profiler</h4>
            <span class="badge badge-allowed">🛡️ Sinkholed</span>
          </div>
          <p>Prevents Microsoft Edge from transmitting browser activity and diagnostic payloads in the background.</p>
        </div>
        <button class="btn-action" onclick="showToast('DNS Sinkhole', 'Edge background telemetry domains are sinkholed to 0.0.0.0!', 'shield')">Protected via Sinkhole</button>
      </div>
    `;
  }
}

async function toggleTelemetryService(service, disable) {
  try {
    const res = await fetch(`${API_BASE}/api/telemetry/toggle`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ service, disable })
    });
    const data = await res.json();
    if (data.success) {
      showToast("Service Protected", `${service} is now ${disable ? 'disabled & blocked' : 'enabled'}.`, "success");
    } else {
      showToast("Service Notice", data.error || data.output || "Requires Administrator privileges.", "warn");
    }
    loadOsInfoAndPrivacy();
  } catch (err) {
    showToast("Notice", "Service management requires root on Linux or Administrator on Windows.", "warn");
  }
}

async function toggleOsFeature(target, currentActive) {
  try {
    const res = await fetch(`${API_BASE}/api/windows-privacy/toggle`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, disable: currentActive !== false })
    });
    const data = await res.json();
    if (data.success) {
      showToast("OS Privacy Setting", `${target} privacy protection ${currentActive !== false ? 'activated' : 'restored'}.`, "success");
    } else {
      showToast("OS Notice", data.output || data.error || "Requires Administrator privileges.", "warn");
    }
    loadOsInfoAndPrivacy();
  } catch (err) {
    showToast("Notice", "Windows service modifications require Administrator privileges.", "warn");
  }
}

// ==================== Stats Updates ====================
function updateStats(newStats) {
  if (!newStats) return;
  state.stats = Object.assign(state.stats, newStats);
  updateStatsDisplay();
}

function updateStatsDisplay() {
  document.getElementById("blockedCount").textContent = state.stats.blocked_trackers.toLocaleString();
  document.getElementById("totalRequestsCount").textContent = state.stats.total_requests.toLocaleString();
  document.getElementById("monitoredAppsCount").textContent = (state.stats.monitored_apps || state.apps.length).toString();

  if (state.stats.top_companies && state.stats.top_companies.length > 0) {
    const top = state.stats.top_companies[0];
    document.getElementById("topCorporation").textContent = top.company;
    document.getElementById("topCorporationSub").textContent = `${top.count} telemetry sockets intercepted`;
  }
}

// ==================== Utilities & Event Listeners ====================
function escapeHtml(text) {
  if (!text) return "";
  const div = document.createElement("div");
  div.innerText = text;
  return div.innerHTML;
}

document.addEventListener("DOMContentLoaded", () => {
  bootstrapInitialState();
  initWebSocket();
  initNetworkGraph();
  loadApps();
  renderSurveillanceMatrix();
  loadRules();
  loadOsInfoAndPrivacy();
  loadVpnState();

  // Tab Switching
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const targetTab = btn.getAttribute("data-tab");
      const targetSec = document.getElementById(targetTab);
      if (targetSec) targetSec.classList.add("active");
      state.currentTab = targetTab;

      if (targetTab === "graphTab") {
        const canvas = document.getElementById("networkGraphCanvas");
        if (canvas && canvas.parentElement) {
          const rect = canvas.parentElement.getBoundingClientRect();
          const dpr = window.devicePixelRatio || 1;
          canvas.width = rect.width * dpr;
          canvas.height = rect.height * dpr;
          const ctx = canvas.getContext("2d");
          ctx.scale(dpr, dpr);
        }
      }
      if (targetTab === "alertsTab") {
        state.unreadAlertsCount = 0;
        updateAlertsBadge();
        renderAlertsFeed();
      }
      if (targetTab === "appMatrixTab") loadApps();
      if (targetTab === "rulesTab") loadRules();
      if (targetTab === "vpnTab") loadVpnState();
      if (targetTab === "windowsOsTab") loadOsInfoAndPrivacy();
    });
  });

  // Filter buttons in Live Radar
  document.querySelectorAll(".filter-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      state.filter = btn.getAttribute("data-filter");
      renderWaterfall();
    });
  });

  // Search Input
  document.getElementById("radarSearchInput").addEventListener("input", (e) => {
    state.searchQuery = e.target.value;
    renderWaterfall();
  });

  // Stream Pause / Resume
  document.getElementById("toggleStreamBtn").addEventListener("click", (e) => {
    state.isPaused = !state.isPaused;
    e.target.textContent = state.isPaused ? "▶️ Resume Stream" : "⏸️ Pause Stream";
  });

  // Refresh Apps
  document.getElementById("refreshAppsBtn").addEventListener("click", loadApps);

  // Add Rule
  document.getElementById("addRuleBtn").addEventListener("click", addCustomRule);

  // Shield Mode Selector
  document.getElementById("shieldModeSelect").addEventListener("change", async (e) => {
    try {
      await fetch(`${API_BASE}/api/shield/mode`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: e.target.value })
      });
      showToast("Protection Profile", `Protection profile set to ${e.target.value}.`, "info");
    } catch (err) {
      console.error("Error setting shield mode:", err);
    }
  });

  // Master Shield Toggle
  document.getElementById("masterShieldToggle").addEventListener("change", async (e) => {
    try {
      await fetch(`${API_BASE}/api/shield/toggle`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ active: e.target.checked })
      });
      showToast("Master Shield", e.target.checked ? "Radar and firewall defenses ACTIVE." : "Radar defense PAUSED (Audit mode).", e.target.checked ? "shield" : "warn");
    } catch (err) {
      console.error("Error toggling shield:", err);
    }
  });

  // App Picker Modal Wireup
  const openPickerBtn = document.getElementById("openAppPickerBtn");
  if (openPickerBtn) openPickerBtn.addEventListener("click", openAppPicker);

  const closePickerBtn = document.getElementById("closeAppPickerBtn");
  if (closePickerBtn) closePickerBtn.addEventListener("click", closeAppPicker);

  const modalBackdrop = document.getElementById("appPickerModal");
  if (modalBackdrop) {
    modalBackdrop.addEventListener("click", (e) => {
      if (e.target === modalBackdrop) closeAppPicker();
    });
  }

  const pickerSearch = document.getElementById("appPickerSearch");
  if (pickerSearch) {
    pickerSearch.addEventListener("input", (e) => {
      state.appPickerQuery = e.target.value;
      renderAppPickerList();
    });
  }

  // App Picker Filter Pills
  document.querySelectorAll("#appPickerFilters .filter-pill").forEach(pill => {
    pill.addEventListener("click", () => {
      document.querySelectorAll("#appPickerFilters .filter-pill").forEach(p => p.classList.remove("active"));
      pill.classList.add("active");
      state.appPickerFilter = pill.getAttribute("data-cat");
      renderAppPickerList();
    });
  });

  // Custom Executable Add Button
  const customExeBtn = document.getElementById("addCustomExeBtn");
  if (customExeBtn) customExeBtn.addEventListener("click", addCustomExecutable);

  // WireGuard & Proton VPN Modal Wireups
  const openProtonBtn = document.getElementById("openProtonAuthBtn");
  if (openProtonBtn) openProtonBtn.addEventListener("click", () => document.getElementById("protonAuthModal").classList.add("open"));

  const closeProtonBtn = document.getElementById("closeProtonAuthBtn");
  if (closeProtonBtn) closeProtonBtn.addEventListener("click", () => document.getElementById("protonAuthModal").classList.remove("open"));

  const openCustomTunnelBtn = document.getElementById("openCustomTunnelBtn");
  if (openCustomTunnelBtn) openCustomTunnelBtn.addEventListener("click", () => document.getElementById("customTunnelModal").classList.add("open"));

  const closeCustomTunnelBtn = document.getElementById("closeCustomTunnelBtn");
  if (closeCustomTunnelBtn) closeCustomTunnelBtn.addEventListener("click", () => document.getElementById("customTunnelModal").classList.remove("open"));

  const openPfModalBtn = document.getElementById("openPortForwardModalBtn");
  if (openPfModalBtn) {
    openPfModalBtn.addEventListener("click", () => {
      populatePortForwardTunnels();
      document.getElementById("portForwardModal").classList.add("open");
    });
  }

  const closePfModalBtn = document.getElementById("closePortForwardModalBtn");
  if (closePfModalBtn) closePfModalBtn.addEventListener("click", () => document.getElementById("portForwardModal").classList.remove("open"));

  const saveProtonAuthBtn = document.getElementById("saveProtonAuthBtn");
  if (saveProtonAuthBtn) saveProtonAuthBtn.addEventListener("click", saveProtonAuth);

  const genKeyBtn = document.getElementById("genWireguardKeypairBtn");
  if (genKeyBtn) {
    genKeyBtn.addEventListener("click", async () => {
      try {
        const res = await fetch(`${API_BASE}/api/vpn/wireguard/generate-keypair`);
        const data = await res.json();
        if (data.private_key) {
          document.getElementById("protonPrivateKeyInput").value = data.private_key;
          document.getElementById("protonAddressInput").value = data.address || "10.2.0.2/32";
          showToast("Keypair Generated", "New WireGuard private key generated! Click 'Save' to apply.", "success");
        }
      } catch (e) {
        showToast("Keygen Error", "Could not generate keypair: " + e, "error");
      }
    });
  }

  const saveCustomTunnelBtn = document.getElementById("saveCustomTunnelBtn");
  if (saveCustomTunnelBtn) saveCustomTunnelBtn.addEventListener("click", saveCustomTunnel);

  const savePfBtn = document.getElementById("savePortForwardBtn");
  if (savePfBtn) savePfBtn.addEventListener("click", savePortForwardRule);

  const orbotNewIdentityBtn = document.getElementById("orbotNewIdentityBtn");
  if (orbotNewIdentityBtn) orbotNewIdentityBtn.addEventListener("click", cycleOrbotIdentity);

  const checkOrbotBtn = document.getElementById("checkOrbotBtn");
  if (checkOrbotBtn) checkOrbotBtn.addEventListener("click", loadOrbotStatus);

  // Auto-parse Proton .conf paste
  const confPaste = document.getElementById("protonConfPaste");
  if (confPaste) {
    confPaste.addEventListener("input", (e) => {
      const text = e.target.value;
      const privMatch = text.match(/PrivateKey\s*=\s*([^\s\r\n]+)/i);
      const addrMatch = text.match(/Address\s*=\s*([^\s\r\n]+)/i);
      if (privMatch) document.getElementById("protonPrivateKeyInput").value = privMatch[1];
      if (addrMatch) document.getElementById("protonAddressInput").value = addrMatch[1];
    });
  }

  // Proton Filters
  document.querySelectorAll("#protonFilters .filter-pill").forEach(pill => {
    pill.addEventListener("click", () => {
      document.querySelectorAll("#protonFilters .filter-pill").forEach(p => p.classList.remove("active"));
      pill.classList.add("active");
      state.protonFilter = pill.getAttribute("data-filter");
      renderProtonServers();
    });
  });

  const protonSearch = document.getElementById("protonServerSearch");
  if (protonSearch) {
    protonSearch.addEventListener("input", (e) => {
      state.protonQuery = e.target.value;
      renderProtonServers();
    });
  }
});

// ==================== System Installed Apps Picker ====================
async function openAppPicker() {
  const modal = document.getElementById("appPickerModal");
  modal.classList.add("open");

  try {
    const res = await fetch(`${API_BASE}/api/system-apps`);
    state.systemApps = await res.json();
    const countBadge = document.getElementById("totalAppsBadge");
    if (countBadge) countBadge.textContent = state.systemApps.length;
    renderAppPickerList();
  } catch (err) {
    const list = document.getElementById("appPickerList");
    if (list) list.innerHTML = `<div style="color: var(--accent-block); text-align: center; padding: 20px;">Error loading installed applications: ${err}</div>`;
  }
}

function closeAppPicker() {
  const modal = document.getElementById("appPickerModal");
  if (modal) modal.classList.remove("open");
}

function renderAppPickerList() {
  const container = document.getElementById("appPickerList");
  if (!container || !state.systemApps) return;
  container.innerHTML = "";

  const q = (state.appPickerQuery || "").toLowerCase();
  const cat = state.appPickerFilter || "all";

  const filtered = state.systemApps.filter(app => {
    if (q) {
      const searchable = `${app.name} ${app.process_name} ${app.publisher} ${app.category}`.toLowerCase();
      if (!searchable.includes(q)) return false;
    }
    if (cat === "running") return app.is_running;
    if (cat !== "all") return app.category === cat;
    return true;
  });

  if (filtered.length === 0) {
    container.innerHTML = `<div style="text-align: center; padding: 30px; color: var(--text-muted);">No matching installed applications found.</div>`;
    return;
  }

  filtered.slice(0, 100).forEach(app => {
    const item = document.createElement("div");
    item.className = "app-picker-item";

    const runningPill = app.is_running
      ? `<span class="badge badge-allowed" style="font-size: 0.65rem; padding: 1px 6px;">Running Now</span>`
      : "";

    const managedPill = app.is_managed
      ? `<span class="badge" style="background: rgba(0, 229, 255, 0.15); color: var(--accent-cyan); font-size: 0.65rem; padding: 1px 6px;">In Matrix</span>`
      : "";

    const safeName = (app.name || "").replace(/'/g, "\\'");
    const safeProc = (app.process_name || "").replace(/'/g, "\\'");
    const safeExe = (app.exe_path || "").replace(/'/g, "\\'").replace(/\\/g, "\\\\");

    item.innerHTML = `
      <div class="app-item-info">
        <div class="app-item-icon">${app.icon || "📦"}</div>
        <div class="app-item-text">
          <div class="app-item-title">
            ${escapeHtml(app.name)}
            ${runningPill}
            ${managedPill}
          </div>
          <div class="app-item-sub">
            <span style="color: #cbd5e1; font-weight: 600;">${escapeHtml(app.process_name)}</span> &bull; 
            ${escapeHtml(app.publisher || "Desktop App")} &bull; 
            <span style="color: var(--text-muted);">${escapeHtml(app.exe_path)}</span>
          </div>
        </div>
      </div>

      <div class="app-item-actions">
        <button class="btn-action" title="Add to Privacy Matrix with Tracker Shielding" onclick="selectSystemApp('${safeName}', '${safeProc}', '${safeExe}', 'block_trackers')">
          🛡️ Shield Trackers
        </button>
        <button class="btn-action btn-danger" title="Block this app completely from internet via Windows Firewall" onclick="selectSystemApp('${safeName}', '${safeProc}', '${safeExe}', 'block_all')">
          🛑 Block All
        </button>
      </div>
    `;
    container.appendChild(item);
  });
}

async function selectSystemApp(name, process_name, exe_path, mode) {
  try {
    const res = await fetch(`${API_BASE}/api/apps/select`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, process_name, exe_path, mode })
    });
    const data = await res.json();
    if (data.success) {
      if (state.systemApps) {
        const found = state.systemApps.find(a => a.process_name.toLowerCase() === process_name.toLowerCase());
        if (found) found.is_managed = true;
      }
      renderAppPickerList();
      loadApps();
      showToast("App Monitored", `${name} added with policy: ${mode}`, "success");
    }
  } catch (err) {
    showToast("Error", "Error adding app to matrix: " + err, "error");
  }
}

async function addCustomExecutable() {
  const pathInput = document.getElementById("customAppExePath");
  const nameInput = document.getElementById("customAppName");
  const exe_path = pathInput.value.trim();
  const name = nameInput.value.trim() || exe_path.split("\\").pop() || "Custom App";
  const process_name = exe_path.split("\\").pop() || `${name}.exe`;

  if (!exe_path) {
    showToast("Validation", "Please specify the path to the executable.", "warn");
    return;
  }

  await selectSystemApp(name, process_name, exe_path, "block_trackers");
  pathInput.value = "";
  nameInput.value = "";
}

// ==================== WireGuard & Proton VPN Controller ====================
async function loadVpnState() {
  try {
    // 1. Tunnels
    const tRes = await fetch(`${API_BASE}/api/vpn/tunnels`);
    state.vpnTunnels = await tRes.json();
    renderTunnels();
    renderMasterVpnCard();

    // 2. Proton Auth
    const aRes = await fetch(`${API_BASE}/api/vpn/proton/auth`);
    state.protonAuth = await aRes.json();
    renderProtonAuthBanner();

    // 3. Proton Servers
    const sRes = await fetch(`${API_BASE}/api/vpn/proton/servers`);
    state.protonServers = await sRes.json();
    renderProtonServers();

    // 4. Orbot Status
    loadOrbotStatus();

    // 5. Port Forwarding & NAT-PMP Dynamic Status
    loadPortForwarding();
    loadNatPmpStatus();

    // 6. VPN App Bindings
    try {
      const bRes = await fetch(`${API_BASE}/api/vpn/bindings`);
      if (bRes.ok) {
        state.appBindings = await bRes.json();
      }
    } catch (e) {}

    // 7. App Split Tunneling Matrix
    renderAppRoutingMatrix();
  } catch (err) {
    console.error("Error loading VPN state:", err);
  }
}

function renderMasterVpnCard() {
  const avatar = document.getElementById("masterShieldAvatar");
  const statusText = document.getElementById("masterVpnStatusText");
  const badge = document.getElementById("masterVpnBadge");
  const subText = document.getElementById("masterVpnSubText");
  const btn = document.getElementById("masterVpnQuickConnectBtn");
  const btnIcon = document.getElementById("masterVpnBtnIcon");
  const btnText = document.getElementById("masterVpnBtnText");
  const tunnelName = document.getElementById("masterTunnelName");
  const virtualIp = document.getElementById("masterVirtualIp");

  if (!avatar || !statusText || !badge || !btn) return;

  const tunnels = state.vpnTunnels || [];
  const activeTunnel = tunnels.find(t => t.status === "Connected");

  if (activeTunnel) {
    avatar.className = "vpn-shield-avatar connected";
    avatar.textContent = activeTunnel.flag || "🛡️";
    statusText.textContent = "SHIELD CONNECTED";
    badge.textContent = "WireGuard Encrypted";
    badge.style.background = "rgba(0, 255, 157, 0.18)";
    badge.style.color = "#00ff9d";
    badge.style.borderColor = "rgba(0, 255, 157, 0.4)";

    subText.textContent = `All outbound desktop network packets encrypted and routed through ${activeTunnel.name} (${activeTunnel.country}).`;

    btn.className = "vpn-btn-master btn-disconnect";
    btnIcon.textContent = "🛑";
    btnText.textContent = "Disconnect Shield";

    if (tunnelName) tunnelName.textContent = `${activeTunnel.name} (${activeTunnel.country})`;
    if (virtualIp) virtualIp.textContent = `${activeTunnel.address || "10.2.0.2"} (Virtual IP)`;
  } else {
    avatar.className = "vpn-shield-avatar";
    avatar.textContent = "🛡️";
    statusText.textContent = "DISCONNECTED";
    badge.textContent = "Exposed to ISP";
    badge.style.background = "rgba(255, 0, 85, 0.2)";
    badge.style.color = "#ff0055";
    badge.style.borderColor = "rgba(255, 0, 85, 0.4)";

    subText.textContent = "Direct clearnet route active. Telemetry beacons, trackers, and ISP logging are active.";

    btn.className = "vpn-btn-master btn-connect";
    btnIcon.textContent = "⚡";
    btnText.textContent = "Quick Connect (Fastest Node)";

    if (tunnelName) tunnelName.textContent = "None (Direct Clearnet)";
    if (virtualIp) virtualIp.textContent = "Clearnet (Unmasked)";
  }
}

window.toggleMasterVpn = async function() {
  const tunnels = state.vpnTunnels || [];
  const activeTunnel = tunnels.find(t => t.status === "Connected");

  if (activeTunnel) {
    try {
      await fetch(`${API_BASE}/api/vpn/tunnels/${encodeURIComponent(activeTunnel.id)}/toggle`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ activate: false })
      });
      showToast("VPN Disconnected", `Disconnected from ${activeTunnel.name}. Direct route restored.`, "warn");
      await loadVpnState();
    } catch (e) {
      showToast("VPN Error", "Error disconnecting tunnel: " + e, "error");
    }
  } else {
    if (tunnels.length > 0) {
      const first = tunnels[0];
      try {
        await fetch(`${API_BASE}/api/vpn/tunnels/${encodeURIComponent(first.id)}/toggle`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ activate: true })
        });
        showToast("WireGuard Connected", `Connected to ${first.name} (${first.country})! Traffic encrypted.`, "success");
        await loadVpnState();
      } catch (e) {
        showToast("VPN Error", "Error activating tunnel: " + e, "error");
      }
    } else {
      try {
        showToast("Deploying VPN", "Provisioning fastest WireGuard node from Proton VPN fleet...", "info");
        const deployRes = await fetch(`${API_BASE}/api/vpn/proton/deploy`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ server_id: "nl-free-01", custom_name: "Proton Netherlands (Fastest Free)" })
        });
        const dData = await deployRes.json();
        if (dData.tunnel && dData.tunnel.id) {
          await fetch(`${API_BASE}/api/vpn/tunnels/${encodeURIComponent(dData.tunnel.id)}/toggle`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ activate: true })
          });
          showToast("WireGuard Shield Active", "Connected to Proton Netherlands WireGuard! All packets encrypted.", "success");
          await loadVpnState();
        } else {
          showToast("Proton Deployment Notice", "Please configure Proton credentials in '🔑 Proton VPN Auth'.", "warn");
        }
      } catch (e) {
        showToast("VPN Error", "Quick Connect error: " + e, "error");
      }
    }
  }
};

window.toggleKillSwitch = async function(enabled) {
  const lbl = document.getElementById("killSwitchLabel");
  if (lbl) {
    lbl.textContent = enabled ? "ACTIVE" : "DISABLED";
    lbl.style.color = enabled ? "#00ff9d" : "var(--text-muted)";
  }
  try {
    const res = await fetch(`${API_BASE}/api/vpn/killswitch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ active: enabled })
    });
    const data = await res.json();
    if (data.success) {
      showToast("Kill Switch", enabled ? "Anti-Leak Kill Switch armed: Leak ports dropped." : "Kill Switch disarmed.", enabled ? "shield" : "warn");
    } else {
      showToast("Kill Switch", data.output || "Kill switch status updated", "info");
    }
  } catch (e) {
    showToast("Kill Switch Error", "Could not apply firewall rule: " + e, "error");
  }
};

function renderProtonAuthBanner() {
  const auth = state.protonAuth || {};
  const title = document.getElementById("protonStatusTitle");
  const sub = document.getElementById("protonStatusSub");
  const badge = document.getElementById("protonAuthBadge");

  const systemProtonTunnel = (state.vpnTunnels || []).find(
    t => (t.tunnel_type === "proton" || (t.name && t.name.toLowerCase().includes("proton"))) && t.status === "Connected"
  );

  if (systemProtonTunnel) {
    if (title) title.textContent = "Proton VPN Active (System Tunnel Connected)";
    if (sub) sub.textContent = `Live traffic encrypted via official Proton VPN client (Interface: ${systemProtonTunnel.interface_name || 'ProtonVPN'}, IP: ${systemProtonTunnel.address || '10.2.0.2'}).`;
    if (badge) badge.innerHTML = `<span class="badge badge-allowed" style="background: rgba(0, 255, 157, 0.2); color: #00ff9d;">🟢 System VPN Active</span>`;
  } else if (auth.configured) {
    if (title) title.textContent = `Proton WireGuard Ready (${auth.tier} Plan)`;
    if (sub) sub.textContent = `Assigned Client IP: ${auth.address} | Authenticated for WireGuard Deployment`;
    if (badge) badge.innerHTML = `<span class="badge badge-allowed">Proton Auth Active</span>`;
  } else {
    if (title) title.textContent = "Proton WireGuard: Credentials Needed";
    if (sub) sub.textContent = "Click '🔑 Proton VPN Auth' to enter WireGuard credentials or paste your Proton .conf.";
    if (badge) badge.innerHTML = `<span class="badge badge-telemetry">Auth Required</span>`;
  }
}

function renderTunnels() {
  const container = document.getElementById("activeTunnelsGrid");
  const label = document.getElementById("tunnelsCountLabel");
  if (!container) return;
  container.innerHTML = "";

  const tunnels = state.vpnTunnels || [];
  if (label) label.textContent = `${tunnels.length} Tunnels Configured (${tunnels.filter(t => t.status === 'Connected').length} Active)`;

  if (tunnels.length === 0) {
    container.innerHTML = `
      <div class="glass-panel" style="grid-column: 1/-1; padding: 30px; text-align: center; color: var(--text-muted);">
        No WireGuard tunnels configured yet. Select a Proton server below or click "➕ Add WireGuard Tunnel" above.
      </div>
    `;
    return;
  }

  tunnels.forEach(t => {
    const card = document.createElement("div");
    card.className = "glass-panel app-card";
    const isConn = t.status === "Connected";

    card.innerHTML = `
      <div>
        <div class="app-card-header">
          <div class="app-title-group">
            <div style="font-size: 1.8rem;">${t.flag || "🌐"}</div>
            <div>
              <div class="app-name">${escapeHtml(t.name)}</div>
              <div class="app-path">${escapeHtml(t.endpoint)}</div>
            </div>
          </div>
          <span class="badge ${isConn ? 'badge-allowed' : 'badge-functional'}">
            ${isConn ? '🟢 Connected' : '⚪ Idle'}
          </span>
        </div>

        <div class="app-stats-row">
          <div>
            <div style="color: var(--text-muted);">Throughput</div>
            <div style="font-weight: 700; color: var(--accent-cyan); font-family: var(--font-mono); font-size: 0.75rem;">
              &darr; ${t.rx_speed_kbps || 0} kbps | &uarr; ${t.tx_speed_kbps || 0} kbps
            </div>
          </div>
          <div>
            <div style="color: var(--text-muted);">Total Transfer</div>
            <div style="font-weight: 700; color: #fff; font-family: var(--font-mono); font-size: 0.75rem;">
              ${t.total_recv_mb || 0} MB / ${t.total_sent_mb || 0} MB
            </div>
          </div>
        </div>
      </div>

      <div style="display: flex; gap: 8px; margin-top: 12px;">
        <button class="btn-action ${isConn ? 'btn-danger' : ''}" style="flex: 1;" onclick="toggleTunnel('${t.id}', ${!isConn})">
          ${isConn ? '⚡ Disconnect' : '🚀 Connect'}
        </button>
        <button class="btn-action btn-danger" title="Remove Tunnel" onclick="deleteTunnel('${t.id}')">
          🗑️
        </button>
      </div>
    `;
    container.appendChild(card);
  });
}

function renderProtonServers() {
  const container = document.getElementById("protonServersGrid");
  if (!container || !state.protonServers) return;
  container.innerHTML = "";

  const q = (state.protonQuery || "").toLowerCase();
  const filter = state.protonFilter || "all";

  const filtered = state.protonServers.filter(s => {
    if (q) {
      const match = `${s.name} ${s.country} ${s.city} ${s.features.join(' ')}`.toLowerCase();
      if (!match.includes(q)) return false;
    }
    if (filter === "free") return s.tier.toLowerCase() === "free";
    if (filter === "plus") return s.tier.toLowerCase() === "plus";
    if (filter !== "all") return s.country_code.toLowerCase() === filter.toLowerCase();
    return true;
  });

  if (filtered.length === 0) {
    container.innerHTML = `<div class="glass-panel" style="grid-column: 1/-1; padding: 30px; text-align: center; color: var(--text-muted);">No Proton servers matching filter.</div>`;
    return;
  }

  filtered.forEach(s => {
    const card = document.createElement("div");
    card.className = "glass-panel app-card";

    const featuresBadges = s.features.map(f => `<span class="badge" style="background: rgba(255,255,255,0.06); font-size: 0.65rem;">${f}</span>`).join(" ");

    card.innerHTML = `
      <div>
        <div class="app-card-header">
          <div class="app-title-group">
            <div style="font-size: 1.8rem;">${s.flag}</div>
            <div>
              <div class="app-name">${s.name}</div>
              <div class="app-path">${s.country} &bull; ${s.city}</div>
            </div>
          </div>
          <span class="badge ${s.tier === 'Free' ? 'badge-allowed' : 'badge-telemetry'}">${s.tier}</span>
        </div>

        <div style="margin-bottom: 10px;">
          <div style="display: flex; justify-content: space-between; font-size: 0.75rem; color: var(--text-muted); margin-bottom: 4px;">
            <span>Server Load</span>
            <span style="font-weight: 700; color: #fff;">${s.load}%</span>
          </div>
          <div style="width: 100%; height: 5px; background: rgba(255,255,255,0.1); border-radius: 4px; overflow: hidden;">
            <div style="width: ${s.load}%; height: 100%; background: ${s.load > 75 ? 'var(--accent-block)' : 'var(--accent-safe)'};"></div>
          </div>
        </div>

        <div style="display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 12px;">
          ${featuresBadges}
        </div>
      </div>

      <button class="btn-action" style="width: 100%; padding: 8px; font-weight: 700;" onclick="deployProtonServer('${s.id}', '${s.name}')">
        ⚡ Deploy WireGuard Tunnel
      </button>
    `;
    container.appendChild(card);
  });
}

async function deployProtonServer(serverId, name) {
  try {
    const res = await fetch(`${API_BASE}/api/vpn/proton/deploy`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ server_id: serverId, custom_name: `Proton ${name}` })
    });
    const data = await res.json();
    if (data.auth_required) {
      showToast("Proton Auth Required", data.error || "Please enter WireGuard credentials or paste a .conf in '🔑 Proton VPN Auth'.", "warn");
      const modal = document.getElementById("protonAuthModal");
      if (modal) modal.classList.add("open");
      return;
    }
    if (data.success) {
      showToast("WireGuard Deployed", `Tunnel deployed for Proton ${name}! Activated in tunnel list.`, "success");
      loadVpnState();
    } else {
      showToast("Deployment Notice", data.error || "Could not deploy WireGuard tunnel.", "warn");
    }
  } catch (err) {
    showToast("VPN Error", "Error deploying Proton WireGuard tunnel: " + err, "error");
  }
}

async function toggleTunnel(tunnelId, activate) {
  try {
    await fetch(`${API_BASE}/api/vpn/tunnels/${encodeURIComponent(tunnelId)}/toggle`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ activate })
    });
    loadVpnState();
  } catch (err) {
    showToast("VPN Error", "Error toggling tunnel: " + err, "error");
  }
}

async function deleteTunnel(tunnelId) {
  try {
    await fetch(`${API_BASE}/api/vpn/tunnels/${encodeURIComponent(tunnelId)}`, { method: "DELETE" });
    showToast("Tunnel Removed", "WireGuard tunnel removed successfully.", "info");
    loadVpnState();
  } catch (err) {
    showToast("VPN Error", "Error deleting tunnel: " + err, "error");
  }
}

async function saveProtonAuth() {
  const private_key = document.getElementById("protonPrivateKeyInput").value.trim();
  const address = document.getElementById("protonAddressInput").value.trim();
  const tier = document.getElementById("protonTierSelect").value;

  if (!private_key) {
    showToast("Validation", "Please enter your Proton WireGuard PrivateKey.", "warn");
    return;
  }

  try {
    await fetch(`${API_BASE}/api/vpn/proton/auth`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ private_key, address, tier })
    });
    document.getElementById("protonAuthModal").classList.remove("open");
    loadVpnState();
    showToast("Credentials Saved", "Proton VPN WireGuard credentials saved successfully!", "success");
  } catch (err) {
    showToast("Auth Error", "Error saving Proton auth: " + err, "error");
  }
}

async function saveCustomTunnel() {
  const name = document.getElementById("customTunnelName").value.trim() || "Custom WireGuard";
  const endpoint = document.getElementById("customEndpoint").value.trim();
  const public_key = document.getElementById("customPubKey").value.trim();
  const private_key = document.getElementById("customPrivKey").value.trim();
  const address = document.getElementById("customAddress").value.trim() || "10.2.0.2/32";
  const country = document.getElementById("customCountry").value.trim() || "Global";

  if (!endpoint || !public_key || !private_key) {
    showToast("Validation", "Please provide endpoint, public key, and private key.", "warn");
    return;
  }

  try {
    await fetch(`${API_BASE}/api/vpn/tunnels`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, endpoint, public_key, private_key, address, country })
    });
    document.getElementById("customTunnelModal").classList.remove("open");
    loadVpnState();
    showToast("Tunnel Created", "WireGuard Tunnel added successfully!", "success");
  } catch (err) {
    showToast("Tunnel Error", "Error adding WireGuard tunnel: " + err, "error");
  }
}

// ==================== App Split Tunneling Routing ====================
function renderAppRoutingMatrix() {
  const tbody = document.getElementById("appRoutingTableBody");
  if (!tbody) return;
  tbody.innerHTML = "";

  const tunnels = state.vpnTunnels || [];
  const bindings = state.appBindings || {};

  // Build app list: registered apps + detected apps if empty
  let appList = state.apps && state.apps.length > 0 ? [...state.apps] : [
    { name: "Brave Browser", process_name: "brave.exe", exe_path: "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" },
    { name: "Google Chrome", process_name: "chrome.exe", exe_path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" },
    { name: "Steam Client", process_name: "steam.exe", exe_path: "C:\\Program Files (x86)\\Steam\\steam.exe" },
    { name: "Discord", process_name: "Discord.exe", exe_path: "%LocalAppData%\\Discord\\app.exe" },
    { name: "qBittorrent", process_name: "qbittorrent.exe", exe_path: "C:\\Program Files\\qBittorrent\\qbittorrent.exe" }
  ];

  appList.forEach(app => {
    const tr = document.createElement("tr");
    const procKey = app.process_name.toLowerCase().trim();
    const binding = bindings[procKey];
    const boundTid = binding ? binding.tunnel_id : "direct";

    // Options for tunnels
    let tunnelOptions = `<option value="direct" ${boundTid === "direct" ? "selected" : ""}>🌐 Direct Clearnet (Shield Protected)</option>`;
    tunnelOptions += `<option value="orbot" ${boundTid === "orbot" ? "selected" : ""}>🧅 Orbot / Tor Onion Network (SOCKS5 9050)</option>`;
    tunnels.forEach(t => {
      const isSel = boundTid === t.id ? "selected" : "";
      const portStr = t.proxy_port ? ` [Port ${t.proxy_port}]` : "";
      tunnelOptions += `<option value="${t.id}" ${isSel}>${t.flag || "🛡️"} WireGuard: ${escapeHtml(t.name)} (${t.country || "Global"})${portStr}</option>`;
    });

    let statusBadge = `<span class="badge" style="background: rgba(255,255,255,0.06); color: var(--text-muted);">Direct Shield</span>`;
    let launchBtn = "";

    if (boundTid && boundTid !== "direct") {
      const flag = binding ? (binding.flag || "🔒") : "🔒";
      const tname = binding ? binding.name : "Active Tunnel";
      statusBadge = `<span class="badge badge-allowed" style="background: rgba(0,255,157,0.15); color: #00ff9d; border: 1px solid rgba(0,255,157,0.3);">
        ${flag} Routed: ${escapeHtml(tname)}
      </span>`;
      const safeProc = (app.process_name || "").replace(/'/g, "\\'").replace(/\\/g, "\\\\");
      const safeExe = (app.exe_path || "").replace(/'/g, "\\'").replace(/\\/g, "\\\\");
      const safeTid = (boundTid || "").replace(/'/g, "\\'");
      launchBtn = `<button class="btn-action" style="padding: 3px 8px; font-size: 0.72rem; margin-top: 4px; display: inline-flex; align-items: center; gap: 4px;" onclick="launchAppWithVpn('${safeProc}', '${safeExe}', '${safeTid}')">
        <span>🚀</span> Launch via VPN
      </button>`;
    }

    tr.innerHTML = `
      <td>
        <div style="display: flex; align-items: center; gap: 8px;">
          <span>${getAppIcon(app.process_name)}</span>
          <div>
            <div style="font-weight: 700; color: #fff;">${escapeHtml(app.process_name)}</div>
            <div style="font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(app.name || app.process_name)}</div>
          </div>
        </div>
      </td>
      <td style="color: var(--text-muted); font-size: 0.75rem; max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
        ${escapeHtml(app.exe_path || "Auto-detected by OS")}
      </td>
      <td>
        <select class="app-action-select" onchange="setAppRouting('${escapeHtml(app.process_name)}', this.value)">
          ${tunnelOptions}
        </select>
      </td>
      <td>
        <div style="display: flex; flex-direction: column; align-items: flex-start; gap: 4px;">
          ${statusBadge}
          ${launchBtn}
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

async function setAppRouting(processName, routeChoice) {
  let mode = "bypass";
  let tunnelId = null;

  if (routeChoice === "orbot") {
    mode = "orbot";
    tunnelId = "orbot";
  } else if (routeChoice !== "direct" && routeChoice !== "clearnet") {
    mode = "tunnel";
    tunnelId = routeChoice;
  }

  try {
    const res = await fetch(`${API_BASE}/api/vpn/split-tunneling`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ process_name: processName, mode, tunnel_id: tunnelId })
    });
    const data = await res.json();
    
    // Update local state bindings
    if (!state.appBindings) state.appBindings = {};
    const procKey = processName.toLowerCase().trim();
    if (tunnelId && tunnelId !== "direct") {
      const t = (state.vpnTunnels || []).find(x => x.id === tunnelId);
      state.appBindings[procKey] = {
        tunnel_id: tunnelId,
        name: t ? t.name : (tunnelId === "orbot" ? "Orbot Tor" : tunnelId),
        country: t ? t.country : "VPN",
        flag: t ? t.flag : "🔒",
        proxy_url: t ? t.proxy_url : (tunnelId === "orbot" ? "socks5://127.0.0.1:9050" : null)
      };
      showToast("Split Tunnel", `${processName} routed via ${t ? t.name : routeChoice}.`, "success");
    } else {
      delete state.appBindings[procKey];
      showToast("Split Tunnel", `${processName} set to Direct Shield.`, "info");
    }

    renderAppRoutingMatrix();
  } catch (err) {
    console.error("Error setting app routing:", err);
  }
}

async function launchAppWithVpn(processName, exePath, tunnelId) {
  try {
    const res = await fetch(`${API_BASE}/api/vpn/launch-app`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ process_name: processName, exe_path: exePath, tunnel_id: tunnelId })
    });
    const data = await res.json();
    if (data.success) {
      showToast("App Launched", `Launched ${processName} with ${data.tunnel} routing.`, "success");
    } else {
      showToast("Launch Info", data.error || "Could not launch automatically.", "info");
    }
  } catch (err) {
    showToast("Launch Failed", "Error launching app: " + err, "error");
  }
}

async function applyVpnPreset(presetName) {
  if (presetName === "brave_us") {
    let usTunnel = (state.vpnTunnels || []).find(t => (t.country && t.country.toLowerCase().includes("united states")) || (t.name && t.name.toLowerCase().includes("us")));
    if (!usTunnel) {
      showToast("Deploying US Tunnel", "Auto-deploying US-FREE#1 for Brave split-tunnel...", "info");
      try {
        const dRes = await fetch(`${API_BASE}/api/vpn/proton/deploy`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ server_id: "us-free-01" })
        });
        const dData = await dRes.json();
        if (dData.success && dData.tunnel) {
          usTunnel = dData.tunnel;
          await fetch(`${API_BASE}/api/vpn/tunnels/${encodeURIComponent(usTunnel.id)}/toggle`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ activate: true })
          });
        }
      } catch (e) {}
    }

    if (usTunnel) {
      await setAppRouting("brave.exe", usTunnel.id);
      await setAppRouting("brave", usTunnel.id);
      showToast("Preset Applied", `Brave browser routed through 🇺🇸 ${usTunnel.name}`, "success");
    } else {
      showToast("Preset Notice", "Deploy 'US-FREE#1' from the server fleet below.", "info");
    }
  } else if (presetName === "games_india") {
    let inTunnel = (state.vpnTunnels || []).find(t => (t.country && t.country.toLowerCase().includes("india")) || (t.name && t.name.toLowerCase().includes("in")));
    if (!inTunnel) {
      showToast("Deploying India Tunnel", "Auto-deploying IN-FREE#1 for Gaming split-tunnel...", "info");
      try {
        const dRes = await fetch(`${API_BASE}/api/vpn/proton/deploy`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ server_id: "in-free-01" })
        });
        const dData = await dRes.json();
        if (dData.success && dData.tunnel) {
          inTunnel = dData.tunnel;
          await fetch(`${API_BASE}/api/vpn/tunnels/${encodeURIComponent(inTunnel.id)}/toggle`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ activate: true })
          });
        }
      } catch (e) {}
    }

    if (inTunnel) {
      await setAppRouting("steam.exe", inTunnel.id);
      await setAppRouting("game.exe", inTunnel.id);
      await setAppRouting("bgmi.exe", inTunnel.id);
      await setAppRouting("valorant.exe", inTunnel.id);
      showToast("Preset Applied", `Gaming apps routed through 🇮🇳 ${inTunnel.name}`, "success");
    } else {
      showToast("Preset Notice", "Deploy 'IN-FREE#1' or 'IN#1' from the server fleet below.", "info");
    }
  } else if (presetName === "torrent_nl") {
    let nlTunnel = (state.vpnTunnels || []).find(t => (t.country && t.country.toLowerCase().includes("netherlands")) || (t.name && t.name.toLowerCase().includes("nl")));
    if (!nlTunnel) {
      showToast("Deploying NL Tunnel", "Auto-deploying NL-FREE#1 for P2P split-tunnel...", "info");
      try {
        const dRes = await fetch(`${API_BASE}/api/vpn/proton/deploy`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ server_id: "nl-free-01" })
        });
        const dData = await dRes.json();
        if (dData.success && dData.tunnel) {
          nlTunnel = dData.tunnel;
          await fetch(`${API_BASE}/api/vpn/tunnels/${encodeURIComponent(nlTunnel.id)}/toggle`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ activate: true })
          });
        }
      } catch (e) {}
    }

    if (nlTunnel) {
      await setAppRouting("qbittorrent.exe", nlTunnel.id);
      await setAppRouting("utorrent.exe", nlTunnel.id);
      showToast("Preset Applied", `P2P apps routed through 🇳🇱 ${nlTunnel.name}`, "success");
    } else {
      showToast("Preset Notice", "Deploy 'NL-FREE#1' from the server fleet below.", "info");
    }
  } else if (presetName === "reset_direct") {
    const appsToReset = state.apps ? state.apps.map(a => a.process_name) : ["brave.exe", "steam.exe", "qbittorrent.exe"];
    for (const p of appsToReset) {
      await setAppRouting(p, "direct");
    }
    showToast("Preset Applied", "All apps reset to Direct Shield.", "info");
  }

  loadVpnState();
}

async function quitTrackerControl() {
  if (!confirm("Are you sure you want to stop all protection and quit TrackerControl PC? This will restore DNS settings and disconnect all VPN tunnels.")) {
    return;
  }
  try {
    await fetch(`${API_BASE}/api/system/quit`, { method: "POST" });
    showToast("Shutting Down", "TrackerControl PC is shutting down...", "info");
    setTimeout(() => {
      document.body.innerHTML = `
        <div style="display: flex; height: 100vh; align-items: center; justify-content: center; flex-direction: column; background: #0a0d12; color: #fff; font-family: sans-serif; text-align: center; padding: 20px;">
          <div style="font-size: 3rem; margin-bottom: 12px;">🛡️</div>
          <h2 style="color: #00ff9d; margin-bottom: 8px;">TrackerControl PC Engine Stopped</h2>
          <p style="color: #94a3b8; max-width: 500px;">System DNS filtering has been restored and all WireGuard tunnels disconnected.</p>
          <p style="color: #64748b; font-size: 0.85rem; margin-top: 14px;">You may now safely close this window.</p>
        </div>
      `;
    }, 800);
  } catch (e) {
    console.error(e);
  }
}

// ==================== Orbot VPN Controller ====================
async function loadOrbotStatus() {
  try {
    const res = await fetch(`${API_BASE}/api/vpn/orbot/identity`);
    const data = await res.json();
    state.orbotStatus = data;

    const badge = document.getElementById("orbotStatusBadge");
    const details = document.getElementById("orbotDetailsText");
    const identity = document.getElementById("orbotIdentityText");
    const toggleBtn = document.getElementById("toggleTorDaemonBtn");

    const isRunning = data.orbot_status && data.orbot_status.is_running;

    if (badge) {
      badge.textContent = isRunning ? "🟢 Orbot Active" : "⚪ Orbot Offline";
      badge.style.background = isRunning ? "rgba(0, 255, 157, 0.2)" : "rgba(255,255,255,0.06)";
      badge.style.color = isRunning ? "var(--accent-safe)" : "var(--text-muted)";
    }

    if (toggleBtn) {
      if (isRunning) {
        toggleBtn.textContent = "🛑 Stop Tor Service";
        toggleBtn.style.background = "rgba(255, 0, 85, 0.2)";
        toggleBtn.style.borderColor = "rgba(255, 0, 85, 0.5)";
        toggleBtn.style.color = "#ff0055";
      } else {
        toggleBtn.textContent = "⚡ Start Tor Service";
        toggleBtn.style.background = "rgba(0, 255, 157, 0.15)";
        toggleBtn.style.borderColor = "#00ff9d";
        toggleBtn.style.color = "#fff";
      }
    }

    if (details) {
      if (isRunning) {
        details.textContent = `SOCKS5 Proxy: 127.0.0.1:${data.orbot_status.socks_port} | ControlPort: ${data.orbot_status.control_port || '9051'} | Onion Routing Active`;
      } else if (data.orbot_status && data.orbot_status.tor_binary_found) {
        details.textContent = `Tor detected on system (${data.orbot_status.tor_binary_path}). Click 'Start Tor Service' to launch.`;
      } else {
        details.textContent = `SOCKS5 Port: 9050 / 9150 | ControlPort: 9051 | Start Orbot / Tor to enable Onion routing.`;
      }
    }

    if (identity) {
      identity.textContent = `Clearnet IP: ${data.clearnet_ip} | Tor Exit Node: ${data.tor_exit_ip || 'Not routed'}`;
    }
  } catch (err) {
    console.error("Error loading Orbot status:", err);
  }
}

window.toggleTorDaemon = async function() {
  const btn = document.getElementById("toggleTorDaemonBtn");
  if (btn) btn.disabled = true;
  try {
    showToast("Tor Daemon", "Toggling Tor background service...", "info");
    const res = await fetch(`${API_BASE}/api/vpn/orbot/toggle`, { method: "POST" });
    const data = await res.json();
    if (data.success) {
      showToast("Tor Service", data.message || "Tor daemon state updated.", "success");
      await loadOrbotStatus();
    } else {
      showToast("Tor Notice", data.error || "Could not toggle Tor service.", "warn");
    }
  } catch (err) {
    showToast("Tor Error", "Error communicating with Tor manager: " + err, "error");
  } finally {
    if (btn) btn.disabled = false;
  }
};

async function cycleOrbotIdentity() {
  try {
    const res = await fetch(`${API_BASE}/api/vpn/orbot/new-identity`, { method: "POST" });
    const data = await res.json();
    if (data.success) {
      showToast("Tor Circuit Cycled", "New Tor circuit requested! (SIGNAL NEWNYM delivered to Tor controller).", "success");
      await loadOrbotStatus();
    } else {
      showToast("Tor Notice", data.error || "ControlPort 9051 not detected. Click 'Start Tor Service' to launch daemon.", "warn");
    }
  } catch (err) {
    showToast("Tor Error", "Error cycling Tor identity: " + err, "error");
  }
}

// ==================== Proton VPN Dynamic NAT-PMP (RFC 6886) Engine ====================
async function loadNatPmpStatus() {
  try {
    const res = await fetch(`${API_BASE}/api/vpn/nat-pmp/status`);
    const data = await res.json();
    state.natPmp = data;

    const badge = document.getElementById("natPmpStatusBadge");
    const portEl = document.getElementById("natPmpAssignedPort");
    const inPortEl = document.getElementById("natPmpInternalPort");
    const leaseEl = document.getElementById("natPmpLeaseTime");
    const reqBtn = document.getElementById("requestNatPmpBtn");
    const stopBtn = document.getElementById("stopNatPmpBtn");

    if (!badge || !portEl) return;

    if (data.active && data.assigned_external_port) {
      badge.textContent = "🟢 Dynamic P2P Active";
      badge.style.background = "rgba(0, 255, 157, 0.2)";
      badge.style.color = "var(--accent-safe)";
      badge.style.border = "1px solid rgba(0, 255, 157, 0.4)";

      portEl.innerHTML = `${data.assigned_external_port} <button class="btn-action" style="padding: 2px 8px; font-size: 0.7rem; margin-left: 8px; background: rgba(0,229,255,0.2); border-color: var(--accent-cyan); color: #fff;" onclick="navigator.clipboard.writeText('${data.assigned_external_port}'); showToast('Port Copied', 'Assigned P2P port ${data.assigned_external_port} copied to clipboard!', 'info')">📋 Copy</button>`;
      inPortEl.textContent = `${data.internal_port} (Local Host)`;
      leaseEl.textContent = `Expires in ${data.seconds_remaining}s (RFC 6886 Auto-Renewing)`;
      leaseEl.style.color = "var(--accent-safe)";

      if (reqBtn) reqBtn.style.display = "none";
      if (stopBtn) stopBtn.style.display = "inline-flex";
    } else {
      badge.textContent = data.status === "Refreshing" ? "⚡ Requesting..." : "⚪ Idle";
      badge.style.background = "rgba(255,255,255,0.06)";
      badge.style.color = "var(--text-muted)";
      badge.style.border = "none";

      portEl.textContent = "---";
      inPortEl.textContent = "---";
      leaseEl.textContent = data.error ? `Notice: ${data.error}` : "RFC 6886 Ping Inactive";
      leaseEl.style.color = data.error ? "#ff0055" : "var(--text-muted)";

      if (reqBtn) reqBtn.style.display = "inline-flex";
      if (stopBtn) stopBtn.style.display = "none";
    }
  } catch (err) {
    console.error("Error loading NAT-PMP status:", err);
  }
}

window.requestProtonNatPmp = async function() {
  showToast("Proton NAT-PMP", "Sending RFC 6886 port mapping request to Proton gateway 10.2.0.1:5351...", "info");
  try {
    const res = await fetch(`${API_BASE}/api/vpn/nat-pmp/request`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ lifetime: 60, gateway: "10.2.0.1" })
    });
    const data = await res.json();
    if (data.success) {
      showToast("P2P Port Assigned!", `Proton assigned public port: ${data.assigned_external_port} (TCP & UDP dual stream)`, "success");
      await loadNatPmpStatus();
      await loadPortForwarding();
    } else {
      showToast("NAT-PMP Notice", data.error || "Failed to obtain NAT-PMP mapping. Ensure connected to a Proton P2P server.", "warn");
      await loadNatPmpStatus();
    }
  } catch (err) {
    showToast("NAT-PMP Error", "Error requesting NAT-PMP port: " + err, "error");
  }
};

window.stopProtonNatPmp = async function() {
  try {
    const res = await fetch(`${API_BASE}/api/vpn/nat-pmp/stop`, { method: "POST" });
    const data = await res.json();
    showToast("Port Released", `Dynamic port ${data.released_port || ''} released.`, "info");
    await loadNatPmpStatus();
    await loadPortForwarding();
  } catch (err) {
    showToast("Error", "Error releasing port: " + err, "error");
  }
};

function populatePortForwardTunnels() {
  const sel = document.getElementById("pfTunnelSelect");
  if (!sel) return;
  sel.innerHTML = `
    <option value="all">🌐 All Interfaces (Global Forwarder)</option>
    <option value="orbot">🧅 Orbot / Tor SOCKS5</option>
  `;
  (state.vpnTunnels || []).forEach(t => {
    const opt = document.createElement("option");
    opt.value = t.id;
    opt.textContent = `🛡️ ${t.name} (${t.country || 'WireGuard'})`;
    sel.appendChild(opt);
  });
}

// ==================== Multi-VPN Port Forwarding Engine ====================
async function loadPortForwarding() {
  try {
    const res = await fetch(`${API_BASE}/api/vpn/port-forwarding`);
    state.portForwardRules = await res.json();
    renderPortForwarding();
  } catch (err) {
    console.error("Error loading port forwarding rules:", err);
  }
}

function renderPortForwarding() {
  const tbody = document.getElementById("portForwardingTableBody");
  if (!tbody || !state.portForwardRules) return;
  tbody.innerHTML = "";

  if (state.portForwardRules.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 20px;">No port forwarding rules active. Click "➕ Add Port Forward Rule" to forward WireGuard, P2P, or Tor ports.</td></tr>`;
    return;
  }

  state.portForwardRules.forEach(r => {
    const tr = document.createElement("tr");
    const isActive = r.is_active || r.status === "Active";

    const protoBadge = r.protocol === "BOTH"
      ? `<span class="badge" style="background: rgba(0, 229, 255, 0.2); color: var(--accent-cyan); border: 1px solid rgba(0, 229, 255, 0.4);">TCP+UDP</span>`
      : `<span class="badge badge-functional">${r.protocol}</span>`;

    const tunnelBadge = r.tunnel_id === "orbot"
      ? `<span class="badge" style="background: rgba(157, 78, 221, 0.2); color: #c77dff; border: 1px solid rgba(157, 78, 221, 0.4);">🧅 ${escapeHtml(r.tunnel_name || 'Orbot')}</span>`
      : (r.tunnel_id && r.tunnel_id !== "all"
        ? `<span class="badge" style="background: rgba(181, 23, 158, 0.2); color: #fff; border: 1px solid var(--accent-purple);">🛡️ ${escapeHtml(r.tunnel_name || 'WireGuard')}</span>`
        : `<span class="badge" style="background: rgba(255, 255, 255, 0.06); color: var(--text-muted);">🌐 Global</span>`);

    tr.innerHTML = `
      <td style="font-weight: 700; color: #fff;">${escapeHtml(r.name)}</td>
      <td>${tunnelBadge}</td>
      <td style="font-family: var(--font-mono); color: var(--accent-cyan); font-weight: 700;">${r.listen_port}</td>
      <td style="font-family: var(--font-mono);">${escapeHtml(r.target_host)}:${r.target_port}</td>
      <td>${protoBadge}</td>
      <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted);">
        ${r.connections_handled || 0} conns &bull; ${Math.round((r.bytes_forwarded || 0) / 1024)} KB
      </td>
      <td>
        <span class="badge ${isActive ? 'badge-allowed' : 'badge-functional'}">
          ${isActive ? '🟢 Active' : '⚪ Disabled'}
        </span>
      </td>
      <td>
        <button class="btn-action ${isActive ? 'btn-danger' : ''}" onclick="togglePortForward('${r.id}', ${!isActive})">
          ${isActive ? 'Stop' : 'Start'}
        </button>
        <button class="btn-action btn-danger" style="margin-left: 6px;" onclick="deletePortForward('${r.id}')">
          🗑️
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

window.applyPortPreset = function(name, listen_port, target_host, target_port, proto, tunnel_id) {
  document.getElementById("pfRuleName").value = name;
  document.getElementById("pfListenPort").value = listen_port;
  document.getElementById("pfTargetHost").value = target_host;
  document.getElementById("pfTargetPort").value = target_port;
  document.getElementById("pfProtocol").value = proto || "TCP";
  if (tunnel_id) {
    const sel = document.getElementById("pfTunnelSelect");
    if (sel) sel.value = tunnel_id;
  }
};

async function savePortForwardRule() {
  const name = document.getElementById("pfRuleName").value.trim() || "Port Forward";
  const listen_port = parseInt(document.getElementById("pfListenPort").value);
  const target_host = document.getElementById("pfTargetHost").value.trim() || "127.0.0.1";
  const target_port = parseInt(document.getElementById("pfTargetPort").value);
  const protocol = document.getElementById("pfProtocol").value || "TCP";
  const tunnelSelect = document.getElementById("pfTunnelSelect");
  const tunnel_id = tunnelSelect ? tunnelSelect.value : "all";
  const tunnel_name = tunnelSelect && tunnelSelect.options[tunnelSelect.selectedIndex] ? tunnelSelect.options[tunnelSelect.selectedIndex].text : "All Interfaces";

  if (!listen_port || !target_port) {
    showToast("Validation", "Please specify both listen port and target port.", "warn");
    return;
  }

  try {
    await fetch(`${API_BASE}/api/vpn/port-forwarding`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, listen_port, target_host, target_port, protocol, tunnel_id, tunnel_name, auto_start: true })
    });
    document.getElementById("portForwardModal").classList.remove("open");
    loadPortForwarding();
    showToast("Port Forwarding Deployed", `Rule '${name}' (${protocol} ${listen_port} &rarr; ${target_host}:${target_port}) bound to ${tunnel_name}!`, "success");
  } catch (err) {
    showToast("Port Forward Error", "Error deploying port forward rule: " + err, "error");
  }
}

async function togglePortForward(ruleId, start) {
  try {
    const action = start ? "start" : "stop";
    await fetch(`${API_BASE}/api/vpn/port-forwarding/${encodeURIComponent(ruleId)}/${action}`, { method: "POST" });
    loadPortForwarding();
  } catch (err) {
    showToast("Port Forward Error", "Error toggling port forward rule: " + err, "error");
  }
}

async function deletePortForward(ruleId) {
  try {
    await fetch(`${API_BASE}/api/vpn/port-forwarding/${encodeURIComponent(ruleId)}`, { method: "DELETE" });
    showToast("Port Forward Removed", "Port forwarding rule removed.", "info");
    loadPortForwarding();
  } catch (err) {
    showToast("Port Forward Error", "Error deleting port forward rule: " + err, "error");
  }
}

// ==================== Auto-Updater Frontend Subsystem ====================

function updateUpdaterState(data) {
  if (!data) return;
  state.updater = Object.assign({}, state.updater, data);
  renderUpdaterUI(state.updater);
}

function renderUpdaterUI(data) {
  if (!data) return;

  const currentVer = data.current_version || "1.0.6";
  const latestVer = data.latest_version || currentVer;
  const isAvailable = !!data.update_available;
  const status = data.status || "idle";

  // 1. Top Navbar Header Pill
  const pillText = document.getElementById("updatePillText");
  const pillDot = document.getElementById("updatePillDot");
  if (pillText) {
    pillText.textContent = isAvailable ? `Update: v${latestVer}` : `v${currentVer}`;
  }
  if (pillDot) {
    pillDot.className = "update-pill-dot" + 
      ((status === "ready" || status === "downloaded") ? " ready" : (isAvailable ? " available" : ""));
  }

  // 2. Modal Hero Card Versions
  const curVerElem = document.getElementById("updateCurrentVersion");
  const latVerElem = document.getElementById("updateLatestVersion");
  if (curVerElem) curVerElem.textContent = `v${currentVer}`;
  if (latVerElem) {
    if (status === "checking") {
      latVerElem.textContent = "Scanning...";
    } else if (isAvailable && data.latest_version) {
      latVerElem.textContent = `v${latestVer}`;
    } else {
      latVerElem.textContent = `v${latestVer} (Up to date)`;
    }
  }

  // 3. Status Badge Pill
  const statusPill = document.getElementById("updateStatusPill");
  if (statusPill) {
    if (status === "checking") {
      statusPill.className = "badge badge-functional";
      statusPill.innerHTML = "🔄 Checking GitHub Releases...";
    } else if (status === "downloading") {
      statusPill.className = "badge badge-ad";
      statusPill.innerHTML = `⬇️ Downloading Update (${Math.round(data.download_progress || 0)}%)`;
    } else if ((status === "ready" || status === "downloaded")) {
      statusPill.className = "badge badge-allowed";
      statusPill.style.background = "rgba(0, 255, 157, 0.2)";
      statusPill.style.color = "#00ff9d";
      statusPill.innerHTML = "⚡ Update Downloaded & Ready to Install";
    } else if (status === "applying") {
      statusPill.className = "badge badge-telemetry";
      statusPill.innerHTML = "🔄 Applying Update & Restarting...";
    } else if (isAvailable) {
      statusPill.className = "badge badge-telemetry";
      statusPill.style.background = "rgba(0, 229, 255, 0.2)";
      statusPill.style.color = "var(--accent-cyan)";
      statusPill.innerHTML = `🚀 New Version Available: v${latestVer}`;
    } else if (status === "error") {
      statusPill.className = "badge badge-blocked";
      statusPill.innerHTML = `❌ ${escapeHtml(data.error_message || "Update check failed")}`;
    } else {
      statusPill.className = "badge badge-allowed";
      statusPill.style.background = "";
      statusPill.style.color = "";
      statusPill.innerHTML = "✅ TrackerControl PC is Up to Date";
    }
  }

  // 4. Release Notes & Package Info
  const releaseMeta = document.getElementById("updateReleaseMeta");
  if (releaseMeta) {
    if (isAvailable && data.latest_version) {
      releaseMeta.style.display = "block";
      const title = document.getElementById("updateReleaseTitle");
      if (title) title.textContent = data.release_name || `TrackerControl PC v${latestVer} Release`;

      const dateElem = document.getElementById("updateReleaseDate");
      if (dateElem) {
        dateElem.textContent = data.published_at 
          ? `Published: ${new Date(data.published_at).toLocaleDateString()}`
          : "Published: Recently";
      }

      const changelog = document.getElementById("updateChangelog");
      if (changelog) {
        changelog.textContent = data.release_notes || "Includes updated threat signatures, high-performance VPN routing, and bug fixes.";
      }

      const assetName = document.getElementById("updateAssetName");
      const assetSize = document.getElementById("updateAssetSize");
      const asset = data.selected_asset;
      if (assetName) assetName.textContent = (asset && asset.name) || data.asset_name || "Platform binary";
      if (assetSize) {
        const bytes = (asset && asset.size) || data.total_bytes || data.asset_size || 0;
        assetSize.textContent = bytes > 0 ? `${(bytes / (1024 * 1024)).toFixed(1)} MB` : "Auto-detect";
      }
    } else {
      releaseMeta.style.display = "none";
    }
  }

  // 5. Download Progress Bar
  const progressBox = document.getElementById("updateProgressContainer");
  if (progressBox) {
    if (status === "downloading" || (status === "ready" || status === "downloaded")) {
      progressBox.style.display = "block";
      const fill = document.getElementById("updateProgressFill");
      const pct = document.getElementById("updateProgressPercent");
      const txt = document.getElementById("updateProgressText");
      const speed = document.getElementById("updateSpeedText");
      const bytes = document.getElementById("updateBytesText");

      const prog = (status === "ready" || status === "downloaded") ? 100 : Math.min(100, Math.max(0, data.download_progress || 0));
      if (fill) fill.style.width = `${prog}%`;
      if (pct) pct.textContent = `${Math.round(prog)}%`;
      if (txt) {
        txt.textContent = (status === "ready" || status === "downloaded") 
          ? "Download Complete! Ready for immediate installation." 
          : "Streaming update package directly from GitHub...";
      }
      if (speed) speed.textContent = `${data.download_speed_kbps || 0} KB/s`;
      if (bytes) {
        const dlMb = ((data.downloaded_bytes || 0) / (1024 * 1024)).toFixed(1);
        const totMb = ((data.total_bytes || 0) / (1024 * 1024)).toFixed(1);
        bytes.textContent = `${dlMb} MB / ${totMb} MB`;
      }
    } else {
      progressBox.style.display = "none";
    }
  }

  // 6. Action Buttons & Controls
  const checkBtn = document.getElementById("updateCheckBtn");
  const checkIcon = document.getElementById("updateCheckIcon");
  if (checkBtn) checkBtn.disabled = (status === "checking" || status === "downloading" || status === "applying");
  if (checkIcon) checkIcon.textContent = status === "checking" ? "⏳" : "🔄";

  const downloadBtn = document.getElementById("updateDownloadBtn");
  if (downloadBtn) {
    downloadBtn.style.display = (isAvailable && status !== "downloading" && (status !== "ready" && status !== "downloaded") && status !== "applying") 
      ? "inline-flex" 
      : "none";
  }

  const applyBtn = document.getElementById("updateApplyBtn");
  if (applyBtn) {
    applyBtn.style.display = ((status === "ready" || status === "downloaded")) ? "inline-flex" : "none";
  }

  const ghLink = document.getElementById("updateGithubLink");
  if (ghLink && data.html_url) {
    ghLink.href = data.html_url;
  }

  const autoToggle = document.getElementById("updaterAutoCheckToggle");
  if (autoToggle && data.auto_check_enabled !== undefined) {
    autoToggle.checked = !!data.auto_check_enabled;
  }
}

async function openUpdateModal() {
  const modal = document.getElementById("updateModal");
  if (modal) modal.classList.add("open");
  await loadUpdaterStatus();
}

function closeUpdateModal() {
  const modal = document.getElementById("updateModal");
  if (modal) modal.classList.remove("open");
}

async function loadUpdaterStatus() {
  try {
    const res = await fetch(`${API_BASE}/api/updater/status`);
    if (res.ok) {
      const data = await res.json();
      updateUpdaterState(data);
    }
  } catch (err) {
    console.warn("Failed fetching updater status:", err);
  }
}

async function checkUpdates(manual = false) {
  state.updater.status = "checking";
  renderUpdaterUI(state.updater);

  try {
    const res = await fetch(`${API_BASE}/api/updater/check`, { method: "POST" });
    const data = await res.json();
    updateUpdaterState(data);

    if (data.update_available) {
      showToast("Update Available", `TrackerControl PC v${data.latest_version} is available!`, "info");
    } else if (manual) {
      showToast("Up to Date", `TrackerControl PC is running the latest version (v${data.current_version || "1.0.6"}).`, "success");
    }
  } catch (err) {
    state.updater.status = "error";
    state.updater.error_message = String(err);
    renderUpdaterUI(state.updater);
    showToast("Update Error", "Failed to connect to update service: " + err, "error");
  }
}

async function downloadUpdate() {
  try {
    showToast("Download Initiated", "Streaming update package from GitHub Releases in background...", "info");
    state.updater.status = "downloading";
    state.updater.download_progress = 0;
    renderUpdaterUI(state.updater);

    const res = await fetch(`${API_BASE}/api/updater/download`, { method: "POST" });
    const data = await res.json();
    if (!data.success && data.error) {
      showToast("Download Failed", data.error, "error");
      state.updater.status = "error";
      state.updater.error_message = data.error;
      renderUpdaterUI(state.updater);
    }
  } catch (err) {
    showToast("Download Error", "Error starting update download: " + err, "error");
  }
}

async function applyUpdate() {
  try {
    showToast("Applying Update", "Executing updater script and restarting TrackerControl PC...", "success");
    state.updater.status = "applying";
    renderUpdaterUI(state.updater);

    const res = await fetch(`${API_BASE}/api/updater/apply`, { method: "POST" });
    const data = await res.json();
    if (!data.success && data.error) {
      showToast("Update Failed", data.error, "error");
      state.updater.status = "error";
      state.updater.error_message = data.error;
      renderUpdaterUI(state.updater);
    }
  } catch (err) {
    showToast("Update Error", "Error applying update: " + err, "error");
  }
}

async function toggleAutoCheckUpdates(enabled) {
  try {
    await fetch(`${API_BASE}/api/updater/settings`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ auto_check: enabled })
    });
    showToast("Settings Updated", `Automatic background update checks ${enabled ? "enabled" : "disabled"}.`, "info");
  } catch (err) {
    showToast("Settings Error", "Error saving updater settings: " + err, "error");
  }
}

function handleUpdateAvailable(data) {
  updateUpdaterState(data);
  showToast(
    "Update Available",
    `TrackerControl PC v${data.latest_version || "New"} is available! Click the version badge in the top bar to inspect changelog and download.`,
    "info",
    8000
  );
}

function handleUpdateProgress(data) {
  if (data.progress !== undefined) state.updater.download_progress = data.progress;
  if (data.speed_kbps !== undefined) state.updater.download_speed_kbps = data.speed_kbps;
  if (data.downloaded_bytes !== undefined) state.updater.downloaded_bytes = data.downloaded_bytes;
  if (data.total_bytes !== undefined) state.updater.total_bytes = data.total_bytes;
  state.updater.status = "downloading";
  renderUpdaterUI(state.updater);
}

function handleUpdateReady(data) {
  updateUpdaterState(data);
  state.updater.status = "ready";
  renderUpdaterUI(state.updater);
  showToast(
    "Update Ready to Install",
    "TrackerControl PC update has finished downloading. Click '⚡ Install & Restart' to complete.",
    "success",
    10000
  );
}

function handleUpdateStatus(data) {
  updateUpdaterState(data);
}

// Global modal click outside listener
document.addEventListener("DOMContentLoaded", () => {
  const updateModal = document.getElementById("updateModal");
  if (updateModal) {
    updateModal.addEventListener("click", (e) => {
      if (e.target === updateModal) {
        closeUpdateModal();
      }
    });
  }
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    const updateModal = document.getElementById("updateModal");
    if (updateModal && updateModal.classList.contains("open")) {
      closeUpdateModal();
    }
  }
});

// Window exports
window.openUpdateModal = openUpdateModal;
window.closeUpdateModal = closeUpdateModal;
window.checkUpdates = checkUpdates;
window.downloadUpdate = downloadUpdate;
window.applyUpdate = applyUpdate;
window.toggleAutoCheckUpdates = toggleAutoCheckUpdates;

