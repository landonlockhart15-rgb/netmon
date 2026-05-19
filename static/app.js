/**
 * app.js — NetMon Dashboard Logic (Phase 4)
 *
 * SECTIONS
 * ─────────────────────────────────────────────────────────
 * 1.  Reduced Motion
 * 2.  Clock
 * 3.  Section Navigation  ← NEW: switches between Overview/Health/Settings
 * 4.  DOM References
 * 5.  Utilities
 * 6.  Stat Strip
 * 7.  Scan Summary panel
 * 8.  Device Table
 * 9.  Diff / Recent Activity
 * 10. Scan History
 * 11. Health Section      ← NEW: status, chart, events, telemetry
 * 12. Settings Section    ← NEW: load, save
 * 13. Scan Control
 * 14. Data Loading
 * 15. Init
 * ─────────────────────────────────────────────────────────
 */


/* ============================================================
   1. REDUCED MOTION
   ============================================================ */
const MOTION_KEY = "reducedMotion";

function applyMotionPreference() {
  const osReduced   = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const userReduced = localStorage.getItem(MOTION_KEY) === "true";
  const reduce      = osReduced || userReduced;

  document.documentElement.setAttribute("data-reduced-motion", reduce ? "true" : "false");
  const btn = document.getElementById("motion-toggle");
  if (btn) {
    btn.classList.toggle("is-active", reduce);
    btn.title = reduce ? "Motion OFF — click to enable" : "Motion ON — click to disable";
  }
  // Tell ECharts to disable animation if motion is off
  if (window._latencyChart) {
    window._latencyChart.setOption({ animation: !reduce });
  }
}

function toggleMotion() {
  const current = localStorage.getItem(MOTION_KEY) === "true";
  localStorage.setItem(MOTION_KEY, (!current).toString());
  applyMotionPreference();
}


// Shared locale settings — Chicago time, 12h format, used everywhere
const _TZ   = "America/Chicago";
const _TFMT = { hour: "2-digit", minute: "2-digit", hour12: true, timeZone: _TZ };
const _DFMT = { month: "short", day: "numeric", timeZone: _TZ };
const _DTFMT = { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: true, timeZone: _TZ };

function _fmtTime(d) { return new Date(d).toLocaleTimeString("en-US", _TFMT); }
function _fmtDate(d) { return new Date(d).toLocaleDateString("en-US", _DFMT); }
function _fmtDateTime(d) { return new Date(d).toLocaleString("en-US", _DTFMT); }


/* ============================================================
   2. CLOCK
   ============================================================ */
function startClock() {
  const el = document.getElementById("topbar-clock");
  if (!el) return;
  const tick = () => {
    el.textContent = new Date().toLocaleTimeString("en-US", {
      hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: true,
      timeZone: "America/Chicago",
    });
  };
  tick();
  setInterval(tick, 1000);
}


/* ============================================================
   3. SECTION NAVIGATION
   ============================================================

   Clicking a nav item:
     1. Hides all .page-section elements
     2. Shows the one matching data-section
     3. Updates .active class on nav items
     4. Loads data for that section if needed

   Data loading per section:
     overview  → loadDevices(), loadDiff(), loadScanHistory()
     health    → loadHealthSection() (current status + chart + events + telemetry)
     settings  → loadSettings() (populate form fields)
     others    → nothing (coming soon placeholder)
*/

function switchSection(name) {
  // Hide all sections
  document.querySelectorAll(".page-section").forEach(s => {
    s.style.display = "none";
  });

  // Show the target
  const target = document.getElementById(`section-${name}`);
  if (target) target.style.display = "flex";

  // Update nav active state
  document.querySelectorAll(".nav-item").forEach(item => {
    item.classList.toggle("active", item.dataset.section === name);
  });

  // Stop health telemetry timer when leaving that section
  if (name !== "health" && _telemetryTimer) {
    clearInterval(_telemetryTimer);
    _telemetryTimer = null;
  }

  // Section-specific data loading
  if (name === "health")   loadHealthSection();
  if (name === "settings") loadSettings();
  if (name === "devices")  loadDevicesSection();
  if (name === "alerts")   loadAlertsSection();
  if (name === "traffic")  loadTrafficSection();
  if (name === "shield")   loadShieldSection();
  if (name === "reports")  loadReportsSection();
  if (name === "dns")      loadDnsSection();
  if (name === "logs")     loadLogsSection();
  if (name === "seclab")   loadSecurityLabSection();
  // overview data is loaded at init and after scan — no need to reload on switch
}

// Wire up sidebar nav items
function initNav() {
  document.querySelectorAll(".nav-item").forEach(item => {
    item.addEventListener("click", () => {
      switchSection(item.dataset.section);
    });
  });
}


/* ============================================================
   4. DOM REFERENCES
   ============================================================ */
const scanBtn            = document.getElementById("scan-btn");
const scanStatusEl       = document.getElementById("scan-status");
const devicesContainer   = document.getElementById("devices-container");
const deviceCountBadge   = document.getElementById("device-count");
const scanSummaryContent = document.getElementById("scan-summary-content");
const activityContent    = document.getElementById("activity-content");
const scanHistoryContent = document.getElementById("scan-history-content");

// Stat strip
const statNetworkDot  = document.getElementById("stat-network-dot");
const statNetworkText = document.getElementById("stat-network-text");
const statLatency     = document.getElementById("stat-latency");
const statDeviceCount = document.getElementById("stat-device-count");
const statLastScan    = document.getElementById("stat-last-scan");
const statChanges     = document.getElementById("stat-changes");

// Health section
const hpStatusPanel = document.getElementById("hp-status");
const hpStatusIcon  = document.getElementById("hp-status-icon");
const hpStatusText  = document.getElementById("hp-status-text");
const hpStatusMeta  = document.getElementById("hp-status-meta");
const hpLatencyVal  = document.getElementById("hp-latency-val");
const hpLatencyMeta = document.getElementById("hp-latency-meta");
const hpLossMeta    = document.getElementById("hp-loss-meta");
const hpSpeedVal    = document.getElementById("hp-speed-val");
const hpSpeedUnit   = document.getElementById("hp-speed-unit");
const hpSpeedMeta   = document.getElementById("hp-speed-meta");
const hpEventsContent = document.getElementById("hp-events-content");


/* ============================================================
   5. UTILITIES
   ============================================================ */

function formatRelativeTime(isoString) {
  if (!isoString) return "—";
  const diff = Date.now() - new Date(isoString).getTime();
  if (isNaN(diff)) return "—";
  const s = Math.floor(diff / 1000);
  if (s <  10) return "just now";
  if (s <  60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m <  60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h <  24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function renderSkeleton(container) {
  const rows = Array.from({ length: 6 }, () => `
    <div class="skeleton-row">
      <div class="skeleton-cell skeleton-cell--ip"></div>
      <div class="skeleton-cell skeleton-cell--name"></div>
      <div class="skeleton-cell skeleton-cell--mac"></div>
      <div class="skeleton-cell skeleton-cell--vendor"></div>
      <div class="skeleton-cell skeleton-cell--ports"></div>
      <div class="skeleton-cell skeleton-cell--badge"></div>
    </div>
  `).join("");
  container.innerHTML = `<div class="skeleton-table">${rows}</div>`;
}

function renderEmptyState(container, icon, text, hint) {
  container.innerHTML = `
    <div class="empty-state">
      <div class="empty-icon" aria-hidden="true">${icon}</div>
      <div class="empty-text">${text}</div>
      <div class="empty-hint">${hint}</div>
    </div>
  `;
}


/* ============================================================
   6. STAT STRIP
   ============================================================

   Now shows real health data:
     Network: Online / Degraded / Offline dot + label
     Latency: current ms value
   These are updated by updateHealthStatStrip() after each health check.
*/

function updateHealthStatStrip(health) {
  if (!health || health.status === "unknown") {
    statNetworkText.textContent = "Checking…";
    statNetworkDot.className = "status-dot status-dot--unknown";
    statLatency.textContent = "—";
    return;
  }

  const label = health.status.charAt(0).toUpperCase() + health.status.slice(1);
  statNetworkText.textContent = label;
  statNetworkDot.className = `status-dot status-dot--${health.status}`;

  if (health.latency_ms !== null && health.latency_ms !== undefined &&
      (!window._speedTestLatencyUntil || Date.now() > window._speedTestLatencyUntil)) {
    statLatency.textContent = `${health.latency_ms}ms`;
    statLatency.style.color = health.latency_ms > 200
      ? "var(--status-danger)"
      : health.latency_ms > 100
        ? "var(--status-warning)"
        : "var(--text-bright)";
  } else {
    statLatency.textContent = "—";
    statLatency.style.color = "";
  }
}

function updateScanStatStrip(scan, deviceCount, changeCount) {
  statLastScan.textContent    = scan ? formatRelativeTime(scan.started_at) : "—";
  statDeviceCount.textContent = scan ? deviceCount : "—";

  if (changeCount === null || changeCount === undefined) {
    statChanges.textContent = "—";
    statChanges.style.color = "";
  } else {
    statChanges.textContent = changeCount;
    statChanges.style.color = changeCount > 0 ? "var(--status-warning)" : "";
  }
}


/* ============================================================
   7. SCAN SUMMARY PANEL
   ============================================================ */
function renderScanSummary(scan) {
  if (!scan) {
    renderEmptyState(scanSummaryContent, "◎", "No scan data yet.", "Run a scan to populate this panel.");
    return;
  }
  const scanTime = _fmtDateTime(scan.started_at);
  scanSummaryContent.innerHTML = `
    <div class="scan-stat-grid">
      <div class="scan-stat">
        <div class="scan-stat__value">${scan.host_count}</div>
        <div class="scan-stat__label">Hosts Found</div>
      </div>
      <div class="scan-stat">
        <div class="scan-stat__value">${scan.duration_s?.toFixed(1) ?? "?"}s</div>
        <div class="scan-stat__label">Duration</div>
      </div>
      <div class="scan-stat">
        <div class="scan-stat__value">#${scan.id}</div>
        <div class="scan-stat__label">Scan ID</div>
      </div>
    </div>
    <p class="muted" style="margin-top:12px; font-size:0.8rem;">${scanTime}</p>
  `;
}


/* ============================================================
   8. DEVICE TABLE
   ============================================================ */
function renderDeviceTable(devices, container) {
  if (!devices || devices.length === 0) {
    renderEmptyState(container, "◉", "No hosts responded.",
      "Check the Network panel or set SCAN_TARGET in .env if autodetect picked the wrong subnet.");
    deviceCountBadge.textContent = "";
    return;
  }
  deviceCountBadge.textContent = devices.length;

  const rows = devices.map(device => {
    const portsHtml = device.open_ports.length > 0
      ? device.open_ports.map(p => `<span class="port-tag">${p}</span>`).join("")
      : `<span class="text-dim">—</span>`;

    const nameHtml = device.label
      ? `<strong>${device.label}</strong>`
      : device.hostname || `<span class="text-dim">—</span>`;

    const statusHtml = device.is_known
      ? `<span class="badge badge--trusted">Trusted</span>`
      : `<span class="badge badge--unknown">Unknown</span>`;

    return `
      <tr>
        <td class="col-ip">${device.ip}</td>
        <td class="col-name">${nameHtml}</td>
        <td class="col-mac">${device.mac}</td>
        <td>${device.vendor}</td>
        <td>${portsHtml}</td>
        <td>${statusHtml}</td>
      </tr>
    `;
  }).join("");

  container.innerHTML = `
    <div class="table-scroll-wrap">
      <table class="device-table">
        <thead>
          <tr>
            <th>IP Address</th><th>Name</th><th>MAC Address</th>
            <th>Vendor</th><th>Open Ports</th><th>Status</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}


/* ============================================================
   9. DIFF / RECENT ACTIVITY
   ============================================================ */
const CHANGE_STYLES = {
  new_device:       { cls: "change--new",     icon: "▲" },
  device_missing:   { cls: "change--missing", icon: "▼" },
  ip_changed:       { cls: "change--modified", icon: "⇄" },
  hostname_changed: { cls: "change--modified", icon: "⇄" },
  ports_changed:    { cls: "change--ports",   icon: "◈" },
};

async function loadDiff() {
  try {
    const resp = await fetch("/api/diff/latest");
    if (!resp.ok) throw new Error(`${resp.status}`);
    const data = await resp.json();

    const count = data.prev_scan_id !== null ? data.change_count : null;
    if (statChanges) {
      statChanges.textContent = count === null ? "—" : count;
      statChanges.style.color = (count !== null && count > 0) ? "var(--status-warning)" : "";
    }

    if (!data.changes || data.changes.length === 0) {
      renderEmptyState(activityContent, "◬", "No changes.",
        data.prev_scan_id === null
          ? "Run a second scan to see what changed."
          : "No changes detected since last scan.");
      return;
    }

    const items = data.changes.map(ch => {
      const style = CHANGE_STYLES[ch.change_type] || { cls: "", icon: "·" };
      return `
        <div class="change-event ${style.cls}">
          <span class="change-icon" aria-hidden="true">${style.icon}</span>
          <span class="change-message">${ch.message}</span>
          <span class="change-time">${formatRelativeTime(ch.created_at)}</span>
        </div>
      `;
    }).join("");
    activityContent.innerHTML = `<div class="change-list">${items}</div>`;

  } catch (err) {
    console.error("[netmon] loadDiff:", err);
  }
}


/* ============================================================
   10. SCAN HISTORY
   ============================================================ */
async function loadScanHistory() {
  try {
    const resp = await fetch("/api/scans");
    if (!resp.ok) throw new Error(`${resp.status}`);
    const scans = await resp.json();

    const completed = scans.filter(s => s.status === "complete").slice(0, 10);
    if (completed.length === 0) {
      renderEmptyState(scanHistoryContent, "◎", "No completed scans yet.", "");
      return;
    }

    const items = completed.map(s => {
      const time = _fmtDateTime(s.started_at);
      return `
        <div class="scan-history-item">
          <span class="sh-id">#${s.id}</span>
          <span class="sh-time">${time}</span>
          <span class="sh-hosts">${s.host_count} host${s.host_count !== 1 ? "s" : ""}</span>
          <span class="sh-duration">${s.duration_s != null ? s.duration_s.toFixed(1) + "s" : "—"}</span>
        </div>
      `;
    }).join("");
    scanHistoryContent.innerHTML = `<div class="scan-history-list">${items}</div>`;

  } catch (err) {
    console.error("[netmon] loadScanHistory:", err);
  }
}


/* ============================================================
   11. HEALTH SECTION
   ============================================================

   Three things to load when the Health section is shown:
     a) Current status (GET /api/health/current)
     b) History for the chart (GET /api/health/history)
     c) Live telemetry (GET /api/telemetry)
     d) Latest speed test result (GET /api/speed/latest)

   The ECharts latency chart is created once and reused.
   On subsequent loads we just call chart.setOption() with new data.
*/

// ── Current Status ──────────────────────────────────────────────────────────

async function loadHealthCurrent() {
  try {
    const resp = await fetch("/api/health/current");
    if (!resp.ok) throw new Error(`${resp.status}`);
    const h = await resp.json();

    // Update stat strip
    updateHealthStatStrip(h);

    // Update Health section status panel
    if (hpStatusPanel) {
      // Remove old status class, apply new one
      hpStatusPanel.className = hpStatusPanel.className
        .replace(/\bstatus--\S+/g, "")
        .trim();
      hpStatusPanel.classList.add(`status--${h.status || "unknown"}`);
    }

    const icons = { online: "●", degraded: "◑", offline: "○", unknown: "◎" };
    if (hpStatusIcon) hpStatusIcon.textContent = icons[h.status] || "◎";
    if (hpStatusText) {
      hpStatusText.textContent = (h.status || "unknown").toUpperCase();
      hpStatusText.style.color = {
        online:   "var(--status-online)",
        degraded: "var(--status-warning)",
        offline:  "var(--status-danger)",
      }[h.status] || "var(--text-dim)";
    }
    if (hpStatusMeta) {
      hpStatusMeta.textContent = h.checked_at
        ? `Checked ${formatRelativeTime(h.checked_at)} · target: ${h.target}`
        : (h.error || "No checks run yet");
    }

    // Don't overwrite if a speed test just updated latency (30s grace period)
    if (!window._speedTestLatencyUntil || Date.now() > window._speedTestLatencyUntil) {
      if (hpLatencyVal) {
        hpLatencyVal.textContent = h.latency_ms !== null ? h.latency_ms : "—";
      }
      if (hpLatencyMeta) {
        hpLatencyMeta.textContent = "avg ping RTT · 4 packets";
      }
    }
    // Local latency always updates (speed test doesn't affect it)
    const localVal  = document.getElementById("hp-local-latency-val");
    const localMeta = document.getElementById("hp-local-latency-meta");
    if (localVal) localVal.textContent = h.local_latency_ms !== null && h.local_latency_ms !== undefined
      ? h.local_latency_ms : "—";
    if (localMeta && h.local_target) localMeta.textContent = `ping ${h.local_target}`;
    if (hpLossMeta && h.packet_loss !== null) {
      hpLossMeta.textContent = `Packet loss: ${h.packet_loss}%`;
      hpLossMeta.style.color = h.packet_loss > 10
        ? "var(--status-warning)"
        : "var(--text-dim)";
    }

  } catch (err) {
    console.error("[netmon] loadHealthCurrent:", err);
  }
}

// ── On-demand health check button ───────────────────────────────────────────

async function runHealthCheck() {
  const btn = document.querySelector("#hp-status .btn-secondary");
  if (btn) { btn.disabled = true; btn.textContent = "Checking…"; }

  try {
    const resp = await fetch("/api/health/check", { method: "POST" });
    if (!resp.ok) throw new Error(`${resp.status}`);
    await loadHealthCurrent();
    await loadHealthChart();
  } catch (err) {
    console.error("[netmon] runHealthCheck:", err);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Check Now"; }
  }
}

// ── Speed test button ────────────────────────────────────────────────────────

async function runSpeedTest() {
  const btn = document.getElementById("speed-test-btn");
  if (btn) { btn.disabled = true; btn.textContent = "Testing… (5–20s)"; }
  if (hpSpeedVal)  hpSpeedVal.textContent = "…";
  if (hpSpeedMeta) hpSpeedMeta.textContent = "downloading test file…";

  try {
    const resp = await fetch("/api/speed/test", { method: "POST" });
    if (!resp.ok) throw new Error(`${resp.status}`);
    const data = await resp.json();
    renderSpeedResult(data);
    loadSpeedChart();

    // Update every latency display with the speed test measurement
    // and hold for 30 seconds so background polling doesn't overwrite it
    if (data.latency_ms !== null && data.latency_ms !== undefined) {
      const ms = data.latency_ms;
      const color = ms > 200 ? "var(--accent-crit)" : ms > 100 ? "var(--accent-warn)" : "";
      window._speedTestLatencyUntil = Date.now() + 30_000;
      if (statLatency)  { statLatency.textContent = `${ms}ms`; statLatency.style.color = color; }
      if (hpLatencyVal) { hpLatencyVal.textContent = ms; }
      const hpLatencyMeta = document.getElementById("hp-latency-meta");
      if (hpLatencyMeta) hpLatencyMeta.textContent = "avg RTT · from speed test";
    }
  } catch (err) {
    if (hpSpeedVal)  hpSpeedVal.textContent = "—";
    if (hpSpeedMeta) hpSpeedMeta.textContent = `Error: ${err.message}`;
    console.error("[netmon] runSpeedTest:", err);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Run Speed Test"; }
  }
}

function renderSpeedResult(data) {
  const uploadEl = document.getElementById("hp-upload-val");

  if (data.error && !data.download_mbps && !data.upload_mbps) {
    if (hpSpeedVal)  hpSpeedVal.textContent = "—";
    if (uploadEl)    uploadEl.textContent    = "—";
    if (hpSpeedMeta) hpSpeedMeta.textContent = `Error: ${data.error}`;
    return;
  }
  if (hpSpeedVal)  hpSpeedVal.textContent = data.download_mbps ?? "—";
  if (uploadEl)    uploadEl.textContent   = data.upload_mbps   ?? "—";
  if (hpSpeedUnit) hpSpeedUnit.textContent = "";   // unit now in HTML labels
  if (hpSpeedMeta) {
    const when = data.tested_at ? formatRelativeTime(data.tested_at) : "";
    const parts = [`tested ${when}`];
    if (data.error) parts.push(`(partial: ${data.error})`);
    hpSpeedMeta.textContent = parts.join(" · ");
  }
}

async function loadSpeedLatest() {
  try {
    const resp = await fetch("/api/speed/latest");
    if (!resp.ok) return;
    const data = await resp.json();
    if (data.download_mbps !== null) renderSpeedResult(data);
  } catch (err) {
    console.error("[netmon] loadSpeedLatest:", err);
  }
}

async function loadSpeedChart() {
  try {
    const resp = await fetch("/api/speed/history?limit=30");
    if (!resp.ok) return;
    const points = await resp.json();

    const el = document.getElementById("speed-chart");
    if (!el) return;

    // Section is hidden — defer until user navigates to Health
    if (el.getBoundingClientRect().width === 0) return;

    if (!window._speedChart) {
      window._speedChart = echarts.init(el, null, { renderer: "canvas" });
      window.addEventListener("resize", () => window._speedChart?.resize());
    }

    const reduced = document.documentElement.getAttribute("data-reduced-motion") === "true";

    const tagEl = document.getElementById("hp-speed-chart-tag");
    if (tagEl) tagEl.textContent = `${points.length} TEST${points.length !== 1 ? "S" : ""}`;

    if (!points.length) {
      // Don't touch innerHTML after echarts init — show empty chart instead
      window._speedChart?.setOption({ series: [{ data: [] }, { data: [] }] });
      return;
    }

    const xData    = points.map(p => {
      if (!p.tested_at) return "—";
      const d = new Date(p.tested_at);
      return _fmtDate(d) + "\n" + _fmtTime(d);
    });
    const dlData   = points.map(p => p.download_mbps ?? null);
    const ulData   = points.map(p => p.upload_mbps   ?? null);
    const showLabels = points.length <= 8;

    window._speedChart.setOption({
      animation: !reduced,
      backgroundColor: "transparent",
      legend: {
        data: ["Download", "Upload"],
        textStyle: { color: "#647a94", fontSize: 11 },
        top: 0,
        right: 0,
      },
      tooltip: {
        trigger: "axis",
        backgroundColor: "#1a1d27",
        borderColor: "#2a3a56",
        textStyle: { color: "#c8d6e8", fontSize: 12 },
        formatter(params) {
          const name = params[0]?.name || "";
          const dl = params.find(p => p.seriesName === "Download");
          const ul = params.find(p => p.seriesName === "Upload");
          return `
            <div style="font-size:11px;color:#647a94;margin-bottom:4px">${name.replace("\n", " ")}</div>
            <div>↓ <strong>${dl?.value != null ? dl.value + " Mbps" : "—"}</strong></div>
            <div>↑ <strong>${ul?.value != null ? ul.value + " Mbps" : "—"}</strong></div>
          `;
        },
      },
      grid: { top: 28, right: 16, bottom: 54, left: 56, containLabel: false },
      xAxis: {
        type: "category",
        data: xData,
        axisLine:  { lineStyle: { color: "#1e2a3e" } },
        axisLabel: { color: "#3a4a5e", fontSize: 9, rotate: 35, interval: 0 },
        axisTick:  { show: false },
      },
      yAxis: {
        type: "value",
        name: "Mbps",
        nameTextStyle: { color: "#3a4a5e", fontSize: 10 },
        axisLine:  { show: false },
        axisTick:  { show: false },
        axisLabel: { color: "#3a4a5e", fontSize: 10 },
        splitLine: { lineStyle: { color: "#141c2a" } },
        min: 0,
      },
      series: [
        {
          name: "Download",
          type: "bar",
          data: dlData,
          itemStyle: { color: "#00c8f0", borderRadius: [3, 3, 0, 0] },
          emphasis:  { itemStyle: { color: "#5ee0f8" } },
          label: {
            show: showLabels, position: "top",
            color: "#647a94", fontSize: 10,
            formatter: p => p.value != null ? `${p.value}` : "",
          },
        },
        {
          name: "Upload",
          type: "bar",
          data: ulData,
          itemStyle: { color: "#00e676", borderRadius: [3, 3, 0, 0] },
          emphasis:  { itemStyle: { color: "#66ffaa" } },
          label: {
            show: showLabels, position: "top",
            color: "#647a94", fontSize: 10,
            formatter: p => p.value != null ? `${p.value}` : "",
          },
        },
      ],
    });

  } catch (err) {
    console.error("[netmon] loadSpeedChart:", err);
  }
}

// ── Latency chart (ECharts) ─────────────────────────────────────────────────

/*
  The chart is created ONCE and stored in window._latencyChart.
  On subsequent calls we update its data with setOption().

  Why ECharts?
    - Rich tooltip and formatting for time-series
    - Efficient canvas rendering (handles 1000+ points fine)
    - 1MB total, no other dependencies

  Chart design:
    - X axis: timestamps, auto-formatted
    - Y axis: latency in ms
    - Area chart with gradient fill below the line
    - Null values (offline periods) show as gaps in the line
    - Points coloured by status: green=online, yellow=degraded, red=offline
    - No animation when reduced-motion is active
*/

function getChartColors(dataPoints) {
  // Returns an array of point-level colors matching each data point's status
  return dataPoints.map(p => {
    if (p.status === "offline")  return "#ff4444";
    if (p.status === "degraded") return "#ffc107";
    return "#00c8f0";
  });
}

async function loadHealthChart() {
  try {
    const resp = await fetch("/api/health/history?limit=120");
    if (!resp.ok) throw new Error(`${resp.status}`);
    const points = await resp.json();

    const el = document.getElementById("latency-chart");
    if (!el) return;

    if (el.getBoundingClientRect().width === 0) return;

    if (!window._latencyChart) {
      window._latencyChart = echarts.init(el, null, { renderer: "canvas" });
      window.addEventListener("resize", () => window._latencyChart?.resize());
    }

    const reduced = document.documentElement.getAttribute("data-reduced-motion") === "true";

    // Prepare series data
    // null values (offline) create gaps in the line automatically
    const xData = points.map(p => {
      const d = new Date(p.checked_at);
      return _fmtTime(d);
    });
    const yData = points.map(p => p.latency_ms);  // null = gap

    // Per-point colour for the line (status-based)
    const lineColors = getChartColors(points);

    window._latencyChart.setOption({
      animation: !reduced,
      backgroundColor: "transparent",
      tooltip: {
        trigger: "axis",
        backgroundColor: "#1a1d27",
        borderColor: "#2a3a56",
        textStyle: { color: "#c8d6e8", fontSize: 12 },
        formatter(params) {
          const p = params[0];
          const idx = p.dataIndex;
          const raw = points[idx];
          if (!raw) return "";
          const status = raw.status || "unknown";
          const loss   = raw.packet_loss != null ? `${raw.packet_loss}% loss` : "";
          const ms     = raw.latency_ms  != null ? `${raw.latency_ms}ms`      : "offline";
          return `
            <div style="font-size:11px;color:#647a94;margin-bottom:3px">${p.name}</div>
            <div style="font-weight:700">${ms}</div>
            <div style="font-size:11px;color:#647a94">${status} ${loss ? "· " + loss : ""}</div>
          `;
        },
      },
      grid: { top: 16, right: 16, bottom: 28, left: 48, containLabel: false },
      xAxis: {
        type: "category",
        data: xData,
        axisLine:  { lineStyle: { color: "#1e2a3e" } },
        axisLabel: { color: "#3a4a5e", fontSize: 10, interval: "auto" },
        axisTick:  { show: false },
      },
      yAxis: {
        type: "value",
        name: "ms",
        nameTextStyle: { color: "#3a4a5e", fontSize: 10 },
        axisLine:  { show: false },
        axisTick:  { show: false },
        axisLabel: { color: "#3a4a5e", fontSize: 10 },
        splitLine: { lineStyle: { color: "#141c2a" } },
        min: 0,
      },
      series: [
        {
          type: "line",
          data: yData,
          smooth: true,
          connectNulls: false,   // gaps where latency_ms is null (offline)
          symbol: "circle",
          symbolSize: 4,
          lineStyle: { color: "#00c8f0", width: 2 },
          itemStyle: {
            // Per-point colour based on status
            color(params) {
              return lineColors[params.dataIndex] || "#00c8f0";
            },
          },
          areaStyle: {
            // Gradient fill: accent at top, transparent at bottom
            color: {
              type: "linear",
              x: 0, y: 0, x2: 0, y2: 1,
              colorStops: [
                { offset: 0,   color: "rgba(0,200,240,0.18)" },
                { offset: 1,   color: "rgba(0,200,240,0.01)" },
              ],
            },
          },
        },
      ],
    });

    // Update the panel tag with actual data count
    const tagEl = document.getElementById("hp-chart-tag");
    if (tagEl) tagEl.textContent = `${points.length} CHECKS`;

    // Build outage/degraded event list from the same data
    renderHealthEvents(points);

  } catch (err) {
    console.error("[netmon] loadHealthChart:", err);
  }
}

// ── Health event log ─────────────────────────────────────────────────────────

function renderHealthEvents(points) {
  if (!hpEventsContent || !points) return;

  // Extract runs of "offline" or "degraded" checks
  const events = [];
  let current = null;

  for (const p of points) {
    if (p.status === "offline" || p.status === "degraded") {
      if (!current || current.status !== p.status) {
        if (current) events.push(current);
        current = { status: p.status, start: p.checked_at, count: 1, latency: p.latency_ms, loss: p.packet_loss };
      } else {
        current.count++;
        current.end = p.checked_at;
        // Track worst packet loss seen in this run
        if (p.packet_loss != null && (current.loss == null || p.packet_loss > current.loss)) {
          current.loss = p.packet_loss;
        }
      }
    } else {
      if (current) { events.push(current); current = null; }
    }
  }
  if (current) events.push(current);

  if (events.length === 0) {
    renderEmptyState(hpEventsContent, "◎", "No outage or degraded events.", "All checks within normal range.");
    return;
  }

  // Show most recent first
  const items = events.reverse().slice(0, 20).map(ev => {
    const d = new Date(ev.start);
    const dateStr = _fmtDate(d);
    const timeStr = _fmtTime(d);
    const duration = ev.count > 1 ? ` · ${ev.count} checks` : "";
    const lossStr  = ev.loss != null && ev.loss > 0 ? ` · ${ev.loss}% loss` : "";
    const detail   = ev.latency != null ? `${ev.latency}ms${lossStr}` : `no response${lossStr}`;
    return `
      <div class="health-event health-event--${ev.status}">
        <span class="he-badge he-badge--${ev.status}">${ev.status}</span>
        <span class="he-details">${detail}${duration}</span>
        <span class="he-time">${dateStr} ${timeStr}</span>
      </div>
    `;
  }).join("");

  hpEventsContent.innerHTML = `<div class="health-event-list">${items}</div>`;
}

// ── Telemetry ────────────────────────────────────────────────────────────────

async function loadTelemetry() {
  try {
    const resp = await fetch("/api/telemetry");
    if (!resp.ok) return;
    const data = await resp.json();

    const cpuEl = document.getElementById("tel-cpu");
    const memEl = document.getElementById("tel-mem");
    const pidEl = document.getElementById("tel-pid");

    if (cpuEl) cpuEl.textContent = `${data.cpu_pct}%`;
    if (memEl) memEl.textContent = `${data.mem_mb} MB`;
    if (pidEl) pidEl.textContent = data.pid;
  } catch (err) {
    console.error("[netmon] loadTelemetry:", err);
  }
}

// ── Full health section load ──────────────────────────────────────────────────

let _telemetryTimer = null;

async function loadHealthSection() {
  await loadHealthCurrent();
  await loadHealthChart();
  await loadSpeedLatest();
  await loadSpeedChart();
  await loadTelemetry();

  // Refresh telemetry every 10s while health section is visible
  if (_telemetryTimer) clearInterval(_telemetryTimer);
  _telemetryTimer = setInterval(loadTelemetry, 10_000);
}


/* ============================================================
   12. SETTINGS SECTION
   ============================================================ */

// ── Settings: key → card id mapping ─────────────────────────────────────────
const _CFG_CARD_KEYS = {
  scanning:      ["auto_scan_interval_h"],
  health:        ["health_check_interval_s", "health_target", "health_local_target",
                  "latency_warn_ms", "latency_crit_ms", "packet_loss_warn_pct"],
  speed:         ["speed_test_url"],
  notifications: ["ntfy_server", "ntfy_topic", "ntfy_user", "ntfy_pass",
                  "email_to", "smtp_user", "smtp_pass", "smtp_host", "smtp_port"],
  anomaly:       ["anomaly_spike_multiplier"],
};
// Toggle settings auto-save on change — no card membership needed
const _CFG_TOGGLES = [
  "auto_scan_enabled", "health_alerts_enabled", "ai_enabled", "ai_auto_analyze",
  "ntfy_enabled", "email_enabled", "anomaly_detection_enabled",
];


async function loadSettings() {
  try {
    const [settingsResp, netResp] = await Promise.all([
      fetch("/api/settings"),
      fetch("/api/network/detect", { method: "POST" }).catch(() => null),
    ]);
    if (!settingsResp.ok) throw new Error(`${settingsResp.status}`);
    const data = await settingsResp.json();

    // Populate text / number inputs by [name]
    document.querySelectorAll(".cfg-num-input[name], .cfg-text-input[name]").forEach(el => {
      if (el.name in data) el.value = data[el.name] ?? "";
    });

    // Populate toggle checkboxes by [data-setting]
    document.querySelectorAll(".cfg-toggle-input[data-setting]").forEach(el => {
      const val = (data[el.dataset.setting] ?? "false").toLowerCase();
      el.checked = val === "true" || val === "1";
      _updateToggleLabel(el);
    });

    // Override gateway field with currently detected gateway so it always reflects
    // the active network, regardless of what was last saved to the DB.
    if (netResp && netResp.ok) {
      const net = await netResp.json();
      const detectedGw = net?.gateway;
      const gwField = document.getElementById("s-local-target");
      if (gwField && detectedGw) {
        gwField.value = detectedGw;
        gwField.placeholder = detectedGw;
      }
    }

    updateAIProviderStatus();
  } catch (err) {
    console.error("[netmon] loadSettings:", err);
  }
}

function _updateToggleLabel(checkbox) {
  const label = checkbox.closest(".cfg-toggle")?.querySelector(".cfg-toggle-label");
  if (!label) return;
  label.textContent = checkbox.checked
    ? (label.dataset.on  || "On")
    : (label.dataset.off || "Off");
}

// Auto-save a single setting immediately (used by toggle switches)
async function _saveOneSetting(key, value) {
  try {
    const resp = await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ [key]: value }),
    });
    if (!resp.ok) throw new Error(resp.status);
  } catch (err) {
    console.error("[netmon] _saveOneSetting:", err);
  }
}

// Save all inputs belonging to a card (called by Save button)
async function _saveCfgCard(cardId) {
  const keys   = _CFG_CARD_KEYS[cardId] || [];
  const updates = {};
  keys.forEach(key => {
    const el = document.querySelector(`[name="${key}"]`);
    if (el) updates[key] = el.value;
  });

  const statusEl = document.querySelector(`.cfg-save-status[data-cfg="${cardId}"]`);
  const btnEl    = document.querySelector(`.cfg-save-btn[data-cfg="${cardId}"]`);
  if (btnEl) { btnEl.disabled = true; btnEl.textContent = "Saving…"; }

  try {
    const resp = await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(updates),
    });
    if (!resp.ok) throw new Error(resp.status);
    if (statusEl) {
      statusEl.textContent = "Saved ✓";
      statusEl.className   = "cfg-save-status cfg-save-status--ok";
      setTimeout(() => { statusEl.textContent = ""; statusEl.className = "cfg-save-status"; }, 2500);
    }
  } catch (err) {
    if (statusEl) {
      statusEl.textContent = "Save failed";
      statusEl.className   = "cfg-save-status cfg-save-status--err";
    }
  } finally {
    if (btnEl) { btnEl.disabled = false; btnEl.textContent = "Save"; }
  }
}

// Wire Save buttons
document.addEventListener("click", e => {
  const btn = e.target.closest(".cfg-save-btn");
  if (btn && btn.dataset.cfg) _saveCfgCard(btn.dataset.cfg);
});

// Wire toggle switches — auto-save on change
document.addEventListener("change", e => {
  const toggle = e.target.closest(".cfg-toggle-input");
  if (!toggle || !toggle.dataset.setting) return;
  _updateToggleLabel(toggle);
  _saveOneSetting(toggle.dataset.setting, toggle.checked ? "true" : "false");
});

// Legacy save function — still called if old forms exist anywhere
async function saveSettings(event) {
  if (event && event.preventDefault) event.preventDefault();
}


/* ============================================================
   13. SCAN CONTROL
   ============================================================ */
async function runScan() {
  scanBtn.disabled = true;
  scanStatusEl.innerHTML = `<span class="spinner" aria-hidden="true"></span> Scanning network… this may take 30–60 seconds.`;
  renderSkeleton(devicesContainer);
  deviceCountBadge.textContent = "";

  try {
    const response = await fetch("/api/scan", { method: "POST" });
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.detail || `Server error ${response.status}`);
    }
    const result = await response.json();

    let msg = `Scan #${result.scan_id} complete — ${result.host_count} device(s) in ${result.duration_s}s.`;
    if (result.new_devices > 0) msg += ` <strong style="color:var(--status-online)">${result.new_devices} new.</strong>`;
    if (result.changes > 0)     msg += ` <strong style="color:var(--status-warning)">${result.changes} change(s).</strong>`;
    scanStatusEl.innerHTML = msg;

    await loadAll();
    // If AI auto-analyze is on, show a pending indicator and poll for the result.
    // We do this non-destructively — old result stays visible, a small banner appears.
    _maybeStartAutoAIPolling();
  } catch (err) {
    scanStatusEl.textContent = `Error: ${err.message}`;
    renderEmptyState(devicesContainer, "◬", "Scan failed.", err.message);
    console.error("[netmon] runScan:", err);
  } finally {
    scanBtn.disabled = false;
  }
}


/* ============================================================
   14. DATA LOADING
   ============================================================ */
async function loadDevices() {
  try {
    const resp = await fetch("/api/devices");
    if (!resp.ok) throw new Error(`${resp.status}`);
    const data = await resp.json();

    renderScanSummary(data.scan);
    renderDeviceTable(data.devices, devicesContainer);

    statLastScan.textContent    = data.scan ? formatRelativeTime(data.scan.started_at) : "—";
    statDeviceCount.textContent = data.scan ? data.devices.length : "—";

    if (!data.scan) {
      renderEmptyState(devicesContainer, "◉", "No devices discovered yet.",
        "Run a scan to see devices on your network.");
      deviceCountBadge.textContent = "";
    }
  } catch (err) {
    console.error("[netmon] loadDevices:", err);
    renderEmptyState(devicesContainer, "◬", "Failed to load data.", err.message);
  }
}

async function loadAll() {
  await loadDevices();
  await loadDiff();
  await loadScanHistory();
  await loadHealthCurrent();
  await loadAISummary();
  loadNetworkInfo(false);  // populate network info panel (non-blocking)
}


/* ============================================================
   15. AUTO AI POLLING  (triggered by scan, not by button click)
   ============================================================

   After a scan completes, if AI auto-analyze is enabled the backend
   fires off a background thread. The frontend has no direct signal that
   this happened — so we check the settings and, if auto-analyze is on,
   show a non-intrusive "analyzing" indicator on the AI panel and poll
   until a new result arrives. The old result stays visible underneath.
*/

async function _maybeStartAutoAIPolling() {
  try {
    const resp = await fetch("/api/settings");
    if (!resp.ok) return;
    const settings = await resp.json();

    const aiOn   = (settings.ai_enabled      || "").toLowerCase() === "true";
    const autoOn = (settings.ai_auto_analyze || "").toLowerCase() === "true";
    if (!aiOn || !autoOn) return;

    // Show indicator — keep old content, just update the tag and status message
    const tag = document.getElementById("ai-panel-tag");
    const msg = document.getElementById("ai-status-msg");
    if (tag) { tag.textContent = "AI · ANALYZING…"; tag.style.opacity = "1"; }
    if (msg) {
      msg.textContent = "Auto-analysis running in background…";
      msg.style.color = "";
      msg.classList.add("visible");
    }

    // Use the live progress streamer so the user sees characters as they arrive,
    // same as the manual "Analyze Latest Changes" button.
    _pollAiProgressOverview();

  } catch (_) {}
}


/* ============================================================
   15. AI ANALYSIS  (was section 15 — now followed by 16-18)
   ============================================================

   The AI panel is secondary to deterministic monitoring. Design rules:
     - Always shows a clear "AI disabled" / "No analysis yet" state
     - Never blocks or replaces any other panel
     - On error, shows the error message (not a crash)
     - Token usage shown in footer so the user knows what API calls cost

   States the panel can be in:
     disabled     — AI is off in Settings (show setup hint)
     empty        — AI on, no analysis run yet
     loading      — analysis in progress (button clicked)
     ok           — summary rendered with severity, lists, next steps
     error        — AI call failed (show error, leave old summary if any)
*/

async function loadAISummary() {
  const content = document.getElementById("ai-content");
  const tag     = document.getElementById("ai-panel-tag");
  if (!content) return;

  try {
    const resp = await fetch("/api/ai/latest");
    if (!resp.ok) throw new Error(`${resp.status}`);
    const data = await resp.json();

    // Update the panel tag based on AI state
    if (tag) {
      if (!data.ai_enabled) {
        tag.textContent = "DISABLED";
        tag.style.opacity = "0.4";
      } else if (data.id) {
        tag.textContent = "AI";
        tag.style.opacity = "";
      } else {
        tag.textContent = "AI · READY";
        tag.style.opacity = "";
      }
    }

    if (data.id) window._lastAISummaryId = data.id;
    renderAISummary(content, data);

  } catch (err) {
    console.error("[netmon] loadAISummary:", err);
  }
}

function renderAISummary(container, data) {
  // AI is disabled — show setup hint
  if (!data.ai_enabled) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon" aria-hidden="true">◈</div>
        <div class="empty-text">AI Analysis is disabled.</div>
        <div class="empty-hint">Enable it in Settings → AI Analysis Settings,
          then set AI_PROVIDER (e.g. ollama) in your .env file.</div>
      </div>
    `;
    const btn = document.getElementById("ai-analyze-btn");
    if (btn) btn.disabled = true;
    return;
  }

  // AI enabled but no analysis yet, or there was an error with no prior data
  if (!data.id) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon" aria-hidden="true">◈</div>
        <div class="empty-text">No analysis yet.</div>
        <div class="empty-hint">Run a scan first, then click Analyze Latest Changes.</div>
      </div>
    `;
    return;
  }

  // Analysis exists but had an error
  if (data.error && !data.summary) {
    container.innerHTML = `
      <div class="ai-error">
        <strong>Analysis failed:</strong> ${data.error}
      </div>
    `;
    return;
  }

  // Full summary
  const severityLabel = (data.severity || "low").toUpperCase();
  const when          = formatRelativeTime(data.created_at);
  const tokens        = (data.input_tokens && data.output_tokens)
    ? `${data.input_tokens + data.output_tokens} tokens`
    : "";
  const modelStr = data.model || "";

  const benignItems    = (data.benign    || []).map(t => `<li>${_linkify(escapeHtml(t))}</li>`).join("");
  const concernItems   = (data.concerning|| []).map(t => {
    // If the concern text contains an IP, use the IP as the investigate item so the
    // API can gather real nmap/port evidence. Fall back to the full text if no IP found.
    const _ipM = t.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
    const _invItem = _ipM ? _ipM[1] : t;
    return `<li class="ai-concern-item" data-item="${escapeHtml(_invItem)}">
       <span class="ai-concern-text">${_linkify(escapeHtml(t))}</span>
       <button class="btn-investigate" data-item="${escapeHtml(_invItem)}" data-ctx="scan" title="Ask AI to investigate this">→ Investigate</button>
     </li>`;
  }).join("");
  const nextStepItems  = (data.next_steps|| []).map(t => `<li>${_linkify(escapeHtml(t))}</li>`).join("");

  const listsHtml = (benignItems || concernItems) ? `
    <div class="ai-lists">
      <div class="ai-list-section">
        <div class="ai-list-label ai-list-label--benign">LIKELY NORMAL</div>
        <ul class="ai-list ai-list--benign">${benignItems || "<li>Nothing to note</li>"}</ul>
      </div>
      <div class="ai-list-section">
        <div class="ai-list-label ai-list-label--concerning">WORTH ATTENTION</div>
        <ul class="ai-list ai-list--concerning">${concernItems || "<li>Nothing flagged</li>"}</ul>
      </div>
    </div>
  ` : "";

  const nextStepsHtml = nextStepItems ? `
    <div class="ai-next-steps">
      <div class="ai-next-steps-label">SUGGESTED NEXT STEPS</div>
      <ul>${nextStepItems}</ul>
    </div>
  ` : "";

  const metaParts = [when, modelStr, tokens].filter(Boolean);

  container.innerHTML = `
    <span class="ai-severity ai-severity--${data.severity || "low"}">${severityLabel}</span>
    <div class="ai-summary-text">${_linkify(escapeHtml(data.summary || ""))}</div>
    ${listsHtml}
    ${nextStepsHtml}
    <div class="ai-meta">${metaParts.map(p => `<span>${escapeHtml(p)}</span>`).join("")}</div>
  `;
}

async function runAIAnalysis() {
  const btn = document.getElementById("ai-analyze-btn");
  const msg = document.getElementById("ai-status-msg");

  if (btn) { btn.disabled = true; btn.textContent = "◈ Analyzing…"; }
  if (msg) {
    msg.textContent = "AI is starting…";
    msg.style.color = "";
    msg.classList.add("visible");
  }

  try {
    // Use the focused scan-only endpoint for faster response
    const resp = await fetch("/api/ai/analyze/scan", { method: "POST" });
    if (!resp.ok) throw new Error(`Server error ${resp.status}`);
    const data = await resp.json();

    if (data.status === "disabled") {
      if (msg) { msg.textContent = "AI is disabled — enable it in Settings"; msg.style.color = "var(--status-warning)"; }
      if (btn) { btn.disabled = false; btn.textContent = "◈ Analyze Latest Changes"; }
      return;
    }

    _pollAiProgressOverview();

  } catch (err) {
    if (msg) { msg.textContent = `Error: ${err.message}`; msg.style.color = "var(--status-danger)"; }
    if (btn) { btn.disabled = false; btn.textContent = "◈ Analyze Latest Changes"; }
    console.error("[netmon] runAIAnalysis:", err);
  }
}

// Polls /api/ai/progress every 500ms while AI is generating the scan
// analysis, then fetches /api/ai/latest once status flips to "done".
let _aiOverviewProgressTimer = null;
let _aiOverviewStartId = null;
function _pollAiProgressOverview() {
  if (_aiOverviewProgressTimer) clearTimeout(_aiOverviewProgressTimer);
  _aiOverviewStartId = null;

  const btn = document.getElementById("ai-analyze-btn");
  const msg = document.getElementById("ai-status-msg");
  const content = document.getElementById("ai-content");
  const startedAt = Date.now();

  const tick = async () => {
    try {
      const p = await _apiFetch("/api/ai/progress", { timeoutMs: 5000 });

      if (_aiOverviewStartId === null && p.status === "running") {
        _aiOverviewStartId = p.id;
      }

      // Live status: char count + elapsed
      if (msg && p.status === "running") {
        const elapsed = (p.elapsed_s != null) ? `${p.elapsed_s.toFixed(0)}s` : "";
        msg.textContent = `AI responding · ${p.chars || 0} chars · ${elapsed}`;
      }

      // Show live stream in the AI panel while running
      if (content && p.status === "running") {
        const elapsed = p.elapsed_s != null ? p.elapsed_s.toFixed(1) + 's' : '';
        if (p.partial) {
          content.innerHTML = `
            <div class="ai-live-stream-wrap">
              <div class="ai-live-header">
                <span class="ai-live-dot"></span>
                <span>AI is responding…</span>
                <span class="ai-live-meta">${p.chars || 0} chars · ${elapsed}</span>
              </div>
              <pre class="ai-live-stream">${escapeHtml((p.partial || "").slice(-800))}</pre>
            </div>`;
        } else {
          // Running but first token hasn't arrived yet — show a waiting indicator
          content.innerHTML = `
            <div class="ai-live-stream-wrap">
              <div class="ai-live-header">
                <span class="ai-live-dot"></span>
                <span>AI is starting…</span>
                <span class="ai-live-meta">${elapsed}</span>
              </div>
            </div>`;
        }
      }

      if (p.status === "done" && (_aiOverviewStartId === null || p.id >= _aiOverviewStartId)) {
        try {
          const data = await _apiFetch("/api/ai/latest");
          const resultTime = data.created_at ? new Date(data.created_at).getTime() : 0;
          // Only accept the result if it's recent AND has actual content
          if (resultTime >= startedAt - 5000 && data.summary) {
            window._lastAISummaryId = data.id;
            data.ai_enabled = true;
            if (content) renderAISummary(content, data);
            const tag = document.getElementById("ai-panel-tag");
            if (tag) { tag.textContent = "AI"; tag.style.opacity = ""; }
            if (msg) {
              msg.textContent = "Analysis complete";
              msg.style.color = "";
              setTimeout(() => msg.classList.remove("visible"), 3000);
            }
            if (btn) { btn.disabled = false; btn.textContent = "◈ Analyze Latest Changes"; }
            return;
          }
        } catch (_) {}
      } else if (p.status === "error") {
        if (msg) { msg.textContent = `Error: ${p.error || "unknown"}`; msg.style.color = "var(--status-danger)"; }
        if (btn) { btn.disabled = false; btn.textContent = "◈ Analyze Latest Changes"; }
        return;
      }
    } catch (_) {}
    _aiOverviewProgressTimer = setTimeout(tick, 500);
  };
  tick();
}

// Also update the AI Settings section provider status chip
async function updateAIProviderStatus() {
  const el = document.getElementById("ai-provider-status");
  if (!el) return;
  try {
    const resp = await fetch("/api/ai/latest");
    if (!resp.ok) return;
    const data = await resp.json();
    if (!data.ai_enabled) {
      el.textContent = "AI disabled — toggle above to enable";
    } else if (data.model) {
      el.textContent = `Provider active · last model: ${data.model}`;
      el.style.color = "var(--status-online)";
    } else {
      el.textContent = "AI enabled — provider not yet verified (run an analysis to test)";
    }
  } catch (_) {}
}


/* ============================================================
   16. DEVICES SECTION
   ============================================================

   Shows all known devices (ever seen), lets the user label
   them, toggle trust, and click a row to see per-device history.

   Two views: List (table) and Map (card grid).
   The map loads only when the user switches to it.
*/

let _currentView   = "list";
let _deviceFilter  = "current";   // "all" | "current"
let _allDevicesCache = [];

function setDeviceView(view) {
  _currentView = view;
  document.getElementById("all-devices-list-view").style.display = view === "list" ? "" : "none";
  document.getElementById("all-devices-map-view").style.display  = view === "map"  ? "" : "none";
  document.getElementById("view-list-btn").classList.toggle("active", view === "list");
  document.getElementById("view-map-btn").classList.toggle("active", view === "map");
  if (view === "map" && _allDevicesCache.length) renderDeviceMap(_allDevicesCache);
}

function setDeviceFilter(filter) {
  _deviceFilter = filter;
  document.getElementById("filter-all-btn").classList.toggle("active", filter === "all");
  document.getElementById("filter-current-btn").classList.toggle("active", filter === "current");
  loadDevicesSection();
}

async function loadDevicesSection() {
  const container = document.getElementById("all-devices-container");
  const badge     = document.getElementById("all-device-count");
  if (!container) return;

  try {
    const url = _deviceFilter === "current" ? "/api/devices/all?current_only=true" : "/api/devices/all";
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`${resp.status}`);
    const devices = await resp.json();
    _allDevicesCache = devices;

    if (badge) badge.textContent = devices.length || "";

    if (!devices.length) {
      renderEmptyState(container, "◉", "No devices yet.", "Run a scan to discover devices.");
      return;
    }

    const rows = devices.map(dev => {
      const nameHtml = dev.label
        ? `<span class="dev-label-strong">${escapeHtml(dev.label)}</span>`
        : escapeHtml(dev.hostname || "—");
      const trustBadge = dev.is_known
        ? `<span class="badge badge--trusted">Trusted</span>`
        : `<span class="badge badge--unknown">Unknown</span>`;
      const ports = dev.open_ports.length
        ? dev.open_ports.map(p => `<span class="port-tag">${p}</span>`).join("")
        : `<span class="text-dim">—</span>`;

      return `
        <tr onclick="openDeviceModal(${dev.id})">
          <td class="col-ip">${escapeHtml(dev.latest_ip || "—")}</td>
          <td>${nameHtml}</td>
          <td class="col-mac">${escapeHtml(dev.mac)}</td>
          <td>${escapeHtml(dev.vendor || "—")}</td>
          <td>${ports}</td>
          <td>${trustBadge}</td>
          <td><span class="dev-scan-count">${dev.scan_count}×</span></td>
          <td class="text-dim" style="font-size:0.8rem">${formatRelativeTime(dev.last_seen)}</td>
        </tr>
      `;
    }).join("");

    container.innerHTML = `
      <div class="table-scroll-wrap">
      <table class="all-devices-table">
        <thead>
          <tr>
            <th>IP</th><th>Name / Label</th><th>MAC</th><th>Vendor</th>
            <th>Ports</th><th>Status</th><th>Seen</th><th>Last Seen</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
      </div>
    `;

    if (_currentView === "map") renderDeviceMap(devices);

  } catch (err) {
    renderEmptyState(container, "◬", "Failed to load devices.", err.message);
    console.error("[netmon] loadDevicesSection:", err);
  }
}

function renderDeviceMap(devices) {
  const container = document.getElementById("device-map-container");
  if (!container) return;

  if (!devices.length) {
    renderEmptyState(container, "◉", "No devices.", "Run a scan to populate the map.");
    return;
  }

  const cards = devices.map(dev => {
    const name   = dev.label || dev.hostname || "Unknown";
    const ports  = dev.open_ports.length ? `${dev.open_ports.length} port${dev.open_ports.length !== 1 ? "s" : ""}` : "no open ports";
    const cls    = dev.is_known ? "card--trusted" : "card--unknown";
    const badge  = dev.is_known
      ? `<span class="badge badge--trusted">Trusted</span>`
      : `<span class="badge badge--unknown">Unknown</span>`;

    return `
      <div class="device-card ${cls}" onclick="openDeviceModal(${dev.id})">
        <div class="dc-ip">${escapeHtml(dev.latest_ip || "—")}</div>
        <div class="dc-name">${escapeHtml(name)}</div>
        <div class="dc-vendor">${escapeHtml(dev.vendor || "Unknown vendor")}</div>
        <div class="dc-meta">${badge}<span class="dev-scan-count">${ports}</span></div>
        <div class="dc-actions" onclick="event.stopPropagation()">
          <button class="dc-investigate-btn" onclick="openDeviceModal(${dev.id})" title="Investigate with AI">⬡ Investigate</button>
        </div>
      </div>
    `;
  }).join("");

  container.innerHTML = cards;
}


/* ============================================================
   17. DEVICE DETAIL MODAL
   ============================================================ */

async function openDeviceModal(deviceId) {
  const modal = document.getElementById("device-modal");
  const body  = document.getElementById("modal-body");
  const title = document.getElementById("modal-title");
  if (!modal) return;

  // Show modal immediately with loading state
  modal.style.display = "flex";
  body.innerHTML = `<div class="empty-state"><div class="empty-text">Loading…</div></div>`;

  try {
    const resp = await fetch(`/api/device/${deviceId}/history`);
    if (!resp.ok) throw new Error(`${resp.status}`);
    const data = await resp.json();
    const dev  = data.device;

    title.textContent = dev.label || dev.hostname || dev.mac || `Device #${dev.id}`;

    const vendor   = dev.vendor || "Unknown vendor";
    const firstSeen = dev.first_seen ? _fmtDateTime(dev.first_seen) : "—";
    const lastSeen  = dev.last_seen  ? _fmtDateTime(dev.last_seen)  : "—";

    const historyRows = data.history.map(h => {
      const scanTime = h.scan_time ? _fmtDateTime(h.scan_time) : "—";
      const ports = (h.open_ports || []).join(", ") || "—";
      return `
        <tr>
          <td>#${h.scan_id}</td>
          <td>${scanTime}</td>
          <td>${escapeHtml(h.ip || "—")}</td>
          <td>${escapeHtml(ports)}</td>
        </tr>
      `;
    }).join("");

    body.innerHTML = `
      <div class="modal-section-title">Edit</div>
      <div class="modal-edit-row">
        <div class="modal-input-group">
          <label class="modal-input-label">Label (friendly name)</label>
          <input class="modal-input" id="modal-label-input"
                 type="text" placeholder="e.g. Dad's laptop"
                 value="${escapeHtml(dev.label || "")}" maxlength="80" />
        </div>
        <button class="modal-trust-toggle ${dev.is_known ? "trusted" : ""}"
                id="modal-trust-btn"
                onclick="toggleModalTrust(${dev.id})"
                title="Click to toggle trust status">
          <span id="modal-trust-icon">${dev.is_known ? "✓" : "?"}</span>
          <span id="modal-trust-label">${dev.is_known ? "Trusted" : "Unknown"}</span>
        </button>
        <button class="btn-primary btn-sm" onclick="saveDeviceEdits(${dev.id})">Save</button>
      </div>
      <span class="settings-save-msg" id="modal-save-msg"></span>

      <div class="modal-device-meta">
        <div class="modal-meta-item">
          <span class="modal-meta-label">MAC Address</span>
          <span class="modal-meta-value">${escapeHtml(dev.mac || "—")}</span>
        </div>
        <div class="modal-meta-item">
          <span class="modal-meta-label">Vendor</span>
          <span class="modal-meta-value">${escapeHtml(vendor)}</span>
        </div>
        <div class="modal-meta-item">
          <span class="modal-meta-label">First Seen</span>
          <span class="modal-meta-value">${escapeHtml(firstSeen)}</span>
        </div>
        <div class="modal-meta-item">
          <span class="modal-meta-label">Last Seen</span>
          <span class="modal-meta-value">${escapeHtml(lastSeen)}</span>
        </div>
      </div>

      <div class="modal-section-title">AI Investigation</div>
      <div class="modal-ai-section">
        <button class="btn-primary btn-sm" id="device-investigate-btn"
                onclick="deviceInvestigate('${escapeHtml(dev.latest_ip || "")}', this, ${dev.id})">
          Investigate with AI
        </button>
        <div class="device-ai-live" id="device-ai-live" style="display:none"></div>
      </div>

      <div class="modal-section-title">Scan History (last ${data.history.length})</div>
      ${data.history.length ? `
        <table class="modal-history-table">
          <thead>
            <tr><th>Scan</th><th>Time</th><th>IP</th><th>Open Ports</th></tr>
          </thead>
          <tbody>${historyRows}</tbody>
        </table>
      ` : `<div class="text-dim" style="font-size:0.85rem">No scan history recorded yet.</div>`}
    `;

    // Store current trust state for toggle
    modal._deviceTrusted = dev.is_known;

  } catch (err) {
    body.innerHTML = `<div class="ai-error"><strong>Failed to load device:</strong> ${escapeHtml(err.message)}</div>`;
    console.error("[netmon] openDeviceModal:", err);
  }
}

function closeDeviceModal(event) {
  // Close only when clicking the overlay background (not the panel itself)
  if (event && event.target !== document.getElementById("device-modal")) return;
  const modal = document.getElementById("device-modal");
  if (modal) modal.style.display = "none";
}

async function saveDeviceEdits(deviceId) {
  const label    = document.getElementById("modal-label-input")?.value || "";
  const trusted  = document.getElementById("device-modal")._deviceTrusted;
  const msgEl    = document.getElementById("modal-save-msg");

  try {
    const resp = await fetch(`/api/device/${deviceId}`, {
      method:  "PATCH",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ label, is_known: trusted }),
    });
    if (!resp.ok) throw new Error(`${resp.status}`);

    if (msgEl) {
      msgEl.textContent = "Saved";
      msgEl.classList.add("visible");
      setTimeout(() => msgEl.classList.remove("visible"), 2000);
    }

    // Refresh device list in background
    loadDevicesSection();

  } catch (err) {
    if (msgEl) {
      msgEl.textContent = `Error: ${err.message}`;
      msgEl.style.color = "var(--status-danger)";
      msgEl.classList.add("visible");
    }
    console.error("[netmon] saveDeviceEdits:", err);
  }
}

function toggleModalTrust(deviceId) {
  const modal  = document.getElementById("device-modal");
  const btn    = document.getElementById("modal-trust-btn");
  const icon   = document.getElementById("modal-trust-icon");
  const label  = document.getElementById("modal-trust-label");
  if (!modal) return;

  modal._deviceTrusted = !modal._deviceTrusted;
  const trusted = modal._deviceTrusted;

  btn.classList.toggle("trusted", trusted);
  if (icon)  icon.textContent  = trusted ? "✓" : "?";
  if (label) label.textContent = trusted ? "Trusted" : "Unknown";
}

// Close modal on Escape key
document.addEventListener("keydown", e => {
  if (e.key === "Escape") {
    const modal = document.getElementById("device-modal");
    if (modal && modal.style.display !== "none") modal.style.display = "none";
  }
});


/* ============================================================
   18. ALERTS SECTION
   ============================================================ */

async function loadAlertsSection() {
  const container  = document.getElementById("alerts-container");
  const badge      = document.getElementById("alert-unread-badge");
  if (!container) return;

  try {
    const resp = await fetch("/api/alerts");
    if (!resp.ok) throw new Error(`${resp.status}`);
    const data = await resp.json();

    // Update unread badge
    if (badge) {
      if (data.unread_count > 0) {
        badge.textContent = data.unread_count;
        badge.style.display = "";
      } else {
        badge.style.display = "none";
      }
    }

    if (!data.alerts || !data.alerts.length) {
      renderEmptyState(container, "◬", "No alerts yet.", "New device detections and anomalies appear here.");
      return;
    }

    const items = data.alerts.map(a => {
      const readCls  = a.read ? "alert--read" : "";
      const typeCls  = a.alert_type === "new_device" ? "alert-item--new_device" : "alert-item--other";
      const typeLabel = a.alert_type.replace(/_/g, " ").toUpperCase();
      const time     = formatRelativeTime(a.created_at);

      return `
        <div class="alert-item ${typeCls} ${readCls}" id="alert-${a.id}">
          <span class="alert-type-badge">${escapeHtml(typeLabel)}</span>
          <span class="alert-message">${escapeHtml(a.message)}</span>
          <span class="alert-time">${time}</span>
          ${!a.read ? `<button class="alert-dismiss" onclick="dismissAlert(${a.id})" title="Mark as read">✓</button>` : `<span></span>`}
        </div>
      `;
    }).join("");

    container.innerHTML = `<div class="alert-list">${items}</div>`;

  } catch (err) {
    renderEmptyState(container, "◬", "Failed to load alerts.", err.message);
    console.error("[netmon] loadAlertsSection:", err);
  }
}

async function dismissAlert(alertId) {
  try {
    const resp = await fetch(`/api/alerts/${alertId}/read`, { method: "POST" });
    if (!resp.ok) return;
    // Fade out the item
    const el = document.getElementById(`alert-${alertId}`);
    if (el) el.classList.add("alert--read");
    // Reload to update unread count
    loadAlertsSection();
  } catch (err) {
    console.error("[netmon] dismissAlert:", err);
  }
}

async function markAllAlertsRead() {
  try {
    const resp = await fetch("/api/alerts/read-all", { method: "POST" });
    if (!resp.ok) return;
    loadAlertsSection();
  } catch (err) {
    console.error("[netmon] markAllAlertsRead:", err);
  }
}


/* ============================================================
   19. TRAFFIC CAPTURE
   ============================================================ */

let _trafficProtoChart = null;
let _trafficPollTimer  = null;

async function loadTrafficSection() {
  await Promise.all([
    _loadTrafficInterfaces(),
    _loadTrafficStatus(),
    _loadTrafficSummary(),
    _loadMitmStatus(),
    _loadTrafficAi(),
    refreshDnsLive(),
  ]);
}

async function _loadTrafficInterfaces() {
  try {
    const [data, settings] = await Promise.all([
      _apiFetch("/api/traffic/interfaces"),
      _apiFetch("/api/settings").catch(() => ({})),
    ]);
    const sel  = document.getElementById("traffic-interface-select");
    const warn = document.getElementById("traffic-dep-warning");
    if (!sel) return;

    if (!data.available) {
      sel.innerHTML = '<option value="">No interfaces found</option>';
      if (warn) {
        warn.style.display = "";
        warn.innerHTML =
          `<span class="traffic-dep-icon" aria-hidden="true">⚠</span>
           <span>${escapeHtml(data.error || "dumpcap/tshark not found.")}
           ${data.install_hint
             ? `<br><em>${escapeHtml(data.install_hint)}</em>`
             : ""}
           </span>`;
      }
      return;
    }

    if (warn) warn.style.display = "none";

    // Priority for pre-selection:
    //   1. Currently selected DOM value (user already chose something this session)
    //   2. Saved capture_interface setting from the database
    //   3. First interface whose description contains "wi-fi" or "wireless"
    //   4. First interface in the list
    const current   = sel.value;
    const saved     = (settings.capture_interface || "").trim();
    const wifiIface = data.interfaces.find(i =>
      /wi.?fi|wireless/i.test(i.description || i.display || "")
    );
    const preferred = current || saved || (wifiIface && wifiIface.name) || "";

    sel.innerHTML = data.interfaces.map(iface =>
      `<option value="${escapeHtml(iface.name)}"
        ${iface.name === preferred ? "selected" : ""}>
        ${escapeHtml(iface.display || iface.name)}
       </option>`
    ).join("");
  } catch (err) {
    console.error("[netmon] _loadTrafficInterfaces:", err);
  }
}

async function _loadTrafficStatus() {
  try {
    const st    = await _apiFetch("/api/traffic/status");
    const tag   = document.getElementById("traffic-status-tag");
    const startBtn = document.getElementById("traffic-start-btn");
    const stopBtn  = document.getElementById("traffic-stop-btn");

    if (st.running) {
      if (tag) { tag.textContent = "CAPTURING"; tag.className = "panel-tag tag--ok"; }
      if (startBtn) startBtn.style.display = "none";
      if (stopBtn)  stopBtn.style.display  = "";
      // Poll status while running — every 5 s so updates feel live
      if (!_trafficPollTimer) {
        _trafficPollTimer = setInterval(() => {
          _loadTrafficStatus();
          _loadTrafficSummary();
        }, 5_000);
      }
    } else {
      if (tag) { tag.textContent = "IDLE"; tag.className = "panel-tag"; }
      if (startBtn) startBtn.style.display = "";
      if (stopBtn)  stopBtn.style.display  = "none";
      if (_trafficPollTimer) {
        clearInterval(_trafficPollTimer);
        _trafficPollTimer = null;
      }
    }

    if (st.error) {
      const msg = document.getElementById("traffic-ctrl-msg");
      if (msg) msg.textContent = st.error;
    }
  } catch (err) {
    console.error("[netmon] _loadTrafficStatus:", err);
  }
}

async function _loadTrafficSummary() {
  try {
    const d = await _apiFetch("/api/traffic/summary");
    _renderTrafficStats(d);
    _renderTopTalkers(d.top_talkers     || []);
    _renderTopDests  (d.top_destinations || []);
    _renderProtocolMix(d.protocol_mix   || {});
  } catch (err) {
    console.error("[netmon] _loadTrafficSummary:", err);
  }
}

function _renderTrafficStats(d) {
  const ageEl   = document.getElementById("traffic-analysis-age");
  const content = document.getElementById("traffic-stats-content");

  if (d.id === null && !d.error) {
    if (content) content.innerHTML =
      `<div class="empty-state"><div class="empty-icon" aria-hidden="true">⟋</div>
       <div class="empty-text">No analysis data yet.</div>
       <div class="empty-hint">Start capture — summaries run every minute.</div></div>`;
    return;
  }

  if (ageEl && d.created_at) {
    const age = _relativeTime(new Date(d.created_at));
    ageEl.textContent = age;
  }

  const mb = d.total_bytes ? (d.total_bytes / 1_048_576).toFixed(1) : "0";
  const errorNote = d.error
    ? `<div class="traffic-error">${escapeHtml(d.error)}</div>`
    : "";

  if (content) content.innerHTML = `
    ${errorNote}
    <div class="traffic-kpi-row">
      <div class="traffic-kpi">
        <span class="traffic-kpi-val">${(d.total_packets || 0).toLocaleString()}</span>
        <span class="traffic-kpi-label">packets</span>
      </div>
      <div class="traffic-kpi">
        <span class="traffic-kpi-val">${mb}</span>
        <span class="traffic-kpi-label">MB captured</span>
      </div>
      <div class="traffic-kpi">
        <span class="traffic-kpi-val">${(d.dns_count || 0).toLocaleString()}</span>
        <span class="traffic-kpi-label">DNS queries</span>
      </div>
      <div class="traffic-kpi">
        <span class="traffic-kpi-val">${d.files_analyzed || 0}</span>
        <span class="traffic-kpi-label">files analyzed</span>
      </div>
    </div>
  `;
}

function _renderTopTalkers(rows) {
  const el = document.getElementById("traffic-talkers-content");
  if (!el) return;
  if (!rows.length) {
    el.innerHTML = `<div class="empty-state small-empty"><div class="empty-text">No data yet.</div></div>`;
    return;
  }
  el.innerHTML = _trafficHostTable(rows);
}

function _renderTopDests(rows) {
  const el = document.getElementById("traffic-dests-content");
  if (!el) return;
  if (!rows.length) {
    el.innerHTML = `<div class="empty-state small-empty"><div class="empty-text">No data yet.</div></div>`;
    return;
  }
  el.innerHTML = _trafficHostTable(rows);
}

function _trafficHostTable(rows) {
  const maxBytes = rows[0]?.bytes || 1;
  const trs = rows.map(r => {
    const pct = Math.round((r.bytes / maxBytes) * 100);
    return `<tr>
      <td class="tt-ip">${escapeHtml(r.ip)}</td>
      <td class="tt-bar"><div class="tt-bar-inner" style="width:${pct}%"></div></td>
      <td class="tt-mb">${r.mb} MB</td>
      <td class="tt-pkts">${r.packets.toLocaleString()} pkts</td>
    </tr>`;
  }).join("");
  return `<table class="traffic-host-table">
    <thead><tr>
      <th>IP</th><th>Traffic</th><th>Size</th><th>Packets</th>
    </tr></thead>
    <tbody>${trs}</tbody>
  </table>`;
}

function _renderProtocolMix(mix) {
  const el = document.getElementById("traffic-proto-chart");
  if (!el) return;

  const entries = Object.entries(mix)
    .filter(([, n]) => n > 0)
    .sort(([, a], [, b]) => b - a);

  if (!entries.length) {
    el.innerHTML = `<div class="empty-state small-empty"><div class="empty-text">No protocol data yet.</div></div>`;
    return;
  }

  if (el.getBoundingClientRect().width === 0) return;

  if (!_trafficProtoChart) {
    _trafficProtoChart = echarts.init(el, "dark");
  }
  const labels = entries.map(([p]) => p);
  const values = entries.map(([, n]) => n);

  _trafficProtoChart.setOption({
    backgroundColor: "transparent",
    tooltip: { trigger: "axis" },
    xAxis: {
      type:       "category",
      data:       labels,
      axisLabel:  { color: "#8899aa", fontSize: 11 },
      axisLine:   { lineStyle: { color: "#2a3a4a" } },
    },
    yAxis: {
      type:       "value",
      name:       "packets",
      nameTextStyle: { color: "#8899aa", fontSize: 10 },
      axisLabel:  { color: "#8899aa", fontSize: 10 },
      splitLine:  { lineStyle: { color: "#1a2a3a" } },
    },
    series: [{
      type:      "bar",
      data:      values,
      itemStyle: { color: "#00d4ff", borderRadius: [2, 2, 0, 0] },
      barMaxWidth: 60,
    }],
    grid: { top: 30, right: 20, bottom: 40, left: 60 },
  });
}

function _relativeTime(date) {
  const secs = Math.round((Date.now() - date.getTime()) / 1000);
  if (secs <  60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.round(secs/60)}m ago`;
  return `${Math.round(secs/3600)}h ago`;
}

async function startCapture() {
  const sel   = document.getElementById("traffic-interface-select");
  const sizeEl = document.getElementById("traffic-file-size");
  const cntEl  = document.getElementById("traffic-file-count");
  const msg    = document.getElementById("traffic-ctrl-msg");

  const iface = sel?.value?.trim();
  if (!iface) {
    if (msg) msg.textContent = "Select an interface first.";
    return;
  }

  if (msg) msg.textContent = "Starting…";
  try {
    const result = await _apiFetch("/api/traffic/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        interface:    iface,
        file_size_mb: parseInt(sizeEl?.value || "10"),
        file_count:   parseInt(cntEl?.value  || "5"),
      }),
    });
    if (msg) msg.textContent = result.status === "started"
      ? `Capture started (session #${result.session_id})`
      : result.status;
    await _loadTrafficStatus();
  } catch (err) {
    if (msg) msg.textContent = `Error: ${err.message || err}`;
    console.error("[netmon] startCapture:", err);
  }
}

async function _loadMitmStatus() {
  try {
    const st = await _apiFetch("/api/traffic/mitm/status");
    const tag      = document.getElementById("mitm-status-tag");
    const startBtn = document.getElementById("mitm-start-btn");
    const stopBtn  = document.getElementById("mitm-stop-btn");
    const msg      = document.getElementById("mitm-msg");

    if (st.running) {
      const tagClass = st.active_count > 0 ? "panel-tag tag--ok" : "panel-tag tag--warn";
      if (tag) { tag.textContent = `ON — ${st.active_count} DEVICES`; tag.className = tagClass; }
      if (startBtn) startBtn.style.display = "none";
      if (stopBtn)  stopBtn.style.display  = "";
      if (msg && !st.error) {
        if (st.active_count === 0) {
          msg.textContent = "Resolving device MACs… if this persists, check the server console or open /api/traffic/mitm/diagnose";
        } else {
          msg.textContent = `Routing traffic from ${st.active_count} of ${st.target_count} devices through this machine.`;
        }
      }
    } else {
      if (tag) { tag.textContent = "OFF"; tag.className = "panel-tag"; }
      if (startBtn) startBtn.style.display = "";
      if (stopBtn)  stopBtn.style.display  = "none";
    }
    if (st.error && msg) msg.textContent = `Error: ${st.error}`;
  } catch (err) {
    console.error("[netmon] _loadMitmStatus:", err);
  }
}

async function startMitm() {
  const sel = document.getElementById("traffic-interface-select");
  const msg = document.getElementById("mitm-msg");
  const iface = sel?.value?.trim();

  if (!iface) {
    if (msg) msg.textContent = "Select a capture interface first.";
    return;
  }
  if (msg) msg.textContent = "Starting — resolving MACs for all devices…";

  try {
    const result = await _apiFetch("/api/traffic/mitm/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ interface: iface }),
    });
    if (msg) msg.textContent = `Active — poisoning ${result.target_count} devices via ${result.gateway_ip}`;
    await _loadMitmStatus();
  } catch (err) {
    if (msg) msg.textContent = `Failed: ${err.message || err}`;
    console.error("[netmon] startMitm:", err);
  }
}

async function stopMitm() {
  const msg = document.getElementById("mitm-msg");
  if (msg) msg.textContent = "Stopping — restoring ARP tables…";
  try {
    await _apiFetch("/api/traffic/mitm/stop", { method: "POST" });
    if (msg) msg.textContent = "Disabled. ARP tables restored on all devices.";
    await _loadMitmStatus();
  } catch (err) {
    if (msg) msg.textContent = `Error: ${err.message || err}`;
    console.error("[netmon] stopMitm:", err);
  }
}

async function stopCapture() {
  const msg = document.getElementById("traffic-ctrl-msg");
  if (msg) msg.textContent = "Stopping…";
  try {
    const result = await _apiFetch("/api/traffic/stop", { method: "POST" });
    if (msg) msg.textContent = `Capture stopped (session #${result.session_id || "?"})`;
    await _loadTrafficStatus();

    if (result.ai_analysis === "started") {
      // Scroll the AI panel into view and show live streaming analysis
      const aiPanel = document.getElementById("traffic-ai-panel");
      if (aiPanel) aiPanel.scrollIntoView({ behavior: "smooth", block: "start" });
      _setTrafficAiStatus("analyzing");
      _showTrafficAiLive("AI is analyzing your captured packets…");
      _startAiProgressStream(Date.now(), "traffic");
    } else if (result.ai_analysis === "disabled") {
      if (msg) msg.textContent += " — Enable AI in Settings to auto-analyze captured packets.";
    }
  } catch (err) {
    if (msg) msg.textContent = `Error: ${err.message || err}`;
    console.error("[netmon] stopCapture:", err);
  }
}

async function analyzeTraffic() {
  const btn = document.getElementById("traffic-ai-btn");
  if (btn) btn.disabled = true;
  _setTrafficAiStatus("analyzing");
  _showTrafficAiLive("");   // clear any old live preview
  try {
    // Hit the focused traffic-only endpoint (smaller prompt → faster)
    const result = await _apiFetch("/api/ai/analyze/traffic", { method: "POST" });
    if (result.status === "disabled") {
      _setTrafficAiStatus("disabled");
      _showTrafficAiError("AI is disabled in Settings.");
    } else {
      _startAiProgressStream(Date.now(), "traffic");
    }
  } catch (err) {
    _setTrafficAiStatus("error");
    _showTrafficAiError(`Failed to start analysis: ${err.message || err}`);
    if (btn) btn.disabled = false;
  }
}

// ─── Live progress streaming ──────────────────────────────────────────────────
//
// We poll /api/ai/progress every 500ms while AI is generating, so the user
// sees the response forming character-by-character. When status flips to
// "done", we fetch /api/ai/latest for the parsed result and render it.

let _aiProgressTimer = null;
let _aiProgressStartId = null;

function _startAiProgressStream(startedAt, kind) {
  if (_aiProgressTimer) clearTimeout(_aiProgressTimer);
  _aiProgressStartId = null;

  const tick = async () => {
    try {
      const p = await _apiFetch("/api/ai/progress", { timeoutMs: 5000 });

      // Track the run id of THIS analysis. The first running snapshot we see
      // is ours; we ignore any future runs that happen mid-poll.
      if (_aiProgressStartId === null && p.status === "running") {
        _aiProgressStartId = p.id;
      }

      // Update the live preview area whenever running
      if (p.status === "running") {
        _showTrafficAiLive(p.partial || "", p.elapsed_s, p.chars);
      }

      if (p.status === "done" && (_aiProgressStartId === null || p.id >= _aiProgressStartId)) {
        // Final result — fetch the parsed row from /api/ai/latest
        try {
          const data = await _apiFetch("/api/ai/latest");
          const resultTime = data.created_at ? new Date(data.created_at).getTime() : 0;
          // Only accept if recent AND has actual content (guards against truncated null rows)
          if (resultTime >= startedAt - 5000 && data.summary) {
            _renderTrafficAi(data);
            _setTrafficAiStatus(data.error ? "error" : "ok");
            const btn = document.getElementById("traffic-ai-btn");
            if (btn) btn.disabled = false;
            return;  // stop polling
          }
        } catch (e) {
          console.error("[netmon] fetch latest after done:", e);
        }
        // If /latest hasn't caught up yet, keep polling
      } else if (p.status === "error") {
        _setTrafficAiStatus("error");
        _showTrafficAiError(p.error || "Unknown error");
        const btn = document.getElementById("traffic-ai-btn");
        if (btn) btn.disabled = false;
        return;
      }
    } catch (err) {
      console.error("[netmon] _startAiProgressStream:", err);
    }
    _aiProgressTimer = setTimeout(tick, 500);
  };
  tick();
}

function _showTrafficAiLive(partial, elapsedS, chars) {
  const body = document.getElementById("traffic-ai-body");
  if (!body) return;
  const elapsed   = (elapsedS != null) ? `${elapsedS.toFixed(1)}s` : "—";
  const charCount = chars != null ? chars : (partial || "").length;
  const label     = charCount > 0 ? "AI is responding…" : "AI is starting…";
  const tail = (partial || "").slice(-600);
  body.innerHTML = `
    <div class="traffic-ai-live">
      <div class="ai-live-header">
        <span class="ai-live-dot"></span>
        <span>${label}</span>
        <span class="ai-live-meta">${charCount > 0 ? charCount + " chars · " : ""}${elapsed}</span>
      </div>
      ${tail ? `<pre class="ai-live-stream">${escapeHtml(tail)}</pre>` : ""}
    </div>`;
}

function _setTrafficAiStatus(state) {
  const tag = document.getElementById("traffic-ai-tag");
  const btn = document.getElementById("traffic-ai-btn");
  if (!tag) return;
  const map = {
    "analyzing": ["Analyzing…", "panel-tag tag--warn"],
    "ok":        ["Done",       "panel-tag tag--ok"],
    "error":     ["Error",      "panel-tag tag--bad"],
    "disabled":  ["Disabled",   "panel-tag"],
  };
  const [text, cls] = map[state] || ["—", "panel-tag"];
  tag.textContent = text;
  tag.className = cls;
  if (btn && state === "analyzing") btn.disabled = true;
  if (btn && state !== "analyzing") btn.disabled = false;
}

function _showTrafficAiError(msg) {
  const body = document.getElementById("traffic-ai-body");
  if (body) body.innerHTML = `<p class="traffic-ai-empty" style="color:var(--accent-crit)">${escapeHtml(msg)}</p>`;
}

/**
 * Post-process AI text: make IPs clickable (opens device detail)
 * and domains clickable (external lookup).
 * Input is ALREADY escaped HTML — we only inject safe anchor tags.
 */
function _linkify(escapedText) {
  // Single-pass tokeniser: scan the text once, find IPs OR domains, emit
  // either plain text or an anchor. This avoids nesting a second regex into
  // the attributes of anchors emitted by the first pass (which used to
  // mangle strings like "event.preventDefault" inside onclick handlers).
  const re = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b|\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b/gi;
  let out = "";
  let lastIndex = 0;
  let m;
  while ((m = re.exec(escapedText)) !== null) {
    out += escapedText.slice(lastIndex, m.index);
    if (m[1]) {
      // IP — no inline onclick; use data attribute so no identifier-shaped
      // text ends up inside an HTML attribute where the domain regex could hit it.
      out += `<span class="ai-link ai-link--ip" data-ip="${m[1]}" role="button" tabindex="0">${m[1]}</span>`;
    } else {
      const d = m[2];
      out += `<a class="ai-link ai-link--domain" href="https://www.virustotal.com/gui/domain/${encodeURIComponent(d)}" target="_blank" rel="noopener">${d}</a>`;
    }
    lastIndex = re.lastIndex;
  }
  out += escapedText.slice(lastIndex);
  return out;
}

// Delegated click handler for IP links rendered by _linkify (installed once).
if (!window._ipLinkHandlerInstalled) {
  document.addEventListener("click", (e) => {
    const el = e.target && e.target.closest && e.target.closest(".ai-link--ip");
    if (!el) return;
    e.preventDefault();
    const ip = el.getAttribute("data-ip");
    if (ip) _openDeviceByIp(ip);
  });
  window._ipLinkHandlerInstalled = true;
}

async function _openDeviceByIp(ip) {
  // Switch to Devices section and open the device that has this IP.
  // /api/devices/all returns a raw array; IP field is `latest_ip`.
  try {
    const devices = await _apiFetch("/api/devices/all");
    const list = Array.isArray(devices) ? devices : [];
    const dev = list.find(d => d.latest_ip === ip || d.ip === ip);
    switchSection("devices");
    if (dev && dev.id != null) {
      setTimeout(() => openDeviceModal(dev.id), 300);
    }
  } catch (_) {
    switchSection("devices");
  }
}

function _renderTrafficAi(data) {
  const body = document.getElementById("traffic-ai-body");
  if (!body) return;

  if (data.error && !data.summary) {
    _setTrafficAiStatus("error");
    _showTrafficAiError(data.error);
    return;
  }

  const sevClass = { low: "tag--ok", medium: "tag--warn", high: "tag--bad" }[data.severity] || "";
  _setTrafficAiStatus("ok");

  const listHtml = (items, cls, investigate = false) =>
    items && items.length
      ? `<ul class="ai-list ai-list--${cls}">${items.map(i => {
          if (!investigate) return `<li>${_linkify(escapeHtml(i))}</li>`;
          const _m = i.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
          const _it = _m ? _m[1] : i;
          return `<li class="ai-concern-item" data-item="${escapeHtml(_it)}">
                 <span class="ai-concern-text">${_linkify(escapeHtml(i))}</span>
                 <button class="btn-investigate" data-item="${escapeHtml(_it)}" data-ctx="traffic" title="Ask AI to investigate this">→ Investigate</button>
               </li>`;
        }).join("")}</ul>`
      : "";

  body.innerHTML = `
    <div class="traffic-ai-result">
      <div class="ai-summary-row">
        <span class="panel-tag ${sevClass}" style="text-transform:uppercase">${escapeHtml(data.severity || "low")}</span>
        <p class="ai-summary-text">${_linkify(escapeHtml(data.summary || ""))}</p>
      </div>
      ${data.concerning?.length  ? `<div class="ai-section"><span class="ai-section-label">Concerning</span>${listHtml(data.concerning, "bad", true)}</div>` : ""}
      ${data.benign?.length      ? `<div class="ai-section"><span class="ai-section-label">Looks Normal</span>${listHtml(data.benign, "ok")}</div>` : ""}
      ${data.next_steps?.length  ? `<div class="ai-section"><span class="ai-section-label">Next Steps</span>${listHtml(data.next_steps, "steps")}</div>` : ""}
      <p class="ai-meta">Model: ${escapeHtml(data.model || "—")} · ${data.created_at ? _fmtDateTime(data.created_at) : ""}</p>
    </div>`;
}

async function _loadTrafficAi() {
  try {
    const data = await _apiFetch("/api/ai/latest");
    if (data && (data.summary || data.error)) {
      _renderTrafficAi(data);
    }
  } catch (_) {}
}

// ── AI Investigate (agentic loop) ─────────────────────────────────────────────
//
// Step 1: "→ Investigate" button gathers real network data (tshark, device DB)
//         then asks qwen to analyse evidence and propose specific resolutions.
// Step 2: User sees findings + proposed resolutions with Accept / Skip buttons.
// Step 3: Clicking Accept calls /api/ai/resolve to execute the action.
//         A Revert button then appears so the change can be undone.

document.addEventListener("click", async (e) => {
  // ── Investigate button ──────────────────────────────────────────────────────
  const invBtn = e.target.closest(".btn-investigate");
  if (invBtn && !invBtn.disabled) {
    const item = invBtn.dataset.item || "";
    const ctx  = invBtn.dataset.ctx  || "analysis";
    if (!item) return;

    invBtn.disabled = true;
    invBtn.textContent = "…";

    const li = invBtn.closest("li.ai-concern-item");
    let resultEl = li?.querySelector(".ai-investigate-result");
    if (!resultEl && li) {
      resultEl = document.createElement("div");
      resultEl.className = "ai-investigate-result";
      li.appendChild(resultEl);
    }
    // Live progress display — polls /api/ai/progress every 500ms while the
    // investigate request is in flight so the user can see what's happening
    if (resultEl) resultEl.innerHTML = `
      <div class="inv-progress-wrap">
        <div class="inv-progress-header">
          <span class="ai-live-dot"></span>
          <span class="inv-progress-phase">Gathering evidence…</span>
          <span class="inv-progress-meta"></span>
        </div>
        <pre class="inv-progress-steps"></pre>
      </div>`;

    let _invPollTimer = null;
    let _invPollStartId = null;
    const _phaseEl = resultEl?.querySelector(".inv-progress-phase");
    const _metaEl  = resultEl?.querySelector(".inv-progress-meta");
    const _stepsEl = resultEl?.querySelector(".inv-progress-steps");

    if (resultEl) {
      _invPollTimer = setInterval(async () => {
        try {
          const p = await _apiFetch("/api/ai/progress", { timeoutMs: 3000 });
          if (p.kind !== "investigate") return;  // ignore unrelated scan analysis
          if (_invPollStartId === null && p.status === "running") _invPollStartId = p.id;
          if (p.status !== "running" || !p.partial) return;

          // Detect phase: evidence step messages vs raw AI JSON tokens
          const partial  = p.partial || "";
          const isAiPhase = partial.includes('"verdict"') || partial.startsWith('{"') || partial.startsWith('{\n');
          const elapsed  = p.elapsed_s != null ? `${p.elapsed_s.toFixed(0)}s` : "";

          if (isAiPhase) {
            if (_phaseEl) _phaseEl.textContent = "AI is analyzing…";
            if (_metaEl)  _metaEl.textContent  = `${p.chars || 0} chars · ${elapsed}`;
            // Show the last ~500 chars of the streaming JSON
            if (_stepsEl) _stepsEl.textContent = partial.slice(-500);
          } else {
            if (_phaseEl) _phaseEl.textContent = "Gathering evidence…";
            if (_metaEl)  _metaEl.textContent  = elapsed;
            // Show the last 10 non-empty lines of the step log
            if (_stepsEl) {
              const lines = partial.split("\n").filter(l => l.trim()).slice(-10);
              _stepsEl.textContent = lines.join("\n");
            }
          }
        } catch (_) {}
      }, 500);
    }

    try {
      const data = await _apiFetch("/api/ai/investigate", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ item, context: ctx }),
      });

      clearInterval(_invPollTimer);

      if (data.error && !data.verdict) {
        if (resultEl) resultEl.innerHTML = `<span class="inv-error">Error: ${escapeHtml(data.error)}</span>`;
        invBtn.disabled = false;
        invBtn.textContent = "→ Investigate";
        return;
      }

      _renderInvestigateResult(resultEl, data, item, ctx);
      invBtn.textContent = "✓ Done";
    } catch (err) {
      clearInterval(_invPollTimer);
      if (resultEl) resultEl.innerHTML = `<span class="inv-error">Failed: ${escapeHtml(err.message)}</span>`;
      invBtn.disabled = false;
      invBtn.textContent = "→ Investigate";
    }
    return;
  }

  // ── Accept resolution button ────────────────────────────────────────────────
  const acceptBtn = e.target.closest(".btn-inv-accept");
  if (acceptBtn && !acceptBtn.disabled) {
    const actionType = acceptBtn.dataset.actionType || "";
    const paramsRaw  = acceptBtn.dataset.params || "{}";
    const resCard    = acceptBtn.closest(".inv-resolution");
    if (!resCard) return;

    acceptBtn.disabled = true;
    acceptBtn.textContent = "Executing…";

    let params = {};
    try { params = JSON.parse(paramsRaw); } catch (_) {}

    // Pre-flight: for label_device, extract label from description if params.label is missing
    if (actionType === "label_device" && !params.label) {
      const descEl = resCard.querySelector(".inv-res-desc");
      const descText = descEl ? descEl.textContent.trim() : "";
      // Match: "Label as 'Wyze Smart Bulb'" or "Label as Wyze Smart Bulb"
      const m = descText.match(/label\s+(?:device\s+)?as\s+['"']?([^'"]+)['"']?/i);
      if (m && m[1]) params.label = m[1].replace(/['"]/g, "").trim();
    }

    // Pre-flight validation before hitting the server
    const needsIp    = ["label_device","mark_trusted","mark_untrusted","block_device","block_ip_firewall"].includes(actionType);
    const ipOk       = !!(params.ip && /^\d{1,3}(\.\d{1,3}){3}$/.test(String(params.ip).trim()));
    const labelOk    = actionType !== "label_device" || !!(params.label && String(params.label).trim());
    const preflightOk = (!needsIp || ipOk) && labelOk;
    if (!preflightOk) {
      const statusEl = resCard.querySelector(".inv-res-status");
      let reason = "Can't run: ";
      if (needsIp && !ipOk) reason += "action needs a single device IP (not available for service/domain items).";
      else if (!labelOk)    reason += "AI didn't produce a device label — skip this action and re-investigate with more context.";
      if (statusEl) statusEl.textContent = reason;
      acceptBtn.disabled = false;
      acceptBtn.textContent = "Accept";
      return;
    }

    try {
      const result = await _apiFetch("/api/ai/resolve", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ action_type: actionType, params }),
      });

      const statusEl = resCard.querySelector(".inv-res-status");
      if (statusEl) statusEl.textContent = result.description || "Done.";
      acceptBtn.textContent = "✓ Executed";

      // Show revert button if action is reversible
      if (result.revert && result.revert.action_type !== "no_action") {
        const revertBtn = document.createElement("button");
        revertBtn.className = "btn-inv-revert";
        revertBtn.dataset.actionType = result.revert.action_type;
        revertBtn.dataset.params     = JSON.stringify(result.revert.params || {});
        revertBtn.textContent = "↩ Revert";
        resCard.appendChild(revertBtn);
      }
    } catch (err) {
      acceptBtn.disabled = false;
      acceptBtn.textContent = "Accept";
      const statusEl = resCard.querySelector(".inv-res-status");
      // Surface the actual backend detail message if available
      const raw = err.message || "Unknown error";
      const jsonStart = raw.indexOf("{");
      let detail = raw;
      if (jsonStart !== -1) {
        try { detail = JSON.parse(raw.slice(jsonStart))?.detail || raw; } catch (_) {}
      }
      if (statusEl) statusEl.textContent = `Error: ${detail}`;
    }
    return;
  }

  // ── Revert button ───────────────────────────────────────────────────────────
  const revertBtn = e.target.closest(".btn-inv-revert");
  if (revertBtn && !revertBtn.disabled) {
    const actionType = revertBtn.dataset.actionType || "";
    const paramsRaw  = revertBtn.dataset.params || "{}";
    revertBtn.disabled = true;
    revertBtn.textContent = "Reverting…";

    let params = {};
    try { params = JSON.parse(paramsRaw); } catch (_) {}

    try {
      const result = await _apiFetch("/api/ai/resolve", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ action_type: actionType, params }),
      });
      revertBtn.textContent = "↩ Reverted";
    } catch (err) {
      revertBtn.disabled = false;
      revertBtn.textContent = "↩ Revert";
    }
    return;
  }

  // ── Skip resolution button ──────────────────────────────────────────────────
  const skipBtn = e.target.closest(".btn-inv-skip");
  if (skipBtn) {
    const resCard = skipBtn.closest(".inv-resolution");
    if (resCard) resCard.style.opacity = "0.4";
    skipBtn.textContent = "Skipped";
    skipBtn.disabled = true;
  }

  // ── Follow-up "Ask Qwen" button ─────────────────────────────────────────────
  const followupBtn = e.target.closest(".btn-inv-followup-send");
  if (followupBtn && !followupBtn.disabled) {
    const resultEl = followupBtn.closest(".ai-investigate-result");
    if (!resultEl) return;
    const textarea = resultEl.querySelector(".inv-followup-input");
    const note = (textarea?.value || "").trim();
    if (!note) { textarea?.focus(); return; }

    const item = resultEl.dataset.invItem || "";
    const ctx  = resultEl.dataset.invCtx  || "analysis";
    if (!item) return;

    followupBtn.disabled = true;
    followupBtn.textContent = "Thinking…";

    // Keep the existing result visible while we fetch the updated analysis
    const spinner = document.createElement("div");
    spinner.className = "inv-followup-thinking";
    spinner.textContent = "AI is re-analyzing with your context…";
    followupBtn.parentElement?.after(spinner);

    try {
      const data = await _apiFetch("/api/ai/investigate", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ item, context: ctx, user_note: note }),
      });
      _renderInvestigateResult(resultEl, data, item, ctx);
    } catch (err) {
      spinner.textContent = `Error: ${escapeHtml(err.message)}`;
      followupBtn.disabled = false;
      followupBtn.textContent = "Ask AI →";
    }
    return;
  }

  // ── Deep Capture button ─────────────────────────────────────────────────────
  const deepBtn = e.target.closest(".btn-inv-deep-capture");
  if (deepBtn && !deepBtn.disabled) {
    const ip = deepBtn.dataset.ip || "";
    if (!ip) return;
    const resultEl = deepBtn.closest(".ai-investigate-result");
    if (!resultEl) return;
    const item = resultEl.dataset.invItem || ip;
    const ctx  = resultEl.dataset.invCtx  || "analysis";

    deepBtn.disabled = true;

    // Find the capture note element and use it as status display
    const noteEl = resultEl.querySelector(".inv-capture-note");
    const DURATION = 30;
    let remaining = DURATION;

    const tick = () => {
      deepBtn.textContent = `Capturing… ${remaining}s`;
      if (noteEl) noteEl.textContent = `Capturing traffic from ${ip} — ${remaining}s remaining. Stay on this page.`;
      remaining--;
    };
    tick();
    const timer = setInterval(tick, 1000);

    try {
      // Start the capture
      const startRes = await _apiFetch("/api/ai/deep_capture/start", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ ip, duration: DURATION }),
      });
      const captureId = startRes.capture_id;
      if (!captureId) throw new Error(startRes.error || "Failed to start capture");

      // Poll until done
      let pcapPath = "";
      for (let i = 0; i < (DURATION + 25) * 2; i++) {
        await new Promise(r => setTimeout(r, 500));
        const poll = await _apiFetch(`/api/ai/deep_capture/${captureId}`);
        if (poll.status === "done") { pcapPath = poll.pcap_path || ""; break; }
        if (poll.status === "error") throw new Error(poll.error || "Capture failed");
      }

      clearInterval(timer);
      if (!pcapPath) throw new Error("Capture completed but no file returned");

      deepBtn.textContent = "Analyzing capture…";
      if (noteEl) noteEl.textContent = "Capture complete — AI is re-analyzing with fresh data…";

      // Re-investigate with the focused capture file
      const data = await _apiFetch("/api/ai/investigate", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ item, context: ctx, deep_pcap_path: pcapPath }),
      });
      _renderInvestigateResult(resultEl, data, item, ctx);
    } catch (err) {
      clearInterval(timer);
      deepBtn.disabled = false;
      deepBtn.textContent = "⬡ Deep Capture (30s)";
      if (noteEl) noteEl.textContent = `Capture failed: ${err.message}`;
    }
    return;
  }
});


function _renderInvestigateResult(el, data, _item, _ctx) {
  if (!el) return;
  // Store context on the element so follow-up and deep-capture handlers can read it
  const item = _item || data.item || el.dataset.invItem || "";
  const ctx  = _ctx  || data.context || el.dataset.invCtx || "analysis";
  el.dataset.invItem = item;
  el.dataset.invCtx  = ctx;

  const verdictClass = { normal: "inv--normal", noise: "inv--noise", suspicious: "inv--suspicious" }[data.verdict] || "";
  const verdictLabel = { normal: "Normal", noise: "Noise", suspicious: "Suspicious" }[data.verdict] || (data.verdict || "Unknown");
  const impactClass  = { low: "inv-impact--low", medium: "inv-impact--med", high: "inv-impact--high" };

  // ── Auto-executed action banner ────────────────────────────────────────────
  const ae = data.auto_executed;
  let autoHtml = "";
  if (ae && !ae.error && ae.action_type !== "no_action") {
    const revertBtn = ae.revert
      ? `<button class="btn-inv-revert"
                 data-action-type="${escapeHtml(ae.revert.action_type)}"
                 data-params="${escapeHtml(JSON.stringify(ae.revert.params || {}))}">↩ Revert</button>`
      : "";
    autoHtml = `
      <div class="inv-auto-executed">
        <span class="inv-auto-label">✓ Action taken</span>
        <span class="inv-auto-desc">${escapeHtml(ae.result || ae.description || "")}</span>
        ${ae.why_it_helps ? `<span class="inv-auto-why">${escapeHtml(ae.why_it_helps)}</span>` : ""}
        ${revertBtn}
      </div>`;
  } else if (ae && ae.error) {
    const isGuardrail = ae.error.startsWith("auto_execute blocked:");
    autoHtml = `<div class="inv-auto-executed ${isGuardrail ? "inv-auto--blocked" : "inv-auto--error"}">
      <span class="inv-auto-label">${isGuardrail ? "🔒 Action held for review" : "⚠ Auto-action failed"}</span>
      <span class="inv-auto-desc">${escapeHtml(isGuardrail
        ? `AI suggested "${ae.action_type}" — this requires your approval. Review the options below.`
        : ae.error)}</span>
    </div>`;
  }

  // ── Evidence collected (collapsible) ──────────────────────────────────────
  const evidenceItems = data.evidence_items || [];
  const evidenceHtml = evidenceItems.length ? `
    <details class="inv-evidence">
      <summary class="inv-evidence-summary">Evidence collected (${evidenceItems.length} items)</summary>
      <ul class="inv-evidence-list">
        ${evidenceItems.map(e => `<li><pre class="inv-evidence-item">${escapeHtml(e)}</pre></li>`).join("")}
      </ul>
    </details>` : "";

  // ── Devices involved ──────────────────────────────────────────────────────
  const sourcesHtml = (data.sources || []).length
    ? `<div class="inv-sources">
        <span class="inv-sources-label">Device:</span>
        ${data.sources.map(s =>
          `<span class="inv-source-chip">${escapeHtml(s.ip)}${s.label ? ` · ${escapeHtml(s.label)}` : ""}${s.mac ? ` · ${escapeHtml(s.mac)}` : ""}</span>`
        ).join("")}
       </div>`
    : "";

  // ── Proposed resolution cards ─────────────────────────────────────────────
  const resolutionsHtml = (data.proposed_resolutions || []).map((r, i) => {
    const isNoAction = r.action_type === "no_action";
    const impact     = r.impact || "";
    const impBadge   = impact ? `<span class="inv-impact-badge ${impactClass[impact] || ""}">${impact.toUpperCase()}</span>` : "";
    return `
      <div class="inv-resolution" data-res-id="${escapeHtml(r.id || String(i))}">
        <div class="inv-res-header">
          <div class="inv-res-desc">${escapeHtml(r.description || "")}</div>
          ${impBadge}
        </div>
        ${r.why_it_helps      ? `<div class="inv-res-why">Why: ${escapeHtml(r.why_it_helps)}</div>` : ""}
        ${r.what_revert_does  ? `<div class="inv-res-revert">Revert: ${escapeHtml(r.what_revert_does)}</div>` : ""}
        <div class="inv-res-actions">
          ${!isNoAction
            ? (() => {
                // Actions that need a device IP — disable if Qwen didn't supply one
                const needsIp = ["label_device","mark_trusted","mark_untrusted","block_device","block_ip_firewall"].includes(r.action_type);
                const hasIp   = !!(r.params && r.params.ip && /^\d{1,3}(\.\d{1,3}){3}$/.test(r.params.ip));
                const cantRun = needsIp && !hasIp;
                return `<button class="btn-inv-accept${cantRun ? " btn-inv-accept--dim" : ""}"
                           data-action-type="${escapeHtml(r.action_type)}"
                           data-params="${escapeHtml(JSON.stringify(r.params || {}))}"
                           ${cantRun ? 'disabled title="This action needs a device IP — not available for service/domain items"' : ""}>Accept</button>
                         <button class="btn-inv-skip">Skip</button>`;
              })()
            : `<button class="btn-inv-accept btn-inv-accept--dim"
                       data-action-type="no_action" data-params="{}">No further action</button>`
          }
          <span class="inv-res-status"></span>
        </div>
      </div>`;
  }).join("");

  // ── Deep Capture button (only for IPs) ────────────────────────────────────
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(item);
  const deepCaptureBtn = isIp
    ? `<button class="btn-inv-deep-capture" data-ip="${escapeHtml(item)}" title="Capture 30 seconds of live traffic from this device for deeper analysis">
         ⬡ Deep Capture (30s)
       </button>`
    : "";

  el.innerHTML = `
    <div class="inv-result ${verdictClass}">
      <div class="inv-header">
        <span class="inv-badge">${escapeHtml(verdictLabel)}</span>
        ${data.what ? `<span class="inv-what">${escapeHtml(data.what)}</span>` : ""}
        ${deepCaptureBtn}
      </div>
      ${data.findings ? `<p class="inv-findings">${escapeHtml(data.findings)}</p>` : ""}
      ${autoHtml}
      ${sourcesHtml}
      ${evidenceHtml}
      ${resolutionsHtml
        ? `<div class="inv-resolutions">
             <div class="inv-resolutions-label">What would you like to do?</div>
             ${resolutionsHtml}
           </div>`
        : ""}
      <div class="inv-followup">
        <div class="inv-followup-label">Tell the AI more or ask a question</div>
        <div class="inv-followup-row">
          <textarea class="inv-followup-input" rows="2"
            placeholder="e.g. I think this is my Roku TV, or: why is port 8080 open?"></textarea>
          <button class="btn-inv-followup-send">Ask AI →</button>
        </div>
        <div class="inv-capture-note">
          ${isIp ? "Use Deep Capture to watch live traffic from this device (30 s), then the AI re-analyzes with fresh data." : ""}
        </div>
      </div>
    </div>`;
}


/* internal helper: fetch JSON, throw on non-2xx.
   opts.timeoutMs — abort and throw if no response within N ms (default: none) */
async function _apiFetch(url, opts = {}) {
  const { timeoutMs, ...fetchOpts } = opts;
  let controller, tid;
  if (timeoutMs) {
    controller = new AbortController();
    tid = setTimeout(() => controller.abort(), timeoutMs);
    fetchOpts.signal = controller.signal;
  }
  try {
    const resp = await fetch(url, fetchOpts);
    if (!resp.ok) {
      const text = await resp.text().catch(() => resp.statusText);
      throw new Error(`${resp.status} ${text}`);
    }
    return resp.json();
  } finally {
    if (tid) clearTimeout(tid);
  }
}


/* ── Utility: escape HTML to prevent injection in AI text ─────────────────── */
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}


/* ============================================================
   19. ACTIVITY LOGS
   ============================================================

   Displays a paginated, filterable timeline of all automated
   actions, scans, AI verdicts, and firewall changes.
   Refreshes every 30 seconds while the section is visible.
*/

const _LOGS_PAGE = 50;   // entries per page

let _logsState = {
  category:  "",
  search:    "",
  offset:    0,
  total:     0,
  timer:     null,
};

const _LOG_LEVEL_META = {
  info:     { icon: "●", cls: "log-info",     label: "Info"    },
  warning:  { icon: "◆", cls: "log-warning",  label: "Warning" },
  critical: { icon: "▲", cls: "log-critical", label: "Critical"},
  action:   { icon: "✦", cls: "log-action",   label: "Action"  },
  threat:   { icon: "☠", cls: "log-threat",   label: "Threat"  },
};

const _LOG_CAT_LABELS = {
  scan:     "Scan",
  traffic:  "Traffic",
  ai:       "AI",
  firewall: "Firewall",
  threat:   "Threat",
  system:   "System",
  alert:    "Alert",
};

function _logRelTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  const now = Date.now();
  const diff = Math.floor((now - d.getTime()) / 1000);
  if (diff < 60)   return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return `${Math.floor(diff/86400)}d ago`;
}

function _renderLogEntry(e) {
  const meta   = _LOG_LEVEL_META[e.level] || _LOG_LEVEL_META.info;
  const catLbl = _LOG_CAT_LABELS[e.category] || e.category;
  const ts     = _fmtDateTime(e.created_at);
  const rel    = _logRelTime(e.created_at);
  const hasDetail = !!(e.detail);
  const devTag = e.device_ip
    ? `<span class="log-device-tag">${escapeHtml(e.device_ip)}</span>`
    : "";

  return `
    <div class="log-entry log-entry--${meta.cls}" data-log-id="${e.id}">
      <div class="log-entry-main">
        <span class="log-level-dot ${meta.cls}" title="${meta.label}">${meta.icon}</span>
        <span class="log-time" title="${escapeHtml(ts)}">${escapeHtml(rel)}</span>
        <span class="log-cat-badge log-cat-${escapeHtml(e.category)}">${escapeHtml(catLbl)}</span>
        <span class="log-summary">${escapeHtml(e.summary)}</span>
        ${devTag}
        ${hasDetail ? `<button class="log-expand-btn" title="Show detail">›</button>` : ""}
      </div>
      ${hasDetail ? `<div class="log-detail" style="display:none"><pre>${escapeHtml(e.detail)}</pre></div>` : ""}
    </div>`;
}

async function _fetchLogs(append = false) {
  const listEl  = document.getElementById("log-list");
  const moreEl  = document.getElementById("log-load-more");
  const statsEl = document.getElementById("log-stats");
  if (!listEl) return;

  if (!append) {
    listEl.innerHTML = `<div class="log-empty">Loading…</div>`;
  }

  const params = new URLSearchParams({
    limit:  _LOGS_PAGE,
    offset: _logsState.offset,
  });
  if (_logsState.category) params.set("category", _logsState.category);
  if (_logsState.search)   params.set("search",   _logsState.search);

  try {
    const data = await _apiFetch(`/api/logs?${params}`);
    _logsState.total = data.total;

    if (!append) listEl.innerHTML = "";

    if (data.entries.length === 0 && !append) {
      listEl.innerHTML = `<div class="log-empty">No log entries match your filters.</div>`;
    } else {
      listEl.insertAdjacentHTML("beforeend",
        data.entries.map(_renderLogEntry).join(""));
    }

    // Show/hide Load More
    const shown = _logsState.offset + data.entries.length;
    if (shown < data.total) {
      moreEl.style.display = "";
    } else {
      moreEl.style.display = "none";
    }

    const filterDesc = _logsState.category
      ? ` · ${_LOG_CAT_LABELS[_logsState.category] || _logsState.category}`
      : "";
    statsEl.textContent = `${data.total} entries${filterDesc}`;

  } catch (err) {
    if (!append) listEl.innerHTML = `<div class="log-empty log-empty--error">Failed to load logs: ${escapeHtml(err.message)}</div>`;
  }
}

function _renderLogAiResult(data, mode) {
  const el = document.getElementById("log-ai-result");
  if (!el) return;
  el.style.display = "";

  if (data.status === "disabled") {
    el.innerHTML = `<strong>AI disabled.</strong> ${escapeHtml(data.message || "Enable AI in Settings to run synthesis.")}`;
    return;
  }

  if (mode === "noise") {
    const patterns = data.repeated_patterns || [];
    el.innerHTML = `
      <strong>Noise learning complete.</strong>
      <div>${escapeHtml(data.safety || "No network behavior changed.")}</div>
      ${patterns.length ? `<ul>${patterns.slice(0, 6).map(p =>
        `<li>${escapeHtml(p.event)} × ${p.count}: ${escapeHtml(p.summary)}</li>`
      ).join("")}</ul>` : `<div>No repeated DNS patterns met the threshold.</div>`}
    `;
    return;
  }

  const steps = Array.isArray(data.next_steps) ? data.next_steps : [];
  const concerning = Array.isArray(data.concerning) ? data.concerning : [];
  el.innerHTML = `
    <strong>${escapeHtml(data.summary || "History synthesis complete.")}</strong>
    ${concerning.length ? `<div>Common issues:</div><ul>${concerning.map(x => `<li>${escapeHtml(x)}</li>`).join("")}</ul>` : ""}
    ${steps.length ? `<div>Safe suggestions:</div><ul>${steps.map(x => `<li>${escapeHtml(x)}</li>`).join("")}</ul>` : ""}
    ${data.error ? `<div class="log-empty--error">${escapeHtml(data.error)}</div>` : ""}
  `;
}

async function runLogAiSynthesis() {
  const btn = document.getElementById("log-ai-synthesize-btn");
  if (btn) { btn.disabled = true; btn.textContent = "Analyzing..."; }
  try {
    const data = await _apiFetch("/api/ai/history-synthesis", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({
        days: 7,
        question: "What common issues, repeated noise, and safe autonomous suggestions do you see?",
      }),
      timeoutMs: 120000,
    });
    _renderLogAiResult(data, "synthesis");
    _logsState.offset = 0;
    _fetchLogs(false);
  } catch (err) {
    _renderLogAiResult({ summary: "History synthesis failed.", error: err.message }, "synthesis");
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Analyze last 7 days"; }
  }
}

async function runDnsNoiseLearning() {
  const btn = document.getElementById("log-ai-noise-btn");
  if (btn) { btn.disabled = true; btn.textContent = "Learning..."; }
  try {
    const data = await _apiFetch("/api/autonomy/learn-noise", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ category: "dns", days: 7, apply: false }),
    });
    _renderLogAiResult(data, "noise");
    _logsState.offset = 0;
    _fetchLogs(false);
  } catch (err) {
    _renderLogAiResult({ repeated_patterns: [], safety: `Noise learning failed: ${err.message}` }, "noise");
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Learn DNS noise"; }
  }
}

// ── Shield / Security Dashboard ──────────────────────────────────────────────

let _shieldTimer            = null;
let _shieldInvestigating    = false;   // pauses auto-refresh while Qwen result is visible
let _shieldPendingResult    = null;    // { eventId, result } — re-injected after every feed rebuild

const _SHIELD_LEVEL = {
  secure:   { label: "NETWORK SECURE",   sub: "All systems nominal — no active threats detected", cls: "secure" },
  warning:  { label: "ANOMALY DETECTED", sub: "Suspicious activity logged — monitoring closely",  cls: "warning" },
  critical: { label: "THREAT ACTIVE",    sub: "Critical event detected — immediate attention needed", cls: "critical" },
};

const _SHIELD_CAT_ICON = {
  scan:     "◉", traffic: "⟋", ai: "◈", firewall: "⬡",
  threat:   "☠", system:  "◎", alert: "◬", health: "♥",
};

const _LAYER_ORDER = ["auto_scan","health","anomaly","threat_intel","nighttime","traffic","ai","auto_report","notifications"];

async function loadShieldSection() {
  try {
    const data = await _apiFetch("/api/shield");
    _renderShield(data);
  } catch (err) {
    document.getElementById("shield-banner").className = "shield-banner shield-banner--warning";
    document.getElementById("shield-status").textContent = "LOAD ERROR";
    document.getElementById("shield-sub").textContent = err.message;
  }
  loadAutonomousActions();

  if (_shieldTimer) clearInterval(_shieldTimer);
  _shieldTimer = setInterval(async () => {
    const sec = document.getElementById("section-shield");
    if (!sec || sec.style.display === "none") { clearInterval(_shieldTimer); return; }
    if (_shieldInvestigating) return;  // don't rebuild DOM while Qwen is streaming
    try {
      const data = await _apiFetch("/api/shield");
      _renderShield(data);
    } catch (_) {}
  }, 5000);
}

function _renderShield(data) {
  const lvl = _SHIELD_LEVEL[data.threat_level] || _SHIELD_LEVEL.secure;

  // Banner
  const banner = document.getElementById("shield-banner");
  banner.className = `shield-banner shield-banner--${lvl.cls}`;
  document.getElementById("shield-icon").textContent   = data.threat_level === "critical" ? "☠" : data.threat_level === "warning" ? "◬" : "⬡";
  document.getElementById("shield-status").textContent = lvl.label;
  document.getElementById("shield-sub").textContent    = lvl.sub;

  // Stats
  const s = data.stats || {};
  document.getElementById("ss-devices").textContent  = s.devices  ?? "—";
  document.getElementById("ss-uptime").textContent   = s.uptime_pct != null ? s.uptime_pct + "%" : "—";
  document.getElementById("ss-blocks").textContent   = s.dns_blocked_total ?? s.blocks ?? "—";
  document.getElementById("ss-threats").textContent  = s.threats_24h ?? "—";

  // Protection layers
  const layersEl = document.getElementById("shield-layers");
  const layers   = (data.layers || []).sort((a, b) =>
    _LAYER_ORDER.indexOf(a.id) - _LAYER_ORDER.indexOf(b.id)
  );
  layersEl.innerHTML = layers.map(layer => {
    const dot      = layer.enabled ? "shield-dot--on" : "shield-dot--off";
    const status   = layer.enabled ? "ACTIVE" : "OFF";
    const statusCls= layer.enabled ? "shield-layer-status--on" : "shield-layer-status--off";
    const canToggle= !!layer.setting_key;
    const toggleHtml = canToggle
      ? `<label class="shield-toggle" title="${layer.enabled ? "Disable" : "Enable"} ${layer.name}">
           <input type="checkbox" class="shield-toggle-input"
                  data-setting="${escapeHtml(layer.setting_key)}"
                  ${layer.enabled ? "checked" : ""} />
           <span class="shield-toggle-track"><span class="shield-toggle-thumb"></span></span>
         </label>`
      : `<span class="shield-layer-always">ALWAYS ON</span>`;
    const lastEvt = layer.last_event ? `<span class="shield-layer-last">Last: ${_fmtDateTime(layer.last_event)}</span>` : "";
    return `
      <div class="shield-layer ${layer.enabled ? "shield-layer--on" : "shield-layer--off"}">
        <span class="shield-dot ${dot}"></span>
        <div class="shield-layer-info">
          <div class="shield-layer-top">
            <span class="shield-layer-name">${escapeHtml(layer.name)}</span>
            <span class="shield-layer-status ${statusCls}">${status}</span>
          </div>
          <span class="shield-layer-desc">${escapeHtml(layer.description)}</span>
          <div class="shield-layer-meta">
            <span class="shield-layer-stat">${escapeHtml(layer.stat || "")}</span>
            ${lastEvt}
          </div>
        </div>
        ${toggleHtml}
      </div>`;
  }).join("");

  // Wire toggle auto-save
  layersEl.querySelectorAll(".shield-toggle-input").forEach(input => {
    input.addEventListener("change", () => {
      _saveOneSetting(input.dataset.setting, input.checked ? "true" : "false");
      showToast(`${input.checked ? "Enabled" : "Disabled"} — takes effect on next cycle`, "info", 3000);
    });
  });

  // Event feed — tabbed by category
  const feedEl    = document.getElementById("shield-feed");
  const events    = data.events    || [];
  const dnsEvents = data.dns_events || [];
  const aiEnabled = (data.layers || []).find(l => l.id === "ai")?.enabled;
  const dnsCount  = data.stats?.dns_blocked_total ?? dnsEvents.length;

  // Preserve active tab across refreshes
  const activeTab = feedEl.dataset.activeTab || "threats";

  const _renderFeedTab = (tab) => {
    feedEl.dataset.activeTab = tab;
    let tabEvents, emptyMsg, clearFn, clearLabel;
    if (tab === "dns") {
      tabEvents  = dnsEvents;
      emptyMsg   = "No DNS blocks logged";
      clearFn    = "shieldClearDnsLogs()";
      clearLabel = "Clear DNS Logs";
    } else {
      tabEvents  = events;
      emptyMsg   = "All clear — no active threats or anomalies";
      clearFn    = "shieldDismissAll()";
      clearLabel = "Clear All";
    }

    const badgeDns = dnsCount > 0
      ? `<span class="feed-tab-badge">${dnsCount > 999 ? "999+" : dnsCount}</span>` : "";
    const badgeThreats = events.length > 0
      ? `<span class="feed-tab-badge feed-tab-badge--warn">${events.length}</span>` : "";

    const toolbar = `
      <div class="feed-tabs">
        <button class="feed-tab ${tab === "threats" ? "feed-tab--active" : ""}"
                onclick="_shieldTab('threats')">Threats ${badgeThreats}</button>
        <button class="feed-tab ${tab === "dns" ? "feed-tab--active" : ""}"
                onclick="_shieldTab('dns')">DNS Blocked ${badgeDns}</button>
      </div>
      <div class="shield-feed-toolbar">
        <span class="shield-feed-count">${tabEvents.length} event${tabEvents.length !== 1 ? "s" : ""}</span>
        <button class="shield-clear-btn" onclick="${clearFn}">${clearLabel}</button>
      </div>`;

    if (!tabEvents.length) {
      feedEl.innerHTML = toolbar + `<div class="shield-feed-empty">${emptyMsg}</div>`;
    } else {
      feedEl.innerHTML = toolbar + tabEvents.map(e => _renderShieldEvent(e, aiEnabled)).join("");
    }

    const newest = tabEvents[0]?.created_at;
    document.getElementById("shield-feed-age").textContent = newest ? _fmtDateTime(newest) : "";
  };

  // After the feed HTML is written, re-inject any in-progress investigation result
  // so navigating away and back (or a forced reload) doesn't lose the Qwen answer.
  const _reinjectPending = () => {
    if (!_shieldPendingResult) return;
    const { eventId, result } = _shieldPendingResult;
    const card = document.getElementById(`sev-card-${eventId}`);
    if (!card) return;   // event not in current tab — result stays in memory for next switch
    let liveEl = card.querySelector(".sev-live");
    if (!liveEl) {
      liveEl = document.createElement("div");
      liveEl.className = "sev-live";
      card.querySelector(".sev-actions")?.insertAdjacentElement("beforebegin", liveEl);
    }
    _renderShieldInvestigateResult(liveEl, result);
  };

  window._shieldTab     = (tab) => { _renderFeedTab(tab); _reinjectPending(); };
  window._shieldTabData = { events, dnsEvents, aiEnabled, dnsCount };
  _renderFeedTab(activeTab);
  _reinjectPending();

  // Blocks table
  const blocksEl = document.getElementById("shield-blocks");
  const blocks   = data.blocks || [];
  if (!blocks.length) {
    blocksEl.innerHTML = `<div class="shield-blocks-empty">No active firewall blocks — network is clean</div>`;
  } else {
    blocksEl.innerHTML = `
      <table class="shield-blocks-table">
        <thead><tr>
          <th>IP Address</th><th>Reason</th><th>Direction</th><th></th>
        </tr></thead>
        <tbody>
          ${blocks.map(b => `
            <tr>
              <td class="shield-block-ip">${escapeHtml(b.ip || "—")}</td>
              <td class="shield-block-reason">${escapeHtml(b.reason || "—")}</td>
              <td class="shield-block-dir">${escapeHtml(b.direction || "—")}</td>
              <td><button class="shield-unblock-btn"
                    onclick="shieldUnblock('${escapeHtml(b.ip)}', this)">Unblock</button></td>
            </tr>`).join("")}
        </tbody>
      </table>`;
  }
}

// ── Shield event card renderer ────────────────────────────────────────────────

const _EVT_READABLE = {
  traffic_spike:   "Traffic spike detected",
  port_scan:       "Port scan detected",
  health_outage:   "Network outage",
  nighttime_device:"Unknown device at night",
  threat_intel_hit:"Threat intelligence match",
  auto_block:      "IP auto-blocked",
  remote_block:    "IP blocked remotely",
  device_new:      "New unknown device",
  scan_completed:  "Scan completed",
  firewall_blocked:"Firewall block applied",
  security_report: "Autonomous security report",
};

const _EVT_EXPLAIN = {
  traffic_spike:    "A device suddenly sent or received far more data than its normal baseline. This can indicate malware, an ongoing attack, or an unexpected large transfer.",
  port_scan:        "A device probed many ports or hosts in a short time. This is a classic indicator of network reconnaissance or an attacker mapping your network.",
  health_outage:    "Your internet connection had sustained packet loss or high latency across multiple checks. This can signal a DDoS attack, ISP issue, or router problem.",
  nighttime_device: "An unrecognized device connected to your network during the night hours (22:00–06:00). This is unusual and may warrant investigation.",
  threat_intel_hit: "A destination IP or domain matched a known malicious feed (botnet C2, malware host, phishing site). Traffic to/from this endpoint is suspicious.",
  auto_block:       "NetMon automatically blocked this IP based on confirmed threat evidence. You can review and remove the block below.",
  device_new:       "A device that has never been seen before joined your network.",
};

function _renderShieldEvent(e, aiEnabled) {
  const lvlCls  = { warning: "warn", critical: "crit", threat: "crit", action: "act", info: "info" }[e.level] || "info";
  const lvlLbl  = (e.level || "").toUpperCase();
  const time    = e.created_at ? _fmtDateTime(e.created_at) : "—";
  const title   = _EVT_READABLE[e.event] || e.summary || e.event || "Security event";
  const explain = _EVT_EXPLAIN[e.event] || "";
  const ip      = e.device_ip || (e.detail && e.detail.ip) || "";
  const catIcon = _SHIELD_CAT_ICON[e.category] || "·";

  // Build detail lines from the detail object
  const detailLines = [];
  if (e.detail && typeof e.detail === "object") {
    const d = e.detail;
    if (d.ip && d.ip !== ip)     detailLines.push(`IP: ${d.ip}`);
    if (d.mac)                   detailLines.push(`MAC: ${d.mac}`);
    if (d.hostname)              detailLines.push(`Host: ${d.hostname}`);
    if (d.rule)                  detailLines.push(`Rule: ${d.rule}`);
    if (d.reason)                detailLines.push(`Reason: ${d.reason}`);
    if (d.hits)                  detailLines.push(`Feeds: ${d.hits.map(h => h.feed).join(", ")}`);
    if (d.scan_id)               detailLines.push(`Scan #${d.scan_id} · ${d.hosts ?? "?"} hosts · ${d.new_devices ?? 0} new`);
  }

  // Inline AI verdict (pre-loaded from backend)
  let verdictHtml = "";
  if (e.ai_verdict) {
    const v = e.ai_verdict;
    const vsev = v.severity || "low";
    verdictHtml = `
      <div class="sev-verdict sev-verdict--${vsev}">
        <span class="sev-verdict-label">⬡ AI: ${vsev.toUpperCase()}</span>
        <span class="sev-verdict-text">${escapeHtml(v.summary || "")}</span>
        <span class="sev-verdict-time">${v.created_at ? _fmtDateTime(v.created_at) : ""}</span>
      </div>`;
  }

  // Action buttons
  const _UNBLOCKABLE = new Set(["192.168.1.1", "127.0.0.1", "0.0.0.0", "::1"]);
  const isDnsEvent     = e.category === "dns";
  const dnsTarget      = e.detail?.domain || null;   // domain to investigate for DNS events
  const isInternalOnly = _UNBLOCKABLE.has(ip);
  // DNS events: investigate the blocked DOMAIN (not the router IP)
  // Regular events: investigate the device IP, unless it's a gateway/localhost
  const canInvestigate = aiEnabled && (
    (isDnsEvent && !!dnsTarget) ||
    (!isDnsEvent && !!ip && !isInternalOnly)
  );
  const investigateTarget = isDnsEvent ? dnsTarget : ip;
  const canBlock = ip && !isDnsEvent && !isInternalOnly && e.level !== "action";

  const actionsHtml = `
    <div class="sev-actions">
      ${canInvestigate ? `<button class="sev-btn sev-btn--investigate" onclick="shieldInvestigate('${escapeHtml(investigateTarget)}', ${e.id}, this)">Investigate with AI</button>` : ""}
      ${canBlock       ? `<button class="sev-btn sev-btn--block"       onclick="shieldBlockIp('${escapeHtml(ip)}', this)">Block ${escapeHtml(ip)}</button>` : ""}
      <button class="sev-btn sev-btn--dismiss" onclick="shieldDismissOne(${e.id}, this)">Dismiss</button>
    </div>`;

  return `
    <div class="sev-card sev-card--${lvlCls}" id="sev-card-${e.id}">
      <div class="sev-card-head">
        <div class="sev-card-head-left">
          <span class="sev-badge sev-badge--${lvlCls}">${lvlLbl}</span>
          <span class="sev-cat">${catIcon} ${escapeHtml((e.category || "").toUpperCase())}</span>
          ${ip ? `<span class="sev-ip">${escapeHtml(ip)}</span>` : ""}
        </div>
        <span class="sev-time">${escapeHtml(time)}</span>
      </div>
      <div class="sev-title">${escapeHtml(title)}</div>
      <div class="sev-summary">${escapeHtml(e.summary || "")}</div>
      ${explain ? `<div class="sev-explain">${escapeHtml(explain)}</div>` : ""}
      ${detailLines.length ? `<div class="sev-detail">${detailLines.map(l => `<span>${escapeHtml(l)}</span>`).join("")}</div>` : ""}
      ${verdictHtml}
      ${actionsHtml}
    </div>`;
}

async function shieldInvestigate(item, eventId, btn) {
  btn.disabled         = true;
  btn.textContent      = "Analyzing…";
  _shieldInvestigating = true;   // pause 5s auto-refresh so the card stays in the DOM

  // Find (or create) the live element inside the card.
  // Called twice — at start and after POST — so we always write to the current DOM node.
  function _getLiveEl() {
    const card = document.getElementById(`sev-card-${eventId}`);
    if (!card) return null;
    let el = card.querySelector(".sev-live");
    if (!el) {
      el = document.createElement("div");
      el.className = "sev-live";
      card.querySelector(".sev-actions")?.insertAdjacentElement("beforebegin", el);
    }
    return el;
  }

  const liveEl = _getLiveEl();
  if (liveEl) {
    liveEl.innerHTML = `
      <span class="sev-live-label">⬡ AI — analyzing <strong>${escapeHtml(item)}</strong>…</span>
      <pre class="sev-live-stream"></pre>`;
  }

  // Parallel progress poll — update the stream box as Qwen types
  let stopPoll = false;
  (async () => {
    while (!stopPoll) {
      await new Promise(r => setTimeout(r, 700));
      if (stopPoll) break;
      try {
        const prog = await _apiFetch("/api/ai/progress");
        if (prog.status === "running" && prog.partial) {
          const streamEl = document.getElementById(`sev-card-${eventId}`)?.querySelector(".sev-live-stream");
          if (streamEl) {
            streamEl.textContent = prog.partial.slice(-400);
            streamEl.scrollTop   = streamEl.scrollHeight;
          }
          btn.textContent = `Analyzing… (${Math.round(prog.elapsed_s || 0)}s)`;
        }
      } catch (_) {}
    }
  })();

  try {
    const result = await _apiFetch("/api/ai/investigate", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ item, source: "shield" }),
    });
    stopPoll = true;

    // Re-find the live element — write to whichever DOM node currently exists
    const freshLive = _getLiveEl();
    if (result && !result.error) {
      _shieldPendingResult = { eventId, result };  // persist so nav-away/back restores it
      _shieldInvestigating = true;                 // keep feed paused until user decides
      if (freshLive) _renderShieldInvestigateResult(freshLive, result);
    } else {
      if (freshLive) freshLive.innerHTML = `<span class="sev-live-error">${escapeHtml(result?.error || "Analysis returned no result")}</span>`;
    }
  } catch (err) {
    stopPoll = true;
    const freshLive = _getLiveEl();
    if (freshLive) freshLive.innerHTML = `<span class="sev-live-error">Investigation failed: ${escapeHtml(err.message)}</span>`;
    showToast(`Investigation failed: ${err.message}`, "warning");
    _shieldInvestigating = false;  // resume on error — nothing to decide
  } finally {
    btn.disabled    = false;
    btn.textContent = "Re-investigate";
    // NOTE: _shieldInvestigating stays true on success — the result stays
    // visible until the user picks an action (or "No Action / Continue").
  }
}

function _renderShieldInvestigateResult(container, result, deviceId) {
  const verdict    = (result.verdict || "unknown").toLowerCase();
  const verdictCls = { malicious: "threat", suspicious: "warning", benign: "ok", normal: "ok", noise: "dim", unknown: "dim" }[verdict] || "dim";
  const what       = result.what     || "";
  const findings   = result.findings || "";
  const resolutions = result.proposed_resolutions || [];

  // Device modal uses deviceResolveAction (refreshes modal); shield uses shieldResolveAction
  const resolveHandler = deviceId
    ? (encoded) => `deviceResolveAction('${encoded}',this,${deviceId})`
    : (encoded) => `shieldResolveAction('${encoded}',this)`;

  const resHtml = resolutions.map(r => {
    const atype = r.action_type || "";
    const label = atype === "whitelist_domain"
      ? "Whitelist — never block again"
      : (r.description || atype);
    const cls = atype === "whitelist_domain" ? "sev-res-btn sev-res-btn--whitelist"
              : atype.includes("block")      ? "sev-res-btn sev-res-btn--block"
              : "sev-res-btn";
    const encoded = encodeURIComponent(JSON.stringify(r));
    return `<button class="${cls}" onclick="${resolveHandler(encoded)}">${escapeHtml(label)}</button>`;
  }).join("");

  // "No Action" always present — lets user dismiss the result and resume the feed
  // In device modal context, just hide the result instead of reloading the shield section
  const noActionHandler = deviceId
    ? `this.closest('.sev-result').remove()`
    : `shieldResumeAfterInvestigate(this)`;
  const noActionLabel = deviceId ? "Dismiss" : "No Action — Continue to Block";
  const noActionHtml = `<button class="sev-res-btn sev-res-btn--noaction" onclick="${noActionHandler}">${noActionLabel}</button>`;

  const _ts = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  container.innerHTML = `
    <div class="sev-result">
      <div class="sev-result-head sev-result-head--${verdictCls}">
        ⬡ ${verdict.toUpperCase()}${what ? ` — ${escapeHtml(what)}` : ""}
      </div>
      ${findings ? `<div class="sev-result-findings">${escapeHtml(findings)}</div>` : ""}
      <div class="sev-result-actions">
        ${resHtml}
        ${noActionHtml}
      </div>
      <div class="sev-result-ts">Investigated at ${_ts}</div>
    </div>`;
}

function shieldResumeAfterInvestigate(btn) {
  btn.textContent      = "Resuming…";
  btn.disabled         = true;
  _shieldPendingResult = null;
  _shieldInvestigating = false;
  loadShieldSection();
}

async function shieldResolveAction(encoded, btn) {
  let resolution;
  try { resolution = JSON.parse(decodeURIComponent(encoded)); }
  catch { showToast("Bad resolution data", "warning"); return; }

  btn.disabled    = true;
  btn.textContent = "Applying…";
  try {
    const r = await _apiFetch("/api/ai/resolve", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ action_type: resolution.action_type, params: resolution.params }),
    });
    if (r.success) {
      showToast(r.description, "info", 6000);
      btn.textContent      = "Done ✓";
      _shieldPendingResult = null;
      _shieldInvestigating = false;
      setTimeout(loadShieldSection, 1200);
    } else {
      throw new Error(r.description || "Action failed");
    }
  } catch (err) {
    btn.disabled    = false;
    btn.textContent = resolution.action_type === "whitelist_domain" ? "Whitelist — never block again" : "Retry";
    showToast(`Failed: ${err.message}`, "warning");
  }
}

// ── Device-modal resolve action (label, trust etc — refreshes modal not shield) ──
async function deviceResolveAction(encoded, btn, deviceId) {
  let resolution;
  try { resolution = JSON.parse(decodeURIComponent(encoded)); }
  catch { showToast("Bad resolution data", "warning"); return; }

  btn.disabled    = true;
  btn.textContent = "Applying…";
  try {
    const r = await _apiFetch("/api/ai/resolve", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ action_type: resolution.action_type, params: resolution.params }),
    });
    if (r.success) {
      showToast(r.description, "info", 6000);
      btn.textContent = "Done ✓";
      // Refresh the modal so label/trust state updates visually
      if (deviceId) setTimeout(() => openDeviceModal(deviceId), 800);
    } else {
      throw new Error(r.description || "Action failed");
    }
  } catch (err) {
    btn.disabled    = false;
    btn.textContent = resolution.description || "Retry";
    showToast(`Failed: ${err.message}`, "warning");
  }
}

// ── Device-tab Qwen investigation ─────────────────────────────────────────────
// Same streaming logic as shieldInvestigate but renders into the device modal.

async function deviceInvestigate(ip, btn, deviceId) {
  if (!ip) { showToast("No IP address for this device — cannot investigate.", "warning"); return; }

  btn.disabled    = true;
  btn.textContent = "Analyzing…";

  const liveEl = document.getElementById("device-ai-live");
  if (!liveEl) return;
  liveEl.style.display = "";
  liveEl.innerHTML = `
    <span class="sev-live-label">⬡ AI — analyzing <strong>${escapeHtml(ip)}</strong>…</span>
    <pre class="sev-live-stream"></pre>`;
  const streamEl = liveEl.querySelector(".sev-live-stream");

  // Parallel progress poll — shows Qwen's output forming in real time
  let stopPoll = false;
  (async () => {
    while (!stopPoll) {
      await new Promise(r => setTimeout(r, 700));
      if (stopPoll) break;
      try {
        const prog = await _apiFetch("/api/ai/progress");
        if (prog.status === "running" && prog.partial && streamEl) {
          streamEl.textContent = prog.partial.slice(-500);
          streamEl.scrollTop   = streamEl.scrollHeight;
          btn.textContent = `Analyzing… (${Math.round(prog.elapsed_s || 0)}s)`;
        } else if (prog.status === "done" || prog.status === "idle") {
          btn.textContent = "Finalizing…";
        }
      } catch (_) {}
    }
  })();

  try {
    const result = await _apiFetch("/api/ai/investigate", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ item: ip, source: "devices" }),
    });
    stopPoll = true;

    if (result && !result.error) {
      const isRerun = btn.textContent.startsWith("Analyzing");
      _renderShieldInvestigateResult(liveEl, result, deviceId);
      showToast("Re-investigation complete — verdict: " + (result.verdict || "unknown").toUpperCase(), "info", 4000);
      // Pre-fill label input so user can also save via the top Save button
      const labelRes = (result.proposed_resolutions || []).find(r => r.action_type === "label_device");
      if (labelRes?.params?.label) {
        const labelInput = document.getElementById("modal-label-input");
        if (labelInput) labelInput.value = labelRes.params.label;
      }
    } else {
      liveEl.innerHTML = `<span class="sev-live-error">${escapeHtml(result?.error || "Analysis returned no result")}</span>`;
    }
  } catch (err) {
    stopPoll = true;
    liveEl.innerHTML = `<span class="sev-live-error">Investigation failed: ${escapeHtml(err.message)}</span>`;
    showToast(`Investigation failed: ${err.message}`, "warning");
  } finally {
    btn.disabled    = false;
    btn.textContent = "Re-investigate";
  }
}

async function shieldBlockIp(ip, btn) {
  btn.disabled    = true;
  btn.textContent = "Blocking…";
  try {
    await _apiFetch("/api/command", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ command: `block ${ip}` }),
    });
    showToast(`Blocked ${ip}`, "info", 3000);
    btn.textContent = "Blocked";
  } catch (err) {
    btn.disabled    = false;
    btn.textContent = `Block ${ip}`;
    showToast(`Block failed: ${err.message}`, "warning");
  }
}

async function shieldDismissOne(eventId, btn) {
  btn.disabled = true;
  try {
    await _apiFetch(`/api/shield/events/${eventId}/dismiss`, { method: "POST" });
    const card = document.getElementById(`sev-card-${eventId}`);
    if (card) {
      card.style.transition = "opacity .3s";
      card.style.opacity    = "0";
      setTimeout(() => { card.remove(); _updateFeedCount(); }, 300);
    }
  } catch (err) {
    btn.disabled = false;
    showToast(`Dismiss failed: ${err.message}`, "warning");
  }
}

async function shieldDismissAll() {
  try {
    await _apiFetch("/api/shield/dismiss-all", { method: "POST" });
    showToast("Threat events cleared", "info", 2000);
    setTimeout(loadShieldSection, 400);
  } catch (err) {
    showToast(`Failed: ${err.message}`, "warning");
  }
}

async function shieldClearDnsLogs() {
  try {
    const r = await _apiFetch("/api/shield/clear-dns-logs", { method: "POST" });
    showToast(`DNS logs cleared (${r.deleted ?? 0} entries)`, "info", 2000);
    setTimeout(loadShieldSection, 400);
  } catch (err) {
    showToast(`Failed: ${err.message}`, "warning");
  }
}

function _updateFeedCount() {
  const remaining = document.querySelectorAll(".sev-card").length;
  const countEl   = document.querySelector(".shield-feed-count");
  if (!remaining) {
    document.getElementById("shield-feed").innerHTML =
      `<div class="shield-feed-empty">All clear — no active threats or anomalies</div>`;
    document.getElementById("shield-feed-age").textContent = "";
  } else if (countEl) {
    countEl.textContent = `${remaining} active event${remaining !== 1 ? "s" : ""}`;
  }
}

async function shieldUnblock(ip, btn) {
  btn.disabled = true;
  btn.textContent = "Removing...";
  try {
    await _apiFetch("/api/command", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ command: `unblock ${ip}` }),
    });
    showToast(`Unblocked ${ip}`, "info", 3000);
    setTimeout(loadShieldSection, 1500);
  } catch (err) {
    btn.disabled = false;
    btn.textContent = "Unblock";
    showToast(`Failed: ${err.message}`, "warning");
  }
}

// ── Autonomous Actions (Shield section) ─────────────────────────────────────
//
// Surface every action NetMon took without explicit user clicks (anomaly
// auto-blocks, AI auto-execute decisions, phone-tap ntfy commands) and
// give each one a single-click Undo that replays the stored revert payload
// through ai_resolve.

const _AUTO_ACTOR_META = {
  anomaly_auto: { icon: "⚠", label: "Anomaly detector", title: "Action taken automatically by the anomaly detector" },
  ai_auto:      { icon: "◈", label: "AI investigation",  title: "Action auto-executed during an AI investigation" },
  ntfy_command: { icon: "📱", label: "Phone command",     title: "Action triggered from a notification action button" },
};

async function loadAutonomousActions() {
  const host = document.getElementById("shield-auto-actions");
  if (!host) return;
  const status = document.getElementById("auto-filter")?.value || "active";
  host.innerHTML = `<div class="shield-loading">Loading...</div>`;

  try {
    const data = await _apiFetch(`/api/autonomous-actions?status=${encodeURIComponent(status)}&limit=50`);
    _renderAutonomousActions(host, data.entries || [], status);
  } catch (err) {
    host.innerHTML = `<div class="shield-loading">Failed to load: ${escapeHtml(err.message)}</div>`;
  }
}

function _renderAutonomousActions(host, entries, status) {
  if (!entries.length) {
    const empty = status === "reverted"
      ? "Nothing reverted yet."
      : status === "all"
        ? "No autonomous actions recorded yet."
        : "All clear — no autonomous actions pending review.";
    host.innerHTML = `<div class="shield-feed-empty">${empty}</div>`;
    return;
  }

  const rows = entries.map(e => {
    const meta = _AUTO_ACTOR_META[e.actor] || { icon: "◎", label: e.actor, title: e.actor };
    const when = _fmtDateTime(e.created_at);
    const reverted = !!e.reverted_at;
    const btn = reverted
      ? `<span class="auto-reverted">Reverted ${_fmtDateTime(e.reverted_at)}</span>`
      : `<button class="auto-undo-btn" data-id="${e.id}" onclick="revertAutonomousAction(${e.id}, this)">Undo</button>`;
    const target = e.device_ip ? `<span class="auto-target">${escapeHtml(e.device_ip)}</span>` : "";
    return `
      <tr class="auto-row${reverted ? ' auto-row--reverted' : ''}">
        <td class="auto-when" title="${escapeHtml(when)}">${escapeHtml(when)}</td>
        <td class="auto-actor" title="${escapeHtml(meta.title)}">
          <span class="auto-icon">${meta.icon}</span>
          <span class="auto-actor-label">${escapeHtml(meta.label)}</span>
        </td>
        <td class="auto-summary">${escapeHtml(e.summary)} ${target}</td>
        <td class="auto-action">${btn}</td>
      </tr>`;
  }).join("");

  host.innerHTML = `
    <table class="auto-table">
      <thead><tr><th>When</th><th>Source</th><th>Action</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

async function revertAutonomousAction(actionId, btn) {
  if (!confirm("Reverse this autonomous action?")) return;
  if (btn) {
    btn.disabled    = true;
    btn.textContent = "Reverting...";
  }
  try {
    const res = await _apiFetch(`/api/autonomous-actions/${actionId}/revert`, { method: "POST" });
    showToast(res.description || "Reverted.", res.success === false ? "warning" : "info", 4000);
    loadAutonomousActions();
    // Refresh the firewall blocks table too, since the rule list likely changed
    setTimeout(loadShieldSection, 600);
  } catch (err) {
    if (btn) {
      btn.disabled    = false;
      btn.textContent = "Undo";
    }
    showToast(`Failed: ${err.message}`, "warning");
  }
}

// ── Security Reports Section ──────────────────────────────────────────────────

const _RPT_SEV_COLOR = { low: "secure", medium: "warning", high: "critical", critical: "critical" };
const _RPT_SEV_LABEL = { low: "LOW", medium: "MEDIUM", high: "HIGH", critical: "CRITICAL" };

async function loadReportsSection() {
  const list  = document.getElementById("rpt-list");
  const empty = document.getElementById("rpt-empty");
  if (!list) return;

  list.innerHTML = `<div class="rpt-loading">Loading reports…</div>`;
  if (empty) empty.style.display = "none";

  try {
    const reports = await _apiFetch("/api/reports?limit=48");

    // Apply severity filter
    const sevFilter = document.getElementById("rpt-filter-sev")?.value || "";
    const filtered = sevFilter ? reports.filter(r => r.severity === sevFilter) : reports;

    if (!filtered.length) {
      list.innerHTML = "";
      if (empty) empty.style.display = "flex";
      return;
    }

    list.innerHTML = filtered.map(r => _renderReport(r)).join("");
  } catch (err) {
    list.innerHTML = `<div class="rpt-error">Failed to load reports: ${escapeHtml(err.message)}</div>`;
  }
}

// ── Qwen chat ─────────────────────────────────────────────────────────────────

function sendQuickQuestion(q) {
  document.getElementById("rpt-chat-input").value = q;
  sendChatQuestion();
}

async function sendChatQuestion() {
  const input  = document.getElementById("rpt-chat-input");
  const sendBtn= document.getElementById("rpt-chat-send");
  const msgs   = document.getElementById("rpt-chat-messages");
  const q = (input.value || "").trim();
  if (!q) return;

  input.value    = "";
  input.disabled = true;
  sendBtn.disabled = true;

  // Append user bubble
  msgs.insertAdjacentHTML("beforeend", `
    <div class="rpt-msg rpt-msg--user">
      <div class="rpt-msg-bubble">${escapeHtml(q)}</div>
    </div>`);

  // Typing indicator
  const typingId = "rpt-typing-" + Date.now();
  msgs.insertAdjacentHTML("beforeend", `
    <div class="rpt-msg rpt-msg--qwen" id="${typingId}">
      <span class="rpt-msg-avatar">⬡</span>
      <div class="rpt-msg-bubble rpt-msg-typing">
        <span></span><span></span><span></span>
      </div>
    </div>`);
  msgs.scrollTop = msgs.scrollHeight;

  try {
    const res = await _apiFetch("/api/reports/chat", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ question: q }),
    });

    document.getElementById(typingId)?.remove();
    const answer = res.answer || "(no response)";
    msgs.insertAdjacentHTML("beforeend", `
      <div class="rpt-msg rpt-msg--qwen">
        <span class="rpt-msg-avatar">⬡</span>
        <div class="rpt-msg-bubble">${escapeHtml(answer).replace(/\n/g, "<br>")}</div>
      </div>`);
  } catch (err) {
    document.getElementById(typingId)?.remove();
    msgs.insertAdjacentHTML("beforeend", `
      <div class="rpt-msg rpt-msg--qwen">
        <span class="rpt-msg-avatar">⬡</span>
        <div class="rpt-msg-bubble rpt-msg-error">${escapeHtml(err.message)}</div>
      </div>`);
  } finally {
    input.disabled   = false;
    sendBtn.disabled = false;
    input.focus();
    msgs.scrollTop   = msgs.scrollHeight;
  }
}

async function runReportNow() {
  const btn = document.getElementById("rpt-run-btn");
  btn.disabled    = true;
  btn.textContent = "Generating…";

  try {
    await _apiFetch("/api/reports/run-now", { method: "POST" });
    showToast("AI is generating your report — refreshing in 35 seconds…", "info", 5000);

    // Poll every 5s for up to 60s, refresh as soon as a new report appears
    const before = (await _apiFetch("/api/reports?limit=1"))[0]?.id ?? 0;
    let found = false;
    for (let i = 0; i < 12; i++) {
      await new Promise(r => setTimeout(r, 5000));
      const latest = (await _apiFetch("/api/reports?limit=1"))[0];
      if (latest && latest.id > before) {
        found = true;
        break;
      }
    }
    await loadReportsSection();
    if (found) showToast("Report ready", "info", 3000);
  } catch (err) {
    showToast(`Failed: ${err.message}`, "warning");
  } finally {
    btn.disabled    = false;
    btn.textContent = "Run Now";
  }
}

function _renderReport(r) {
  const sevClass = _RPT_SEV_COLOR[r.severity] || "secure";
  const sevLabel = _RPT_SEV_LABEL[r.severity] || (r.severity || "").toUpperCase();
  const time     = r.created_at ? _fmtDateTime(r.created_at) : "—";
  const period   = (r.period_start && r.period_end)
    ? `${_fmtTime(r.period_start)} – ${_fmtTime(r.period_end)}`
    : "";

  if (r.error) {
    return `<div class="rpt-card rpt-card--error">
      <div class="rpt-card-head">
        <span class="rpt-sev-badge rpt-sev--secure">INFO</span>
        <span class="rpt-card-time">${time}</span>
      </div>
      <div class="rpt-card-headline">Report generation failed</div>
      <div class="rpt-card-error">${escapeHtml(r.error)}</div>
    </div>`;
  }

  const anomalies = Array.isArray(r.anomalies) ? r.anomalies : [];
  const recs      = Array.isArray(r.recommendations) ? r.recommendations : [];

  return `<div class="rpt-card rpt-card--${sevClass}" onclick="this.classList.toggle('rpt-card--open')">
    <div class="rpt-card-head">
      <div class="rpt-card-head-left">
        <span class="rpt-sev-badge rpt-sev--${sevClass}">${sevLabel}</span>
        <span class="rpt-card-type">${(r.report_type || "hourly").toUpperCase()}</span>
        ${period ? `<span class="rpt-card-period">${escapeHtml(period)}</span>` : ""}
      </div>
      <span class="rpt-card-time">${time}</span>
    </div>
    <div class="rpt-card-headline">${escapeHtml(r.headline || "No summary")}</div>
    <div class="rpt-card-body">
      ${(r.body || "").split("\n\n").map(p => `<p>${escapeHtml(p.trim())}</p>`).join("")}
      ${anomalies.length ? `
        <div class="rpt-anomalies">
          <div class="rpt-section-label">Anomalies detected</div>
          <ul>${anomalies.map(a => `<li>${escapeHtml(a)}</li>`).join("")}</ul>
        </div>` : ""}
      ${recs.length ? `
        <div class="rpt-recommendations">
          <div class="rpt-section-label">Recommendations</div>
          <ul>${recs.map(rec => `<li>${escapeHtml(rec)}</li>`).join("")}</ul>
        </div>` : ""}
      ${r.model ? `<div class="rpt-model">Generated by ${escapeHtml(r.model)}</div>` : ""}
    </div>
    <div class="rpt-card-expand-hint">Click to expand</div>
  </div>`;
}

// ── Live DNS / Activity View ──────────────────────────────────────────────────

async function refreshDnsLive() {
  const el = document.getElementById("dns-live-list");
  if (!el) return;
  el.innerHTML = `<span class="dns-empty dns-loading">Loading…</span>`;

  try {
    const data = await _apiFetch("/api/traffic/dns-live");

    if (data.error) {
      el.innerHTML = `<span class="dns-empty">${escapeHtml(data.error)}</span>`;
      return;
    }

    const ips = Object.keys(data);
    if (!ips.length) {
      el.innerHTML = `<span class="dns-empty">No activity captured yet. Start packet capture and wait a moment.</span>`;
      return;
    }

    el.innerHTML = ips.sort().map(ip => {
      const domains = data[ip] || [];
      const domainHtml = domains.slice(0, 20).map(d =>
        `<span class="dns-domain" title="${escapeHtml(d.domain)}">${escapeHtml(d.domain)}<span class="dns-count">${d.count}</span></span>`
      ).join("");
      return `
        <div class="dns-device">
          <div class="dns-device-ip">${escapeHtml(ip)}</div>
          <div class="dns-domains">${domainHtml || '<span class="dns-empty-small">no queries</span>'}</div>
        </div>`;
    }).join("");
  } catch (err) {
    el.innerHTML = `<span class="dns-empty">Failed: ${escapeHtml(err.message)}</span>`;
  }
}

// ── Notification test ─────────────────────────────────────────────────────────

async function testNotification(level = "info") {
  try {
    const res = await _apiFetch("/api/notifications/test", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ level }),
    });
    if (res.ntfy_sent) {
      showToast(
        level === "critical"
          ? "Critical test alert sent — check your phone for the notification with action buttons"
          : "Test notification sent — check your phone",
        "info", 5000
      );
    } else {
      const detail = res.ntfy_response ? ` — ${res.ntfy_response}` : "";
      showToast(`Not sent: ${res.ntfy_error || "unknown error"}${detail}`, "warning", 10000);
    }
  } catch (err) {
    showToast(`Test failed: ${err.message}`, "warning");
  }
}

function loadLogsSection() {
  _logsState.offset = 0;
  _fetchLogs(false);

  // Auto-refresh every 30s while section is visible
  if (_logsState.timer) clearInterval(_logsState.timer);
  _logsState.timer = setInterval(() => {
    const sec = document.getElementById("section-logs");
    if (sec && sec.style.display !== "none") {
      // Refresh from top (don't paginate — just reload first page)
      _logsState.offset = 0;
      _fetchLogs(false);
    } else {
      clearInterval(_logsState.timer);
      _logsState.timer = null;
    }
  }, 30_000);
}

// ── Event wiring ─────────────────────────────────────────────────────────────

// Filter tabs
document.addEventListener("click", (e) => {
  const tab = e.target.closest(".log-filter-tab");
  if (tab) {
    document.querySelectorAll(".log-filter-tab").forEach(t => t.classList.remove("active"));
    tab.classList.add("active");
    _logsState.category = tab.dataset.cat || "";
    _logsState.offset   = 0;
    _fetchLogs(false);
    return;
  }

  // Expand/collapse detail
  const expandBtn = e.target.closest(".log-expand-btn");
  if (expandBtn) {
    const entry  = expandBtn.closest(".log-entry");
    const detail = entry?.querySelector(".log-detail");
    if (detail) {
      const open = detail.style.display !== "none";
      detail.style.display = open ? "none" : "";
      expandBtn.textContent = open ? "›" : "‹";
    }
    return;
  }

  // Clear button
  if (e.target.id === "log-clear-btn") {
    if (!confirm("Clear all activity log entries? This cannot be undone.")) return;
    _apiFetch("/api/logs", { method: "DELETE" }).then(() => {
      _logsState.offset = 0;
      _fetchLogs(false);
    }).catch(err => alert("Clear failed: " + err.message));
    return;
  }

  // Load more
  if (e.target.id === "log-load-more-btn") {
    _logsState.offset += _LOGS_PAGE;
    _fetchLogs(true);
    return;
  }

  if (e.target.id === "log-ai-synthesize-btn") {
    runLogAiSynthesis();
    return;
  }

  if (e.target.id === "log-ai-noise-btn") {
    runDnsNoiseLearning();
    return;
  }
});

// Search box — debounced
let _logSearchTimer = null;
document.addEventListener("input", (e) => {
  if (e.target.id !== "log-search") return;
  clearTimeout(_logSearchTimer);
  _logSearchTimer = setTimeout(() => {
    _logsState.search = e.target.value.trim();
    _logsState.offset = 0;
    _fetchLogs(false);
  }, 350);
});


/* ============================================================
   19. INIT
   ============================================================ */

/*
  Health polling — why we need this:
  The background health check loop waits ~8 seconds on startup before
  its first ping, then runs every N minutes. The page loads immediately
  and calls loadHealthCurrent() once — if no rows exist yet, it gets
  status:"unknown" and shows "Checking…" forever with no auto-refresh.

  Fix: poll every 15 seconds. This means the stat strip updates within
  15 seconds of the first background check completing, and stays fresh
  as new checks arrive.

  We also do a one-shot retry at 12 seconds to catch the startup delay
  check (which fires at ~8s) without waiting a full 15s interval.
*/
function startHealthPolling() {
  // Catch the startup delay check (fires ~8s after server start)
  setTimeout(loadHealthCurrent, 12_000);
  // Then keep polling on a regular cadence
  setInterval(loadHealthCurrent, 15_000);
}

/* ============================================================
   20. GLOBAL STATUS POLLER
   ============================================================
   Polls /api/status every 5 seconds to:
   - Show/hide live activity chips in the topbar
   - Update the "Last Scan" stat card with a scanning indicator
   - Auto-refresh data when a background scan completes
   - Show a toast notification on scan completion
*/

let _lastKnownScanId  = null;   // track last seen scan id to detect new results
let _lastScanRunning  = false;  // track transition: running → done
let _lastAiRunning    = false;
let _lastCapRunning   = false;

// ── Toast notification ───────────────────────────────────────────────────────
function showToast(message, level = "info", durationMs = 4000) {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `toast toast--${level}`;
  toast.textContent = message;
  container.appendChild(toast);

  // Trigger entrance animation on next frame
  requestAnimationFrame(() => toast.classList.add("toast--visible"));

  setTimeout(() => {
    toast.classList.remove("toast--visible");
    toast.addEventListener("transitionend", () => toast.remove(), { once: true });
  }, durationMs);
}

// ── Status poller ────────────────────────────────────────────────────────────
async function _pollStatus() {
  let status;
  try {
    status = await _apiFetch("/api/status", { timeoutMs: 4000 });
  } catch (_) {
    return;   // silent — server may be restarting
  }

  const scanRunning = status.scan?.running === true;
  const aiRunning   = status.ai?.running   === true;
  const capRunning  = status.capture?.running === true;
  const scanId      = status.scan?.scan_id;
  const scanSource  = status.scan?.source;   // "manual" | "auto"

  // ── Activity chips ───────────────────────────────────────────────────────
  const chipScan    = document.getElementById("chip-scan");
  const chipAi      = document.getElementById("chip-ai");
  const chipCapture = document.getElementById("chip-capture");

  if (chipScan)    { chipScan.style.display    = scanRunning ? "" : "none"; }
  if (chipAi)      { chipAi.style.display      = aiRunning   ? "" : "none"; }
  if (chipCapture) { chipCapture.style.display  = capRunning  ? "" : "none"; }

  // ── Stat-strip scan card ─────────────────────────────────────────────────
  const scanLabel = document.getElementById("stat-scan-label");
  const scanCard  = document.getElementById("stat-scan-card");
  if (scanRunning) {
    if (scanLabel) scanLabel.textContent = "Scanning…";
    if (scanCard)  scanCard.classList.add("stat-card--active");
  } else {
    if (scanLabel) scanLabel.textContent = "Last Scan";
    if (scanCard)  scanCard.classList.remove("stat-card--active");
  }

  // ── Detect scan completion → auto-refresh ────────────────────────────────
  const scanJustFinished = _lastScanRunning && !scanRunning;
  const newScanArrived   = scanId !== null && scanId !== _lastKnownScanId;

  if (scanJustFinished || newScanArrived) {
    const isAuto   = scanSource === "auto";
    const hosts    = status.scan?.host_count  ?? "?";
    const newDevs  = status.scan?.new_devices ?? 0;
    const changes  = status.scan?.changes     ?? 0;

    // Refresh UI data (non-disruptive — only updates current section's data)
    _refreshAfterScan();

    // Toast
    let msg = `${isAuto ? "Auto-scan" : "Scan"} complete — ${hosts} device${hosts !== 1 ? "s" : ""}`;
    if (newDevs > 0) msg += `, ${newDevs} new`;
    if (changes > 0) msg += `, ${changes} change${changes !== 1 ? "s" : ""}`;
    showToast(msg, newDevs > 0 ? "warning" : "info");
  }

  // ── AI: toast when done ───────────────────────────────────────────────────
  if (_lastAiRunning && !aiRunning) {
    showToast("AI investigation complete", "info", 2500);
  }

  _lastKnownScanId  = scanId ?? _lastKnownScanId;
  _lastScanRunning  = scanRunning;
  _lastAiRunning    = aiRunning;
  _lastCapRunning   = capRunning;
}

function _refreshAfterScan() {
  // Always refresh the overview and stat strip — they show scan-derived data
  loadAll();

  // Also refresh the currently visible section if it shows scan data
  const active = document.querySelector(".nav-item.active")?.dataset?.section;
  if (active === "devices")  loadDevicesSection();
  if (active === "alerts")   loadAlertsSection();
  if (active === "logs")     { _logsState.offset = 0; _fetchLogs(false); }
}

function startStatusPolling() {
  _pollStatus();                         // immediate first check
  setInterval(_pollStatus, 5_000);       // then every 5 seconds
}


// Scripts at the bottom of <body> run after the DOM is fully parsed,
// so DOMContentLoaded is not needed — call init directly.
applyMotionPreference();
startClock();
initNav();   // still runs as a fallback for any dynamically added nav items
loadAll();
startHealthPolling();
startStatusPolling();


// ═══════════════════════════════════════════════════════ NETWORK INFO ══

let _netInfoLocalIp = "";

async function loadNetworkInfo(showLoading = false) {
  const el = document.getElementById("netinfo-content");
  if (!el) return;
  if (showLoading) el.innerHTML = '<div class="netinfo-loading">Loading\u2026</div>';
  try {
    const d = await _apiFetch("/api/network/info");
    _renderNetworkInfo(el, d);
  } catch (e) {
    el.innerHTML = '<div class="netinfo-loading">Unable to load network info</div>';
  }
}

function _renderNetworkInfo(el, d) {
  const p = d.primary || {};
  _netInfoLocalIp = p.ipv4 || "";
  const dnsServers = p.dns_servers || [];
  const localIp    = p.ipv4 || "";
  const netmonIsDns = dnsServers.includes(localIp) && localIp !== "";

  function row(label, value, cls) {
    return `<div class="netinfo-row">
      <span class="netinfo-label">${label}</span>
      <span class="netinfo-value${cls ? " " + cls : ""}">${value || "\u2014"}</span>
    </div>`;
  }

  function dnsRow(servers) {
    if (!servers || servers.length === 0) return row("DNS Servers", "\u2014");
    const badges = servers.map(s => {
      const isNetmon = s === localIp;
      return `<span class="netinfo-dns-badge${isNetmon ? " netmon" : ""}">${s}${isNetmon ? " \u2605" : ""}</span>`;
    }).join(" ");
    return `<div class="netinfo-row">
      <span class="netinfo-label">DNS Servers</span>
      <span class="netinfo-value">${badges}</span>
    </div>`;
  }

  let html = "";

  html += `<div class="netinfo-card">
    <div class="netinfo-card-title">This PC (${p.description || p.name || "Active Adapter"})</div>
    ${row("Local IP", p.ipv4, "accent")}
    ${row("Subnet", p.subnet)}
    ${row("MAC Address", p.mac)}
    ${row("DHCP", p.dhcp_enabled)}
  </div>`;

  html += `<div class="netinfo-card">
    <div class="netinfo-card-title">Router / Gateway</div>
    ${row("Router IP", p.gateway, "accent")}
    ${row("DHCP Server", p.dhcp_server)}
    ${row("Lease From",  p.lease_obtained ? _shortDate(p.lease_obtained) : null)}
    ${row("Lease Until", p.lease_expires  ? _shortDate(p.lease_expires)  : null)}
  </div>`;

  const dnsNote = netmonIsDns
    ? '<div style="font-size:.74rem;color:var(--accent);margin-top:6px;">\u2605 NetMon Ad Blocker is your active DNS</div>'
    : (dnsServers[0] === p.gateway
        ? '<div style="font-size:.74rem;color:var(--text-muted);margin-top:6px;">Your router is handling DNS for this PC</div>'
        : "");
  html += `<div class="netinfo-card">
    <div class="netinfo-card-title">DNS Configuration</div>
    ${dnsRow(dnsServers)}
    ${row("Upstream (router)", p.gateway)}
    ${dnsNote}
  </div>`;

  html += `<div class="netinfo-card">
    <div class="netinfo-card-title">Public / WAN</div>
    ${row("Public IP", d.public_ip, "accent")}
    ${row("Tailscale IP", _getTailscaleIp(d.adapters))}
  </div>`;

  const others = (d.adapters || []).filter(a => a.ipv4 !== p.ipv4 && !a.ipv4?.startsWith("100."));
  if (others.length) {
    html += `<div class="netinfo-card">
      <div class="netinfo-card-title">Other Adapters</div>
      ${others.map(a => row(a.name?.replace(/^.* adapter /, "") || "Adapter", a.ipv4)).join("")}
    </div>`;
  }

  el.innerHTML = html;
  el.className = "netinfo-grid";
}

function _shortDate(str) {
  if (!str) return null;
  try {
    const d = new Date(str);
    if (!isNaN(d)) return d.toLocaleString("en-US", {month:"short",day:"numeric",year:"numeric",hour:"2-digit",minute:"2-digit",hour12:true,timeZone:_TZ});
  } catch (_) {}
  return str;
}

function _getTailscaleIp(adapters) {
  if (!adapters) return null;
  const ts = adapters.find(a => a.name?.toLowerCase().includes("tailscale"));
  return ts?.ipv4 || null;
}


// ═══════════════════════════════════════════════════════ DNS AD BLOCKER ══

let _dnsLocalIp = "";

async function loadDnsSection() {
  try {
    const dns = await _apiFetch("/api/dns/status");
    _renderDnsStatus(dns);
    _apiFetch("/api/network/info").then(netinfo => {
      if (netinfo?.primary?.ipv4) {
        dns.local_ip = netinfo.primary.ipv4;
        const ipEl = document.getElementById("dns-local-ip");
        if (ipEl) ipEl.textContent = netinfo.primary.ipv4;
        _dnsLocalIp = netinfo.primary.ipv4;
      }
    }).catch(() => {});
  } catch (e) {
    console.error("[dns] load error", e);
    const badge = document.getElementById("dns-status-badge");
    if (badge) { badge.textContent = "Error"; badge.className = "dns-status-badge stopped"; }
  }
}

function _renderDnsStatus(d) {
  _dnsLocalIp = d.local_ip || "";

  const badge = document.getElementById("dns-status-badge");
  if (badge) {
    if (d.running) {
      badge.textContent = "Running";
      badge.className = "dns-status-badge running";
    } else {
      badge.textContent = d.enabled ? "Starting\u2026" : "Stopped";
      badge.className = "dns-status-badge stopped";
    }
  }

  const enBtn  = document.getElementById("dns-enable-btn");
  const disBtn = document.getElementById("dns-disable-btn");
  if (enBtn)  enBtn.style.display  = d.enabled ? "none" : "";
  if (disBtn) disBtn.style.display = d.enabled ? "" : "none";

  const s = d.stats || {};
  _setTxt("dns-total-domains", (s.total_domains || 0).toLocaleString());
  _setTxt("dns-queries-today", (s.queries_today || 0).toLocaleString());
  _setTxt("dns-blocked-today", (s.blocked_today || 0).toLocaleString());

  const pct = s.queries_today > 0
    ? ((s.blocked_today / s.queries_today) * 100).toFixed(1) + "% blocked"
    : "0% blocked";
  _setTxt("dns-block-pct", pct);

  const srcs = s.sources || {};
  for (const [key, count] of Object.entries(srcs)) {
    const el = document.getElementById(`dns-src-${key}`);
    if (el) el.textContent = count.toLocaleString() + " domains";
  }

  if (s.last_updated) {
    const dt = new Date(s.last_updated);
    _setTxt("dns-last-updated", dt.toLocaleString("en-US", _DTFMT));
  } else {
    _setTxt("dns-last-updated", "Never \u2014 lists not yet downloaded");
  }

  _setTxt("dns-source-count", Object.keys(srcs).length || 3);

  const top   = s.top_blocked || [];
  const topEl = document.getElementById("dns-top-list");
  if (topEl) {
    if (top.length === 0) {
      topEl.innerHTML = '<div class="dns-top-empty">No blocked queries yet today</div>';
    } else {
      const maxCount = top[0]?.count || 1;
      topEl.innerHTML = top.map((item, i) => {
        const barW = Math.max(4, Math.round((item.count / maxCount) * 120));
        return `<div class="dns-top-row">
          <span class="dns-top-rank">${i + 1}</span>
          <span class="dns-top-domain" title="${item.domain}">${item.domain}</span>
          <div class="dns-top-bar" style="width:${barW}px"></div>
          <span class="dns-top-count">${item.count}</span>
        </div>`;
      }).join("");
    }
  }

  const ipEl = document.getElementById("dns-local-ip");
  if (ipEl) ipEl.textContent = d.local_ip || "Unknown";
}

function _setTxt(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

async function dnsEnable() {
  const btn = document.getElementById("dns-enable-btn");
  if (btn) { btn.disabled = true; btn.textContent = "Enabling\u2026"; }
  try {
    await _apiFetch("/api/dns/enable", { method: "POST" });
    showToast("DNS ad blocker enabling \u2014 downloading blocklists\u2026", "info");
    setTimeout(() => loadDnsSection(), 3000);
    setTimeout(() => loadDnsSection(), 8000);
    setTimeout(() => loadDnsSection(), 20000);
  } catch (e) {
    showToast("Failed to enable DNS blocker: " + e.message, "error");
    if (btn) { btn.disabled = false; btn.textContent = "Enable"; }
  }
}

async function dnsDisable() {
  const btn = document.getElementById("dns-disable-btn");
  if (btn) { btn.disabled = true; btn.textContent = "Stopping\u2026"; }
  try {
    await _apiFetch("/api/dns/disable", { method: "POST" });
    showToast("DNS ad blocker disabled", "warning");
    setTimeout(() => loadDnsSection(), 1000);
  } catch (e) {
    showToast("Failed to disable DNS blocker: " + e.message, "error");
    if (btn) { btn.disabled = false; btn.textContent = "Disable"; }
  }
}

async function dnsRefresh() {
  const btn = document.getElementById("dns-refresh-btn");
  if (btn) { btn.disabled = true; btn.textContent = "Downloading\u2026"; }
  try {
    await _apiFetch("/api/dns/blocklist/refresh", { method: "POST" });
    showToast("Blocklist refresh started \u2014 this may take 30\u201360 seconds", "info");
    setTimeout(() => {
      loadDnsSection();
      if (btn) { btn.disabled = false; btn.textContent = "Refresh Lists"; }
    }, 45000);
  } catch (e) {
    showToast("Refresh failed: " + e.message, "error");
    if (btn) { btn.disabled = false; btn.textContent = "Refresh Lists"; }
  }
}

async function dnsResetStats() {
  try {
    await _apiFetch("/api/dns/stats/reset", { method: "POST" });
    showToast("Daily stats reset", "info");
    loadDnsSection();
  } catch (e) {
    showToast("Reset failed: " + e.message, "error");
  }
}

function dnsCopyIp() {
  const ip = _dnsLocalIp || document.getElementById("dns-local-ip")?.textContent;
  if (!ip || ip === "Unknown") { showToast("IP address not available", "warning"); return; }
  navigator.clipboard.writeText(ip).then(() => showToast("IP copied: " + ip, "info"));
}
