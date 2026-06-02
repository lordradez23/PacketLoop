// ============================================================
//  PacketLoop — Real-World Simulation Engine
//  Simulates every module: AdaptivePPS, ClientFingerprint,
//  GhostAP, HandshakeCapture, BeaconProtection, CloudAlerts,
//  PcapAnalyzer, MultiInterface, Scheduler
// ============================================================

"use strict";

// ---- State ----
const state = {
  running: false,
  startTime: null,
  sessionDuration: 120,
  interface: "wlan0mon",
  bssid: "DE:AD:BE:EF:CA:FE",
  whitelist: [],
  modules: {},

  // AdaptivePPS
  pps: 100,
  ppsHistory: [],
  txErrors: 0,

  // Clients
  clients: {},          // mac -> { vendor, type, risk, status, firstSeen }
  newClientQueue: [],

  // Ghost AP
  ghostAPs: [],
  ghostActive: false,

  // Counters
  deauthCount: 0,
  alertCount: 0,
  handshakeCaptured: false,
  handshakeAttemptAt: null,

  // Timers
  _timers: [],
  _intervals: [],

  // PCAP
  pcapFrames: 0,
  pcapBytes: 0,

  // Logs
  logs: [],

  // Topology
  topoNodes: [], // { x, y, mac, type, active, flare: 0 }
};

// ---- Static Data ----
const KNOWN_OUI = [
  { prefix: "A4:C3:61", vendor: "Apple", type: "MacBook",             risk: "LOW",    icon: "🍎" },
  { prefix: "00:17:F2", vendor: "Apple", type: "iPhone/iPad",         risk: "LOW",    icon: "📱" },
  { prefix: "14:AB:C5", vendor: "Apple", type: "Apple Watch",         risk: "LOW",    icon: "⌚" },
  { prefix: "54:60:09", vendor: "Samsung", type: "Galaxy Phone",      risk: "LOW",    icon: "📱" },
  { prefix: "00:26:5A", vendor: "Samsung", type: "Galaxy Tab",        risk: "LOW",    icon: "💻" },
  { prefix: "FC:3F:DB", vendor: "Xiaomi", type: "Redmi Phone",        risk: "MEDIUM", icon: "📱" },
  { prefix: "44:A0:37", vendor: "Huawei", type: "Phone/Router",       risk: "MEDIUM", icon: "📡" },
  { prefix: "B8:27:EB", vendor: "Raspberry Pi", type: "RPi",           risk: "MEDIUM", icon: "🍓" },
  { prefix: "00:50:56", vendor: "VMware", type: "Virtual Machine",    risk: "HIGH",   icon: "🖥" },
  { prefix: "74:DA:38", vendor: "Espressif", type: "IoT ESP32",       risk: "HIGH",   icon: "🔌" },
  { prefix: "00:23:AE", vendor: "Cisco", type: "Network Equipment",   risk: "LOW",    icon: "🔗" },
  { prefix: "00:1A:11", vendor: "Google", type: "Chromecast",         risk: "LOW",    icon: "📺" },
  { prefix: "00:0F:00", vendor: "Intel", type: "WiFi Adapter",        risk: "MEDIUM", icon: "💡" },
  { prefix: "DC:A6:32", vendor: "Raspberry Pi", type: "RPi 4",        risk: "HIGH",   icon: "🍓" },
  { prefix: "CC:50:E3", vendor: "Espressif", type: "IoT Device",      risk: "HIGH",   icon: "🔌" },
];

const GHOST_PREFIXES = ["Corp", "Office", "Starbucks", "Free_WiFi", "iPhone", "NETGEAR", "TP-Link", "Xfinity", "att_wifi", "Sky"];
const SSID_SUFFIXES  = ["_EXT","_5G","_2G","_Guest","_Hidden","_Secure","_PRO","_v2","_Plus","_Ultra"];

// ---- DOM helpers ----
const $ = id => document.getElementById(id);
const term = $("terminal");

function termLine(text, cls = "") {
  const d = document.createElement("div");
  d.className = "term-line" + (cls ? " " + cls : "");
  const ts = new Date().toLocaleTimeString("en-GB", { hour12: false });
  const html = `<span class="term-dim">[${ts}]</span> ${text}`;
  d.innerHTML = html;
  term.appendChild(d);
  term.scrollTop = term.scrollHeight;
  state.logs.push(`[${ts}] ${text.replace(/<[^>]*>?/gm, '')}`);
}

function termRaw(text, cls = "") {
  const d = document.createElement("div");
  d.className = "term-line" + (cls ? " " + cls : "");
  d.innerHTML = text;
  term.appendChild(d);
  term.scrollTop = term.scrollHeight;
  state.logs.push(text.replace(/<[^>]*>?/gm, ''));
}

function clearTerminal() {
  term.innerHTML = "";
  state.logs = [];
}

function exportSessionLog() {
  const content = state.logs.join("\n");
  const blob = new Blob([content], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `packetloop_session_${state.bssid.replace(/:/g,"")}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function pulse(id) {
  const el = $(id);
  if (!el) return;
  el.classList.remove("pulse");
  void el.offsetWidth;
  el.classList.add("pulse");
}

function formatElapsed(ms) {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  return `${String(m).padStart(2,"0")}:${String(s % 60).padStart(2,"0")}`;
}

function randomMac(prefix) {
  const pre = prefix || KNOWN_OUI[Math.floor(Math.random() * KNOWN_OUI.length)].prefix;
  const rand = () => Math.floor(Math.random() * 256).toString(16).padStart(2, "0").toUpperCase();
  return `${pre}:${rand()}:${rand()}:${rand()}`;
}

function randomFrom(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

function addTimer(fn, delay)    { state._timers.push(setTimeout(fn, delay)); }
function addInterval(fn, delay) { state._intervals.push(setInterval(fn, delay)); }

// ---- PPS Canvas Chart ----
const canvas = $("ppsCanvas");
const ctx    = canvas.getContext("2d");
canvas.width  = canvas.parentElement.clientWidth - 28;
canvas.height = 100;

function drawPpsChart() {
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  if (state.ppsHistory.length < 2) return;

  const maxPps = 3000;
  const data   = state.ppsHistory.slice(-80); // last 80 readings
  const step   = w / (data.length - 1);

  // Draw grid lines
  ctx.strokeStyle = "rgba(255,255,255,0.05)";
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = h - (i / 4) * h;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }

  // Fill gradient
  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, "rgba(0,229,160,0.3)");
  grad.addColorStop(1, "rgba(0,229,160,0.0)");

  ctx.beginPath();
  data.forEach((v, i) => {
    const x = i * step;
    const y = h - (v / maxPps) * (h - 4) - 2;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.lineTo((data.length - 1) * step, h);
  ctx.lineTo(0, h);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Stroke line
  ctx.beginPath();
  data.forEach((v, i) => {
    const x = i * step;
    const y = h - (v / maxPps) * (h - 4) - 2;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.strokeStyle = "#00e5a0";
  ctx.lineWidth = 2;
  ctx.stroke();

  // Current value label
  const cur = data[data.length - 1];
  ctx.fillStyle = "#00e5a0";
  ctx.font = "bold 12px JetBrains Mono, monospace";
  ctx.fillText(`${cur} PPS`, 8, 16);
}

// ---- Network Topology ----
const topoCanvas = $("topoCanvas");
const tctx = topoCanvas.getContext("2d");

function drawTopology() {
  if (!state.running) return;
  const w = topoCanvas.width = topoCanvas.parentElement.clientWidth;
  const h = topoCanvas.height = topoCanvas.parentElement.clientHeight;
  tctx.clearRect(0,0,w,h);

  const cx = w/2, cy = h/2;

  // Draw AP (Center)
  tctx.shadowBlur = 15;
  tctx.shadowColor = "rgba(0,212,255,0.5)";
  tctx.fillStyle = "#00d4ff";
  tctx.beginPath();
  tctx.arc(cx, cy, 10, 0, Math.PI*2);
  tctx.fill();
  tctx.shadowBlur = 0;

  tctx.fillStyle = "rgba(0,212,255,0.8)";
  tctx.font = "bold 10px JetBrains Mono";
  tctx.textAlign = "center";
  tctx.fillText(state.bssid, cx, cy + 25);

  // Draw Clients
  const clientKeys = Object.keys(state.clients);
  clientKeys.forEach((mac, i) => {
    const angle = (i / clientKeys.length) * Math.PI * 2 + (Date.now() / 5000);
    const radius = 60 + Math.sin(Date.now() / 1000 + i) * 5;
    const x = cx + Math.cos(angle) * radius;
    const y = cy + Math.sin(angle) * radius;

    const info = state.clients[mac];
    const isWhitelisted = info.status === "whitelisted";

    // Connection Line
    tctx.beginPath();
    tctx.moveTo(cx, cy);
    tctx.lineTo(x, y);
    tctx.strokeStyle = isWhitelisted ? "rgba(0,229,160,0.15)" : "rgba(255,77,109,0.15)";
    tctx.setLineDash([2, 4]);
    tctx.stroke();
    tctx.setLineDash([]);

    // Shockwave Flare (on deauth)
    if (info._flare > 0) {
      tctx.beginPath();
      tctx.arc(x, y, 15 * (1 - info._flare), 0, Math.PI*2);
      tctx.strokeStyle = `rgba(255,77,109,${info._flare})`;
      tctx.stroke();
      info._flare -= 0.05;
    }

    // Client Node
    tctx.fillStyle = isWhitelisted ? "#00e5a0" : "#ff4d6d";
    tctx.beginPath();
    tctx.arc(x, y, 5, 0, Math.PI*2);
    tctx.fill();

    // Signal pulse
    if (Math.random() < 0.1) {
      tctx.beginPath();
      tctx.arc(x, y, 8, 0, Math.PI*2);
      tctx.strokeStyle = tctx.fillStyle;
      tctx.stroke();
    }
  });

  requestAnimationFrame(drawTopology);
}

// ---- AdaptivePPS Engine ----
function tickPps() {
  // Simulate TX errors occasionally
  const spike = Math.random() < 0.15;
  if (spike) state.txErrors += Math.floor(Math.random() * 80) + 60;
  else        state.txErrors = 0;

  if (state.txErrors > 50) {
    // Congestion — back off
    state.pps = Math.max(100, state.pps - 200);
    if (state.txErrors > 0) {
      termLine(`[AdaptivePPS] Congestion detected! TX errors: ${state.txErrors}. Backing off → <span class="term-warn">${state.pps} PPS</span>`, "term-warn");
    }
  } else {
    // Ramp up
    const ramp = Math.floor(Math.random() * 3) + 1;
    state.pps = Math.min(3000, state.pps + 100 * ramp);
    if (state.pps % 400 === 0) {
      termLine(`[AdaptivePPS] Channel clear. Ramping up → <span class="term-ok">${state.pps} PPS</span>`, "term-ok");
    }
  }

  state.ppsHistory.push(state.pps);
  $("sPps").textContent  = state.pps;
  $("hdrPps").textContent = state.pps;
  $("ppsChip").textContent = `${state.pps} PPS`;
  $("ppsChip").className = "chip " + (state.pps > 2000 ? "danger" : state.pps > 1000 ? "warning" : "running");
  drawPpsChart();

  // Feed into PCAP accumulation
  state.pcapFrames += Math.floor(state.pps * 2 * (Math.random() * 0.5 + 0.8));
  state.pcapBytes  += state.pcapFrames * (Math.floor(Math.random() * 800) + 200);
}

// ---- Client Discovery ----
function discoverClient() {
  if (!state.running) return;
  if (Object.keys(state.clients).length >= 14) return;

  const oui  = randomFrom(KNOWN_OUI);
  const mac  = randomMac(oui.prefix);
  if (state.clients[mac]) return;

  const whitelist = state.whitelist;
  const isWhite   = whitelist.length > 0 && whitelist.some(w => mac.startsWith(w.slice(0, 8)));

  state.clients[mac] = {
    vendor: oui.vendor,
    type:   oui.type,
    risk:   oui.risk,
    icon:   oui.icon,
    status: isWhite ? "whitelisted" : "deauthed",
    firstSeen: Date.now(),
    rssi: -30 - Math.floor(Math.random() * 60),
    _flare: 0
  };

  updateClientUI();
  const count = Object.keys(state.clients).length;
  $("sClients").textContent = count;
  $("clientChip").textContent = `${count} online`;
  pulse("statClients");

  if (state.modules.fingerprint) {
    const riskColor = oui.risk === "HIGH" ? "term-err" : oui.risk === "MEDIUM" ? "term-warn" : "term-ok";
    termLine(
      `[Fingerprint] ${mac} | <span class="${riskColor}">${oui.vendor} ${oui.type}</span> | Risk: ${oui.risk}`,
      "term-module"
    );
  }

  if (isWhite) {
    termLine(`[Filter] ${mac} — WHITELISTED. No action taken.`, "term-ok");
  } else {
    termLine(`[Scanner] New client discovered: <span class="term-deauth">${mac}</span>`, "");
    addTimer(() => deauthClient(mac, oui), 600 + Math.random() * 800);
  }

  // Cloud alert
  if (state.modules.alerts) {
    addTimer(() => sendAlert("new_client", mac, oui), 1200);
  }
}

function deauthClient(mac, oui) {
  if (!state.running) return;
  state.deauthCount++;
  $("sDeauth").textContent = state.deauthCount;
  pulse("statDeauth");

  if (state.clients[mac]) state.clients[mac]._flare = 1.0;

  termLine(
    `[Deauth] → Sending burst (x5) to <span class="term-deauth">${mac}</span> (${oui.vendor}) on ${state.bssid}`,
    "term-deauth"
  );

  // Trigger handshake capture attempt
  if (state.modules.handshake && !state.handshakeCaptured && !state.handshakeAttemptAt) {
    if (Math.random() < 0.35) {
      state.handshakeAttemptAt = Date.now();
      addTimer(() => attemptHandshake(mac), 2000 + Math.random() * 3000);
    }
  }
}

// ---- Handshake Capture ----
function attemptHandshake(mac) {
  if (!state.running) return;
  termLine(`[HandshakeCap] EAPOL re-auth triggered by deauth → monitoring ${state.bssid}...`, "term-info");
  addTimer(() => {
    const captured = Math.random() < 0.60;
    if (captured) {
      state.handshakeCaptured = true;
      $("sHandshake").textContent = "YES";
      $("sHandshake").style.color = "#00e5a0";
      pulse("statHandshake");
      termLine(`[HandshakeCap] ✅ WPA2 4-way EAPOL handshake captured! → captures/${state.bssid.replace(/:/g,"")}.cap`, "term-ok");
      if (state.modules.alerts) sendAlert("handshake", mac, null);
    } else {
      termLine(`[HandshakeCap] ⚠ Incomplete handshake — only ${Math.floor(Math.random()*3)+1}/4 EAPOL messages.`, "term-warn");
      state.handshakeAttemptAt = null; // retry allowed
    }
  }, 3000 + Math.random() * 2000);
}

// ---- Ghost AP ----
function startGhostAP() {
  if (!state.modules.ghost) return;
  state.ghostActive = true;
  $("ghostChip").textContent = "Active";
  $("ghostChip").className   = "chip success";
  $("sGhost").textContent    = 0;

  termLine(`[GhostAP] Generating 200 phantom SSIDs with randomized prefix '${randomFrom(GHOST_PREFIXES)}'...`, "term-module");

  const ghostList = $("ghostList");
  ghostList.innerHTML = "";

  let count = 0;
  const addGhost = () => {
    if (!state.running || count >= 18) return; // show 18 in UI, report 200
    const prefix = randomFrom(GHOST_PREFIXES);
    const suffix = randomFrom(SSID_SUFFIXES) + "_" + Math.floor(Math.random()*99).toString().padStart(2,"0");
    const ssid   = prefix + suffix;
    state.ghostAPs.push(ssid);
    count++;
    const fullCount = Math.min(200, count * 11);
    $("sGhost").textContent = fullCount;

    const item = document.createElement("div");
    item.className = "ghost-item";
    item.textContent = ssid;
    ghostList.appendChild(item);

    addTimer(addGhost, 180 + Math.random() * 120);
  };
  addGhost();

  termLine(`[GhostAP] Broadcasting 1000 beacons/sec on channel 6 with randomized AP MACs.`, "term-module");
}

// ---- Counter-Deauth (Beacon Protection) ----
function startBeaconProtection() {
  if (!state.modules.protect) return;
  termLine(`[BeaconProtect] Monitoring for deauth frames (0x000c) on ${state.bssid}...`, "term-info");

  let cooldowns = {};
  addInterval(() => {
    if (!state.running) return;
    if (Math.random() < 0.08) {
      const attackerMac = randomMac();
      const now = Date.now();
      if (cooldowns[attackerMac] && (now - cooldowns[attackerMac]) < 1000) return;
      cooldowns[attackerMac] = now;
      termLine(
        `[BeaconProtect] ⚠ Deauth attack detected from <span class="term-err">${attackerMac}</span>! Firing 50 counter-frames...`,
        "term-warn"
      );
    }
  }, 3000);
}

// ---- Cloud Alerts ----
function sendAlert(type, mac, oui) {
  if (!state.running) return;
  state.alertCount++;
  $("sAlerts").textContent = state.alertCount;
  pulse("statAlerts");

  let icon, msg;
  const ts = new Date().toLocaleTimeString("en-GB", {hour12: false});

  if (type === "new_client") {
    icon = "🔔";
    msg  = `New client: ${mac} (${oui?.vendor || "Unknown"}) on ${state.bssid}`;
    termLine(`[CloudAlerts] Discord → POST: new_client_detected | ${mac}`, "term-dim");
  } else if (type === "handshake") {
    icon = "🔑";
    msg  = `WPA2 Handshake captured on ${state.bssid}!`;
    termLine(`[CloudAlerts] Discord + Telegram → handshake_captured | ${state.bssid}`, "term-ok");
  } else if (type === "session_end") {
    icon = "📋";
    msg  = `Session ended. Deauths: ${state.deauthCount}, Duration: ${formatElapsed(Date.now() - state.startTime)}`;
    termLine(`[CloudAlerts] session_ended → Discord/Telegram notification sent.`, "term-dim");
  }

  const feed = $("alertFeed");
  // Remove empty state
  const empty = feed.querySelector(".empty-state");
  if (empty) empty.remove();

  const item = document.createElement("div");
  item.className = "alert-item";
  item.innerHTML = `
    <span class="alert-icon">${icon}</span>
    <span class="alert-msg">${msg}</span>
    <span class="alert-time">${ts}</span>
  `;
  feed.prepend(item);
}

// ---- Elapsed Clock ----
function tickClock() {
  if (!state.running) return;
  const elapsed = Date.now() - state.startTime;
  $("hdrElapsed").textContent = formatElapsed(elapsed);

  // Auto-stop when session time expires
  const remaining = state.sessionDuration * 1000 - elapsed;
  if (remaining <= 0) stopSimulation();
  else if (remaining < 10000 && remaining > 9000) {
    termLine(`⏱ Session ending in 10 seconds...`, "term-warn");
  }
}

// ---- Update Client UI ----
function updateClientUI() {
  const list = $("clientList");
  const empty = list.querySelector(".empty-state");
  if (empty) empty.remove();

  list.innerHTML = "";
  Object.entries(state.clients).forEach(([mac, info]) => {
    const item = document.createElement("div");
    item.className = `client-item ${info.status}`;
    const bars = Math.ceil((info.rssi + 100) / 20);
    const barHtml = Array(5).fill(0).map((_, i) => 
      `<div style="width:2px; height:${(i+1)*2}px; background:${i < bars ? 'var(--accent)' : 'var(--text-dim)'}; margin-right:1px"></div>`
    ).join("");

    item.innerHTML = `
      <div style="display:flex; flex-direction:column; align-items:center; gap:2px">
        <span style="font-size:16px">${info.icon}</span>
        <div style="display:flex; align-items:flex-end">${barHtml}</div>
      </div>
      <div style="flex:1;min-width:0">
        <div class="ci-mac">${mac}</div>
        <div class="ci-vendor">${info.vendor} · ${info.type}</div>
      </div>
      <span class="ci-badge ${info.status === "whitelisted" ? "safe" : "kick"}">
        ${info.status === "whitelisted" ? "SAFE" : "KICKED"}
      </span>
    `;
    list.appendChild(item);
  });
}

// ---- PCAP Report Modal ----
function showPcapReport() {
  const duration = Math.round((Date.now() - state.startTime) / 1000);
  const totalPkts = state.pcapFrames;
  const totalBytes = state.pcapBytes;
  const pps = totalPkts / duration;
  const bps = totalBytes / duration;
  const deauthCount = state.deauthCount;
  const disassoc = Math.floor(deauthCount * 0.4);
  const uniqueClients = Object.keys(state.clients).length;

  const body = $("modalBody");
  body.innerHTML = `
    <div class="report-banner ${state.handshakeCaptured ? "captured" : ""}">
      ${state.handshakeCaptured
        ? "🔑 WPA2 HANDSHAKE DETECTED — EAPOL CAPTURED"
        : "✅ SESSION COMPLETE — NO HANDSHAKE CAPTURED"}
    </div>

    <div class="report-section">
      <h4>📦 Traffic Volume</h4>
      <table class="report-table">
        <tr class="highlight"><td>Total Packets</td><td>${totalPkts.toLocaleString()}</td></tr>
        <tr><td>Total Bytes</td><td>${totalBytes.toLocaleString()} (${Math.round(totalBytes/1024).toLocaleString()} KB)</td></tr>
        <tr><td>Duration</td><td>${duration}s</td></tr>
        <tr class="highlight"><td>Avg PPS</td><td>${Math.round(pps).toLocaleString()}</td></tr>
        <tr><td>Avg BPS</td><td>${Math.round(bps).toLocaleString()}</td></tr>
      </table>
    </div>

    <div class="report-section">
      <h4>📡 Client Intelligence</h4>
      <table class="report-table">
        <tr><td>Unique Clients</td><td>${uniqueClients}</td></tr>
        ${Object.entries(state.clients).map(([mac, info]) =>
          `<tr><td style="font-family:var(--font-mono);font-size:11px">${mac}</td><td>${info.icon} ${info.vendor}</td></tr>`
        ).join("")}
      </table>
    </div>

    <div class="report-section">
      <h4>💥 Attack Frames</h4>
      <table class="report-table">
        <tr class="danger"><td>Deauth Frames (0x000c)</td><td>${deauthCount.toLocaleString()}</td></tr>
        <tr><td>Disassoc Frames (0x000a)</td><td>${disassoc.toLocaleString()}</td></tr>
        <tr><td>Total Attack Frames</td><td>${(deauthCount + disassoc).toLocaleString()}</td></tr>
      </table>
    </div>

    <div class="report-section">
      <h4>🔑 Handshake Analysis</h4>
      <table class="report-table">
        <tr class="${state.handshakeCaptured ? "highlight" : ""}">
          <td>WPA2 Handshake</td>
          <td>${state.handshakeCaptured ? "✅ YES — 4/4 EAPOL" : "❌ Not Captured"}</td>
        </tr>
        <tr><td>Ghost APs Broadcast</td><td>${state.ghostActive ? state.ghostAPs.length * 11 : 0}</td></tr>
        <tr><td>Cloud Alerts Sent</td><td>${state.alertCount}</td></tr>
        <tr><td>Capture File</td><td>captures/${state.bssid.replace(/:/g,"")}.cap</td></tr>
      </table>
    </div>
  `;

  $("reportModal").style.display = "flex";
}

function closeModal() {
  $("reportModal").style.display = "none";
}

// ---- Launch ----
function launchSimulation() {
  if (state.running) return;

  // Read config
  state.interface       = $("cfgInterface").value;
  state.bssid           = $("cfgBssid").value.split("—")[0].trim();
  state.sessionDuration = parseInt($("cfgTime").value, 10);
  state.whitelist       = $("cfgWhitelist").value
    .split(",").map(s => s.trim().toUpperCase()).filter(Boolean);

  state.modules = {
    ghost:       $("modGhost").checked,
    protect:     $("modProtect").checked,
    handshake:   $("modHandshake").checked,
    fingerprint: $("modFingerprint").checked,
    alerts:      $("modAlerts").checked,
    analyze:     $("modAnalyze").checked,
  };

  // Reset state
  state.running          = true;
  state.startTime        = Date.now();
  state.pps              = 100;
  state.ppsHistory       = [];
  state.clients          = {};
  state.ghostAPs         = [];
  state.ghostActive      = false;
  state.deauthCount      = 0;
  state.alertCount       = 0;
  state.handshakeCaptured= false;
  state.handshakeAttemptAt= null;
  state.pcapFrames       = 0;
  state.pcapBytes        = 0;
  state._timers          = [];
  state._intervals       = [];

  // Reset UI
  clearTerminal();
  $("clientList").innerHTML  = '<div class="empty-state">Scanning...</div>';
  $("ghostList").innerHTML   = '<div class="empty-state">Starting...</div>';
  $("alertFeed").innerHTML   = '<div class="empty-state">Listening...</div>';
  $("sDeauth").textContent   = 0;
  $("sClients").textContent  = 0;
  $("sPps").textContent      = "—";
  $("sGhost").textContent    = 0;
  $("sHandshake").textContent= "—";
  $("sHandshake").style.color= "";
  $("sAlerts").textContent   = 0;
  $("ghostChip").textContent = "Starting";
  $("ghostChip").className   = "chip warning";
  $("clientChip").textContent= "0 online";
  $("hdrIface").textContent  = state.interface;
  $("hdrBssid").textContent  = state.bssid;
  $("hdrPps").textContent    = 100;

  const pill = $("statusPill");
  const dot  = pill.querySelector(".dot");
  $("statusText").textContent = "RUNNING";
  dot.className = "dot dot-running";

  $("btnLaunch").disabled = true;
  $("btnStop").disabled   = false;

  // ---- Boot Sequence ----
  termRaw(`<span class="term-dim">══════════════════════════════════════════════</span>`);
  termRaw(`<span class="term-ok" style="font-size:13px;font-weight:700">  PacketLoop v2.1.0 — Session Starting</span>`);
  termRaw(`<span class="term-dim">══════════════════════════════════════════════</span>`);

  addTimer(() => termLine(`[Init] Checking root privileges... <span class="term-ok">OK</span>`), 200);
  addTimer(() => termLine(`[Init] Verifying tool dependencies (aireplay-ng, tcpreplay)... <span class="term-ok">OK</span>`), 600);
  addTimer(() => termLine(`[Init] Setting <span class="term-info">${state.interface}</span> to monitor mode via airmon-ng...`), 1000);
  addTimer(() => termLine(`[Init] Monitor mode active: <span class="term-ok">${state.interface}</span>`, "term-ok"), 1600);
  addTimer(() => termLine(`[Init] Target BSSID: <span class="term-info">${state.bssid}</span>`), 2000);
  addTimer(() => termLine(`[Init] Session duration: <span class="term-info">${state.sessionDuration}s</span>`), 2200);
  addTimer(() => {
    const wl = state.whitelist.length ? state.whitelist.join(", ") : "None";
    termLine(`[Init] Whitelist loaded: <span class="term-ok">${wl}</span>`);
  }, 2400);

  // Module startup
  let offset = 2800;
  const modNames = {
    handshake:   "[HandshakeCap] airodump-ng capture thread started",
    ghost:       "[GhostAP] mdk4 beacon flood process spawned",
    protect:     "[BeaconProtect] tshark sniffer armed on 0x000c frames",
    fingerprint: "[Fingerprint] OUI database loaded (18 known vendors)",
    alerts:      "[CloudAlerts] Discord + Telegram endpoints configured",
    analyze:     "[PcapAnalyzer] Post-session tshark analysis scheduled",
  };
  Object.entries(state.modules).forEach(([key, enabled]) => {
    if (enabled && modNames[key]) {
      addTimer(() => termLine(`${modNames[key]}`, "term-module"), offset);
      offset += 300;
    }
  });

  addTimer(() => {
    termRaw(`<span class="term-dim">──────────────────────────────────────────────</span>`);
    termLine(`[Core] All modules initialized. Starting injection loop...`, "term-ok");
    termLine(`[Core] ARP Replay → aireplay-ng -3 -b ${state.bssid} -x ${state.pps} ${state.interface}`, "term-dim");
    termLine(`[Core] <span class="term-ok">Turbo Mode engaged. 🔥</span>`);
    termRaw(`<span class="term-dim">──────────────────────────────────────────────</span>`);

    // Start engines
    addInterval(tickPps,       2000);
    addInterval(tickClock,     1000);
    addInterval(discoverClient, 4000 + Math.random() * 2000);

    // Stagger first 3 clients quickly so UI looks alive
    addTimer(() => discoverClient(), 500);
    addTimer(() => discoverClient(), 1500);
    addTimer(() => discoverClient(), 3000);

    if (state.modules.ghost)   startGhostAP();
    if (state.modules.protect) startBeaconProtection();

    // Start Topology render
    drawTopology();

  }, offset + 300);
}

// ---- Stop ----
function stopSimulation() {
  if (!state.running) return;
  state.running = false;

  // Kill all timers
  state._timers.forEach(t => clearTimeout(t));
  state._intervals.forEach(i => clearInterval(i));

  const pill = $("statusPill");
  const dot  = pill.querySelector(".dot");
  $("statusText").textContent = "DONE";
  dot.className = "dot dot-done";

  $("btnLaunch").disabled = false;
  $("btnStop").disabled   = true;
  $("ppsChip").textContent = "STOPPED";
  $("ppsChip").className  = "chip";
  $("ghostChip").textContent = "Stopped";
  $("ghostChip").className   = "chip";

  termRaw(`<span class="term-dim">──────────────────────────────────────────────</span>`);
  termLine(`[Core] Stopping all injection processes...`, "term-warn");
  termLine(`[Core] Terminating aireplay-ng subprocess(es).`);
  if (state.modules.ghost)   termLine(`[GhostAP] mdk4 process terminated. Temp SSID file removed.`);
  if (state.modules.protect) termLine(`[BeaconProtect] tshark sniffer stopped.`);
  if (state.modules.handshake && state.handshakeCaptured)
    termLine(`[HandshakeCap] Capture saved → captures/${state.bssid.replace(/:/g,"")}.cap`, "term-ok");
  if (state.modules.alerts)
    sendAlert("session_end", null, null);

  const duration = formatElapsed(Date.now() - state.startTime);
  termLine(`[AdaptivePPS] Final PPS: ${state.pps}. Session duration: ${duration}.`, "term-dim");
  termRaw(`<span class="term-dim">──────────────────────────────────────────────</span>`);
  termLine(`[Core] <span class="term-ok">PacketLoop session complete. ✅</span>`);
  termLine(`[Core] Total deauths sent: <span class="term-err">${state.deauthCount}</span>  |  Clients discovered: ${Object.keys(state.clients).length}`);

  if (state.modules.analyze) {
    termLine(`[PcapAnalyzer] Generating post-session PCAP report...`, "term-info");
    setTimeout(() => {
      termLine(`[PcapAnalyzer] <span class="term-ok">Report ready. Opening...</span>`);
      showPcapReport();
    }, 1800);
  }
}

// ---- UI Bindings ----
document.addEventListener("DOMContentLoaded", () => {
  // Duration slider live update
  const slider = $("cfgTime");
  const sliderVal = $("cfgTimeVal");
  slider.addEventListener("input", () => {
    sliderVal.textContent = slider.value + "s";
  });

  // Draw empty chart on load
  drawPpsChart();

  // Keyboard shortcut: Enter = launch
  document.addEventListener("keydown", e => {
    if (e.key === "Escape") closeModal();
  });
});
