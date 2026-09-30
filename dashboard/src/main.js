import ForceGraph3D from "3d-force-graph";
import * as THREE from "three";
import SpriteText from "three-spritetext";

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;

const LAMPS = ["#17B26A", "#F5B400", "#F5701E", "#E5222D"];
const LEVELS = {
  clean: { i: 0, label: "Clean", tone: LAMPS[0] },
  suspicious: { i: 1, label: "Suspicious", tone: LAMPS[1] },
  likely_malicious: { i: 2, label: "Likely malicious", tone: LAMPS[2] },
  malicious: { i: 3, label: "Malicious", tone: LAMPS[3] },
  inconclusive: { i: -1, label: "Inconclusive", tone: "#8C958F" },
};
const SEV = { critical: ["#E5222D", "#fff"], high: ["#F5701E", "#13171A"], medium: ["#F5B400", "#13171A"], low: ["#9CCFC1", "#13171A"], info: ["var(--sunk)", "var(--muted)"] };
const KIND = {
  sample: { color: "#FFFFFF", label: "Sample", icon: "i-file" },
  process: { color: "#FFB020", label: "Processes", icon: "i-process" },
  file: { color: "#4FD8E8", label: "Files", icon: "i-file" },
  network: { color: "#FF6E8A", label: "Network", icon: "i-net" },
};
const SINGULAR = { process: "Process", file: "File", network: "Network", sample: "Sample" };

const state = { reports: [], current: null, tab: "evidence", hidden: new Set(), query: "", graph: null, graphData: null, rotate: true, pinned: false, token: 0 };

const levelOf = (d) => (d?.status === "failed" ? LEVELS.inconclusive : LEVELS[d?.verdict?.level] || LEVELS.inconclusive);
const short = (h) => (h ? h.slice(0, 8) + "…" + h.slice(-6) : "");
function when(iso) {
  try {
    const d = new Date(iso), now = new Date();
    return d.toDateString() === now.toDateString() ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : d.toLocaleDateString([], { month: "short", day: "numeric" });
  } catch { return ""; }
}
function toast(msg) {
  const t = document.createElement("div"); t.className = "toast"; t.textContent = msg; document.body.appendChild(t); setTimeout(() => t.remove(), 1400);
}
const copy = (text) => navigator.clipboard?.writeText(text).then(() => toast("Copied"), () => {});
async function api(path, opts) { const r = await fetch(path, opts); if (!r.ok) throw new Error(r.status); return r.json(); }
const icon = (id, s = 16) => `<svg width="${s}" height="${s}"><use href="#${id}"/></svg>`;

// ---------- stack light ----------
function tower() {
  let s = `<svg class="tower-svg" viewBox="0 0 64 172" aria-hidden="true"><rect class="metal" x="17" y="1" width="30" height="9" rx="4.5"/>`;
  for (let k = 0; k < 4; k++) {
    const i = 3 - k, y = 11 + k * 35;
    s += `<g class="lamp" data-i="${i}" style="--c:${LAMPS[i]}"><rect class="lens" x="7" y="${y}" width="50" height="32" rx="8"/><g class="ribs"><path d="M7 ${y + 11}h50M7 ${y + 21}h50"/></g><rect class="gloss" x="13" y="${y + 4}" width="5" height="24" rx="2.5"/></g>`;
  }
  return s + `<rect class="metal" x="3" y="151" width="58" height="12" rx="4"/><rect class="metal" x="12" y="163" width="40" height="7" rx="3"/></svg>`;
}
function powerOn(root, lit, token) {
  const lamps = [...root.querySelectorAll(".lamp")];
  const at = (i) => lamps.find((l) => +l.dataset.i === i);
  const set = (i) => { if (token !== state.token) return; lamps.forEach((l) => l.classList.remove("on")); if (i >= 0) at(i).classList.add("on"); };
  if (reduce) return set(lit);
  const sweep = [0, 1, 2, 3].filter((i) => i <= Math.max(lit, 0));
  sweep.forEach((i, k) => setTimeout(() => set(i), 120 + k * 150));
  setTimeout(() => set(lit), 120 + sweep.length * 150 + 60);
}

// ---------- copy ----------
const PHRASE = {
  escape: "probed for a way out of the sandbox", persistence: "tried to make itself run again later",
  "sensitive-files": "read credential or system files", network: "tried to reach the network",
  "net-tools": "ran download or remote-access tools", listener: "opened a listening port",
  "hidden-files": "created hidden files", "fs-write": "wrote outside its temp folder",
  "fs-tamper": "deleted or changed files", timeout: "ran past the time limit", killed: "was stopped by the system",
};
function list(a) { return a.length <= 1 ? a.join("") : a.slice(0, -1).join(", ") + " and " + a[a.length - 1]; }
function summarize(d) {
  if (d.status === "failed") return d.error || "The analysis did not finish.";
  const parts = [];
  for (const f of d.findings || []) {
    if (f.id === "children") { const n = parseInt((f.title.match(/\d+/) || [0])[0], 10); if (n) parts.push(`started ${n} other program${n > 1 ? "s" : ""}`); }
    else if (PHRASE[f.id]) parts.push(PHRASE[f.id]);
  }
  if (!parts.length) return "Nothing suspicious happened while it ran.";
  let s = "It " + list(parts) + ".";
  const acts = (d.events || []).filter((e) => e.type !== "process");
  const blocked = acts.filter((e) => e.blocked).length;
  if (blocked) s += ` The sandbox blocked ${blocked} of ${acts.length} file and network actions.`;
  return s;
}

// ---------- sidebar ----------
function renderList() {
  const q = state.query.toLowerCase();
  const rows = state.reports.filter((r) => !q || (r.sample?.name || "").toLowerCase().includes(q) || (r.sample?.sha256 || "").includes(q));
  $("#count").textContent = state.reports.length;
  $("#list").innerHTML = rows.map((r) => {
    const l = levelOf(r), failed = r.status === "failed";
    return `<button class="item" data-id="${esc(r.id)}" aria-current="${state.current?.id === r.id}">
      <span class="led" style="--c:${l.tone}"></span>
      <span class="info"><span class="nm">${esc(r.sample?.name || "Unknown")}</span><span class="sub">${failed ? "Failed" : esc(l.label)}</span></span>
      <span class="meta"><span class="sc">${failed ? "!" : esc(r.verdict?.score ?? "–")}</span><span class="tm">${esc(when(r.created_at))}</span></span></button>`;
  }).join("") || `<div class="none" style="padding:14px">No matches</div>`;
}

async function refresh(first) {
  let list;
  try { list = await api("/api/reports"); $("#offline").hidden = true; } catch { $("#offline").hidden = false; return; }
  const changed = JSON.stringify(list.map((r) => r.id)) !== JSON.stringify(state.reports.map((r) => r.id));
  state.reports = list;
  $("#empty").hidden = list.length > 0;
  if (!list.length) { state.current = null; renderList(); return; }
  if (changed || first) {
    renderList();
    const there = state.current && list.some((r) => r.id === state.current.id);
    if (first || !there || (changed && list[0].id !== state.current?.id && !state.pinned)) await select(list[0].id);
  }
}

async function select(id, pin) {
  if (pin) state.pinned = id !== state.reports[0]?.id;
  state.current = await api("/api/report/" + encodeURIComponent(id));
  state.token++;
  $("#nodeCard").hidden = true;
  renderList(); renderHead(); renderReadout(); renderPanel(); buildGraph();
}

// ---------- head + readout ----------
function renderHead() {
  const d = state.current;
  $("#fname").textContent = d.sample?.name || "Unknown";
  $("#ftype").textContent = d.sample?.type || "";
  $("#hashText").textContent = short(d.sample?.sha256);
  const lim = d.run?.limits || {};
  const bits = [lim.network === "none" ? "No network" : null, lim.filesystem === "read-only" ? "read-only disk" : null, lim.memory_mb ? `${lim.memory_mb} MB` : null, lim.cpus ? `${lim.cpus} CPU` : null, lim.timeout_s ? `${lim.timeout_s} s limit` : null].filter(Boolean);
  $("#spec").innerHTML = bits.length ? icon("i-lock", 14) + esc(bits.join(", ")) : "";
}

function count(el, to, ms = 900) {
  if (reduce) { el.textContent = to; return; }
  const t0 = performance.now();
  const step = (t) => { const p = Math.min(1, (t - t0) / ms), e = 1 - Math.pow(1 - p, 3); el.textContent = Math.round(to * e); if (p < 1 && el.isConnected) requestAnimationFrame(step); };
  requestAnimationFrame(step);
}

function renderReadout() {
  const d = state.current, failed = d.status === "failed", L = levelOf(d);
  const score = failed ? null : d.verdict?.score ?? 0;
  const root = $("#readout");
  root.dataset.level = failed ? "inconclusive" : d.verdict?.level || "inconclusive";
  const bounds = [[0, 15], [15, 40], [40, 70], [70, 100]], names = ["Clean", "Suspicious", "Likely", "Malicious"];
  const label = failed ? "Analysis failed" : d.verdict?.label || L.label;
  root.innerHTML = `
    <div class="ro-top">
      <div class="tower">${tower()}</div>
      <div>
        <div class="vrow"><div class="verdict ${label.length > 12 ? "long" : ""}">${esc(label)}</div><div class="score"><b id="scoreNum">${failed ? "–" : 0}</b><span>/100</span></div></div>
        <p class="summary">${esc(summarize(d))}</p>
      </div>
    </div>
    <div class="gauge">
      <div class="needle" id="needle" ${failed ? "hidden" : ""}></div>
      <div class="track">${bounds.map(([a, b], i) => `<div class="seg" style="--c:${LAMPS[i]}"><i data-w="${score == null ? 0 : Math.max(0, Math.min(1, (score - a) / (b - a))) * 100}"></i></div>`).join("")}</div>
      <div class="segnames">${names.map((n) => `<span>${n}</span>`).join("")}</div>
    </div>`;
  const token = state.token;
  powerOn(root, L.i, token);
  if (score != null) count($("#scoreNum"), score);
  requestAnimationFrame(() => requestAnimationFrame(() => {
    if (token !== state.token) return;
    root.querySelectorAll(".seg i").forEach((i) => (i.style.width = i.dataset.w + "%"));
    const n = $("#needle"); if (n && score != null) n.style.left = Math.min(100, score) + "%";
  }));
}

// ---------- tabs ----------
function renderPanel() {
  const d = state.current, p = $("#panel");
  document.querySelectorAll("#tabs button").forEach((b) => b.setAttribute("aria-selected", b.dataset.tab === state.tab));
  if (state.tab === "evidence") {
    const fs = d.findings || [];
    const rows = fs.map((f) => { const [bg, fg] = SEV[f.severity] || SEV.info; return `<div class="f"><div class="pts" style="--sev:${bg};--on-sev:${fg}">+${f.points}</div><div><div class="t">${esc(f.title)}</div><div class="d">${esc(f.detail)}</div></div></div>`; }).join("");
    const run = d.run || {};
    p.innerHTML = (rows || `<div class="none" style="padding:14px 0">No suspicious behavior was recorded.</div>`)
      + (d.status === "failed" ? "" : `<div class="total"><span>Risk score</span><b>${esc(d.verdict?.score ?? 0)}</b></div>`)
      + `<dl class="runlist"><dt>Exit code</dt><dd>${esc(run.exit_code ?? "–")}${run.timed_out ? " (timed out)" : ""}</dd><dt>Run time</dt><dd>${run.duration_ms ? (run.duration_ms / 1000).toFixed(1) + " s" : "–"}</dd><dt>Source</dt><dd>${run.image === "replay" ? "Saved trace, no container" : esc(run.image || "–")}</dd></dl>
         <div class="note">Heuristic triage from observed behavior. It is not an antivirus verdict.</div>`;
  } else if (state.tab === "timeline") {
    const rows = (d.events || []).map((e) => `<div class="ev" style="--k:${KIND[e.type]?.color}"><span class="ic">${icon(KIND[e.type]?.icon || "i-file", 17)}</span>
      <div style="min-width:0"><div class="b">${esc(e.label)}</div><div class="m">${esc(e.detail)}</div></div>
      <span class="r">${e.blocked ? `<span class="pill ok">Blocked</span>` : ""}${["high", "critical"].includes(e.severity) ? `<span class="pill hot">High risk</span>` : ""}</span></div>`).join("");
    p.innerHTML = rows ? `<div class="tl">${rows}</div>` : `<div class="none" style="padding:14px 0">No behavior was recorded.</div>`;
  } else if (state.tab === "iocs") {
    const i = d.iocs || {};
    const grp = (t, a = []) => `<div class="grp">${t}<span>${a.length}</span></div>` + (a.map((x) => `<div class="ioc"><span>${esc(x)}</span><button data-copy="${esc(x)}" aria-label="Copy" title="Copy">${icon("i-copy", 15)}</button></div>`).join("") || `<div class="none">None found</div>`);
    p.innerHTML = grp("Network", i.network) + grp("Files", i.files) + grp("Processes", i.processes) + grp("Sample hash", [d.sample?.sha256].filter(Boolean));
  } else {
    p.innerHTML = `<div class="grp">Program output</div><pre class="term">${esc(d.output || "(no output)")}</pre><div class="grp">Full trace</div><pre class="term">${esc(d.raw_log || "(empty)")}</pre>`;
  }
}

// ---------- 3D chamber ----------
const glowCache = {};
function glowTex(color) {
  if (glowCache[color]) return glowCache[color];
  const c = document.createElement("canvas"); c.width = c.height = 128;
  const g = c.getContext("2d"), r = g.createRadialGradient(64, 64, 0, 64, 64, 64);
  r.addColorStop(0, color + "e6"); r.addColorStop(0.3, color + "55"); r.addColorStop(1, color + "00");
  g.fillStyle = r; g.fillRect(0, 0, 128, 128);
  return (glowCache[color] = new THREE.CanvasTexture(c));
}
function ringTex(color) {
  const c = document.createElement("canvas"); c.width = c.height = 128;
  const g = c.getContext("2d"); g.strokeStyle = color; g.lineWidth = 4; g.beginPath(); g.arc(64, 64, 56, 0, Math.PI * 2); g.stroke();
  return new THREE.CanvasTexture(c);
}
const pulsers = [];

function makeGraphData(d) {
  const nodes = [], links = [];
  const root = { id: "root", kind: "sample", label: d.sample?.name || "sample", detail: `The sample. ${d.sample?.type || ""}`.trim() };
  nodes.push(root);
  const byPid = new Map(), seen = new Map();
  for (const e of d.events || []) {
    if (e.type !== "process") continue;
    const n = { id: `p${nodes.length}`, kind: "process", label: e.label, detail: e.detail, severity: e.severity, blocked: e.blocked };
    nodes.push(n); byPid.set(e.pid, n); links.push({ source: root.id, target: n.id });
  }
  for (const e of d.events || []) {
    if (e.type === "process") continue;
    const k = `${e.type}|${e.label}`; if (seen.has(k)) continue;
    const n = { id: `n${nodes.length}`, kind: e.type, label: e.label, detail: e.detail, severity: e.severity, blocked: e.blocked };
    seen.set(k, n); nodes.push(n); links.push({ source: (byPid.get(e.pid) || root).id, target: n.id });
  }
  return { nodes, links };
}
function visible() {
  const g = state.graphData || { nodes: [], links: [] };
  const nodes = g.nodes.filter((n) => n.kind === "sample" || !state.hidden.has(n.kind));
  const ids = new Set(nodes.map((n) => n.id));
  return { nodes, links: g.links.filter((l) => ids.has(l.source.id ?? l.source) && ids.has(l.target.id ?? l.target)) };
}
function renderFilters() {
  $("#filters").innerHTML = ["process", "file", "network"].map((k) => `<button class="chip" data-kind="${k}" aria-pressed="${!state.hidden.has(k)}" style="--k:${KIND[k].color}"><i></i>${KIND[k].label}</button>`).join("");
}
function nodeObject(n) {
  const grp = new THREE.Group(), hot = n.severity === "high" || n.severity === "critical";
  const tone = levelOf(state.current).tone;
  const color = n.kind === "sample" ? "#FFFFFF" : KIND[n.kind].color;
  const r = n.kind === "sample" ? 8 : hot ? 5.6 : 4.6;
  grp.add(new THREE.Mesh(new THREE.SphereGeometry(r, 28, 28), new THREE.MeshBasicMaterial({ color })));
  const haloColor = n.kind === "sample" ? tone : color;
  const halo = new THREE.Sprite(new THREE.SpriteMaterial({ map: glowTex(haloColor), blending: THREE.AdditiveBlending, depthWrite: false, transparent: true, opacity: n.blocked ? 0.55 : 1 }));
  halo.scale.setScalar(r * (n.kind === "sample" ? 11 : 7)); grp.add(halo);
  if (n.kind === "sample") {
    const ring = new THREE.Sprite(new THREE.SpriteMaterial({ map: ringTex(tone), transparent: true, depthWrite: false, opacity: 0.8 }));
    ring.scale.setScalar(r * 4); ring.userData.base = r * 4; grp.add(ring); pulsers.push(ring);
  }
  const text = n.label.length > 26 ? n.label.slice(0, 25) + "…" : n.label;
  const t = new SpriteText(n.blocked && n.kind === "network" ? text + " (blocked)" : text, n.kind === "sample" ? 6.4 : 4.8, "#E6F4EE");
  t.fontFace = "Archivo, sans-serif"; t.fontWeight = n.kind === "sample" ? "700" : "600"; t.position.y = -(r + 7); t.material.depthWrite = false; grp.add(t);
  return grp;
}
function setRotate(on) {
  state.rotate = on;
  const c = state.graph?.controls(); if (c) c.autoRotate = on;
  const b = $("#rot"); b.setAttribute("aria-pressed", on);
  b.innerHTML = `${icon(on ? "i-pause" : "i-play", 14)}<span>${on ? "Pause rotation" : "Resume rotation"}</span>`;
}
function buildGraph() {
  const d = state.current;
  state.graphData = makeGraphData(d);
  pulsers.length = 0;
  renderFilters();
  const el = $("#graph");
  if (!state.graph) {
    state.graph = ForceGraph3D({ controlType: "orbit", rendererConfig: { antialias: true, alpha: true } })(el)
      .backgroundColor("rgba(0,0,0,0)").showNavInfo(false).nodeLabel(() => "")
      .linkColor(() => "rgba(200,235,225,0.32)").linkOpacity(0.6).linkWidth(0.5)
      .linkDirectionalParticles(2).linkDirectionalParticleWidth(1.4).linkDirectionalParticleSpeed(0.007)
      .linkDirectionalParticleColor((l) => KIND[(l.target.kind || "file")]?.color || "#fff")
      .onNodeClick(pick).onBackgroundClick(() => ($("#nodeCard").hidden = true));
    state.graph.d3Force("charge").strength(-240); state.graph.d3Force("link").distance(52);
    const dust = new THREE.BufferGeometry(), pos = [];
    for (let i = 0; i < 380; i++) { const r = 260 + Math.random() * 520, a = Math.random() * 6.283, b = Math.acos(2 * Math.random() - 1); pos.push(r * Math.sin(b) * Math.cos(a), r * Math.sin(b) * Math.sin(a), r * Math.cos(b)); }
    dust.setAttribute("position", new THREE.Float32BufferAttribute(pos, 3));
    state.graph.scene().add(new THREE.Points(dust, new THREE.PointsMaterial({ color: 0xa8e0d2, size: 2.2, map: glowTex("#a8e0d2"), transparent: true, opacity: 0.55, sizeAttenuation: false, depthWrite: false, blending: THREE.AdditiveBlending })));
    const floor = new THREE.PolarGridHelper(190, 16, 6, 64, 0x6fbfae, 0x3f8a7c); floor.position.y = -95;
    (Array.isArray(floor.material) ? floor.material : [floor.material]).forEach((m) => { m.transparent = true; m.opacity = 0.22; m.depthWrite = false; });
    state.graph.scene().add(floor);
    const c = state.graph.controls(); c.autoRotateSpeed = 1.2; c.enableDamping = true; c.addEventListener("start", () => setRotate(false));
    new ResizeObserver(size).observe($("#glass"));
    (function loop(t) { pulsers.forEach((s) => { const k = 1 + 0.16 * Math.sin(t / 420); s.scale.setScalar(s.userData.base * k); s.material.opacity = 0.85 - 0.45 * (k - 0.84) / 0.32; }); requestAnimationFrame(loop); })(0);
  }
  state.graph.nodeThreeObject(nodeObject).graphData(visible());
  setRotate(state.rotate); size();
  setTimeout(() => state.graph.zoomToFit(700, 40), 1000);
}
function size() { const g = $("#glass"); state.graph?.width(g.clientWidth).height(g.clientHeight); }
function pick(n) {
  const c = $("#nodeCard");
  c.innerHTML = `<button class="x" id="closeNode" aria-label="Close">×</button><h3>${esc(n.label)}</h3>
    <div class="kind" style="--k:${KIND[n.kind].color}"><i></i>${SINGULAR[n.kind]}${n.blocked ? `<span class="tagpill ok">Blocked</span>` : ""}${n.severity && n.severity !== "info" ? `<span class="tagpill">${esc(n.severity)} risk</span>` : ""}</div>
    <p>${esc(n.detail)}</p>`;
  c.hidden = false; setRotate(false);
  const r = 1 + 90 / Math.hypot(n.x, n.y, n.z || 1);
  state.graph.cameraPosition({ x: n.x * r, y: n.y * r, z: n.z * r }, n, 800);
}

// ---------- events ----------
document.addEventListener("click", async (e) => {
  const t = e.target.closest("button");
  if (!t) return;
  if (t.dataset.copy) return copy(t.dataset.copy);
  if (t.classList.contains("item")) return select(t.dataset.id, true);
  if (t.dataset.tab) { state.tab = t.dataset.tab; return renderPanel(); }
  if (t.dataset.kind) { state.hidden.has(t.dataset.kind) ? state.hidden.delete(t.dataset.kind) : state.hidden.add(t.dataset.kind); renderFilters(); return state.graph.graphData(visible()); }
  if (t.id === "closeNode") return ($("#nodeCard").hidden = true);
  if (t.id === "rot") return setRotate(!state.rotate);
  if (t.id === "hash") return copy(state.current?.sample?.sha256 || "");
  if (t.id === "theme") {
    const h = document.documentElement, next = h.dataset.theme === "light" ? "dark" : "light";
    h.dataset.theme = next; try { localStorage.setItem("amas-theme", next); } catch {}
    t.innerHTML = icon(next === "light" ? "i-moon" : "i-sun", 18); return;
  }
  if (t.id === "export" && state.current) {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(state.current, null, 2)], { type: "application/json" }));
    a.download = `amas-${state.current.id}.json`; a.click(); return;
  }
  if (t.id === "clear") {
    if (!confirm("Delete all saved analyses? This can't be undone.")) return;
    await api("/api/reports", { method: "DELETE" }); state.current = null; state.reports = []; state.pinned = false; refresh(true);
  }
});
$("#q").addEventListener("input", (e) => { state.query = e.target.value; renderList(); });

try { const s = localStorage.getItem("amas-theme"); if (s) { document.documentElement.dataset.theme = s; $("#theme").innerHTML = icon(s === "light" ? "i-moon" : "i-sun", 18); } } catch {}
$("#emptyTower").innerHTML = tower();
refresh(true);
setInterval(refresh, 3000);
