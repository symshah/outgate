// OutboundWin offline map/globe. No network: Leaflet + bundled imagery (NASA Blue Marble,
// Natural Earth II relief), d3-geo for great-circle arcs, globe.gl for the 3D globe.
"use strict";

// Colour set per APP theme (Settings › Appearance). Aurora is the default: mint = allowed,
// coral = blocked, cyan = chart. The map imagery itself comes from the bundled raster layers.
const APP_PALETTES = {
  Aurora:   { bg:"#0D0F1A", arc:"#34D399", blocked:"#FB7185", point:"#34D399", chart:"#22D3EE" },
  Midnight: { bg:"#0B1322", arc:"#4da3ff", blocked:"#E5484D", point:"#7cc4ff", chart:"#4da3ff" },
  Dark:     { bg:"#1b1c1f", arc:"#4da3ff", blocked:"#ef4444", point:"#7cc4ff", chart:"#4da3ff" },
  Light:    { bg:"#eef2f7", arc:"#1d4ed8", blocked:"#dc2626", point:"#1e3a8a", chart:"#1d4ed8" },
};
function pal() { return APP_PALETTES[state.appTheme] || APP_PALETTES.Dark; }

// Legacy theme table kept for backwards compatibility with older payloads.
const THEMES = {
  graphite:   { bg:"#1b1c1f", land:"#2e3036", landStroke:"#45484f", ocean:null,    arc:"#4da3ff", blocked:"#ef4444", point:"#7cc4ff" },
  bluemarble: { bg:"#0a1a33", land:"#1d3a63", landStroke:"#2c5288", ocean:null,    arc:"#ffd166", blocked:"#ef4444", point:"#9ecbff" },
  midnight:   { bg:"#0b0e17", land:"#1a2030", landStroke:"#2a3350", ocean:null,    arc:"#8ab4ff", blocked:"#ff5d5d", point:"#bcd6ff" },
  daylight:   { bg:"#eef2f7", land:"#c9d4e0", landStroke:"#a8b6c6", ocean:null,    arc:"#1d4ed8", blocked:"#dc2626", point:"#1e3a8a" },
  amber:      { bg:"#171310", land:"#33291f", landStroke:"#54452f", ocean:null,    arc:"#ffb454", blocked:"#ff6b4a", point:"#ffd9a0" },
};

const state = {
  theme: "graphite",
  appTheme: "Dark",       // System | Light | Dark | Midnight — pushed from the app so the map follows it
  mapStyle: "satellite",  // 'satellite' | 'standard' | 'muted'  (SPEC-UI §0.3)
  mode: "2d",             // '2d' | '3d'
  data: null,             // last pushed payload
  window: null,           // [minIdx0, minIdx1] filter from chart drag (absolute UTC minute indices)
  places: [],             // aggregated city rows
};

let globeEl = null, globeInstance = null;
const viz = document.getElementById("viz");
const tip = document.getElementById("tip");

// ---------- data push from C# ----------
window.__push = function (payload) {
  if (typeof payload === "string") payload = JSON.parse(payload); // injected via ExecuteScriptAsync
  state.data = payload;
  if (payload.theme) { state.appTheme = payload.theme; applyAppTheme(); }
  aggregatePlaces();
  renderAll(false);
};

// The app's Settings › Appearance theme drives the page chrome (Midnight = navy map background).
function applyAppTheme() {
  document.body.classList.toggle("aurora", state.appTheme === "Aurora");
  document.body.classList.toggle("midnight", state.appTheme === "Midnight");
  document.body.classList.toggle("light", state.appTheme === "Light");
  if (globeInstance) {
    try { globeInstance.backgroundColor(state.appTheme === "Aurora" ? "#0D0F1A" : (state.appTheme === "Midnight" ? "#0B1322" : "#04060c")); } catch (e) { }
  }
}

function inWindow(d) {
  if (!state.window || !d.lastSeenMin) return true;
  return d.lastSeenMin >= state.window[0] && d.lastSeenMin <= state.window[1];
}

// Aggregate destinations into city rows (arcs + list share this).
function aggregatePlaces() {
  const p = state.data;
  if (!p) { state.places = []; return; }
  const byCity = new Map();
  for (const d of p.dests) {
    if (d.lat == null || d.lon == null) continue; // local/unknown — no coordinates
    if (!inWindow(d)) continue;
    const k = (d.city || "?") + "|" + (d.country || "");
    let row = byCity.get(k);
    if (!row) { row = { city:d.city, country:d.country, cc:d.cc, lat:d.lat, lon:d.lon, bytes:0, blocked:false, apps:new Set(), hosts:[] }; byCity.set(k, row); }
    row.bytes += d.bytes;
    if (d.blocked) row.blocked = true;
    row.apps.add(d.app);
    if (row.hosts.length < 3 && d.host) row.hosts.push(d.host);
  }
  state.places = [...byCity.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 40);
}

function fmtBytes(b) {
  if (b < 1024) return b + " B";
  if (b < 1048576) return (b / 1024).toFixed(1) + " KB";
  if (b < 1073741824) return (b / 1048576).toFixed(1) + " MB";
  return (b / 1073741824).toFixed(2) + " GB";
}

// ---------- 2D map: Leaflet + bundled raster imagery (no tiles, no network) ----------
let countries = null;    // GeoJSON FeatureCollection, loaded once (borders + coastlines)
let lmap = null;
let rasterLayer = null, bordersLayer = null, arcsLayer = null, dotsLayer = null, labelsLayer = null, originLayer = null;
let userMoved = false;    // the user panned/zoomed — their view is kept; auto-fit stops
let programmatic = false; // true while WE call fitBounds/setView, so those don't count as user moves

/// Move the map ourselves with the guard set, so the move is not mistaken for a user interaction.
function moveMap(fn) { programmatic = true; try { fn(); } finally { programmatic = false; } }

// Satellite = NASA Blue Marble (topography + bathymetry, public domain), Standard = Natural Earth II
// shaded relief with water (public domain). Both bundled at 8192x4096 equirectangular; Muted is the
// satellite image desaturated + darkened. Colours are applied as CSS filters on the raster layer.
const RASTERS = {
  satellite: { url: "bluemarble.jpg", className: "raster-satellite" },
  standard:  { url: "ne2-relief.jpg", className: "raster-standard" },
  muted:     { url: "bluemarble.jpg", className: "raster-muted" },
};

async function loadCountries() {
  try {
    const r = await fetch("countries-110m.json"); // https://appassets/ virtual host (file:// XHR is blocked)
    if (!r.ok) throw new Error("http " + r.status);
    const topo = await r.json();
    countries = topojson.feature(topo, topo.objects.countries);
    document.title = "countries-ok features=" + (countries ? countries.features.length : 0);
  } catch (e) { console.error("countries load failed", e); document.title = "COUNTRIES-FAIL " + e.message; }
}

function originLatLng() {
  const p = state.data;
  return p && p.origin ? [p.origin.lat, p.origin.lon] : [24.4539, 54.3773]; // Settings › Location default
}

function ensureMap() {
  if (lmap) return;
  lmap = L.map("viz", {
    crs: L.CRS.EPSG4326,                    // the raster is equirectangular, so plain lat/lon fits exactly
    center: originLatLng(), zoom: 4,
    zoomControl: false, attributionControl: false,
    minZoom: 0, maxZoom: 9, zoomSnap: 0.25, wheelPxPerZoomLevel: 90,
    maxBounds: [[-89.5, -179.5], [89.5, 179.5]], maxBoundsViscosity: 0.5,
  });
  L.control.zoom({ position: "bottomright" }).addTo(lmap);
  // Fit control: hand the view back to auto-fit (origin + all destinations)
  const FitControl = L.Control.extend({
    options: { position: "bottomright" },
    onAdd: function () {
      const bar = L.DomUtil.create("div", "leaflet-bar");
      const a = L.DomUtil.create("a", "", bar);
      a.href = "#";
      a.title = "Fit to my connections";
      a.innerHTML = "&#9678;";
      a.style.fontSize = "17px";
      a.style.lineHeight = "26px";
      a.style.textAlign = "center";
      L.DomEvent.on(a, "click", function (e) { L.DomEvent.stop(e); refitToData(); });
      return bar;
    }
  });
  lmap.addControl(new FitControl());
  applyRaster();
  if (countries) addBorders();
  // Auto-fit follows the data until the user takes over the view. Leaflet calls fitBounds/setView
  // without an originalEvent, so anything that lands while we are NOT the ones moving the map is a
  // real interaction (wheel, drag, double-click, the +/- buttons) — after that the zoom sticks.
  lmap.on("zoomend dragend", e => { if (!programmatic) userMoved = true; });
}

function applyRaster() {
  if (!lmap) return;
  const def = RASTERS[state.mapStyle] || RASTERS.satellite;
  if (rasterLayer) lmap.removeLayer(rasterLayer);
  rasterLayer = L.imageOverlay(def.url, [[-90, -180], [90, 180]], { className: def.className, interactive: false });
  rasterLayer.addTo(lmap);
  rasterLayer.bringToBack();
}

function addBorders() {
  if (!lmap || !countries) return;
  if (bordersLayer) lmap.removeLayer(bordersLayer);
  bordersLayer = L.geoJSON(countries, {
    interactive: false, className: "country-line",
    style: { color: "#ffffff", weight: 0.7, opacity: 0.30, fill: false },
  }).addTo(lmap);
}

const ORIGIN_ICON_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="#eaf4ff" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><rect x="4.5" y="5" width="15" height="10" rx="1.5"/><path d="M2.5 19h19"/></svg>';

function renderMap2D() {
  if (!lmap) ensureMap();
  if (!lmap) return;
  addBorders();

  for (const layer of [arcsLayer, dotsLayer, labelsLayer, originLayer])
    if (layer) lmap.removeLayer(layer);
  arcsLayer = null; dotsLayer = null; labelsLayer = null; originLayer = null;

  const o = originLatLng();
  originLayer = L.marker(o, {
    icon: L.divIcon({ className: "origin-marker", html: '<div class="origin-dot">' + ORIGIN_ICON_SVG + "</div>", iconSize: [26, 26], iconAnchor: [13, 13] }),
    interactive: false, zIndexOffset: 600, keyboard: false,
  }).addTo(lmap);

  const p = state.data;
  if (!p) return;
  const t = pal();
  arcsLayer = L.layerGroup().addTo(lmap);
  dotsLayer = L.layerGroup().addTo(lmap);
  labelsLayer = L.layerGroup().addTo(lmap);
  const labelled = state.places.slice(0, 10); // city labels for the biggest destinations

  for (const c of state.places) {
    // Great-circle arc via d3.geoInterpolate (d3-geo v3 has no geoGreatCircle).
    let pts = null;
    try {
      const interp = d3.geoInterpolate([o[1], o[0]], [c.lon, c.lat]);
      pts = [];
      for (let i = 0; i <= 48; i++) { const q = interp(i / 48); pts.push([q[1], q[0]]); }
    } catch (e) { pts = null; }
    if (pts) {
      L.polyline(pts, {
        color: c.blocked ? t.blocked : t.arc,
        weight: Math.min(3, 0.6 + Math.log10(c.bytes + 1) / 2),
        opacity: 0.78, interactive: false,
      }).addTo(arcsLayer);
    }

    const dot = L.circleMarker([c.lat, c.lon], {
      radius: Math.min(9, 2 + Math.log10(c.bytes + 1) / 2.5),
      color: "#ffffff55", weight: 1,
      fillColor: c.blocked ? t.blocked : t.point, fillOpacity: 0.95,
    }).addTo(dotsLayer);
    dot.bindTooltip(placeHtml(c), { className: "dot-tip", direction: "top", offset: [0, -6] });

    if (labelled.indexOf(c) >= 0 && c.city) {
      L.marker([c.lat, c.lon], {
        interactive: false, keyboard: false,
        icon: L.divIcon({ className: "city-label-wrap", html: '<span class="city-label-text">' + esc(c.city) + "</span>", iconSize: [0, 0], iconAnchor: [-7, -6] }),
      }).addTo(labelsLayer);
    }
  }
}

/// Fit the view to the origin + every destination (SPEC-UI §0.1), ~60 px padding.
/// Once the user zooms or pans we never move their view again — a manual zoom must not be undone
/// by the next data push. "Fit" (map control) or fitToData(true) hands the view back to auto-fit.
function fitToData(force) {
  if (!lmap) return;
  if (!force && userMoved) return;   // the user is driving the view — leave it alone
  const pts = [originLatLng()];
  for (const c of state.places) pts.push([c.lat, c.lon]);
  if (pts.length < 2) {
    if (force || !state.data) moveMap(() => lmap.setView(originLatLng(), 4, { animate: false })); // origin, regional
    return;
  }
  const b = L.latLngBounds(pts);
  moveMap(() => lmap.fitBounds(b, { padding: [60, 60], maxZoom: 6, animate: false }));
}

/// "Fit" button: hand the view back to auto-fit and reframe immediately.
function refitToData() {
  userMoved = false;
  fitToData(true);
}

// ---------- 3D globe: same Blue Marble texture, night sky ----------
function renderGlobe() {
  if (!globeEl) {
    // Globe() takes a DIV container and creates/manages its own WebGL canvas inside it —
    // passing an existing <canvas> bypasses width()/height() sizing (stays 300x150).
    globeEl = document.createElement("div");
    globeEl.className = "globe-canvas";
    viz.insertBefore(globeEl, viz.firstChild);
  }
  const w = Math.max(300, viz.clientWidth || window.innerWidth - 250), h = Math.max(200, viz.clientHeight || window.innerHeight - 160);

  if (!globeInstance) {
    globeInstance = Globe()(globeEl);
    window.__globe = globeInstance; // exposed for tests / Phase 5 IPC
    const o = originLatLng();
    globeInstance.pointOfView({ lat: o[0], lng: o[1], altitude: 1.9 }, 0);
    // SPEC-UI §0.3: the globe uses the same bundled Blue Marble imagery, on a dark night sky.
    globeInstance.globeImageUrl("bluemarble.jpg");
    globeInstance.backgroundColor("#0D0F1A");
    globeInstance.atmosphereColor("#5aa9ff");
    globeInstance.atmosphereAltitude(0.16);
    window.addEventListener("resize", () => renderGlobe());
  }
  const g = globeInstance;
  g.width(w).height(h);
  try { g.globeMaterial().color.set("#ffffff"); } catch (e) { /* older bundle */ } // full-colour texture, not tinted

  const p = state.data;
  if (!p) return;
  const t = pal();
  g.pointsData(state.places.map(c => ({
    lat: c.lat, lng: c.lon,
    size: Math.min(0.9, 0.15 + Math.log10(c.bytes + 1) / 6),
    color: c.blocked ? t.blocked : t.point,
    label: placeHtml(c), // globe.gl hover tooltip (scene-tooltip element)
  })));
  g.arcsData(state.places.map(c => ({
    startLat: p.origin.lat, startLng: p.origin.lon,
    endLat: c.lat, endLng: c.lon,
    color: () => (c.blocked ? t.blocked : t.arc),
    stroke: Math.min(3, 0.8 + Math.log10(c.bytes + 1) / 2.5),
    altAutoScale: 0.25,
  })));
}

// ---------- side list ----------
function placeHtml(c) {
  const apps = [...c.apps].slice(0, 3).join(", ");
  return `<b>${esc(c.city || "?")}${c.country ? ", " + esc(c.country) : ""}</b><br/>` +
    (c.blocked ? '<span style="color:var(--danger)">blocked</span> · ' : "") +
    `${fmtBytes(c.bytes)}<br/><span class="sub">${esc(apps)}</span>`;
}

function esc(s) { return String(s).replace(/[&<>"]/g, ch => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;" }[ch])); }

function renderPlaces() {
  const box = document.getElementById("places");
  if (!state.data) { box.innerHTML = '<div class="sub" style="color:var(--muted)">no destinations with coordinates yet</div>'; return; }
  if (state.places.length === 0) { box.innerHTML = '<div style="color:var(--muted)">nothing in the selected window</div>'; return; }
  const top = state.places.slice(0, 25);
  box.innerHTML = top.map((c, i) => `
    <div class="place" data-i="${i}">
      <div style="min-width:0"><div class="nm">${esc(c.city || "?")}${c.cc ? " · " + esc(c.cc) : ""}</div>
      <div class="sub">${[...c.apps].slice(0,2).join(", ")}</div></div>
      <div style="text-align:right"><div class="by">${fmtBytes(c.bytes)}</div>${c.blocked ? '<div class="blk">blocked</div>' : ""}</div>
    </div>`).join("");
  for (const el of box.querySelectorAll(".place")) {
    el.addEventListener("mousemove", ev => showTip(ev, placeHtml(state.places[+el.dataset.i])));
    el.addEventListener("mouseleave", hideTip);
  }
}

function renderStat() {
  const p = state.data;
  if (!p) return;
  const total = p.dests.reduce((a, d) => a + (inWindow(d) ? d.bytes : 0), 0);
  document.getElementById("stat").textContent =
    `${state.places.length} places · ${fmtBytes(total)}${state.window ? " · filtered window" : ""}`;
}

// ---------- traffic chart (last hour, drag to filter) ----------
const chart = document.getElementById("chart");
let dragStart = null;

function renderChart() {
  const p = state.data;
  if (!p) return;
  const dpr = window.devicePixelRatio || 1;
  const w = chart.clientWidth, h = chart.clientHeight;
  chart.width = w * dpr; chart.height = h * dpr;
  const ctx = chart.getContext("2d");
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);

  const buckets = p.minuteBuckets || []; // [[minIdx, bytes], ...] ascending
  if (buckets.length === 0) return;
  const min0 = buckets[0][0], min1 = buckets[buckets.length - 1][0];
  const span = Math.max(1, min1 - min0 + 1);
  const maxV = Math.max(1, ...buckets.map(b => b[1]));
  const bw = w / span;

  ctx.fillStyle = pal().chart;
  for (const [mi, v] of buckets) {
    const x = (mi - min0) * bw;
    const bh = Math.max(v > 0 ? 2 : 0, (v / maxV) * (h - 4));
    ctx.globalAlpha = state.window && !(mi >= state.window[0] && mi <= state.window[1]) ? 0.35 : 0.9;
    ctx.fillRect(x, h - bh, Math.max(1, bw - 1), bh);
  }
  ctx.globalAlpha = 1;

  // window overlay
  if (state.window) {
    const x0 = (state.window[0] - min0) * bw, x1 = (state.window[1] - min0 + 1) * bw;
    ctx.strokeStyle = "#ffffffaa"; ctx.lineWidth = 1;
    ctx.strokeRect(x0, 0.5, Math.max(2, x1 - x0), h - 1);
    document.getElementById("rangeNote").textContent = `window: ${minToHhmm(state.window[0])}–${minToHhmm(state.window[1] + 1)} (UTC)`;
  } else {
    document.getElementById("rangeNote").textContent = "drag across the chart to filter map + list";
  }

  function minToHhmm(mi) { const d = new Date(mi * 60000); return String(d.getUTCHours()).padStart(2, "0") + ":" + String(d.getUTCMinutes()).padStart(2, "0"); }
}

chart.addEventListener("mousedown", e => { dragStart = chartXToMin(e); });
window.addEventListener("mousemove", e => { if (dragStart == null) return; const cur = chartXToMin(e); state.window = [Math.min(dragStart, cur), Math.max(dragStart, cur)]; aggregatePlaces(); renderAll(false); });
window.addEventListener("mouseup", () => { dragStart = null; });

function chartXToMin(e) {
  const p = state.data; if (!p || !p.minuteBuckets || p.minuteBuckets.length === 0) return 0;
  const rect = chart.getBoundingClientRect();
  const min0 = p.minuteBuckets[0][0], span = Math.max(1, p.minuteBuckets[p.minuteBuckets.length - 1][0] - min0 + 1);
  const frac = Math.min(1, Math.max(0, (e.clientX - rect.left) / rect.width));
  return Math.round(min0 + frac * span);
}

// ---------- tooltip (side list; the map itself uses Leaflet tooltips) ----------
function showTip(ev, html) {
  tip.innerHTML = html;
  tip.style.display = "block";
  const r = viz.getBoundingClientRect();
  let x = ev.clientX - r.left + 14, y = ev.clientY - r.top + 10;
  if (x > r.width - 270) x -= 290;
  tip.style.left = x + "px"; tip.style.top = y + "px";
}
function hideTip() { tip.style.display = "none"; }

// ---------- controls ----------
document.getElementById("btn2d").addEventListener("click", () => setMode("2d"));
document.getElementById("btn3d").addEventListener("click", () => setMode("3d"));
(function wireStyleButtons() {
  const seg = document.getElementById("styleSeg");
  if (!seg) return;
  for (const b of seg.querySelectorAll("button")) {
    b.addEventListener("click", () => {
      const s = b.getAttribute("data-style");
      if (!s || s === state.mapStyle) return;
      state.mapStyle = s;
      for (const x of seg.querySelectorAll("button")) x.classList.toggle("on", x === b);
      applyRaster();
      if (bordersLayer && lmap) bordersLayer.bringToFront();
    });
  }
})();

// Self-test hook (used by the C# probe / Phase 5 IPC): exercises map styles, the chart drag-filter
// and the two 2D orders the user checks (direct, and back from the globe).
window.__selftest = function () {
  const out = {};
  const seg = document.getElementById("styleSeg");
  const restore = state.mapStyle;
  const picked = [];
  if (seg) for (const b of seg.querySelectorAll("button")) { b.click(); picked.push(state.mapStyle); }
  out.styles = picked.join(",");
  if (seg) for (const b of seg.querySelectorAll("button")) if (b.getAttribute("data-style") === restore) b.click();

  const ch = document.getElementById("chart");
  const r = ch.getBoundingClientRect();
  if (r.width > 0 && state.data && (state.data.minuteBuckets || []).length > 1) {
    ch.dispatchEvent(new MouseEvent("mousedown", { clientX: r.left + r.width * 0.2, clientY: r.top + 5 }));
    window.dispatchEvent(new MouseEvent("mousemove", { clientX: r.left + r.width * 0.6, clientY: r.top + 5 }));
    window.dispatchEvent(new MouseEvent("mouseup"));
    out.drag = state.window ? "ok:" + state.window.join(",") : "none";
    out.rangeNote = document.getElementById("rangeNote").textContent;
    state.window = null; aggregatePlaces(); renderAll(false); // clear filter again
  } else { out.drag = "chart-empty"; }

  function probe2d() {
    if (!lmap) return "no-map";
    const img = document.querySelector("#viz .leaflet-image-layer");
    const loaded = img && img.complete && img.naturalWidth > 0 ? "loaded " + img.naturalWidth + "x" + img.naturalHeight : (img ? "NOT-LOADED" : "NO-RASTER");
    const arcs = document.querySelectorAll("#viz path.leaflet-interactive").length;
    const size = lmap.getSize();
    return loaded + " " + arcs + "svg " + Math.round(size.x) + "x" + Math.round(size.y) +
      " c=" + lmap.getCenter().lat.toFixed(2) + "," + lmap.getCenter().lng.toFixed(2) + " z=" + lmap.getZoom().toFixed(2);
  }
  try {
    setMode("2d"); fitToData(true); out["2d-direct"] = probe2d();
    setMode("3d"); out["3d"] = document.querySelector(".globe-canvas canvas") ? "canvas" : "no-canvas";
    setMode("2d"); out["2d-after-3d"] = probe2d();
  } catch (e) { out.modes = "ERR " + e.message; }

  // Zoom must stick: (a) our own programmatic moves must NOT count as user interaction (otherwise
  // auto-fit would stop following the data by itself), and (b) once the user has zoomed, a data push
  // must not move the view. Synchronous and deterministic; the wheel gesture itself is verified by
  // the app working at all (Leaflet applies wheel zoom asynchronously, so it cannot be asserted here).
  try {
    const z0 = lmap.getZoom();
    moveMap(function () { lmap.setZoom(Math.min(6, z0 + 2), { animate: false }); }); // the path fitToData uses
    const guardOk = (userMoved === false);
    userMoved = true;                                        // what a real zoom/drag sets
    renderAll(false);                                        // exactly what a data push does
    const z2 = lmap.getZoom();
    out.zoom = "z0=" + z0.toFixed(2) + " afterProgrammatic=" + lmap.getZoom().toFixed(2) + " afterPush=" + z2.toFixed(2)
             + " programmaticDetectedAsUser=" + (!guardOk);
    out.zoomSticks = (guardOk && Math.abs(z2 - Math.min(6, z0 + 2)) < 0.01) ? "OK" : "FAIL";
    refitToData();
  } catch (e) { out.zoom = "ERR " + e.message; }
  out.places = state.places.length;
  out.globeTexture = (globeInstance && globeInstance.globeImageUrl()) ? String(globeInstance.globeImageUrl()) : "none";
  return JSON.stringify(out);
};

function setMode(m) {
  state.mode = m;
  document.getElementById("btn2d").classList.toggle("on", m === "2d");
  document.getElementById("btn3d").classList.toggle("on", m === "3d");
  renderAll(false);
}

function renderAll(forceFit) {
  const t = THEMES[state.theme];
  document.body.style.background = t.bg;
  if (state.mode === "2d") {
    if (globeEl) globeEl.style.display = "none";
    if (lmap) lmap.getContainer().style.display = "block";
    renderMap2D();
    if (lmap) { lmap.invalidateSize(); fitToData(forceFit === true); }
  } else {
    if (lmap) lmap.getContainer().style.display = "none";
    if (globeEl) globeEl.style.display = "block";
    renderGlobe();
  }
  renderPlaces();
  renderChart();
  renderStat();
}

// The WPF host resizes this control without any window resize event (page shown/hidden, window
// resize, first layout), so watch the container itself and redraw whenever its size changes.
(function watchVizSize() {
  let lastW = 0, lastH = 0;
  const check = () => {
    const w = viz.clientWidth, h = viz.clientHeight;
    if (w === lastW && h === lastH) return;
    lastW = w; lastH = h;
    if (state.mode === "2d") { if (lmap) { lmap.invalidateSize(); fitToData(false); } }
    else renderChart();
  };
  if (typeof ResizeObserver !== "undefined") new ResizeObserver(check).observe(viz);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) check(); });
  setInterval(check, 1000); // fallback: ResizeObserver misses size changes while hidden
})();

window.addEventListener("resize", () => { if (state.mode === "2d" && lmap) { lmap.invalidateSize(); fitToData(false); } });
loadCountries().then(() => { ensureMap(); renderAll(true); });

// Data arrives from C# via WebView2 PostWebMessageAsJson (delivered as 'webviewmessage').
window.addEventListener("error", e => { document.title = "JSERR " + (e.message || "?") + "@" + (e.lineno || 0); });
function handleHostPayload(e, tag) {
  try {
    var d = e.data;
    if (d === undefined || d === null) return;
    if (typeof d !== "object") { document.title = tag + " nonobj:" + typeof d; return; }
    if (Array.isArray(d.dests)) { window.__push(d); document.title = `got ${d.dests.length} dests`; }
    else document.title = tag + " keys=" + Object.keys(d).join(",");
  } catch (err) { document.title = "PUSHERR " + err.message; }
}
window.addEventListener("webviewmessage", e => handleHostPayload(e, "WV"));
window.addEventListener("message", e => handleHostPayload(e, "MSG"));
