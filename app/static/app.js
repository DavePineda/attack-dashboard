"use strict";
// Dashboard sin dependencias externas: datos de /api/v1/stats y gráficos SVG propios.
(() => {
  const $ = (id) => document.getElementById(id);
  const SVG = "http://www.w3.org/2000/svg";
  const REFRESH_MS = 60_000;
  // El agente da señal cada 2 min, aunque no haya ataques: 10 min sin ella es un fallo.
  const LIVE_MS = 10 * 60_000;
  const SERIES = [
    { key: "fail2ban", n: "1", unit: "baneos" },
    { key: "ufw", n: "2", unit: "paquetes" },
  ];
  const nf = new Intl.NumberFormat("es-CO");
  const dec1 = new Intl.NumberFormat("es-CO", { maximumFractionDigits: 1 });
  const compact = { format: (v) => (Math.abs(v) >= 1e6 ? `${dec1.format(v / 1e6)} M`
    : Math.abs(v) >= 1e3 ? `${dec1.format(v / 1e3)} k` : nf.format(v)) };
  const regionNames = (() => {
    try { return new Intl.DisplayNames(["es"], { type: "region" }); } catch { return null; }
  })();
  const SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 81: "HTTP alt",
    110: "POP3", 111: "RPC", 123: "NTP", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "Submission",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 1883: "MQTT",
    2222: "SSH alt", 2375: "Docker", 2376: "Docker TLS", 3306: "MySQL", 3389: "RDP",
    5060: "SIP", 5432: "PostgreSQL", 5555: "ADB", 5900: "VNC", 5985: "WinRM", 6379: "Redis",
    6443: "Kubernetes", 7547: "TR-069", 8000: "HTTP alt", 8080: "HTTP proxy", 8081: "HTTP alt",
    8443: "HTTPS alt", 8888: "HTTP alt", 9000: "HTTP alt", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB", 51820: "WireGuard",
  };

  let range = "7d";
  let data = null;
  let timer = null;

  // ---------------------------------------------------------------- utilidades
  const el = (tag, attrs = {}, ...children) => {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") node.className = v; else node.setAttribute(k, v);
    }
    for (const c of children) node.append(c);
    return node;
  };
  const svgEl = (tag, attrs = {}) => {
    const node = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    return node;
  };
  const flag = (cc) => (/^[A-Z]{2}$/.test(cc)
    ? String.fromCodePoint(...[...cc].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65)) : "🏳️");
  const countryName = (cc) => {
    if (!/^[A-Z]{2}$/.test(cc || "")) return "Desconocido";
    try { return regionNames?.of(cc) || cc; } catch { return cc; }
  };
  const fmtDate = (iso, tz, dateOnly = false) => iso ? new Intl.DateTimeFormat("es-CO", dateOnly
    ? { timeZone: tz, weekday: "short", day: "numeric", month: "short" }
    : { timeZone: tz, day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" },
  ).format(new Date(iso)) : "—";
  const fmtBucket = (iso) => fmtDate(iso, data.timezone, data.timeline.unit === "day");
  const ago = (iso) => {
    if (!iso) return "sin eventos";
    const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 90) return "hace un momento";
    if (s < 3600) return `hace ${Math.round(s / 60)} min`;
    if (s < 86400) return `hace ${Math.round(s / 3600)} h`;
    return `hace ${Math.round(s / 86400)} d`;
  };
  const niceMax = (v) => {
    if (v <= 0) return 4;
    const exp = 10 ** Math.floor(Math.log10(v));
    for (const m of [1, 2, 2.5, 5, 10]) if (m * exp >= v) return m * exp;
    return 10 * exp;
  };

  // ---------------------------------------------------------------- tooltip
  const tip = $("tooltip");
  const showTip = (evt, html) => {
    tip.replaceChildren(...html);
    tip.hidden = false;
    const pad = 12;
    const r = tip.getBoundingClientRect();
    let x = evt.clientX + pad;
    let y = evt.clientY - r.height - pad;
    if (x + r.width > window.innerWidth - 8) x = evt.clientX - r.width - pad;
    if (y < 8) y = evt.clientY + pad;
    tip.style.left = `${Math.max(8, x)}px`;
    tip.style.top = `${y}px`;
  };
  const hideTip = () => { tip.hidden = true; };

  // Las dos gráficas comparten periodos: la hora bajo el puntero se resalta en ambas.
  const bands = {};
  const highlight = (i) => {
    for (const list of Object.values(bands)) list.forEach((band, j) => band.classList.toggle("on", j === i));
  };
  const clearHover = () => { highlight(-1); hideTip(); };
  const bucketTip = (b) => [el("strong", {}, fmtBucket(b.t)), ...SERIES.map((s) =>
    el("span", { class: "line" }, el("span", { class: "key", "data-series": s.n }),
       `${nf.format(b[s.key])} ${s.unit}`))];
  // En pantallas táctiles no hay "salir" del puntero: el resaltado se quita al tocar fuera.
  document.addEventListener("pointerdown", (evt) => { if (!evt.target.closest(".chart")) clearHover(); });
  // El tooltip es fijo a la ventana: al desplazarse quedaría lejos de su barra.
  window.addEventListener("scroll", hideTip, { passive: true });

  // ---------------------------------------------------------------- gráfico de barras
  function barChart(container, buckets, key, seriesClass) {
    container.replaceChildren();
    bands[key] = [];
    const total = buckets.reduce((a, b) => a + b[key], 0);
    if (!buckets.length || total === 0) {
      container.append(el("div", { class: "empty" }, "Sin eventos en este rango."));
      return;
    }
    const width = Math.max(260, container.clientWidth);
    const height = container.clientHeight || 200;
    const m = { top: 8, right: 4, bottom: 22, left: 40 };
    const w = width - m.left - m.right;
    const h = height - m.top - m.bottom;
    const max = niceMax(Math.max(...buckets.map((b) => b[key])));
    const svg = svgEl("svg", { viewBox: `0 0 ${width} ${height}`, "aria-hidden": "true" });

    for (let i = 0; i <= 4; i++) {
      const v = (max / 4) * i;
      const y = m.top + h - (v / max) * h;
      svg.append(svgEl("line", { class: "gridline", x1: m.left, x2: width - m.right, y1: y, y2: y }));
      const t = svgEl("text", { class: "axis-label", x: m.left - 8, y: y + 4, "text-anchor": "end" });
      t.textContent = compact.format(v);
      svg.append(t);
    }

    const slot = w / buckets.length;
    const barW = Math.max(1, Math.min(slot - Math.min(2, slot * 0.25), 28));
    const gap = slot - barW;
    const every = Math.ceil(buckets.length / Math.max(2, Math.floor(w / 56)));

    buckets.forEach((b, i) => {
      const x = m.left + i * slot + gap / 2;
      const bh = (b[key] / max) * h;
      const y = m.top + h - bh;
      const band = svgEl("rect", { class: "hover-band", x: m.left + i * slot, y: m.top, width: slot, height: h });
      svg.append(band);
      bands[key].push(band);
      if (bh > 0) {
        const r = Math.min(4, barW / 2, bh);
        const bottom = m.top + h;
        // Extremo superior redondeado, base recta sobre el eje.
        const d = `M${x},${bottom} V${y + r} Q${x},${y} ${x + r},${y} H${x + barW - r} ` +
                  `Q${x + barW},${y} ${x + barW},${y + r} V${bottom} Z`;
        svg.append(svgEl("path", { class: seriesClass, d }));
      }
      if (i % every === 0) {
        const t = svgEl("text", { class: "axis-label", x: x + barW / 2, y: height - 6, "text-anchor": "middle" });
        t.textContent = b.label;
        svg.append(t);
      }
      const hit = svgEl("rect", { class: "hit", x: m.left + i * slot, y: m.top, width: slot, height: h + m.bottom });
      const show = (evt) => { highlight(i); showTip(evt, bucketTip(b)); };
      hit.addEventListener("pointermove", show);
      hit.addEventListener("pointerdown", show);
      hit.addEventListener("pointerleave", (evt) => { if (evt.pointerType !== "touch") clearHover(); });
      svg.append(hit);
    });
    container.append(svg);
  }

  function dataTable(container, buckets, key, header) {
    const rows = buckets.filter((b) => b[key] > 0).map((b) =>
      el("tr", {}, el("td", {}, fmtBucket(b.t)), el("td", { class: "num" }, nf.format(b[key]))));
    container.replaceChildren(rows.length
      ? el("table", { class: "data" },
          el("thead", {}, el("tr", {}, el("th", { scope: "col" }, "Inicio del periodo"),
                                       el("th", { scope: "col", class: "num" }, header))),
          el("tbody", {}, ...rows))
      : el("p", {}, "Sin eventos en este rango."));
  }

  // ---------------------------------------------------------------- listas
  function barList(container, items, render, emptyText) {
    container.replaceChildren();
    if (!items.length) {
      container.append(el("li", { class: "empty" }, emptyText));
      return;
    }
    const max = Math.max(...items.map((i) => i.value), 1);
    for (const item of items) {
      const { name, detail, value, valueText } = render(item);
      const fill = el("div", { class: "fill" });
      fill.style.width = `${(value / max) * 100}%`;
      const nameEl = el("span", { class: "name", title: detail ? `${name} · ${detail}` : name }, name);
      if (detail) nameEl.append(el("small", {}, detail));
      container.append(el("li", {}, nameEl, el("span", { class: "val" }, valueText),
                          el("div", { class: "track" }, fill)));
    }
  }

  // ---------------------------------------------------------------- render
  function render() {
    const d = data;
    document.title = d.title;
    $("title").textContent = d.title;
    $("k-bans").textContent = nf.format(d.summary.bans);
    $("k-blocked").textContent = compact.format(d.summary.blocked);
    $("k-blocked").title = nf.format(d.summary.blocked);
    $("k-ips").textContent = nf.format(d.summary.unique_ips);
    $("k-countries").textContent = d.geoip ? nf.format(d.summary.countries) : "—";
    $("k-countries-note").textContent = d.geoip ? "Según la IP de origen" : "GeoIP no configurado";
    $("retention").textContent = d.retention_days;

    const per = d.timeline.unit === "hour" ? "por hora" : "por día";
    const b = d.timeline.buckets;
    const sum = (k) => b.reduce((a, x) => a + x[k], 0);
    $("t-f2b-sub").textContent = `${nf.format(sum("fail2ban"))} baneos · ${per}`;
    $("t-ufw-sub").textContent = `${nf.format(sum("ufw"))} paquetes · ${per}`;
    clearHover();
    barChart($("chart-f2b"), b, "fail2ban", "bar-1");
    barChart($("chart-ufw"), b, "ufw", "bar-2");
    dataTable($("table-f2b"), b, "fail2ban", "Baneos");
    dataTable($("table-ufw"), b, "ufw", "Paquetes");

    const countries = $("countries");
    countries.classList.add("series-3");
    barList(countries, d.countries.map((c) => ({ ...c, value: c.ips })), (c) => ({
      name: `${flag(c.country)}  ${countryName(c.country)}`, value: c.ips,
      valueText: `${nf.format(c.ips)} IP${c.ips === 1 ? "" : "s"}`,
    }), d.geoip ? "Sin eventos en este rango." : "Configura GEOIP_DB para ver países.");

    const ports = $("ports");
    ports.classList.add("series-2");
    barList(ports, d.ports.map((p) => ({ ...p, value: p.hits })), (p) => ({
      name: `${p.port}/${(p.proto || "").toLowerCase()}`, detail: SERVICES[p.port] || "",
      value: p.hits, valueText: compact.format(p.hits),
    }), "Sin bloqueos de UFW en este rango.");

    barList($("jails"), d.jails.map((j) => ({ ...j, value: j.bans })), (j) => ({
      name: j.jail, detail: `${nf.format(j.ips)} IP${j.ips === 1 ? "" : "s"}`,
      value: j.bans, valueText: nf.format(j.bans),
    }), "Sin baneos en este rango.");

    $("top-sub").textContent = d.masked
      ? "Agrupado por red (/24 en IPv4, /48 en IPv6)" : "Por dirección IP";
    const rows = d.top.map((t) => el("tr", {},
      el("td", {}, t.addr),
      el("td", {}, d.geoip ? `${flag(t.country)} ${countryName(t.country)}` : "—"),
      el("td", { class: "num" }, nf.format(t.bans)),
      el("td", { class: "num" }, nf.format(t.blocked)),
      el("td", { class: "num" }, nf.format(t.hosts)),
      el("td", {}, fmtDate(t.last_seen, d.timezone))));
    $("top").replaceChildren(...(rows.length ? rows
      : [el("tr", {}, el("td", { colspan: "6" }, "Sin eventos en este rango."))]));

    const attrib = $("geo-attrib");
    attrib.hidden = !(d.geoip && d.geoip_attribution);
    // La licencia de DB-IP (CC BY 4.0) pide un enlace a su sitio en la página que usa sus datos.
    attrib.replaceChildren(d.geoip_attribution_url
      ? el("a", { href: d.geoip_attribution_url, rel: "noopener" }, d.geoip_attribution || "")
      : d.geoip_attribution || "");
    const src = $("source-link");
    if (d.source_url) src.href = d.source_url; else src.closest("p").hidden = true;
    updateStatus();
  }

  const setLive = (live) => document.querySelector(".pulse").classList.toggle("stale", !live);

  // "En vivo" depende del latido del agente, no del último evento: UFW entrega sus
  // ventanas de 10 min ya cerradas, así que el último evento suele tener 10-20 min.
  function updateStatus() {
    if (!data) return;
    const beat = data.sensors.last_seen;
    const live = Boolean(beat) && Date.now() - new Date(beat).getTime() <= LIVE_MS;
    const last = data.summary.last_event;
    $("status").replaceChildren(el("strong", {}, live ? "En vivo" : "Sin señal del agente"),
      ` · ${last ? `último evento ${ago(last)}` : "sin eventos en este rango"}`);
    setLive(live);
  }

  // ---------------------------------------------------------------- datos
  async function load() {
    try {
      const res = await fetch(`/api/v1/stats?range=${encodeURIComponent(range)}`,
                              { headers: { Accept: "application/json" }, cache: "no-store" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      data = await res.json();
      render();
    } catch (err) {
      $("status").textContent = "No se pudieron cargar los datos";
      setLive(false);
      console.error(err);
    }
  }

  function schedule() {
    clearInterval(timer);
    timer = setInterval(() => { if (!document.hidden) load(); }, REFRESH_MS);
  }

  document.querySelectorAll(".seg button").forEach((btn) => {
    btn.addEventListener("click", () => {
      range = btn.dataset.range;
      document.querySelectorAll(".seg button").forEach((b) =>
        b.setAttribute("aria-checked", String(b === btn)));
      load();
      schedule();
    });
  });
  document.addEventListener("visibilitychange", () => { if (!document.hidden) load(); });
  setInterval(updateStatus, 30_000);

  let resizeTimer;
  new ResizeObserver(() => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => { if (data) render(); }, 120);
  }).observe($("chart-f2b"));

  load();
  schedule();
})();
