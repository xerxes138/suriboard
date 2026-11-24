/* Suricata Dashboard - React-Frontend (ohne Build-Schritt: React + htm + Chart.js) */
(function () {
  "use strict";
  const { useState, useEffect, useRef, useMemo, useCallback } = React;

  // ------------------------------------------------------------------ Sprache (de/en)
  // German is the source language. English comes from window.I18N_EN (i18n-en.js), keyed by the
  // German text. Every string child and the props title/placeholder/aria-label (and all string props
  // of components) are looked up automatically; composed strings use T("… {n} …", { n }).
  const LANG = (() => {
    try { const l = localStorage.getItem("lang"); if (l === "de" || l === "en") return l; } catch (e) {}
    return (navigator.language || "de").toLowerCase().startsWith("de") ? "de" : "en";
  })();
  document.documentElement.lang = LANG;
  const DICT = LANG === "en" ? (window.I18N_EN || {}) : null;
  const PATTERNS = DICT ? (window.I18N_EN_PATTERNS || []).map(([re, rep]) => [new RegExp(re), rep]) : [];
  const MISSING = new Set();
  function trPattern(key) {
    for (const [re, rep] of PATTERNS) {
      const m = re.exec(key);
      if (m) return rep.replace(/\$(\d)/g, (_, i) => tr(m[+i] || ""));
    }
    return undefined;
  }
  function tr(s) {
    if (!DICT || typeof s !== "string" || !/[A-Za-zÄÖÜäöüß]/.test(s)) return s;
    const m = /^(\s*)([\s\S]*?)(\s*)$/.exec(s);
    const key = m[2].replace(/\s+/g, " ");
    let v = DICT[key];
    if (v === undefined) v = trPattern(key);
    if (v === undefined) { if (/[äöüÄÖÜß]/.test(key)) MISSING.add(key); return s; }
    // a fragment that becomes pure punctuation (e.g. " nicht." -> ".") must not keep its leading space
    return (/^[.,:;)]/.test(v) ? "" : m[1]) + v + m[3];
  }
  function T(s, vars) {
    let r = DICT ? (DICT[s] !== undefined ? DICT[s] : (MISSING.add(s), s)) : s;
    if (vars) r = r.replace(/\{(\w+)\}/g, (_, k) => (vars[k] != null ? vars[k] : ""));
    return r;
  }
  window.__i18nMissing = MISSING;
  const DOM_TEXT_PROPS = ["title", "placeholder", "aria-label", "alt"];
  // multi-root htm templates come as arrays (e.g. ${cond ? html`text <b>x</b> more` : ""})
  const trChild = (c) => (typeof c === "string" ? tr(c) : Array.isArray(c) ? c.map(trChild) : c);
  function h(type, props, ...children) {
    if (DICT) {
      if (props) {
        props = Object.assign({}, props);
        if (typeof type === "string") {
          for (const k of DOM_TEXT_PROPS) if (typeof props[k] === "string") props[k] = tr(props[k]);
        } else {
          for (const k in props) if (k !== "key" && typeof props[k] === "string") props[k] = tr(props[k]);
        }
      }
      for (let i = 0; i < children.length; i++) children[i] = trChild(children[i]);
    }
    return React.createElement(type, props, ...children);
  }
  const html = htm.bind(h);
  function setLang(l) {
    try { localStorage.setItem("lang", l); } catch (e) {}
    window.location.reload();
  }

  // ------------------------------------------------------------------ Hilfen

  const RANGES = [
    { h: 1, label: "1 Std" }, { h: 6, label: "6 Std" }, { h: 24, label: "24 Std" },
    { h: 168, label: "7 Tage" }, { h: 720, label: "30 Tage" },
  ];
  const REFRESH_MS = 30000;
  const FRONTEND_VERSION = "1.12.0";

  async function api(path, opts) {
    const r = await fetch(path, { credentials: "same-origin", ...(opts || {}) });
    const j = await r.json().catch(() => ({}));
    if (r.status === 401 && j.login) {
      // Sitzung abgelaufen oder abgemeldet -> zur Anmeldeseite
      window.location.replace("/login");
      return new Promise(() => {});
    }
    if (r.status === 403 && j.must_change) window.dispatchEvent(new Event("must-change-password"));
    if (!r.ok) throw new Error(j.error || r.statusText);
    return j;
  }
  const postJson = (path, body) =>
    api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

  function useApi(path, deps) {
    const [state, setState] = useState({ data: null, error: null, loading: true });
    useEffect(() => {
      let alive = true;
      if (!path) { setState({ data: null, error: null, loading: false }); return; }
      setState((s) => ({ ...s, loading: true }));
      api(path)
        .then((data) => alive && setState({ data, error: null, loading: false }))
        .catch((e) => alive && setState((s) => ({ data: s.data, error: e.message, loading: false })));
      return () => { alive = false; };
    }, [path, ...(deps || [])]);
    return state;
  }

  const nf = new Intl.NumberFormat(LANG === "en" ? "en-US" : "de-DE");
  const fmtNum = (n) => (n == null ? "–" : nf.format(n));
  function fmtBytes(b) {
    if (b == null) return "–";
    const u = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return (i ? b.toFixed(b < 10 ? 1 : 0) : b) + " " + u[i];
  }
  const pad = (n) => String(n).padStart(2, "0");
  function fmtTime(ts, withDate) {
    const d = new Date(ts * 1000);
    const t = pad(d.getHours()) + ":" + pad(d.getMinutes());
    if (!withDate) return t;
    return LANG === "en" ? pad(d.getMonth() + 1) + "/" + pad(d.getDate()) + " " + t : pad(d.getDate()) + "." + pad(d.getMonth() + 1) + ". " + t;
  }
  function fmtDateTime(ts) {
    if (!ts) return "–";
    const d = new Date(ts * 1000);
    const day = LANG === "en" ? d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate())
      : pad(d.getDate()) + "." + pad(d.getMonth() + 1) + "." + d.getFullYear();
    return day + " " + pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }
  function fmtAgo(ts) {
    if (!ts) return "–";
    const s = Math.max(0, Date.now() / 1000 - ts);
    if (s < 60) return T("gerade eben");
    if (s < 3600) return T("vor {n} Min", { n: Math.round(s / 60) });
    if (s < 86400) return T("vor {n} Std", { n: Math.round(s / 3600) });
    return T("vor {n} Tagen", { n: Math.round(s / 86400) });
  }
  const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

  // Farbe folgt der Kategorie (nicht dem Rang): feste Slots fuer bekannte Protokolle,
  // weitere bekommen den naechsten freien Slot und behalten ihn.
  const FIXED_SLOTS = {
    tls: 1, dns: 2, unknown: 3, quic: 4, http: 5, ssh: 6, ntp: 7, dhcp: 8,
    TCP: 1, UDP: 2, ICMP: 3, IPv6_ICMP: 4, "IPv6-ICMP": 4,
  };
  const assigned = { app_proto: {}, proto: {} };
  function seriesColor(name, ns) {
    if (name === "andere") return cssVar("--series-other");
    const map = assigned[ns || "app_proto"];
    if (!(name in map)) {
      const used = new Set(Object.values(map));
      let slot = FIXED_SLOTS[name] && !used.has(FIXED_SLOTS[name]) ? FIXED_SLOTS[name] : 0;
      for (let i = 1; i <= 8 && !slot; i++) if (!used.has(i)) slot = i;
      map[name] = slot; // 0 = keine Farbe mehr frei -> grau
    }
    return map[name] ? cssVar("--series-" + map[name]) : cssVar("--series-other");
  }
  const SEV_COLORS = { "Schwere 1": "--critical", "Schwere 2": "--serious", "Schwere 3+": "--warning", harmlos: "--harmless" };
  function sevColor(sev) { return cssVar(sev <= 1 ? "--critical" : sev === 2 ? "--serious" : "--warning"); }
  function hexAlpha(hex, a) {
    const h = hex.replace("#", "");
    const n = parseInt(h.length === 3 ? h.split("").map((c) => c + c).join("") : h, 16);
    return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
  }

  // ------------------------------------------------------------------ Diagramme

  function ChartView({ config, height }) {
    const canvas = useRef(null);
    const chart = useRef(null);
    useEffect(() => {
      chart.current = new Chart(canvas.current, config);
      return () => chart.current && chart.current.destroy();
    }, [config.type]);
    useEffect(() => {
      if (!chart.current) return;
      chart.current.data = config.data;
      chart.current.options = config.options;
      chart.current.update("none");
    }, [config]);
    return html`<div class="chart-box" style=${{ height: height + "px" }}><canvas ref=${canvas}></canvas></div>`;
  }

  function baseOptions(stacked, yFormat, labels, withDate) {
    const muted = cssVar("--muted"), grid = cssVar("--grid"), text = cssVar("--text");
    return {
      responsive: true, maintainAspectRatio: false, animation: false,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: cssVar("--surface"), titleColor: text, bodyColor: text,
          borderColor: cssVar("--axis"), borderWidth: 1, padding: 10, boxPadding: 4,
          itemSort: (a, b) => b.datasetIndex - a.datasetIndex,
          filter: (item) => item.raw > 0,
          callbacks: {
            title: (items) => items.length ? fmtTime(labels[items[0].dataIndex], true) : "",
            label: (item) => " " + item.dataset.label + ": " + yFormat(item.raw),
          },
        },
      },
      scales: {
        x: {
          stacked, grid: { display: false }, border: { color: cssVar("--axis") },
          ticks: {
            color: muted, maxRotation: 0, autoSkip: true, maxTicksLimit: 8,
            callback: (v, i) => fmtTime(labels[i], withDate),
          },
        },
        y: {
          stacked, beginAtZero: true, grid: { color: grid }, border: { display: false },
          ticks: { color: muted, maxTicksLimit: 5, callback: (v) => yFormat(v) },
        },
      },
    };
  }

  function Legend({ items }) {
    return html`<div class="legend">${items.map((it) => html`
      <span key=${it.name}><i class="swatch" style=${{ background: it.color }}></i>${it.name}
        ${it.value != null ? html`<span style=${{ color: "var(--muted)" }}>${it.value}</span>` : null}</span>`)}</div>`;
  }

  function TrafficChart({ hours, tick, theme }) {
    const [metric, setMetric] = useState("flows");
    const [group, setGroup] = useState("app_proto");
    const { data, error } = useApi(`/api/traffic?hours=${hours}&metric=${metric}&group=${group}`, [tick]);
    const fmt = metric === "bytes" ? fmtBytes : fmtNum;
    const config = useMemo(() => {
      if (!data) return null;
      const labels = data.buckets;
      // groesste Serie unten
      const series = data.series.slice();
      return {
        type: "line",
        data: {
          labels,
          datasets: series.map((s) => {
            const c = seriesColor(s.name, group);
            return {
              label: tr(s.name), data: s.data, fill: true, borderColor: c, borderWidth: 1.5,
              backgroundColor: hexAlpha(c, 0.8), pointRadius: 0, pointHoverRadius: 4,
              pointHoverBorderColor: cssVar("--surface"), pointHoverBorderWidth: 2,
              pointHoverBackgroundColor: c, tension: 0.25,
            };
          }),
        },
        options: baseOptions(true, fmt, labels, hours > 24),
      };
    }, [data, theme, group]);
    return html`
      <div class="card mb">
        <div class="card-head">
          <div>
            <h2>Verbindungen im Zeitverlauf</h2>
            <div class="sub">${metric === "bytes" ? "Datenvolumen" : "Anzahl Flows"} je ${data ? Math.round(data.bucket / 60) : "–"} Min, gestapelt nach ${group === "app_proto" ? "Anwendungsprotokoll" : "Transportprotokoll"}</div>
          </div>
          <div class="seg">
            <button class=${metric === "flows" ? "active" : ""} onClick=${() => setMetric("flows")}>Flows</button>
            <button class=${metric === "bytes" ? "active" : ""} onClick=${() => setMetric("bytes")}>Bytes</button>
          </div>
          <div class="seg">
            <button class=${group === "app_proto" ? "active" : ""} onClick=${() => setGroup("app_proto")}>Anwendung</button>
            <button class=${group === "proto" ? "active" : ""} onClick=${() => setGroup("proto")}>Transport</button>
          </div>
        </div>
        ${error && html`<div class="err">${error}</div>`}
        ${config ? html`<${ChartView} config=${config} height=${280} />` : html`<div class="empty" style=${{ height: 280 }}>lädt …</div>`}
        ${data && html`<${Legend} items=${data.series.map((s) => ({ name: s.name, color: seriesColor(s.name, group), value: fmt(s.total) }))} />`}
      </div>`;
  }

  function AlertTimeline({ hours, tick, theme }) {
    const { data, error } = useApi(`/api/alerts/timeline?hours=${hours}`, [tick]);
    const config = useMemo(() => {
      if (!data) return null;
      const labels = data.buckets;
      return {
        type: "bar",
        data: {
          labels,
          datasets: data.series.map((s) => ({
            label: tr(s.name), data: s.data, backgroundColor: cssVar(SEV_COLORS[s.name] || "--series-other"),
            borderColor: cssVar("--surface"), borderWidth: { top: 1 }, borderRadius: 2,
            borderSkipped: "bottom", categoryPercentage: 0.9, barPercentage: 1,
          })),
        },
        options: baseOptions(true, fmtNum, labels, hours > 24),
      };
    }, [data, theme]);
    return html`
      <div class="card">
        <h2>Alerts im Zeitverlauf</h2>
        <div class="sub">Offene Alerts nach Schweregrad, als harmlos markierte grau</div>
        ${error && html`<div class="err">${error}</div>`}
        ${config ? html`<${ChartView} config=${config} height=${220} />` : html`<div class="empty" style=${{ height: 220 }}>lädt …</div>`}
        ${data && html`<${Legend} items=${data.series.map((s) => ({ name: s.name, color: cssVar(SEV_COLORS[s.name] || "--series-other"), value: fmtNum(s.total) }))} />`}
      </div>`;
  }

  // ------------------------------------------------------------------ Listen

  function BarList({ rows, value, label, color, onClick, fmt, display }) {
    if (!rows) return html`<div class="empty">lädt …</div>`;
    if (!rows.length) return html`<div class="empty">keine Daten</div>`;
    const max = Math.max(...rows.map(value), 1);
    return html`<ul class="blist">${rows.map((r) => {
      const name = label(r);
      return html`<li key=${name}>
        <div class="row">
          ${color && html`<i class="swatch" style=${{ background: color(r) }}></i>`}
          <span class="name mono" title=${name}>
            ${onClick ? html`<button class="link" onClick=${() => onClick(r)}>${name}</button>` : name}${display ? display(r) : null}
          </span>
          <span class="num">${(fmt || fmtNum)(value(r))}</span>
        </div>
        <div class="track"><div class="fill" style=${{ width: (100 * value(r) / max) + "%", background: color ? color(r) : undefined }}></div></div>
      </li>`;
    })}</ul>`;
  }

  function TopCard({ title, sub, kind, hours, tick, order, onClick }) {
    const { data } = useApi(`/api/top?hours=${hours}&kind=${kind}&limit=10&order=${order || "count"}`, [tick]);
    return html`<div class="card">
      <h2>${title}</h2><div class="sub">${sub}</div>
      <${BarList} rows=${data} label=${(r) => r.key} value=${(r) => order === "bytes" ? r.bytes : r.count}
        fmt=${order === "bytes" ? fmtBytes : fmtNum} onClick=${onClick}
        display=${kind === "src_ip" || kind === "dest_ip" || kind === "dns_client" ? (r) => html`<${DevName} ip=${r.key} />` : null} />
    </div>`;
  }

  function ProtocolCard({ hours, tick, theme }) {
    const { data } = useApi(`/api/protocols?hours=${hours}`, [tick]);
    const rows = data ? data.app_proto.slice(0, 10) : null;
    return html`<div class="card">
      <h2>Anwendungsprotokolle</h2><div class="sub">Anzahl Flows</div>
      <${BarList} rows=${rows} label=${(r) => r.name} value=${(r) => r.flows} color=${(r) => seriesColor(r.name)} />
      ${data && html`<div class="sub" style=${{ marginTop: 10 }}>Transport: ${data.proto.map((p) => p.name + " " + fmtNum(p.flows)).join(" · ")}</div>`}
    </div>`;
  }

  // ------------------------------------------------------------------ Alerts

  function Severity({ s }) {
    const label = s <= 1 ? "hoch" : s === 2 ? "mittel" : "niedrig";
    return html`<span class="sev"><i style=${{ background: sevColor(s) }}></i>${s} · ${label}</span>`;
  }

  function ActionBadge({ a }) {
    const t = { blocked: "blockiert", wdrop: "würde blockieren", allowed: "erlaubt" }[a] || a;
    return html`<span class=${"badge " + (a || "allowed")}>${t}</span>`;
  }

  // Zwischenablage: navigator.clipboard gibt es nur bei HTTPS/localhost.
  // Im LAN (http://pi:8080) daher Fallback ueber ein unsichtbares Textfeld.
  async function copyText(text) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (e) { /* Fallback unten */ }
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.cssText = "position:fixed;top:0;left:0;opacity:0";
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(ta);
    if (!ok) window.prompt(T("Kopieren mit Strg+C:"), text);
    return true;
  }

  function CopyButton({ text, label, title }) {
    const [done, setDone] = useState(false);
    const click = async (e) => {
      e.stopPropagation();
      await copyText(text);
      setDone(true);
      setTimeout(() => setDone(false), 1200);
    };
    return html`<button class=${"copy" + (label ? " labeled" : "") + (done ? " done" : "")}
      title=${title || T("„{x}“ kopieren", { x: text })} aria-label=${title || "kopieren"} onClick=${click}>
      ${done ? "✓" : "⧉"}${label ? html`<span>${done ? "kopiert" : label}</span>` : null}</button>`;
  }

  // Selbst vergebene Geraetenamen {ip: [name, quelle]} fuer alle Ansichten
  const DevCtx = React.createContext({ names: {}, reload: () => {} });
  const AdminCtx = React.createContext(false);
  function useDevName(ip) {
    const { names } = React.useContext(DevCtx);
    return (names && ip && names[ip]) || null;
  }
  function DevName({ ip }) {
    const d = useDevName(ip);
    if (!d) return null;
    return html`<span class=${"devname" + (d[1] === "dhcp" ? " dhcp" : "")} title=${T("Gerät: {x}", { x: d[0] }) + " (" + tr(NAME_SRC[d[1]] || d[1]) + ")"}>${d[0]}</span>`;
  }

  function Endpoint({ ip, port, onIp }) {
    if (!ip) return html`<span class="mono">–</span>`;
    return html`<span class="mono endpoint">${onIp ? html`<button class="link mono" title="Alerts dieser IP anzeigen" onClick=${() => onIp(ip)}>${ip}</button>` : ip}${port != null ? html`<span class="port">:${port}</span>` : ""}<${CopyButton} text=${ip} title=${"IP " + ip + " kopieren"} /><${DevName} ip=${ip} /></span>`;
  }

  // ------------------------------------------------------------------ Reputation

  const VERDICTS = {
    malicious: { label: "Blockliste", icon: "⚠" },
    suspicious: { label: "auffällig", icon: "!" },
    unknown: { label: "unbekannt", icon: "?" },
    popular: { label: "verbreitet", icon: "◦" },
    known: { label: "bekannter Dienst", icon: "✓" },
    local: { label: "lokal", icon: "" },
  };

  function repText(r) {
    if (!r) return "";
    switch (r.verdict) {
      case "malicious": return (r.lists && r.lists[0]) || (r.domain_lists && r.domain_lists[0]) || "Blockliste";
      case "suspicious": return (r.lists && r.lists[0]) || (r.domain_lists && r.domain_lists[0]) || "auffällig";
      case "known": return (r.services && r.services[0]) || "bekannter Dienst";
      case "popular": return r.name || "verbreitete Domain";
      default: return r.asn || "unbekannt";
    }
  }

  // Kurzes Etikett fuer eine IP (Listenansichten). r = kompakte Bewertung vom Backend.
  function RepBadge({ r, withName }) {
    if (!r || r.verdict === "local") return null;
    const v = VERDICTS[r.verdict] || VERDICTS.unknown;
    const title = [tr(v.label).toUpperCase(), r.name ? T("Hostname: {x}", { x: r.name }) : null, ...(r.reasons || []).map(tr)].filter(Boolean).join("\n");
    const extra = withName && r.verdict !== "popular" && r.name ? r.name : null;
    return html`<span class="rep-wrap" title=${title}>
      <span class=${"rep " + r.verdict}>${v.icon ? v.icon + " " : ""}${repText(r)}</span>
      ${extra ? html`<span class="cat rep-name">${extra}</span>` : null}</span>`;
  }

  function RepCell({ rep }) {
    if (!rep) return null;
    const parts = [rep.src, rep.dest].filter((r) => r && r.verdict !== "local");
    if (!parts.length) return html`<span class="cat">lokal</span>`;
    return html`<div class="rep-cell">${parts.map((r, i) => html`<${RepBadge} key=${i} r=${r} withName />`)}</div>`;
  }

  function AlertTable({ items, onFlag, onUnflag, onIp, onSid, compact }) {
    const [detail, setDetail] = useState(null);
    const isAdmin = React.useContext(AdminCtx);
    const { openRule, ruleDialog } = useRuleDialog();
    if (!items) return html`<div class="empty">lädt …</div>`;
    if (!items.length) return html`<div class="empty">Keine Alerts – alles ruhig 🎉</div>`;
    return html`<div class="table-wrap"><table>
      <thead><tr>
        <th>Zeit</th><th>Aktion</th><th>Schwere</th><th>Signatur</th>
        <th>Quelle → Ziel</th><th>Reputation</th>${!compact && html`<th>Proto</th>`}<th></th>
      </tr></thead>
      <tbody>${items.map((a) => html`
        <tr key=${a.id} class=${(a.harmless ? "harmless " : "") + (a.is_new && !a.harmless ? "is-new" : "")}>
          <td class="ts-cell">${fmtDateTime(a.ts)}</td>
          <td><${ActionBadge} a=${a.action} /></td>
          <td><${Severity} s=${a.severity} /></td>
          <td>
            <div class="sig"><button class="link sig-link" title="Details und eve.json-Kontext" onClick=${() => setDetail(a)}>${a.signature}</button>
              ${a.is_new && !a.harmless ? html` <span class="badge new">NEU</span>` : null}
              ${a.harmless ? html` <span class="badge harmless" title=${!a.sig_flag && a.ctx_desc ? tr(a.ctx_desc) : ""}>${!a.sig_flag && a.ctx_flag ? "harmlos (Kontext)" : "harmlos"}</span>` : null}</div>
            <div class="cat">${onSid ? html`<button class="link" onClick=${() => onSid(a.sid)}>SID ${a.gid}:${a.sid}</button>` : `SID ${a.gid}:${a.sid}`}${a.category ? " · " + a.category : ""}</div>
          </td>
          <td class="endpoints"><span class="nowrap"><${Endpoint} ip=${a.src_ip} port=${a.src_port} onIp=${onIp} /></span> <span class="nowrap">→ <${Endpoint} ip=${a.dest_ip} port=${a.dest_port} onIp=${onIp} /></span></td>
          <td><${RepCell} rep=${a.rep} /></td>
          ${!compact && html`<td>${a.proto}${a.app_proto ? "/" + a.app_proto : ""}</td>`}
          <td class="actions-cell"><div class="row-actions">
            <button class="btn" onClick=${() => setDetail(a)}>Details</button>
            ${a.harmless
              ? html`<button class="btn" title=${!a.sig_flag && a.ctx_desc ? tr(a.ctx_desc) : ""} onClick=${() => onUnflag(a)}>${!a.sig_flag && a.ctx_flag ? "Kontext-Regel aufheben" : "Markierung aufheben"}</button>`
              : html`<button class="btn" onClick=${() => onFlag(a)}>Harmlos</button>`}
            ${isAdmin && html`<button class="btn" title="drop/reject-Regel in local.rules anlegen" onClick=${() => openRule({ alertId: a.id })}>Sperren …</button>`}</div></td>
        </tr>`)}</tbody>
    </table></div>
    ${detail && html`<${AlertDetail} alert=${detail} onClose=${() => setDetail(null)}
      onFlag=${detail.harmless ? null : () => { const d = detail; setDetail(null); onFlag(d); }}
      onRule=${isAdmin ? () => { const d = detail; setDetail(null); openRule({ alertId: d.id }); } : null} />`}
    ${ruleDialog}`;
  }

  // ------------------------------------------------------------------ Alert-Details / eve-Kontext

  const WINDOWS = [
    { b: 60, a: 60, label: "±1 Min" },
    { b: 60, a: 300, label: "−1 / +5 Min" },
    { b: 300, a: 1800, label: "−5 / +30 Min" },
    { b: 1800, a: 3600, label: "−30 / +60 Min" },
  ];

  function fmtClock(ts) {
    const d = new Date(ts * 1000);
    return pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }
  function fmtRel(sec) {
    const a = Math.abs(sec), sign = sec < 0 ? "−" : "+";
    if (a < 60) return sign + a + " s";
    if (a < 3600) return sign + Math.round(a / 60) + " min";
    return sign + (a / 3600).toFixed(1) + " h";
  }

  function summarize(ev) {
    const f = ev.flow || {};
    switch (ev.event_type) {
      case "flow":
        return [ev.app_proto || ev.proto, fmtBytes(f.bytes_toserver || 0) + " ↑ / " + fmtBytes(f.bytes_toclient || 0) + " ↓",
          T("{n} Pakete", { n: (f.pkts_toserver || 0) + (f.pkts_toclient || 0) }),
          f.age != null ? T("Dauer {n} s", { n: f.age }) : null, f.state, f.reason,
          f.action ? T("Aktion: {x}", { x: f.action }) : null, f.alerted ? T("mit Alert") : null].filter(Boolean).join(" · ");
      case "dns": {
        const d = ev.dns || {};
        const name = d.rrname || (d.queries && d.queries[0] && d.queries[0].rrname) || (d.answers && d.answers[0] && d.answers[0].rrname) || "";
        const answers = (d.answers || []).map((x) => x.rdata).filter(Boolean);
        if (d.grouped) Object.values(d.grouped).forEach((v) => Array.isArray(v) && v.forEach((x) => answers.push(typeof x === "string" ? x : JSON.stringify(x))));
        return (d.type === "answer" || d.type === "response" ? T("Antwort") : T("Anfrage")) + " " + name + (d.rrtype ? " (" + d.rrtype + ")" : "") +
          (answers.length ? " → " + answers.slice(0, 6).join(", ") : "") + (d.rcode && d.rcode !== "NOERROR" ? " · " + d.rcode : "");
      }
      case "tls": {
        const t = ev.tls || {};
        return ["SNI " + (t.sni || "–"), t.version, t.subject ? T("Zertifikat: {x}", { x: t.subject }) : null,
          t.ja3 && t.ja3.hash ? "JA3 " + t.ja3.hash : null,
          typeof t.ja4 === "string" ? "JA4 " + t.ja4 : null].filter(Boolean).join(" · ");
      }
      case "http": {
        const h = ev.http || {};
        return [(h.http_method || "") + " " + (h.hostname || "") + (h.url || ""), h.status ? "→ " + h.status : null,
          h.http_user_agent ? "UA: " + h.http_user_agent : null].filter(Boolean).join(" · ");
      }
      case "alert": {
        const al = ev.alert || {};
        return al.signature + " (SID " + al.signature_id + ", " + al.action + ")";
      }
      case "fileinfo": {
        const fi = ev.fileinfo || {};
        return [fi.filename, fi.size != null ? fmtBytes(fi.size) : null, fi.magic, fi.sha256 ? "sha256 " + fi.sha256 : null].filter(Boolean).join(" · ");
      }
      case "anomaly": {
        const an = ev.anomaly || {};
        return [an.type, an.event, an.layer].filter(Boolean).join(" · ");
      }
      default:
        return (ev.app_proto || ev.proto || "") ;
    }
  }

  function EventRow({ ev, alertTs }) {
    const [open, setOpen] = useState(false);
    const shown = { ...ev };
    delete shown._ts;
    const json = JSON.stringify(shown, null, 2);
    return html`<li class=${"ev" + (open ? " open" : "")}>
      <div class="ev-head" onClick=${() => setOpen(!open)}>
        <span class="ev-time mono" title=${fmtDateTime(ev._ts)}>${fmtClock(ev._ts)} <span class="cat">${fmtRel(ev._ts - alertTs)}</span></span>
        <span class=${"ev-type t-" + ev.event_type}>${ev.event_type}</span>
        <span class="ev-sum">${summarize(ev)}
          <span class="cat mono"> ${ev.src_ip}${ev.src_port != null ? ":" + ev.src_port : ""} → ${ev.dest_ip}${ev.dest_port != null ? ":" + ev.dest_port : ""}</span></span>
        <span class="ev-toggle">${open ? "▾" : "▸"}</span>
      </div>
      ${open && html`<div class="ev-body">
        <div class="ev-actions"><${CopyButton} text=${json} label="JSON kopieren" title="Event als JSON kopieren" /></div>
        <pre class="json">${json}</pre>
      </div>`}
    </li>`;
  }

  function EventList({ title, sub, events, alertTs, empty }) {
    return html`<section class="ctx">
      <h4>${title} <span class="cat">${events ? events.length : ""}</span></h4>
      ${sub && html`<div class="cat">${sub}</div>`}
      ${!events ? null : !events.length ? html`<div class="cat ctx-empty">${empty || "nichts gefunden"}</div>`
        : html`<ul class="evlist">${events.map((ev, i) => html`<${EventRow} key=${i} ev=${ev} alertTs=${alertTs} />`)}</ul>`}
    </section>`;
  }

  const LEVEL_CLASS = { malicious: "malicious", suspicious: "suspicious", known: "known", popular: "popular", info: "unknown" };

  // Ausfuehrliche Bewertung einer IP (Details, Threat-Feed-Seite)
  function RepDetail({ a, compact }) {
    if (!a) return null;
    const v = VERDICTS[a.verdict] || VERDICTS.unknown;
    if (!a.global) return html`<div class="rep-card"><div class="rep-card-head"><span class="mono">${a.ip}</span> <span class="cat">private/lokale Adresse – kein Lookup</span></div></div>`;
    return html`<div class="rep-card">
      <div class="rep-card-head">
        <span class="mono">${a.ip}</span> <${CopyButton} text=${a.ip} />
        <span class=${"rep " + a.verdict}>${v.icon ? v.icon + " " : ""}${v.label}</span>
      </div>
      ${a.asn && html`<div class="cat">AS${a.asn.asn} · ${a.asn.name}${a.asn.country ? " · " + a.asn.country : ""}</div>`}
      <ul class="reasons">${a.reasons.filter((r) => r.level !== "info").map((r, i) => html`<li key=${i} class=${"lvl-" + (LEVEL_CLASS[r.level] || "unknown")}>${r.text}</li>`)}
        ${!a.reasons.some((r) => r.level !== "info") ? html`<li class="lvl-unknown">Auf keiner geladenen Liste, kein bekannter Dienst.</li>` : null}</ul>
      ${a.names && a.names.length ? html`<div class="hostnames">${a.names.map((n) => html`
        <span key=${n.name} class=${"hn" + (n.lists.length ? " bad" : n.service ? " good" : "")}
          title=${[n.source ? T("gesehen über {x}", { x: n.source }) : null, n.last_seen ? T("zuletzt {x}", { x: fmtDateTime(n.last_seen) }) : null,
            n.service ? T("Dienst: {x}", { x: n.service }) : null, n.rank ? T("Tranco-Rang {n}", { n: n.rank }) : null,
            ...n.lists.map((l) => T("auf {x}", { x: tr(l.name) }) + (l.via && l.via !== n.name ? T(" (als {x})", { x: l.via }) : ""))].filter(Boolean).join("\n")}>
          ${n.name}${n.rank ? html`<span class="cat"> #${fmtNum(n.rank)}</span>` : null}</span>`)}
        ${a.names_total > a.names.length ? html`<span class="cat">+ ${a.names_total - a.names.length} weitere</span>` : null}</div>`
        : !compact && html`<div class="cat">Kein Hostname zu dieser IP bekannt (DNS-Antwort, TLS-SNI oder HTTP-Host).</div>`}
    </div>`;
  }

  function AlertDetail({ alert: a, onClose, onFlag, onRule }) {
    const [win, setWin] = useState(1);
    const w = WINDOWS[win];
    const { data, error, loading } = useApi(`/api/alert_context?id=${a.id}&before=${w.b}&after=${w.a}`);
    useEffect(() => {
      const h = (e) => e.key === "Escape" && onClose();
      window.addEventListener("keydown", h);
      return () => window.removeEventListener("keydown", h);
    }, []);
    const names = (ip) => (data && data.hostnames[ip]) || [];
    const rep = data && data.reputation;
    const { names: devNames } = React.useContext(DevCtx);
    const nameText = (ip) => [devNames[ip] && devNames[ip][0], ...names(ip).map((n) => n.name)].filter(Boolean).join(", ");
    const summaryText = [
      fmtDateTime(a.ts) + "  " + a.signature,
      "SID " + a.gid + ":" + a.sid + " · " + T("Schwere") + " " + a.severity + " · " + a.action + (a.category ? " · " + a.category : ""),
      T("Quelle:") + " " + a.src_ip + (a.src_port != null ? ":" + a.src_port : "") + (nameText(a.src_ip) ? "  (" + nameText(a.src_ip) + ")" : ""),
      (T("Ziel:") + "      ").slice(0, 7) + " " + a.dest_ip + (a.dest_port != null ? ":" + a.dest_port : "") + (nameText(a.dest_ip) ? "  (" + nameText(a.dest_ip) + ")" : ""),
      "Proto:  " + a.proto + (a.app_proto ? "/" + a.app_proto : ""),
      data && data.flow_ids.length ? "Flow-ID: " + data.flow_ids.join(", ") : null,
    ].filter(Boolean).join("\n");
    const ipRow = (label, ip, port) => html`
      <dt>${label}</dt>
      <dd>
        <span class="mono">${ip}${port != null ? ":" + port : ""}</span> <${CopyButton} text=${ip} title=${"IP " + ip + " kopieren"} /> <${DevName} ip=${ip} />
        ${names(ip).length ? html`<div class="hostnames">${names(ip).map((n) => html`<span key=${n.name} class="hn" title=${"aus " + n.source.toUpperCase()}>${n.name}<span class="cat"> ${n.source}</span></span>`)}</div>` : null}
      </dd>`;
    return html`<div class="modal-bg" onClick=${(e) => e.target === e.currentTarget && onClose()}>
      <div class="modal wide" role="dialog" aria-modal="true" aria-label="Alert-Details">
        <div class="detail-head">
          <div>
            <h3>${a.signature}</h3>
            <div class="badges"><${ActionBadge} a=${a.action} /> <${Severity} s=${a.severity} />
              ${a.is_new && !a.harmless ? html`<span class="badge new">NEU</span>` : null}
              ${a.harmless ? html`<span class="badge harmless">harmlos</span>` : null}</div>
          </div>
          <button class="icon-btn" title="Schließen (Esc)" onClick=${onClose}>✕</button>
        </div>

        <dl class="kv detail-kv">
          <dt>Zeit</dt><dd>${fmtDateTime(a.ts)}</dd>
          ${ipRow("Quelle", a.src_ip, a.src_port)}
          ${ipRow("Ziel", a.dest_ip, a.dest_port)}
          <dt>Protokoll</dt><dd>${a.proto}${a.app_proto ? "/" + a.app_proto : ""}</dd>
          <dt>Regel</dt><dd>SID ${a.gid}:${a.sid} rev ${a.rev} <${CopyButton} text=${String(a.sid)} title="SID kopieren" />${a.category ? html` · <span class="cat">${a.category}</span>` : null}</dd>
          ${data && data.flow_ids.length ? html`<dt>Flow-ID</dt><dd class="mono">${data.flow_ids.join(", ")} <${CopyButton} text=${data.flow_ids.join(" ")} title="Flow-ID kopieren" /></dd>` : null}
        </dl>
        <section class="rep-section">
          <h4>Reputation ${rep ? html`<span class=${"rep " + rep.verdict}>${(VERDICTS[rep.verdict] || {}).label}</span>` : null}</h4>
          ${!data && !error ? html`<div class="rep-cell">${[a.rep && a.rep.src, a.rep && a.rep.dest].map((r, i) => html`<${RepBadge} key=${i} r=${r} withName />`)}<span class="cat">Details werden geladen …</span></div>`
            : rep ? html`
              ${!rep.feeds_loaded && html`<div class="cat">Noch keine Threat-Feeds geladen – siehe Tab „Threat-Feeds“.</div>`}
              <div class="grid cols-2 rep-grid">${Object.values(rep.ips).filter((x) => x.global).map((x) => html`<${RepDetail} key=${x.ip} a=${x} />`)}</div>
              ${!Object.values(rep.ips).some((x) => x.global) && html`<div class="cat">Beide Adressen sind lokal – kein Lookup nötig.</div>`}
              ${rep.verdict === "known" && html`<div class="okmsg">Die externe Adresse gehört zu einem bekannten Update- bzw. Systemdienst und steht auf keiner Blockliste. Sehr wahrscheinlich ein Fehlalarm.
                ${onFlag ? " Wenn das für diese Signatur immer so ist, kannst du sie als harmlos markieren." : ""}</div>`}
              ${rep.verdict === "malicious" && html`<div class="err">Mindestens eine Adresse bzw. ein Hostname steht auf einer Blockliste. Diesen Alert genau prüfen.</div>`}`
            : null}
        </section>
        ${data && data.fingerprints && data.fingerprints.length ? html`<section class="rep-section">
          <h4>TLS-Fingerprints</h4>
          <div class="cat">Aus TLS-/QUIC-Events dieser Verbindung und weiteren Verbindungen zwischen den beiden Hosts</div>
          <div class="fp-list">${data.fingerprints.map((f) => html`<div key=${f.type + f.fp} class="fp-line"><${FpHead} a=${f} />
            ${f.verdict === "malicious" || f.verdict === "suspicious" ? html`<${FpReasons} a=${f} />` : null}</div>`)}</div>
          ${data.fingerprints.some((f) => f.verdict === "malicious") && html`<div class="err" style=${{ marginTop: 8 }}>Der TLS-Fingerprint passt zu bekannter Schadsoftware. Das Gerät prüfen.</div>`}
        </section>` : null}

        <div class="detail-actions">
          <${CopyButton} text=${a.src_ip + " " + a.dest_ip} label="Beide IPs" title="Quell- und Ziel-IP kopieren" />
          <${CopyButton} text=${summaryText} label="Zusammenfassung" title="Alert als Text kopieren" />
          ${onFlag && html`<button class="btn" onClick=${onFlag}>Als harmlos markieren</button>`}
          ${onRule && html`<button class="btn" onClick=${onRule}>Regel zum Sperren erstellen …</button>`}
        </div>

        <div class="ctx-bar">
          <div><b>Kontext aus eve.json</b>
            <div class="cat">${loading ? "durchsuche eve.json …" : data
              ? T("{n} passende Events · {b} gelesen · {from}–{to}", { n: fmtNum(data.events_scanned), b: fmtBytes(data.files.reduce((s, f) => s + f.bytes_read, 0)), from: fmtClock(data.window.from), to: fmtClock(data.window.to) })
              : ""}</div></div>
          <div class="seg">${WINDOWS.map((x, i) => html`<button key=${i} class=${i === win ? "active" : ""} onClick=${() => setWin(i)}>${x.label}</button>`)}</div>
        </div>
        ${error && html`<div class="err">${error}</div>`}
        ${data && data.notes.map((n, i) => html`<div key=${i} class="err">${n}</div>`)}
        ${data && html`<div style=${{ opacity: loading ? 0.5 : 1 }}>
          <${EventList} title="Diese Verbindung" alertTs=${a.ts} events=${data.connection}
            sub="Gleiche Flow-ID bzw. gleiche IPs, Ports und Protokoll. Das flow-Event erscheint erst nach Verbindungsende – ggf. Zeitfenster vergrößern."
            empty="Keine Events zu genau dieser Verbindung im Zeitfenster." />
          <${EventList} title="Namensauflösung" alertTs=${a.ts} events=${data.dns}
            sub="DNS-Antworten, die eine der beiden IPs enthalten" empty="Keine DNS-Antwort mit diesen IPs im Zeitfenster." />
          <${EventList} title="Weitere Ereignisse zwischen den beiden Hosts" alertTs=${a.ts} events=${data.host_pair}
            empty="Keine weiteren Verbindungen zwischen diesen IPs im Zeitfenster." />
          <section class="ctx">
            <h4>Andere Gesprächspartner im Zeitfenster</h4>
            <div class="cat">Mit wem haben die beteiligten IPs sonst kommuniziert? Hilfreich, um z. B. weitere betroffene Geräte zu finden.</div>
            <div class="grid cols-2" style=${{ marginTop: 8 }}>
              ${Object.entries(data.peers).map(([ip, peers]) => html`<div key=${ip}>
                <div class="peer-head mono">${ip}</div>
                ${!peers.length ? html`<div class="cat ctx-empty">keine</div>` : html`<ul class="blist">${peers.map((p) => html`<li key=${p.peer}><div class="row">
                  <span class="name mono">${p.peer} <${CopyButton} text=${p.peer} /></span>
                  <span class="num">${fmtNum(p.count)} <span class="cat">${Object.keys(p.types).join(", ")}</span></span></div></li>`)}</ul>`}
              </div>`)}
            </div>
          </section>
        </div>`}
      </div>
    </div>`;
  }

  const CTX_KINDS = [["service", "Bekannter Dienst"], ["asn", "Netzbetreiber"], ["domain", "Domain"], ["cidr", "IP / Netz"]];
  const uniq = (a) => a.filter((x, i) => x != null && x !== "" && a.indexOf(x) === i);

  function FlagDialog({ target, onClose, onDone }) {
    const q = target.id ? "alert_id=" + target.id : `gid=${target.gid}&sid=${target.sid}`;
    const { data, error } = useApi("/api/flags/suggest?" + q);
    const [scope, setScope] = useState("all");
    const [kind, setKind] = useState("service");
    const [value, setValue] = useState("");
    const [note, setNote] = useState("");
    const [busy, setBusy] = useState(false);
    const [preview, setPreview] = useState(null);
    const peers = data ? data.peers.filter((p) => p.global) : [];
    const sugg = data ? {
      service: ["*", ...uniq(peers.flatMap((p) => p.services))],
      asn: uniq(peers.filter((p) => p.asn).map((p) => String(p.asn.asn))),
      domain: uniq(peers.flatMap((p) => p.domains)),
      cidr: uniq(data.peers.map((p) => p.ip)),
    } : null;
    const asnName = (n) => { const p = peers.find((x) => x.asn && String(x.asn.asn) === n); return p ? p.asn.name : ""; };
    // sinnvolle Vorauswahl: Dienst > Netzbetreiber > Domain > Adresse
    useEffect(() => {
      if (!sugg) return;
      const k = sugg.service.length > 1 ? "service" : sugg.asn.length ? "asn" : sugg.domain.length ? "domain" : "cidr";
      setKind(k);
      setValue(k === "service" ? sugg.service[1] : (sugg[k][0] || ""));
    }, [data]);
    const pickKind = (k) => { setKind(k); setValue(k === "service" ? (sugg.service[1] || "*") : (sugg[k][0] || "")); };
    useEffect(() => {
      if (scope !== "ctx" || !value) { setPreview(null); return; }
      const t = setTimeout(() => postJson("/api/flags/preview", { gid: target.gid, sid: target.sid, kind, value })
        .then(setPreview).catch((e) => setPreview({ error: e.message })), 300);
      return () => clearTimeout(t);
    }, [scope, kind, value]);
    const save = async () => {
      setBusy(true);
      try {
        await postJson("/api/flags", { gid: target.gid, sid: target.sid, note, ...(scope === "ctx" ? { kind, value } : {}) });
        onDone();
      } catch (e) { alert(tr(e.message)); setBusy(false); }
    };
    const chips = (list, label) => html`<div class="chips">${list.map((v) => html`
      <button key=${v} type="button" class=${"chip-btn" + (v === value ? " active" : "")} onClick=${() => setValue(v)}>${label ? label(v) : v}</button>`)}</div>`;
    return html`<div class="modal-bg" onClick=${(e) => e.target === e.currentTarget && onClose()}>
      <div class="modal flag-modal" role="dialog" aria-modal="true" aria-label="Als harmlos markieren">
        <h3>Als harmlos markieren</h3>
        <p><b>${target.signature}</b><br/>SID ${target.gid}:${target.sid}</p>
        ${error && html`<div class="err">${error}</div>`}
        <div class="rule-kinds">
          <label class=${"rule-kind" + (scope === "all" ? " active" : "")}>
            <input type="radio" name="fscope" checked=${scope === "all"} onChange=${() => setScope("all")} />
            <span><b>Ganze Signatur</b><br /><span class="cat">Alle bisherigen und künftigen Alerts dieser Signatur werden in den Standardansichten ausgeblendet.</span></span></label>
          <label class=${"rule-kind" + (scope === "ctx" ? " active" : "")}>
            <input type="radio" name="fscope" checked=${scope === "ctx"} onChange=${() => setScope("ctx")} />
            <span><b>Nur in diesem Zusammenhang</b><br /><span class="cat">Harmlos nur, wenn die Gegenstelle zu einem bestimmten Dienst, Netz oder einer Domain gehört. Bei anderen Adressen wirst du weiter gewarnt.</span></span></label>
        </div>
        ${scope === "ctx" && !data && !error && html`<div class="empty">lädt …</div>`}
        ${scope === "ctx" && sugg && html`
          <div class="field"><label>Bedingung für die Gegenstelle</label>
            <div class="seg">${CTX_KINDS.map(([k, l]) => html`<button key=${k} type="button" class=${kind === k ? "active" : ""} onClick=${() => pickKind(k)}>${l}</button>`)}</div></div>
          ${kind === "service" && html`<div class="field">
            ${chips(sugg.service, (v) => (v === "*" ? T("jeder bekannte Update-/Systemdienst") : v))}
            ${sugg.service.length < 2 && html`<div class="cat">Für die beteiligten Adressen wurde kein bekannter Dienst erkannt.</div>`}
            <div class="cat">Bekannte Dienste erkennt das Dashboard am Hostnamen der Gegenstelle (z. B. Windows Update, Microsoft, Apple, Debian).</div></div>`}
          ${kind === "asn" && html`<div class="field">
            ${sugg.asn.length ? chips(sugg.asn, (v) => "AS" + v + (asnName(v) ? " " + asnName(v) : "")) : null}
            <input type="text" class="mono" value=${value} onInput=${(e) => setValue(e.target.value.trim())} placeholder="z. B. 8075" />
            <div class="cat">Das Netz eines Betreibers, z. B. AS8075 Microsoft. Braucht den Feed „IP → Netzbetreiber“.</div></div>`}
          ${kind === "domain" && html`<div class="field">
            ${sugg.domain.length ? chips(sugg.domain) : null}
            <input type="text" class="mono" value=${value} onInput=${(e) => setValue(e.target.value.trim())} placeholder="z. B. microsoft.com" />
            <div class="cat">Trifft zu, wenn ein Hostname der Gegenstelle diese Domain oder eine Subdomain ist (aus DNS, TLS-SNI, HTTP).</div></div>`}
          ${kind === "cidr" && html`<div class="field">
            ${chips(sugg.cidr)}
            <input type="text" class="mono" value=${value} onInput=${(e) => setValue(e.target.value.trim())} placeholder="z. B. 13.107.0.0/16 oder 192.168.1.20" />
            <div class="cat">Eine Adresse oder ein Netz in CIDR-Schreibweise. Gilt für Quelle und Ziel, auch für lokale Geräte.</div></div>`}
          <div class="okmsg">Gilt nie, wenn eine der Adressen auf einer Blockliste steht oder als auffällig gilt – solche Alerts bleiben immer sichtbar.</div>
          ${preview && (preview.error ? html`<div class="err">${tr(preview.error)}</div>`
            : html`<div class="cat preview-count">${T("Würde {m} von {t} Alerts dieser Signatur der letzten 30 Tage ausblenden.", { m: fmtNum(preview.matched), t: fmtNum(preview.total) })}</div>`)}
          ${data.rules.length > 0 && html`<div class="cat">Bestehende Regeln: ${data.rules.map((r) => tr(r.desc)).join(" · ")}</div>`}`}
        <textarea placeholder="Notiz, z. B. „apt-Updates vom Laptop“ oder „Discord-Voice“" value=${note}
          onInput=${(e) => setNote(e.target.value)}></textarea>
        <div class="actions">
          <button class="btn" onClick=${onClose}>Abbrechen</button>
          <button class="btn primary" disabled=${busy || (scope === "ctx" && (!value || !preview || !!preview.error))} onClick=${save}>Als harmlos markieren</button>
        </div>
      </div>
    </div>`;
  }

  // Gemeinsame Flag-Logik fuer alle Seiten
  function useFlagging(refresh) {
    const [target, setTarget] = useState(null);
    const unflag = async (a) => {
      // Alert, der nur durch eine Kontext-Regel harmlos ist -> diese Regel aufheben
      const rule = a.rule_id || (!a.sig_flag && a.ctx_flag);
      if (rule && !a.rule_id && !confirm(T("Kontext-Regel „{x}“ für diese Signatur aufheben?", { x: tr(a.ctx_desc || "") }))) return;
      try { await api(rule ? `/api/flags?rule=${rule}` : `/api/flags?gid=${a.gid}&sid=${a.sid}`, { method: "DELETE" }); }
      catch (e) { alert(tr(e.message)); }
      refresh();
    };
    // Nur einbinden, solange der Dialog offen ist, und pro Signatur neu (key):
    // so startet jeder Aufruf mit leerem Notizfeld und nicht "busy" vom letzten Speichern
    const dialog = target ? html`<${FlagDialog} key=${target.gid + ":" + target.sid + ":" + (target.id || "")} target=${target}
      onClose=${() => setTarget(null)} onDone=${() => { setTarget(null); refresh(); }} />` : null;
    return { flag: setTarget, unflag, dialog };
  }

  // ------------------------------------------------------------------ Seiten

  function Overview({ hours, tick, theme, refresh, goAlerts }) {
    const { data: s, error } = useApi(`/api/summary?hours=${hours}`, [tick]);
    const { data: recent } = useApi(`/api/alerts?hours=${hours}&limit=8`, [tick]);
    const { flag, unflag, dialog } = useFlagging(refresh);
    const rangeLabel = (RANGES.find((r) => r.h === hours) || {}).label;
    return html`<div>
      ${error && html`<div class="err">API nicht erreichbar: ${error}</div>`}
      <div class="grid kpis">
        <div class=${"card kpi alert" + (s && !s.alerts_open ? " zero" : "")}>
          <div class="label">Offene Alerts</div>
          <div class="value">${s ? fmtNum(s.alerts_open) : "–"}</div>
          <div class="hint">${s ? T("{n} harmlose ausgeblendet", { n: fmtNum(s.alerts_harmless) }) : ""}</div>
        </div>
        <button class=${"card kpi kpi-btn" + (s && s.rep && (s.rep.malicious || s.rep.suspicious) ? " rep-bad" : "")}
          onClick=${() => goAlerts({ rep: "bad" })} title="Offene Alerts mit Blocklisten-Treffer anzeigen">
          <div class="label">Blocklisten-Treffer</div>
          <div class="value">${s && s.rep ? fmtNum((s.rep.malicious || 0) + (s.rep.suspicious || 0)) : "–"}</div>
          <div class="hint">${s && s.rep ? T("{n} zu bekannten Diensten", { n: fmtNum(s.rep.known || 0) }) : ""}</div>
        </button>
        <div class="card kpi">
          <div class="label">Neue Signaturen</div>
          <div class="value">${s ? fmtNum(s.new_signatures) : "–"}</div>
          <div class="hint">erstmals gesehen in ${s ? s.new_signature_hours : 24} Std</div>
        </div>
        <div class="card kpi">
          <div class="label">Blockiert</div>
          <div class="value">${s ? fmtNum(s.alerts_blocked) : "–"}</div>
          <div class="hint">${s ? T("{n} davon offen", { n: fmtNum(s.alerts_blocked_open) }) : ""}</div>
        </div>
        <div class="card kpi">
          <div class="label">Verbindungen (Flows)</div>
          <div class="value">${s ? fmtNum(s.flows) : "–"}</div>
          <div class="hint">${s ? T("{n} Quell-IPs", { n: fmtNum(s.clients) }) : ""}</div>
        </div>
        <div class="card kpi">
          <div class="label">Datenvolumen</div>
          <div class="value">${s ? fmtBytes(s.bytes) : "–"}</div>
          <div class="hint">${s ? T("{n} Events", { n: fmtNum(s.events) }) + " · " + tr(rangeLabel) : ""}</div>
        </div>
      </div>

      <${TrafficChart} hours=${hours} tick=${tick} theme=${theme} />

      <div class="grid cols-2 mb">
        <${AlertTimeline} hours=${hours} tick=${tick} theme=${theme} />
        <${ProtocolCard} hours=${hours} tick=${tick} theme=${theme} />
      </div>

      <div class="card mb">
        <div class="card-head">
          <div><h2>Neueste offene Alerts</h2><div class="sub">ohne als harmlos markierte Signaturen</div></div>
          <button class="btn" onClick=${() => goAlerts({})}>Alle Alerts →</button>
        </div>
        <${AlertTable} items=${recent && recent.items} onFlag=${flag} onUnflag=${unflag} compact
          onIp=${(ip) => goAlerts({ ip })} onSid=${(sid) => goAlerts({ sid })} />
      </div>

      <div class="grid cols-3 mb">
        <${TopCard} title="Top Clients" sub="Quell-IPs nach Flows" kind="src_ip" hours=${hours} tick=${tick} onClick=${(r) => goAlerts({ ip: r.key })} />
        <${TopCard} title="Top Ziele" sub="Ziel-IPs nach Datenvolumen" kind="dest_ip" order="bytes" hours=${hours} tick=${tick} onClick=${(r) => goAlerts({ ip: r.key })} />
        <${TopCard} title="Top Ziel-Ports" sub="Protokoll/Port nach Flows" kind="dest_port" hours=${hours} tick=${tick} />
        <${TopCard} title="Top DNS-Anfragen" sub="angefragte Domains" kind="dns" hours=${hours} tick=${tick} />
        <${TopCard} title="Top TLS-Server (SNI)" sub="verschlüsselte Ziele" kind="tls_sni" hours=${hours} tick=${tick} />
        <${TopCard} title="Top HTTP-Hosts" sub="unverschlüsselter Web-Traffic" kind="http_host" hours=${hours} tick=${tick} />
      </div>
      ${dialog}
    </div>`;
  }

  const PAGE = 50;
  const REP_FILTERS = [
    ["", "alle"],
    ["hide_known", "bekannte Dienste ausblenden"],
    ["bad", "nur Blocklisten-Treffer"],
    ["malicious", "nur bösartige"],
    ["unknown", "nur unbekannte"],
  ];

  function AlertsPage({ hours, tick, refresh, filter, setFilter }) {
    const [q, setQ] = useState("");
    const [qDebounced, setQDebounced] = useState("");
    const [showHarmless, setShowHarmless] = useState(false);
    const [onlyBlocked, setOnlyBlocked] = useState(false);
    const [page, setPage] = useState(0);
    useEffect(() => { const t = setTimeout(() => setQDebounced(q), 300); return () => clearTimeout(t); }, [q]);
    useEffect(() => setPage(0), [qDebounced, showHarmless, onlyBlocked, filter, hours]);
    const params = new URLSearchParams({ hours, limit: PAGE, offset: page * PAGE });
    if (qDebounced) params.set("q", qDebounced);
    if (showHarmless) params.set("include_harmless", "1");
    if (onlyBlocked) params.set("action", "blocked");
    if (filter.ip) params.set("ip", filter.ip);
    if (filter.sid) params.set("sid", filter.sid);
    if (filter.rep) params.set("rep", filter.rep);
    const { data, error } = useApi("/api/alerts?" + params, [tick]);
    const { flag, unflag, dialog } = useFlagging(refresh);
    const total = data ? data.total : 0;
    return html`<div class="card">
      <div class="filters">
        <input type="search" placeholder="Signatur, Kategorie oder SID suchen" value=${q} onInput=${(e) => setQ(e.target.value)} />
        <label><input type="checkbox" checked=${showHarmless} onChange=${(e) => setShowHarmless(e.target.checked)} /> harmlose anzeigen</label>
        <label><input type="checkbox" checked=${onlyBlocked} onChange=${(e) => setOnlyBlocked(e.target.checked)} /> nur blockierte</label>
        <label>Reputation <select value=${filter.rep || ""} onChange=${(e) => setFilter({ ...filter, rep: e.target.value || undefined })}>
          ${REP_FILTERS.map(([v, l]) => html`<option key=${v} value=${v}>${l}</option>`)}</select></label>
        ${filter.ip && html`<span class="chip">IP ${filter.ip}<button onClick=${() => setFilter({ ...filter, ip: undefined })}>✕</button></span>`}
        ${filter.sid && html`<span class="chip">SID ${filter.sid}<button onClick=${() => setFilter({ ...filter, sid: undefined })}>✕</button></span>`}
      </div>
      ${error && html`<div class="err">${error}</div>`}
      <${AlertTable} items=${data && data.items} onFlag=${flag} onUnflag=${unflag}
        onIp=${(ip) => setFilter({ ...filter, ip })} onSid=${(sid) => setFilter({ ...filter, sid })} />
      <div class="pager">
        <span>${fmtNum(total)} Alerts</span>
        <button class="btn" disabled=${page === 0} onClick=${() => setPage(page - 1)}>← zurück</button>
        <span>Seite ${page + 1} / ${Math.max(1, Math.ceil(total / PAGE))}</span>
        <button class="btn" disabled=${(page + 1) * PAGE >= total} onClick=${() => setPage(page + 1)}>weiter →</button>
      </div>
      ${dialog}
    </div>`;
  }

  function SignaturesPage({ hours, tick, refresh, goAlerts }) {
    const isAdmin = React.useContext(AdminCtx);
    const [showHarmless, setShowHarmless] = useState(false);
    const [rulesTick, setRulesTick] = useState(0);
    const { data, error } = useApi(`/api/signatures?hours=${hours}&include_harmless=${showHarmless ? 1 : 0}`, [tick]);
    const { data: flags } = useApi("/api/flags", [tick]);
    const { data: ctxRules } = useApi("/api/flags/rules", [tick]);
    const { data: ownRules } = useApi(isAdmin ? "/api/rules" : null, [tick, rulesTick]);
    const { flag, unflag, dialog } = useFlagging(refresh);
    const { openRule, ruleDialog } = useRuleDialog(() => setRulesTick((t) => t + 1));
    const blockedBy = {};
    ((ownRules && ownRules.rules) || []).forEach((r) => { if (r.managed && r.original_sid) blockedBy[r.original_sid] = r; });
    return html`<div>
      <div class="card mb">
        <div class="card-head">
          <div>
            <h2>Signaturen im Zeitraum</h2>
            <div class="sub">Gruppiert nach Regel (SID). Markiere wiederkehrendes, bekanntes Rauschen als harmlos – übrig bleibt, was neu oder verdächtig ist.</div>
          </div>
          <label class="filters" style=${{ margin: 0 }}><input type="checkbox" checked=${showHarmless} onChange=${(e) => setShowHarmless(e.target.checked)} /> harmlose anzeigen</label>
        </div>
        ${error && html`<div class="err">${error}</div>`}
        ${!data ? html`<div class="empty">lädt …</div>` : !data.length ? html`<div class="empty">Keine offenen Signaturen im Zeitraum 🎉</div>` : html`
        <div class="table-wrap"><table>
          <thead><tr><th>Signatur</th><th>Schwere</th><th class="num">Treffer</th><th class="num">davon blockiert</th>
            <th>Beispiele</th><th>Zuerst gesehen</th><th>Zuletzt</th><th></th></tr></thead>
          <tbody>${data.map((s) => html`
            <tr key=${s.gid + ":" + s.sid} class=${(s.harmless ? "harmless " : "") + (s.is_new && !s.harmless ? "is-new" : "")}>
              <td>
                <div class="sig">${s.signature}
                  ${s.is_new && !s.harmless ? html` <span class="badge new">NEU</span>` : null}
                  ${s.verdict === "malicious" || s.verdict === "suspicious" ? html` <span class=${"rep " + s.verdict}>${VERDICTS[s.verdict].icon} ${VERDICTS[s.verdict].label}</span>` : null}
                  ${s.harmless ? html` <span class="badge harmless">harmlos</span>` : null}
                  ${blockedBy[s.sid] ? html` <span class=${"badge " + (blockedBy[s.sid].enabled ? "blocked" : "harmless")} title=${T("eigene Regel SID {n}", { n: blockedBy[s.sid].sid })}>${blockedBy[s.sid].enabled ? T("eigene {a}-Regel", { a: blockedBy[s.sid].action }) : "eigene Regel deaktiviert"}</span>` : null}</div>
                <div class="cat"><button class="link" onClick=${() => goAlerts({ sid: s.sid })}>SID ${s.gid}:${s.sid}</button>${s.category ? " · " + s.category : ""}${s.note ? " · „" + s.note + "“" : ""}${s.ctx_hidden ? " · " + T("{n} harmlos mit Kontext ausgeblendet", { n: fmtNum(s.ctx_hidden) }) : s.ctx_rules ? " · " + T("{n} Kontext-Regel(n)", { n: s.ctx_rules }) : ""}</div>
              </td>
              <td><${Severity} s=${s.severity} /></td>
              <td class="num">${fmtNum(s.count)}</td>
              <td class="num">${fmtNum(s.blocked)}</td>
              <td class="mono" style=${{ fontSize: 12 }}>${(s.examples || []).map((e, i) => html`<div key=${i} class="example"><span class="nowrap">${e.src_ip}<${CopyButton} text=${e.src_ip} /><${DevName} ip=${e.src_ip} /></span> <span class="nowrap">→ ${e.dest_ip}${e.dest_port != null ? ":" + e.dest_port : ""}<${CopyButton} text=${e.dest_ip} /> <span style=${{ color: "var(--muted)" }}>×${e.n}</span></span>
                ${[e.src_rep, e.dest_rep].map((r, j) => html`<${RepBadge} key=${j} r=${r} withName />`)}</div>`)}
                ${s.src_count > 1 || s.dest_count > 1 ? html`<div class="cat">${s.src_count} Quellen, ${s.dest_count} Ziele</div>` : null}</td>
              <td class="ts-cell">${fmtDateTime(s.first_seen)}</td>
              <td class="nowrap">${fmtAgo(s.last_seen)}</td>
              <td class="actions-cell"><div class="row-actions">${s.harmless
                ? html`<button class="btn" onClick=${() => unflag({ gid: s.gid, sid: s.sid })}>Markierung aufheben</button>`
                : html`<button class="btn" onClick=${() => flag(s)}>Harmlos</button>`}
                ${isAdmin && html`<button class="btn" title="drop/reject-Regel in local.rules anlegen" onClick=${() => openRule({ gid: s.gid, sid: s.sid, signature: s.signature })}>Sperren …</button>`}</div></td>
            </tr>`)}</tbody>
        </table></div>`}
      </div>

      <div class="card">
        <h2>Als harmlos markiert</h2>
        <div class="sub">Diese Signaturen werden in Übersicht und Alert-Liste ausgeblendet (gilt für alle Zeiträume).</div>
        ${!flags ? html`<div class="empty">lädt …</div>` : !flags.length ? html`<div class="empty">Noch keine Signatur markiert.</div>` : html`
        <div class="table-wrap"><table>
          <thead><tr><th>Signatur</th><th>Notiz</th><th>Markiert am</th><th class="num">Treffer gesamt</th><th>Zuletzt</th><th></th></tr></thead>
          <tbody>${flags.map((f) => html`<tr key=${f.gid + ":" + f.sid}>
            <td><div class="sig">${f.signature || "(noch nicht gesehen)"}</div><div class="cat">SID ${f.gid}:${f.sid}</div></td>
            <td>${f.note || html`<span class="cat">–</span>`}</td>
            <td class="nowrap">${fmtDateTime(f.created)}</td>
            <td class="num">${fmtNum(f.total)}</td>
            <td class="nowrap">${fmtAgo(f.last_seen)}</td>
            <td><button class="btn" onClick=${() => unflag(f)}>Markierung aufheben</button></td>
          </tr>`)}</tbody>
        </table></div>`}
        ${ctxRules && ctxRules.length > 0 && html`
        <h2 style=${{ marginTop: 18 }}>Harmlos mit Kontext</h2>
        <div class="sub">Diese Signaturen sind nur bei bestimmten Gegenstellen ausgeblendet. Andere Alerts derselben Signatur bleiben sichtbar – und Adressen auf Blocklisten immer.</div>
        <div class="table-wrap"><table>
          <thead><tr><th>Signatur</th><th>Bedingung</th><th>Notiz</th><th>Angelegt</th><th class="num">Ausgeblendet</th><th>Zuletzt</th><th></th></tr></thead>
          <tbody>${ctxRules.map((r) => html`<tr key=${r.id}>
            <td><div class="sig">${r.signature || "(noch nicht gesehen)"}</div><div class="cat">SID ${r.gid}:${r.sid}</div></td>
            <td>${tr(r.desc)}</td>
            <td>${r.note || html`<span class="cat">–</span>`}</td>
            <td class="nowrap">${fmtDateTime(r.created)}</td>
            <td class="num">${fmtNum(r.hidden)}</td>
            <td class="nowrap">${fmtAgo(r.last_hidden)}</td>
            <td><button class="btn" onClick=${() => unflag({ rule_id: r.id })}>Aufheben</button></td>
          </tr>`)}</tbody>
        </table></div>`}
      </div>
      ${isAdmin && html`<div class="mb-top"><${OwnRulesCard} tick=${tick + rulesTick} onChanged=${() => setRulesTick((t) => t + 1)} /></div>`}
      ${dialog}
      ${ruleDialog}
    </div>`;
  }

  // ------------------------------------------------------------------ Eigene Regeln (local.rules)

  const RULE_KINDS = [
    ["sig", "Signatur blockieren", "Kopie der Originalregel als drop/reject-Regel mit eigener SID"],
    ["ip", "IP-Adresse sperren", "sämtlicher Verkehr von und zu dieser Adresse"],
    ["domain", "Domain sperren", "DNS-Anfragen, TLS (SNI) und HTTP für die Domain und alle Subdomains"],
  ];

  function RuleEnvWarnings({ env, compact }) {
    if (!env) return null;
    const snippet = "rule-files:\n  - suricata.rules\n  - " + env.local_rules;
    return html`<div class="rule-env">
      ${env.file.error && html`<div class="err">${env.local_rules}: ${env.file.error}</div>`}
      ${!env.file.error && !env.file.exists && html`<div class="warnmsg"><span class="mono">${env.local_rules}</span> gibt es noch nicht. Die Datei wird beim ersten Speichern angelegt.</div>`}
      ${env.yaml.error
        ? html`<div class="warnmsg"><span class="mono">${env.suricata_yaml}</span>: ${env.yaml.error}. Ob Suricata die eigene Regeldatei lädt, lässt sich so nicht prüfen. Den Pfad zu suricata.yaml kannst du in den Einstellungen ändern.</div>`
        : !env.loaded && html`<div class="warnmsg"><b>Suricata lädt <span class="mono">${env.local_rules}</span> nicht.</b>${" "}
            Die Datei fehlt in <span class="mono">${env.suricata_yaml}</span> unter <span class="mono">rule-files</span>. Ohne diesen Eintrag bleiben eigene Regeln wirkungslos.
            ${!compact && html`<div style=${{ marginTop: 6 }}>Ergänzen und Suricata einmal neu starten (<span class="mono">sudo systemctl restart suricata</span>):</div>
            <pre class="json">${snippet}</pre>
            <div class="cat">Relative Namen sucht Suricata in <span class="mono">default-rule-path</span> (${env.yaml.default_rule_path || "nicht gesetzt"}), deshalb den vollen Pfad eintragen. suricata-update ändert suricata.yaml nicht, der Eintrag bleibt also erhalten.</div>`}</div>`}
      ${!env.ips_seen && html`<div class="cat">Hinweis: Bisher wurde kein Alert blockiert. drop und reject wirken nur, wenn Suricata als IPS läuft (inline, z. B. mit NFQUEUE). Im reinen IDS-Modus melden diese Regeln nur.</div>`}
    </div>`;
  }

  function ReloadStatus({ st }) {
    if (!st) return null;
    const cls = st.running ? "warnmsg" : st.ok ? "okmsg" : st.ok === false ? "err" : "warnmsg";
    return html`<div class=${cls}>${st.running ? "⟳ " : ""}${st.message}
      ${st.failed && st.failed.length ? html`<ul>${st.failed.map((f) => html`<li key=${f.sid} class="mono" style=${{ fontSize: 12 }}>SID ${f.sid}: ${f.rule}</li>`)}</ul>` : null}
      ${!st.running && st.ts ? html` <span class="cat">(${fmtDateTime(st.ts)})</span>` : null}</div>`;
  }

  // Status des Neuladens abfragen, solange es laeuft
  function useReload(initial) {
    const [st, setSt] = useState(initial || null);
    useEffect(() => {
      if (!st || !st.running) return;
      const t = setTimeout(() => api("/api/rules").then((r) => setSt(r.reload)).catch(() => {}), 2000);
      return () => clearTimeout(t);
    }, [st]);
    return [st, setSt];
  }

  function RuleDialog({ source, onClose, onDone }) {
    const q = source.alertId ? "alert_id=" + source.alertId : `gid=${source.gid}&sid=${source.sid}`;
    const { data, error } = useApi("/api/rules/suggest?" + q);
    const [kind, setKind] = useState(null);
    const [ip, setIp] = useState("");
    const [domain, setDomain] = useState("");
    const [action, setAction] = useState("drop");
    const [note, setNote] = useState("");
    const [reload, setReload] = useState(true);
    const [preview, setPreview] = useState(null);
    const [busy, setBusy] = useState(false);
    const [saved, setSaved] = useState(null);
    const [reloadSt, setReloadSt] = useReload(null);
    useEffect(() => {
      const h = (e) => e.key === "Escape" && onClose();
      window.addEventListener("keydown", h);
      return () => window.removeEventListener("keydown", h);
    }, []);
    useEffect(() => {
      if (!data) return;
      setKind(data.original ? "sig" : "ip");
      const ext = data.ips.find((x) => x.global) || data.ips[0];
      setIp(ext ? ext.ip : "");
      setDomain(data.domains[0] || "");
    }, [data]);
    const body = { kind, action, note, sid: data && data.sid, ip, domain, reload };
    useEffect(() => {
      if (!data || !kind || saved) return;
      setPreview(null);
      const t = setTimeout(() => postJson("/api/rules/build", body)
        .then((r) => setPreview({ rules: r.rules })).catch((e) => setPreview({ error: e.message })), 300);
      return () => clearTimeout(t);
    }, [data, kind, ip, domain, action, note]);

    const save = async () => {
      setBusy(true);
      try {
        const r = await postJson("/api/rules/add", body);
        setSaved(r.rules);
        setReloadSt(r.reload);
        onDone && onDone();
      } catch (e) { setPreview({ error: e.message }); }
      setBusy(false);
    };
    const env = data && data.env;
    const ipInfo = data && data.ips.find((x) => x.ip === ip);
    const title = (data && data.signature) || source.signature || (data ? "SID " + data.gid + ":" + data.sid : "");
    return html`<div class="modal-bg" onClick=${(e) => e.target === e.currentTarget && onClose()}>
      <div class="modal rule-modal" role="dialog" aria-modal="true" aria-label="Regel erstellen">
        <div class="detail-head">
          <div><h3>Regel zum Blockieren erstellen</h3>
            <div class="cat">${title}${data ? " · SID " + data.gid + ":" + data.sid : ""}</div></div>
          <button class="icon-btn" title="Schließen (Esc)" onClick=${onClose}>✕</button>
        </div>
        ${error && html`<div class="err">${error}</div>`}
        ${!data && !error && html`<div class="empty">lädt …</div>`}
        ${data && !saved && html`
          <${RuleEnvWarnings} env=${env} />
          ${data.existing.length > 0 && html`<div class="warnmsg">Dazu gibt es schon eigene Regeln:
            <ul>${data.existing.map((r) => html`<li key=${r.sid}>SID ${r.sid}: ${r.msg}${r.enabled ? "" : " " + T("(deaktiviert)")}</li>`)}</ul></div>`}

          <div class="field"><label>Was soll blockiert werden?</label>
            <div class="rule-kinds">${RULE_KINDS.map(([k, label, hint]) => {
              const off = (k === "sig" && !data.original) || (k === "ip" && !data.ips.length);
              return html`<label key=${k} class=${"rule-kind" + (kind === k ? " active" : "") + (off ? " off" : "")}>
                <input type="radio" name="rk" checked=${kind === k} disabled=${off && k === "sig"} onChange=${() => setKind(k)} />
                <span><b>${label}</b><br /><span class="cat">${k === "sig" && !data.original
                  ? T("Originalregel nicht gefunden in {x} (Ordner in den Einstellungen prüfen)", { x: env.rules_dir }) : hint}</span></span></label>`;
            })}</div></div>

          ${kind === "sig" && data.original && html`<div class="field"><label>Originalregel</label>
            <pre class="json rule-text">${data.original.text}</pre>
            <div class="cat">aus ${data.original.file}, Zeile ${data.original.line}${data.original.enabled ? "" : " (dort auskommentiert)"}. Die Originalregel bleibt unverändert und meldet weiter. Die Kopie blockiert zusätzlich.</div></div>`}

          ${kind === "ip" && html`<div class="field"><label>IP-Adresse</label>
            <div class="candidates">${data.ips.map((x) => html`<label key=${x.ip} class="radio-line">
              <input type="radio" name="rip" checked=${ip === x.ip} onChange=${() => setIp(x.ip)} />
              <span class="mono">${x.ip}</span> <${DevName} ip=${x.ip} />
              <span class="cat">${x.global ? (x.names.length ? x.names.slice(0, 3).join(", ") : "extern") : "lokales Gerät"}</span></label>`)}</div>
            <input type="text" class="mono" spellcheck="false" value=${ip} onInput=${(e) => setIp(e.target.value.trim())} placeholder="oder Adresse eingeben" />
            ${ipInfo && !ipInfo.global && html`<div class="warnmsg">Das ist eine Adresse im eigenen Netz. Die Regel sperrt den gesamten Verkehr dieses Geräts, auch ins Internet.</div>`}</div>`}

          ${kind === "domain" && html`<div class="field"><label>Domain</label>
            <input type="text" class="mono" spellcheck="false" list="rule-domains" value=${domain}
              onInput=${(e) => setDomain(e.target.value.trim())} placeholder="z. B. example.com" />
            <datalist id="rule-domains">${data.domains.map((d) => html`<option key=${d} value=${d} />`)}</datalist>
            <div class="cat">${data.domains.length ? "Bekannte Namen der beteiligten IPs: " + data.domains.join(", ") : "Für die beteiligten IPs sind keine Hostnamen bekannt."} Subdomains werden mit gesperrt.</div></div>`}

          <div class="inline-form">
            <div class="field"><label>Aktion</label>
              <div class="seg">
                <button class=${action === "drop" ? "active" : ""} onClick=${() => setAction("drop")}>drop</button>
                <button class=${action === "reject" ? "active" : ""} onClick=${() => setAction("reject")}>reject</button>
              </div>
              <div class="cat">${action === "drop" ? "verwirft die Pakete still" : "verwirft und schickt einen TCP-Reset bzw. ICMP-Fehler: Programme brechen sofort ab statt zu warten"}</div></div>
            <div class="field"><label>Notiz (optional)</label>
              <input type="text" value=${note} maxLength="80" onInput=${(e) => setNote(e.target.value)} placeholder="z. B. Tracking im Smart-TV" /></div>
          </div>

          <div class="field"><label>Vorschau für <span class="mono" title=${env.local_rules}>${env.local_rules.split("/").pop()}</span></label>
            ${!preview ? html`<div class="cat">…</div>` : preview.error ? html`<div class="err">${preview.error}</div>`
              : html`<pre class="json rule-text">${preview.rules.map((r) => r.text).join("\n")}</pre>`}</div>

          <div class="field"><label class="switch"><input type="checkbox" checked=${reload && env.rules_reload !== "none"} disabled=${env.rules_reload === "none"}
            onChange=${(e) => setReload(e.target.checked)} /><span class="slider"></span> Suricata danach die Regeln neu laden lassen</label>
            ${env.rules_reload === "none" && html`<div class="cat">Automatisches Neuladen ist in den Einstellungen abgeschaltet.</div>`}</div>
          <div class="actions">
            <button class="btn" onClick=${onClose}>Abbrechen</button>
            <button class="btn primary" disabled=${busy || !preview || !!preview.error || !!env.file.error} onClick=${save}>Regel speichern</button>
          </div>`}
        ${saved && html`
          <div class="okmsg">Gespeichert in <span class="mono">${env.local_rules}</span>: SID ${saved.map((r) => r.sid).join(", ")}</div>
          ${reloadSt ? html`<${ReloadStatus} st=${reloadSt} />` : html`<div class="warnmsg">Suricata wurde nicht neu geladen. Die Regel wirkt erst nach <span class="mono">sudo suricatasc -c reload-rules</span> oder einem Neustart von Suricata.</div>`}
          ${!env.loaded && html`<${RuleEnvWarnings} env=${env} compact />`}
          <div class="actions"><button class="btn primary" onClick=${onClose}>Schließen</button></div>`}
      </div>
    </div>`;
  }

  // Dialog-Steuerung fuer Alert-Tabellen und Signaturen
  function useRuleDialog(after) {
    const [src, setSrc] = useState(null);
    const dialog = src ? html`<${RuleDialog} key=${JSON.stringify(src)} source=${src}
      onClose=${() => setSrc(null)} onDone=${after} />` : null;
    return { openRule: setSrc, ruleDialog: dialog };
  }

  function OwnRulesCard({ tick, onChanged }) {
    const [reloadTick, setReloadTick] = useState(0);
    const { data, error } = useApi("/api/rules", [tick, reloadTick]);
    const [reloadSt, setReloadSt] = useReload(null);
    const [busy, setBusy] = useState(false);
    const [showOther, setShowOther] = useState(false);
    useEffect(() => { if (data && data.reload && !reloadSt) setReloadSt(data.reload); }, [data]);
    const act = async (path, body, question) => {
      if (question && !confirm(tr(question))) return;
      setBusy(true);
      try {
        const r = await postJson(path, body);
        if (r.reload) setReloadSt(r.reload);
      } catch (e) { alert(tr(e.message)); }
      setBusy(false);
      setReloadTick((t) => t + 1);
      onChanged && onChanged();
    };
    if (!data) return html`<div class="card">${error ? html`<div class="err">${error}</div>` : html`<div class="empty">lädt …</div>`}</div>`;
    const own = data.rules.filter((r) => r.managed);
    const other = data.rules.filter((r) => !r.managed);
    return html`<div class="card">
      <div class="card-head">
        <div><h2>Eigene Blockier-Regeln</h2>
          <div class="sub">Im Dashboard angelegte Regeln in <span class="mono">${data.local_rules}</span>. Neue Regeln erstellst du über „Sperren …“ bei einem Alert oder einer Signatur.</div></div>
        <button class="btn" disabled=${busy || data.rules_reload === "none" || (reloadSt && reloadSt.running)} onClick=${() => act("/api/rules/reload", {})}>Suricata neu laden</button>
      </div>
      <${RuleEnvWarnings} env=${data} />
      <${ReloadStatus} st=${reloadSt} />
      ${!own.length ? html`<div class="empty">Noch keine eigenen Regeln.</div>` : html`
      <div class="table-wrap"><table>
        <thead><tr><th>SID</th><th>Aktion</th><th>Regel</th><th>Angelegt</th><th></th></tr></thead>
        <tbody>${own.map((r) => html`<tr key=${r.sid} class=${r.enabled ? "" : "harmless"}>
          <td class="mono">${r.sid}</td>
          <td><span class=${"badge " + (r.action === "drop" || r.action.startsWith("reject") ? "blocked" : "allowed")}>${r.action}</span></td>
          <td><div class="sig">${r.msg}${r.enabled ? null : html` <span class="badge harmless">deaktiviert</span>`}</div>
            <details><summary class="cat">Regeltext</summary><pre class="json rule-text">${r.text}</pre></details></td>
          <td class="nowrap">${r.created ? r.created.replace(/_/g, "-") : "–"}</td>
          <td class="nowrap">
            <button class="btn" disabled=${busy} onClick=${() => act("/api/rules/modify", { sid: r.sid, op: r.enabled ? "disable" : "enable" })}>${r.enabled ? "Deaktivieren" : "Aktivieren"}</button>${" "}
            <button class="btn" disabled=${busy} onClick=${() => act("/api/rules/modify", { sid: r.sid, op: "delete" }, T("Regel SID {sid} endgültig aus {f} löschen?", { sid: r.sid, f: data.local_rules }))}>Löschen</button></td>
        </tr>`)}</tbody>
      </table></div>`}
      ${other.length > 0 && html`<div style=${{ marginTop: 10 }}>
        <button class="link" onClick=${() => setShowOther(!showOther)}>${showOther ? "▾" : "▸"} ${T(other.length === 1 ? "1 weitere Regel in der Datei (von Hand angelegt, wird hier nicht verändert)" : "{n} weitere Regeln in der Datei (von Hand angelegt, werden hier nicht verändert)", { n: other.length })}</button>
        ${showOther && html`<pre class="json rule-text" style=${{ marginTop: 6 }}>${other.map((r) => (r.enabled ? "" : "# ") + r.text).join("\n")}</pre>`}</div>`}
    </div>`;
  }

  function RulesSettings() {
    const [st, setSt] = useState(null);
    const [form, setForm] = useState(null);
    const [msg, setMsg] = useState(null);
    const [busy, setBusy] = useState(false);
    const load = (s) => {
      setSt(s);
      setForm({ rules_dir: s.rules_dir, local_rules: s.local_rules, suricata_yaml: s.suricata_yaml, rules_reload: s.rules_reload });
    };
    useEffect(() => { api("/api/rules").then(load).catch((e) => setMsg({ err: true, text: e.message })); }, []);
    if (!form) return html`<div class="card settings">${msg ? html`<div class="err">${msg.text}</div>` : html`<div class="empty">lädt …</div>`}</div>`;
    const set = (k) => (e) => { setForm({ ...form, [k]: e.target ? e.target.value : e }); setMsg(null); };
    const save = async () => {
      setBusy(true);
      try { load(await postJson("/api/rules/settings", form)); setMsg({ err: false, text: "Gespeichert." }); }
      catch (e) { setMsg({ err: true, text: e.message }); }
      setBusy(false);
    };
    const changed = ["rules_dir", "local_rules", "suricata_yaml", "rules_reload"].some((k) => form[k] !== st[k]);
    const okBad = (ok, text) => html`<div class=${"check " + (ok ? "ok" : "bad")}>${ok ? "✓ " : "✗ "}${text}</div>`;
    return html`<div class="card settings">
      <h2>Suricata-Regeln</h2>
      <div class="sub">Für „Sperren …“ bei Alerts und Signaturen: Das Dashboard schreibt eigene drop/reject-Regeln in deine eigene Regeldatei und lässt Suricata sie neu laden.</div>
      <div class="field"><label>Ordner mit den offiziellen Regeln</label>
        <input type="text" class="mono" spellcheck="false" value=${form.rules_dir} onInput=${set("rules_dir")} />
        ${form.rules_dir === st.rules_dir && okBad(st.rules_dir_ok, st.rules_dir_ok ? "Ordner gefunden" : "Ordner nicht gefunden")}
        <div class="cat">Hier sucht das Dashboard den Originaltext einer Signatur (alle *.rules-Dateien). Bei suricata-update meist <span class="mono">/var/lib/suricata/rules</span>.</div></div>
      <div class="field"><label>Eigene Regeldatei</label>
        <input type="text" class="mono" spellcheck="false" value=${form.local_rules} onInput=${set("local_rules")} />
        ${form.local_rules === st.local_rules && (st.file.error ? okBad(false, st.file.error)
          : okBad(true, st.file.exists ? "beschreibbar" : "wird beim ersten Speichern angelegt"))}
        <div class="cat">Das Dashboard hängt neue Regeln an und ändert nur Regeln, die es selbst angelegt hat. Deine übrigen Zeilen bleiben unangetastet. Vor jeder Änderung liegt eine Kopie in <span class="mono">data/${(form.local_rules.split("/").pop() || "local.rules")}.bak</span>.</div></div>
      <div class="field"><label>suricata.yaml</label>
        <input type="text" class="mono" spellcheck="false" value=${form.suricata_yaml} onInput=${set("suricata_yaml")} />
        ${form.suricata_yaml === st.suricata_yaml && form.local_rules === st.local_rules && (st.yaml.error ? okBad(false, st.yaml.error)
          : okBad(st.loaded, st.loaded ? "eigene Regeldatei steht unter rule-files" : "eigene Regeldatei fehlt unter rule-files"))}
        <div class="cat">Nur zum Prüfen, ob Suricata die eigene Regeldatei lädt. Das Dashboard ändert suricata.yaml nicht.</div></div>
      <div class="field"><label>Suricata nach Änderungen neu laden</label>
        <div class="seg">${[["suricatasc", "suricatasc reload-rules"], ["usr2", "USR2-Signal"], ["none", "nicht automatisch"]].map(([v, l]) => html`
          <button key=${v} class=${form.rules_reload === v ? "active" : ""} onClick=${() => set("rules_reload")(v)}>${l}</button>`)}</div>
        <div class="cat">${form.rules_reload === "suricatasc" ? html`Braucht <span class="mono">unix-command: enabled: yes</span> in suricata.yaml (Standard bei Debian). Meldet zurück, ob Suricata eine Regel abgelehnt hat.`
          : form.rules_reload === "usr2" ? "Schickt Suricata das Signal USR2. Fehler stehen nur in suricata.log."
          : html`Du lädst selbst neu, z. B. mit <span class="mono">sudo suricatasc -c reload-rules</span>.`}
          ${" "}Das Dashboard braucht dafür Root-Rechte (Standard im mitgelieferten systemd-Dienst).</div></div>
      <${RuleEnvWarnings} env=${st} />
      ${msg && html`<div class=${msg.err ? "err" : "okmsg"}>${msg.text}</div>`}
      <div class="actions"><button class="btn primary" disabled=${busy || !changed} onClick=${save}>Speichern</button></div>
    </div>`;
  }

  // ------------------------------------------------------------------ Anomalien

  const SEV = { high: { label: "hoch", cls: "malicious" }, medium: { label: "mittel", cls: "suspicious" }, low: { label: "niedrig", cls: "unknown" } };
  const BYTE_METRICS = new Set(["bytes_out", "bytes_in"]);
  const fmtMetric = (m, v) => (BYTE_METRICS.has(m) ? fmtBytes(v) : fmtNum(Math.round(v || 0)));
  const fmtDur = (sec) => { const d = Math.ceil(sec / 86400); return d <= 1 ? T("1 Tag") : T("{n} Tage", { n: d }); };

  function DevLabel({ device, dev }) {
    const d = device || { dev, ips: [dev] };
    return html`<div class="dev-label">
      <div><b>${d.name || (d.ips && d.ips[0]) || dev}</b></div>
      <div class="cat mono">${[d.name ? (d.ips || []).slice(0, 2).join(", ") : (d.ips || []).slice(1, 2).join(", "), d.mac].filter(Boolean).join(" · ")}</div>
    </div>`;
  }

  function anomalyExplain(a, labels) {
    const d = a.detail || {};
    if (a.kind === "volume") return T("{v} in der Stunde ab {t} · sonst höchstens {max}, meist {med}", { v: fmtMetric(a.metric, d.value), t: fmtTime(d.hour), max: fmtMetric(a.metric, d.max), med: fmtMetric(a.metric, d.median) });
    if (a.kind === "time") return T("{n} Verbindungen um {h} Uhr · in den letzten {d} Tagen um diese Zeit an {s} Tag(en) aktiv", { n: fmtNum(d.flows), h: d.hour_of_day, d: d.days, s: d.seen_days });
    if (a.kind === "new") {
      const cat = (labels && labels[a.metric]) || a.metric;
      const what = d.total ? T("{n} neue: {list}", { n: d.total, list: (d.items || []).slice(0, 8).join(", ") + (d.total > 8 ? " …" : "") }) : (d.items || [a.item]).join(", ");
      return what + " · " + T("{cat} bisher: {n}, zuletzt ca. {r} neue pro Tag", { cat: tr(cat), n: fmtNum(d.known), r: LANG === "en" ? String(d.rate) : String(d.rate).replace(".", ",") });
    }
    return d.text || "";
  }

  function SevBadge({ s }) {
    const v = SEV[s] || SEV.low;
    return html`<span class=${"rep " + v.cls}>${v.label}</span>`;
  }

  function Bars({ values, max, labels, title, cls }) {
    const m = max || Math.max(1, ...values);
    return html`<div class=${"bars " + (cls || "")}>${values.map((v, i) => html`<div key=${i} class="vbar" title=${title ? title(i, v) : String(v)}>
      <i style=${{ height: Math.max(v > 0 ? 6 : 0, Math.round((v / m) * 100)) + "%" }}></i>
      ${labels && labels[i] != null ? html`<span>${labels[i]}</span>` : null}</div>`)}</div>`;
  }

  function DeviceProfile({ dev, onClose, isAdmin, onChanged }) {
    const [local, setLocal] = useState(0);
    const { data, error } = useApi("/api/anomalies/device?dev=" + encodeURIComponent(dev), [local]);
    const unmute = async (m) => { await postJson("/api/anomalies/mute", { dev, kind: m.kind, metric: m.metric, mute: false }); setLocal((x) => x + 1); onChanged(); };
    const b = data && data.baseline;
    return html`<div class="modal-bg" onClick=${(e) => e.target === e.currentTarget && onClose()}>
      <div class="modal wide" role="dialog" aria-modal="true" aria-label="Geräteprofil">
        <div class="detail-head">
          <div><h3>Verhaltensprofil</h3>${data && html`<${DevLabel} device=${data.device} dev=${dev} />`}</div>
          <button class="icon-btn" title="Schließen" onClick=${onClose}>✕</button>
        </div>
        ${error && html`<div class="err">${error}</div>`}
        ${!data ? html`<div class="empty">lädt …</div>` : html`
          <div class="cat">Beobachtet seit ${fmtDateTime(data.meta.first_seen)}, zuletzt aktiv ${fmtAgo(data.meta.last_seen)} · ${b.active_days} aktive Tage ·
            ${b.learned ? html`<span class="check ok">wird überwacht</span>` : html`<b>lernt noch</b> (${b.learn_left > 0 ? T("noch {x}", { x: fmtDur(b.learn_left) }) : ""}${b.learn_left > 0 && b.need_active ? ", " : ""}${b.need_active ? T("noch {n} aktive Tage", { n: b.need_active }) : ""})`}</div>

          <section class="rep-section">
            <h4>Wann ist das Gerät aktiv?</h4>
            <div class="cat">An wie vielen der letzten ${b.days} Tage das Gerät zur jeweiligen Uhrzeit aktiv war (≥ 10 Verbindungen pro Stunde)</div>
            <${Bars} values=${b.hod} max=${Math.max(1, b.days)} labels=${b.hod.map((_, i) => (i % 3 === 0 ? i : ""))} title=${(i, v) => T("{h} Uhr: an {v} von {d} Tagen", { h: i, v, d: b.days })} />
          </section>

          <section class="rep-section">
            <h4>Letzte 48 Stunden</h4>
            <${Bars} cls="small" values=${data.recent.map((r) => r.flows)} labels=${data.recent.map((r) => { const h = new Date(r.hour * 1000).getHours(); return h % 6 === 0 ? h : ""; })}
              title=${(i, v) => { const r = data.recent[i]; return fmtDateTime(r.hour) + ": " + T("{n} Verbindungen, {b} gesendet, {p} Gegenstellen", { n: fmtNum(r.flows), b: fmtBytes(r.bytes_out), p: r.peers_ext }); }} />
          </section>

          <section class="rep-section">
            <h4>Übliche Werte pro Stunde</h4>
            <div class="table-wrap"><table>
              <thead><tr><th></th><th class="num">Median</th><th class="num">99 %</th><th class="num">Maximum</th></tr></thead>
              <tbody>${Object.entries(b.stats).map(([m, st]) => html`<tr key=${m}><td>${data.metric_labels[m] || m}</td>
                <td class="num">${fmtMetric(m, st.median)}</td><td class="num">${fmtMetric(m, st.p99)}</td><td class="num">${fmtMetric(m, st.max)}</td></tr>`)}</tbody>
            </table></div>
          </section>

          <section class="rep-section">
            <h4>Was das Gerät kennt</h4>
            <div class="grid cols-2 known-grid">${Object.keys(data.novelty_labels).map((k) => html`<div key=${k}>
              <div class="cat"><b>${data.novelty_labels[k]}</b> (${fmtNum(data.known[k + "_total"])})</div>
              <div class="hostnames">${data.known[k].length ? data.known[k].map((x) => html`<span key=${x.item} class="hn"
                title=${T("zuerst {x}", { x: fmtDateTime(x.first_seen) }) + "\n" + T("zuletzt {x}", { x: fmtDateTime(x.last_seen) }) + "\n" + fmtNum(x.count) + "×"}>${x.item}</span>`)
                : html`<span class="cat">–</span>`}</div></div>`)}</div>
          </section>

          ${data.mutes.length ? html`<section class="rep-section"><h4>Stummgeschaltet</h4>
            ${data.mutes.map((m) => html`<div key=${m.kind + m.metric} class="example">${muteLabel(m, data)}
              ${isAdmin && html`<button class="btn" onClick=${() => unmute(m)}>wieder melden</button>`}</div>`)}</section>` : null}

          <section class="rep-section"><h4>Warnungen zu diesem Gerät</h4>
            ${!data.items.length ? html`<div class="cat">Keine.</div>` : data.items.map((a) => html`<div key=${a.id} class=${"anomaly-line" + (a.status !== "open" ? " done" : "")}>
              <${SevBadge} s=${a.severity} /> <b>${a.title}</b> <span class="cat">${fmtDateTime(a.ts)}${a.status !== "open" ? " · erledigt" : ""}</span>
              <div class="cat">${anomalyExplain(a, data.novelty_labels)}</div></div>`)}
          </section>`}
      </div>
    </div>`;
  }

  function muteLabel(m, data) {
    const what = m.kind === "new" ? T("Neues: {x}", { x: tr((data.novelty_labels || {})[m.metric] || m.metric) })
      : m.kind === "volume" ? T("Menge: {x}", { x: tr((data.metric_labels || {})[m.metric] || m.metric) }) : T("Ungewöhnliche Uhrzeit");
    return what + (m.metric === "*" ? " (alle)" : "");
  }

  function AnomaliesPage({ tick, refresh, isAdmin }) {
    const [status, setStatus] = useState("open");
    const [local, setLocal] = useState(0);
    const { data, error } = useApi("/api/anomalies?status=" + status, [tick, local]);
    const [profile, setProfile] = useState(null);
    const [msg, setMsg] = useState(null);
    const reload = () => { setLocal((x) => x + 1); refresh(); };
    const act = async (path, body) => {
      try { await postJson(path, body); setMsg(null); } catch (e) { setMsg(e.message); }
      reload();
    };
    const mute = (a) => {
      const what = a.kind === "new" ? "„" + a.title + "“" : a.kind === "volume" ? "„" + a.title + "“" : "Aktivität zu ungewöhnlicher Uhrzeit";
      if (confirm(T("„{x}“ für dieses Gerät nicht mehr melden? (Lässt sich im Geräteprofil rückgängig machen.)", { x: what })))
        act("/api/anomalies/mute", { dev: a.dev, kind: a.kind, metric: a.metric });
    };
    const learned = data ? data.devices.filter((d) => d.learned).length : 0;
    return html`<div>
      <div class="card mb">
        <div class="card-head">
          <div>
            <h2>Anomalien im Verhalten lokaler Geräte</h2>
            <div class="sub">Das Dashboard lernt für jedes Gerät, wie viel, wann und wohin es normalerweise kommuniziert, und warnt bei deutlichen Abweichungen.
              ${data ? " " + T("Lernphase: {d} Tage (mind. 3 aktive). {n} von {t} Geräten werden überwacht.", { d: data.learning_days, n: learned, t: data.devices.length }) : ""}</div>
          </div>
          <div class="seg">
            <button class=${status === "open" ? "active" : ""} onClick=${() => setStatus("open")}>offen</button>
            <button class=${status === "all" ? "active" : ""} onClick=${() => setStatus("all")}>alle (30 Tage)</button>
          </div>
          ${isAdmin && data && data.items.some((a) => a.status === "open") && html`<button class="btn" onClick=${() => confirm(T("Alle offenen Warnungen als erledigt markieren?")) && act("/api/anomalies/ack", { all: true })}>Alle erledigt</button>`}
        </div>
        ${error && html`<div class="err">${error}</div>`}
        ${msg && html`<div class="err">${msg}</div>`}
        ${data && !data.enabled && html`<div class="warnmsg">Die Anomalieerkennung ist in config.json abgeschaltet (<span class="mono">"anomaly_detection": false</span>).</div>`}
        ${data && data.error && html`<div class="err">Fehler bei der letzten Prüfung: ${data.error}</div>`}
        ${!data ? html`<div class="empty">lädt …</div>` : !data.items.length ? html`<div class="empty">${status === "open" ? "Keine offenen Warnungen." : "Keine Warnungen in den letzten 30 Tagen."}
            ${data.devices.length && !learned ? " Die Geräte sind noch in der Lernphase." : ""}</div>` : html`
          <div class="table-wrap"><table class="anomaly-table">
            <thead><tr><th>Zeit</th><th>Gerät</th><th>Warnung</th><th></th></tr></thead>
            <tbody>${data.items.map((a) => html`<tr key=${a.id} class=${a.status !== "open" ? "harmless" : ""}>
              <td class="nowrap">${fmtDateTime(a.ts)}</td>
              <td><button class="link" onClick=${() => setProfile(a.dev)}><${DevLabel} device=${a.device} dev=${a.dev} /></button></td>
              <td><div><${SevBadge} s=${a.severity} /> <b>${a.title}</b>${a.status !== "open" ? html` <span class="badge harmless">erledigt</span>` : null}</div>
                <div class="cat">${anomalyExplain(a, data.novelty_labels)}</div></td>
              <td><div class="row-actions">
                <button class="btn" onClick=${() => setProfile(a.dev)}>Profil</button>
                ${isAdmin && (a.status === "open"
                  ? html`<button class="btn" onClick=${() => act("/api/anomalies/ack", { ids: [a.id] })}>Erledigt</button>
                         <button class="btn" title="Diese Art Warnung für dieses Gerät nicht mehr melden" onClick=${() => mute(a)}>Nicht mehr melden</button>`
                  : html`<button class="btn" onClick=${() => act("/api/anomalies/ack", { ids: [a.id], status: "open" })}>Wieder öffnen</button>`)}
              </div></td>
            </tr>`)}</tbody>
          </table></div>`}
        ${data && html`<div class="cat" style=${{ marginTop: 10 }}>
          Neue Warnungen stehen auch im Log${data.notify ? " und werden per Benachrichtigung verschickt" : " (Benachrichtigung aufs Handy: anomaly_notify_url in config.json, siehe README)"}.
          ${data.last_run ? " " + T("Letzte Prüfung {x}.", { x: fmtAgo(data.last_run) }) : ""}
          ${isAdmin && data.enabled ? html` <button class="link" onClick=${() => act("/api/anomalies/check", {})}>Jetzt prüfen</button>` : null}</div>`}
      </div>

      <div class="card">
        <h2>Geräte</h2>
        <div class="sub">Alle lokalen Geräte der letzten 7 Tage mit ihrem gelernten Verhalten. Klick auf ein Gerät zeigt das Profil.</div>
        ${data && !data.devices.length ? html`<div class="empty">Noch keine Geräte gesehen. Das Profil entsteht aus flow-, dns- und tls-Events in eve.json.</div>` : null}
        ${data && data.devices.length ? html`<div class="table-wrap"><table>
          <thead><tr><th>Gerät</th><th>Status</th><th>Beobachtet seit</th><th class="num">Daten/Std (99 %)</th><th class="num">Verbindungen/Std (99 %)</th><th>Kennt</th><th class="num">Offen</th></tr></thead>
          <tbody>${data.devices.map((d) => html`<tr key=${d.dev}>
            <td><button class="link" onClick=${() => setProfile(d.dev)}><${DevLabel} device=${d.device} dev=${d.dev} /></button></td>
            <td class="nowrap">${d.learned ? html`<span class="rep known">überwacht</span>`
              : html`<span class="rep unknown" title=${(d.learn_left > 0 ? T("noch {x}", { x: fmtDur(d.learn_left) }) : "") + (d.need_active ? " · " + T("noch {n} aktive Tage", { n: d.need_active }) : "")}>lernt noch${d.learn_left > 0 ? " · " + fmtDur(d.learn_left) : ""}</span>`}</td>
            <td class="nowrap">${fmtDateTime(d.first_seen)}</td>
            <td class="num">${fmtBytes(d.stats.bytes_out.p99)}</td>
            <td class="num">${fmtNum(d.stats.flows.p99)}</td>
            <td class="cat">${["port", "country", "domain", "lan_port", "in_port"].filter((k) => d.known[k]).map((k) => data.novelty_labels[k] + " " + d.known[k]).join(" · ") || "–"}</td>
            <td class="num">${d.open ? html`<span class="rep malicious">${d.open}</span>` : "–"}</td>
          </tr>`)}</tbody>
        </table></div>` : null}
        ${data && data.mutes.length ? html`<div class="cat" style=${{ marginTop: 10 }}>${data.mutes.length} stummgeschaltete Warnungsart(en) – zu sehen und rückgängig zu machen im jeweiligen Geräteprofil.</div>` : null}
        <div class="cat" style=${{ marginTop: 12 }}>
          <b>So wird geprüft:</b> Mengen (gesendete Daten, Verbindungen, Gegenstellen, lokale Geräte, Ports, DNS) gegen das Maximum und den 99-%-Wert der letzten 14 Tage ·
          neue Ziel-Ports, Länder, Domains, LAN-Dienste und von außen erreichbare Dienste – aber nur bei Geräten, die in der Kategorie sonst selten Neues zeigen ·
          Aktivität zu Uhrzeiten, zu denen das Gerät sonst nie aktiv ist. Eine Warnung ist ein Hinweis zum Nachsehen, kein Beweis.</div>
      </div>
      ${profile && html`<${DeviceProfile} dev=${profile} isAdmin=${isAdmin} onClose=${() => setProfile(null)} onChanged=${reload} />`}
    </div>`;
  }

  // ------------------------------------------------------------------ TLS-Fingerprints

  const FP_TYPE_LABEL = { ja3: "JA3", ja3s: "JA3S", ja4: "JA4", ja4s: "JA4S" };
  const FP_TYPE_HINT = {
    ja3: "JA3: TLS-Client-Fingerabdruck (MD5)", ja3s: "JA3S: Antwort des Servers (MD5)",
    ja4: "JA4: TLS-/QUIC-Client-Fingerabdruck", ja4s: "JA4S: Antwort des Servers",
  };

  function FpBadge({ a }) {
    if (!a) return null;
    const label = a.labels && a.labels[0];
    const text = { malicious: label || "Malware", suspicious: label || "auffällig",
      known: label || "bekannt", unknown: "unbekannt" }[a.verdict] || a.verdict;
    const icon = { malicious: "⚠ ", suspicious: "! ", known: "✓ ", unknown: "" }[a.verdict] || "";
    const title = (a.reasons || []).map((r) => r.text).join("\n") || "Auf keiner geladenen Liste";
    return html`<span class=${"rep " + a.verdict} title=${title}>${icon}${text}</span>`;
  }

  function FpHead({ a, short }) {
    return html`<span class="fp-head">
      <span class="badge allowed fp-type" title=${FP_TYPE_HINT[a.type]}>${FP_TYPE_LABEL[a.type] || a.type}</span>
      <span class="mono fp">${a.fp}</span><${CopyButton} text=${a.fp} title="Fingerprint kopieren" />
      ${!short && html`<${FpBadge} a=${a} />`}
      ${a.harmless ? html`<span class="badge harmless">harmlos</span>` : null}
      ${a.note ? html`<span class="cat">„${a.note}“</span>` : null}
    </span>`;
  }

  function FpReasons({ a }) {
    const rs = (a.reasons || []).filter((r) => r.level !== "known" || a.verdict === "known");
    if (!rs.length) return null;
    return html`<ul class="reasons">${rs.map((r, i) => html`<li key=${i} class=${"lvl-" + (LEVEL_CLASS[r.level] || "unknown")}>${r.text}</li>`)}</ul>`;
  }

  function FpNoteDialog({ target, onClose, onDone }) {
    const [label, setLabel] = useState(target.note || "");
    const [harmless, setHarmless] = useState(target.harmless || target.verdict !== "unknown" ? !!target.harmless : false);
    const [err, setErr] = useState(null);
    const save = async (e) => {
      e.preventDefault();
      try { await postJson("/api/fingerprints/note", { type: target.type, fp: target.fp, label, harmless }); onDone(); }
      catch (x) { setErr(x.message); }
    };
    return html`<div class="modal-bg" onClick=${(e) => e.target === e.currentTarget && onClose()}>
      <form class="modal" role="dialog" aria-modal="true" aria-label="Fingerprint bearbeiten" onSubmit=${save}>
        <h3>${FP_TYPE_LABEL[target.type]}-Fingerprint bearbeiten</h3>
        <p class="mono fp">${target.fp}</p>
        <div class="field"><label>Eigene Bezeichnung</label>
          <input type="text" value=${label} maxLength="80" placeholder="z. B. „Home Assistant“ oder „Smart-TV-App“"
            onInput=${(e) => setLabel(e.target.value)} autoFocus /></div>
        <label class="switch"><input type="checkbox" checked=${harmless} onChange=${(e) => setHarmless(e.target.checked)} /><span class="slider"></span>
          Als harmlos markieren – zählt dann nicht mehr als Treffer</label>
        ${err && html`<div class="err" style=${{ marginTop: 10 }}>${err}</div>`}
        <div class="actions">
          <button type="button" class="btn" onClick=${onClose}>Abbrechen</button>
          <button class="btn primary">Speichern</button>
        </div>
        <div class="cat" style=${{ marginTop: 8 }}>Leere Bezeichnung und kein Haken entfernt den Eintrag wieder.</div>
      </form>
    </div>`;
  }

  function moreList(list, total, render) {
    return html`${list.slice(0, 3).map(render)}${total > 3 ? html`<div class="cat">+ ${total - 3} weitere</div>` : null}`;
  }

  const FP_FILTERS = [["all", "Alle"], ["hits", "Treffer"], ["new", "Neu"], ["unknown", "Unbekannt"]];

  function FingerprintsPage({ hours, tick, refresh, isAdmin }) {
    const [local, setLocal] = useState(0);
    const { data, error } = useApi(`/api/fingerprints?hours=${hours}`, [tick, local]);
    const [q, setQ] = useState("");
    const [view, setView] = useState("all");
    const [showHarmless, setShowHarmless] = useState(false);
    const [edit, setEdit] = useState(null);
    const names = React.useContext(DevCtx).names || {};

    const items = useMemo(() => {
      if (!data) return [];
      const term = q.trim().toLowerCase();
      return data.items.filter((a) => {
        if (a.harmless && !showHarmless) return false;
        if (view === "hits" && !(a.verdict === "malicious" || a.verdict === "suspicious")) return false;
        if (view === "new" && !a.is_new) return false;
        if (view === "unknown" && a.verdict !== "unknown") return false;
        if (!term) return true;
        const hay = [a.fp, a.note, ...(a.labels || []), ...a.clients.map((c) => c.ip + " " + ((names[c.ip] || [])[0] || "")),
          ...a.servers.map((x) => x.server)].join(" ").toLowerCase();
        return hay.includes(term);
      });
    }, [data, q, view, showHarmless, names]);
    const hidden = data ? data.items.filter((a) => a.harmless).length : 0;

    return html`<div>
      <div class="card">
        <div class="card-head">
          <div>
            <h2>TLS-Fingerprints</h2>
            <div class="sub">JA3 und JA4 beschreiben, <i>wie</i> ein Programm eine verschlüsselte Verbindung aufbaut – unabhängig von IP und Domain.
              So fallen Malware-Clients auf, aber auch unerwartete Programme (z. B. ein Python-Skript auf dem Fernseher). Geprüft gegen die Fingerprint-Listen im Tab Threat-Feeds.</div>
          </div>
        </div>
        <div class="filters">
          <input type="search" placeholder="Suche: Hash, Gerät, IP, Ziel, Bezeichnung" value=${q} onInput=${(e) => setQ(e.target.value)} />
          <div class="seg">${FP_FILTERS.map(([id, label]) => html`<button key=${id} class=${view === id ? "active" : ""} onClick=${() => setView(id)}>${label}</button>`)}</div>
          <label><input type="checkbox" checked=${showHarmless} onChange=${(e) => setShowHarmless(e.target.checked)} /> harmlose anzeigen${hidden ? " (" + hidden + ")" : ""}</label>
        </div>
        ${error && html`<div class="err">${error}</div>`}
        ${data && !data.feeds_loaded && html`<div class="warnmsg">Noch keine Fingerprint-Listen geladen – im Tab „Threat-Feeds“ aktualisieren. Bis dahin ist alles „unbekannt“.</div>`}
        ${!data ? html`<div class="empty">lädt …</div>`
          : !data.any_data ? html`<div class="okmsg fp-setup">
              <b>Noch keine JA3/JA4-Daten in eve.json gefunden.</b> Das Dashboard liest die Felder <span class="mono">ja3</span>, <span class="mono">ja3s</span>, <span class="mono">ja4</span> und <span class="mono">ja4s</span> aus <span class="mono">tls</span>- und <span class="mono">quic</span>-Events.
              In <span class="mono">suricata.yaml</span> müssen die Fingerprints berechnet <i>und</i> im eve-log ausgegeben werden, z. B.:
              <pre class="mono">app-layer:
  protocols:
    tls:
      ja3-fingerprints: yes
      ja4-fingerprints: yes   # ab Suricata 7.0.4/8
outputs:
  - eve-log:
      types:
        - tls:
            extended: yes
            custom: [subject, issuer, sni, version, ja3, ja3s, ja4]</pre>
              Die genauen Schlüssel hängen von der Suricata-Version ab. Danach Suricata neu starten.</div>`
          : !items.length ? html`<div class="empty">${data.items.length ? "Nichts passt zum Filter." : "Im Zeitraum keine Fingerprints gesehen."}</div>`
          : html`<div class="table-wrap"><table class="fp-table">
            <thead><tr><th>Fingerprint</th><th>Geräte</th><th>Ziele</th><th class="num">Verbindungen</th><th>Zuerst gesehen</th><th>Zuletzt</th>${isAdmin && html`<th></th>`}</tr></thead>
            <tbody>${items.map((a) => html`<tr key=${a.type + a.fp} class=${(a.harmless ? "harmless " : "") + (a.is_new && !a.harmless ? "is-new" : "")}>
              <td class="fp-cell">
                <${FpHead} a=${a} />
                ${a.is_new && !a.harmless ? html` <span class="badge new">NEU</span>` : null}
                ${a.verdict !== "unknown" && a.verdict !== "known" ? html`<${FpReasons} a=${a} />` : null}
              </td>
              <td>${moreList(a.clients, a.clients_total, (c) => html`<div key=${c.ip} class="nowrap"><span class="mono">${c.ip}</span> <${DevName} ip=${c.ip} /></div>`)}</td>
              <td>${moreList(a.servers, a.servers_total, (x) => html`<div key=${x.server} class="fp-server" title=${T("{n} Verbindungen", { n: fmtNum(x.count) })}>${x.server}</div>`)}</td>
              <td class="num">${fmtNum(a.conns)}</td>
              <td class="nowrap">${fmtDateTime(a.first_seen)}</td>
              <td class="nowrap">${fmtAgo(a.last_seen)}</td>
              ${isAdmin && html`<td><button class="btn" onClick=${() => setEdit(a)}>${a.note || a.harmless ? "Bearbeiten" : "Notiz / harmlos"}</button></td>`}
            </tr>`)}</tbody>
          </table></div>`}
        ${data && data.any_data ? html`<div class="cat" style=${{ marginTop: 12 }}>
          ${Object.entries(data.types).map(([t, n]) => fmtNum(n) + " " + FP_TYPE_LABEL[t]).join(" · ")} im Zeitraum.
          „NEU“ = erstmals in den letzten ${data.new_hours} Std gesehen. JA3 ist nicht eindeutig – verschiedene Programme können denselben Hash haben. Ein Treffer ist ein Hinweis, kein Beweis: Gerät und Ziele ansehen.</div>` : null}
      </div>
      ${edit && html`<${FpNoteDialog} target=${edit} onClose=${() => setEdit(null)}
        onDone=${() => { setEdit(null); setLocal((x) => x + 1); refresh(); }} />`}
    </div>`;
  }

  // ------------------------------------------------------------------ Geraete

  const MAC_INPUT_RE = /^[0-9a-f]{2}([:-]?)[0-9a-f]{2}(\1[0-9a-f]{2}){4}$/i;
  // zweites Bit des ersten Oktetts = lokal verwaltet (zufaellige/private WLAN-MAC)
  const isRandomMac = (mac) => !!mac && /^.[26ae]/i.test(mac);
  const NAME_SRC = { mac: "per MAC-Adresse", ip: "per IP-Adresse", dhcp: "Hostname aus DHCP" };

  function saveDeviceName(kind, key, name, extra) {
    return api("/api/devices", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kind, key, name, ...(extra || {}) }),
    });
  }

  function NameEditor({ kind, k, value, placeholder, onSaved, extra }) {
    const [v, setV] = useState(value || "");
    const [state, setState] = useState(null);   // null | "saving" | "ok" | Fehlertext
    useEffect(() => setV(value || ""), [value, k]);
    const save = async () => {
      if (v.trim() === (value || "")) return;
      setState("saving");
      try {
        await saveDeviceName(kind, k, v, extra);
        setState("ok");
        if (onSaved) onSaved();
        setTimeout(() => setState(null), 1500);
      } catch (e) { setState(e.message); }
    };
    return html`<div class="name-edit">
      <input type="text" value=${v} maxLength="64" placeholder=${placeholder || "Name vergeben …"}
        aria-label="Gerätename" onChange=${(e) => setV(e.target.value)} onBlur=${save}
        onKeyDown=${(e) => { if (e.key === "Enter") e.target.blur(); if (e.key === "Escape") setV(value || ""); }} />
      ${state === "ok" ? html`<span class="saved" title="gespeichert">✓</span>`
        : state === "saving" ? html`<span class="cat">…</span>`
        : state ? html`<span class="err-inline">${state}</span>` : null}
    </div>`;
  }

  function DevicesPage({ tick, goAlerts }) {
    const { reload } = React.useContext(DevCtx);
    const [t, setT] = useState(0);
    const { data, error } = useApi("/api/devices", [tick, t]);
    const [q, setQ] = useState("");
    const [onlyNamed, setOnlyNamed] = useState(false);
    const [newKey, setNewKey] = useState("");
    const [newName, setNewName] = useState("");
    const [msg, setMsg] = useState(null);
    const changed = () => { setT((x) => x + 1); reload(); };
    const s = q.trim().toLowerCase();
    const list = data && data.devices.filter((d) => {
      if (onlyNamed && !d.name) return false;
      return !s || [d.name, d.dhcp, d.mac, ...d.ips.map((h) => h.ip)].some((x) => x && x.toLowerCase().includes(s));
    });
    const add = async (e) => {
      e.preventDefault();
      const k = newKey.trim();
      if (!k || !newName.trim()) return setMsg({ err: true, text: "Bitte MAC- oder IP-Adresse und Namen eingeben." });
      try {
        await saveDeviceName(MAC_INPUT_RE.test(k) ? "mac" : "ip", k, newName, { replace_ip_names: true });
        setNewKey(""); setNewName(""); setMsg({ text: T("„{x}“ gespeichert.", { x: newName.trim() }) });
        changed();
      } catch (err) { setMsg({ err: true, text: err.message }); }
    };
    const remove = async (d) => {
      try { await saveDeviceName(d.kind, d.key, ""); changed(); } catch (e) { setMsg({ err: true, text: e.message }); }
    };

    return html`<div class="grid">
      <div class="card">
        <div class="card-head"><div>
          <h2>Geräte</h2>
          <div class="sub">Eigene Namen erscheinen bei Alerts, in der Übersicht und in der Live-Ansicht.
            Ist die MAC-Adresse bekannt, hängt der Name an ihr und bleibt auch bei einer neuen IP erhalten.</div>
        </div></div>
        ${error && html`<div class="err">${error}</div>`}
        ${data && !data.has_macs && html`<div class="err">
          Bisher wurden keine MAC-Adressen gesehen, deshalb hängen Namen vorerst an der IP-Adresse.
          Damit Suricata MAC-Adressen mitschreibt, in <span class="mono">/etc/suricata/suricata.yaml</span> beim
          <span class="mono">eve-log</span> die Option <span class="mono">ethernet: yes</span> setzen (ab Suricata 7) und Suricata neu starten.
          Auch <span class="mono">dhcp</span>-Events liefern MAC-Adresse und Hostname, wenn der Sensor die DHCP-Anfragen sieht.
        </div>`}
        <div class="filters">
          <input type="search" placeholder="Name, IP, MAC suchen …" value=${q} onChange=${(e) => setQ(e.target.value)} />
          <label><input type="checkbox" checked=${onlyNamed} onChange=${(e) => setOnlyNamed(e.target.checked)} /> nur benannte</label>
          ${list && html`<span class="cat">${list.length} von ${data.devices.length}</span>`}
        </div>
        ${!list ? html`<div class="empty">lädt …</div>` : !list.length ? html`<div class="empty">${data.devices.length ? "Keine Treffer." : "Noch keine lokalen Geräte gesehen."}</div>` : html`
        <div class="table-wrap"><table class="devices">
          <thead><tr><th>Name</th><th>Gerät</th><th>IP-Adressen</th><th>zuletzt gesehen</th><th></th></tr></thead>
          <tbody>${list.map((d) => {
            const ipName = d.ip_names && Object.values(d.ip_names)[0];
            const shown = d.name || ipName || d.dhcp;
            const more = d.ips.slice(1, 4).map((h) => h.ip);
            return html`<tr key=${d.kind + d.key}>
              <td class="dev-name">
                <${NameEditor} kind=${d.kind} k=${d.key} value=${d.name} onSaved=${changed}
                  placeholder=${ipName ? ipName + " " + T("(per IP)") : d.dhcp ? d.dhcp + " (DHCP)" : T("Name vergeben …")}
                  extra=${d.kind === "mac" ? { replace_ip_names: true } : null} />
                <div class="cat">${d.kind === "mac" ? "gilt für die MAC-Adresse" : "gilt für die IP-Adresse"}${d.dhcp && d.name ? " · DHCP: " + d.dhcp : ""}</div>
                ${d.ip_names && Object.entries(d.ip_names).map(([ip, n]) => html`<div key=${ip} class="cat dev-oldname">
                  ${d.name ? "Nicht mehr verwendet: " : "Bisher: "}„${n}“ per IP ${ip}${" · "}<button class="link" onClick=${() => saveDeviceName("ip", ip, "").then(changed)}>entfernen</button></div>`)}
              </td>
              <td>
                ${d.mac ? html`<span class="mono">${d.mac}</span>` : html`<span class="cat">keine MAC bekannt</span>`}
                <div class="dev-badges">
                  ${isRandomMac(d.mac) && html`<span class="badge" title="Lokal verwaltete MAC-Adresse, typisch für die WLAN-Privatsphäre-Funktion von Handys und Laptops. Sie bleibt pro WLAN meist gleich. Steht die Funktion auf „rotierend“, ändert sie sich, und der Name muss neu vergeben werden.">private MAC</span>`}
                  ${d.shared && html`<span class="badge warn" title=${"Diese MAC gehört zu mindestens " + data.shared_limit + " IPv4-Adressen, vermutlich ein Router zwischen Sensor und Geräten. Namen werden deshalb pro IP vergeben."}>geteilte MAC</span>`}
                  ${d.manual && html`<span class="badge" title="Von Hand angelegt, bisher nicht im Verkehr gesehen">noch nicht gesehen</span>`}
                </div>
              </td>
              <td>
                ${d.ips.length ? html`<button class="link mono" title="Alerts dieser IP anzeigen" onClick=${() => goAlerts({ ip: d.ips[0].ip })}>${d.ips[0].ip}</button>` : html`<span class="cat">–</span>`}
                ${more.length > 0 && html`<div class="cat mono dev-more">${more.join(", ")}${d.ips.length > 4 ? " +" + (d.ips.length - 4) : ""}</div>`}
              </td>
              <td class="nowrap" title=${fmtDateTime(d.last_seen)}>${d.last_seen ? fmtAgo(d.last_seen) : "–"}</td>
              <td>${shown && d.name ? html`<button class="icon-btn" title=${T("Namen „{x}“ entfernen", { x: d.name })} onClick=${() => remove(d)}>✕</button>` : null}</td>
            </tr>`;
          })}</tbody>
        </table></div>`}
      </div>

      <div class="card">
        <h2>Gerät von Hand eintragen</h2>
        <div class="sub">Für Geräte, die noch nicht aufgetaucht sind. Eine MAC-Adresse ist besser als eine IP, weil sie sich nicht ändert.</div>
        <form class="filters dev-add" onSubmit=${add}>
          <input type="text" class="mono" placeholder="MAC oder IP, z. B. 3c:22:fb:12:34:56" value=${newKey} onChange=${(e) => setNewKey(e.target.value)} />
          <input type="text" placeholder="Name" maxLength="64" value=${newName} onChange=${(e) => setNewName(e.target.value)} />
          <button class="btn primary" type="submit">Speichern</button>
        </form>
        ${msg && html`<div class=${msg.err ? "err" : "okmsg"}>${msg.text}</div>`}
        <div class="cat">Der Name per MAC gilt für alle Adressen des Geräts, auch für IPv6. Haben eine MAC und eine IP beide einen Namen, gewinnt die MAC.
          Alte Alerts zeigen den Namen des Geräts, das die IP <em>jetzt</em> hat.</div>
      </div>
    </div>`;
  }

  function StatusPage({ tick }) {
    const { data: s, error } = useApi("/api/status", [tick]);
    const { data: et } = useApi("/api/event_types?hours=24", [tick]);
    const file = (f) => f && html`<dd>${f.path}<br/>
      <span class="cat">gelesen ${fmtBytes(f.offset)} von ${fmtBytes(f.size)}${f.error ? " · " + T("Fehler: {x}", { x: f.error }) : ""}${f.used === false ? " · nicht verwendet (alert_source=eve)" : ""}</span></dd>`;
    return html`<div class="grid cols-2">
      <div class="card">
        <h2>Einlesen</h2><div class="sub">Zustand des Hintergrund-Prozesses</div>
        ${error && html`<div class="err">${error}</div>`}
        ${s && html`<dl class="kv">
          <dt>eve.json</dt>${file(s.files.eve_json)}
          <dt>fast.log</dt>${file(s.files.fast_log)}
          <dt>Alert-Quelle</dt><dd>${s.alert_source}</dd>
          <dt>Letzter Durchlauf</dt><dd>${fmtDateTime(s.last_cycle)} (${s.last_cycle_seconds}s)${s.behind ? " · holt noch Rückstand auf …" : ""}</dd>
          <dt>Zeilen verarbeitet</dt><dd>${fmtNum(s.lines_total)} seit Start · ${fmtNum(s.parse_errors)} nicht lesbar</dd>
          <dt>Datenbank</dt><dd>${fmtBytes(s.db_size)} · ${fmtNum(s.alerts_in_db)} Alerts · ${fmtNum(s.flags)} Markierungen</dd>
          <dt>Daten von</dt><dd>${fmtDateTime(s.data_from)} bis ${fmtDateTime(s.data_to)}</dd>
          <dt>Aufbewahrung</dt><dd>${s.retention_days} Tage</dd>
          <dt>Version</dt><dd>Backend ${s.version || "alt (< 1.2.0)"} · Frontend ${FRONTEND_VERSION}</dd>
          <dt>Installiert in</dt><dd class="mono">${s.install_dir || "–"}</dd>
        </dl>`}
      </div>
      <div class="card">
        <h2>Event-Typen</h2><div class="sub">eve.json, letzte 24 Std</div>
        <${BarList} rows=${et} label=${(r) => r.name} value=${(r) => r.n} />
      </div>
    </div>`;
  }

  const KIND_LABEL = { ip: "IP-Liste", domain: "Domain-Liste", rank: "Rangliste", asn: "Netzbetreiber",
    ja3: "JA3-Liste", ja4: "JA4-Liste", ja4map: "JA4-Zuordnung" };
  const CAT_LABEL = { malicious: "bösartig", suspicious: "auffällig" };

  function LookupCard() {
    const [q, setQ] = useState("");
    const [res, setRes] = useState(null);
    const [err, setErr] = useState(null);
    const [busy, setBusy] = useState(false);
    const run = async (e) => {
      e && e.preventDefault();
      if (!q.trim()) return;
      setBusy(true); setErr(null);
      try { setRes(await api("/api/intel/lookup?q=" + encodeURIComponent(q.trim()))); }
      catch (x) { setErr(x.message); setRes(null); }
      setBusy(false);
    };
    const d = res && res.domain;
    return html`<div class="card mb">
      <h2>Reputation prüfen</h2>
      <div class="sub">IP-Adresse, Domain oder JA3/JA4-Fingerprint gegen alle geladenen Feeds und die gesehenen Daten prüfen</div>
      <form class="filters" onSubmit=${run}>
        <input type="text" class="mono lookup-input" placeholder="z. B. 13.107.4.50, windowsupdate.com oder t13d1516h2_8daaf6152771_02713d6af862" value=${q} onInput=${(e) => setQ(e.target.value)} />
        <button class="btn primary" disabled=${busy}>${busy ? "prüfe …" : "Prüfen"}</button>
      </form>
      ${err && html`<div class="err">${err}</div>`}
      ${res && res.type === "ip" && html`<div>
        <${RepDetail} a=${res.ip} />
        <div class="cat" style=${{ marginTop: 6 }}>${res.alerts ? fmtNum(res.alerts) + " Alerts mit dieser IP in der Datenbank, zuletzt " + fmtAgo(res.last_alert) : "Keine Alerts mit dieser IP in der Datenbank."}</div>
      </div>`}
      ${res && res.type === "fingerprint" && res.items.map((a) => html`<div key=${a.type} class="rep-card" style=${{ marginBottom: 8 }}>
        <div class="rep-card-head"><${FpHead} a=${a} /></div>
        <${FpReasons} a=${a} />
        ${!a.matches.length && html`<div class="cat">Auf keiner geladenen Fingerprint-Liste.</div>`}
        ${a.clients ? html`<div class="cat">${fmtNum(a.clients)} Gerät(e), ${fmtNum(a.conns)} Verbindungen, zuerst ${fmtDateTime(a.first_seen)}, zuletzt ${fmtAgo(a.last_seen)}</div>
          <div class="grid cols-2" style=${{ marginTop: 6 }}>
            <div><div class="cat">Geräte</div>${a.clients_list.map((c) => html`<div key=${c.ip} class="example"><span class="mono">${c.ip}</span> <${DevName} ip=${c.ip} /> <span class="cat">×${fmtNum(c.count)}</span></div>`)}</div>
            <div><div class="cat">Ziele</div>${a.servers_list.map((x) => html`<div key=${x.server} class="example"><span class="mono">${x.server}</span> <span class="cat">×${fmtNum(x.count)}</span></div>`)}</div>
          </div>`
          : html`<div class="cat">Dieser Fingerprint wurde im Netz noch nicht gesehen.</div>`}
      </div>`)}
      ${res && res.type === "domain" && html`<div class="rep-card">
        <div class="rep-card-head"><span class="mono">${d.name}</span>
          ${d.lists.length ? html`<span class="rep malicious">⚠ ${d.lists.map((l) => l.name).join(", ")}</span>`
            : d.service ? html`<span class="rep known">✓ ${d.service}</span>` : html`<span class="rep unknown">auf keiner Liste</span>`}</div>
        <div class="cat">${d.rank ? T("Tranco-Rang {n}", { n: fmtNum(d.rank) }) : T("nicht in den Tranco-Top-Domains")}${d.lists.some((l) => l.via !== d.name) ? " · " + T("gelistet als {x}", { x: d.lists.map((l) => l.via).join(", ") }) : ""}</div>
        ${res.ips.length ? html`<div style=${{ marginTop: 8 }}><div class="cat">Im Netz gesehene IPs zu dieser Domain:</div>
          ${res.ips.map((r) => html`<div key=${r.ip} class="example"><span class="mono">${r.ip}</span> <${RepBadge} r=${r} withName /></div>`)}</div>`
          : html`<div class="cat">Diese Domain wurde im Netz noch nicht gesehen.</div>`}
      </div>`}
    </div>`;
  }

  function FeedsPage({ tick }) {
    const [local, setLocal] = useState(0);
    const { data: s, error } = useApi("/api/intel/status", [tick, local]);
    const [msg, setMsg] = useState(null);
    const busy = s && (s.busy || s.feeds.some((f) => f.queued));
    useEffect(() => {  // waehrend Updates laufen, alle 3 s neu laden
      if (!busy) return;
      const t = setTimeout(() => setLocal((x) => x + 1), 3000);
      return () => clearTimeout(t);
    }, [busy, s]);
    const post = async (path, body) => {
      try {
        await api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
        setMsg(null);
      } catch (e) { setMsg(e.message); }
      setLocal((x) => x + 1);
    };
    return html`<div>
      <${LookupCard} />
      <div class="card">
        <div class="card-head">
          <div>
            <h2>Threat-Feeds</h2>
            <div class="sub">Öffentliche Listen, die automatisch geladen und in <span class="mono">${s ? s.dir : "data/feeds"}</span> gespeichert werden. Jeder Alert wird beim Anzeigen dagegen geprüft.</div>
          </div>
          <button class="btn" disabled=${busy} onClick=${() => post("/api/intel/update", {})}>${busy ? "aktualisiere …" : "Alle jetzt aktualisieren"}</button>
        </div>
        ${error && html`<div class="err">${error}</div>`}
        ${msg && html`<div class="err">${msg}</div>`}
        ${s && !s.enabled && html`<div class="err">Automatische Updates sind in config.json abgeschaltet (<span class="mono">"threat_intel": false</span>). Manuelles Aktualisieren funktioniert trotzdem.</div>`}
        ${!s ? html`<div class="empty">lädt …</div>` : html`<div class="table-wrap"><table>
          <thead><tr><th></th><th>Feed</th><th>Art</th><th class="num">Einträge</th><th>Stand</th><th></th></tr></thead>
          <tbody>${s.feeds.map((f) => html`<tr key=${f.id} class=${f.enabled ? "" : "harmless"}>
            <td><input type="checkbox" checked=${f.enabled} title=${f.enabled ? "deaktivieren" : "aktivieren"}
              onChange=${(e) => post("/api/intel/feeds", { id: f.id, enabled: e.target.checked })} /></td>
            <td><div class="sig">${f.homepage ? html`<a href=${f.homepage} target="_blank" rel="noopener noreferrer">${f.name}</a>` : f.name}${f.custom ? html` <span class="badge allowed">eigener</span>` : null}</div>
              <div class="cat">${f.info}</div>
              ${f.error && html`<div class="check bad">✕ ${f.error}</div>`}</td>
            <td class="nowrap">${KIND_LABEL[f.kind] || f.kind}${f.category && ["ip", "domain", "ja3", "ja4"].includes(f.kind) ? html`<div class="cat">${CAT_LABEL[f.category] || f.category}</div>` : null}</td>
            <td class="num">${f.entries != null ? fmtNum(f.entries) : "–"}</td>
            <td class="nowrap">${f.updating ? "lädt …" : f.queued ? "in Warteschlange" : f.last_success ? fmtAgo(f.last_success) : "noch nie"}
              <div class="cat">${T("alle {x}", { x: f.interval_h >= 48 ? T("{n} Tage", { n: Math.round(f.interval_h / 24) }) : T("{n} Std", { n: f.interval_h }) })}</div></td>
            <td><button class="btn" disabled=${!f.enabled || f.updating || f.queued} onClick=${() => post("/api/intel/update", { id: f.id })}>aktualisieren</button></td>
          </tr>`)}</tbody>
        </table></div>
        <div class="cat" style=${{ marginTop: 12 }}>
          ${T("Hostnamen-Zuordnung: {n} IP/Name-Paare für {i} IPs aus DNS-Antworten, TLS-SNI und HTTP-Host", { n: fmtNum(s.ip_names.n), i: fmtNum(s.ip_names.ips) })}${s.ip_names.since ? " " + T("(seit {x})", { x: fmtDateTime(s.ip_names.since) }) : ""}.
          Darüber werden Domain-Listen und ${fmtNum(s.trusted_domains)} bekannte Update-/Systemdienste (z. B. Windows Update, Apple, Debian) einer IP zugeordnet.
          Eigene vertrauenswürdige Domains und Feeds lassen sich in <span class="mono">config.json</span> eintragen (<span class="mono">trusted_domains</span>, <span class="mono">custom_feeds</span>).
        </div>`}
      </div>
    </div>`;
  }

  function FileCheck({ c }) {
    if (!c) return null;
    if (c.exists && c.readable)
      return html`<div class="check ok">✓ gefunden · ${fmtBytes(c.size)}</div>`;
    return html`<div class="check bad">✕ ${c.error || "nicht lesbar"}</div>`;
  }

  function PathField({ label, hint, value, onChange, check, candidates }) {
    return html`<div class="field">
      <label>${label}</label>
      <input type="text" class="mono" spellcheck="false" value=${value}
        onInput=${(e) => onChange(e.target.value)} placeholder="/pfad/zur/datei" />
      <${FileCheck} c=${check} />
      ${hint && html`<div class="cat">${hint}</div>`}
      ${candidates && candidates.length > 0 && html`<div class="candidates">
        <div class="cat">Gefunden – zum Übernehmen anklicken:</div>
        ${candidates.map((c) => html`<button key=${c.path} class="btn mono" onClick=${() => onChange(c.path)}>
          ${c.path} <span class="cat">${c.readable ? fmtBytes(c.size) : "keine Leserechte"}</span></button>`)}
      </div>`}
    </div>`;
  }


  // ------------------------------------------------------------------ Konto & Benutzer

  function PasswordModal({ me, forced, onClose, onDone }) {
    const [f, setF] = useState({ old: "", neu: "", rep: "" });
    const [err, setErr] = useState(null);
    const [busy, setBusy] = useState(false);
    const min = (me && me.min_password) || 8;
    const set = (k) => (e) => { setF({ ...f, [k]: e.target.value }); setErr(null); };
    const submit = async (e) => {
      e.preventDefault();
      if (f.neu.length < min) return setErr(T("Das neue Passwort muss mindestens {n} Zeichen lang sein.", { n: min }));
      if (f.neu !== f.rep) return setErr("Die beiden neuen Passwörter stimmen nicht überein.");
      setBusy(true);
      try { await postJson("/api/me/password", { old: f.old, new: f.neu }); onDone(); }
      catch (x) { setErr(x.message); }
      setBusy(false);
    };
    return html`<div class="modal-bg" onClick=${(e) => !forced && e.target === e.currentTarget && onClose()}>
      <form class="modal" role="dialog" aria-modal="true" aria-label="Passwort ändern" onSubmit=${submit}>
        <h3>${forced ? "Neues Passwort festlegen" : "Passwort ändern"}</h3>
        ${forced && html`<p>Du bist mit einem vorläufigen Passwort angemeldet. Lege jetzt ein eigenes fest, um das Dashboard zu nutzen.</p>`}
        <input type="text" autocomplete="username" value=${me.username} readOnly hidden />
        <div class="field"><label>Bisheriges Passwort</label>
          <input type="password" autocomplete="current-password" value=${f.old} onInput=${set("old")} required autoFocus /></div>
        <div class="field"><label>Neues Passwort <span class="cat">(mindestens ${min} Zeichen)</span></label>
          <input type="password" autocomplete="new-password" value=${f.neu} onInput=${set("neu")} required /></div>
        <div class="field"><label>Neues Passwort wiederholen</label>
          <input type="password" autocomplete="new-password" value=${f.rep} onInput=${set("rep")} required /></div>
        ${err && html`<div class="err">${err}</div>`}
        <div class="actions">
          ${forced ? html`<button type="button" class="btn" onClick=${logout}>Abmelden</button>`
            : html`<button type="button" class="btn" onClick=${onClose}>Abbrechen</button>`}
          <button class="btn primary" disabled=${busy}>Speichern</button>
        </div>
        <div class="cat" style=${{ marginTop: 10 }}>Andere Sitzungen dieses Kontos werden dabei abgemeldet.</div>
      </form>
    </div>`;
  }

  async function logout() {
    try { await api("/api/logout", { method: "POST" }); } catch (e) {}
    window.location.replace("/login");
  }

  function UserMenu({ me, onPassword }) {
    const [open, setOpen] = useState(false);
    const ref = useRef(null);
    useEffect(() => {
      if (!open) return;
      const h = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
      document.addEventListener("mousedown", h);
      return () => document.removeEventListener("mousedown", h);
    }, [open]);
    return html`<div class="user-menu" ref=${ref}>
      <button class="icon-btn user-btn" title="Konto" onClick=${() => setOpen(!open)}>👤 ${me.username}</button>
      ${open && html`<div class="menu">
        <div class="who"><b>${me.username}</b><br /><span class=${"role " + me.role}>${me.roles[me.role]}</span></div>
        <button onClick=${() => { setOpen(false); onPassword(); }}>Passwort ändern</button>
        <button onClick=${logout}>Abmelden</button>
      </div>`}
    </div>`;
  }

  function SetPasswordModal({ user, min, onClose, onSaved }) {
    const [pw, setPw] = useState("");
    const [must, setMust] = useState(true);
    const [err, setErr] = useState(null);
    const submit = async (e) => {
      e.preventDefault();
      if (pw.length < min) return setErr(T("Mindestens {n} Zeichen.", { n: min }));
      try { onSaved(await postJson("/api/users", { op: "password", username: user, password: pw, must_change: must })); }
      catch (x) { setErr(x.message); }
    };
    return html`<div class="modal-bg" onClick=${(e) => e.target === e.currentTarget && onClose()}>
      <form class="modal" role="dialog" aria-modal="true" aria-label="Passwort setzen" onSubmit=${submit}>
        <h3>Passwort für ${user} setzen</h3>
        <p>Alle Sitzungen von ${user} werden beendet.</p>
        <div class="field"><label>Neues Passwort</label>
          <input type="password" autocomplete="new-password" value=${pw} onInput=${(e) => { setPw(e.target.value); setErr(null); }} autoFocus /></div>
        <label class="switch"><input type="checkbox" checked=${must} onChange=${(e) => setMust(e.target.checked)} /><span class="slider"></span> Muss bei der nächsten Anmeldung geändert werden</label>
        ${err && html`<div class="err" style=${{ marginTop: 10 }}>${err}</div>`}
        <div class="actions">
          <button type="button" class="btn" onClick=${onClose}>Abbrechen</button>
          <button class="btn primary">Speichern</button>
        </div>
      </form>
    </div>`;
  }

  function UsersCard({ me }) {
    const [data, setData] = useState(null);
    const [msg, setMsg] = useState(null);
    const [pwFor, setPwFor] = useState(null);
    const empty = { username: "", password: "", role: "viewer", must_change: true };
    const [add, setAdd] = useState(empty);

    const load = () => api("/api/users").then(setData).catch((e) => setMsg({ err: true, text: e.message }));
    useEffect(() => { load(); }, []);
    const run = async (body, ok) => {
      setMsg(null);
      try { setData(await postJson("/api/users", body)); if (ok) setMsg({ err: false, text: ok }); return true; }
      catch (e) { setMsg({ err: true, text: e.message }); return false; }
    };
    const submitAdd = async (e) => {
      e.preventDefault();
      if (await run({ op: "add", ...add }, T("Benutzer „{x}“ angelegt.", { x: add.username }))) setAdd(empty);
    };
    if (!data) return html`<div class="card settings">${msg ? html`<div class="err">${msg.text}</div>` : html`<div class="empty">lädt …</div>`}</div>`;
    const self = (u) => u.username.toLowerCase() === me.username.toLowerCase();
    return html`<div class="card settings">
      <h2>Benutzer</h2>
      <div class="sub">Wer das Dashboard öffnen darf. <b>Administrator</b> darf alles, <b>Nur lesen</b> sieht alle Daten, kann aber nichts markieren, benennen oder einstellen.</div>
      <div class="table-wrap"><table class="users-table">
        <thead><tr><th>Benutzer</th><th>Rolle</th><th>Letzte Anmeldung</th><th>Sitzungen</th><th></th></tr></thead>
        <tbody>${data.users.map((u) => html`<tr key=${u.username}>
          <td><b>${u.username}</b>${self(u) ? html` <span class="cat">(du)</span>` : null}
            ${u.must_change ? html`<div class="cat">muss Passwort ändern</div>` : null}</td>
          <td>${self(u) ? html`<span class=${"role " + u.role}>${data.roles[u.role]}</span>`
            : html`<div class="seg">${Object.entries(data.roles).map(([r, label]) => html`
                <button key=${r} class=${u.role === r ? "active" : ""} onClick=${() => u.role !== r && run({ op: "role", username: u.username, role: r })}>${label}</button>`)}</div>`}</td>
          <td>${u.last_login ? fmtDateTime(u.last_login) : html`<span class="cat">nie</span>`}</td>
          <td class="num">${u.sessions}</td>
          <td><div class="row-actions">${!self(u) && html`
            <button class="btn" onClick=${() => setPwFor(u.username)}>Passwort …</button>
            ${u.sessions > 0 && html`<button class="btn" onClick=${() => run({ op: "logout", username: u.username }, T("{x} wurde abgemeldet.", { x: u.username }))}>Abmelden</button>`}
            <button class="btn danger" onClick=${() => confirm(T("Benutzer „{x}“ wirklich löschen?", { x: u.username })) && run({ op: "delete", username: u.username }, "Benutzer gelöscht.")}>Löschen</button>`}
          </div></td>
        </tr>`)}</tbody>
      </table></div>

      <form class="inline-form" onSubmit=${submitAdd} autocomplete="off">
        <div class="field"><label>Neuer Benutzer</label>
          <input type="text" placeholder="Benutzername" value=${add.username} autocomplete="off"
            onInput=${(e) => setAdd({ ...add, username: e.target.value.trim() })} required /></div>
        <div class="field"><label>Passwort <span class="cat">(≥ ${data.min_password})</span></label>
          <input type="password" autocomplete="new-password" value=${add.password}
            onInput=${(e) => setAdd({ ...add, password: e.target.value })} required /></div>
        <div class="field"><label>Rolle</label>
          <select value=${add.role} onChange=${(e) => setAdd({ ...add, role: e.target.value })}>
            ${Object.entries(data.roles).map(([r, label]) => html`<option key=${r} value=${r}>${label}</option>`)}
          </select></div>
        <div class="field"><button class="btn primary">Hinzufügen</button></div>
      </form>
      <label class="switch" style=${{ marginTop: 8 }}><input type="checkbox" checked=${add.must_change}
        onChange=${(e) => setAdd({ ...add, must_change: e.target.checked })} /><span class="slider"></span> Neuer Benutzer muss das Passwort bei der ersten Anmeldung ändern</label>
      ${msg && html`<div class=${msg.err ? "err" : "okmsg"} style=${{ marginTop: 10 }}>${msg.text}</div>`}
      <div class="cat" style=${{ marginTop: 12 }}>Passwort vergessen? Auf dem Pi: <span class="mono">sudo ./users.sh passwd admin</span></div>
      ${pwFor && html`<${SetPasswordModal} user=${pwFor} min=${data.min_password} onClose=${() => setPwFor(null)}
        onSaved=${(d) => { setData(d); setMsg({ err: false, text: T("Passwort für {x} gesetzt.", { x: pwFor }) }); setPwFor(null); }} />`}
    </div>`;
  }

  function HttpsCard() {
    const [st, setSt] = useState(null);
    const [form, setForm] = useState(null);
    const [msg, setMsg] = useState(null);
    const [busy, setBusy] = useState(false);
    useEffect(() => {
      api("/api/https").then((s) => {
        setSt(s);
        setForm({ enabled: s.configured, https_port: s.https_port, http_redirect: s.http_redirect });
      }).catch((e) => setMsg({ err: true, text: e.message }));
    }, []);
    if (!st || !form) return html`<div class="card settings">${msg ? html`<div class="err">${msg.text}</div>` : html`<div class="empty">lädt …</div>`}</div>`;

    const save = async (extra) => {
      setBusy(true); setMsg(null);
      try {
        const r = await postJson("/api/https", { ...form, https_port: Number(form.https_port), ...(extra || {}) });
        const url = r.scheme + "://" + location.hostname + ":" + r.port + "/";
        setMsg({ err: false, text: T("Gespeichert. Das Dashboard startet neu und ist gleich unter {x} erreichbar …", { x: url }) });
        setTimeout(() => { window.location.href = url; }, 4000);
      } catch (e) { setMsg({ err: true, text: e.message }); setBusy(false); }
    };
    const c = st.cert;
    const daysLeft = c && c.not_after ? Math.floor((c.not_after - Date.now() / 1000) / 86400) : null;
    const changed = form.enabled !== st.configured || Number(form.https_port) !== st.https_port || form.http_redirect !== st.http_redirect;
    return html`<div class="card settings">
      <h2>HTTPS</h2>
      <div class="sub">Verschlüsselt die Verbindung zum Dashboard, damit Passwörter und Daten im Netz nicht mitgelesen werden können.</div>
      ${!st.auth && html`<div class="warnmsg">Die Anmeldung ist in <span class="mono">config.json</span> abgeschaltet (<span class="mono">"auth": false</span>). Jeder im Netz hat vollen Zugriff.</div>`}
      <dl class="kv">
        <dt>Status</dt><dd>${st.active ? html`<span class="check ok">✓ aktiv auf Port ${st.https_port}</span>` : html`<span class="cat">aus – unverschlüsseltes HTTP auf Port ${st.http_port}</span>`}</dd>
        ${st.error && html`<dt>Fehler</dt><dd class="check bad">${st.error}</dd>`}
        ${c && !c.error && html`
          <dt>Zertifikat</dt><dd>${c.self_signed ? "selbstsigniert" : c.issuer}${c.names ? html` <span class="cat">· gilt für ${c.names.join(", ")}</span>` : null}</dd>
          <dt>Gültig bis</dt><dd>${c.not_after ? fmtDateTime(c.not_after) : "–"}${daysLeft != null && daysLeft < 30 ? html` <span class="check bad">(${daysLeft < 0 ? T("abgelaufen") : T("noch {n} Tage", { n: daysLeft })})</span>` : null}</dd>
          <dt>SHA-256</dt><dd class="mono" style=${{ fontSize: 11 }}>${c.fingerprint}</dd>`}
        ${c && c.error && html`<dt>Zertifikat</dt><dd class="check bad">${c.error}</dd>`}
        <dt>Dateien</dt><dd class="mono" style=${{ fontSize: 12 }}>${st.cert_path}<br />${st.key_path}</dd>
      </dl>

      <div class="field"><label class="switch"><input type="checkbox" checked=${form.enabled}
        onChange=${(e) => setForm({ ...form, enabled: e.target.checked })} /><span class="slider"></span> HTTPS verwenden</label></div>
      ${form.enabled && html`
        <div class="inline-form">
          <div class="field"><label>HTTPS-Port</label>
            <input type="number" min="1" max="65535" value=${form.https_port} onInput=${(e) => setForm({ ...form, https_port: e.target.value })} /></div>
        </div>
        <div class="field"><label class="switch"><input type="checkbox" checked=${form.http_redirect}
          onChange=${(e) => setForm({ ...form, http_redirect: e.target.checked })} /><span class="slider"></span> http://…:${st.http_port} automatisch auf HTTPS umleiten</label></div>
        <div class="cat">Fehlt ein Zertifikat, erzeugt das Dashboard ein selbstsigniertes. Der Browser warnt dann beim ersten Aufruf („Verbindung nicht privat“) – einmal „Erweitert → Trotzdem fortfahren“ wählen. Vergleiche dazu den SHA-256-Fingerabdruck oben. Eigene Zertifikate (z. B. Let's Encrypt) trägst du in <span class="mono">config.json</span> unter <span class="mono">https_cert</span> und <span class="mono">https_key</span> ein.</div>`}
      ${msg && html`<div class=${msg.err ? "err" : "okmsg"} style=${{ marginTop: 10 }}>${msg.text}</div>`}
      <div class="actions">
        ${st.active && c && c.self_signed && html`<button class="btn" disabled=${busy}
          onClick=${() => confirm(T("Neues selbstsigniertes Zertifikat erzeugen (z. B. nach IP-Wechsel)? Der Browser warnt danach erneut.")) && save({ regenerate: true })}>Zertifikat neu erzeugen</button>`}
        <button class="btn primary" disabled=${busy || !changed} onClick=${() => save()}>Speichern und neu starten</button>
      </div>
    </div>`;
  }

  function LogSettings({ refresh }) {
    const [form, setForm] = useState(null);
    const [checks, setChecks] = useState({});
    const [found, setFound] = useState(null);
    const [searching, setSearching] = useState(false);
    const [msg, setMsg] = useState(null);
    const [saving, setSaving] = useState(false);

    useEffect(() => {
      api("/api/settings").then((s) => {
        setForm({ eve_json: s.eve_json, fast_log: s.fast_log, alert_source: s.alert_source });
        setChecks(s.check);
      }).catch((e) => setMsg({ err: true, text: e.message }));
    }, []);

    // Pfade beim Tippen pruefen (verzoegert)
    useEffect(() => {
      if (!form) return;
      const t = setTimeout(() => {
        ["eve_json", "fast_log"].forEach((k) =>
          api("/api/settings/check?path=" + encodeURIComponent(form[k]))
            .then((c) => setChecks((old) => ({ ...old, [k]: c }))).catch(() => {}));
      }, 400);
      return () => clearTimeout(t);
    }, [form && form.eve_json, form && form.fast_log]);

    if (!form) return html`<div class="card">${msg ? html`<div class="err">${msg.text}</div>` : html`<div class="empty">lädt …</div>`}</div>`;
    const set = (k) => (v) => { setForm({ ...form, [k]: v }); setMsg(null); };

    const search = async () => {
      setSearching(true);
      try { setFound(await api("/api/settings/find")); } catch (e) { setMsg({ err: true, text: e.message }); }
      setSearching(false);
    };
    const save = async () => {
      setSaving(true);
      try {
        const r = await api("/api/settings", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(form) });
        setChecks(r.check);
        setMsg({ err: false, text: r.saved_to_file
          ? "Gespeichert. Die neuen Dateien werden ab sofort eingelesen."
          : "Übernommen, aber die Einstellungsdatei konnte nicht geschrieben werden – nach einem Neustart gelten wieder die alten Pfade." });
        refresh();
      } catch (e) { setMsg({ err: true, text: e.message }); }
      setSaving(false);
    };
    const needFast = form.alert_source === "fastlog";
    return html`<div class="card settings">
      <h2>Logdateien</h2>
      <div class="sub">Wo das Dashboard die Suricata-Logs findet. Den Pfad siehst du in <span class="mono">/etc/suricata/suricata.yaml</span> unter <span class="mono">default-log-dir</span>.</div>

      <${PathField} label="eve.json" hint="Verbindungen, Protokolle, DNS, TLS, HTTP" value=${form.eve_json}
        onChange=${set("eve_json")} check=${checks.eve_json} candidates=${found && found.eve_json} />

      <div class="field">
        <label>Quelle für Alerts</label>
        <div class="seg">
          <button class=${needFast ? "active" : ""} onClick=${() => set("alert_source")("fastlog")}>fast.log</button>
          <button class=${!needFast ? "active" : ""} onClick=${() => set("alert_source")("eve")}>eve.json (event_type alert)</button>
        </div>
      </div>

      ${needFast && html`<${PathField} label="fast.log" hint="Alerts" value=${form.fast_log}
        onChange=${set("fast_log")} check=${checks.fast_log} candidates=${found && found.fast_log} />`}

      ${found && !found.eve_json.length && !found.fast_log.length && html`<div class="cat">Die Suche hat an den üblichen Orten nichts gefunden.</div>`}
      ${msg && html`<div class=${msg.err ? "err" : "okmsg"}>${msg.text}</div>`}
      <div class="actions">
        <button class="btn" disabled=${searching} onClick=${search}>${searching ? "suche …" : "Dateien automatisch suchen"}</button>
        <button class="btn primary" disabled=${saving} onClick=${save}>Speichern</button>
      </div>
      <div class="cat" style=${{ marginTop: 12 }}>Beim Wechsel auf eine andere Datei wird sie von Anfang an eingelesen. Bereits gespeicherte Daten und Harmlos-Markierungen bleiben erhalten.</div>
    </div>`;
  }


  // ------------------------------------------------------------------ Sichern & Wiederherstellen

  const SECTION_ORDER = ["settings", "device_names", "flags", "fp_notes", "anomaly_mutes", "feeds", "rules", "users"];

  function ImportPreview({ doc, source, labels, onCancel }) {
    const present = SECTION_ORDER.filter((k) => doc[k] != null);
    const [sel, setSel] = useState(() => present.filter((k) => k !== "users"));
    const [mode, setMode] = useState("merge");
    const [busy, setBusy] = useState(false);
    const [res, setRes] = useState(null);
    const [err, setErr] = useState(null);
    const count = (k) => Array.isArray(doc[k]) ? doc[k].length : Object.keys(doc[k] || {}).length;
    const toggle = (k) => setSel(sel.includes(k) ? sel.filter((x) => x !== k) : [...sel, k]);
    const run = async () => {
      if (mode === "replace" && !confirm(T("Vorhandene Einträge der gewählten Bereiche werden zuerst gelöscht. Fortfahren?"))) return;
      setBusy(true); setErr(null);
      try {
        const r = await postJson("/api/userdata/import", { data: doc, sections: sel, mode });
        setRes(r);
        if (r.restarting) {
          const url = r.scheme + "://" + location.hostname + ":" + r.port + "/";
          setTimeout(() => { window.location.href = url; }, 5000);
        }
      } catch (x) { setErr(x.message); }
      setBusy(false);
    };
    const s = doc.settings || {};
    return html`<div class="rep-card import-preview">
      <div class="rep-card-head">${source}</div>
      <div class="cat">Exportiert ${doc.exported ? fmtDateTime(doc.exported) : "?"}${doc.host ? " " + T("auf {x}", { x: doc.host }) : ""}${doc.app_version ? " · " + T("Version {x}", { x: doc.app_version }) : ""}</div>
      ${!res ? html`
        <div class="import-sections">${present.map((k) => html`<div key=${k}><label class="switch">
          <input type="checkbox" checked=${sel.includes(k)} onChange=${() => toggle(k)} /><span class="slider"></span>
          ${labels[k] || k} <span class="cat">${k === "settings" ? Object.keys(s).length + " Werte" : count(k)}</span></label>
          ${k === "settings" && sel.includes("settings") && html`<div class="cat mono import-settings">${Object.entries(s).map(([sk, v]) => html`<div key=${sk}>${sk}: ${String(v)}</div>`)}</div>`}</div>`)}</div>
        ${sel.includes("settings") && "https" in s && html`<div class="cat">Ändert sich die HTTPS-Einstellung, startet das Dashboard danach neu.</div>`}
        ${sel.includes("users") && html`<div class="warnmsg">Benutzer werden ergänzt bzw. mit Passwort und Rolle aus der Datei überschrieben (nie gelöscht). Betroffene Benutzer werden abgemeldet.</div>`}
        <div class="field"><label>Vorhandene Daten</label>
          <div class="seg">
            <button class=${mode === "merge" ? "active" : ""} onClick=${() => setMode("merge")}>zusammenführen</button>
            <button class=${mode === "replace" ? "active" : ""} onClick=${() => setMode("replace")}>ersetzen</button>
          </div>
          <div class="cat">${mode === "merge" ? "Einträge aus der Datei kommen hinzu bzw. überschreiben gleiche Einträge, alles andere bleibt." : "Die gewählten Bereiche werden vorher geleert und genau wie in der Datei wiederhergestellt."}</div>
        </div>
        ${err && html`<div class="err">${err}</div>`}
        <div class="actions">
          <button class="btn" onClick=${onCancel}>Abbrechen</button>
          <button class="btn primary" disabled=${busy || !sel.length} onClick=${run}>${busy ? "importiere …" : "Importieren"}</button>
        </div>`
      : html`<div class="okmsg">Importiert: ${Object.entries(res.summary).map(([k, n]) => (labels[k] || k) + " " + n).join(" · ") || "nichts"}.
          ${res.restarting ? " Das Dashboard startet neu und lädt gleich die Seite neu …" : ""}</div>
        ${res.notes.map((n, i) => html`<div key=${i} class="warnmsg">${n}</div>`)}
        <div class="actions"><button class="btn" onClick=${() => { onCancel(); window.location.reload(); }}>Fertig</button></div>`}
    </div>`;
  }

  function DataCard({ restoreReq }) {
    const [info, setInfo] = useState(null);
    const [withUsers, setWithUsers] = useState(false);
    const [preview, setPreview] = useState(null);
    const [msg, setMsg] = useState(null);
    const fileRef = useRef(null);
    const cardRef = useRef(null);
    const load = () => api("/api/userdata/backups").then(setInfo).catch((e) => setMsg({ err: true, text: e.message }));
    useEffect(() => { load(); }, []);

    const onFile = (e) => {
      const f = e.target.files && e.target.files[0];
      e.target.value = "";
      if (!f) return;
      const r = new FileReader();
      r.onload = () => {
        try {
          const doc = JSON.parse(r.result);
          if (!doc || doc.format !== "suricata-dashboard-userdata") throw new Error("Keine Export-Datei des Suricata Dashboards.");
          setMsg(null); setPreview({ doc, source: T("Datei: {x}", { x: f.name }) });
        } catch (x) { setMsg({ err: true, text: T("Datei nicht lesbar: {x}", { x: x.message }) }); }
      };
      r.readAsText(f);
    };
    const restore = async (b) => {
      try { setPreview({ doc: await api("/api/userdata/backup?name=" + encodeURIComponent(b.name)), source: "Automatische Sicherung vom " + fmtDateTime(b.time) }); }
      catch (x) { setMsg({ err: true, text: x.message }); }
    };
    const backupNow = async () => {
      try {
        const r = await postJson("/api/userdata/backup_now", {});
        setInfo(r);
        setMsg({ err: false, text: r.written ? T("Sicherung {x} angelegt.", { x: r.written }) : T("Keine Änderungen seit der letzten Sicherung.") });
      } catch (x) { setMsg({ err: true, text: x.message }); }
    };
    useEffect(() => {  // vom Hinweis-Banner aus "Wiederherstellen" geklickt
      if (!info || !restoreReq) return;
      const b = info.backups.find((x) => x.name === restoreReq);
      if (b) {
        restore(b);
        setTimeout(() => cardRef.current && cardRef.current.scrollIntoView({ behavior: "smooth", block: "start" }), 150);
      }
    }, [info, restoreReq]);
    const labels = (info && info.labels) || {};
    const summary = (c) => SECTION_ORDER.filter((k) => c[k]).map((k) => ({ settings: "Einstellungen", device_names: "Geräte", flags: "Signaturen", fp_notes: "Fingerprints", anomaly_mutes: "Stummschaltungen", feeds: "Feeds", users: "Benutzer" }[k] + " " + (k === "settings" ? "✓" : c[k]))).join(" · ");

    return html`<div class="card settings" ref=${cardRef}>
      <h2>Sichern & Wiederherstellen</h2>
      <div class="sub">Alles, was du selbst eingegeben hast: Pfade und HTTPS-Einstellung, Gerätenamen, harmlos markierte Signaturen, Fingerprint-Notizen, Feed-Auswahl, die im Dashboard angelegten Blockier-Regeln und optional die Benutzer. Alles andere lernt das Dashboard aus eve.json neu.</div>

      <div class="field"><label>Exportieren</label>
        <label class="switch"><input type="checkbox" checked=${withUsers} onChange=${(e) => setWithUsers(e.target.checked)} /><span class="slider"></span>
          Benutzer mit Passwort-Hash mitsichern</label>
        ${withUsers && html`<div class="cat">Die Datei enthält dann die Passwort-Hashes – sicher aufbewahren.</div>`}
        <div><a class="btn primary" href=${"/api/userdata/export?users=" + (withUsers ? 1 : 0)} download>Als Datei herunterladen</a></div>
      </div>

      <div class="field"><label>Importieren</label>
        <input type="file" accept=".json,application/json" ref=${fileRef} onChange=${onFile} hidden />
        <div><button class="btn" onClick=${() => fileRef.current && fileRef.current.click()}>Datei auswählen …</button></div>
        <div class="cat">Vor dem Übernehmen siehst du, was in der Datei steht, und wählst die Bereiche aus.</div>
      </div>
      ${preview && html`<${ImportPreview} key=${preview.source} doc=${preview.doc} source=${preview.source} labels=${labels} onCancel=${() => { setPreview(null); load(); }} />`}
      ${msg && html`<div class=${msg.err ? "err" : "okmsg"}>${msg.text}</div>`}

      <div class="field"><label>Automatische Sicherungen</label>
        <div class="cat">Nach jeder Änderung legt das Dashboard eine Sicherung in <span class="mono">${info ? info.dir : "data/backups"}</span> an (die neuesten ${info ? info.keep : 20} bleiben). Sie überstehen auch eine kaputte oder unvollständig kopierte Datenbank.</div>
        ${!info ? html`<div class="empty">lädt …</div>` : !info.backups.length ? html`<div class="cat">Noch keine Sicherung – es wurde noch nichts Eigenes gespeichert.</div>` : html`
          <div class="table-wrap"><table class="backup-table"><tbody>${info.backups.slice(0, 8).map((b) => html`<tr key=${b.name}>
            <td class="nowrap">${b.time ? fmtDateTime(b.time) : b.name}</td>
            <td>${b.error ? html`<span class="check bad">${b.error}</span>` : html`<span class="cat">${summary(b.counts)}</span>`}</td>
            <td><div class="row-actions">
              <a class="btn" href=${"/api/userdata/backup?name=" + encodeURIComponent(b.name)} download=${b.name}>Herunterladen</a>
              <button class="btn" disabled=${!!b.error} onClick=${() => restore(b)}>Wiederherstellen …</button></div></td>
          </tr>`)}</tbody></table></div>
          ${info.backups.length > 8 ? html`<div class="cat">+ ${info.backups.length - 8} ältere</div>` : null}`}
        <div><button class="btn" onClick=${backupNow}>Jetzt sichern</button></div>
      </div>
      <div class="cat">Im Browser geänderte Einstellungen liegen in <span class="mono">${info ? info.settings_path : "data/settings.json"}</span> – also im data-Ordner, nicht mehr in config.json. Beim Aktualisieren den data-Ordner behalten (oder vorher exportieren).</div>
    </div>`;
  }

  function SettingsPage({ refresh, me, restoreReq }) {
    return html`<div>
      <${LogSettings} refresh=${refresh} />
      <${RulesSettings} />
      ${me.auth_enabled && html`<${UsersCard} me=${me} />`}
      <${HttpsCard} />
      <${DataCard} restoreReq=${restoreReq} />
    </div>`;
  }

  // ------------------------------------------------------------------ Live-Ansicht

  const LIVE_HOLDS = [[10, "10 s"], [15, "15 s"], [30, "30 s"], [60, "1 Min"], [120, "2 Min"], [300, "5 Min"]];
  const FADE_MS = 700;
  const trunc = (s, n) => (s && s.length > n ? s.slice(0, n - 1) + "…" : s || "");

  // Text an der Kante: letzte DNS-Anfrage bzw. TLS-SNI / HTTP-Host dieser Verbindung
  function edgeLabel(e) {
    const more = (l) => (l.length > 1 ? " +" + (l.length - 1) : "");
    if (e.queries && e.queries.length) return { text: "DNS " + trunc(e.queries[0], 32) + more(e.queries), name: null };
    if (e.names && e.names.length) {
      const proto = ((e.services && e.services[0]) || "").split(" ")[0];
      return { text: (proto ? proto + " " : "") + trunc(e.names[0], 32) + more(e.names), name: e.names[0] };
    }
    return null;
  }

  function nodeTitle(n) {
    if (!n) return "";
    if (n.kind === "device") return n.name || n.id;
    if (n.kind === "group") return n.name;
    return (n.names && n.names[0]) || (n.rep && n.rep.name) || n.id;
  }

  // Kraftbasierter Graph auf einem Canvas (ohne Bibliothek). Haelt eigene Knoten-
  // objekte, damit Positionen zwischen den sekuendlichen Updates erhalten bleiben.
  class LiveGraph {
    constructor(canvas, cb) {
      this.cv = canvas; this.ctx = canvas.getContext("2d"); this.cb = cb;
      this.nodes = new Map(); this.edges = new Map();
      this.view = { x: 0, y: 0, k: 1 };
      this.autoFit = true;   // Ausschnitt folgt dem Graphen, bis der Nutzer selbst zoomt/verschiebt
      this.heat = 1; this.hover = null; this.selected = null; this.drag = null;
      this.snapNow = 0; this.snapAt = 0;
      this.setColors();
      this.resize();
      this.ro = new ResizeObserver(() => this.resize());
      this.ro.observe(canvas);
      this.bind();
      this.frame = this.frame.bind(this);
      this.raf = requestAnimationFrame(this.frame);
    }
    destroy() { cancelAnimationFrame(this.raf); this.ro.disconnect(); this.unbind(); }
    setColors() {
      const v = (n) => cssVar(n);
      this.col = {
        text: v("--text"), text2: v("--text-2"), muted: v("--muted"), surface: v("--surface"),
        page: v("--surface"), edge: v("--axis"), device: v("--accent"), group: v("--series-7"),
        malicious: v("--critical"), suspicious: v("--serious"), known: v("--good"),
        popular: v("--series-1"), unknown: v("--series-other"), local: v("--accent"),
        alert: v("--critical"), warn: v("--warning"),
      };
    }
    resize() {
      const r = this.cv.getBoundingClientRect(), dpr = window.devicePixelRatio || 1;
      this.w = r.width; this.h = r.height; this.dpr = dpr;
      this.cv.width = Math.round(r.width * dpr); this.cv.height = Math.round(r.height * dpr);
    }
    resetView() { this.autoFit = true; this.heat = Math.max(this.heat, 0.3); }
    fit() {
      let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
      for (const n of this.nodes.values()) {
        if (n.gone) continue;
        x0 = Math.min(x0, n.x - 70); x1 = Math.max(x1, n.x + 70);
        y0 = Math.min(y0, n.y - 20); y1 = Math.max(y1, n.y + 50);
      }
      if (x0 === Infinity) return;
      const v = this.view;
      const k = Math.max(0.3, Math.min(1.4, (this.w - 40) / (x1 - x0), (this.h - 60) / (y1 - y0)));
      const tx = -((x0 + x1) / 2) * k, ty = -((y0 + y1) / 2) * k - 10;
      v.k += (k - v.k) * 0.06; v.x += (tx - v.x) * 0.06; v.y += (ty - v.y) * 0.06;
    }
    zoom(f, cx, cy) {
      this.autoFit = false;
      const v = this.view, k = Math.max(0.25, Math.min(4, v.k * f));
      cx = cx == null ? this.w / 2 : cx; cy = cy == null ? this.h / 2 : cy;
      // Punkt unter dem Cursor bleibt stehen
      const wx = (cx - this.w / 2 - v.x) / v.k, wy = (cy - this.h / 2 - v.y) / v.k;
      v.k = k; v.x = cx - this.w / 2 - wx * k; v.y = cy - this.h / 2 - wy * k;
    }

    update(snap) {
      const now = performance.now();
      this.snapNow = snap.now; this.snapAt = now;
      const seenN = new Set(), seenE = new Set();
      const deg = {};
      for (const e of snap.edges) { deg[e.device] = (deg[e.device] || 0) + 1; deg[e.peer] = (deg[e.peer] || 0) + 1; }
      for (const d of snap.nodes) {
        seenN.add(d.id);
        let n = this.nodes.get(d.id);
        if (!n) {
          // neue Gegenstelle neben ihrem Geraet starten, Geraete zufaellig nahe der Mitte
          const e = snap.edges.find((e) => e.peer === d.id || e.device === d.id);
          const anchor = e && this.nodes.get(e.device === d.id ? e.peer : e.device);
          const a = Math.random() * Math.PI * 2, r = anchor ? 40 : 60 + Math.random() * 80;
          n = { id: d.id, x: (anchor ? anchor.x : 0) + Math.cos(a) * r, y: (anchor ? anchor.y : 0) + Math.sin(a) * r,
            vx: 0, vy: 0, alpha: 0, born: now };
          this.nodes.set(d.id, n);
          this.heat = Math.max(this.heat, 0.5);
        }
        n.d = d; n.gone = 0; n.deg = deg[d.id] || 0;
      }
      for (const e of snap.edges) {
        seenE.add(e.id);
        let g = this.edges.get(e.id);
        if (!g) { g = { id: e.id, alpha: 0, flash: now }; this.edges.set(e.id, g); }
        else if (g.d && e.last > g.d.last) g.flash = now;   // neue Aktivitaet -> kurz aufleuchten
        g.d = e; g.gone = 0;
        g.s = e.device; g.t = e.peer;
        const lbl = edgeLabel(e);
        if ((lbl && lbl.text) !== (g.label && g.label.text)) { g.label = lbl; g.labelAt = now; }
        g.alert = e.alerts.length > 0;
      }
      for (const n of this.nodes.values()) {
        if (!seenN.has(n.id) && !n.gone) n.gone = now;
        n.alert = false;
      }
      for (const g of this.edges.values()) if (!seenE.has(g.id) && !g.gone) g.gone = now;
      for (const n of this.nodes.values()) { n.alertSig = null; n.svc = null; }
      for (const g of this.edges.values()) {
        if (g.gone) continue;
        const a = this.nodes.get(g.s), b = this.nodes.get(g.t);
        if (b && !b.svc) b.svc = g.d.services[0];
        if (!g.alert) continue;
        if (a) a.alert = true;
        if (b) { b.alert = true; if (!b.alertSig) b.alertSig = g.d.alerts[0].signature; }
      }
    }

    // --- Simulation -----------------------------------------------------------
    step() {
      const nodes = [...this.nodes.values()];
      if (this.heat < 0.004 && !this.drag) return;
      const k = this.heat;
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j];
          let dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy;
          if (d2 > 490000) continue;           // weiter als 700 px: egal
          if (d2 < 1) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 1; }
          const big = (a.d && a.d.kind === "device" ? 3 : 1) * (b.d && b.d.kind === "device" ? 3 : 1);
          const f = (2600 * big) / d2;
          const d = Math.sqrt(d2), fx = (dx / d) * f, fy = (dy / d) * f;
          a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
        }
      }
      for (const g of this.edges.values()) {
        const a = this.nodes.get(g.s), b = this.nodes.get(g.t);
        if (!a || !b) continue;
        const lan = g.d && g.d.dir === "lan";
        const len = lan ? 200 : 90 + Math.min(80, (a.deg || 1) * 3);
        const dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) || 1;
        const f = (d - len) * 0.04, fx = (dx / d) * f, fy = (dy / d) * f;
        // Geraete sind "schwer": die Gegenstellen bewegen sich mehr
        const wa = a.d && a.d.kind === "device" && !lan ? 0.25 : 0.5;
        a.vx += fx * wa; a.vy += fy * wa; b.vx -= fx * (1 - wa); b.vy -= fy * (1 - wa);
      }
      for (const n of nodes) {
        const dev = n.d && n.d.kind === "device";
        n.vx -= n.x * (dev ? 0.006 : 0.002); n.vy -= n.y * (dev ? 0.006 : 0.002);
        if (this.drag && this.drag.node === n) { n.vx = n.vy = 0; continue; }
        const lim = 30;
        n.x += Math.max(-lim, Math.min(lim, n.vx * k)); n.y += Math.max(-lim, Math.min(lim, n.vy * k));
        n.vx *= 0.55; n.vy *= 0.55;
      }
      this.heat = Math.max(0, this.heat * 0.985 - 0.0005);
    }

    // --- Zeichnen -------------------------------------------------------------
    nodeRadius(n) {
      if (!n.d) return 5;
      if (n.d.kind === "device") return 10 + Math.min(6, Math.sqrt(n.deg || 0));
      return 6;
    }
    nodeColor(n) {
      const d = n.d || {}, c = this.col;
      if (d.kind === "device") return c.device;
      if (d.kind === "group") return c.group;
      return c[(d.rep && d.rep.verdict) || "unknown"] || c.unknown;
    }
    frame(t) {
      this.raf = requestAnimationFrame(this.frame);
      if (document.hidden) return;
      this.step();
      const now = performance.now();
      // ein- und ausblenden
      for (const [id, n] of this.nodes) {
        n.alpha = n.gone ? Math.max(0, 1 - (now - n.gone) / FADE_MS) : Math.min(1, (now - n.born) / FADE_MS);
        if (n.gone && n.alpha <= 0) { this.nodes.delete(id); if (this.selected === id) this.cb.onSelect(null); }
      }
      for (const [id, g] of this.edges) {
        g.alpha = g.gone ? Math.max(0, 1 - (now - g.gone) / FADE_MS) : Math.min(1, g.alpha + 0.06);
        if (g.gone && g.alpha <= 0) this.edges.delete(id);
      }
      if (this.autoFit) this.fit();
      this.draw(now);
    }
    draw(now) {
      const ctx = this.ctx, c = this.col, v = this.view, dpr = this.dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, this.w, this.h);
      ctx.translate(this.w / 2 + v.x, this.h / 2 + v.y);
      ctx.scale(v.k, v.k);
      const focus = this.hover || this.selected;
      const near = new Set();
      if (focus) for (const g of this.edges.values()) if (g.s === focus || g.t === focus) { near.add(g.s); near.add(g.t); }
      const pulse = 0.5 + 0.5 * Math.sin(now / 250);

      // Kanten
      for (const g of this.edges.values()) {
        const a = this.nodes.get(g.s), b = this.nodes.get(g.t);
        if (!a || !b) continue;
        const dim = focus && !(g.s === focus || g.t === focus) ? 0.25 : 1;
        const flash = Math.max(0, 1 - (now - g.flash) / 1500);
        const bytes = (g.d && g.d.bytes) || 0;
        ctx.globalAlpha = g.alpha * dim * (g.d && !g.d.open ? 0.55 : 0.9);
        ctx.strokeStyle = g.alert ? c.alert : flash > 0 ? c.device : c.edge;
        ctx.lineWidth = (1 + Math.min(4, Math.log10(1 + bytes) / 2) + flash * 1.5) / Math.sqrt(v.k);
        ctx.setLineDash(g.d && g.d.dir === "in" ? [5, 4] : []);
        ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
        if (flash > 0 && g.d && g.d.open) {   // laufender Punkt = gerade aktiv
          const p = ((now - g.flash) / 1500);
          const fromPeer = g.d.dir === "in";
          const x = fromPeer ? b.x + (a.x - b.x) * p : a.x + (b.x - a.x) * p;
          const y = fromPeer ? b.y + (a.y - b.y) * p : a.y + (b.y - a.y) * p;
          ctx.fillStyle = g.alert ? c.alert : c.device;
          ctx.beginPath(); ctx.arc(x, y, 2.5, 0, Math.PI * 2); ctx.fill();
        }
      }
      ctx.setLineDash([]);

      // Knoten
      const many = this.nodes.size > 120 && v.k < 1.2;
      const labels = [];
      for (const n of this.nodes.values()) {
        const d = n.d || {}, r = this.nodeRadius(n);
        const dim = focus && !near.has(n.id) && n.id !== focus ? 0.3 : 1;
        ctx.globalAlpha = n.alpha * dim;
        if (n.alert) {
          ctx.strokeStyle = c.alert; ctx.lineWidth = 2;
          ctx.globalAlpha = n.alpha * dim * (0.35 + 0.5 * pulse);
          ctx.beginPath(); ctx.arc(n.x, n.y, r + 4 + pulse * 3, 0, Math.PI * 2); ctx.stroke();
          ctx.globalAlpha = n.alpha * dim;
        }
        ctx.fillStyle = this.nodeColor(n);
        ctx.beginPath();
        if (d.kind === "group") {   // Raute fuer Multicast/Broadcast
          ctx.moveTo(n.x, n.y - r - 1); ctx.lineTo(n.x + r + 1, n.y); ctx.lineTo(n.x, n.y + r + 1); ctx.lineTo(n.x - r - 1, n.y); ctx.closePath();
        } else ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.fill();
        ctx.lineWidth = n.id === this.selected ? 3 : 1.5;
        ctx.strokeStyle = n.id === this.selected ? c.text : c.surface;
        ctx.stroke();
        if (d.kind === "device") {
          ctx.fillStyle = "#fff"; ctx.font = "600 10px system-ui, sans-serif";
          ctx.textAlign = "center"; ctx.textBaseline = "middle";
          ctx.fillText(String(n.deg || ""), n.x, n.y + 0.5);
        }
        const show = !many || d.kind === "device" || n.alert || n.id === focus || near.has(n.id) ||
          (d.rep && (d.rep.verdict === "malicious" || d.rep.verdict === "suspicious"));
        if (show && n.alpha > 0.05) {
          const prio = n.id === focus ? 0 : n.alert ? 1 : d.kind === "device" ? 2 : near.has(n.id) ? 3 : 4;
          labels.push([n, r, dim, prio]);
        }
      }
      labels.sort((a, b) => a[3] - b[3]);
      const placed = [], drawnTitle = new Map();
      // Beschriftungen zuletzt, damit sie ueber den Kanten liegen
      ctx.textAlign = "center"; ctx.textBaseline = "top";
      for (const [n, r, dim, prio] of labels) {
        const d = n.d || {}, lines = [];
        const dev = d.kind === "device";
        lines.push([trunc(nodeTitle(d), 30), dev ? "600 12px" : "500 11px", c.text]);
        if (n.alertSig) lines.push(["⚠ " + trunc(n.alertSig, 38), "600 11px", c.alert]);
        let sub = "";
        if (dev) sub = d.name ? d.id : (d.hidden ? T("+{n} weitere", { n: d.hidden }) : "");
        else {
          const svc = n.svc;
          const rep = d.rep && d.rep.verdict !== "unknown" && d.rep.verdict !== "local" ? repText(d.rep) : (d.rep && d.rep.asn) || "";
          sub = [svc, rep && rep !== nodeTitle(d) ? trunc(rep, 26) : ""].filter(Boolean).join(" · ");
        }
        if (sub) lines.push([sub, "400 10px", c.muted]);
        // ueberdeckt die Beschriftung eine schon gezeichnete? Dann nur den Titel bzw. gar nichts
        let bw = 0;
        for (const [txt, font] of lines) { ctx.font = font + " system-ui, sans-serif"; bw = Math.max(bw, ctx.measureText(txt).width); }
        const box = (cnt) => ({ x0: n.x - bw / 2 - 2, x1: n.x + bw / 2 + 2, y0: n.y + r + 3, y1: n.y + r + 4 + cnt * 13 });
        const hit = (b) => placed.some((p) => b.x0 < p.x1 && b.x1 > p.x0 && b.y0 < p.y1 && b.y1 > p.y0);
        let bx = box(lines.length);
        if (prio > 0 && hit(bx)) {
          lines.length = n.alertSig ? 2 : 1; bx = box(lines.length);
          if (prio > 2 && hit(bx)) continue;
        }
        placed.push(bx);
        drawnTitle.set(n.id, nodeTitle(d));
        let y = n.y + r + 4;
        for (const [txt, font, color] of lines) {
          ctx.font = font + " system-ui, sans-serif";
          const w = ctx.measureText(txt).width;
          ctx.globalAlpha = n.alpha * dim * 0.8;
          ctx.fillStyle = c.surface;
          ctx.fillRect(n.x - w / 2 - 2, y - 1, w + 4, 13);
          ctx.globalAlpha = n.alpha * dim;
          ctx.fillStyle = color;
          ctx.fillText(txt, n.x, y);
          y += 13;
        }
      }
      this.drawEdgeLabels(now, focus, many, placed, drawnTitle);
      ctx.globalAlpha = 1;
    }

    // Kantentexte nach den Knoten: niedrigere Prioritaet, weichen Beschriftungen aus
    drawEdgeLabels(now, focus, many, placed, drawnTitle) {
      const ctx = this.ctx, c = this.col;
      ctx.font = "400 10px system-ui, sans-serif";
      ctx.textAlign = "center"; ctx.textBaseline = "middle";
      const list = [];
      for (const g of this.edges.values()) {
        if (!g.label || g.alpha < 0.05) continue;
        const a = this.nodes.get(g.s), b = this.nodes.get(g.t);
        if (!a || !b) continue;
        const isFocus = focus && (g.s === focus || g.t === focus);
        if (many && !isFocus) continue;
        // steht genau dieser Name schon am Zielpunkt, nicht doppelt schreiben
        if (g.label.name && drawnTitle.get(g.t) === g.label.name && !isFocus) continue;
        list.push([g, a, b, isFocus]);
      }
      // Knotenkreise sind tabu. Fokussierte Kanten (Hover/Auswahl) duerfen ueber die
      // abgedunkelten Beschriftungen, alle anderen weichen ihnen aus.
      const circles = [];
      for (const n of this.nodes.values()) {
        if (n.gone) continue;
        const r = this.nodeRadius(n) + 3;
        circles.push({ x0: n.x - r, x1: n.x + r, y0: n.y - r, y1: n.y + r });
      }
      const all = placed.concat(circles), forFocus = circles.slice();
      const hit = (arr, b) => arr.some((p) => b.x0 < p.x1 && b.x1 > p.x0 && b.y0 < p.y1 && b.y1 > p.y0);
      // fokussierte und frisch geaenderte zuerst
      list.sort((x, y) => (y[3] - x[3]) || (y[0].labelAt - x[0].labelAt));
      for (const [g, a, b, isFocus] of list) {
        const w = ctx.measureText(g.label.text).width;
        let x, y, bx = null;
        for (const t of [0.5, 0.33, 0.67]) {   // Mitte, sonst ein Drittel weiter
          x = a.x + (b.x - a.x) * t; y = a.y + (b.y - a.y) * t;
          const cand = { x0: x - w / 2 - 3, x1: x + w / 2 + 3, y0: y - 7, y1: y + 7 };
          if (!hit(isFocus ? forFocus : all, cand)) { bx = cand; break; }
        }
        if (!bx) continue;
        all.push(bx); forFocus.push(bx);
        const dim = focus && !isFocus ? 0.3 : 1;
        const fresh = Math.max(0, 1 - (now - g.labelAt) / 2500);   // neue Anfrage: kurz hervorheben
        ctx.globalAlpha = g.alpha * dim * 0.85;
        ctx.fillStyle = c.surface;
        ctx.fillRect(bx.x0, bx.y0, bx.x1 - bx.x0, bx.y1 - bx.y0);
        ctx.globalAlpha = g.alpha * dim;
        ctx.fillStyle = g.alert ? c.alert : fresh > 0 ? c.device : c.text2;
        ctx.fillText(g.label.text, x, y + 0.5);
      }
    }

    // --- Maus / Touch ---------------------------------------------------------
    toWorld(ev) {
      const r = this.cv.getBoundingClientRect(), v = this.view;
      const sx = ev.clientX - r.left, sy = ev.clientY - r.top;
      return { sx, sy, x: (sx - this.w / 2 - v.x) / v.k, y: (sy - this.h / 2 - v.y) / v.k };
    }
    pick(p) {
      let best = null, bd = Infinity;
      for (const n of this.nodes.values()) {
        if (n.gone) continue;
        const r = this.nodeRadius(n) + 4 / this.view.k, dx = n.x - p.x, dy = n.y - p.y, d = dx * dx + dy * dy;
        if (d < r * r && d < bd) { best = n; bd = d; }
      }
      return best;
    }
    bind() {
      const cv = this.cv;
      this.h_down = (ev) => {
        const p = this.toWorld(ev), n = this.pick(p);
        try { cv.setPointerCapture(ev.pointerId); } catch (e) { /* z. B. synthetische Events */ }
        this.drag = { node: n, sx: p.sx, sy: p.sy, vx: this.view.x, vy: this.view.y, moved: false };
      };
      this.h_move = (ev) => {
        const p = this.toWorld(ev);
        if (this.drag) {
          const dr = this.drag;
          if (Math.abs(p.sx - dr.sx) + Math.abs(p.sy - dr.sy) > 4) dr.moved = true;
          if (dr.node) { dr.node.x = p.x; dr.node.y = p.y; this.heat = Math.max(this.heat, 0.3); }
          else if (dr.moved) { this.autoFit = false; this.view.x = dr.vx + p.sx - dr.sx; this.view.y = dr.vy + p.sy - dr.sy; }
          return;
        }
        const n = this.pick(p), id = n ? n.id : null;
        cv.style.cursor = n ? "pointer" : "grab";
        if (id !== this.hover) { this.hover = id; }
      };
      this.h_up = () => {
        const dr = this.drag; this.drag = null;
        if (dr && !dr.moved) {
          this.selected = dr.node ? dr.node.id : null;
          this.cb.onSelect(this.selected);
        }
      };
      this.h_leave = () => { this.hover = null; };
      this.h_wheel = (ev) => {
        ev.preventDefault();
        const p = this.toWorld(ev);
        this.zoom(ev.deltaY < 0 ? 1.15 : 1 / 1.15, p.sx, p.sy);
      };
      cv.addEventListener("pointerdown", this.h_down);
      cv.addEventListener("pointermove", this.h_move);
      cv.addEventListener("pointerup", this.h_up);
      cv.addEventListener("pointercancel", this.h_up);
      cv.addEventListener("pointerleave", this.h_leave);
      cv.addEventListener("wheel", this.h_wheel, { passive: false });
    }
    unbind() {
      const cv = this.cv;
      cv.removeEventListener("pointerdown", this.h_down);
      cv.removeEventListener("pointermove", this.h_move);
      cv.removeEventListener("pointerup", this.h_up);
      cv.removeEventListener("pointercancel", this.h_up);
      cv.removeEventListener("pointerleave", this.h_leave);
      cv.removeEventListener("wheel", this.h_wheel);
    }
  }

  function LiveDetail({ id, snap, onClose, goAlerts }) {
    const { reload } = React.useContext(DevCtx);
    const node = snap && snap.nodes.find((n) => n.id === id);
    if (!node) return html`<div class="live-side card"><div class="empty">Die Verbindung ist nicht mehr aktiv.</div>
      <button class="btn" onClick=${onClose}>schließen</button></div>`;
    const edges = snap.edges.filter((e) => e.device === id || e.peer === id);
    const dev = node.kind === "device";
    const totalBytes = edges.reduce((s, e) => s + e.bytes, 0);
    const alerts = edges.flatMap((e) => e.alerts.map((a) => ({ ...a, e })));
    const kindLabel = dev ? "Lokales Gerät" : node.kind === "group" ? "Multicast / Broadcast" : "Gegenstelle";
    return html`<div class="live-side card">
      <div class="card-head"><div>
        <div class="cat">${kindLabel}</div>
        <h2 class="live-title">${nodeTitle(node)}</h2>
        <div class="mono cat">${[nodeTitle(node) !== node.id ? node.id : null, node.mac].filter(Boolean).join(" · ")}</div>
      </div><button class="icon-btn" title="schließen" onClick=${onClose}>✕</button></div>
      ${dev && (() => {
        const byMac = node.mac && !node.shared;
        const own = node.name_source === "mac" || node.name_source === "ip";
        return html`<div class="live-name">
          <${NameEditor} kind=${byMac ? "mac" : "ip"} k=${byMac ? node.mac : node.id} value=${own ? node.name : ""}
            placeholder=${node.name ? node.name + " (DHCP)" : T("Name vergeben …")} onSaved=${reload}
            extra=${byMac ? { replace_ip_names: true } : null} />
          <div class="cat">${byMac ? "Der Name gilt für diese MAC-Adresse, auch wenn sich die IP ändert." : node.shared ? "Geteilte MAC (Router?) – der Name gilt für diese IP." : "Keine MAC bekannt – der Name gilt für diese IP."}</div>
        </div>`;
      })()}
      ${node.rep && node.kind === "remote" && html`<div class="live-rep"><${RepBadge} r=${node.rep} />
        ${node.rep.asn && html`<div class="cat">${node.rep.asn}</div>`}</div>`}
      ${node.names && node.names.length > 1 && html`<div class="cat">Weitere Namen: ${node.names.slice(1).join(", ")}</div>`}
      ${alerts.length > 0 && html`<div class="live-alerts">${alerts.map((a, i) => html`
        <div key=${i} class="live-alert"><b>⚠ ${a.signature}</b>
          <div class="cat">SID ${a.sid} · Schwere ${a.severity} · ${a.count}× · ${a.action}${dev ? " · " + nodeTitle(snap.nodes.find((n) => n.id === a.e.peer)) : ""}</div></div>`)}</div>`}
      <div class="cat live-sum">${edges.length} ${edges.length === 1 ? "Verbindung" : "Verbindungen"}${totalBytes ? " · " + T("{b} (beendete Flows)", { b: fmtBytes(totalBytes) }) : ""}${node.hidden ? " · " + T("+{n} weitere nicht angezeigt", { n: node.hidden }) : ""}</div>
      <div class="live-conns">${edges.map((e) => {
        const other = snap.nodes.find((n) => n.id === (e.device === id ? e.peer : e.device));
        const arrow = e.dir === "in" ? (e.device === id ? "←" : "→") : (e.device === id ? "→" : "←");
        return html`<div key=${e.id} class="live-conn">
          <div><span class="live-arrow">${arrow}</span> <b>${trunc(nodeTitle(other), 40)}</b>
            ${other && other.kind === "remote" && other.rep && !["unknown", "popular"].includes(other.rep.verdict) && html` <${RepBadge} r=${other.rep} />`}</div>
          <div class="cat">${e.services.join(", ")}${e.dir === "in" ? " · eingehend" : ""}${e.open ? " · aktiv" : " · beendet"} · seit ${fmtTime(e.first)}${e.flows ? " · " + T("{n} Flows, {b}", { n: e.flows, b: fmtBytes(e.bytes) }) : ""}</div>
          ${e.names.length > 0 && html`<div class="cat">Host: ${e.names.join(", ")}</div>`}
          ${e.queries.length > 0 && html`<div class="cat">DNS: ${e.queries.join(", ")}</div>`}
        </div>`;
      })}</div>
      <div class="actions"><button class="btn" onClick=${() => goAlerts({ ip: id })}>Alerts zu ${dev ? "diesem Gerät" : "dieser IP"} →</button></div>
    </div>`;
  }

  function LivePage({ theme, goAlerts }) {
    const read = (k, d) => { try { return localStorage.getItem(k) || d; } catch (e) { return d; } };
    const [on, setOn] = useState(false);
    const [paused, setPaused] = useState(false);
    const [hold, setHold] = useState(Number(read("live_hold", "30")));
    const [opts, setOpts] = useState(() => { try { return JSON.parse(read("live_opts", "")) || {}; } catch (e) { return {}; } });
    const [snap, setSnap] = useState(null);
    const [error, setError] = useState(null);
    const [sel, setSel] = useState(null);
    const canvas = useRef(null);
    const graph = useRef(null);
    const o = { alerts: false, lan: true, groups: true, ...opts };
    useEffect(() => { try { localStorage.setItem("live_hold", hold); localStorage.setItem("live_opts", JSON.stringify(opts)); } catch (e) {} }, [hold, opts]);

    useEffect(() => {
      if (!on) return;
      const g = new LiveGraph(canvas.current, { onSelect: setSel });
      graph.current = g;
      return () => { g.destroy(); graph.current = null; setSnap(null); setSel(null); };
    }, [on]);
    useEffect(() => { if (graph.current) { graph.current.setColors(); } }, [theme]);
    useEffect(() => { if (graph.current) graph.current.selected = sel; }, [sel]);

    useEffect(() => {
      if (!on || paused) return;
      let alive = true, timer = null;
      const q = `/api/live?hold=${hold}&alerts=${o.alerts ? 1 : 0}&lan=${o.lan ? 1 : 0}&groups=${o.groups ? 1 : 0}`;
      const poll = async () => {
        if (!document.hidden) {
          try {
            const s = await api(q);
            if (!alive) return;
            setSnap(s); setError(null);
            if (graph.current) graph.current.update(s);
          } catch (e) { if (alive) setError(e.message); }
        }
        if (alive) timer = setTimeout(poll, 1000);
      };
      poll();
      return () => { alive = false; clearTimeout(timer); };
    }, [on, paused, hold, o.alerts, o.lan, o.groups]);

    const setOpt = (k) => (e) => setOpts({ ...opts, [k]: e.target.checked });
    const devices = snap ? snap.nodes.filter((n) => n.kind === "device").length : 0;
    const alertCount = snap ? snap.edges.filter((e) => e.alerts.length).length : 0;
    const g = graph.current;

    return html`<div>
      <div class="card live-bar">
        <label class="switch" title="Live-Ansicht ein/aus">
          <input type="checkbox" checked=${on} onChange=${(e) => { setOn(e.target.checked); setPaused(false); }} />
          <span class="slider"></span><b>Live</b>
        </label>
        ${on && html`<button class="btn" onClick=${() => setPaused(!paused)}>${paused ? "▶ weiter" : "❚❚ anhalten"}</button>`}
        <div class="filters live-filters">
          <label>Haltezeit <select value=${hold} onChange=${(e) => setHold(Number(e.target.value))}>
            ${LIVE_HOLDS.map(([v, l]) => html`<option key=${v} value=${v}>${l}</option>`)}</select></label>
          <label><input type="checkbox" checked=${o.alerts} onChange=${setOpt("alerts")} /> nur Alerts</label>
          <label><input type="checkbox" checked=${o.lan} onChange=${setOpt("lan")} /> LAN-intern</label>
          <label><input type="checkbox" checked=${o.groups} onChange=${setOpt("groups")} /> Multicast/Broadcast</label>
        </div>
        <div class="spacer"></div>
        ${on && snap && html`<div class="live-stats">
          <span><b>${devices}</b> Geräte</span><span><b>${snap.edges.length}</b> Verbindungen</span>
          ${alertCount > 0 && html`<span class="live-stat-alert"><b>⚠ ${alertCount}</b> mit Alert</span>`}
          <span><b>${fmtNum(snap.eps)}</b> Events/s</span>
          <span class="cat">${paused ? "angehalten" : fmtDateTime(snap.now)}</span></div>`}
      </div>

      ${!on && html`<div class="card live-off">
        <h2>Live-Ansicht</h2>
        <p>Zeigt die Geräte im Netz und ihre aktuellen Verbindungen als Graph. Die Daten werden jede Sekunde aktualisiert.</p>
        <p class="cat">Solange die Ansicht läuft, liest der Pi die eve.json jede Sekunde statt im normalen Takt, und der Browser zeichnet den Graphen fortlaufend.
        Sie schaltet sich automatisch ab, wenn du den Tab wechselst oder die Seite schließt.</p>
        <button class="btn primary" onClick=${() => setOn(true)}>Live-Ansicht starten</button>
      </div>`}

      ${on && html`<div class=${"live-layout" + (sel ? " with-side" : "")}>
        <div class="card live-graph">
          ${error && html`<div class="err">${error}</div>`}
          <canvas ref=${canvas} class="live-canvas"></canvas>
          ${snap && !snap.edges.length && html`<div class="live-empty">
            ${o.alerts ? "Gerade keine Verbindungen mit Alerts." : "Noch keine Verbindungen gesehen. Neue Ereignisse aus eve.json erscheinen hier nach ein bis zwei Sekunden."}</div>`}
          <div class="live-zoom">
            <button class="icon-btn" title="vergrößern" onClick=${() => g && g.zoom(1.25)}>+</button>
            <button class="icon-btn" title="verkleinern" onClick=${() => g && g.zoom(0.8)}>−</button>
            <button class="icon-btn" title="Ansicht zurücksetzen" onClick=${() => g && g.resetView()}>⤢</button>
          </div>
          <div class="live-legend">
            <span><i class="lg device"></i>Gerät</span>
            <span><i class="lg malicious"></i>Blockliste</span>
            <span><i class="lg suspicious"></i>auffällig</span>
            <span><i class="lg known"></i>bekannter Dienst</span>
            <span><i class="lg popular"></i>verbreitet</span>
            <span><i class="lg unknown"></i>unbekannt</span>
            <span><i class="lg group"></i>Multicast</span>
            <span><i class="lg ring"></i>Alert</span>
            <span><i class="lg dash"></i>eingehend</span>
          </div>
        </div>
        ${sel && html`<${LiveDetail} id=${sel} snap=${snap} goAlerts=${goAlerts}
          onClose=${() => { setSel(null); if (g) g.selected = null; }} />`}
      </div>`}
    </div>`;
  }

  // ------------------------------------------------------------------ App

  function App() {
    const [me, setMe] = useState(null);
    const [meErr, setMeErr] = useState(null);
    const loadMe = () => api("/api/me").then((m) => { setMe(m); setMeErr(null); }).catch((e) => setMeErr(e.message));
    useEffect(() => {
      loadMe();
      const h = () => loadMe();
      window.addEventListener("must-change-password", h);
      return () => window.removeEventListener("must-change-password", h);
    }, []);
    if (!me) return html`<main>${meErr ? html`<div class="err">${meErr}</div>` : html`<div class="empty">lädt …</div>`}</main>`;
    if (me.must_change) return html`<${PasswordModal} me=${me} forced onDone=${() => window.location.reload()} />`;
    return html`<${Dashboard} me=${me} />`;
  }

  function Dashboard({ me }) {
    const read = (k, d) => { try { return localStorage.getItem(k) || d; } catch (e) { return d; } };
    const isAdmin = me.role === "admin";
    const [pwOpen, setPwOpen] = useState(false);
    const [restoreReq, setRestoreReq] = useState(null);
    const [tab, setTabRaw] = useState(() => {
      const t = read("tab", "overview");
      return t === "settings" && !isAdmin ? "overview" : t;
    });
    const setTab = (t) => setTabRaw(t === "settings" && !isAdmin ? "overview" : t);
    const [hours, setHours] = useState(Number(read("hours", "24")));
    const [tick, setTick] = useState(0);
    const [filter, setFilter] = useState({});
    const [theme, setTheme] = useState(document.documentElement.dataset.theme || "auto");
    const refresh = useCallback(() => setTick((t) => t + 1), []);
    const { data: summary } = useApi("/api/summary?hours=24", [tick]);
    const { data: status } = useApi("/api/status", [tick]);
    const [devTick, setDevTick] = useState(0);
    const { data: devNames } = useApi("/api/devices/names", [tick, devTick]);
    const devCtx = useMemo(() => ({ names: devNames || {}, reload: () => setDevTick((t) => t + 1) }), [devNames]);

    useEffect(() => { const t = setInterval(refresh, REFRESH_MS); return () => clearInterval(t); }, []);
    useEffect(() => { try { localStorage.setItem("tab", tab); localStorage.setItem("hours", hours); } catch (e) {} }, [tab, hours]);
    useEffect(() => {
      const mq = window.matchMedia("(prefers-color-scheme: dark)");
      const h = () => setTheme((t) => (t === "auto" || t.startsWith("auto") ? "auto-" + mq.matches : t));
      mq.addEventListener("change", h);
      return () => mq.removeEventListener("change", h);
    }, []);
    const cycleTheme = () => {
      const isDark = document.documentElement.dataset.theme === "dark" ||
        (!document.documentElement.dataset.theme && window.matchMedia("(prefers-color-scheme: dark)").matches);
      const next = isDark ? "light" : "dark";
      document.documentElement.dataset.theme = next;
      try { localStorage.setItem("theme", next); } catch (e) {}
      setTheme(next);
    };
    const goAlerts = (f) => { setFilter(f); setTab("alerts"); window.scrollTo(0, 0); };
    const stale = !status || !status.last_cycle || Date.now() / 1000 - status.last_cycle > 120;

    const tabs = [
      ["overview", "Übersicht"],
      ["alerts", "Alerts", summary && summary.alerts_open],
      ["signatures", "Signaturen", summary && summary.new_signatures],
      ["live", "Live"],
      ["devices", "Geräte"],
      ["fingerprints", "Fingerprints", summary && summary.fp_hits],
      ["anomalies", "Anomalien", summary && summary.anomalies_open],
      ["feeds", "Threat-Feeds"],
      ["status", "Status"],
      isAdmin && ["settings", "Einstellungen"],
    ].filter(Boolean);
    const fileProblem = status && (status.files.eve_json.error ||
      (status.files.fast_log.used && status.files.fast_log.error));
    return html`<${AdminCtx.Provider} value=${isAdmin}><${DevCtx.Provider} value=${devCtx}>
      <header><div class="bar">
        <div class="brand"><i class=${"dot" + (stale ? " stale" : "")} title=${stale ? "Keine aktuellen Daten" : "Einlesen läuft"}></i>Suricata IPS</div>
        <nav>${tabs.map(([id, label, count]) => html`
          <button key=${id} class=${"tab" + (tab === id ? " active" : "")} onClick=${() => { if (id === "alerts") setFilter({}); setTab(id); }}>
            ${label}${count ? html`<span class="count">${count > 999 ? "999+" : count}</span>` : null}
          </button>`)}</nav>
        <div class="spacer"></div>
        <div class="tools">
          ${["overview", "alerts", "signatures", "fingerprints"].includes(tab) && html`<div class="seg">${RANGES.map((r) => html`
            <button key=${r.h} class=${hours === r.h ? "active" : ""} onClick=${() => setHours(r.h)}>${r.label}</button>`)}</div>`}
          <button class="icon-btn" title="Aktualisieren" onClick=${refresh}>⟳</button>
          <button class="icon-btn" title="Hell/Dunkel umschalten" onClick=${cycleTheme}>◐</button>
          <button class="icon-btn lang-btn" title=${LANG === "de" ? "Switch to English" : "Auf Deutsch umschalten"} onClick=${() => setLang(LANG === "de" ? "en" : "de")}>${LANG === "de" ? "EN" : "DE"}</button>
          ${me.auth_enabled && html`<${UserMenu} me=${me} onPassword=${() => setPwOpen(true)} />`}
        </div>
      </div></header>
      <main>
        ${status && status.version !== FRONTEND_VERSION && html`<div class="err">
          Versionen passen nicht zusammen: Backend ${status.version || "alt (< 1.2.0)"}, Frontend ${FRONTEND_VERSION}.
          Bitte <span class="mono">backend/server.py</span> mit kopieren und den Dienst neu starten
          (<span class="mono">sudo systemctl restart suricata-dashboard</span>).
        </div>`}
        ${fileProblem && tab !== "settings" && html`<div class="err">
          Logdatei nicht lesbar: ${status.files.eve_json.error ? status.files.eve_json.path + " – " + status.files.eve_json.error
            : status.files.fast_log.path + " – " + status.files.fast_log.error}
          ${isAdmin && html`<button class="btn" style=${{ marginLeft: 10 }} onClick=${() => setTab("settings")}>Pfade einstellen</button>`}
        </div>`}
        ${isAdmin && status && status.restore_hint && html`<div class="warnmsg restore-hint">
          <b>Eigene Daten fehlen?</b> In der Datenbank stehen keine Gerätenamen und Markierungen, die automatische Sicherung vom
          ${" " + fmtDateTime(status.restore_hint.time)} enthält aber
          ${" " + [["device_names", "Gerätename", "Gerätenamen"], ["flags", "markierte Signatur", "markierte Signaturen"],
            ["fp_notes", "Fingerprint-Notiz", "Fingerprint-Notizen"], ["feeds", "Feed-Einstellung", "Feed-Einstellungen"]]
            .filter(([k]) => status.restore_hint.counts[k])
            .map(([k, one, many]) => { const n = status.restore_hint.counts[k]; return n + " " + tr(n === 1 ? one : many); }).join(", ")}.
          <button class="btn primary" style=${{ marginLeft: 10 }} onClick=${() => { setRestoreReq(status.restore_hint.name); setTab("settings"); }}>Wiederherstellen …</button>
        </div>`}
        ${!me.auth_enabled && html`<div class="err">Die Anmeldung ist abgeschaltet (<span class="mono">"auth": false</span> in config.json) – jeder im Netz hat vollen Zugriff.</div>`}
        ${tab === "overview" && html`<${Overview} hours=${hours} tick=${tick} theme=${theme} refresh=${refresh} goAlerts=${goAlerts} />`}
        ${tab === "alerts" && html`<${AlertsPage} hours=${hours} tick=${tick} refresh=${refresh} filter=${filter} setFilter=${setFilter} />`}
        ${tab === "signatures" && html`<${SignaturesPage} hours=${hours} tick=${tick} refresh=${refresh} goAlerts=${goAlerts} />`}
        ${tab === "live" && html`<${LivePage} theme=${theme} goAlerts=${goAlerts} />`}
        ${tab === "devices" && html`<${DevicesPage} tick=${tick} goAlerts=${goAlerts} />`}
        ${tab === "anomalies" && html`<${AnomaliesPage} tick=${tick} refresh=${refresh} isAdmin=${isAdmin} />`}
        ${tab === "fingerprints" && html`<${FingerprintsPage} hours=${hours} tick=${tick} refresh=${refresh} isAdmin=${isAdmin} />`}
        ${tab === "feeds" && html`<${FeedsPage} tick=${tick} />`}
        ${tab === "status" && html`<${StatusPage} tick=${tick} />`}
        ${tab === "settings" && isAdmin && html`<${SettingsPage} refresh=${refresh} me=${me} restoreReq=${restoreReq} />`}
      </main>
      ${pwOpen && html`<${PasswordModal} me=${me} onClose=${() => setPwOpen(false)}
        onDone=${() => setPwOpen(false)} />`}
      </${DevCtx.Provider}></${AdminCtx.Provider}>`;
  }

  ReactDOM.createRoot(document.getElementById("root")).render(html`<${App} />`);
})();
