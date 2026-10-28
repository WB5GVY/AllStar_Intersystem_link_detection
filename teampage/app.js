/* Repeater node status page — renders public_export schema 1.
   Data: GET /api/status (the Static Web App's proxy, login-protected). For local
   testing with `python3 -m http.server` the page falls back to ./status.json.
   Everything is rendered with DOM APIs (textContent) — no innerHTML with data. */
(function () {
  "use strict";
  var LOCAL = /^(localhost|127\.0\.0\.1|\[::1\])$/.test(window.location.hostname) || window.location.protocol === "file:";
  var DATA_URLS = LOCAL ? ["/api/status", "./status.json"] : ["/api/status"];
  var loginShown = false;       // sign-in banner shown: stop polling until the page is reloaded
  var lastErr = null;           // sticky: a fetch/schema error survives the 15 s banner refresh
  var inFlight = false;         // one fetch at a time
  var POLL_MS = 60000;
  var SHOW_GITHUB_LOGIN = false;   // Microsoft sign-in only, per Bennett (2026-10-20)
  var last = null;              // last document
  var lastFetched = null;       // Date of the last successful fetch

  // ---------- helpers ----------
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function age(s) {
    if (s === null || s === undefined || isNaN(s)) return "—";
    s = Math.max(0, Number(s));
    if (s < 60) return "<1 m";
    if (s < 3600) return Math.round(s / 60) + " m";
    if (s < 86400) return (s / 3600).toFixed(1) + " h";
    return (s / 86400).toFixed(1) + " d";
  }
  function uptime(s) {
    if (s === null || s === undefined) return "—";
    s = Number(s);
    var d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600);
    return d > 0 ? d + " d " + h + " h" : h + " h " + Math.floor((s % 3600) / 60) + " m";
  }
  function fmtTime(iso) {
    if (!iso) return "";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    var p = function (n) { return (n < 10 ? "0" : "") + n; };
    return (d.getMonth() + 1) + "-" + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes());
  }
  function wrapMark(td) {
    var span = el("span", "mark");
    while (td.firstChild) span.appendChild(td.firstChild);
    td.appendChild(span);
  }
  function textWith(td, parts) {   // parts: array of strings or nodes
    parts.forEach(function (p) { td.appendChild(typeof p === "string" ? document.createTextNode(p) : p); });
    return td;
  }

  // ---------- cell renderers (shared by table and cards) ----------
  function regText(n) {
    var r = n.registered || {};
    if (r.ok === null || r.ok === undefined) return { text: ["?"], bad: false, unk: true };
    var t = [(r.ok ? "✓ " : "✗ ") + age(r.age_s)];
    if (r.time) t.push(el("span", "small", " (" + fmtTime(r.time) + ")"));
    return { text: t, bad: !r.ok, unk: false };
  }
  function linkText(n) {
    var l = n.link || {};
    if (l.letter === "self") return { text: ["hub"], bad: false, unk: false };
    if (!l.letter) return { text: ["?"], bad: false, unk: true };
    var good = (l.letter === "T" || l.letter === "R" || l.letter === "L");
    var t = l.letter + (l.text ? " " + l.text : "");
    return { text: [t], bad: !good, unk: l.letter === "?" };
  }
  function postText(n) {
    var p = n.posting || {};
    if (p.ok === null || p.ok === undefined) return { text: ["?"], bad: false, unk: true };
    var t = [(p.ok ? "✓ " : "✗ ") + (p.ok ? age(p.age_s) : "—")];
    if (p.version) t.push(el("span", "small", " " + p.version));
    return { text: t, bad: !p.ok, unk: false };
  }
  function dnsShort(n) {
    var d = n.dns || {}, a = d.asl || {}, h = d.hamvoip || {};
    if (a.present === null || a.present === undefined) return { text: ["?"], bad: false, unk: true };
    var t = "ASL " + (a.present ? "✓" + (a.txt_port ? " " + a.txt_port : "") : "✗") + " · HV ";
    if (h.expected === true) t += (h.present ? "✓" : "✗");
    else t += (h.present ? "✓" : "n/a");
    var issues = (d.issues || []);
    if (issues.length) t += " ⚠";
    var bad = !a.present || (h.expected === true && !h.present) || issues.length > 0;
    return { text: [t], bad: bad, unk: false };
  }
  function dnsLong(n) {
    var d = n.dns || {}, a = d.asl || {}, h = d.hamvoip || {};
    if (a.present === null || a.present === undefined) return { text: ["? (not checked)"], bad: false, unk: true };
    var t = "ASL: " + (a.present ? ("A " + (a.a_ip || "—") + " · TXT " + (a.txt_ip || "—") + (a.txt_port ? ":" + a.txt_port : "")) : "no record");
    t += " · HV: ";
    if (h.present) t += (h.txt_ip || "—") + (h.txt_port ? ":" + h.txt_port : "");
    else if (h.expected === true) t += "missing";
    else t += "n/a";
    var issues = (d.issues || []);
    if (issues.length) t += " · ⚠ " + issues.join("; ");
    var notes = (d.notes || []);
    var parts = [t];
    if (notes.length) parts.push(el("span", "small", " · " + notes.join("; ")));
    var bad = !a.present || (h.expected === true && !h.present) || issues.length > 0;
    return { text: parts, bad: bad, unk: false };
  }
  function cell(tag, r) {
    var td = el(tag);
    textWith(td, r.text);
    if (r.bad) wrapMark(td);
    return td;
  }

  // ---------- banner / summary ----------
  function setBanner(doc, err) {
    var b = document.getElementById("banner");
    b.className = "banner";
    clear(b);
    if (!doc) {
      b.classList.add("banner-red");
      b.appendChild(document.createTextNode("No data" + (err ? " — " + err : "")));
      return;
    }
    var dataTs = doc.health_updated || doc.scan_time || doc.generated_at;   // the age of the FACTS, not of the render (audit S4)
    var gen = new Date(dataTs);
    var ageS = isNaN(gen.getTime()) ? null : Math.max(0, (Date.now() - gen.getTime()) / 1000);
    var stale = (doc.legend && doc.legend.stale_after_s) || 900;
    var cls = ageS === null ? "banner-red" : ageS > 3600 ? "banner-red" : ageS > stale ? "banner-amber" : "banner-ok";
    b.classList.add(cls);
    var head = "Node data " + (ageS === null ? "of unknown age" : age(ageS) + " old");
    if (cls === "banner-red" && ageS !== null) head += " — STALE: the monitor, its node-health step, or its host may be down";
    else if (cls === "banner-amber") head += " — getting stale";
    if (doc.scan_ok === false) head += " · last scan reported a problem";
    if (doc.scan_gated === true) head += " · scan gated (hub record unavailable)";
    b.appendChild(document.createTextNode(head));
    var dmn = doc.daemon || {};
    var sub = "node health " + (doc.health_updated || "—") + " · scan " + (doc.scan_time || "—") + " · rendered " + (doc.generated_at || "—") +
              (dmn.commit ? " · daemon " + dmn.commit : "") + (dmn.host ? " @ " + dmn.host : "") +
              (err ? " · last fetch failed: " + err : "") +
              (lastFetched ? " · fetched " + fmtTime(lastFetched.toISOString()) : "");
    b.appendChild(el("small", null, sub));
  }
  function setSummary(doc) {
    var s = document.getElementById("summary");
    clear(s);
    var c = doc.counts || {};
    var part = function (label, k, kk) {
      var span = el("span");
      span.appendChild(el("b", null, (c[k] === null || c[k] === undefined ? "?" : c[k]) + "/" + (c[kk] === null || c[kk] === undefined ? "?" : c[kk])));
      span.appendChild(document.createTextNode(" " + label + "   "));
      return span;
    };
    s.appendChild(part("registered", "registered", "registered_known"));
    s.appendChild(part("linked", "linked", "linked_known"));
    s.appendChild(part("posting", "posting", "posting_known"));
    s.appendChild(part("ASL DNS", "dns_asl", "dns_asl_known"));
    s.appendChild(part("HamVoIP DNS", "dns_hv", "dns_hv_known"));
    var di = el("span"); di.appendChild(el("b", null, c.dns_issues === null || c.dns_issues === undefined ? "?" : c.dns_issues));
    di.appendChild(document.createTextNode(" DNS issues")); s.appendChild(di);
  }

  // ---------- table ----------
  function renderTable(doc) {
    var tb = document.getElementById("status-rows");
    clear(tb);
    (doc.groups || []).forEach(function (g) {
      (g.nodes || []).forEach(function (num) {
        var n = doc.nodes[num] || {};
        var tr = el("tr");
        var reg = regText(n), lnk = linkText(n), pst = postText(n), dns = dnsShort(n);
        var dotTd = el("td");
        var dot = el("span", "dot");
        var overall = n.observed === false ? "unk" : (reg.bad || pst.bad || (lnk.bad && lnk.unk === false) || dns.bad) ? "bad" : "";
        if (overall) dot.classList.add(overall);
        dotTd.appendChild(dot);
        tr.appendChild(dotTd);
        var numTd = el("td");
        var a = el("a", null, num); a.href = "#node-" + num; numTd.appendChild(a);
        tr.appendChild(numTd);
        var dTd = el("td", "desc", n.description || "");
        if (n.callsign) { dTd.appendChild(el("span", "small", " " + n.callsign)); }
        tr.appendChild(dTd);
        tr.appendChild(cell("td", reg));
        var lt = cell("td", lnk);
        if (n.link && n.link.from && n.link.letter !== "self") lt.appendChild(el("span", "small", " (" + n.link.from + ")"));
        tr.appendChild(lt);
        tr.appendChild(cell("td", pst));
        tr.appendChild(cell("td", dns));
        tb.appendChild(tr);
      });
    });
    var lg = document.getElementById("legend");
    var letters = (doc.legend && doc.legend.letters) || {};
    lg.textContent = "Link letters: " + Object.keys(letters).map(function (k) { return k + " " + letters[k]; }).join(" · ") +
      ". Yellow = abnormal. Grey dot = not observed this scan.";
  }

  // ---------- cards ----------
  function row(k, r) {
    var tr = el("tr");
    tr.appendChild(el("td", "k", k));
    var v = el("td", "v");
    textWith(v, r.text);
    if (r.bad) wrapMark(v);
    tr.appendChild(v);
    return tr;
  }
  function plain(k, text) { return row(k, { text: [text === null || text === undefined || text === "" ? "—" : String(text)], bad: false }); }
  function card(num, n) {
    var c = el("article", "card");
    c.id = "node-" + num;
    var h = el("h3");
    h.appendChild(el("span", "num", num));
    if (n.callsign) h.appendChild(el("span", "call", n.callsign));
    h.appendChild(el("span", "desc", n.description || ""));
    c.appendChild(h);
    var t = el("table");
    t.appendChild(row("Registered", regText(n)));
    t.appendChild(row("Link" + (n.link && n.link.from ? " (" + n.link.from + ")" : ""), linkText(n)));
    t.appendChild(row("Posting", postText(n)));
    t.appendChild(row("DNS", dnsLong(n)));
    var r = n.radio || {}, s = n.stats || {};
    t.appendChild(plain("Freq / Tone", (r.frequency || "—") + " / " + (r.tone || "—")));
    t.appendChild(plain("Location", r.location || r.site || "—"));
    t.appendChild(plain("IP : port", s.ipaddr ? s.ipaddr + " : " + (s.port || "—") + (s.udpport && s.udpport !== s.port ? "  (portal port " + s.udpport + ")" : "") + (s.proxy_ip ? "  via " + s.proxy_ip : "") : "—"));
    t.appendChild(plain("Uptime · Key-ups", (n.uptime_s === null || n.uptime_s === undefined ? "—" : uptime(n.uptime_s)) + " · " + (n.keyups === null || n.keyups === undefined ? "—" : n.keyups)));
    var ltr = el("tr"); ltr.appendChild(el("td", "k", "Links" + (n.links && n.links.length ? " (" + n.links.length + ")" : "")));
    var lv = el("td", "v links");
    if (n.links && n.links.length) n.links.forEach(function (tok) {
      var sp = el("span", tok.charAt(0) === "C" ? "c" : "", tok); lv.appendChild(sp);
    }); else lv.textContent = n.posting && n.posting.ok ? "(none)" : "(not posting)";
    ltr.appendChild(lv); t.appendChild(ltr);
    if (n.observed === false) t.appendChild(plain("Note", n.gated ? "scan gated — hub record unavailable" : "not observed this scan"));
    c.appendChild(t);
    var links = el("p", "small");
    var a1 = el("a", null, "stats page"); a1.href = "https://stats.allstarlink.org/stats/" + encodeURIComponent(num); a1.target = "_blank"; a1.rel = "noopener";
    var a2 = el("a", null, "network map"); a2.href = "https://stats.allstarlink.org/maps/" + encodeURIComponent(num); a2.target = "_blank"; a2.rel = "noopener";
    links.appendChild(a1); links.appendChild(document.createTextNode(" · ")); links.appendChild(a2);
    c.appendChild(links);
    return c;
  }
  function renderGroups(doc) {
    var root = document.getElementById("groups");
    clear(root);
    (doc.groups || []).forEach(function (g) {
      var sec = el("section");
      var h = el("h2");
      h.appendChild(el("span", "icon", g.icon === "hub" ? "⌾" : g.icon === "bridge" ? "⇄" : g.icon === "account" ? "☺" : "•"));
      h.appendChild(document.createTextNode(g.name || ""));
      sec.appendChild(h);
      var grid = el("div", "cards");
      (g.nodes || []).forEach(function (num) { grid.appendChild(card(num, doc.nodes[num] || {})); });
      sec.appendChild(grid);
      root.appendChild(sec);
    });
  }

  // ---------- fetch loop ----------
  function showLogin() {
    loginShown = true;
    var b = document.getElementById("banner");
    b.className = "banner banner-amber";
    clear(b);
    b.appendChild(document.createTextNode("Sign-in required. "));
    var a1 = el("a", null, "Sign in with Microsoft"); a1.href = "/.auth/login/aad?post_login_redirect_uri=/";
    b.appendChild(a1);
    if (SHOW_GITHUB_LOGIN) {       // the GitHub provider is disabled on the site for now (2026-10-20); flip when re-enabled
      var a2 = el("a", null, "Sign in with GitHub"); a2.href = "/.auth/login/github?post_login_redirect_uri=/";
      b.appendChild(document.createTextNode(" · ")); b.appendChild(a2);
    }
    b.appendChild(el("small", null, "Invited team members only. If you are signed in and still see this, your account has not been given the team role yet."));
  }
  function render(doc, err) {
    if (doc) {
      if (doc.schema !== 1) { lastErr = "unsupported document schema " + doc.schema + " — this page needs an update"; setBanner(last, lastErr); return; }
      try {
        setSummary(doc); renderTable(doc); renderGroups(doc);
        last = doc; lastErr = null;
      } catch (e) {
        lastErr = "document could not be rendered (" + (e && e.message ? e.message : "error") + ")";
      }
    } else if (err) {
      lastErr = err;
    }
    setBanner(last, lastErr);
  }
  function fetchOnce(i) {
    i = i || 0;
    if (loginShown) return;
    if (i === 0) { if (inFlight) return; inFlight = true; }
    if (i >= DATA_URLS.length) { inFlight = false; render(null, "no data source reachable"); return; }
    // redirect: "manual" — the Static Web App answers 401 with a redirect to the identity provider;
    // following it cross-origin would fail CORS and hide the real reason (audit S5).
    // Every path below ends by clearing inFlight (audit V2); a 20 s abort guards a hung fetch.
    var ctl = (typeof AbortController === "function") ? new AbortController() : null;
    var abortTimer = ctl ? setTimeout(function () { ctl.abort(); }, 20000) : null;
    var next = function () { if (abortTimer) clearTimeout(abortTimer); return fetchOnce(i + 1); };
    var finish = function (err) { if (abortTimer) clearTimeout(abortTimer); inFlight = false; if (err !== undefined) render(null, err); };
    fetch(DATA_URLS[i], { cache: "no-store", credentials: "same-origin", redirect: "manual", signal: ctl ? ctl.signal : undefined }).then(function (r) {
      if (r.type === "opaqueredirect" || r.status === 401 || r.status === 403) { finish(); showLogin(); return null; }
      if (!r.ok) { if (i + 1 < DATA_URLS.length) return next(); throw new Error("HTTP " + r.status + (r.status === 404 ? " (no snapshot published yet)" : "")); }
      return r.json().then(function (doc) {
        if (!doc || typeof doc !== "object") throw new Error("empty document");
        return doc;
      });
    }).then(function (doc) {
      if (doc === null) return;             // login path already handled
      finish(); lastFetched = new Date(); render(doc, null);
    }).catch(function (e) {
      if (i + 1 < DATA_URLS.length) return next();
      finish(e && e.name === "AbortError" ? "fetch timed out" : (e && e.message ? e.message : "fetch failed"));
    });
  }
  fetchOnce();
  setInterval(function () { fetchOnce(); }, POLL_MS);
  setInterval(function () { if (last && !loginShown) setBanner(last, lastErr); }, 15000);   // keep the age fresh, keep the error
})();
