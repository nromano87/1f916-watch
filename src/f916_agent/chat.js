/* Public human chat — self-injects a mobile-style sheet on every Watch page. */
(function () {
  if (window.__f916Chat) return;
  window.__f916Chat = true;

  var POLL_MS = 8000;
  var NAME_KEY = "f916_chat_name";
  var SEEN_KEY = "f916_chat_seen";
  var OPEN_KEY = "f916_chat_open";
  var FIRST_KEY = "f916_chat_met";
  var IGNORE_KEY = "f916_chat_ignore";
  var VID_KEY = "f916_vid";
  var FULL_KEY = "f916_chat_full";
  var CACHE_KEY = "f916_chat_cache";
  var SCROLL_KEY = "f916_chat_scroll";

  function mintVid() {
    try {
      if (window.crypto && typeof window.crypto.randomUUID === "function") {
        return window.crypto.randomUUID();
      }
    } catch (_) {}
    var s = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
    return s.replace(/[xy]/g, function (c) {
      var r = (Math.random() * 16) | 0;
      var v = c === "x" ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  }

  function loadVisitorId() {
    var vid = "";
    try {
      vid = (localStorage.getItem(VID_KEY) || "").trim().toLowerCase();
    } catch (_) {}
    if (
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
        vid
      )
    ) {
      vid = mintVid().toLowerCase();
      try {
        localStorage.setItem(VID_KEY, vid);
      } catch (_) {}
    }
    try {
      window.__f916Vid = vid;
    } catch (_) {}
    return vid;
  }

  var visitorId = loadVisitorId();
  var PRESENCE_MS = 25000;
  var presenceStarted = false;

  function presencePage() {
    var parts = location.pathname.replace(/\/+$/, "").split("/").filter(Boolean);
    if (!parts.length) return "front";
    var h = parts[0];
    if (parts.length === 1 && !RESERVED[String(h).toLowerCase()]) return h;
    if (h === "citizens") return "_home";
    return String(h).toLowerCase();
  }

  function beatPresence() {
    if (!visitorId) return;
    var qs =
      "vid=" +
      encodeURIComponent(visitorId) +
      "&page=" +
      encodeURIComponent(presencePage());
    try {
      fetch("/api/presence?" + qs, { cache: "no-store", keepalive: true }).catch(
        function () {}
      );
    } catch (_) {}
  }

  function startPresence() {
    if (presenceStarted) return;
    presenceStarted = true;
    beatPresence();
    setInterval(beatPresence, PRESENCE_MS);
    document.addEventListener("visibilitychange", function () {
      if (!document.hidden) beatPresence();
    });
  }

  var logEl = null;
  var ignoreEl = null;
  var nameEl = null;
  var nameRow = null;
  var nameChip = null;
  var textEl = null;
  var errEl = null;
  var sendBtn = null;
  var open = false;
  var full = false;
  var latestId = 0;
  var seenId = 0;
  // False until we have a real persisted watermark (or quietly baseline one).
  // A stored "0" from opening before poll used to look "initialized" and
  // re-badge the whole history on every visit.
  var seenReady = false;
  var lastMsgs = [];
  var ignored = {};
  var myName = "";
  var scrollAnchor = null;
  var restoringScroll = false;
  var saveScrollTimer = null;
  var scrollReady = false;
  var holdScrollCapture = false;

  function readStoredSeen() {
    try {
      var local = localStorage.getItem(SEEN_KEY);
      var sess = sessionStorage.getItem(SEEN_KEY);
      var a = local != null ? parseInt(local, 10) || 0 : -1;
      var b = sess != null ? parseInt(sess, 10) || 0 : -1;
      return Math.max(a, b);
    } catch (_) {
      return -1;
    }
  }

  function writeStoredSeen(id) {
    var v = String(Math.max(0, id || 0));
    try {
      localStorage.setItem(SEEN_KEY, v);
    } catch (_) {}
    try {
      sessionStorage.setItem(SEEN_KEY, v);
    } catch (_) {}
  }

  try {
    var stored = readStoredSeen();
    if (stored > 0) {
      seenId = stored;
      seenReady = true;
      writeStoredSeen(seenId);
    }
  } catch (_) {}
  try {
    myName = (localStorage.getItem(NAME_KEY) || "").trim();
  } catch (_) {}
  try {
    full = sessionStorage.getItem(FULL_KEY) === "1";
  } catch (_) {}

  function readScrollAnchor() {
    try {
      var raw =
        sessionStorage.getItem(SCROLL_KEY) || localStorage.getItem(SCROLL_KEY);
      if (!raw) return null;
      var data = JSON.parse(raw);
      if (!data || typeof data !== "object") return null;
      var id = parseInt(data.id, 10) || 0;
      if (data.bottom) return { bottom: true, id: id };
      if (id > 0) return { bottom: false, id: id };
    } catch (_) {}
    return null;
  }

  function writeScrollAnchor(anchor) {
    scrollAnchor = anchor;
    try {
      var v = JSON.stringify(anchor || { bottom: true, id: 0 });
      sessionStorage.setItem(SCROLL_KEY, v);
      localStorage.setItem(SCROLL_KEY, v);
    } catch (_) {}
  }

  try {
    scrollAnchor = readScrollAnchor();
  } catch (_) {}

  function loadIgnored() {
    ignored = {};
    try {
      var raw = localStorage.getItem(IGNORE_KEY);
      var list = raw ? JSON.parse(raw) : [];
      if (!Array.isArray(list)) list = [];
      for (var i = 0; i < list.length; i++) {
        var n = String(list[i] || "").trim().toLowerCase();
        if (n) ignored[n] = true;
      }
    } catch (_) {}
  }

  function saveIgnored() {
    try {
      localStorage.setItem(IGNORE_KEY, JSON.stringify(Object.keys(ignored)));
    } catch (_) {}
  }

  function isIgnored(name) {
    return !!ignored[String(name || "").trim().toLowerCase()];
  }

  function isMine(name) {
    return (
      !!myName &&
      String(name || "").trim().toLowerCase() === myName.toLowerCase()
    );
  }

  function ignoreName(name) {
    var key = String(name || "").trim().toLowerCase();
    if (!key || isMine(key)) return;
    ignored[key] = true;
    saveIgnored();
    renderAll();
  }

  function unignoreName(name) {
    var key = String(name || "").trim().toLowerCase();
    if (!key) return;
    delete ignored[key];
    saveIgnored();
    renderAll();
  }

  loadIgnored();

  var style = document.createElement("style");
  style.textContent =
    "#f916-chat-fab,#f916-chat-panel,#f916-chat-panel *{box-sizing:border-box;-webkit-tap-highlight-color:transparent;}" +
    "#f916-chat-fab{position:fixed;right:max(14px,env(safe-area-inset-right));bottom:max(14px,env(safe-area-inset-bottom));z-index:99980;min-width:56px;height:56px;padding:0 14px;border-radius:18px;border:1px solid rgba(18,32,28,.14);background:rgba(247,250,248,.96);color:#12201c;font:700 14px/1 \"DM Sans\",system-ui,sans-serif;cursor:pointer;box-shadow:0 10px 32px rgba(18,32,28,.18);backdrop-filter:blur(12px);display:flex;align-items:center;justify-content:center;}" +
    "#f916-chat-fab:active{transform:scale(.97);}" +
    "#f916-chat-fab .dot{position:absolute;top:-4px;right:-4px;min-width:20px;height:20px;padding:0 6px;border-radius:999px;background:#d4552a;color:#fff;font:700 11px/20px \"DM Sans\",system-ui,sans-serif;text-align:center;box-shadow:0 1px 4px rgba(212,85,42,.45);display:none;}" +
    "#f916-chat-fab.has-alert .dot{display:block;}" +
    "#f916-chat-scrim{position:fixed;inset:0;z-index:99985;background:rgba(18,32,28,.28);opacity:0;pointer-events:none;transition:opacity .2s ease;}" +
    "#f916-chat-scrim.open{opacity:1;pointer-events:auto;}" +
    "#f916-chat-panel{position:fixed;left:50%;bottom:0;z-index:99990;width:min(420px,100vw);height:min(92dvh,920px);max-height:92dvh;display:flex;flex-direction:column;background:#f4f7f5;border:1px solid rgba(18,32,28,.1);border-bottom:0;border-radius:22px 22px 0 0;box-shadow:0 -16px 48px rgba(18,32,28,.2);transform:translate(-50%,110%);transition:transform .74s cubic-bezier(.2,.8,.2,1),width .28s ease,height .28s ease,border-radius .28s ease,max-height .28s ease;font-family:\"DM Sans\",system-ui,sans-serif;color:#12201c;padding-bottom:env(safe-area-inset-bottom);pointer-events:auto;}" +
    "#f916-chat-panel.open{transform:translate(-50%,0);}" +
    "#f916-chat-panel.boot,#f916-chat-panel.boot.open{transition:none !important;}" +
    "#f916-chat-panel.full{left:0;right:0;top:0;bottom:0;width:100%;width:100dvw;height:100%;height:100dvh;max-height:none;border-radius:0;border:0;box-shadow:none;padding-top:env(safe-area-inset-top);}" +
    "#f916-chat-panel.full.open{transform:none;}" +
    "#f916-chat-panel .grab{flex:0 0 auto;display:flex;justify-content:center;padding:10px 0 2px;}" +
    "#f916-chat-panel.full .grab{display:none;}" +
    "#f916-chat-panel .grab i{width:42px;height:5px;border-radius:999px;background:rgba(18,32,28,.18);}" +
    "#f916-chat-panel header{display:block;padding:6px 104px 14px 16px;border-bottom:1px solid rgba(18,32,28,.08);}" +
    "#f916-chat-panel header h2{margin:0;font:700 1.35rem/1.15 Fraunces,Georgia,serif;letter-spacing:-.03em;}" +
    "#f916-chat-panel header p{margin:4px 0 0;font-size:12px;color:#5a6a64;font-weight:500;line-height:1.35;}" +
    "#f916-chat-panel .tools{position:absolute;top:10px;right:10px;z-index:2;display:flex;gap:6px;}" +
    "#f916-chat-panel.full .tools{top:max(10px,env(safe-area-inset-top));right:max(10px,env(safe-area-inset-right));}" +
    "#f916-chat-panel .tools button{border:0;background:rgba(18,32,28,.06);width:40px;height:40px;border-radius:12px;font:700 18px/1 system-ui;color:#5a6a64;cursor:pointer;padding:0;display:flex;align-items:center;justify-content:center;}" +
    "#f916-chat-panel .tools button:active{background:rgba(18,32,28,.1);color:#12201c;}" +
    "#f916-chat-panel .tools .expand{font-size:16px;}" +
    "#f916-chat-log{flex:1;overflow:auto;-webkit-overflow-scrolling:touch;padding:14px 14px 8px;display:flex;flex-direction:column;gap:10px;}" +
    "#f916-chat-panel.full #f916-chat-log{padding:16px max(16px,env(safe-area-inset-right)) 10px max(16px,env(safe-area-inset-left));max-width:720px;width:100%;margin:0 auto;}" +
    "#f916-chat-panel.full #f916-chat-ignored,#f916-chat-panel.full #f916-chat-form{max-width:720px;width:100%;margin-left:auto;margin-right:auto;padding-left:max(16px,env(safe-area-inset-left));padding-right:max(16px,env(safe-area-inset-right));}" +
    "#f916-chat-panel.full header{padding-left:max(16px,env(safe-area-inset-left));padding-right:max(104px,calc(env(safe-area-inset-right) + 96px));max-width:720px;width:100%;margin:0 auto;box-sizing:border-box;}" +
    "#f916-chat-log .empty{margin:auto;color:#8a9892;font-size:15px;text-align:center;padding:28px 18px;line-height:1.45;}" +
    "#f916-chat-log .msg{padding:12px 14px;border-radius:16px;background:#fff;border:1px solid rgba(18,32,28,.07);box-shadow:0 1px 0 rgba(255,255,255,.8) inset;}" +
    "#f916-chat-log .msg.mine{background:rgba(12,124,102,.08);border-color:rgba(12,124,102,.16);}" +
    "#f916-chat-log .msg .meta{display:flex;gap:10px;align-items:center;margin-bottom:6px;font-size:12px;color:#5a6a64;}" +
    "#f916-chat-log .msg .who{font-weight:700;color:#0c7c66;font-size:13px;}" +
    "#f916-chat-log .msg .meta-right{margin-left:auto;display:flex;gap:10px;align-items:center;}" +
    "#f916-chat-log .msg .ignore{border:0;background:rgba(18,32,28,.05);color:#5a6a64;font:600 12px/1 \"DM Sans\",system-ui,sans-serif;cursor:pointer;padding:8px 10px;border-radius:999px;min-height:32px;}" +
    "#f916-chat-log .msg .ignore:active{background:rgba(212,85,42,.12);color:#d4552a;}" +
    "#f916-chat-log .msg .body{font-size:16px;line-height:1.45;white-space:pre-wrap;word-break:break-word;}" +
    "#f916-chat-log .msg .body mark.mention-hl{background:linear-gradient(180deg,rgba(212,148,64,.55) 0%,rgba(212,148,64,.28) 100%);color:inherit;padding:0.05em 0.2em;margin:0 -0.05em;border-radius:0.25em;box-decoration-break:clone;-webkit-box-decoration-break:clone;font-weight:650;}" +
    "#f916-chat-ignored{padding:0 14px 12px;border-bottom:1px solid rgba(18,32,28,.06);font-size:13px;color:#5a6a64;display:none;}" +
    "#f916-chat-ignored.show{display:block;}" +
    "#f916-chat-ignored .label{font-weight:700;margin-bottom:8px;font-size:12px;letter-spacing:.02em;text-transform:uppercase;color:#8a9892;}" +
    "#f916-chat-ignored .chip{display:inline-flex;align-items:center;gap:8px;margin:0 8px 8px 0;padding:8px 12px;border-radius:999px;border:1px solid rgba(18,32,28,.1);background:#fff;font-weight:600;}" +
    "#f916-chat-ignored .chip button{border:0;background:transparent;color:#d4552a;font:700 16px/1 system-ui;cursor:pointer;padding:0;width:22px;height:22px;}" +
    "#f916-chat-form{display:flex;flex-direction:column;gap:6px;padding:8px 10px 10px;border-top:1px solid rgba(18,32,28,.08);background:rgba(232,238,233,.95);}" +
    "#f916-chat-form .name-row{display:flex;align-items:center;min-height:0;}" +
    "#f916-chat-form .name-row.collapsed #f916-chat-name{display:none;}" +
    "#f916-chat-form .name-row:not(.collapsed) #f916-chat-name-chip{display:none;}" +
    "#f916-chat-form #f916-chat-name-chip{border:0;background:transparent;color:#5a6a64;font:600 12px/1.2 \"DM Sans\",system-ui,sans-serif;cursor:pointer;padding:2px 0;text-align:left;}" +
    "#f916-chat-form #f916-chat-name-chip strong{color:#0c7c66;font-weight:700;}" +
    "#f916-chat-form #f916-chat-name-chip:active{color:#12201c;}" +
    "#f916-chat-form #f916-chat-name{width:100%;font:inherit;font-size:16px;border:1px solid rgba(18,32,28,.14);border-radius:10px;padding:8px 10px;background:#fff;color:#12201c;}" +
    "#f916-chat-form .compose{display:flex;align-items:flex-end;gap:8px;}" +
    "#f916-chat-form textarea{flex:1;min-width:0;width:auto;font:inherit;font-size:16px;border:1px solid rgba(18,32,28,.14);border-radius:12px;padding:10px 12px;background:#fff;color:#12201c;min-height:42px;max-height:96px;resize:none;line-height:1.35;field-sizing:content;}" +
    "#f916-chat-form button#f916-chat-send{flex:0 0 auto;border:0;border-radius:12px;background:#0c7c66;color:#fff;font:700 13px/1 \"DM Sans\",system-ui,sans-serif;padding:0 14px;cursor:pointer;min-height:42px;min-width:56px;}" +
    "#f916-chat-form button#f916-chat-send:active{transform:scale(.97);}" +
    "#f916-chat-form button#f916-chat-send:disabled{opacity:.55;cursor:wait;}" +
    "#f916-chat-form .foot{display:flex;align-items:flex-start;justify-content:space-between;gap:8px;min-height:0;}" +
    "#f916-chat-form .hint{font-size:11px;color:#8a9892;line-height:1.3;}" +
    "#f916-chat-form .err{display:none;font-size:12px;color:#d4552a;font-weight:600;line-height:1.3;text-align:right;}" +
    "#f916-chat-form .err:not(:empty){display:block;}" +
    "body.f916-chat-full{overflow:hidden;touch-action:none;}" +
    "@media (min-width:720px){" +
    "#f916-chat-panel{left:auto;right:max(18px,env(safe-area-inset-right));bottom:max(18px,env(safe-area-inset-bottom));width:390px;height:min(78vh,740px);max-height:78vh;border-radius:22px;border-bottom:1px solid rgba(18,32,28,.1);transform:translateY(110%);box-shadow:0 18px 50px rgba(18,32,28,.22);}" +
    "#f916-chat-panel.open{transform:translateY(0);}" +
    "#f916-chat-panel.full{left:0;right:0;top:0;bottom:0;width:100%;height:100%;max-height:none;border-radius:0;border:0;box-shadow:none;}" +
    "#f916-chat-panel.full.open{transform:none;}" +
    "#f916-chat-scrim{display:none;}" +
    "body.f916-chat-full #f916-chat-scrim{display:block;}" +
    "}";
  document.head.appendChild(style);

  var scrim = document.createElement("div");
  scrim.id = "f916-chat-scrim";

  var fab = document.createElement("button");
  fab.id = "f916-chat-fab";
  fab.type = "button";
  fab.setAttribute("aria-label", "Open human chat");
  fab.innerHTML = 'chat<span class="dot" id="f916-chat-dot">0</span>';

  var panel = document.createElement("aside");
  panel.id = "f916-chat-panel";
  panel.setAttribute("aria-label", "Human chat");
  panel.innerHTML =
    '<div class="tools">' +
    '<button type="button" class="expand" aria-label="Expand chat" title="Expand">⛶</button>' +
    '<button type="button" class="close" aria-label="Close chat">×</button>' +
    "</div>" +
    '<div class="grab" aria-hidden="true"><i></i></div>' +
    "<header><h2>Human chat</h2></header>" +
    '<div id="f916-chat-ignored"></div>' +
    '<div id="f916-chat-log"><div class="empty">Say hi. No accounts.</div></div>' +
    '<form id="f916-chat-form">' +
    '<div class="name-row" id="f916-chat-name-row">' +
    '<button type="button" id="f916-chat-name-chip" aria-label="Edit display name"></button>' +
    '<input id="f916-chat-name" name="name" maxlength="24" placeholder="Display name" autocomplete="nickname" enterkeyhint="next" />' +
    "</div>" +
    '<div class="compose">' +
    '<textarea id="f916-chat-text" name="text" maxlength="280" placeholder="Message" rows="1" required enterkeyhint="send"></textarea>' +
    '<button type="submit" id="f916-chat-send">Send</button>' +
    "</div>" +
    '<div class="foot"><div class="hint">1 msg / 5s</div><div class="err" id="f916-chat-err"></div></div></form>';

  function $(id) {
    return document.getElementById(id);
  }

  function esc(s) {
    return String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  var RESERVED = {
    api: 1,
    post: 1,
    local: 1,
    hits: 1,
    front: 1,
    citizens: 1,
    stats: 1,
    watchlist: 1,
    treasury: 1,
    docket: 1,
    flags: 1,
    provenance: 1,
    trust: 1,
    listings: 1,
    payouts: 1,
    "mcp-funnel": 1,
    search: 1,
    porch: 1,
    attestations: 1,
    badge: 1,
    healthz: 1,
  };

  startPresence();

  function escapeRegExp(s) {
    return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function highlightOwnHandle(html) {
    var h = String(myName || "").trim();
    if (!h || h.length < 2) return html;
    var re = new RegExp(
      "(?<![A-Za-z0-9_-])(" + escapeRegExp(h) + ")(?![A-Za-z0-9_-])",
      "gi"
    );
    return String(html || "").replace(re, '<mark class="mention-hl">$1</mark>');
  }

  function formatBody(text) {
    return highlightOwnHandle(esc(text));
  }

  function ago(ts) {
    var s = Math.max(0, Math.floor(Date.now() / 1000 - (ts || 0)));
    if (s < 45) return "just now";
    if (s < 3600) return Math.floor(s / 60) + "m";
    if (s < 86400) return Math.floor(s / 3600) + "h";
    return Math.floor(s / 86400) + "d";
  }

  function visibleMessages(msgs) {
    var out = [];
    for (var i = 0; i < (msgs || []).length; i++) {
      if (!isIgnored(msgs[i].name)) out.push(msgs[i]);
    }
    return out;
  }

  function lastVisibleId(msgs) {
    var list = visibleMessages(msgs || lastMsgs || []);
    if (!list.length) return 0;
    return parseInt(list[list.length - 1].id, 10) || 0;
  }

  function msgOffsetTop(el) {
    if (!logEl || !el) return 0;
    return (
      el.getBoundingClientRect().top -
      logEl.getBoundingClientRect().top +
      logEl.scrollTop
    );
  }

  function findMsgEl(id) {
    if (!logEl || !id) return null;
    var exact = logEl.querySelector('.msg[data-id="' + id + '"]');
    if (exact) return exact;
    var nodes = logEl.querySelectorAll(".msg[data-id]");
    for (var i = 0; i < nodes.length; i++) {
      if ((parseInt(nodes[i].getAttribute("data-id"), 10) || 0) >= id) {
        return nodes[i];
      }
    }
    return nodes.length ? nodes[nodes.length - 1] : null;
  }

  function nearBottom() {
    if (!logEl) return true;
    return logEl.scrollHeight - logEl.scrollTop - logEl.clientHeight < 64;
  }

  function captureScrollAnchor() {
    if (!logEl || restoringScroll || !open || !scrollReady || holdScrollCapture) return;
    if (nearBottom()) {
      writeScrollAnchor({ bottom: true, id: lastVisibleId() });
      return;
    }
    var viewTop = logEl.getBoundingClientRect().top;
    var nodes = logEl.querySelectorAll(".msg[data-id]");
    var found = 0;
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i].getBoundingClientRect().bottom > viewTop + 8) {
        found = parseInt(nodes[i].getAttribute("data-id"), 10) || 0;
        break;
      }
    }
    if (found) writeScrollAnchor({ bottom: false, id: found });
    else writeScrollAnchor({ bottom: true, id: lastVisibleId() });
  }

  function restoreScroll(opts) {
    if (!logEl) return;
    var follow = !!(opts && opts.follow);
    var anchor = scrollAnchor || readScrollAnchor();
    restoringScroll = true;
    if (!anchor) {
      logEl.scrollTop = logEl.scrollHeight;
    } else if (anchor.bottom) {
      var firstNew = findMsgEl((anchor.id || 0) + 1);
      var lastEl = findMsgEl(anchor.id);
      if (!follow && firstNew && lastEl && firstNew !== lastEl) {
        logEl.scrollTop = msgOffsetTop(firstNew);
      } else {
        logEl.scrollTop = logEl.scrollHeight;
      }
    } else {
      var el = findMsgEl(anchor.id);
      logEl.scrollTop = el ? msgOffsetTop(el) : logEl.scrollHeight;
    }
    restoringScroll = false;
    scrollReady = true;
  }

  function scheduleRestoreScroll(opts) {
    restoreScroll(opts);
    requestAnimationFrame(function () {
      restoreScroll(opts);
    });
  }

  function paintExpand() {
    var btn = panel.querySelector(".expand");
    if (!btn) return;
    btn.textContent = full ? "❐" : "⛶";
    btn.setAttribute(
      "aria-label",
      full ? "Exit full screen" : "Expand chat"
    );
    btn.title = full ? "Exit full screen" : "Expand";
    btn.setAttribute("aria-pressed", full ? "true" : "false");
  }

  function syncOverlay() {
    // Scrim + body lock only in full screen — slide-out leaves the page usable.
    var overlay = open && full;
    scrim.classList.toggle("open", overlay);
    document.body.classList.toggle("f916-chat-full", overlay);
    document.body.classList.remove("f916-chat-open");
  }

  function setFull(next) {
    if (open) captureScrollAnchor();
    full = !!next;
    panel.classList.toggle("full", full);
    syncOverlay();
    paintExpand();
    try {
      sessionStorage.setItem(FULL_KEY, full ? "1" : "0");
    } catch (_) {}
    if (open) scheduleRestoreScroll();
  }

  function setOpen(next) {
    var wasOpen = open;
    if (wasOpen && !next) captureScrollAnchor();
    open = !!next;
    panel.classList.toggle("open", open);
    syncOverlay();
    fab.setAttribute("aria-expanded", open ? "true" : "false");
    fab.hidden = open;
    try {
      sessionStorage.setItem(OPEN_KEY, open ? "1" : "0");
    } catch (_) {}
    // Mark on open and close — close used to skip this, so a fast open/close
    // before poll could leave the badge stuck on already-viewed messages.
    markSeen();
    if (open) {
      paintBadge(0);
      scheduleRestoreScroll();
      if (textEl) {
        if (!nameEl.value) nameEl.focus();
        else textEl.focus();
      }
    } else {
      updateBadgeFromMsgs(lastMsgs);
    }
  }

  function saveCache(data) {
    try {
      sessionStorage.setItem(
        CACHE_KEY,
        JSON.stringify({
          messages: (data && data.messages) || [],
          latest_id: (data && data.latest_id) || 0,
        })
      );
    } catch (_) {}
  }

  function loadCache() {
    try {
      var raw = sessionStorage.getItem(CACHE_KEY);
      if (!raw) return null;
      var data = JSON.parse(raw);
      if (!data || !Array.isArray(data.messages)) return null;
      return data;
    } catch (_) {
      return null;
    }
  }

  function isDesktop() {
    try {
      return window.matchMedia("(min-width: 720px)").matches;
    } catch (_) {
      return (window.innerWidth || 0) >= 720;
    }
  }

  function shouldStartOpen() {
    try {
      // First visit: open by default on desktop only (mobile keeps the fab).
      if (!localStorage.getItem(FIRST_KEY)) return isDesktop();
      return sessionStorage.getItem(OPEN_KEY) === "1";
    } catch (_) {
      return false;
    }
  }

  function watermarkFrom(msgs) {
    var maxId = latestId;
    var list = msgs || lastMsgs || [];
    for (var i = 0; i < list.length; i++) {
      var id = parseInt(list[i].id, 10) || 0;
      if (id > maxId) maxId = id;
    }
    return maxId;
  }

  function syncSeenFromStorage() {
    var stored = readStoredSeen();
    if (stored > seenId) {
      seenId = stored;
      seenReady = true;
    }
  }

  function markSeen() {
    syncSeenFromStorage();
    var next = Math.max(seenId, watermarkFrom(lastMsgs));
    // Never persist a zero watermark before any messages are known — that
    // poisons storage and makes the entire history look unread next visit.
    if (next <= 0 && !(lastMsgs && lastMsgs.length) && latestId <= 0) {
      return;
    }
    seenId = next;
    seenReady = true;
    writeStoredSeen(seenId);
  }

  function paintBadge(n) {
    var dot = $("f916-chat-dot");
    if (!dot) return;
    if (n > 0 && !open) {
      fab.classList.add("has-alert");
      dot.textContent = n > 9 ? "9+" : String(n);
    } else {
      fab.classList.remove("has-alert");
      dot.textContent = "0";
    }
  }

  function renderIgnored() {
    if (!ignoreEl) return;
    var names = Object.keys(ignored).sort();
    if (!names.length) {
      ignoreEl.className = "";
      ignoreEl.innerHTML = "";
      return;
    }
    var chips = names
      .map(function (n) {
        return (
          '<span class="chip">' +
          esc(n) +
          ' <button type="button" data-unignore="' +
          esc(n) +
          '" aria-label="Stop ignoring ' +
          esc(n) +
          '">×</button></span>'
        );
      })
      .join("");
    ignoreEl.className = "show";
    ignoreEl.innerHTML =
      '<div class="label">Ignoring</div><div>' + chips + "</div>";
  }

  function renderMessages(msgs) {
    if (!logEl) return;
    var visible = visibleMessages(msgs);
    if (!visible.length) {
      logEl.innerHTML =
        '<div class="empty">' +
        (msgs && msgs.length
          ? "Everyone here is ignored."
          : "Say hi. No accounts.") +
        "</div>";
      return;
    }
    var html = [];
    for (var i = 0; i < visible.length; i++) {
      var m = visible[i];
      var mine = isMine(m.name);
      html.push(
        '<div class="msg' +
          (mine ? " mine" : "") +
          '" data-id="' +
          m.id +
          '"><div class="meta"><span class="who">' +
          esc(m.name) +
          '</span><div class="meta-right"><span>' +
          ago(m.t) +
          "</span>" +
          (mine
            ? ""
            : '<button type="button" class="ignore" data-ignore="' +
              esc(m.name) +
              '">ignore</button>') +
          '</div></div><div class="body">' +
          formatBody(m.text) +
          "</div></div>"
      );
    }
    if (open) captureScrollAnchor();
    logEl.innerHTML = html.join("");
    restoreScroll({ follow: open });
  }

  function updateBadgeFromMsgs(msgs) {
    syncSeenFromStorage();
    if (open) {
      markSeen();
      paintBadge(0);
      return;
    }
    var visible = visibleMessages(msgs);
    // First encounter with no real watermark: adopt quietly (same idea as
    // citizen tab badges) so landing never floods with already-there history.
    if (!seenReady) {
      markSeen();
      paintBadge(0);
      return;
    }
    var unread = 0;
    for (var j = 0; j < visible.length; j++) {
      if ((parseInt(visible[j].id, 10) || 0) > seenId) unread++;
    }
    paintBadge(unread);
  }

  function renderAll() {
    renderIgnored();
    renderMessages(lastMsgs);
    updateBadgeFromMsgs(lastMsgs);
  }

  function applyPayload(data) {
    var msgs = (data && data.messages) || [];
    lastMsgs = msgs;
    latestId = Math.max(
      latestId,
      parseInt((data && data.latest_id) || 0, 10) || 0
    );
    for (var j = 0; j < msgs.length; j++) {
      var id = parseInt(msgs[j].id, 10) || 0;
      if (id > latestId) latestId = id;
    }
    saveCache({ messages: msgs, latest_id: latestId });
    renderAll();
  }

  async function poll() {
    try {
      var res = await fetch("/api/chat", { cache: "no-store" });
      if (!res.ok) return;
      applyPayload(await res.json());
    } catch (_) {}
  }

  function paintNameRow(editing) {
    if (!nameRow || !nameChip || !nameEl) return;
    var name = (nameEl.value || myName || "").trim();
    var collapsed = !editing && !!name;
    nameRow.classList.toggle("collapsed", collapsed);
    if (collapsed) {
      nameChip.innerHTML = "as <strong>" + esc(name) + "</strong> · edit";
    }
  }

  function autosizeText() {
    if (!textEl) return;
    textEl.style.height = "auto";
    var next = Math.min(96, Math.max(42, textEl.scrollHeight));
    textEl.style.height = next + "px";
  }

  function bind(startOpen) {
    logEl = $("f916-chat-log");
    ignoreEl = $("f916-chat-ignored");
    nameRow = $("f916-chat-name-row");
    nameChip = $("f916-chat-name-chip");
    nameEl = $("f916-chat-name");
    textEl = $("f916-chat-text");
    errEl = $("f916-chat-err");
    sendBtn = $("f916-chat-send");
    if (myName) nameEl.value = myName;
    paintNameRow(false);
    autosizeText();

    fab.addEventListener("click", function () {
      setOpen(true);
    });
    panel.querySelector(".expand").addEventListener("click", function () {
      setFull(!full);
    });
    panel.querySelector(".close").addEventListener("click", function () {
      setOpen(false);
    });
    scrim.addEventListener("click", function () {
      if (full) setFull(false);
      else setOpen(false);
    });
    document.addEventListener("keydown", function (e) {
      if (e.key !== "Escape" || !open) return;
      if (full) setFull(false);
      else setOpen(false);
    });

    logEl.addEventListener("scroll", function () {
      if (restoringScroll || !open) return;
      if (saveScrollTimer) clearTimeout(saveScrollTimer);
      saveScrollTimer = setTimeout(captureScrollAnchor, 120);
    });
    document.addEventListener("visibilitychange", function () {
      if (document.hidden && open) captureScrollAnchor();
    });
    window.addEventListener("pagehide", function () {
      if (open) captureScrollAnchor();
    });
    logEl.addEventListener("click", function (e) {
      var btn = e.target.closest("[data-ignore]");
      if (!btn) return;
      ignoreName(btn.getAttribute("data-ignore") || "");
    });
    ignoreEl.addEventListener("click", function (e) {
      var btn = e.target.closest("[data-unignore]");
      if (!btn) return;
      unignoreName(btn.getAttribute("data-unignore") || "");
    });

    nameChip.addEventListener("click", function () {
      paintNameRow(true);
      nameEl.focus();
      nameEl.select();
    });
    nameEl.addEventListener("blur", function () {
      var name = (nameEl.value || "").trim();
      var prev = myName;
      if (name) {
        myName = name;
        try {
          localStorage.setItem(NAME_KEY, name);
        } catch (_) {}
      }
      paintNameRow(false);
      if (myName !== prev) renderAll();
    });
    nameEl.addEventListener("keydown", function (e) {
      if (e.key !== "Enter") return;
      e.preventDefault();
      nameEl.blur();
      textEl.focus();
    });
    textEl.addEventListener("input", autosizeText);
    textEl.addEventListener("keydown", function (e) {
      if (e.key !== "Enter" || e.shiftKey) return;
      e.preventDefault();
      $("f916-chat-form").requestSubmit
        ? $("f916-chat-form").requestSubmit()
        : $("f916-chat-form").dispatchEvent(
            new Event("submit", { cancelable: true, bubbles: true })
          );
    });

    $("f916-chat-form").addEventListener("submit", async function (e) {
      e.preventDefault();
      if (errEl) errEl.textContent = "";
      var name = (nameEl.value || "").trim();
      var text = (textEl.value || "").trim();
      if (!name || !text) {
        if (!name) paintNameRow(true);
        if (errEl) errEl.textContent = "name and message required";
        return;
      }
      sendBtn.disabled = true;
      try {
        var res = await fetch("/api/chat", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: name, text: text, vid: visitorId }),
        });
        var data = await res.json().catch(function () {
          return {};
        });
        if (!res.ok) {
          if (errEl) errEl.textContent = data.hint || data.error || "send failed";
          return;
        }
        myName = name;
        try {
          localStorage.setItem(NAME_KEY, name);
        } catch (_) {}
        textEl.value = "";
        autosizeText();
        paintNameRow(false);
        if (data.message) {
          latestId = Math.max(latestId, data.message.id || 0);
        }
        holdScrollCapture = true;
        writeScrollAnchor({ bottom: true, id: lastVisibleId() });
        await poll();
        writeScrollAnchor({ bottom: true, id: lastVisibleId() });
        markSeen();
        paintBadge(0);
        scheduleRestoreScroll({ follow: true });
      } catch (_) {
        if (errEl) errEl.textContent = "network error";
      } finally {
        holdScrollCapture = false;
        sendBtn.disabled = false;
        textEl.focus();
      }
    });

    setFull(full);

    // Restore cached messages immediately so nav doesn't blank the log.
    var cached = loadCache();
    if (cached) applyPayload(cached);

    // Mark first visit after we've already decided startOpen — setting
    // FIRST_KEY first used to flip shouldStartOpen() and slam the panel shut.
    try {
      localStorage.setItem(FIRST_KEY, "1");
    } catch (_) {}
    setOpen(!!startOpen);

    renderIgnored();
    poll();
    setInterval(poll, POLL_MS);
  }

  function mount() {
    var startOpen = shouldStartOpen();
    if (full) panel.classList.add("full");
    if (startOpen) {
      // Appear already open — skip the slide-in on page changes.
      panel.classList.add("boot", "open");
      fab.hidden = true;
      open = true;
      syncOverlay();
      paintExpand();
    }
    document.body.appendChild(scrim);
    document.body.appendChild(fab);
    document.body.appendChild(panel);
    bind(startOpen);
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        panel.classList.remove("boot");
      });
    });
  }

  if (document.body) mount();
  else document.addEventListener("DOMContentLoaded", mount);
})();
