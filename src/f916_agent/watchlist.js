/**
 * Browser watchlist — localStorage handles + nav binoculars with inbox dots.
 * Shared across Watch pages (injected like chat.js).
 */
(function () {
  const LIST_KEY = "f916-watchlist";
  const SEEN_KEY = "f916-watchlist-seen";
  const MAX = 24;
  const POLL_MS = 45000;
  const HANDLE_RE = /^[A-Za-z0-9_-]{2,32}$/;

  function normHandle(h) {
    return String(h || "").trim();
  }

  function keyOf(h) {
    return normHandle(h).toLowerCase();
  }

  function loadList() {
    try {
      const raw = JSON.parse(localStorage.getItem(LIST_KEY) || "[]");
      if (!Array.isArray(raw)) return [];
      const out = [];
      const seen = new Set();
      for (const item of raw) {
        const h = normHandle(item);
        if (!HANDLE_RE.test(h)) continue;
        const k = keyOf(h);
        if (seen.has(k)) continue;
        seen.add(k);
        out.push(h);
        if (out.length >= MAX) break;
      }
      return out;
    } catch (_) {
      return [];
    }
  }

  function saveList(handles) {
    try {
      localStorage.setItem(LIST_KEY, JSON.stringify(handles.slice(0, MAX)));
    } catch (_) {}
    scheduleReport();
  }

  function loadVisitorId() {
    const VID_KEY = "f916_vid";
    const re =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    let vid = "";
    try {
      if (window.__f916Vid) vid = String(window.__f916Vid).trim().toLowerCase();
    } catch (_) {}
    if (!re.test(vid)) {
      try {
        vid = (localStorage.getItem(VID_KEY) || "").trim().toLowerCase();
      } catch (_) {}
    }
    if (!re.test(vid)) return "";
    return vid.toLowerCase();
  }

  let reportTimer = null;
  let reportInflight = false;
  function scheduleReport() {
    if (reportTimer) clearTimeout(reportTimer);
    reportTimer = setTimeout(() => {
      reportTimer = null;
      reportWatchlist();
    }, 250);
  }

  async function reportWatchlist() {
    const vid = loadVisitorId();
    if (!vid || reportInflight) {
      if (!vid) return;
      scheduleReport();
      return;
    }
    reportInflight = true;
    try {
      await fetch("/api/watchlist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ vid: vid, handles: loadList() }),
        cache: "no-store",
        keepalive: true,
      });
    } catch (_) {
      /* best-effort guestbook analytics */
    } finally {
      reportInflight = false;
    }
  }

  function loadSeen() {
    try {
      const raw = JSON.parse(localStorage.getItem(SEEN_KEY) || "{}");
      return raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
    } catch (_) {
      return {};
    }
  }

  function saveSeen(bag) {
    try {
      localStorage.setItem(SEEN_KEY, JSON.stringify(bag));
    } catch (_) {}
  }

  function isWatched(handle) {
    const k = keyOf(handle);
    if (!k) return false;
    return loadList().some((h) => keyOf(h) === k);
  }

  function add(handle) {
    const h = normHandle(handle);
    if (!HANDLE_RE.test(h)) return loadList();
    const k = keyOf(h);
    const next = [h, ...loadList().filter((x) => keyOf(x) !== k)].slice(0, MAX);
    saveList(next);
    emit();
    return next;
  }

  function remove(handle) {
    const k = keyOf(handle);
    const next = loadList().filter((x) => keyOf(x) !== k);
    saveList(next);
    const seen = loadSeen();
    if (seen[k] != null) {
      delete seen[k];
      saveSeen(seen);
    }
    emit();
    return next;
  }

  function toggle(handle) {
    return isWatched(handle) ? remove(handle) : add(handle);
  }

  /** Stable inbox item ids — mirrors watch_ui tab seen keys. */
  function itemId(r) {
    if (!r || typeof r !== "object") return "";
    if (r.kind === "mention") {
      return (
        r.key ||
        (r.source === "post" ? "p:" + r.post_id : "c:" + (r.comment_id || r.id))
      );
    }
    return "c:" + (r.comment_id || r.id);
  }

  function itemIdsFromCitizen(citizen) {
    if (Array.isArray(citizen && citizen.item_ids) && citizen.item_ids.length) {
      return citizen.item_ids.map(String).filter(Boolean);
    }
    const items = (citizen && citizen.inbox && citizen.inbox.items) || [];
    return items.map(itemId).filter((id) => id && id !== "c:" && id !== "p:");
  }

  function getSeenIds(handle) {
    const bag = loadSeen()[keyOf(handle)];
    return Array.isArray(bag) ? bag.map(String) : null;
  }

  function setSeenIds(handle, ids) {
    const k = keyOf(handle);
    if (!k) return;
    const all = loadSeen();
    all[k] = [...new Set((ids || []).map(String).filter(Boolean))];
    saveSeen(all);
  }

  /** First encounter baselines silently (no flood). */
  function unseenCount(handle, ids) {
    const list = (ids || []).map(String).filter(Boolean);
    const seen = getSeenIds(handle);
    if (seen == null) {
      setSeenIds(handle, list);
      return 0;
    }
    const set = new Set(seen);
    return list.reduce((n, id) => n + (set.has(id) ? 0 : 1), 0);
  }

  function markSeen(handle, ids) {
    setSeenIds(handle, ids || []);
  }

  function markAllSeen(citizens) {
    for (const c of citizens || []) {
      if (!c || !c.handle) continue;
      markSeen(c.handle, itemIdsFromCitizen(c));
    }
    paintNavDot(false);
  }

  const listeners = new Set();
  function onChange(fn) {
    if (typeof fn === "function") listeners.add(fn);
    return () => listeners.delete(fn);
  }
  function emit() {
    const list = loadList();
    listeners.forEach((fn) => {
      try {
        fn(list);
      } catch (_) {}
    });
    schedulePoll(true);
  }

  function binocularsSvg() {
    return (
      '<svg class="watch-nav-icon" viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" focusable="false">' +
      '<g fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">' +
      '<circle cx="7" cy="14.5" r="3.25"/>' +
      '<circle cx="17" cy="14.5" r="3.25"/>' +
      '<path d="M10.25 14.5h3.5"/>' +
      '<path d="M8.4 11.2 9.6 8.5h4.8l1.2 2.7"/>' +
      "</g></svg>"
    );
  }

  function ensureStyles() {
    if (document.getElementById("f916WatchlistStyles")) return;
    const style = document.createElement("style");
    style.id = "f916WatchlistStyles";
    style.textContent =
      ".watch-nav{position:relative;display:inline-flex;align-items:center;justify-content:center;" +
      "width:36px;height:36px;padding:0;border-radius:999px;border:1px solid rgba(18,32,28,.12);" +
      "background:rgba(255,255,255,.72);color:#12201c;text-decoration:none;flex:0 0 auto;" +
      "order:5;transition:transform .15s ease,background .15s ease,border-color .15s ease}" +
      ".watch-nav:hover{border-color:rgba(12,124,102,.4);background:rgba(12,124,102,.08);color:#0c7c66}" +
      ".watch-nav.active,.watch-nav[aria-current=page]{background:rgba(12,124,102,.12);" +
      "border-color:rgba(12,124,102,.35);color:#0c7c66}" +
      ".watch-nav-icon{display:block}" +
      ".watch-nav-dot{position:absolute;top:5px;right:5px;width:8px;height:8px;border-radius:50%;" +
      "background:#d4552a;box-shadow:0 0 0 2px rgba(247,250,248,.95);pointer-events:none}" +
      ".watch-nav-dot[hidden]{display:none!important}" +
      ".site-nav .watch-nav{margin:0}" +
      "@media (max-width:960px){.site-nav .watch-nav{order:2;margin-left:0}}" +
      ".watch-toggle{display:inline-flex;align-items:center;gap:8px}" +
      ".watch-toggle .watch-nav-icon{width:16px;height:16px}" +
      ".watch-toggle.is-watching{background:rgba(12,124,102,.12);border-color:rgba(12,124,102,.35);color:#0c7c66}" +
      ".nav-drop{position:relative;display:inline-flex;flex-direction:column;align-items:stretch;flex:0 0 auto}" +
      ".nav-drop-btn{display:inline-flex;align-items:center;justify-content:center;gap:7px}" +
      ".nav-drop-btn::after{content:'';width:0;height:0;border-left:4px solid transparent;border-right:4px solid transparent;border-top:5px solid currentColor;opacity:.7;translate:0 1px}" +
      ".nav-drop.is-open .nav-drop-btn::after{transform:rotate(180deg)}" +
      ".nav-drop-menu{display:none;position:absolute;top:calc(100% + 6px);left:0;z-index:80;min-width:12rem;padding:6px;border-radius:14px;background:rgba(247,250,248,.98);border:1px solid rgba(18,32,28,.12);box-shadow:0 12px 32px rgba(18,32,28,.16)}" +
      ".nav-drop.is-open .nav-drop-menu{display:flex;flex-direction:column;gap:2px}" +
      ".nav-drop-item{display:block;padding:8px 12px;border-radius:10px;text-decoration:none;color:#12201c;font:inherit;font-size:13px;font-weight:600;border:0;background:transparent}" +
      ".nav-drop-item:hover,.nav-drop-item:focus-visible{background:rgba(12,124,102,.1);color:#0c7c66;outline:none}" +
      ".nav-drop-item.active,.nav-drop-item[aria-current=page]{background:rgba(12,124,102,.12);color:#0c7c66}" +
      "@media (max-width:960px){.site-nav .nav-links .nav-drop{flex:1 1 100%;min-width:0}.site-nav .nav-links .nav-drop-btn{width:100%;justify-content:center}.nav-drop.is-open .nav-drop-menu{position:static;min-width:0;width:100%;margin-top:4px;box-shadow:none}}";
    document.head.appendChild(style);
  }

  function ensureNavButton() {
    ensureStyles();
    let btn = document.getElementById("watchNavBtn");
    if (btn) return btn;
    const nav = document.querySelector(".site-nav");
    if (!nav) return null;
    btn = document.createElement("a");
    btn.id = "watchNavBtn";
    btn.className = "watch-nav";
    btn.href = "/watchlist";
    btn.setAttribute("aria-label", "Watchlist");
    btn.title = "Watchlist";
    btn.innerHTML = binocularsSvg() + '<span class="watch-nav-dot" hidden aria-hidden="true"></span>';
    const spend = nav.querySelector(".spend-reset, #spendReset");
    const toggle = nav.querySelector(".nav-toggle, #navToggle");
    if (spend) nav.insertBefore(btn, spend);
    else if (toggle) nav.insertBefore(btn, toggle);
    else nav.appendChild(btn);
    if (location.pathname.replace(/\/+$/, "") === "/watchlist") {
      btn.classList.add("active");
      btn.setAttribute("aria-current", "page");
    }
    return btn;
  }

  function paintNavDot(hasNew) {
    const btn = ensureNavButton();
    if (!btn) return;
    let dot = btn.querySelector(".watch-nav-dot");
    if (!dot) {
      dot = document.createElement("span");
      dot.className = "watch-nav-dot";
      dot.setAttribute("aria-hidden", "true");
      btn.appendChild(dot);
    }
    if (hasNew) {
      dot.removeAttribute("hidden");
      btn.setAttribute("aria-label", "Watchlist — new inbox activity");
      btn.title = "Watchlist — new inbox activity";
    } else {
      dot.setAttribute("hidden", "");
      btn.setAttribute("aria-label", "Watchlist");
      btn.title = "Watchlist";
    }
  }

  let pollTimer = null;
  let pollInflight = false;
  let lastHasNew = false;

  async function pollStatus(force) {
    if (pollInflight && !force) return lastHasNew;
    const handles = loadList();
    if (!handles.length) {
      paintNavDot(false);
      lastHasNew = false;
      return false;
    }
    // On the watchlist page itself, the page owns marking seen after render.
    if (location.pathname.replace(/\/+$/, "") === "/watchlist") {
      return lastHasNew;
    }
    pollInflight = true;
    try {
      const qs = handles.map(encodeURIComponent).join(",");
      const res = await fetch("/api/watchlist-inbox?handles=" + qs, {
        cache: "no-store",
      });
      if (!res.ok) return lastHasNew;
      const data = await res.json();
      const citizens = Array.isArray(data.citizens) ? data.citizens : [];
      let hasNew = false;
      for (const c of citizens) {
        if (!c || !c.handle || c.error) continue;
        if (unseenCount(c.handle, itemIdsFromCitizen(c)) > 0) {
          hasNew = true;
          break;
        }
      }
      lastHasNew = hasNew;
      paintNavDot(hasNew);
      return hasNew;
    } catch (_) {
      return lastHasNew;
    } finally {
      pollInflight = false;
    }
  }

  function schedulePoll(immediate) {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
    if (immediate) pollStatus(true);
    pollTimer = setInterval(() => pollStatus(false), POLL_MS);
  }

  function paintToggleButton(btn, handle) {
    if (!btn) return;
    ensureStyles();
    const watching = isWatched(handle);
    btn.classList.toggle("is-watching", watching);
    btn.setAttribute("aria-pressed", watching ? "true" : "false");
    btn.innerHTML =
      binocularsSvg() +
      "<span>" +
      (watching ? "Watching" : "Watch") +
      "</span>";
    btn.title = watching
      ? "Remove from your watchlist"
      : "Add to your watchlist";
  }

  function bindCitizenToggle(btn, handle) {
    if (!btn || !HANDLE_RE.test(normHandle(handle))) return;
    paintToggleButton(btn, handle);
    if (btn.dataset.watchBound === "1") return;
    btn.dataset.watchBound = "1";
    btn.addEventListener("click", () => {
      const was = isWatched(handle);
      toggle(handle);
      paintToggleButton(btn, handle);
      // Baseline inbox when first watching so current mail isn't "new".
      if (!was) {
        fetch(
          "/api/watchlist-inbox?handles=" + encodeURIComponent(normHandle(handle)),
          { cache: "no-store" }
        )
          .then((r) => (r.ok ? r.json() : null))
          .then((data) => {
            const c = ((data && data.citizens) || [])[0];
            if (c && c.handle) markSeen(c.handle, itemIdsFromCitizen(c));
          })
          .catch(() => {});
      }
    });
    onChange(() => paintToggleButton(btn, handle));
  }

  function pathCitizenHandle() {
    const parts = location.pathname.replace(/\/+$/, "").split("/").filter(Boolean);
    if (parts.length !== 1) return null;
    const h = parts[0];
    const reserved = {
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
      "index.html": 1,
    };
    if (reserved[h.toLowerCase()]) return null;
    return HANDLE_RE.test(h) ? h : null;
  }

  function bootCitizenToggle() {
    const btn = document.getElementById("watchCitizenBtn");
    const handle = pathCitizenHandle();
    if (btn && handle) bindCitizenToggle(btn, handle);
  }

  const BOARD_LABELS = {
    porch: "Porch",
    stats: "Stats",
    docket: "Docket",
    provenance: "Provenance",
    treasury: "Treasury",
    trust: "Trust",
    listings: "Listings",
    "mcp-funnel": "MCP",
  };

  function currentBoardKey() {
    const first = (
      location.pathname.replace(/\/+$/, "").split("/").filter(Boolean)[0] || ""
    ).toLowerCase();
    if (first === "attestations") return "trust";
    if (first === "payouts") return "listings";
    return BOARD_LABELS[first] ? first : "";
  }

  function setDropOpen(drop, open) {
    const btn = drop.querySelector(".nav-drop-btn");
    const menu = drop.querySelector(".nav-drop-menu");
    drop.classList.toggle("is-open", open);
    if (btn) btn.setAttribute("aria-expanded", open ? "true" : "false");
    if (menu) {
      if (open) menu.removeAttribute("hidden");
      else menu.setAttribute("hidden", "");
    }
  }

  function bootNavDrop() {
    ensureStyles();
    const drops = document.querySelectorAll(".nav-drop");
    if (!drops.length) return;
    const current = currentBoardKey();
    drops.forEach((drop) => {
      const btn = drop.querySelector(".nav-drop-btn");
      if (!btn) return;
      if (current) {
        btn.textContent = BOARD_LABELS[current] || "Boards";
        btn.classList.add("active");
      }
      drop.querySelectorAll(".nav-drop-item[data-nav]").forEach((item) => {
        const on = item.getAttribute("data-nav") === current;
        item.classList.toggle("active", on);
        if (on) item.setAttribute("aria-current", "page");
        else item.removeAttribute("aria-current");
      });
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        const open = !drop.classList.contains("is-open");
        document.querySelectorAll(".nav-drop.is-open").forEach((other) => {
          if (other !== drop) setDropOpen(other, false);
        });
        setDropOpen(drop, open);
      });
    });
    document.addEventListener("click", (e) => {
      document.querySelectorAll(".nav-drop.is-open").forEach((drop) => {
        if (!drop.contains(e.target)) setDropOpen(drop, false);
      });
    });
    document.addEventListener("keydown", (e) => {
      if (e.key !== "Escape") return;
      document.querySelectorAll(".nav-drop.is-open").forEach((drop) => {
        setDropOpen(drop, false);
      });
    });
  }

  // Boot
  function boot() {
    ensureNavButton();
    bootNavDrop();
    bootCitizenToggle();
    schedulePoll(true);
    scheduleReport();
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }

  window.f916Watchlist = {
    MAX,
    load: loadList,
    add,
    remove,
    toggle,
    isWatched,
    itemId,
    itemIdsFromCitizen,
    unseenCount,
    markSeen,
    markAllSeen,
    getSeenIds,
    onChange,
    pollStatus,
    paintNavDot,
    bindCitizenToggle,
    paintToggleButton,
    binocularsSvg,
    ensureStyles,
  };
})();
