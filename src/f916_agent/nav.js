/**
 * Page-switch loading indicator.
 * A same-origin link click paints a bar and a "Loading…" chip on the
 * current page immediately, and the next page keeps the bar (plus skeleton
 * rows) until its board text leaves the loading state. Inline, not deferred,
 * so the chip exists before the first paint of a slow document.
 */
(function () {
  if (window.__f916Nav) return;
  window.__f916Nav = 1;

  var navigating = false;
  var PENDING = /^(loading|warming|connecting|gathering|searching|fetching)(\b|…|\.\.\.)/i;

  function norm(el) {
    return ((el && el.textContent) || "").replace(/\s+/g, " ").trim();
  }

  function isPendingText(el) {
    var t = norm(el);
    if (!t || t.length > 80) return false;
    if (PENDING.test(t)) return true;
    if (/^assets loading/i.test(t)) return true;
    if (/^loading treasury/i.test(t)) return true;
    return false;
  }

  function errorShowing() {
    var err = document.getElementById("error");
    if (!err || err.hidden || err.classList.contains("hidden")) return false;
    return norm(err).length > 0;
  }

  function contentPending() {
    if (!document.body || errorShowing()) return false;
    if (
      document.body.classList.contains("is-loading") &&
      !document.body.classList.contains("is-refreshing") &&
      !document.body.classList.contains("is-settled")
    ) {
      return true;
    }
    var ids = ["boardMeta", "bucketsNote", "assetsNote", "body"];
    for (var i = 0; i < ids.length; i++) {
      if (isPendingText(document.getElementById(ids[i]))) return true;
    }
    return false;
  }

  function hasOwnSkeleton() {
    return !!(
      document.querySelector(".skel-status, .skel-row") ||
      (document.body && document.body.classList.contains("is-loading"))
    );
  }

  function ensure() {
    if (document.getElementById("f916NavStyle")) return;
    var style = document.createElement("style");
    style.id = "f916NavStyle";
    style.textContent =
      ".f916-nav-progress{position:fixed;top:0;left:0;right:0;height:3px;z-index:200;pointer-events:none;overflow:hidden;background:rgba(12,124,102,.18)}" +
      ".f916-nav-progress[hidden]{display:none!important}" +
      ".f916-nav-progress-bar{height:100%;width:34%;background:#0c7c66;animation:f916-nav-slide 1.05s ease-in-out infinite}" +
      "@keyframes f916-nav-slide{0%{transform:translateX(-120%)}100%{transform:translateX(380%)}}" +
      ".f916-nav-live{position:fixed;top:max(12px,env(safe-area-inset-top));left:50%;transform:translateX(-50%);z-index:200;pointer-events:none;display:flex;align-items:center;gap:8px;padding:7px 12px;border-radius:999px;background:rgba(247,250,248,.97);border:1px solid rgba(12,124,102,.32);box-shadow:0 8px 24px rgba(18,32,28,.14);color:#0c7c66;font:600 13px/1.2 \"DM Sans\",system-ui,sans-serif}" +
      ".f916-nav-live:empty{display:none!important}" +
      ".f916-nav-live::before{content:\"\";width:7px;height:7px;border-radius:50%;background:#0c7c66;box-shadow:0 0 0 0 rgba(12,124,102,.45);animation:f916-nav-ping 1.4s ease-out infinite;flex:0 0 auto}" +
      "@keyframes f916-nav-ping{0%{box-shadow:0 0 0 0 rgba(12,124,102,.45)}70%{box-shadow:0 0 0 7px rgba(12,124,102,0)}100%{box-shadow:0 0 0 0 rgba(12,124,102,0)}}" +
      "html.is-navigating,html.is-navigating body{cursor:progress}" +
      "a.is-nav-pending{opacity:.72}" +
      "#boardMeta.is-pending,#bucketsNote.is-pending,#assetsNote.is-pending{display:flex;align-items:center;gap:8px;font-weight:650;color:#0c7c66}" +
      "#boardMeta.is-pending::before,#bucketsNote.is-pending::before,#assetsNote.is-pending::before{content:\"\";width:7px;height:7px;border-radius:50%;background:#0c7c66;animation:f916-nav-ping 1.4s ease-out infinite;flex:0 0 auto}" +
      ".f916-skel{display:flex;flex-direction:column;gap:10px;margin:8px 0 16px}" +
      ".f916-skel>span{display:block;height:72px;border-radius:14px;border:1px solid rgba(18,32,28,.06);background:linear-gradient(105deg,rgba(18,32,28,.06) 0%,rgba(18,32,28,.06) 38%,rgba(255,255,255,.72) 50%,rgba(18,32,28,.06) 62%,rgba(18,32,28,.06) 100%);background-size:220% 100%;animation:f916-nav-shimmer 1.55s ease-in-out infinite}" +
      "@keyframes f916-nav-shimmer{0%{background-position:100% 0}100%{background-position:-100% 0}}" +
      "@media (prefers-reduced-motion:reduce){.f916-nav-progress-bar,.f916-nav-live::before,#boardMeta.is-pending::before,#bucketsNote.is-pending::before,#assetsNote.is-pending::before,.f916-skel>span{animation:none}.f916-nav-progress-bar{width:100%;opacity:.85}}";
    (document.head || document.documentElement).appendChild(style);

    var bar = document.createElement("div");
    bar.id = "f916NavProgress";
    bar.className = "f916-nav-progress";
    bar.hidden = true;
    bar.setAttribute("role", "progressbar");
    bar.setAttribute("aria-valuemin", "0");
    bar.setAttribute("aria-valuemax", "100");
    bar.setAttribute("aria-label", "Loading");
    bar.setAttribute("aria-hidden", "true");
    bar.innerHTML = '<div class="f916-nav-progress-bar"></div>';

    var live = document.createElement("div");
    live.id = "f916NavLive";
    live.className = "f916-nav-live";
    live.setAttribute("role", "status");
    live.setAttribute("aria-live", "polite");
    document.body.appendChild(bar);
    document.body.appendChild(live);
  }

  function show(chip) {
    ensure();
    var bar = document.getElementById("f916NavProgress");
    bar.hidden = false;
    bar.removeAttribute("aria-hidden");
    bar.setAttribute("aria-valuetext", "Loading");
    document.documentElement.classList.add("is-navigating");
    document.documentElement.setAttribute("aria-busy", "true");
    var live = document.getElementById("f916NavLive");
    var next = chip ? "Loading…" : "";
    if (live.textContent !== next) live.textContent = next;
  }

  function hide() {
    var bar = document.getElementById("f916NavProgress");
    if (bar) {
      bar.hidden = true;
      bar.setAttribute("aria-hidden", "true");
    }
    var live = document.getElementById("f916NavLive");
    if (live) live.textContent = "";
    document.documentElement.classList.remove("is-navigating");
    document.documentElement.removeAttribute("aria-busy");
    document.querySelectorAll("a.is-nav-pending").forEach(function (a) {
      a.classList.remove("is-nav-pending");
      a.removeAttribute("aria-busy");
    });
  }

  var SKEL =
    '<div class="f916-skel" data-f916-skel="1" aria-hidden="true"><span></span><span></span><span></span></div>';

  function markBusy(el) {
    if (!el || el.getAttribute("data-f916-busy") === "1") return;
    el.setAttribute("aria-busy", "true");
    el.setAttribute("data-f916-busy", "1");
  }

  function ensureSkel(el) {
    if (!el || el.querySelector("[data-f916-skel]")) return;
    if (el.querySelector("article, .row, .sec, table, pre")) return;
    el.insertAdjacentHTML("beforeend", SKEL);
    markBusy(el);
  }

  function paintPlaceholders() {
    if (hasOwnSkeleton()) return;
    var meta = document.getElementById("boardMeta");
    if (meta && isPendingText(meta)) meta.classList.add("is-pending");
    ["bucketsNote", "assetsNote"].forEach(function (id) {
      var el = document.getElementById(id);
      if (el && isPendingText(el)) el.classList.add("is-pending");
    });
    if (meta && isPendingText(meta)) {
      ensureSkel(document.getElementById("boardList"));
      [
        "checkpointList",
        "identityList",
        "anchorList",
        "witnessList",
        "legacyList",
        "attestList",
      ].forEach(function (id) {
        ensureSkel(document.getElementById(id));
      });
      var body = document.getElementById("body");
      if (body && (isPendingText(body) || !norm(body))) ensureSkel(body);
      var holdings = document.getElementById("holdingsPane");
      if (holdings && norm(holdings) === "—") ensureSkel(holdings);
    }
    var lone = document.getElementById("body");
    if (lone && isPendingText(lone)) ensureSkel(lone);
    var buckets = document.getElementById("bucketsNote");
    if (buckets && isPendingText(buckets)) {
      var pane = document.getElementById("holdingsPane");
      if (pane && norm(pane) === "—") ensureSkel(pane);
    }
  }

  function clearPlaceholders() {
    document.querySelectorAll("[data-f916-skel]").forEach(function (el) {
      el.remove();
    });
    document.querySelectorAll("[data-f916-busy]").forEach(function (el) {
      el.removeAttribute("aria-busy");
      el.removeAttribute("data-f916-busy");
    });
    document.querySelectorAll(".is-pending").forEach(function (el) {
      el.classList.remove("is-pending");
    });
  }

  function sync() {
    if (!document.body) return;
    var pending = contentPending();
    if (!navigating && !pending) {
      clearPlaceholders();
      hide();
      return;
    }
    if (pending) paintPlaceholders();
    // Chip only for the gap after a click, while this document is still
    // showing. Skeleton rows carry the wait once the next page has painted.
    show(navigating);
  }

  function armableAnchor(event) {
    if (event.defaultPrevented || event.button !== 0) return null;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return null;
    var node = event.target;
    if (!node || !node.closest) return null;
    var a = node.closest("a[href]");
    if (!a || a.hasAttribute("download")) return null;
    var target = (a.getAttribute("target") || "").trim().toLowerCase();
    if (target && target !== "_self") return null;
    var raw = a.getAttribute("href") || "";
    if (!raw || raw.charAt(0) === "#") return null;
    var url;
    try {
      url = new URL(a.href, location.href);
    } catch (e) {
      return null;
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    if (url.origin !== location.origin) return null;
    if (url.pathname === location.pathname && url.search === location.search) return null;
    return a;
  }

  function arm(anchor) {
    navigating = true;
    if (anchor) {
      anchor.classList.add("is-nav-pending");
      anchor.setAttribute("aria-busy", "true");
    }
    sync();
  }

  document.addEventListener("click", function (event) {
    var a = armableAnchor(event);
    if (!a) return;
    arm(a);
  });

  document.addEventListener("submit", function (event) {
    if (event.defaultPrevented) return;
    var form = event.target;
    if (!form || !form.getAttribute) return;
    if (form.tagName !== "FORM") return;
    var target = (form.getAttribute("target") || "").trim().toLowerCase();
    if (target && target !== "_self") return;
    var url;
    try {
      url = new URL(form.getAttribute("action") || ".", location.href);
    } catch (e) {
      return;
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") return;
    if (url.origin !== location.origin) return;
    arm(null);
  });

  window.addEventListener("pageshow", function (event) {
    if (!event.persisted) return;
    navigating = false;
    sync();
  });

  if (window.navigation && window.navigation.addEventListener) {
    window.navigation.addEventListener("navigateerror", function () {
      navigating = false;
      sync();
    });
  }

  function watch(el, opts) {
    if (!el) return;
    var obs = new MutationObserver(function () {
      sync();
    });
    obs.observe(el, opts);
  }

  sync();
  if (document.body) {
    watch(document.body, { attributes: true, attributeFilter: ["class"] });
    ["boardMeta", "bucketsNote", "assetsNote", "body", "error"].forEach(function (id) {
      watch(document.getElementById(id), {
        childList: true,
        characterData: true,
        subtree: true,
        attributes: true,
        attributeFilter: ["hidden", "class"],
      });
    });
  }
})();
