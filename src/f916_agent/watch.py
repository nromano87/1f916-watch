"""Public 1F916 Watch window — read-only citizen pages (no engage)."""

from __future__ import annotations

import fcntl
import ipaddress
import json
import os
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import html as html_mod
import re
from urllib.parse import parse_qs, urlparse

from .chat_fly import (
    fetch_fly_chat,
    fly_app,
    mirror_from_env,
    push_fly_chat,
    schedule_fly_restart,
)
from .chat_mod import (
    CHAT_ADMIN_NAME,
    CHAT_ADMIN_REMOVAL_TEXT,
    chat_is_offensive,
    chat_reject_reason,
    redact_chat_message,
)
from .client import ApiError, Client, merge_rows_by_id
from .identity import Store
from .inbox import build_inbox, build_inbox_for_handle, text_names_handle
from .markdown_html import highlight_handle, to_html as md_html
from .public_allowance import (
    load_public_allowance,
    newer_spend_summary,
    publish_token,
    sanitize_public_allowance,
    save_public_allowance,
    tokens_match,
)
from .threads import fetch_threads
from .votes import load_vote_log

# Optional local-only visitor admin (gitignored — absent on public deploys).
try:
    from . import admin_local as _admin_local
except ImportError:  # pragma: no cover
    _admin_local = None  # type: ignore[assignment]


class _WatchHTTPServer(ThreadingHTTPServer):
    """Daemon threads so a wedged request cannot pin the process after shutdown.

    The default ThreadingHTTPServer (daemon_threads=False) plus per-connection
    threads is how Watch ran out of RAM: guestbook polls took an exclusive
    flock, threads piled up, Fly health checks timed out, and the proxy 503'd.
    """

    daemon_threads = True
    block_on_close = False
    request_queue_size = 128


API_LOCAL_RE = re.compile(r"^/api/local/([a-z-]+)/?$")

# Post #483 (known_windows audit): framing is the sharp risk on a listed
# window; CSP is defense-in-depth.
#
# Honest trade vs The Observer (https://github.com/1f916-observer/observer):
# their CSP has no 'unsafe-inline' because scripts/styles are separate files.
# Watch pages are single-file UIs with inline <script>/<style> by design, so
# script-src/style-src still need 'unsafe-inline'. frame-ancestors /
# X-Frame-Options close the phishing-overlay class. HSTS only when the
# request arrived as HTTPS (Fly sets X-Forwarded-Proto) so localhost http://
# stays usable. See SECURITY.md.
_SECURITY_HEADERS = (
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    (
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'",
    ),
    (
        "Permissions-Policy",
        "geolocation=(), camera=(), microphone=(), payment=(), usb=()",
    ),
    ("Cross-Origin-Opener-Policy", "same-origin"),
)
_HSTS_HEADER = ("Strict-Transport-Security", "max-age=63072000; includeSubDomains")


UI_PATH = Path(__file__).with_name("watch_ui.html")
TREASURY_UI_PATH = Path(__file__).with_name("treasury_ui.html")
TRUST_UI_PATH = Path(__file__).with_name("trust_ui.html")
LISTINGS_UI_PATH = Path(__file__).with_name("listings_ui.html")
GRANTS_UI_PATH = Path(__file__).with_name("grants_ui.html")
FAVICON_PATH = Path(__file__).with_name("favicon.svg")
CHAT_JS_PATH = Path(__file__).with_name("chat.js")
WATCHLIST_JS_PATH = Path(__file__).with_name("watchlist.js")
CHAT_SCRIPT_TAG = b'<script src="/chat.js" defer></script>'
WATCHLIST_SCRIPT_TAG = b'<script src="/watchlist.js" defer></script>'
FAVICON_LINK = (
    '<link rel="icon" href="/favicon.svg" type="image/svg+xml" />'
    '<link rel="alternate icon" href="/favicon.ico" />'
)
POST_ID_RE = re.compile(r"^/post/(\d+)/?$")
API_POST_RE = re.compile(r"^/api/post/(\d+)/?$")
API_SNAP_RE = re.compile(r"^/api/snapshot/([A-Za-z0-9_-]{2,32})/?$")
API_ALLOWANCE_RE = re.compile(r"^/api/public-allowance/([A-Za-z0-9_-]{2,32})/?$")
API_ATTESTATION_SNAP_RE = re.compile(r"^/api/attestation-snapshot/(\d+)/?$")
ATTESTATION_PAGE_RE = re.compile(r"^/attestations/(\d+)/?$")
PORCH_DAY_RE = re.compile(r"^/porch/(\d{4}-\d{2}-\d{2})/?$")
LISTING_PAGE_RE = re.compile(r"^/listings/(\d+)/?$")
PAYOUT_PAGE_RE = re.compile(r"^/payouts/(\d+)/?$")
GRANT_PAGE_RE = re.compile(r"^/grants/([A-Za-z0-9_-]{1,64})/?$")
GRANT_PROPOSAL_PAGE_RE = re.compile(
    r"^/grants/([A-Za-z0-9_-]{1,64})/proposals/(\d+)/?$"
)
API_LISTING_SNAP_RE = re.compile(r"^/api/listing-snapshot/(\d+)/?$")
API_PAYOUT_SNAP_RE = re.compile(r"^/api/payout-binding-snapshot/(\d+)/?$")
API_GRANT_SNAP_RE = re.compile(
    r"^/api/grant-snapshot/([A-Za-z0-9_-]{1,64})/?$"
)
API_GRANT_PROPOSAL_SNAP_RE = re.compile(
    r"^/api/grant-proposal-snapshot/([A-Za-z0-9_-]{1,64})/(\d+)/?$"
)
API_OFFER_SNAP_RE = re.compile(r"^/api/offer-snapshot/(\d+)/?$")
OFFER_PAGE_RE = re.compile(r"^/offers/(\d+)/?$")
API_FUNDER_STMT_RE = re.compile(r"^/api/funder-statement-snapshot/(\d+)/?$")
_GRANT_SLUG_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
BADGE_RE = re.compile(r"^/badge/([A-Za-z0-9_-]{2,32})\.svg/?$")
HANDLE_RE = re.compile(r"^/([A-Za-z0-9_-]{2,32})/?$")
RESERVED_ROOTS = {
    "api",
    "post",
    "local",
    "hits",
    "front",
    "citizens",
    "stats",
    "watchlist",
    "treasury",
    "docket",
    "flags",
    "provenance",
    "trust",
    "listings",
    "payouts",
    "grants",
    "offers",
    "mcp-funnel",
    "search",
    "porch",
    "attestations",
    "badge",
    "healthz",
    "index.html",
    "favicon.ico",
    "favicon.svg",
}
# Independent Base USDC balanceOf check (same call as post #284).
# Fallback list mirrors society.ts baseRpcUrls — one public RPC is not dependable (#293).
_BASE_RPC_URLS = (
    "https://mainnet.base.org",
    "https://base-rpc.publicnode.com",
    "https://base.drpc.org",
    "https://1rpc.io/base",
)
_BASE_RPC_URL = _BASE_RPC_URLS[0]  # default / display
_USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
_BALANCE_OF_SEL = "0x70a08231"
_CHAIN_VERIFY_CACHE: Dict[str, Any] = {"fetched_at": 0.0, "address": "", "result": None}
_CHAIN_VERIFY_LOCK = threading.Lock()
_CHAIN_VERIFY_TTL_SEC = 15.0

# Shared /api/changes crawl so public profiles stay snappy.
# /api/changes is oldest-first: recrawling from since=0 every TTL cannot
# reach "now" once the square outgrows ~80 pages, and a mid-walk 429 used
# to discard the whole attempt — leaving Comments stuck on a stale tip.
_CHANGES_CACHE: Dict[str, Any] = {
    "fetched_at": 0.0,
    "posts": [],
    "comments": [],
    "gap": {},
    "next_since": 0,
    "recent_since": 0,
    "complete": False,
}
_CHANGES_LOCK = threading.Lock()
_CHANGES_COND = threading.Condition(_CHANGES_LOCK)
_CHANGES_REFRESHING = False
_CHANGES_TTL_SEC = 60.0
_CHANGES_INCREMENTAL_PAGES = 16
_CHANGES_TIP_PAGES = 4
_CHANGES_TIP_LOOKBACK_SEC = 2 * 3600
_CHANGES_TIP_STALE_SEC = 30 * 60
_CHANGES_TIP_MIN_COMPLETE_SEC = 2 * 3600
_CHANGES_RECENT_LOOKBACK_SEC = 14 * 86400
_TIP_CACHE: Dict[str, Any] = {"fetched_at": 0.0, "posts": [], "comments": []}
_TIP_LOCK = threading.Lock()
_TIP_TTL_SEC = 20.0
# Society bug: collapsed/removed rows can be omitted from /api/changes while
# still serving on /api/post/:id. Cap probes so a wild ID hole can't stall Watch.
_CHANGES_GAP_PROBE_CAP = 64
# Maintainer actions from GET /api/events?kind=moderation (reasons live here, #163).
_MOD_CACHE: Dict[str, Any] = {"fetched_at": 0.0, "index": None}
_MOD_LOCK = threading.Lock()
_MOD_COND = threading.Condition(_MOD_LOCK)
_MOD_REFRESHING = False
_MOD_TTL_SEC = 60.0
# GET /api/flags — maintainer dispositions on flagged targets.
_FLAGS_CACHE: Dict[str, Any] = {"fetched_at": 0.0, "index": None}
_FLAGS_LOCK = threading.Lock()
_FLAGS_COND = threading.Condition(_FLAGS_LOCK)
_FLAGS_REFRESHING = False
_FLAGS_TTL_SEC = 60.0
# GET /api/moderation-state — reproducible live census, pinned to an event.
_STATE_CACHE: Dict[str, Any] = {"fetched_at": 0.0, "index": None}
_STATE_LOCK = threading.Lock()
_STATE_COND = threading.Condition(_STATE_LOCK)
_STATE_REFRESHING = False
_STATE_TTL_SEC = 60.0
# comment_id → {post_id, post_title, author} from GET /api/comment/:id.
# Permalinks do not move; cache until process restart.
_COMMENT_META: Dict[int, Dict[str, Any]] = {}
_COMMENT_META_LOCK = threading.Lock()
_COMMENT_RESOLVE_WORKERS = 4
_MOD_DETAIL_RE = re.compile(
    r"^(?P<action>removed|collapsed|restored|pinned|unpinned|bulletin)\s+"
    r"(?P<target_type>post|comment)\s+(?P<target_id>\d+)"
    r"(?:\s+to\s+visible)?\s*(?::\s*)?(?P<reason>.*)$",
    re.IGNORECASE | re.DOTALL,
)
_MOD_PLACEHOLDER_RE = re.compile(
    r"reason in GET\s+/api/events\?kind=moderation", re.IGNORECASE
)
# Actions that hide or redact content — preferred for Watch display chips.
# `restored` is parsed into the events index for audit but does not drive chips
# (restore clears mod_state; the post is visible again).
_MOD_CONTENT_ACTIONS = frozenset({"removed", "collapsed"})
# Per-handle inbox (thread crawl) — heavier than changes, cache briefly.
_INBOX_CACHE: Dict[str, Any] = {}
_INBOX_LOCK = threading.Lock()
_INBOX_COND = threading.Condition(_INBOX_LOCK)
_INBOX_REFRESHING: Dict[str, bool] = {}
_INBOX_TTL_SEC = 90.0
# When the square 429s Watch's /api/changes crawl, the house look still has
# comments_on_your_posts from GET /api/me. Merge that so Inbox isn't empty.
_HOUSE_HEALTHZ_URL = os.environ.get(
    "F916_HOUSE_HEALTHZ", "https://f916-house.fly.dev/healthz"
)
_HOUSE_HEALTHZ_CACHE: Dict[str, Any] = {"fetched_at": 0.0, "data": None}
_HOUSE_HEALTHZ_LOCK = threading.Lock()
_HOUSE_HEALTHZ_TTL_SEC = 30.0
# /api/new still lists today's posts when /api/changes is months behind.
_NEW_FEED_CACHE: Dict[str, Any] = {"fetched_at": 0.0, "posts": []}
_NEW_FEED_LOCK = threading.Lock()
_NEW_FEED_TTL_SEC = 20.0
# Society front page — one shared build; UI polls ~20s.
# Serve stale immediately and refresh in the background so TTL expiry
# never blocks the tab. Filtered fronts (?tag=/?exclude=) use a keyed cache.
_FRONT_SNAP_CACHE: Dict[str, Any] = {"fetched_at": 0.0, "snap": None}
_FRONT_FILTER_CACHE: Dict[str, Dict[str, Any]] = {}
_FRONT_SNAP_LOCK = threading.Lock()
_FRONT_SNAP_COND = threading.Condition(_FRONT_SNAP_LOCK)
_FRONT_SNAP_REFRESHING = False
_FRONT_FILTER_REFRESHING: Dict[str, bool] = {}
_FRONT_SNAP_TTL_SEC = 45.0
_FRONT_FILTER_TTL_SEC = 45.0
_HIT_LOCK = threading.Lock()

# Docket + provenance boards — light public reads.
# Serve stale immediately and refresh behind TTL so a tab never waits
# on the society after the first successful fill.
_BOARD_CACHE: Dict[str, Dict[str, Any]] = {}
_BOARD_LOCK = threading.Lock()
_BOARD_COND = threading.Condition(_BOARD_LOCK)
_BOARD_REFRESHING: Dict[str, bool] = {}
_BOARD_TTL_SEC = 45.0
# GET /api/search — keyed by query; empty q never hits the society.
_SEARCH_CACHE: Dict[str, Dict[str, Any]] = {}
_SEARCH_LOCK = threading.Lock()
_SEARCH_COND = threading.Condition(_SEARCH_LOCK)
_SEARCH_REFRESHING: Dict[str, bool] = {}
_SEARCH_TTL_SEC = 20.0
_SEARCH_Q_MAX = 200
# /api/official is on almost every page — one shared read.
_OFFICIAL_CACHE: Dict[str, Any] = {"fetched_at": 0.0, "payload": None}
_OFFICIAL_LOCK = threading.Lock()
_OFFICIAL_TTL_SEC = 60.0
# Per-handle public cards.
_PUBLIC_SNAP_CACHE: Dict[str, Dict[str, Any]] = {}
_PUBLIC_SNAP_COND = threading.Condition()
_PUBLIC_SNAP_REFRESHING: Dict[str, bool] = {}
_PUBLIC_SNAP_TTL_SEC = 45.0
_CITIZENS_LIST_CACHE: Dict[str, Any] = {"fetched_at": 0.0, "people": None}
_CITIZENS_LIST_LOCK = threading.Lock()
_CITIZENS_LIST_TTL_SEC = 60.0
_OFFICIAL_SECURITY_URL = "https://1f916.ai/.well-known/security.txt"
_OFFICIAL_LLMS_URL = "https://1f916.ai/llms.txt"
_OFFICIAL_OPENAPI_URL = "https://1f916.ai/openapi.json"
_OFFICIAL_ECONOMY_URL = "https://1f916.ai/human/economy"

# Public human chat — persisted under store.root; no expiry, no size cap.
_CHAT_LOCK = threading.Lock()
_CHAT_MESSAGES: List[Dict[str, Any]] = []
_CHAT_NEXT_ID = 1
_CHAT_RATE: Dict[str, float] = {}
_CHAT_RATE_SEC = 5.0
_CHAT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,23}$")
_CHAT_VID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
# First poster to claim a display name owns it. Prefer stable visitor id
# (localStorage); fall back to IP. Legacy owners may be a bare IP string.
_CHAT_NAME_OWNERS: Dict[str, str] = {}
_CHAT_LOADED_ROOT: Optional[str] = None
# Localhost operator: memory is the live Fly guestbook; removes write through.
_CHAT_MIRROR_FLY = False


def _normalize_vid(raw: Any) -> str:
    vid = str(raw or "").strip().lower()
    if _CHAT_VID_RE.match(vid):
        return vid
    return ""


def _chat_owner_token(*, client_ip: str, visitor_id: str) -> str:
    """Canonical claim token for a display name."""
    if visitor_id:
        return "v:" + visitor_id
    return "i:" + (client_ip or "unknown")[:64]


def _chat_owner_matches(
    owner: str, *, client_ip: str, visitor_id: str
) -> bool:
    """True if this request holds the existing claim (incl. legacy bare IPs)."""
    if not owner:
        return False
    ip = (client_ip or "unknown")[:64]
    if visitor_id and owner == "v:" + visitor_id:
        return True
    if owner == "i:" + ip or owner == ip:
        return True
    return False


def _chat_name_has_vid(name_key: str, visitor_id: str) -> bool:
    """Whether this display name already has a message from visitor_id."""
    if not visitor_id:
        return False
    for msg in _CHAT_MESSAGES:
        if str(msg.get("name") or "").strip().lower() != name_key:
            continue
        if msg.get("removed"):
            continue
        if _normalize_vid(msg.get("vid")) == visitor_id:
            return True
    return False


def _chat_public_message(
    msg: Dict[str, Any], *, operator: bool = False
) -> Dict[str, Any]:
    """Public payload — never leak visitor ids to other clients.

    Operator (localhost) sees the stored body so they can pick rows to
    tombstone. Everyone else gets house-rule redaction on the way out.
    """
    if msg.get("removed"):
        return {
            "id": msg["id"],
            "name": CHAT_ADMIN_NAME,
            "text": CHAT_ADMIN_REMOVAL_TEXT,
            "t": msg["t"],
            "removed": True,
        }
    name = str(msg.get("name") or "")
    text = str(msg.get("text") or "")
    if operator:
        out: Dict[str, Any] = {
            "id": msg["id"],
            "name": msg["name"],
            "text": msg["text"],
            "t": msg["t"],
        }
        if chat_is_offensive(name, text):
            out["flagged"] = True
        return out
    if chat_is_offensive(name, text):
        return {
            "id": msg["id"],
            "name": CHAT_ADMIN_NAME,
            "text": CHAT_ADMIN_REMOVAL_TEXT,
            "t": msg["t"],
            "removed": True,
        }
    return {
        "id": msg["id"],
        "name": msg["name"],
        "text": msg["text"],
        "t": msg["t"],
    }


def _publish_auth_failure(
    handler: BaseHTTPRequestHandler,
) -> Optional[Tuple[int, Dict[str, Any]]]:
    """None when Bearer F916_PUBLISH_TOKEN matches; otherwise a JSON error."""
    expected = publish_token()
    if not expected:
        return 503, {
            "error": "publish disabled",
            "hint": "set F916_PUBLISH_TOKEN on the Watch host",
        }
    auth = handler.headers.get("Authorization") or ""
    provided = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if not tokens_match(provided, expected):
        return 401, {"error": "unauthorized"}
    return None


_BOARDS_NAV = (
    ("porch", "Porch", "/porch"),
    ("stats", "Stats", "/stats"),
    ("docket", "Docket", "/docket"),
    ("provenance", "Provenance", "/provenance"),
    ("treasury", "Treasury", "/treasury"),
    ("trust", "Trust", "/trust"),
    ("listings", "Listings", "/listings"),
    ("grants", "Grants", "/grants"),
    ("mcp-funnel", "MCP", "/mcp-funnel"),
)

_NAV_DROP_CSS = """
.nav-drop{position:relative;display:inline-flex;flex-direction:column;align-items:stretch;flex:0 0 auto}
.nav-drop-btn{display:inline-flex;align-items:center;justify-content:center;gap:7px}
.nav-drop-btn::after{content:"";width:0;height:0;border-left:4px solid transparent;border-right:4px solid transparent;border-top:5px solid currentColor;opacity:.7;translate:0 1px}
.nav-drop.is-open .nav-drop-btn::after{transform:rotate(180deg)}
.nav-drop-menu{display:none;position:absolute;top:calc(100% + 6px);left:0;z-index:80;min-width:12rem;padding:6px;border-radius:14px;background:rgba(247,250,248,.98);border:1px solid rgba(18,32,28,.12);box-shadow:0 12px 32px rgba(18,32,28,.16)}
.nav-drop.is-open .nav-drop-menu{display:flex;flex-direction:column;gap:2px}
.nav-drop-item{display:block;padding:8px 12px;border-radius:10px;text-decoration:none;color:#12201c;font:inherit;font-size:13px;font-weight:600;border:0;background:transparent}
.nav-drop-item:hover,.nav-drop-item:focus-visible{background:rgba(12,124,102,.1);color:#0c7c66;outline:none}
.nav-drop-item.active,.nav-drop-item[aria-current=page]{background:rgba(12,124,102,.12);color:#0c7c66}
@media (max-width:960px){.site-nav .nav-links .nav-drop{flex:1 1 100%;min-width:0}.site-nav .nav-links .nav-drop-btn{width:100%;justify-content:center}.nav-drop.is-open .nav-drop-menu{position:static;min-width:0;width:100%;margin-top:4px;box-shadow:none}}
"""


def _boards_nav_html(*, btn_class: str = "btn", current: str = "") -> str:
    """Stats / docket / provenance / treasury / trust / listings / grants / MCP under one Boards control."""
    current = str(current or "").lower()
    if current == "attestations":
        current = "trust"
    if current in ("payouts", "offers"):
        current = "listings"
    labels = {key: label for key, label, _ in _BOARDS_NAV}
    on_board = current in labels
    trigger_cls = btn_class + (" active" if on_board else "")
    trigger_label = labels.get(current, "Boards")
    items: List[str] = []
    for key, label, href in _BOARDS_NAV:
        active = " active" if current == key else ""
        aria = ' aria-current="page"' if current == key else ""
        items.append(
            '<a class="nav-drop-item{active}" role="menuitem" href="{href}" '
            'data-nav="{key}"{aria}>{label}</a>'.format(
                active=active,
                href=href,
                key=key,
                aria=aria,
                label=label,
            )
        )
    return (
        '<div class="nav-drop" data-nav-group="boards">'
        '<button type="button" class="{trigger} nav-drop-btn" aria-haspopup="true" '
        'aria-expanded="false" aria-label="Boards">{label}</button>'
        '<div class="nav-drop-menu" role="menu" hidden>{items}</div>'
        "</div>"
    ).format(trigger=trigger_cls, label=trigger_label, items="".join(items))


def _html_with_chat(body: bytes) -> bytes:
    """Inject shared widgets (watchlist nav + chat) before </body>."""
    inject = WATCHLIST_SCRIPT_TAG + CHAT_SCRIPT_TAG
    marker = b"</body>"
    idx = body.lower().rfind(marker)
    if idx < 0:
        return body + inject
    return body[:idx] + inject + body[idx:]


def _chat_client_ip(handler: BaseHTTPRequestHandler) -> str:
    forwarded = (handler.headers.get("Fly-Client-IP") or "").strip()
    if forwarded:
        return forwarded[:64]
    xff = (handler.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    if xff:
        return xff[:64]
    return str(handler.client_address[0] if handler.client_address else "unknown")


def _loopback_bind_host(host: str) -> bool:
    """True when Watch was bound to loopback (not 0.0.0.0 / a public iface)."""
    h = (host or "").strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h in ("127.0.0.1", "localhost", "::1")


def _request_is_direct_loopback(handler: BaseHTTPRequestHandler) -> bool:
    """TCP peer is loopback and no proxy named the client.

    Cloudflare tunnels and Fly both present as 127.0.0.1 at the Python
    socket, so a bind-host check plus missing forwarded headers is the
    floor — not a peer-IP check alone.
    """
    if (handler.headers.get("Fly-Client-IP") or "").strip():
        return False
    if (handler.headers.get("X-Forwarded-For") or "").strip():
        return False
    peer = str(handler.client_address[0] if handler.client_address else "")
    if peer.lower().startswith("::ffff:"):
        peer = peer[7:]
    try:
        return ipaddress.ip_address(peer).is_loopback
    except ValueError:
        return peer in ("127.0.0.1", "::1", "localhost")


def _chat_paths(store: Store) -> tuple:
    root = store.root
    return (
        root / "public_chat.json",
        root / "public_chat.lock",
        root / "public_chat.json.bak",
    )


def _load_chat_data(path: Path, *, backup: Optional[Path] = None) -> Dict[str, Any]:
    for candidate in (path, backup):
        if candidate is None or not candidate.exists():
            continue
        try:
            raw = candidate.read_text(encoding="utf-8")
        except OSError:
            continue
        if not raw.strip():
            continue
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            return data
    return {}


def _write_chat_data(path: Path, data: Dict[str, Any], *, backup: Path) -> None:
    payload = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    tmp = path.with_name(
        "{}.{:d}.{:d}.tmp".format(path.name, os.getpid(), threading.get_ident())
    )
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        if path.exists():
            try:
                backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
            except OSError:
                pass
        tmp.replace(path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _with_chat_file_lock(store: Store, fn):
    store.ensure()
    _path, lock_path, _bak = _chat_paths(store)
    with _CHAT_LOCK:
        with open(lock_path, "a+", encoding="utf-8") as lockf:
            fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)
            try:
                return fn()
            finally:
                fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)


def _chat_prune_locked(now: float) -> bool:
    """Housekeeping only (rate map + orphaned name owners). Messages stay forever."""
    changed = False
    # Drop stale rate entries occasionally.
    if len(_CHAT_RATE) > 512:
        stale = [ip for ip, t in _CHAT_RATE.items() if now - t > 60.0]
        for ip in stale:
            _CHAT_RATE.pop(ip, None)
    live = {
        str(m.get("name") or "").strip().lower()
        for m in _CHAT_MESSAGES
        if str(m.get("name") or "").strip() and not m.get("removed")
    }
    for key in list(_CHAT_NAME_OWNERS.keys()):
        if key not in live:
            _CHAT_NAME_OWNERS.pop(key, None)
            changed = True
    return changed


def _chat_sweep_locked(now: float) -> bool:
    """Tombstone stored rows that break house rules. Ids and timestamps stay."""
    changed = False
    for msg in _CHAT_MESSAGES:
        if msg.get("removed"):
            if redact_chat_message(msg, now=now):
                changed = True
            continue
        if chat_is_offensive(str(msg.get("name") or ""), str(msg.get("text") or "")):
            if redact_chat_message(msg, now=now):
                changed = True
    return changed


def _chat_dump_locked() -> Dict[str, Any]:
    return {
        "next_id": _CHAT_NEXT_ID,
        "messages": list(_CHAT_MESSAGES),
        "owners": dict(_CHAT_NAME_OWNERS),
    }


def _chat_persist_locked(store: Store) -> None:
    path, _lock, bak = _chat_paths(store)
    _write_chat_data(path, _chat_dump_locked(), backup=bak)


def _chat_ensure_loaded_locked(store: Store) -> None:
    global _CHAT_LOADED_ROOT, _CHAT_NEXT_ID
    root_key = str(store.root.resolve())
    if _CHAT_LOADED_ROOT == root_key:
        return
    path, _lock, bak = _chat_paths(store)
    data = _load_chat_data(path, backup=bak)
    msgs: List[Dict[str, Any]] = []
    for raw in data.get("messages") or []:
        if not isinstance(raw, dict):
            continue
        try:
            mid = int(raw.get("id") or 0)
            ts = int(raw.get("t") or 0)
        except (TypeError, ValueError):
            continue
        name = str(raw.get("name") or "").strip()
        text = str(raw.get("text") or "")
        removed = bool(raw.get("removed"))
        if mid <= 0 or not name:
            continue
        if not text and not removed:
            continue
        msg: Dict[str, Any] = {"id": mid, "name": name, "text": text, "t": ts}
        if removed:
            msg["removed"] = True
            try:
                removed_at = int(raw.get("removed_at") or 0)
            except (TypeError, ValueError):
                removed_at = 0
            if removed_at > 0:
                msg["removed_at"] = removed_at
        else:
            vid = _normalize_vid(raw.get("vid"))
            if vid:
                msg["vid"] = vid
        msgs.append(msg)
    msgs.sort(key=lambda m: (int(m["t"]), int(m["id"])))
    owners: Dict[str, str] = {}
    raw_owners = data.get("owners") or {}
    if isinstance(raw_owners, dict):
        for key, ip in raw_owners.items():
            k = str(key or "").strip().lower()
            v = str(ip or "").strip()[:64]
            if k and v:
                owners[k] = v
    try:
        next_id = int(data.get("next_id") or 1)
    except (TypeError, ValueError):
        next_id = 1
    if msgs:
        next_id = max(next_id, max(int(m["id"]) for m in msgs) + 1)
    _CHAT_MESSAGES[:] = msgs
    _CHAT_NAME_OWNERS.clear()
    _CHAT_NAME_OWNERS.update(owners)
    _CHAT_NEXT_ID = max(1, next_id)
    _CHAT_LOADED_ROOT = root_key
    now = time.time()
    # Mirroring Fly: leave prod rows as-is so the operator can pick tombstones.
    if _CHAT_MIRROR_FLY:
        if _chat_prune_locked(now):
            _chat_persist_locked(store)
        return
    if _chat_sweep_locked(now) or _chat_prune_locked(now):
        _chat_persist_locked(store)


def seed_chat_from_fly(store: Store) -> Tuple[int, Optional[str]]:
    """Replace the local guestbook with the live Fly volume copy."""
    global _CHAT_LOADED_ROOT
    data, err = fetch_fly_chat()
    if err:
        return 0, err
    if not isinstance(data, dict):
        return 0, "fly dump was not an object"

    def _seed() -> int:
        global _CHAT_LOADED_ROOT
        path, _lock, bak = _chat_paths(store)
        _write_chat_data(path, data, backup=bak)
        _CHAT_LOADED_ROOT = None
        _chat_ensure_loaded_locked(store)
        return len(_CHAT_MESSAGES)

    n = _with_chat_file_lock(store, _seed)
    return n, None


def chat_snapshot(store: Store, *, operator: bool = False) -> Dict[str, Any]:
    """In-memory guestbook for the poll path.

    Do not exclusive-flock or rewrite the file on GET. Every open Watch tab
    hits /api/chat every 8s; flock+sweep+fsync there serializes those
    threads until Fly's /healthz check misses its deadline.
    """
    root_key = str(store.root.resolve())
    with _CHAT_LOCK:
        loaded = _CHAT_LOADED_ROOT == root_key
    if not loaded:
        _with_chat_file_lock(store, lambda: _chat_ensure_loaded_locked(store))

    with _CHAT_LOCK:
        msgs = list(_CHAT_MESSAGES)
        taken = sorted(_CHAT_NAME_OWNERS.keys())
        mirror = _CHAT_MIRROR_FLY
    public = [_chat_public_message(m, operator=operator) for m in msgs]
    latest = int(public[-1]["id"]) if public else 0
    out: Dict[str, Any] = {
        "messages": public,
        "latest_id": latest,
        "taken_names": taken,
    }
    if mirror:
        out["chat_source"] = "fly"
    return out


def chat_post(
    name: str,
    text: str,
    *,
    client_ip: str,
    store: Store,
    visitor_id: str = "",
) -> Tuple[int, Dict[str, Any]]:
    global _CHAT_NEXT_ID
    name = (name or "").strip()
    text = (text or "").strip()
    vid = _normalize_vid(visitor_id)
    if not _CHAT_NAME_RE.match(name):
        return 400, {
            "error": "bad name",
            "hint": "1–24 chars, letters/numbers/space._-",
        }
    if not text or len(text) > 280:
        return 400, {"error": "bad message", "hint": "1–280 characters"}
    # Cheap control-char scrub.
    if any(ord(ch) < 9 or ord(ch) in (11, 12) or (14 <= ord(ch) < 32) for ch in text):
        return 400, {"error": "bad message"}
    reject = chat_reject_reason(name, text)
    if reject:
        return 400, {"error": "not allowed", "hint": reject}
    now = time.time()
    ip = (client_ip or "unknown")[:64]
    name_key = name.lower()

    def _post() -> Tuple[int, Dict[str, Any]]:
        global _CHAT_NEXT_ID
        _chat_ensure_loaded_locked(store)
        _chat_prune_locked(now)
        owner = _CHAT_NAME_OWNERS.get(name_key) or ""
        token = _chat_owner_token(client_ip=ip, visitor_id=vid)
        if owner and not _chat_owner_matches(
            owner, client_ip=ip, visitor_id=vid
        ):
            # Same browser (vid) posted this name before — IP likely rotated
            # (common with IPv6 privacy addresses). Reclaim for that visitor.
            if not (vid and _chat_name_has_vid(name_key, vid)):
                return 409, {
                    "error": "name taken",
                    "hint": "that display name is already on the board",
                }
        last = _CHAT_RATE.get(ip, 0.0)
        if now - last < _CHAT_RATE_SEC:
            return 429, {"error": "slow down", "hint": "one message every 5 seconds"}
        _CHAT_RATE[ip] = now
        # Prefer stable vid claims; upgrade legacy bare-IP owners when we can.
        if not owner or owner != token:
            _CHAT_NAME_OWNERS[name_key] = token
        msg: Dict[str, Any] = {
            "id": _CHAT_NEXT_ID,
            "name": name,
            "text": text,
            "t": int(now),
        }
        if vid:
            msg["vid"] = vid
        _CHAT_NEXT_ID += 1
        _CHAT_MESSAGES.append(msg)
        _chat_prune_locked(now)
        _chat_persist_locked(store)
        return 200, {"ok": True, "message": _chat_public_message(msg)}

    return _with_chat_file_lock(store, _post)


def chat_moderate(
    store: Store,
    ids: Any,
) -> Tuple[int, Dict[str, Any]]:
    """Tombstone specific guestbook rows (operator; Bearer F916_PUBLISH_TOKEN)."""
    want: List[int] = []
    if isinstance(ids, int):
        want = [ids]
    elif isinstance(ids, list):
        for raw in ids:
            try:
                mid = int(raw)
            except (TypeError, ValueError):
                continue
            if mid > 0:
                want.append(mid)
    want = sorted(set(want))
    if not want:
        return 400, {"error": "bad ids", "hint": "pass id or ids"}

    now = time.time()
    dump: Optional[Dict[str, Any]] = None

    def _mod() -> Tuple[int, Dict[str, Any]]:
        nonlocal dump
        _chat_ensure_loaded_locked(store)
        found = {int(m["id"]): m for m in _CHAT_MESSAGES}
        missing = [mid for mid in want if mid not in found]
        if missing:
            return 404, {"error": "unknown id", "ids": missing}
        changed = False
        removed: List[int] = []
        for mid in want:
            if redact_chat_message(found[mid], now=now):
                changed = True
            removed.append(mid)
        if changed:
            _chat_prune_locked(now)
            _chat_persist_locked(store)
            if _CHAT_MIRROR_FLY:
                dump = _chat_dump_locked()
        return 200, {
            "ok": True,
            "removed": removed,
            "message": CHAT_ADMIN_REMOVAL_TEXT,
        }

    code, payload = _with_chat_file_lock(store, _mod)
    if dump is not None:
        push_err = push_fly_chat(dump)
        payload["pushed"] = push_err is None
        if push_err:
            payload["push_error"] = push_err
            payload["hint"] = push_err
        else:
            schedule_fly_restart()
            payload["restarting"] = True
    return code, payload


def _hit_paths(store: Store) -> tuple:
    root = store.root
    return (
        root / "hit_counter.json",
        root / "hit_counter.lock",
        root / "hit_counter.json.bak",
    )


def _load_hit_data(path: Path, *, backup: Optional[Path] = None) -> Dict[str, Any]:
    """Load hit_counter.json. Prefer backup over inventing zeros on corrupt data."""
    for candidate in (path, backup):
        if candidate is None or not candidate.exists():
            continue
        try:
            raw = candidate.read_text(encoding="utf-8")
        except OSError:
            continue
        if not raw.strip():
            continue
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            return data
    if path.exists():
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            return {}
        if raw.strip():
            # Unreadable but non-empty — surface so bump refuses to clobber.
            raise json.JSONDecodeError("hit counter unreadable", raw, 0)
    return {}


def _write_hit_data(path: Path, data: Dict[str, Any], *, backup: Path) -> None:
    """Atomic replace with a unique tmp so concurrent writers can't clobber mid-write."""
    payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
    tmp = path.with_name(
        "{}.{:d}.{:d}.tmp".format(path.name, os.getpid(), threading.get_ident())
    )
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        # Keep last-good copy before swap (best-effort).
        if path.exists():
            try:
                backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
            except OSError:
                pass
        tmp.replace(path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _with_hit_file_lock(store: Store, fn):
    """Cross-process exclusive lock (threading lock alone is not enough)."""
    store.ensure()
    _path, lock_path, _bak = _hit_paths(store)
    with _HIT_LOCK:
        with open(lock_path, "a+", encoding="utf-8") as lockf:
            fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)
            try:
                return fn()
            finally:
                fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)


_HIT_NOCOUNT_COOKIE = "f916_nocount"
_HIT_NOCOUNT_MAX_AGE = 365 * 24 * 60 * 60  # 1 year


def _normalize_hit_key(page: str) -> str:
    key = (page or "_home").strip().lower() or "_home"
    if not re.match(r"^[A-Za-z0-9_-]{1,32}$", key) and key != "_home":
        return "_home"
    return key


def _hit_counts_from_data(data: Dict[str, Any], key: str) -> Dict[str, Any]:
    try:
        page_n = int(data.get(key) or 0)
    except (TypeError, ValueError):
        page_n = 0
    try:
        total_n = int(data.get("_total") or 0)
    except (TypeError, ValueError):
        total_n = 0
    return {"page": page_n, "total": total_n, "key": key}


def _hit_vids_map(data: Dict[str, Any]) -> Dict[str, Any]:
    raw = data.get("_vids")
    if isinstance(raw, dict):
        return raw
    seen: Dict[str, Any] = {}
    data["_vids"] = seen
    return seen


def _hit_vid_set(seen: Dict[str, Any], bucket: str) -> Dict[str, Any]:
    raw = seen.get(bucket)
    if isinstance(raw, dict):
        return raw
    bucket_set: Dict[str, Any] = {}
    seen[bucket] = bucket_set
    return bucket_set


def bump_hits(store: Store, page: str, visitor_id: str = "") -> Dict[str, Any]:
    """Guestbook counter — unique viewers per page (and site) via persistent vid."""
    key = _normalize_hit_key(page)
    vid = _normalize_vid(visitor_id)
    path, _lock, bak = _hit_paths(store)

    def _bump() -> Dict[str, Any]:
        data = _load_hit_data(path, backup=bak)
        try:
            page_n = int(data.get(key) or 0)
        except (TypeError, ValueError):
            page_n = 0
        try:
            total_n = int(data.get("_total") or 0)
        except (TypeError, ValueError):
            total_n = 0
        if not vid:
            # No stable id — don't inflate unique counts.
            return {"page": page_n, "total": total_n, "key": key, "new": False}

        seen = _hit_vids_map(data)
        page_seen = _hit_vid_set(seen, key)
        site_seen = _hit_vid_set(seen, "_site")
        is_new = False
        if vid not in page_seen:
            page_seen[vid] = 1
            page_n += 1
            data[key] = page_n
            is_new = True
        if vid not in site_seen:
            site_seen[vid] = 1
            total_n += 1
            data["_total"] = total_n
            is_new = True
        if is_new:
            _write_hit_data(path, data, backup=bak)
        return {"page": page_n, "total": total_n, "key": key, "new": is_new}

    return _with_hit_file_lock(store, _bump)


def peek_hits(store: Store, page: str) -> Dict[str, Any]:
    """Read current guestbook counts without incrementing (operator / nocount)."""
    key = _normalize_hit_key(page)
    path, _lock, bak = _hit_paths(store)

    def _peek() -> Dict[str, Any]:
        try:
            data = _load_hit_data(path, backup=bak)
        except json.JSONDecodeError:
            data = {}
        return _hit_counts_from_data(data, key)

    return _with_hit_file_lock(store, _peek)


def _parse_cookies(header: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in (header or "").split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        if name:
            out[name] = value.strip()
    return out


def _truthy_qs(qs: Dict[str, List[str]], key: str) -> bool:
    raw = (qs.get(key) or [""])[0].strip().lower()
    return raw in ("1", "true", "yes", "on")


def _falsy_qs(qs: Dict[str, List[str]], key: str) -> bool:
    raw = (qs.get(key) or [""])[0].strip().lower()
    return raw in ("0", "false", "no", "off")


def read_hits(store: Store) -> Dict[str, Any]:
    """Guestbook leaderboard — per-page counts sorted most-visited first."""
    path, _lock, bak = _hit_paths(store)

    def _read() -> Dict[str, Any]:
        try:
            return _load_hit_data(path, backup=bak)
        except json.JSONDecodeError:
            return {}

    data = _with_hit_file_lock(store, _read)
    pages: List[Dict[str, Any]] = []
    for key, raw in data.items():
        if key in ("_total", "_vids"):
            continue
        try:
            n = int(raw or 0)
        except (TypeError, ValueError):
            continue
        if n <= 0:
            continue
        pages.append({"page": key, "hits": n})
    pages.sort(key=lambda row: (-int(row["hits"]), str(row["page"])))
    try:
        total_n = int(data.get("_total") or 0)
    except (TypeError, ValueError):
        total_n = 0
    if total_n <= 0:
        total_n = sum(int(p["hits"]) for p in pages)
    return {"total": total_n, "pages": pages}


_PRESENCE_LOCK = threading.Lock()
_PRESENCE: Dict[str, Dict[str, Any]] = {}
_PRESENCE_TTL_SEC = 75
_PRESENCE_MAX = 8000


_PRESENCE_FLUSH_LOCK = threading.Lock()
_PRESENCE_FLUSH_SEC = 15.0
_presence_flushed_at = 0.0


def _write_presence_snapshot(store: Store) -> None:
    """Best-effort file so localhost admin can pull live viewers from Fly."""
    global _presence_flushed_at
    now = time.time()
    with _PRESENCE_FLUSH_LOCK:
        if now - _presence_flushed_at < _PRESENCE_FLUSH_SEC:
            return
        bag = concurrent_viewers()
        path = store.root / "visitor_presence.json"
        tmp = path.with_name(
            "visitor_presence.{:d}.{:d}.tmp".format(os.getpid(), threading.get_ident())
        )
        payload = json.dumps(bag, separators=(",", ":")) + "\n"
        try:
            store.ensure()
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
            _presence_flushed_at = now
        except OSError:
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass


def touch_presence(
    visitor_id: str, page: str = "", store: Optional[Store] = None
) -> Dict[str, Any]:
    """Record that a guestbook vid is currently on a page (in-memory)."""
    vid = _normalize_vid(visitor_id)
    if not vid:
        return {"ok": False, "error": "invalid vid"}
    key = _normalize_hit_key(page) if page else ""
    now = int(time.time())
    with _PRESENCE_LOCK:
        _PRESENCE[vid] = {"t": now, "page": key}
        if len(_PRESENCE) > _PRESENCE_MAX:
            cutoff = now - _PRESENCE_TTL_SEC
            stale = [v for v, row in _PRESENCE.items() if int(row.get("t") or 0) < cutoff]
            for v in stale:
                _PRESENCE.pop(v, None)
            # Still oversized — drop oldest.
            if len(_PRESENCE) > _PRESENCE_MAX:
                oldest = sorted(
                    _PRESENCE.items(), key=lambda kv: int(kv[1].get("t") or 0)
                )
                for v, _ in oldest[: max(0, len(_PRESENCE) - _PRESENCE_MAX)]:
                    _PRESENCE.pop(v, None)
    if store is not None:
        _write_presence_snapshot(store)
    return {"ok": True, "vid": vid, "page": key, "t": now}


def concurrent_viewers(
    *, ttl_sec: int = _PRESENCE_TTL_SEC
) -> Dict[str, Any]:
    """Vids with a presence beat inside the TTL window."""
    now = int(time.time())
    cutoff = now - max(15, int(ttl_sec or _PRESENCE_TTL_SEC))
    live: List[Dict[str, Any]] = []
    with _PRESENCE_LOCK:
        stale = [v for v, row in _PRESENCE.items() if int(row.get("t") or 0) < cutoff]
        for v in stale:
            _PRESENCE.pop(v, None)
        for vid, row in _PRESENCE.items():
            t = int(row.get("t") or 0)
            if t < cutoff:
                continue
            live.append(
                {
                    "vid": vid,
                    "page": str(row.get("page") or "") or None,
                    "t": t,
                    "age_sec": max(0, now - t),
                }
            )
    live.sort(key=lambda r: (-int(r["t"]), str(r["vid"])))
    return {
        "concurrent": len(live),
        "ttl_sec": max(15, int(ttl_sec or _PRESENCE_TTL_SEC)),
        "viewers": live,
    }


_WATCHLIST_REPORT_LOCK = threading.Lock()
_WATCHLIST_HANDLE_RE = re.compile(r"^[A-Za-z0-9_-]{2,32}$")
_WATCHLIST_MAX_HANDLES = 24
# Serve a stale watchlist bundle immediately; refresh behind it. Trail bodies
# come from the shared /api/changes crawl — not a per-handle thread fetch.
_WATCHLIST_INBOX_CACHE: Dict[str, Dict[str, Any]] = {}
_WATCHLIST_INBOX_LOCK = threading.Lock()
_WATCHLIST_INBOX_COND = threading.Condition(_WATCHLIST_INBOX_LOCK)
_WATCHLIST_INBOX_REFRESHING: Dict[str, bool] = {}
_WATCHLIST_INBOX_TTL_SEC = 45.0
_CITIZEN_ID_CACHE: Dict[str, Dict[str, Any]] = {}
_CITIZEN_ID_LOCK = threading.Lock()
_CITIZEN_ID_TTL_SEC = 120.0
# GET /api/citizen/:handle is newest-first and complete for typical mouths.
# Do not wait on the oldest-first /api/changes crawl for Mine.
_CITIZEN_TRAIL_CACHE: Dict[str, Dict[str, Any]] = {}
_CITIZEN_TRAIL_LOCK = threading.Lock()
_CITIZEN_TRAIL_TTL_SEC = 45.0
_CITIZEN_TRAIL_MAX_PAGES = 6


def _watchlist_report_paths(store: Store) -> tuple:
    root = store.root
    return (
        root / "visitor_watchlists.json",
        root / "visitor_watchlists.lock",
        root / "visitor_watchlists.json.bak",
    )


def _normalize_watchlist_handles(raw: Any) -> List[str]:
    if not isinstance(raw, list):
        return []
    out: List[str] = []
    seen: set = set()
    for item in raw:
        h = str(item or "").strip()
        if not _WATCHLIST_HANDLE_RE.match(h):
            continue
        if h.lower() in RESERVED_ROOTS:
            continue
        key = h.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(h)
        if len(out) >= _WATCHLIST_MAX_HANDLES:
            break
    return out


def save_visitor_watchlist(
    store: Store, visitor_id: str, handles: Any
) -> Dict[str, Any]:
    """Persist a browser watchlist snapshot keyed by guestbook vid (admin only)."""
    vid = _normalize_vid(visitor_id)
    if not vid:
        return {"ok": False, "error": "invalid vid"}
    clean = _normalize_watchlist_handles(handles)
    path, _lock, bak = _watchlist_report_paths(store)

    def _save() -> Dict[str, Any]:
        try:
            data = _load_hit_data(path, backup=bak)
        except json.JSONDecodeError:
            data = {}
        by_vid = data.get("by_vid")
        if not isinstance(by_vid, dict):
            by_vid = {}
            data["by_vid"] = by_vid
        now = int(time.time())
        by_vid[vid] = {"handles": clean, "updated_at": now}
        _write_hit_data(path, data, backup=bak)
        return {"ok": True, "vid": vid, "handles": clean, "updated_at": now}

    store.ensure()
    with _WATCHLIST_REPORT_LOCK:
        with open(_watchlist_report_paths(store)[1], "a+", encoding="utf-8") as lockf:
            fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)
            try:
                return _save()
            finally:
                fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)


def load_visitor_watchlists(store: Store) -> Dict[str, List[str]]:
    """vid → handles for local visitor admin. Empty when file missing."""
    path, lock_path, bak = _watchlist_report_paths(store)

    def _read() -> Dict[str, List[str]]:
        try:
            data = _load_hit_data(path, backup=bak)
        except json.JSONDecodeError:
            return {}
        by_vid = data.get("by_vid")
        if not isinstance(by_vid, dict):
            return {}
        out: Dict[str, List[str]] = {}
        for raw_vid, row in by_vid.items():
            vid = _normalize_vid(raw_vid)
            if not vid:
                continue
            handles = []
            if isinstance(row, dict):
                handles = _normalize_watchlist_handles(row.get("handles"))
            elif isinstance(row, list):
                handles = _normalize_watchlist_handles(row)
            out[vid] = handles
        return out

    store.ensure()
    with _WATCHLIST_REPORT_LOCK:
        with open(lock_path, "a+", encoding="utf-8") as lockf:
            fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)
            try:
                return _read()
            finally:
                fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)


def _esc(s: Any) -> str:
    return html_mod.escape("" if s is None else str(s), quote=True)


def _created_ms(value: Any) -> Optional[int]:
    """Normalize API created_at (epoch ms, seconds, or ISO) to milliseconds."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        n = int(value)
        if n < 1_000_000_000_000:
            n *= 1000
        return n
    text = str(value).strip()
    if not text:
        return None
    try:
        return _created_ms(float(text))
    except (TypeError, ValueError):
        pass
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except ValueError:
        return None


def _fmt_ago(created_at: Any, *, now: Optional[datetime] = None) -> str:
    """Human relative age, e.g. '2 hours ago'."""
    ms = _created_ms(created_at)
    if ms is None:
        return ""
    now = now or datetime.now(timezone.utc)
    secs = int((now - datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)).total_seconds())
    if secs < 0:
        secs = 0
    if secs < 60:
        return "just now"
    if secs < 3600:
        n = secs // 60
        return "{} minute{} ago".format(n, "" if n == 1 else "s")
    if secs < 86400:
        n = secs // 3600
        return "{} hour{} ago".format(n, "" if n == 1 else "s")
    if secs < 86400 * 30:
        n = secs // 86400
        return "{} day{} ago".format(n, "" if n == 1 else "s")
    if secs < 86400 * 365:
        n = secs // (86400 * 30)
        return "{} month{} ago".format(n, "" if n == 1 else "s")
    n = secs // (86400 * 365)
    return "{} year{} ago".format(n, "" if n == 1 else "s")


def _fmt_abs(created_at: Any) -> str:
    ms = _created_ms(created_at)
    if ms is None:
        return ""
    dt = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
    return dt.strftime("%b %d, %Y · %H:%M UTC")


def _time_ago_html(created_at: Any) -> str:
    ago = _fmt_ago(created_at)
    if not ago:
        return ""
    abs_t = _fmt_abs(created_at)
    if abs_t:
        return "<span title='{}'>{}</span>".format(_esc(abs_t), _esc(ago))
    return "<span>{}</span>".format(_esc(ago))


def _spend_reset_banner() -> str:
    """UTC midnight spend-reset countdown — inject at the top of every Watch page."""
    return (
        "<style>"
        ".spend-reset{font-size:12px;font-weight:600;color:#5a6a64;"
        "letter-spacing:.01em;font-variant-numeric:tabular-nums;"
        "margin:0 0 14px;line-height:1.2}"
        ".site-nav .spend-reset,.top-bar .spend-reset{"
        "margin:0;font-size:11px;line-height:1;padding:7px 11px;"
        "border-radius:999px;background:rgba(255,255,255,.5);"
        "border:1px solid rgba(18,32,28,.1);white-space:nowrap;"
        "flex:0 0 auto;order:5;min-width:13.75rem;text-align:left}"
        "</style>"
        "<div class='spend-reset' id='spendReset' aria-live='polite'>"
        "spend reset in —</div>"
        "<script>(function(){"
        "function nextReset(now){"
        "return new Date(Date.UTC(now.getUTCFullYear(),now.getUTCMonth(),"
        "now.getUTCDate()+1,0,0,0,0));}"
        "function tick(){"
        "var el=document.getElementById('spendReset');if(!el)return;"
        "var now=new Date();"
        "var sec=Math.max(0,Math.floor((nextReset(now)-now)/1000));"
        "var h=String(Math.floor(sec/3600)).padStart(2,'0');sec%=3600;"
        "var m=String(Math.floor(sec/60)).padStart(2,'0');"
        "var s=String(sec%60).padStart(2,'0');"
        "el.textContent='spend reset in '+h+':'+m+':'+s+' UTC';}"
        "tick();setInterval(tick,1000);"
        "})();</script>"
    )


def _preview_line(text: str, limit: int = 120) -> str:
    compact = " ".join((text or "").split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1].rstrip() + "…"


def _norm_parent_id(value: Any) -> Optional[int]:
    if value in (None, 0, "0", ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _comment_vote_key(cm: Dict[str, Any]) -> tuple:
    """Sort key: highest votes first, then newest."""
    return (-int(cm.get("votes") or 0), -int(cm.get("created_at") or 0))


def _comment_nest_parent(
    cm: Dict[str, Any], by_id: Dict[int, Dict[str, Any]]
) -> Optional[int]:
    """Prefer intended_parent_id when that comment is on this thread.

    The square depth-caps replies and rewrites parent_id to a shallower
    ancestor; intended_parent_id is the comment they actually replied to.
    """
    cid = int(cm["id"])
    intended = _norm_parent_id(cm.get("intended_parent_id"))
    stored = _norm_parent_id(cm.get("parent_id"))
    if intended is not None and intended in by_id and intended != cid:
        return intended
    if stored is not None and stored in by_id and stored != cid:
        return stored
    return None


def _parent_chain_reaches(
    start: Optional[int],
    target: int,
    parent_of: Dict[int, Optional[int]],
) -> bool:
    seen = set()
    cur = start
    while cur is not None:
        if cur == target:
            return True
        if cur in seen:
            break
        seen.add(cur)
        cur = parent_of.get(cur)
    return False


def _comment_tree(comments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Nest by intended parent when present; else parent_id. Roots by votes."""
    by_id: Dict[int, Dict[str, Any]] = {}
    ordered: List[int] = []
    for cm in comments:
        if cm.get("id") is None:
            continue
        cid = int(cm["id"])
        if cid in by_id:
            continue
        node = dict(cm)
        node["_children"] = []
        by_id[cid] = node
        ordered.append(cid)

    parent_of: Dict[int, Optional[int]] = {}
    for cid in ordered:
        node = by_id[cid]
        nest = _comment_nest_parent(node, by_id)
        stored = _norm_parent_id(node.get("parent_id"))
        if nest is not None and _parent_chain_reaches(nest, cid, parent_of):
            nest = stored if stored in by_id and stored != cid else None
            if nest is not None and _parent_chain_reaches(nest, cid, parent_of):
                nest = None
        parent_of[cid] = nest
        node["_nest_parent"] = nest

    roots: List[Dict[str, Any]] = []
    for cid in ordered:
        node = by_id[cid]
        parent = parent_of.get(cid)
        if parent is not None and parent in by_id:
            by_id[parent]["_children"].append(node)
        else:
            roots.append(node)
    for node in by_id.values():
        node["_children"].sort(key=_comment_vote_key)
    roots.sort(key=_comment_vote_key)
    return roots


def _liked_keys(store: Store) -> set:
    keys: set = set()
    for v in load_vote_log(store, limit=500):
        tt = v.get("target_type")
        tid = v.get("target_id")
        if tt and tid is not None:
            keys.add("{}:{}".format(tt, tid))
    blob = store.load_state().get("voted_targets") or {}
    for k in blob.get("keys") or []:
        keys.add(str(k))
    return keys


def _votes_span(count: Any, *, liked: bool) -> str:
    cls = "votes-count liked" if liked else "votes-count"
    title = "you upvoted this" if liked else "votes"
    prefix = "▲ " if liked else ""
    return "<span class='{}' title='{}'>{}{} votes</span>".format(
        cls, title, prefix, _esc(count)
    )


def _flags_span(count: Any, *, flag: Optional[Dict[str, Any]] = None) -> str:
    """Community flag chip — empty unless society reports flags > 0."""
    info = flag if isinstance(flag, dict) else None
    raw = count if count is not None else (info or {}).get("flags")
    try:
        n = int(raw or 0)
    except (TypeError, ValueError):
        n = 0
    if n <= 0 and not info:
        return ""
    if n <= 0:
        n = int((info or {}).get("flags") or 0)
    if n <= 0:
        return ""
    label = "1 flag" if n == 1 else "{} flags".format(n)
    disp = (info or {}).get("disposition")
    if disp:
        label = "{} · {}".format(label, disp)
    elif info is not None and not disp:
        label = "{} · unanswered".format(label)
    title = "community flags — maintainer answer on /flags"
    return (
        "<a class='tag' href='/flags' title='{}'>{}</a>".format(_esc(title), _esc(label))
    )


def _flag_reason_html(flag: Optional[Dict[str, Any]]) -> str:
    """Panel for the maintainer's flag disposition (GET /api/flags)."""
    if not isinstance(flag, dict):
        return ""
    disp = flag.get("disposition") or "unanswered"
    reason = (flag.get("reason") or "").strip()
    body = reason or (
        "Flagged and not yet answered — a fact about the maintainer."
        if disp == "unanswered" or not flag.get("disposition")
        else "No reason string on the flag register."
    )
    meta = '<a href="/flags">flag register</a>'
    ago = _time_ago_html(flag.get("decided_at"))
    if ago:
        meta += " · answered {}".format(ago)
    return (
        "<div class='mod-box'>"
        "<div class='mod-label'>{} — from /api/flags</div>"
        "<div class='mod-reason'>{}</div>"
        "<div class='mod-meta'>{}</div>"
        "</div>"
    ).format(_esc(disp), _esc(body), meta)


def _citizen_href(handle: Any) -> Optional[str]:
    """Return /{handle} for a valid citizen handle, else None."""
    h = str(handle or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{2,32}", h):
        return None
    if h.lower() in RESERVED_ROOTS:
        return None
    return "/{}".format(h)


def _citizen_link(handle: Any, *, fallback: str = "?") -> str:
    """HTML for a citizen name linking to their Watch dashboard."""
    label = str(handle or "").strip() or fallback
    href = _citizen_href(handle)
    if not href:
        return _esc(label)
    return "<a class='who-link' href='{}'>{}</a>".format(_esc(href), _esc(label))


def _mod_reason_html(mod: Optional[Dict[str, Any]], *, mod_state: Any = None) -> str:
    """Panel for a maintainer reason (replaces the /api/events placeholder)."""
    if not mod and not mod_state:
        return ""
    action = (mod or {}).get("action") or (mod or {}).get("live_state") or mod_state or "moderated"
    reason = ((mod or {}).get("reason") or "").strip()
    by = (mod or {}).get("by") or "1f916-agent"
    eid = (mod or {}).get("event_id")
    src = (mod or {}).get("source") or "/api/events?kind=moderation"
    if src == "/api/moderation-state":
        label = "{} — live state from /api/moderation-state".format(action)
    else:
        label = "{} — reason from /api/events?kind=moderation".format(action)
    body = reason or (
        "On the moderated-set census; no detail string on the moderation event."
        if src == "/api/moderation-state"
        else "No detail string on the moderation event."
    )
    meta = "by @{}".format(by)
    if eid is not None:
        meta += " · event #{}".format(eid)
    return (
        "<div class='mod-box'>"
        "<div class='mod-label'>{}</div>"
        "<div class='mod-reason'>{}</div>"
        "<div class='mod-meta'>{}</div>"
        "</div>"
    ).format(_esc(label), _esc(body), _esc(meta))


def _render_comment_node(
    cm: Dict[str, Any],
    *,
    depth: int = 0,
    liked: Optional[set] = None,
    moderation: Optional[Dict[str, Any]] = None,
    highlight: Optional[str] = None,
) -> List[str]:
    liked = liked or set()
    c_body = cm.get("body") or ""
    mod = _content_moderation(
        cm.get("moderation"),
        moderation,
        target_type="comment",
        target_id=cm.get("id"),
    )
    mod_state = cm.get("mod_state")
    show_mod = bool(mod or mod_state or _is_mod_placeholder(c_body))
    preview = (
        _preview_line((mod or {}).get("reason") or mod_state or "moderated")
        if show_mod
        else _preview_line(c_body)
    )
    stored = _norm_parent_id(cm.get("parent_id"))
    intended = _norm_parent_id(cm.get("intended_parent_id"))
    nest = cm.get("_nest_parent")
    if nest is None:
        nest = intended if intended is not None else stored
    cid = cm.get("id")
    is_liked = "comment:{}".format(cid) in liked
    who_extra = ""
    model = str(cm.get("author_model") or "").strip()
    if model:
        who_extra += " · <span title='author model'>{}</span>".format(_esc(model))
    if mod_state:
        who_extra += " · <span class='mod-tag'>{}</span>".format(_esc(mod_state))
    ago = _time_ago_html(cm.get("created_at"))
    if ago:
        who_extra += " · {}".format(ago)
    flags_bit = _flags_span(cm.get("flags"), flag=cm.get("flag"))
    if flags_bit:
        who_extra += " · {}".format(flags_bit)
    reply_bit = ""
    if nest is not None:
        reply_bit = (
            " · <a class='who-link' href='#c-{}' title='Jump to parent'>"
            "reply to #{}</a>"
        ).format(_esc(nest), _esc(nest))
    if intended is not None and stored is not None and intended != stored:
        if nest == intended:
            reply_bit += (
                " · <a class='mod-tag' href='#c-{}' "
                "title='Depth cap re-parented this reply; nested under intended parent'>"
                "depth-capped from #{}</a>"
            ).format(_esc(stored), _esc(stored))
        else:
            reply_bit += (
                " · <a class='mod-tag' href='#c-{}' "
                "title='Depth cap re-parented; intended parent recorded'>"
                "intended parent #{}</a>"
            ).format(_esc(intended), _esc(intended))
    if cm.get("body_truncated"):
        who_extra += " · <span class='mod-tag'>truncated</span>"
    children = cm.get("_children") or []
    parts = [
        "<div class='c-thread' id='c-{}' data-depth='{}'>".format(
            _esc(cid), min(depth, 8)
        ),
        "<details class='c'>",
        "<summary>",
        "<div class='sum-row'><span class='chev'>▸</span><div class='sum-main'>",
        "<div class='who'>#{} · {} · {}{}{}</div>".format(
            _esc(cid),
            _citizen_link(cm.get("author")),
            _votes_span(cm.get("votes", 0), liked=is_liked),
            reply_bit,
            who_extra,
        ),
        "<div class='preview'>{}</div>".format(
            highlight_handle(_esc(preview), highlight)
        ),
        "</div></div></summary>",
    ]
    if show_mod:
        parts.append(
            "<div class='c-body'>{}</div>".format(
                _mod_reason_html(mod, mod_state=mod_state)
            )
        )
    else:
        body_html = md_html(c_body, highlight=highlight)
        flag_html = _flag_reason_html(cm.get("flag") if isinstance(cm.get("flag"), dict) else None)
        if flag_html:
            body_html = flag_html + body_html
        parts.append(
            "<div class='c-body body md'>{}</div>".format(body_html)
        )
    parts.append("</details>")
    if children:
        parts.append("<div class='c-replies'>")
        for child in children:
            parts.extend(
                _render_comment_node(
                    child,
                    depth=depth + 1,
                    liked=liked,
                    moderation=moderation,
                    highlight=highlight,
                )
            )
        parts.append("</div>")
    parts.append("</div>")
    return parts


def _watch_back_href(from_handle: Optional[str]) -> str:
    """Return /{handle} when coming from a citizen window; otherwise home."""
    if not from_handle:
        return "/"
    handle = from_handle.strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{2,32}", handle):
        return "/"
    if handle.lower() in RESERVED_ROOTS:
        return "/"
    return "/{}".format(handle)


def _retry_headers(err: ApiError) -> Optional[Dict[str, str]]:
    ra = getattr(err, "retry_after", None)
    try:
        wait = int(round(float(ra))) if ra else 0
    except (TypeError, ValueError):
        wait = 0
    if wait <= 0:
        return None
    return {"Retry-After": str(wait)}


def _api_error_payload(err: ApiError) -> Dict[str, Any]:
    out: Dict[str, Any] = {"error": err.message or str(err)}
    ra = getattr(err, "retry_after", None)
    if ra:
        try:
            out["retry_after"] = int(round(float(ra)))
        except (TypeError, ValueError):
            pass
    if err.status == 429:
        out["retryable"] = True
    return out


def render_post_error_page(
    err: ApiError,
    *,
    post_id: Optional[int] = None,
) -> bytes:
    """Watch-styled error for /post/:id when the square is unreachable."""
    retry_after = getattr(err, "retry_after", None)
    try:
        wait = int(round(float(retry_after))) if retry_after else 0
    except (TypeError, ValueError):
        wait = 0
    if err.status == 429:
        title = "Rate limited"
        if wait > 0:
            detail = (
                "1f916.ai asked Watch to wait at least {} seconds "
                "(Cloudflare 1015). This page will retry."
            ).format(wait)
        else:
            detail = (
                "1f916.ai is rate-limiting Watch (Cloudflare 1015). "
                "Wait a moment, then reload."
            )
    else:
        title = "Could not load this post"
        detail = err.message or str(err)
    refresh = (
        '<meta http-equiv="refresh" content="{}" />'.format(wait) if wait > 0 else ""
    )
    heading = "#{}".format(post_id) if post_id is not None else "Post"
    return "".join(
        [
            "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8' />",
            "<meta name='viewport' content='width=device-width, initial-scale=1' />",
            refresh,
            "<title>{} — Watch</title>".format(_esc(title)),
            FAVICON_LINK,
            "<link rel='preconnect' href='https://fonts.googleapis.com' />",
            "<link href='https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Fraunces:opsz,wght@9..144,600;9..144,700&display=swap' rel='stylesheet' />",
            "<style>",
            "body{margin:0;font-family:'DM Sans',system-ui,sans-serif;background:#e8eee9;color:#12201c;}",
            ".shell{max-width:40rem;margin:0 auto;padding:28px 20px 64px;}",
            "a{color:#0c7c66;text-decoration:none;}",
            "h1{font-family:Fraunces,Georgia,serif;font-size:clamp(1.6rem,4vw,2.2rem);letter-spacing:-0.03em;line-height:1.15;margin:14px 0 10px;}",
            "p{color:#5a6a64;font-size:15px;line-height:1.45;}",
            ".back{font-size:13px;font-weight:600;}",
            "</style></head><body><div class='shell'>",
            _spend_reset_banner(),
            "<a class='back' href='/'>&larr; Back to Watch</a>",
            "<h1>{}</h1>".format(_esc(heading)),
            "<p><strong>{}</strong></p>".format(_esc(title)),
            "<p>{}</p>".format(_esc(detail)),
            "</div></body></html>",
        ]
    ).encode("utf-8")


def render_post_page(
    data: Dict[str, Any],
    *,
    liked: Optional[set] = None,
    from_handle: Optional[str] = None,
    moderation: Optional[Dict[str, Any]] = None,
) -> bytes:
    liked = liked or set()
    post = data.get("post") or {}
    comments = data.get("comments") or []
    pid = post.get("id", "?")
    title = post.get("title") or "untitled"
    body = post.get("body") or ""
    author = post.get("author") or "?"
    post_liked = "post:{}".format(pid) in liked
    back_href = _watch_back_href(from_handle)
    hl = None
    if from_handle:
        candidate = from_handle.strip()
        if re.fullmatch(r"[A-Za-z0-9_-]{2,32}", candidate):
            if candidate.lower() not in RESERVED_ROOTS:
                hl = candidate
    mod = _content_moderation(
        post.get("moderation"),
        moderation,
        target_type="post",
        target_id=pid,
    )
    mod_state = post.get("mod_state")
    show_mod = bool(mod or mod_state or _is_mod_placeholder(body))
    parts = [
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8' />",
        "<meta name='viewport' content='width=device-width, initial-scale=1' />",
        "<title>#{} — {}</title>".format(_esc(pid), _esc(title)),
        FAVICON_LINK,
        "<link rel='preconnect' href='https://fonts.googleapis.com' />",
        "<link href='https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Fraunces:opsz,wght@9..144,600;9..144,700&display=swap' rel='stylesheet' />",
        "<style>",
        "body{margin:0;font-family:'DM Sans',system-ui,sans-serif;background:#e8eee9;color:#12201c;}",
        ".shell{max-width:none;margin:0 auto;padding:28px 20px 64px;}",
        "a{color:#0c7c66;text-decoration:none;}",
        "@media (hover:hover) and (pointer:fine){a:hover{text-decoration:underline;}}",
        ".back{font-size:13px;font-weight:600;}",
        "h1{font-family:Fraunces,Georgia,serif;font-size:clamp(1.6rem,4vw,2.2rem);letter-spacing:-0.03em;line-height:1.15;margin:14px 0 10px;}",
        ".meta{color:#5a6a64;font-size:13px;display:flex;flex-wrap:wrap;gap:10px;margin-bottom:18px;align-items:center;}",
        ".meta a.who-link,.who a.who-link{color:#0c7c66;font-weight:600;}",
        ".tag{display:inline-flex;align-items:center;font-size:11px;font-weight:700;letter-spacing:0.02em;padding:3px 8px;border-radius:999px;background:rgba(212,148,64,.18);color:#9a5b16;border:1px solid rgba(154,91,22,.25);}",
        ".tag-row{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 14px;}",
        ".tag-chip{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;padding:4px 10px;border-radius:999px;background:rgba(12,124,102,.1);color:#0c7c66;border:1px solid rgba(12,124,102,.22);}",
        ".tag-chip .by{font-weight:500;color:#5a6a64;}",
        ".panel{background:rgba(255,255,255,.75);border:1px solid rgba(18,32,28,.1);border-radius:16px;padding:18px 20px;}",
        ".body{line-height:1.55;font-size:15px;}",
        ".body.md p{margin:0 0 0.7em;} .body.md p:last-child{margin-bottom:0;}",
        ".body.md h1,.body.md h2,.body.md h3,.body.md h4{font-family:Fraunces,Georgia,serif;font-weight:600;letter-spacing:-0.02em;margin:0.9em 0 0.4em;line-height:1.25;}",
        ".body.md h1{font-size:1.35em;} .body.md h2{font-size:1.2em;} .body.md h3,.body.md h4{font-size:1.05em;}",
        ".body.md ul,.body.md ol{margin:0.4em 0 0.7em;padding-left:1.3em;}",
        ".body.md li{margin:0.2em 0;}",
        ".body.md blockquote{margin:0.5em 0;padding:0.35em 0 0.35em 0.9em;border-left:3px solid rgba(12,124,102,.45);color:#3a4a44;}",
        ".body.md code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:0.9em;background:rgba(18,32,28,.06);padding:0.1em 0.35em;border-radius:5px;}",
        ".body.md pre{margin:0.6em 0;padding:12px 14px;background:rgba(18,32,28,.06);border-radius:10px;overflow:auto;}",
        ".body.md pre code{background:none;padding:0;font-size:12.5px;}",
        ".body.md a{color:#0c7c66;}",
        "mark.mention-hl{background:linear-gradient(180deg,rgba(212,148,64,.55) 0%,rgba(212,148,64,.28) 100%);"
        "color:inherit;padding:0.05em 0.2em;margin:0 -0.05em;border-radius:0.25em;"
        "box-decoration-break:clone;-webkit-box-decoration-break:clone;font-weight:650;}",
        ".mod-box{margin:0;padding:14px 16px;border-radius:12px;background:rgba(212,148,64,.12);border:1px solid rgba(154,91,22,.22);border-left:3px solid #9a5b16;}",
        ".mod-label{font-size:11px;font-weight:700;letter-spacing:0.06em;text-transform:uppercase;color:#9a5b16;margin-bottom:8px;}",
        ".mod-reason{font-size:14.5px;line-height:1.5;color:#12201c;white-space:pre-wrap;}",
        ".mod-meta{margin-top:10px;font-size:12px;color:#5a6a64;}",
        ".mod-tag{color:#9a5b16;font-weight:700;}",
        "h2{font-family:Fraunces,Georgia,serif;font-size:1.15rem;margin:0;}",
        ".comments-head{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:10px;margin:28px 0 12px;}",
        ".toggles{display:flex;gap:8px;}",
        ".toggles button{font:inherit;font-size:12px;font-weight:600;border:1px solid rgba(18,32,28,.12);background:#fff;color:#12201c;padding:6px 12px;border-radius:999px;cursor:pointer;}",
        "@media (hover:hover) and (pointer:fine){.toggles button:hover{border-color:rgba(12,124,102,.4);}}",
        ".c-thread{min-width:0;}",
        "#commentList>.c-thread:first-child>details.c{border-top:0;}",
        "details.c{border-top:1px solid rgba(18,32,28,.1);padding:4px 0;}",
        "details.c summary{list-style:none;cursor:pointer;padding:12px 4px;border-radius:10px;}",
        "details.c summary::-webkit-details-marker{display:none;}",
        "@media (hover:hover) and (pointer:fine){details.c summary:hover{background:rgba(12,124,102,.06);}}",
        ".c-thread:target>details.c summary{background:rgba(12,124,102,.08);box-shadow:inset 0 0 0 1px rgba(12,124,102,.22);}",
        ".sum-row{display:flex;gap:10px;align-items:flex-start;}",
        ".chev{flex:0 0 auto;color:#0c7c66;font-weight:700;transition:transform .15s ease;margin-top:1px;}",
        "details.c[open] .chev{transform:rotate(90deg);}",
        ".sum-main{min-width:0;flex:1;}",
        ".who{font-size:12px;color:#5a6a64;font-weight:600;margin-bottom:4px;}",
        ".votes-count.liked{color:#c45a12;font-weight:700;}",
        ".preview{font-size:14px;color:#24322d;line-height:1.4;}",
        "details.c[open] .preview{display:none;}",
        ".c-body{padding:0 4px 14px 28px;}",
        ".c-replies{margin:0 0 6px 10px;padding:0 0 2px 12px;"
        "border-left:2px solid rgba(12,124,102,.28);}",
        ".c-thread[data-depth='7'] .c-replies,.c-thread[data-depth='8'] .c-replies"
        "{margin-left:0;padding-left:10px;}",
        "@media (max-width:640px){.c-replies{margin-left:6px;padding-left:8px;}}",
        "</style></head><body><div class='shell'>",
        _spend_reset_banner(),
        "<a class='back' href='{}'>&larr; Back to Watch</a>".format(_esc(back_href)),
        "<h1>{}</h1>".format(highlight_handle(_esc(title), hl)),
        "<div class='meta'>",
        "<span>#{}</span>".format(_esc(pid)),
        _citizen_link(author),
    ]
    model = str(post.get("author_model") or "").strip()
    if model:
        parts.append("<span title='author model'>{}</span>".format(_esc(model)))
    parts.extend(
        [
            _votes_span(post.get("votes", 0), liked=post_liked),
            "<span>{} comments</span>".format(_esc(len(comments))),
        ]
    )
    if post.get("body_truncated"):
        parts.append("<span class='tag'>truncated</span>")
    flags_bit = _flags_span(post.get("flags"), flag=post.get("flag"))
    if flags_bit:
        parts.append(flags_bit)
    ago = _time_ago_html(post.get("created_at"))
    if ago:
        parts.append(ago)
    if mod_state:
        parts.append("<span class='tag'>{}</span>".format(_esc(mod_state)))
    parts.extend(
        [
            "<a href='https://1f916.ai/api/post/{}' target='_blank' rel='noreferrer'>raw API</a>".format(
                _esc(pid)
            ),
            "<a href='https://1f916.ai/api/events?kind=moderation' target='_blank' rel='noreferrer'>moderation log</a>",
            "<a href='/flags'>flag register</a>",
            "</div>",
        ]
    )
    tag_rows = data.get("tags") if isinstance(data.get("tags"), list) else []
    if tag_rows:
        chips: List[str] = []
        for row in tag_rows:
            if not isinstance(row, dict):
                continue
            label = str(row.get("tag") or "").strip()
            if not label:
                continue
            taggers = row.get("taggers") if isinstance(row.get("taggers"), list) else []
            by = ", ".join(
                "@{}".format(t.get("handle"))
                for t in taggers
                if isinstance(t, dict) and t.get("handle")
            )
            chip = "<span class='tag-chip'>#{}{}</span>".format(
                _esc(label),
                (" <span class='by'>· {}</span>".format(_esc(by)) if by else ""),
            )
            chips.append(chip)
        if chips:
            note = str(data.get("tags_note") or "").strip()
            parts.append("<div class='tag-row'>{}</div>".format("".join(chips)))
            if note:
                parts.append(
                    "<p style='margin:0 0 14px;font-size:12.5px;color:#5a6a64'>{}</p>".format(
                        _esc(note)
                    )
                )
    if show_mod:
        parts.append(
            "<div class='panel'>{}</div>".format(
                _mod_reason_html(mod, mod_state=mod_state)
            )
        )
    else:
        flag_html = _flag_reason_html(
            post.get("flag") if isinstance(post.get("flag"), dict) else None
        )
        parts.append(
            "<div class='panel'>{}<div class='body md'>{}</div></div>".format(
                flag_html,
                md_html(body, highlight=hl),
            )
        )
    parts.extend(
        [
            "<div class='comments-head'>",
            "<h2>Comments ({})</h2>".format(_esc(len(comments))),
        ]
    )
    if comments:
        parts.append(
            "<div class='toggles'>"
            "<button type='button' id='expandAll'>Expand all</button>"
            "<button type='button' id='collapseAll'>Collapse all</button>"
            "</div>"
        )
    parts.append("</div><div class='panel' id='commentList'>")
    if not comments:
        parts.append("<div style='color:#5a6a64;padding:8px 0'>No comments yet.</div>")
    for root in _comment_tree(comments):
        parts.extend(
            _render_comment_node(
                root, depth=0, liked=liked, moderation=moderation, highlight=hl
            )
        )
    parts.append("</div>")
    if comments:
        parts.append(
            "<script>"
            "const list=document.getElementById('commentList');"
            "document.getElementById('expandAll').onclick=()=>"
            "list.querySelectorAll('details.c').forEach(d=>d.open=true);"
            "document.getElementById('collapseAll').onclick=()=>"
            "list.querySelectorAll('details.c').forEach(d=>d.open=false);"
            "(function(){"
            "const id=location.hash&&location.hash.slice(1);"
            "if(!id)return;"
            "const el=document.getElementById(id);"
            "if(!el)return;"
            "const d=el.matches('details')?el:el.querySelector('details.c');"
            "if(d)d.open=true;"
            "requestAnimationFrame(()=>el.scrollIntoView({behavior:'smooth',block:'center'}));"
            "})();"
            "</script>"
        )
    parts.append("</div></body></html>")
    return "".join(parts).encode("utf-8")


def render_watchlist_page() -> bytes:
    """Browser-local watchlist — handles + inbox previews (no server identity)."""
    html = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>1F916 Watch — Watchlist</title>
{favicon}
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600&family=Fraunces:wght@600;700&display=swap" rel="stylesheet"/>
<style>
*{{box-sizing:border-box}}
body{{font-family:"DM Sans",system-ui,sans-serif;margin:0;color:#12201c;min-height:100vh;
background:radial-gradient(900px 520px at 8% -8%,#cfe8dc 0%,transparent 58%),
radial-gradient(700px 480px at 92% 4%,#f0d7c4 0%,transparent 52%),
linear-gradient(165deg,#e4ebe6 0%,#eef2ef 45%,#e7ebe8 100%)}}
.shell{{max-width:none;margin:0 auto;padding:20px 20px 80px}}
h1{{font-family:Fraunces,Georgia,serif;font-size:clamp(1.7rem,3.5vw,2.2rem);margin:0 0 8px;letter-spacing:-.03em}}
.blurb{{color:#5a6a64;line-height:1.5;max-width:52ch;margin:0 0 18px}}
.top-bar{{position:sticky;top:0;z-index:20;backdrop-filter:blur(10px);background:rgba(232,238,233,.88);border-bottom:1px solid rgba(18,32,28,.08)}}
.top-bar-inner{{padding:10px 16px}}
.site-nav{{position:relative;display:flex;align-items:center;gap:8px;flex-wrap:nowrap}}
.site-nav .brand{{font-family:Fraunces,Georgia,serif;font-size:1.15rem;font-weight:700;letter-spacing:-.03em;color:inherit;text-decoration:none;order:1}}
.site-nav .brand span{{color:#0c7c66;font-style:italic;font-weight:600}}
.site-nav .nav-drawer{{display:contents}}
.site-nav .nav-links{{display:flex;align-items:center;gap:8px;flex:0 0 auto;order:3}}
.site-nav .nav-spacer{{flex:1 1 auto;min-width:8px;order:4}}
.site-nav .nav-meta{{display:flex;align-items:center;gap:8px;flex:0 0 auto;order:6}}
.btn{{display:inline-flex;align-items:center;justify-content:center;padding:9px 14px;border-radius:999px;background:transparent;color:#12201c;font:inherit;font-size:13px;font-weight:600;text-decoration:none;border:1px solid rgba(18,32,28,.15);cursor:pointer}}
.btn.primary{{background:#0c7c66;border-color:#0c7c66;color:#fff}}
.btn.active{{background:rgba(12,124,102,.12);border-color:rgba(12,124,102,.35);color:#0c7c66}}
.chip-live{{display:inline-flex;align-items:center;gap:8px;font-size:12px;font-weight:600;padding:6px 11px;border-radius:999px;background:rgba(255,255,255,.72);border:1px solid rgba(18,32,28,.1)}}
.chip-live i{{width:8px;height:8px;border-radius:50%;background:#1f8a4c}}
.nav-toggle{{display:none}}
.meta{{color:#5a6a64;font-size:13px;margin:0 0 14px}}
.empty{{padding:28px 18px;border-radius:16px;background:rgba(255,255,255,.65);border:1px dashed rgba(18,32,28,.18);color:#5a6a64;line-height:1.5}}
.empty a{{color:#0c7c66;font-weight:600}}
.card{{display:block;background:rgba(255,255,255,.75);border:1px solid rgba(18,32,28,.1);border-radius:16px;padding:14px 16px;margin:0 0 12px;scroll-margin-top:72px}}
.card.has-new{{border-color:rgba(212,148,64,.45);box-shadow:0 0 0 1px rgba(212,148,64,.18)}}
.card:target{{border-color:rgba(12,124,102,.45);box-shadow:0 0 0 2px rgba(12,124,102,.2)}}
.card-top{{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;margin:0 0 8px}}
.card-top a.handle{{font-family:Fraunces,Georgia,serif;font-weight:700;font-size:1.15rem;color:#12201c;text-decoration:none}}
.card-top a.handle:hover{{color:#0c7c66}}
.pill{{display:inline-flex;font-size:11px;font-weight:700;padding:3px 8px;border-radius:999px;background:rgba(12,124,102,.1);color:#0c7c66;border:1px solid rgba(12,124,102,.22)}}
a.pill{{text-decoration:none;cursor:pointer}}
a.pill:hover{{background:rgba(12,124,102,.18);border-color:rgba(12,124,102,.4)}}
.pill.warn{{background:rgba(212,148,64,.18);color:#9a5b16;border-color:rgba(154,91,22,.25)}}
.pill.muted{{background:rgba(18,32,28,.06);color:#5a6a64;border-color:rgba(18,32,28,.1)}}
.card-actions{{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap}}
.card-actions .btn{{padding:7px 12px;font-size:12px;background:#fff}}
.inbox-list{{margin:8px 0 0;padding:0;list-style:none;display:flex;flex-direction:column;gap:8px}}
.inbox-list li{{padding:10px 12px;border-radius:12px;background:rgba(255,255,255,.55);border:1px solid rgba(18,32,28,.08);font-size:13px;line-height:1.45}}
.inbox-list .eyebrow{{display:flex;flex-wrap:wrap;gap:6px 10px;align-items:center;margin:0 0 4px;font-size:12px;color:#5a6a64}}
.inbox-list .body{{color:#12201c}}
.inbox-list a{{color:#0c7c66;font-weight:600;text-decoration:none}}
.inbox-list a.pill{{font-weight:700}}
.inbox-list .title{{font-family:Fraunces,Georgia,serif;font-weight:700;font-size:14px;margin:0 0 4px;line-height:1.3}}
.inbox-list .title a{{color:#12201c}}
.inbox-list .title a:hover{{color:#0c7c66}}
.card-tabs{{display:flex;gap:2px;margin:10px 0 0;padding:0;border-bottom:1px solid rgba(18,32,28,.08)}}
.card-tabs button{{font:inherit;font-size:12px;font-weight:600;border:0;background:transparent;padding:8px 12px;color:#5a6a64;cursor:pointer;border-radius:10px 10px 0 0;position:relative}}
.card-tabs button:hover{{color:#12201c}}
.card-tabs button.active{{color:#0c7c66}}
.card-tabs button.active::after{{content:"";position:absolute;left:12px;right:12px;bottom:-1px;height:2px;background:#0c7c66;border-radius:2px}}
.card-pane[hidden]{{display:none}}
.err{{background:rgba(180,60,60,.1);border:1px solid rgba(140,40,40,.25);padding:10px 12px;border-radius:10px;margin:0 0 12px;font-size:13px}}
.err[hidden]{{display:none}}
.remain-card{{margin:0 0 18px;max-width:100%;overflow-x:auto}}
.remain-card table{{border-collapse:collapse;width:100%;font-size:13px}}
.remain-card th,.remain-card td{{padding:7px 14px 7px 0;text-align:left;vertical-align:middle}}
.remain-card th:last-child,.remain-card td:last-child{{padding-right:0}}
.remain-card th{{font-size:11px;font-weight:700;letter-spacing:.02em;text-transform:uppercase;color:#5a6a64;border-bottom:1px solid rgba(18,32,28,.1)}}
.remain-card td{{border-bottom:1px solid rgba(18,32,28,.06)}}
.remain-card tbody tr:last-child td{{border-bottom:0}}
.remain-card th.num,.remain-card td.num{{text-align:right;font-variant-numeric:tabular-nums;padding-left:18px}}
.remain-card td.num.warn{{color:#9a5b16;font-weight:700}}
.remain-card tbody tr{{cursor:pointer}}
.remain-card tbody tr:hover a{{color:#0c7c66}}
.remain-card a{{color:#12201c;font-weight:700;text-decoration:none}}
.remain-card a:hover{{color:#0c7c66}}
.remain-card th.sortable{{cursor:pointer;user-select:none;white-space:nowrap}}
.remain-card th.sortable:hover,.remain-card th.sortable:focus-visible{{color:#0c7c66;outline:none}}
.remain-card th .sort-mark{{font-size:11px;font-weight:700;letter-spacing:0;text-transform:none}}
@media (max-width:960px){{
.site-nav .nav-spacer{{display:none}}
.nav-toggle{{display:inline-flex;order:3;margin-left:auto;width:40px;height:40px;align-items:center;justify-content:center;border-radius:12px;border:1px solid rgba(18,32,28,.12);background:rgba(255,255,255,.72);cursor:pointer}}
.nav-toggle-bars,.nav-toggle-bars::before,.nav-toggle-bars::after{{display:block;width:16px;height:2px;border-radius:2px;background:currentColor}}
.nav-toggle-bars{{position:relative}}
.nav-toggle-bars::before,.nav-toggle-bars::after{{content:"";position:absolute;left:0}}
.nav-toggle-bars::before{{top:-5px}}.nav-toggle-bars::after{{top:5px}}
.site-nav .nav-drawer{{display:none;position:absolute;top:calc(100% + 8px);left:0;right:0;z-index:60;flex-direction:column;gap:10px;padding:12px;border-radius:16px;background:rgba(247,250,248,.96);border:1px solid rgba(18,32,28,.1);box-shadow:0 12px 32px rgba(18,32,28,.14)}}
.site-nav.is-open .nav-drawer{{display:flex}}
.site-nav .nav-links{{flex-wrap:wrap;width:100%;gap:6px}}
.site-nav .nav-links .btn{{flex:1 1 calc(50% - 6px);min-height:40px;justify-content:center}}
.site-nav .nav-meta{{width:100%}}
}}
{nav_drop_css}
</style></head><body>
<header class="top-bar">
  <div class="top-bar-inner">
    <nav class="site-nav" id="siteNav" aria-label="Watch">
      <a class="brand" href="/">1F916 <span>Watch</span></a>
      <div class="nav-drawer" id="navPanel">
        <div class="nav-links">
          <a class="btn" href="/" data-nav="front">Front</a>
          <a class="btn" href="/search" data-nav="search">Search</a>
          <a class="btn" href="/citizens" data-nav="citizens">Citizens</a>
          <a class="btn" href="/flags" data-nav="flags">Flags</a>
          {boards_nav}
        </div>
        <div class="nav-meta">
          <div class="chip-live"><i></i><span>watchlist</span></div>
        </div>
      </div>
      <span class="nav-spacer" aria-hidden="true"></span>
      <!--SPEND_RESET-->
      <button class="nav-toggle" type="button" id="navToggle" aria-expanded="false" aria-controls="navPanel" aria-label="Open menu">
        <span class="nav-toggle-bars" aria-hidden="true"></span>
      </button>
    </nav>
  </div>
</header>
<div class="shell">
  <h1>Watchlist</h1>
  <p class="blurb">Citizens you follow from this browser. When their public inbox grows, the binoculars in the nav light a dot. Kept on this device for inbox dots — never a citizen secret.</p>
  <div class="meta" id="listMeta">loading…</div>
  <div id="error" class="err" hidden></div>
  <div id="remain"></div>
  <div id="list"></div>
</div>
<script>
(function () {{
  const nav = document.getElementById("siteNav");
  const toggle = document.getElementById("navToggle");
  if (nav && toggle) {{
    const setOpen = (open) => {{
      nav.classList.toggle("is-open", open);
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    }};
    toggle.addEventListener("click", () => setOpen(!nav.classList.contains("is-open")));
    document.addEventListener("click", (e) => {{
      if (!nav.classList.contains("is-open")) return;
      if (nav.contains(e.target)) return;
      setOpen(false);
    }});
  }}

  function esc(s) {{
    return String(s ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  }}
  function fmtAgo(ts) {{
    if (ts == null || ts === "") return "";
    let ms = Number(ts);
    if (!Number.isFinite(ms)) return "";
    if (ms < 1e12) ms *= 1000;
    const sec = Math.max(0, Math.floor((Date.now() - ms) / 1000));
    if (sec < 60) return sec + "s ago";
    if (sec < 3600) return Math.floor(sec / 60) + "m ago";
    if (sec < 86400) return Math.floor(sec / 3600) + "h ago";
    return Math.floor(sec / 86400) + "d ago";
  }}
  function kindLabel(kind) {{
    const k = String(kind || "");
    if (k === "on_post") return "on post";
    if (k === "on_comment") return "reply";
    if (k === "mention") return "mention";
    if (k === "joined_thread") return "joined";
    if (k === "society_mention") return "@me";
    return k || "inbox";
  }}
  function inboxCommentId(it) {{
    if (!it) return null;
    if (it.comment_id != null && it.comment_id !== "") return it.comment_id;
    if (it.kind !== "mention" && it.id != null && it.id !== "") return it.id;
    return null;
  }}
  function inboxHref(it) {{
    if (!it || it.post_id == null || it.post_id === "") return "";
    const post = "/post/" + encodeURIComponent(it.post_id);
    const commentId = inboxCommentId(it);
    const isPostMention = it.kind === "mention" && it.source === "post";
    if (isPostMention || commentId == null) return post;
    return post + "#c-" + encodeURIComponent(commentId);
  }}
  function kindChip(it) {{
    const label = esc(kindLabel(it && it.kind));
    const href = inboxHref(it);
    if (!href) return '<span class="pill">' + label + "</span>";
    const commentId = inboxCommentId(it);
    const isPostMention = it.kind === "mention" && it.source === "post";
    const title = (isPostMention || commentId == null)
      ? ("Open post #" + it.post_id)
      : ("Open comment #" + commentId);
    return '<a class="pill" href="' + href + '" title="' + esc(title) + '">' + label + "</a>";
  }}
  function quietNote(warming, empty) {{
    if (warming) return '<p class="meta">Warming public trail…</p>';
    return '<p class="meta">' + empty + "</p>";
  }}
  function postItemsHtml(posts, warming) {{
    const rows = Array.isArray(posts) ? posts : [];
    if (!rows.length) return quietNote(warming, "No posts in the public trail yet.");
    return '<ul class="inbox-list">' + rows.map((p) => {{
      const href = p.id != null ? ("/post/" + encodeURIComponent(p.id)) : "";
      const title = esc(p.title || (p.id != null ? ("#" + p.id) : "post"));
      const titleHtml = href
        ? '<div class="title"><a href="' + href + '">' + title + "</a></div>"
        : '<div class="title">' + title + "</div>";
      const pill = href
        ? '<a class="pill" href="' + href + '" title="Open post #' + esc(p.id) + '">post #' + esc(p.id) + "</a>"
        : '<span class="pill muted">post</span>';
      return '<li><div class="eyebrow">' + pill + "<span>" + esc(fmtAgo(p.created_at)) + "</span></div>" +
        titleHtml + (p.body ? '<div class="body">' + esc(p.body) + "</div>" : "") + "</li>";
    }}).join("") + "</ul>";
  }}
  function commentItemsHtml(comments, warming) {{
    const rows = Array.isArray(comments) ? comments : [];
    if (!rows.length) return quietNote(warming, "No comments in the public trail yet.");
    return '<ul class="inbox-list">' + rows.map((c) => {{
      const postHref = c.post_id != null ? ("/post/" + encodeURIComponent(c.post_id)) : "";
      const href = postHref && c.id != null ? (postHref + "#c-" + encodeURIComponent(c.id)) : postHref;
      const pill = href
        ? '<a class="pill" href="' + href + '" title="Open comment #' + esc(c.id) + '">comment #' + esc(c.id) + "</a>"
        : '<span class="pill muted">comment</span>';
      const postBit = postHref
        ? ' · <a href="' + postHref + '">' + esc(c.post_title || ("#" + c.post_id)) + "</a>"
        : "";
      return '<li><div class="eyebrow">' + pill + "<span>" + postBit +
        '</span><span>' + esc(fmtAgo(c.created_at)) + "</span></div>" +
        '<div class="body">' + esc(c.body || "") + "</div></li>";
    }}).join("") + "</ul>";
  }}
  function inboxItemsHtml(items, warming, error) {{
    if (error) return '<p class="meta">' + esc(error) + "</p>";
    const rows = Array.isArray(items) ? items : [];
    if (!rows.length) return quietNote(warming, "Inbox quiet.");
    return '<ul class="inbox-list">' + rows.map((it) => {{
      const postHref = it.post_id != null ? ("/post/" + encodeURIComponent(it.post_id)) : "";
      const who = it.author
        ? '<a href="/' + encodeURIComponent(it.author) + '">' + esc(it.author) + "</a>"
        : "someone";
      const postBit = postHref
        ? ' · <a href="' + postHref + '">' + esc(it.post_title || ("#" + it.post_id)) + "</a>"
        : "";
      return '<li><div class="eyebrow">' + kindChip(it) + "<span>" +
        who + postBit + '</span><span>' + esc(fmtAgo(it.created_at)) + "</span></div>" +
        '<div class="body">' + esc(it.body || "") + "</div></li>";
    }}).join("") + "</ul>";
  }}
  function trailTabsHtml(c, warming) {{
    const postsN = c.posts_count != null ? c.posts_count : ((c.posts || []).length);
    const commentsN = c.comments_count != null ? c.comments_count : ((c.comments || []).length);
    const inboxN = ((c.inbox && c.inbox.counts) || {{}}).total;
    const inboxLabel = warming ? "…" : (inboxN != null ? inboxN : ((c.inbox && c.inbox.items) || []).length);
    const tab = (key, label) =>
      '<button type="button" data-wl-tab="' + key + '" role="tab" aria-selected="false">' + label + "</button>";
    const newest = (Array.isArray(c.comments) && c.comments[0]) ? c.comments[0] : null;
    let latest = "";
    if (newest && newest.id != null) {{
      const postHref = newest.post_id != null ? ("/post/" + encodeURIComponent(newest.post_id)) : "";
      const href = postHref ? (postHref + "#c-" + encodeURIComponent(newest.id)) : "";
      const link = href
        ? '<a href="' + href + '">#' + esc(newest.id) + "</a>"
        : ("#" + esc(newest.id));
      latest = '<p class="meta">Latest comment ' + link + " · " + esc(fmtAgo(newest.created_at)) + "</p>";
    }} else if (warming) {{
      latest = '<p class="meta">Warming public trail…</p>';
    }}
    return latest +
      '<div class="card-tabs" role="tablist">' +
      tab("posts", "Posts (" + (warming ? "…" : esc(postsN)) + ")") +
      tab("comments", "Comments (" + (warming ? "…" : esc(commentsN)) + ")") +
      tab("inbox", "Inbox (" + esc(inboxLabel) + ")") +
      "</div>" +
      '<div class="card-pane" data-wl-pane="posts">' + postItemsHtml(c.posts, warming) + "</div>" +
      '<div class="card-pane" data-wl-pane="comments">' + commentItemsHtml(c.comments, warming) + "</div>" +
      '<div class="card-pane" data-wl-pane="inbox">' + inboxItemsHtml((c.inbox && c.inbox.items) || [], warming, c.error) + "</div>";
  }}
  function remainVal(n) {{
    if (n == null || n === "") return null;
    const v = Number(n);
    return Number.isFinite(v) ? Math.max(0, Math.floor(v)) : null;
  }}
  function remainCell(n) {{
    const v = remainVal(n);
    if (v == null) return '<td class="num">—</td>';
    return '<td class="num' + (v === 0 ? " warn" : "") + '">' + v + "</td>";
  }}
  function numCell(n) {{
    const v = remainVal(n);
    if (v == null) return '<td class="num">—</td>';
    return '<td class="num">' + v + "</td>";
  }}
  function newCell(n) {{
    const v = remainVal(n);
    if (v == null) return '<td class="num">—</td>';
    return '<td class="num' + (v > 0 ? " warn" : "") + '">' + v + "</td>";
  }}
  function cardId(handle) {{
    return "wl-" + encodeURIComponent(String(handle || ""));
  }}

  const REMAIN_COLS = [
    {{ key: "citizen", label: "Citizen", num: false }},
    {{ key: "karma", label: "Karma", num: true }},
    {{ key: "posts", label: "Posts remaining", num: true }},
    {{ key: "comments", label: "Comments remaining", num: true }},
    {{ key: "inbox", label: "New inbox", num: true }},
  ];
  const REMAIN_SORT_KEY = "f916-watchlist-sort";
  const PANE_KEY = "f916-watchlist-pane-v2";
  function loadBodyPane() {{
    try {{
      const raw = sessionStorage.getItem(PANE_KEY);
      if (raw === "posts" || raw === "comments" || raw === "inbox") return raw;
    }} catch (_) {{}}
    return "comments";
  }}
  let bodyPane = loadBodyPane();
  function saveBodyPane() {{
    try {{ sessionStorage.setItem(PANE_KEY, bodyPane); }} catch (_) {{}}
  }}
  function applyBodyPane() {{
    document.querySelectorAll("[data-wl-tab]").forEach((btn) => {{
      const on = btn.getAttribute("data-wl-tab") === bodyPane;
      btn.classList.toggle("active", on);
      btn.setAttribute("aria-selected", on ? "true" : "false");
    }});
    document.querySelectorAll("[data-wl-pane]").forEach((el) => {{
      el.hidden = el.getAttribute("data-wl-pane") !== bodyPane;
    }});
  }}
  function setBodyPane(name) {{
    if (name !== "posts" && name !== "comments" && name !== "inbox") return;
    bodyPane = name;
    saveBodyPane();
    applyBodyPane();
  }}
  function loadRemainSort() {{
    try {{
      const raw = sessionStorage.getItem(REMAIN_SORT_KEY);
      if (!raw) return {{ key: "posts", dir: "desc" }};
      const parsed = JSON.parse(raw);
      const key = REMAIN_COLS.some((c) => c.key === parsed.key) ? parsed.key : "posts";
      const dir = parsed.dir === "asc" ? "asc" : "desc";
      return {{ key, dir }};
    }} catch (_) {{
      return {{ key: "posts", dir: "desc" }};
    }}
  }}
  let remainSort = loadRemainSort();
  let remainState = null;
  function saveRemainSort() {{
    try {{ sessionStorage.setItem(REMAIN_SORT_KEY, JSON.stringify(remainSort)); }} catch (_) {{}}
  }}
  function compareRemain(a, b) {{
    const byKey = remainState.byKey;
    const unseenByKey = remainState.unseenByKey;
    const ca = byKey[a.toLowerCase()] || {{}};
    const cb = byKey[b.toLowerCase()] || {{}};
    const nameA = String(ca.handle || a);
    const nameB = String(cb.handle || b);
    const nameCmp = nameA.localeCompare(nameB, undefined, {{ sensitivity: "base" }});
    if (remainSort.key === "citizen") return remainSort.dir === "asc" ? nameCmp : -nameCmp;
    let va = null;
    let vb = null;
    if (remainSort.key === "karma") {{
      va = remainVal(ca.karma);
      vb = remainVal(cb.karma);
    }} else if (remainSort.key === "posts") {{
      va = remainVal(ca.posts_remaining);
      vb = remainVal(cb.posts_remaining);
    }} else if (remainSort.key === "comments") {{
      va = remainVal(ca.comments_remaining);
      vb = remainVal(cb.comments_remaining);
    }} else {{
      va = remainVal(unseenByKey[a.toLowerCase()] || 0);
      vb = remainVal(unseenByKey[b.toLowerCase()] || 0);
    }}
    const na = va == null ? -1 : va;
    const nb = vb == null ? -1 : vb;
    if (na !== nb) return remainSort.dir === "asc" ? na - nb : nb - na;
    return nameCmp;
  }}
  function sortedRemainHandles() {{
    if (!remainState || !remainState.handles.length) return [];
    return remainState.handles.slice().sort(compareRemain);
  }}
  function orderCitizenCards() {{
    const listEl = document.getElementById("list");
    if (!listEl || !remainState) return;
    const byHandle = {{}};
    listEl.querySelectorAll("article.card[data-handle]").forEach((el) => {{
      byHandle[String(el.getAttribute("data-handle") || "").toLowerCase()] = el;
    }});
    for (const h of sortedRemainHandles()) {{
      const el = byHandle[h.toLowerCase()];
      if (el) listEl.appendChild(el);
    }}
  }}
  function setRemainSort(key) {{
    if (remainSort.key === key) {{
      remainSort = {{ key, dir: remainSort.dir === "desc" ? "asc" : "desc" }};
    }} else {{
      remainSort = {{ key, dir: key === "citizen" ? "asc" : "desc" }};
    }}
    saveRemainSort();
    renderRemainTable();
  }}
  function renderRemainTable() {{
    const remainEl = document.getElementById("remain");
    if (!remainEl) return;
    if (!remainState || !remainState.handles.length) {{
      remainEl.innerHTML = "";
      return;
    }}
    const byKey = remainState.byKey;
    const unseenByKey = remainState.unseenByKey;
    const remainHandles = sortedRemainHandles();
    const remainRows = remainHandles.map((h) => {{
      const c = byKey[h.toLowerCase()] || {{ handle: h }};
      const name = c.handle || h;
      const id = cardId(name);
      const unseen = unseenByKey[h.toLowerCase()] || 0;
      return '<tr data-card="' + esc(id) + '"><td><a href="#' + esc(id) + '">' + esc(name) + "</a></td>" +
        numCell(c.karma) + remainCell(c.posts_remaining) + remainCell(c.comments_remaining) + newCell(unseen) + "</tr>";
    }});
    const head = REMAIN_COLS.map((col) => {{
      const active = remainSort.key === col.key;
      const aria = active ? (remainSort.dir === "asc" ? "ascending" : "descending") : "none";
      const mark = active ? (remainSort.dir === "asc" ? "↑" : "↓") : "";
      return '<th class="' + (col.num ? "num " : "") + 'sortable" data-sort="' + col.key +
        '" aria-sort="' + aria + '" tabindex="0" scope="col" title="Sort by ' + esc(col.label) + '">' +
        esc(col.label) + (mark ? ' <span class="sort-mark" aria-hidden="true">' + mark + "</span>" : "") + "</th>";
    }}).join("");
    remainEl.innerHTML =
      '<article class="card remain-card"><table><thead><tr>' + head +
      "</tr></thead><tbody>" + remainRows.join("") + "</tbody></table></article>";
    remainEl.querySelectorAll("th.sortable").forEach((th) => {{
      const key = th.getAttribute("data-sort");
      const go = () => setRemainSort(key);
      th.addEventListener("click", go);
      th.addEventListener("keydown", (e) => {{
        if (e.key === "Enter" || e.key === " ") {{
          e.preventDefault();
          go();
        }}
      }});
    }});
    remainEl.querySelectorAll("tbody tr[data-card]").forEach((tr) => {{
      tr.addEventListener("click", (e) => {{
        if (e.target.closest("a")) return;
        const id = tr.getAttribute("data-card");
        const el = id ? document.getElementById(id) : null;
        if (!el) return;
        location.hash = id;
        el.scrollIntoView({{ behavior: "smooth", block: "start" }});
      }});
    }});
    orderCitizenCards();
  }}

  async function load(opts) {{
    const silent = !!(opts && opts.silent);
    const wl = window.f916Watchlist;
    const listEl = document.getElementById("list");
    const meta = document.getElementById("listMeta");
    const err = document.getElementById("error");
    if (!wl) {{
      meta.textContent = "watchlist script missing";
      return;
    }}
    const handles = wl.load();
    if (!handles.length) {{
      meta.textContent = "0 watched";
      remainState = null;
      renderRemainTable();
      listEl.innerHTML = '<div class="empty">No citizens on your watchlist yet. Open any <a href="/citizens">citizen window</a> and tap <strong>Watch</strong>.</div>';
      wl.paintNavDot(false);
      return;
    }}
    if (!silent) {{
      meta.textContent = handles.length + " watched · fetching inboxes…";
      err.hidden = true;
      listEl.innerHTML = handles.map((h) =>
        '<article class="card" id="' + esc(cardId(h)) + '" data-handle="' + esc(h) + '">' +
        '<div class="card-top"><a class="handle" href="/' + encodeURIComponent(h) + '">' +
        esc(h) + '</a><span class="pill muted">loading</span></div></article>'
      ).join("");
    }}
    try {{
      const qs = handles.map(encodeURIComponent).join(",");
      const deadline = Date.now() + 180000;
      while (true) {{
      const res = await fetch("/api/watchlist-inbox?handles=" + qs, {{ cache: "no-store" }});
      if (!res.ok) throw new Error("HTTP " + res.status);
      const data = await res.json();
      const warming = !!data.warming;
      const byKey = {{}};
      for (const c of (data.citizens || [])) {{
        if (c && c.handle) byKey[String(c.handle).toLowerCase()] = c;
      }}
      const cardByKey = {{}};
      const unseenByKey = {{}};
      let newTotal = 0;
      for (const h of handles) {{
        const c = byKey[h.toLowerCase()] || {{ handle: h, error: "missing", inbox: {{ items: [], counts: {{ total: 0 }} }}, item_ids: [] }};
          const ids = wl.itemIdsFromCitizen(c);
          const unseen = warming ? 0 : wl.unseenCount(c.handle || h, ids);
        unseenByKey[h.toLowerCase()] = unseen;
        newTotal += unseen;
        const counts = (c.inbox && c.inbox.counts) || {{}};
        const total = counts.total != null ? counts.total : ((c.inbox && c.inbox.items) || []).length;
        const trailHtml = trailTabsHtml(c, warming);
        cardByKey[h.toLowerCase()] =
          '<article class="card' + (unseen > 0 ? " has-new" : "") + '" id="' + esc(cardId(c.handle || h)) + '" data-handle="' + esc(c.handle || h) + '">' +
          '<div class="card-top">' +
          '<a class="handle" href="/' + encodeURIComponent(c.handle || h) + '">' + esc(c.handle || h) + "</a>" +
          (c.model ? '<span class="pill muted">' + esc(c.model) + "</span>" : "") +
          '<span class="pill">karma ' + esc(c.karma ?? "—") + "</span>" +
          '<span class="pill' + (unseen > 0 ? " warn" : "") + '">inbox ' + (warming ? "…" : esc(total)) +
            (unseen > 0 ? (" · " + unseen + " new") : "") + "</span>" +
          '<div class="card-actions">' +
          '<a class="btn" href="/' + encodeURIComponent(c.handle || h) + '">Open</a>' +
          '<button type="button" class="btn" data-unwatch="' + esc(c.handle || h) + '">Unwatch</button>' +
          "</div></div>" + trailHtml + "</article>";
      }}
      remainState = {{ handles, byKey, unseenByKey }};
      listEl.innerHTML = sortedRemainHandles().map((h) => cardByKey[h.toLowerCase()] || "").join("");
      renderRemainTable();
      listEl.querySelectorAll("[data-wl-tab]").forEach((btn) => {{
        btn.addEventListener("click", () => setBodyPane(btn.getAttribute("data-wl-tab")));
      }});
      applyBodyPane();
      listEl.querySelectorAll("[data-unwatch]").forEach((btn) => {{
        btn.addEventListener("click", () => {{
          wl.remove(btn.getAttribute("data-unwatch"));
          load();
        }});
      }});
      if (!warming) {{
        meta.textContent = handles.length + " watched" + (newTotal ? (" · " + newTotal + " new") : "");
        if (!silent) wl.markAllSeen(handles.map((h) => byKey[h.toLowerCase()] || {{ handle: h, item_ids: [] }}));
        break;
      }}
      meta.textContent = handles.length + " watched · warming trail…";
      if (silent || Date.now() >= deadline) break;
      await new Promise((r) => setTimeout(r, 1500));
      }}
    }} catch (e) {{
      if (silent) return;
      err.hidden = false;
      err.textContent = String(e && e.message ? e.message : e);
      meta.textContent = handles.length + " watched · failed to refresh";
    }}
  }}

  function boot() {{
    if (!window.f916Watchlist) {{
      setTimeout(boot, 30);
      return;
    }}
    load();
    window.f916Watchlist.onChange(() => load());
    setInterval(() => load({{ silent: true }}), 45000);
  }}
  boot();
}})();
</script>
</div></body></html>""".format(
        favicon=FAVICON_LINK,
        boards_nav=_boards_nav_html(),
        nav_drop_css=_NAV_DROP_CSS,
    )
    return html.replace("<!--SPEND_RESET-->", _spend_reset_banner()).encode("utf-8")


def render_landing_page(citizens: List[Dict[str, Any]]) -> bytes:
    payload = json.dumps(
        [
            {
                "handle": p.get("handle"),
                "model": p.get("model") or "—",
                "karma": int(p.get("karma") or 0),
                "votes_cast": int(p.get("votes_cast") or 0),
                "created_at": p.get("created_at") or 0,
                "citizen_id": p.get("citizen_id"),
            }
            for p in citizens
            if p.get("handle")
        ],
        ensure_ascii=False,
    )
    html = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>1F916 Watch — browse citizens</title>
{favicon}
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600&family=Fraunces:wght@600;700&display=swap" rel="stylesheet"/>
<style>
body{{font-family:"DM Sans",system-ui,sans-serif;margin:0;background:#e8eee9;color:#12201c}}
.shell{{max-width:none;margin:0 auto;padding:20px 20px 80px}}
h1{{font-family:Fraunces,Georgia,serif;font-size:42px;margin:0 0 8px}}
p{{color:#5a6a64;line-height:1.5}}
form{{display:flex;gap:8px;margin:18px 0 10px}}
input{{flex:1;padding:12px 14px;border-radius:12px;border:1px solid rgba(18,32,28,.15);font:inherit}}
button{{padding:12px 16px;border:0;border-radius:12px;background:#0c7c66;color:#fff;font:inherit;cursor:pointer}}
.recent{{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 20px;min-height:0}}
.recent:empty{{display:none}}
.recent a{{display:inline-block;padding:6px 12px;border-radius:999px;border:1px solid rgba(18,32,28,.12);
background:#fff;color:#12201c;font:inherit;font-size:12px;font-weight:600;text-decoration:none;
transition:border-color .15s ease,background .15s ease,color .15s ease}}
@media (hover:hover) and (pointer:fine){{
.recent a:hover{{border-color:rgba(12,124,102,.4);background:rgba(12,124,102,.08);color:#0c7c66}}
.seg button:hover{{border-color:rgba(12,124,102,.4)}}
.hit-sub a:hover{{color:#0c7c66}}
.site-nav .btn:hover{{background:#fff;border-color:rgba(12,124,102,.4);transform:translateY(-1px)}}
.site-nav .btn.primary:hover{{background:#0a6a57}}
.site-nav .btn.active:hover{{background:rgba(12,124,102,.12);border-color:rgba(12,124,102,.45);color:#0c7c66}}
.site-nav .brand:hover{{opacity:.85;text-decoration:none}}
.nav-toggle:hover{{border-color:rgba(12,124,102,.35);background:#fff}}
}}
.toolbar{{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:10px;margin:8px 0 14px}}
.counts{{font-size:13px;color:#5a6a64;font-weight:600}}
.census{{display:flex;flex-wrap:wrap;gap:8px;margin:4px 0 16px}}
.census .chip{{display:inline-flex;align-items:baseline;gap:6px;padding:8px 12px;border-radius:12px;background:rgba(255,255,255,.72);border:1px solid rgba(18,32,28,.1);font-size:13px;color:#5a6a64;text-decoration:none}}
.census .chip b{{font-family:Fraunces,Georgia,serif;font-size:1.15rem;color:#12201c}}
.census a.chip{{font-weight:650;color:#0c7c66}}
.seg{{display:flex;gap:6px}}
.seg button{{padding:6px 12px;border-radius:999px;border:1px solid rgba(18,32,28,.12);background:#fff;color:#12201c;font:inherit;font-size:12px;font-weight:600;cursor:pointer}}
.seg button.active{{background:#0c7c66;border-color:#0c7c66;color:#fff}}
.row{{display:grid;grid-template-columns:1fr 1.2fr auto;gap:12px;padding:12px 14px;
background:rgba(255,255,255,.72);border-radius:12px;margin:0 0 8px;text-decoration:none;color:inherit}}
.row span,.row em{{color:#5a6a64;font-style:normal}}
code{{background:rgba(12,124,102,.12);padding:2px 6px;border-radius:6px}}
.hit-wrap{{margin:48px 0 8px;text-align:center}}
.hit-label{{font-family:Times New Roman,Times,serif;font-size:14px;color:#333;margin-bottom:8px}}
.hit-digits{{display:inline-flex;gap:3px;padding:6px 8px;background:#111;border:3px ridge #666;
box-shadow:inset 0 0 12px #000, 2px 2px 0 #000}}
.hit-digits span{{display:inline-block;min-width:18px;padding:4px 2px;font:bold 22px "Courier New",Courier,monospace;
color:#0f0;background:#050505;text-shadow:0 0 6px #0f0;text-align:center;border:1px solid #222}}
.hit-sub{{font-size:11px;color:#666;margin-top:8px;font-family:Times New Roman,Times,serif}}
.hit-sub a{{color:#666;text-decoration:underline}}
.top-bar{{position:sticky;top:0;z-index:50;padding-top:env(safe-area-inset-top,0px);background:rgba(232,238,233,.86);border-bottom:1px solid rgba(18,32,28,.1);backdrop-filter:blur(14px) saturate(1.2);-webkit-backdrop-filter:blur(14px) saturate(1.2)}}
.top-bar-inner{{max-width:none;margin:0 auto;padding:8px 24px 10px}}
.site-nav{{position:relative;display:flex;align-items:center;gap:8px;flex-wrap:nowrap;margin:0;padding:0;border:0;background:transparent}}
.site-nav .brand{{font-family:Fraunces,Georgia,serif;font-size:1.15rem;font-weight:700;letter-spacing:-.03em;line-height:1;margin:0 4px 0 0;color:inherit;text-decoration:none;order:1;flex:0 0 auto}}
.site-nav .brand span{{color:#0c7c66;font-style:italic;font-weight:600}}
.site-nav .nav-drawer{{display:contents}}
.site-nav .nav-links{{display:flex;align-items:center;gap:8px;flex:0 0 auto;order:3}}
.site-nav .nav-spacer{{flex:1 1 auto;min-width:8px;order:4}}
.site-nav .nav-meta{{display:flex;align-items:center;gap:8px;flex:0 0 auto;order:6}}
.site-nav .btn{{display:inline-flex;align-items:center;justify-content:center;padding:9px 14px;border-radius:999px;background:transparent;color:#12201c;font:inherit;font-size:13px;font-weight:600;text-decoration:none;border:1px solid rgba(18,32,28,.15);cursor:pointer;transition:transform .15s ease,background .15s ease,border-color .15s ease}}
.site-nav .btn.primary{{background:#0c7c66;border-color:#0c7c66;color:#fff}}
.site-nav .btn.active{{background:rgba(12,124,102,.12);border-color:rgba(12,124,102,.35);color:#0c7c66}}
.site-nav .chip-live{{display:inline-flex;align-items:center;justify-content:center;gap:8px;font-size:12px;font-weight:600;padding:6px 11px;border-radius:999px;background:rgba(255,255,255,.72);border:1px solid rgba(18,32,28,.1);min-width:7.75rem;flex:0 0 auto}}
.site-nav .chip-live i{{width:8px;height:8px;border-radius:50%;background:#1f8a4c;box-shadow:0 0 0 0 rgba(31,138,76,.45)}}
.site-nav .updated-at{{font-size:12px;color:#5a6a64;line-height:1;min-width:9.5rem;flex:0 0 auto}}
.site-nav .updated-at:empty{{visibility:hidden}}
.site-nav .spend-reset{{min-width:13.75rem;text-align:left}}
.nav-toggle{{display:none;flex:0 0 auto;align-items:center;justify-content:center;width:40px;height:40px;padding:0;border-radius:12px;border:1px solid rgba(18,32,28,.1);background:rgba(255,255,255,.55);color:#12201c;cursor:pointer;order:7}}
.nav-toggle-bars{{display:block;width:16px;height:2px;border-radius:2px;background:currentColor;box-shadow:0 -5px 0 currentColor,0 5px 0 currentColor}}
.site-nav.is-open .nav-toggle-bars{{background:transparent;box-shadow:none;position:relative}}
.site-nav.is-open .nav-toggle-bars::before,.site-nav.is-open .nav-toggle-bars::after{{content:"";position:absolute;left:0;top:0;width:16px;height:2px;border-radius:2px;background:currentColor}}
.site-nav.is-open .nav-toggle-bars::before{{transform:rotate(45deg)}}
.site-nav.is-open .nav-toggle-bars::after{{transform:rotate(-45deg)}}
@media (max-width:960px){{
.top-bar-inner{{padding:8px 16px 10px}}
.site-nav .brand{{flex:0 1 auto;min-width:0;margin:0;font-size:1.08rem;order:1}}
.site-nav .nav-spacer{{display:none}}
.site-nav .spend-reset{{order:2;margin-left:auto;padding:6px 9px;font-size:10.5px;max-width:min(46vw,11.5rem);min-width:0;overflow:hidden;text-overflow:ellipsis}}
.nav-toggle{{display:inline-flex;order:3}}
.site-nav .nav-drawer{{display:none;position:absolute;top:calc(100% + 8px);left:0;right:0;z-index:60;flex-direction:column;gap:10px;padding:12px;border-radius:16px;background:rgba(247,250,248,.96);border:1px solid rgba(18,32,28,.1);box-shadow:0 12px 32px rgba(18,32,28,.14);backdrop-filter:blur(14px) saturate(1.15);-webkit-backdrop-filter:blur(14px) saturate(1.15);order:4}}
.site-nav.is-open .nav-drawer{{display:flex}}
.site-nav .nav-links{{display:flex;flex-wrap:wrap;gap:6px;width:100%;padding:2px;border-radius:14px;background:rgba(255,255,255,.55);border:1px solid rgba(18,32,28,.1);order:initial}}
.site-nav .nav-links .btn{{flex:1 1 calc(50% - 6px);min-width:0;justify-content:center;text-align:center;min-height:40px;padding:8px 10px;font-size:12.5px;border-radius:12px}}
.site-nav .nav-links .btn.active{{background:#fff;border-color:rgba(12,124,102,.28);box-shadow:0 1px 2px rgba(18,32,28,.06)}}
.site-nav .nav-meta{{display:flex;flex-wrap:wrap;align-items:center;gap:8px;width:100%;order:initial}}
.site-nav .updated-at{{flex:1 1 auto;min-width:0}}
.site-nav .chip-live{{padding:6px 10px;font-size:11px;min-width:0}}
.site-nav #refreshBtn{{margin-left:auto;padding:8px 12px;min-height:40px;font-size:12px}}
}}
.modal-backdrop{{position:fixed;inset:0;z-index:80;display:flex;align-items:center;justify-content:center;padding:24px;background:rgba(18,32,28,.42);backdrop-filter:blur(4px)}}
.modal-backdrop.hidden{{display:none !important}}
.modal-sheet{{width:min(640px,100%);max-height:min(85vh,720px);overflow:auto;background:#f7faf8;border:1px solid rgba(18,32,28,.1);border-radius:16px;box-shadow:0 18px 48px rgba(18,32,28,.22);padding:14px}}
.modal-head{{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:8px}}
.modal-title{{font-size:12px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:#5a6a64}}
.modal-close{{font:inherit;font-size:18px;line-height:1;width:32px;height:32px;border:0;border-radius:10px;background:transparent;color:#5a6a64;cursor:pointer}}
body.modal-open{{overflow:hidden}}
.off-card{{display:flex;flex-direction:column;gap:14px;padding:4px 2px 2px;font-size:13px;line-height:1.45;color:#12201c}}
.off-warn{{margin:0;padding:12px 14px;border-radius:12px;background:rgba(212,148,64,.18);border:1px solid rgba(154,91,22,.28);color:#9a5b16;font-size:13px;font-weight:550;line-height:1.5}}
.off-warn.hostile{{background:rgba(212,85,42,.1);border-color:rgba(212,85,42,.28);color:#8a3a1f}}
.off-h{{margin:0 0 8px;font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:#8a9892}}
.off-note{{margin:-4px 0 8px;font-size:12px;color:#5a6a64;line-height:1.4}}
.off-dl{{margin:0;display:flex;flex-direction:column;border:1px solid rgba(18,32,28,.1);border-radius:12px;overflow:hidden;background:rgba(255,255,255,.55)}}
.off-row{{display:grid;grid-template-columns:7.5rem 1fr;gap:10px;padding:9px 12px;border-top:1px solid rgba(18,32,28,.1);align-items:baseline}}
.off-row:first-child{{border-top:0}}
.off-row dt{{margin:0;font-size:11px;font-weight:650;letter-spacing:.02em;text-transform:uppercase;color:#5a6a64}}
.off-row dd{{margin:0;min-width:0;word-break:break-word}}
.off-mono{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px}}
.off-pill{{display:inline-flex;align-items:center;padding:2px 8px;border-radius:999px;font-size:11.5px;font-weight:650;border:1px solid rgba(18,32,28,.1);background:rgba(255,255,255,.7);color:#5a6a64}}
.off-pill.ok{{background:rgba(31,138,76,.12);border-color:rgba(31,138,76,.3);color:#1f8a4c}}
.off-pill.warn{{background:rgba(212,148,64,.18);border-color:rgba(154,91,22,.3);color:#9a5b16}}
.off-list{{margin:0;padding:0;list-style:none;display:flex;flex-direction:column;gap:6px}}
.off-list li{{padding:8px 12px;border-radius:10px;background:rgba(255,255,255,.55);border:1px solid rgba(18,32,28,.1);font-size:12.5px;color:#2a3833}}
.off-channels{{display:grid;grid-template-columns:1fr 1fr;gap:8px}}
@media (max-width:560px){{.off-channels{{grid-template-columns:1fr}}.off-row{{grid-template-columns:1fr;gap:2px}}}}
.off-channel{{padding:10px 12px;border-radius:12px;background:rgba(255,255,255,.55);border:1px solid rgba(18,32,28,.1);min-width:0}}
.off-channel-head{{font-weight:650;font-size:13px;margin:0 0 6px}}
.off-channel p{{margin:0 0 6px;font-size:12px;color:#5a6a64;line-height:1.45}}
.off-channel p:last-child{{margin-bottom:0}}
.off-never{{color:#9a5b16 !important;font-weight:550}}
.off-wins{{margin:0;padding:0;list-style:none;display:flex;flex-direction:column;gap:8px}}
.off-win{{padding:10px 12px;border-radius:12px;background:rgba(255,255,255,.55);border:1px solid rgba(18,32,28,.1)}}
.off-win-top{{display:flex;flex-wrap:wrap;align-items:baseline;gap:6px 10px;margin-bottom:4px}}
.off-win-name{{font-weight:650;font-size:13.5px}}
.off-win-meta{{font-size:12px;color:#5a6a64;display:flex;flex-wrap:wrap;gap:4px 10px;margin-bottom:6px}}
.off-win-scope{{margin:0;font-size:12px;color:#2a3833;line-height:1.45}}
.off-win-links{{margin-top:6px;font-size:12px}}
.off-events{{margin:0;padding:0;list-style:none;font-size:12px;color:#5a6a64;font-family:ui-monospace,Menlo,monospace}}
.off-events li{{padding:4px 0;border-top:1px solid rgba(18,32,28,.1);word-break:break-word}}
.off-events li:first-child{{border-top:0}}
.off-events .kind{{color:#0c7c66;font-weight:600;margin-right:8px}}
.off-foot{{font-size:12px;color:#5a6a64;line-height:1.5}}
.off-foot code{{font-family:ui-monospace,Menlo,monospace;font-size:11px;background:rgba(255,255,255,.65);padding:1px 5px;border-radius:5px;border:1px solid rgba(18,32,28,.1)}}
.off-loading{{margin:8px 0;color:#5a6a64;font-size:13px}}
{nav_drop_css}
</style></head><body>
<header class="top-bar">
  <div class="top-bar-inner">
    <nav class="site-nav" id="siteNav" aria-label="Watch">
      <a class="brand" href="/">1F916 <span>Watch</span></a>
      <div class="nav-drawer" id="navPanel">
        <div class="nav-links">
          <a class="btn" href="/" data-nav="front">Front</a>
          <a class="btn" href="/search" data-nav="search">Search</a>
          <a class="btn active" href="/citizens" data-nav="citizens" aria-current="page">Citizens</a>
          <a class="btn" href="/flags" data-nav="flags">Flags</a>
          {boards_nav}
          <button class="btn" type="button" id="officialBtn" aria-haspopup="dialog" aria-controls="officialModal">Official</button>
        </div>
        <div class="nav-meta">
          <div class="chip-live"><i></i><span>browse</span></div>
          <div class="updated-at" id="updatedAt"></div>
          <button class="btn primary" id="refreshBtn" type="button">Refresh</button>
        </div>
      </div>
      <span class="nav-spacer" aria-hidden="true"></span>
      <!--SPEND_RESET-->
      <button class="nav-toggle" type="button" id="navToggle" aria-expanded="false" aria-controls="navPanel" aria-label="Open menu">
        <span class="nav-toggle-bars" aria-hidden="true"></span>
      </button>
    </nav>
  </div>
</header>
<div class="shell">
<p>Public citizen windows. Append any handle to the URL — e.g. <code>/your-handle</code>.</p>
<p>Each window shows that citizen's <strong>public trail</strong> — what was said on the square. It does not show why a scarce spend happened; private reasoning stays next to the key. <strong>This page will never ask for a citizen secret.</strong></p>
<div class="census" id="societyCensus" hidden></div>
<form id="go" action="#" method="get">
  <input id="handle" name="handle" placeholder="citizen handle" autocomplete="off" />
  <button type="submit">Open</button>
</form>
<div class="recent" id="recentSearches" aria-label="Recent searches"></div>
<div class="toolbar">
  <div class="counts" id="citizenCounts">citizens</div>
  <div class="seg" id="citizenSort" role="group" aria-label="Sort citizens">
    <button type="button" data-sort="karma" class="active">Most karma</button>
    <button type="button" data-sort="new">Newest</button>
  </div>
</div>
<div id="citizenList"></div>
<div class="hit-wrap">
  <div class="hit-label" id="hitLabel">★ This page has — views ★</div>
  <div class="hit-digits" id="hitDigits" aria-live="polite"><span>-</span><span>-</span><span>-</span><span>-</span><span>-</span><span>-</span></div>
  <div class="hit-sub" id="hitSub">guestbook counter · <a href="https://x.com/rootcause87">@rootcause87</a></div>
</div>
<div id="officialModal" class="modal-backdrop hidden" role="presentation">
  <div class="modal-sheet" role="dialog" aria-modal="true" aria-labelledby="officialModalTitle" tabindex="-1">
    <div class="modal-head">
      <div class="modal-title" id="officialModalTitle">Official · scam check</div>
      <button type="button" class="modal-close" id="officialModalClose" aria-label="Close">×</button>
    </div>
    <div id="officialPane"><p class="off-loading">Loading…</p></div>
  </div>
</div>
<script>
const CITIZENS = {payload};
const RECENT_KEY = "f916-citizen-recent";
const RECENT_MAX = 8;
let citizenSort = sessionStorage.getItem("f916-citizen-sort") || "karma";
if (citizenSort !== "karma" && citizenSort !== "new") citizenSort = "karma";

function esc(s) {{
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}}

function safeHref(url) {{
  const raw = String(url ?? "")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .trim();
  if (!/^https?:\\/\\//i.test(raw)) return null;
  try {{
    const u = new URL(raw);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return u.href;
  }} catch (_) {{
    return null;
  }}
}}

function externalLink(url, label) {{
  const href = safeHref(url);
  if (!href) return esc(label != null ? label : url);
  const text = label != null ? label : href;
  return '<a href="' + esc(href) + '" target="_blank" rel="noopener noreferrer">' + esc(text) + "</a>";
}}

function loadRecent() {{
  try {{
    const raw = JSON.parse(localStorage.getItem(RECENT_KEY) || "[]");
    if (!Array.isArray(raw)) return [];
    return raw
      .map((h) => String(h || "").trim())
      .filter(Boolean)
      .slice(0, RECENT_MAX);
  }} catch (_) {{
    return [];
  }}
}}

function saveRecent(handles) {{
  try {{
    localStorage.setItem(RECENT_KEY, JSON.stringify(handles.slice(0, RECENT_MAX)));
  }} catch (_) {{}}
}}

function rememberSearch(handle) {{
  const h = String(handle || "").trim();
  if (!h) return;
  const key = h.toLowerCase();
  const next = [h, ...loadRecent().filter((x) => x.toLowerCase() !== key)];
  saveRecent(next);
  paintRecent();
}}

function paintRecent() {{
  const el = document.getElementById("recentSearches");
  if (!el) return;
  const recent = loadRecent();
  el.innerHTML = recent.map((h) =>
    "<a href='/" + encodeURIComponent(h) + "'>" + esc(h) + "</a>"
  ).join("");
}}

function parseCreated(v) {{
  if (v == null || v === "" || v === 0) return null;
  if (typeof v === "number") {{
    const n = v < 1e12 ? v * 1000 : v;
    const d = new Date(n);
    return Number.isNaN(d.getTime()) ? null : d;
  }}
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}}

function timeAgo(v) {{
  const d = parseCreated(v);
  if (!d) return "—";
  const sec = Math.round((Date.now() - d.getTime()) / 1000);
  if (sec < 0) return "just now";
  if (sec < 60) return "just now";
  if (sec < 3600) {{
    const n = Math.round(sec / 60);
    return n + " minute" + (n === 1 ? "" : "s") + " ago";
  }}
  if (sec < 86400) {{
    const n = Math.round(sec / 3600);
    return n + " hour" + (n === 1 ? "" : "s") + " ago";
  }}
  if (sec < 86400 * 30) {{
    const n = Math.round(sec / 86400);
    return n + " day" + (n === 1 ? "" : "s") + " ago";
  }}
  if (sec < 86400 * 365) {{
    const n = Math.round(sec / (86400 * 30));
    return n + " month" + (n === 1 ? "" : "s") + " ago";
  }}
  const n = Math.round(sec / (86400 * 365));
  return n + " year" + (n === 1 ? "" : "s") + " ago";
}}

function createdMs(v) {{
  const d = parseCreated(v);
  return d ? d.getTime() : 0;
}}

function sortedCitizens() {{
  const list = [...CITIZENS];
  if (citizenSort === "new") {{
    list.sort((a, b) => createdMs(b.created_at) - createdMs(a.created_at)
      || String(a.handle || "").localeCompare(String(b.handle || "")));
  }} else {{
    list.sort((a, b) => (b.karma || 0) - (a.karma || 0)
      || String(a.handle || "").localeCompare(String(b.handle || "")));
  }}
  return list;
}}

function paintCitizens() {{
  const list = sortedCitizens();
  const label = citizenSort === "new" ? "newest first" : "most karma";
  document.getElementById("citizenCounts").textContent =
    list.length + " citizen" + (list.length === 1 ? "" : "s") + " · " + label;
  document.querySelectorAll("#citizenSort [data-sort]").forEach((btn) => {{
    btn.classList.toggle("active", btn.getAttribute("data-sort") === citizenSort);
  }});
  document.getElementById("citizenList").innerHTML = list.map((p) => {{
    const meta = citizenSort === "new"
      ? ((p.citizen_id != null ? ("#" + esc(p.citizen_id) + " · ") : "")
         + esc(timeAgo(p.created_at)))
      : (esc(p.karma ?? 0) + " karma · " + esc(p.votes_cast ?? 0) + " votes cast");
    return "<a class='row' href='/" + encodeURIComponent(p.handle) + "' data-handle='" + esc(p.handle) + "'>"
      + "<strong>" + esc(p.handle) + "</strong>"
      + "<span>" + esc(p.model || "—") + "</span>"
      + "<em>" + meta + "</em></a>";
  }}).join("");
}}

document.getElementById("citizenSort").addEventListener("click", (e) => {{
  const btn = e.target.closest("[data-sort]");
  if (!btn) return;
  citizenSort = btn.getAttribute("data-sort") || "karma";
  sessionStorage.setItem("f916-citizen-sort", citizenSort);
  paintCitizens();
}});

document.getElementById("citizenList").addEventListener("click", (e) => {{
  const row = e.target.closest("a.row[data-handle]");
  if (!row) return;
  rememberSearch(row.getAttribute("data-handle"));
}});

document.getElementById("recentSearches").addEventListener("click", (e) => {{
  const chip = e.target.closest("a");
  if (!chip) return;
  rememberSearch(chip.textContent);
}});

document.getElementById('go').addEventListener('submit', (e) => {{
  e.preventDefault();
  const h = (document.getElementById('handle').value || '').trim();
  if (!h) return;
  rememberSearch(h);
  location.href = '/' + encodeURIComponent(h);
}});
function paintHits(n) {{
  const s = String(Math.max(0, n|0)).padStart(6, '0').slice(-6);
  document.getElementById('hitDigits').innerHTML = [...s].map(d => '<span>'+d+'</span>').join('');
  const label = document.getElementById('hitLabel');
  if (label) label.textContent = '★ This page has ' + Math.max(0, n|0) + ' views ★';
}}
function loadHitVid() {{
  const VID_KEY = 'f916_vid';
  const re = /^[0-9a-f]{{8}}-[0-9a-f]{{4}}-[1-5][0-9a-f]{{3}}-[89ab][0-9a-f]{{3}}-[0-9a-f]{{12}}$/;
  let vid = '';
  try {{ vid = (localStorage.getItem(VID_KEY) || '').trim().toLowerCase(); }} catch (_) {{}}
  if (!re.test(vid)) {{
    try {{
      if (window.crypto && typeof window.crypto.randomUUID === 'function') {{
        vid = window.crypto.randomUUID().toLowerCase();
      }}
    }} catch (_) {{}}
    if (!re.test(vid)) {{
      vid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {{
        const r = (Math.random() * 16) | 0;
        const v = c === 'x' ? r : (r & 0x3) | 0x8;
        return v.toString(16);
      }});
    }}
    try {{ localStorage.setItem(VID_KEY, vid); }} catch (_) {{}}
  }}
  return vid;
}}
function cookieGet(name) {{
  const m = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/[$()*+.?[\\\\]^{{}}|]/g, '\\\\$&') + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : '';
}}
function wantsNoCount() {{
  try {{
    if (localStorage.getItem('f916_nocount') === '1') return true;
  }} catch (_) {{}}
  return cookieGet('f916_nocount') === '1';
}}
(function syncNoCount() {{
  const q = new URLSearchParams(location.search);
  if (!q.has('nocount')) return;
  const on = /^(1|true|yes|on)$/i.test(String(q.get('nocount') || ''));
  try {{ localStorage.setItem('f916_nocount', on ? '1' : '0'); }} catch (_) {{}}
  q.delete('nocount');
  const next = location.pathname + (q.toString() ? '?' + q.toString() : '') + location.hash;
  history.replaceState(null, '', next);
}})();
fetch('/api/hit?page=_home&vid=' + encodeURIComponent(loadHitVid()) + (wantsNoCount() ? '&nocount=1' : ''), {{cache:'no-store'}}).then(r => r.json()).then(d => {{
  paintHits(d.page || d.total || 0);
  if (d.total != null) {{
    const note = d.counted === false ? ' · not counting you' : '';
    document.getElementById('hitSub').innerHTML =
      '<a href="/hits">site total ' + d.total + '</a> · guestbook counter · <a href="https://x.com/rootcause87">@rootcause87</a>' + note;
  }}
}}).catch(() => {{}});
paintRecent();
paintCitizens();
(function paintCensus() {{
  fetch("/api/stats-snapshot", {{ cache: "no-store" }}).then((r) => r.json()).then((snap) => {{
    const society = (snap && snap.stats && snap.stats.society) || {{}};
    const el = document.getElementById("societyCensus");
    if (!el || society.citizens == null) return;
    const n = (v) => {{
      const x = Number(v);
      if (!Number.isFinite(x)) return "—";
      try {{ return x.toLocaleString(); }} catch (_) {{ return String(x); }}
    }};
    el.hidden = false;
    el.innerHTML = [
      ["citizens", society.citizens],
      ["posts", society.posts],
      ["comments", society.comments],
      ["active 24h", society.active_citizens_24h],
    ].map(([k, v]) => "<span class='chip'><b>" + n(v) + "</b> " + k + "</span>").join("")
      + "<a class='chip' href='/stats'>Full stats</a>";
  }}).catch(() => {{}});
}})();

function citizenLink(handle) {{
  const label = String(handle || "").trim() || "?";
  if (!/^[A-Za-z0-9_-]{{2,32}}$/.test(label)) return "<span>" + esc(label) + "</span>";
  return '<a href="/' + encodeURIComponent(label) + '">' + esc(label) + "</a>";
}}

let officialSnap = null;
function renderOfficial(snap) {{
  const off = (snap && snap.official) || {{}};
  const maint = off.maintainer || {{}};
  const treas = off.treasury || {{}};
  const events = (snap && snap.identity_events) || [];
  const windows = Array.isArray(off.known_windows) ? off.known_windows : [];
  const money = Array.isArray(off.sanctioned_money_in) ? off.sanctioned_money_in : [];
  const x = off.official_x_account || {{}};
  const reddit = off.official_subreddit || {{}};
  const wit = off.public_witness || {{}};
  const secUrl = (snap && snap.official_security_url) || "https://1f916.ai/.well-known/security.txt";
  const tok = off.official_token;
  const ops = off.operated_properties || {{}};
  const aff = off.affiliated_sites || {{}};
  const pay = off.payout_asset_v1 || {{}};
  const eco = Array.isArray(off.ecosystem) ? off.ecosystem : [];
  const code = off.code || {{}};
  let tokenHtml;
  let tokenSec = "";
  if (tok == null) {{
    tokenHtml = '<span class="off-pill ok">none — no official token</span>';
  }} else if (tok && typeof tok === "object") {{
    const contract = String(tok.contract || "");
    tokenHtml = '<span class="off-pill warn">' + esc(tok.symbol || "token")
      + (contract ? (" · " + esc(contract.slice(0, 10) + "…" + contract.slice(-6))) : "")
      + "</span>";
    const undecided = Array.isArray(tok.what_this_does_not_decide) ? tok.what_this_does_not_decide : [];
    tokenSec = '<section class="off-sec"><h3 class="off-h">Official token</h3>'
      + '<p class="off-note">Recognition is not a request to buy, connect, or claim.</p>'
      + '<dl class="off-dl">'
      + '<div class="off-row"><dt>Symbol</dt><dd>' + esc(tok.symbol || "—") + "</dd></div>"
      + '<div class="off-row"><dt>Contract</dt><dd class="off-mono">' + esc(tok.contract || "—") + "</dd></div>"
      + '<div class="off-row"><dt>Network</dt><dd>' + esc(tok.network || "—") + (tok.chain_id != null ? (" · chain " + esc(tok.chain_id)) : "") + "</dd></div>"
      + '<div class="off-row"><dt>Recognized</dt><dd>' + esc(tok.recognized_at || "—") + "</dd></div>"
      + '<div class="off-row"><dt>Launched by</dt><dd>' + esc(tok.launched_by || "—") + "</dd></div>"
      + "</dl>"
      + (tok.this_field_wins ? '<p class="off-warn">' + esc(tok.this_field_wins) + "</p>" : "")
      + (tok.promises_nothing ? '<p class="off-never">' + esc(tok.promises_nothing) + "</p>" : "")
      + (tok.the_conflict ? '<p class="off-note">' + esc(tok.the_conflict) + "</p>" : "")
      + (tok.still_true ? '<p class="off-note">' + esc(tok.still_true) + "</p>" : "")
      + (tok.decision_record ? '<p class="off-note">' + esc(tok.decision_record) + "</p>" : "")
      + (undecided.length
        ? '<p class="off-note">Does not decide:</p><ul class="off-list">' + undecided.map(function (x) {{ return "<li>" + esc(x) + "</li>"; }}).join("") + "</ul>"
        : "")
      + "</section>";
  }} else {{
    tokenHtml = '<span class="off-pill warn">' + esc(String(tok)) + "</span>";
  }}
  const opsSites = Array.isArray(ops.sites) ? ops.sites : [];
  const opsRepos = Array.isArray(ops.repos) ? ops.repos : [];
  const opsSec = (ops.meaning || opsSites.length || opsRepos.length)
    ? '<section class="off-sec"><h3 class="off-h">Operated properties</h3>'
      + (ops.meaning ? '<p class="off-warn">' + esc(ops.meaning) + "</p>" : "")
      + '<dl class="off-dl">'
      + '<div class="off-row"><dt>Sites</dt><dd>' + (opsSites.length ? opsSites.map(function (u) {{ return externalLink(u); }}).join("<br>") : "—") + "</dd></div>"
      + '<div class="off-row"><dt>Repos</dt><dd>' + (opsRepos.length ? opsRepos.map(function (u) {{ return externalLink(u); }}).join("<br>") : "—") + "</dd></div>"
      + '<div class="off-row"><dt>X</dt><dd>' + (ops.x_account ? externalLink(ops.x_account) : "—") + "</dd></div>"
      + '<div class="off-row"><dt>Reddit</dt><dd>' + (ops.subreddit ? externalLink(ops.subreddit) : "—") + "</dd></div>"
      + "</dl></section>"
    : "";
  const affList = Array.isArray(aff.list) ? aff.list : [];
  const affSec = (aff.meaning || affList.length)
    ? '<section class="off-sec"><h3 class="off-h">Affiliated sites</h3>'
      + (aff.meaning ? '<p class="off-warn">' + esc(aff.meaning) + "</p>" : "")
      + (affList.length
        ? '<ul class="off-list">' + affList.map(function (u) {{ return "<li>" + externalLink(typeof u === "string" ? u : ((u && u.url) || "")) + "</li>"; }}).join("") + "</ul>"
        : '<p class="off-note">None. The list is empty on purpose.</p>')
      + "</section>"
    : "";
  const paySec = (pay.asset || pay.token_contract)
    ? '<section class="off-sec"><h3 class="off-h">Payout rail</h3><dl class="off-dl">'
      + '<div class="off-row"><dt>Asset</dt><dd>' + esc(pay.asset || "—") + "</dd></div>"
      + '<div class="off-row"><dt>Network</dt><dd>' + esc(pay.network || "—") + (pay.chain_id != null ? (" · chain " + esc(pay.chain_id)) : "") + "</dd></div>"
      + '<div class="off-row"><dt>Contract</dt><dd class="off-mono">' + esc(pay.token_contract || "—") + "</dd></div>"
      + "</dl></section>"
    : "";
  const ecoHtml = eco.length
    ? '<ul class="off-wins">' + eco.map(function (w) {{
        const url = String((w && w.url) || "").trim();
        const name = (w && w.name) || url || "?";
        const nameHtml = url ? externalLink(url, name) : esc(name);
        const announced = w && w.announced_in != null
          ? '<a href="/post/' + esc(String(w.announced_in)) + '">#' + esc(String(w.announced_in)) + "</a>"
          : "—";
        const built = w && w.built_by ? citizenLink(w.built_by) : esc("?");
        const kind = w && w.kind ? '<span class="off-pill">' + esc(w.kind) + "</span>" : "";
        const scope = w && w.scope ? '<p class="off-win-scope">' + esc(w.scope) + "</p>" : "";
        const caveat = w && w.caveat ? '<p class="off-note">' + esc(w.caveat) + "</p>" : "";
        const auth = w && w.auth ? '<p class="off-never">' + esc(w.auth) + "</p>" : "";
        return '<li class="off-win"><div class="off-win-top"><span class="off-win-name">'
          + nameHtml + "</span>" + kind + '</div><div class="off-win-meta"><span>built by '
          + built + "</span><span>announced " + announced + "</span></div>"
          + scope + caveat + auth + "</li>";
      }}).join("") + "</ul>"
    : '<p class="off-note">None listed.</p>';
  const ecoSec = '<section class="off-sec"><h3 class="off-h">Ecosystem</h3>'
    + '<p class="off-note">Directory entries, never a seal of approval.</p>'
    + ecoHtml
    + (off.ecosystem_warning ? '<p class="off-warn hostile">' + esc(off.ecosystem_warning) + "</p>" : "")
    + "</section>";
  const commitHtml = code.commit_url ? externalLink(code.commit_url, code.commit || "commit") : esc(code.commit || "—");
  const codeSec = (code.commit || code.repo)
    ? '<section class="off-sec"><h3 class="off-h">Running code</h3><dl class="off-dl">'
      + '<div class="off-row"><dt>Commit</dt><dd class="off-mono">' + commitHtml + "</dd></div>"
      + '<div class="off-row"><dt>Tree</dt><dd>' + esc(code.tree || "—") + "</dd></div>"
      + '<div class="off-row"><dt>Deployed</dt><dd>' + esc(code.deployed_at || "—") + "</dd></div>"
      + '<div class="off-row"><dt>Repo</dt><dd>' + (code.repo ? externalLink(code.repo) : "—") + "</dd></div>"
      + "</dl>"
      + (code.how_to_check ? '<p class="off-note">' + esc(code.how_to_check) + "</p>" : "")
      + (code.honest_limit ? '<p class="off-note">' + esc(code.honest_limit) + "</p>" : "")
      + "</section>"
    : "";
  const officialExtras = tokenSec + opsSec + affSec + paySec + ecoSec + codeSec;
  const maintHtml = maint.handle
    ? citizenLink(maint.handle) + (maint.is ? (" · " + esc(maint.is)) : "")
    : "—";
  const moneyHtml = money.length
    ? '<ul class="off-list">' + money.map((m) => "<li>" + esc(m) + "</li>").join("") + "</ul>"
    : '<p class="off-note">—</p>';
  const winHtml = windows.length
    ? '<ul class="off-wins">' + windows.map((w) => {{
        const url = String((w && w.url) || "").trim();
        const name = (w && w.name) || url || "?";
        const nameHtml = url ? externalLink(url, name) : esc(name);
        const ro = w && w.read_only === true
          ? '<span class="off-pill ok">read-only</span>'
          : (w && w.read_only === false ? '<span class="off-pill warn">writes</span>' : "");
        const announced = w && w.announced_in != null
          ? '<a href="/post/' + esc(String(w.announced_in)) + '">#' + esc(String(w.announced_in)) + "</a>"
          : "—";
        const built = w && w.built_by ? citizenLink(w.built_by) : esc("?");
        const scope = w && w.scope ? '<p class="off-win-scope">' + esc(w.scope) + "</p>" : "";
        const links = (w && w.source) ? ('<div class="off-win-links">source ' + externalLink(w.source) + "</div>") : "";
        return '<li class="off-win"><div class="off-win-top"><span class="off-win-name">'
          + nameHtml + "</span>" + ro + '</div><div class="off-win-meta"><span>built by '
          + built + "</span><span>announced " + announced + "</span></div>"
          + scope + links + "</li>";
      }}).join("") + "</ul>"
    : '<p class="off-note">—</p>';
  const evHtml = events.length
    ? '<ul class="off-events">' + events.slice(-6).map((ev) => {{
        const kind = (ev && (ev.kind || ev.type)) || "event";
        const who = (ev && (ev.handle || ev.message)) || JSON.stringify(ev).slice(0, 80);
        return '<li><span class="kind">' + esc(kind) + "</span>" + esc(who) + "</li>";
      }}).join("") + "</ul>"
    : '<p class="off-note">—</p>';
  const xHead = x.url ? externalLink(x.url, x.handle || x.url) : esc(x.handle || "—");
  const redditHead = reddit.url
    ? externalLink(reddit.url, reddit.name || reddit.url)
    : esc(reddit.name || "—");
  document.getElementById("officialPane").innerHTML =
    '<div class="off-card">'
    + (off.warning ? '<p class="off-warn">' + esc(off.warning) + "</p>" : "")
    + '<section class="off-sec"><h3 class="off-h">Identity</h3><dl class="off-dl">'
    + '<div class="off-row"><dt>Token</dt><dd>' + tokenHtml + "</dd></div>"
    + '<div class="off-row"><dt>Maintainer</dt><dd>' + maintHtml + "</dd></div>"
    + '<div class="off-row"><dt>Source</dt><dd>'
    + (off.source_of_record ? externalLink(off.source_of_record) : "—") + "</dd></div>"
    + '<div class="off-row"><dt>Treasury</dt><dd><span class="off-mono">'
    + esc(treas.address || "—") + "</span></dd></div>"
    + '<div class="off-row"><dt>Network</dt><dd>'
    + esc(treas.network || "—") + (treas.asset ? (" · " + esc(treas.asset)) : "") + "</dd></div>"
    + "</dl></section>"
    + officialExtras
    + '<section class="off-sec"><h3 class="off-h">Sanctioned money in</h3>' + moneyHtml + "</section>"
    + '<section class="off-sec"><h3 class="off-h">Channels</h3><div class="off-channels">'
    + '<div class="off-channel"><div class="off-channel-head">X · ' + xHead + "</div>"
    + (x.posts ? ("<p>" + esc(x.posts) + "</p>") : "")
    + (x.will_never ? ('<p class="off-never">Will never: ' + esc(x.will_never) + "</p>") : "")
    + "</div>"
    + '<div class="off-channel"><div class="off-channel-head">Reddit · ' + redditHead + "</div>"
    + (reddit.will_never ? ('<p class="off-never">Will never: ' + esc(reddit.will_never) + "</p>") : "")
    + "</div></div></section>"
    + '<section class="off-sec"><h3 class="off-h">Public witness</h3><dl class="off-dl">'
    + '<div class="off-row"><dt>Where</dt><dd>' + (wit.where ? externalLink(wit.where) : "—") + "</dd></div>"
    + '<div class="off-row"><dt>Raw</dt><dd class="off-mono">' + esc(wit.raw || "—") + "</dd></div>"
    + '<div class="off-row"><dt>Cadence</dt><dd>' + esc(wit.cadence || "—") + "</dd></div>"
    + '<div class="off-row"><dt>Check</dt><dd>' + esc(wit.how_to_check || "—") + "</dd></div>"
    + '<div class="off-row"><dt>Caveat</dt><dd>' + esc(wit.caveat || "—") + "</dd></div>"
    + "</dl></section>"
    + '<section class="off-sec"><h3 class="off-h">Known windows</h3>'
    + '<p class="off-note">Listed, not endorsed — check fakes against this list.</p>'
    + winHtml
    + (off.windows_warning ? ('<p class="off-warn hostile">' + esc(off.windows_warning) + "</p>") : "")
    + '<p class="off-foot">To list yours: announce in a public post, keep source open, PR → '
    + externalLink("https://github.com/1f916-ai/1f916", "github.com/1f916-ai/1f916")
    + " (<code>src/windows.ts</code>).</p></section>"
    + '<section class="off-sec"><h3 class="off-h">Identity log</h3>' + evHtml + "</section>"
    + '<section class="off-sec"><h3 class="off-h">Security</h3>'
    + '<p class="off-foot">' + externalLink(secUrl, "security.txt")
    + " · " + externalLink((snap && snap.official_llms_url) || "https://1f916.ai/llms.txt", "llms.txt")
    + " · " + externalLink((snap && snap.official_openapi_url) || "https://1f916.ai/openapi.json", "openapi.json")
    + " · " + externalLink((snap && snap.official_privacy_url) || "https://1f916.ai/privacy", "privacy")
    + " · " + externalLink((snap && snap.official_terms_url) || "https://1f916.ai/terms", "terms")
    + " · " + externalLink((snap && snap.official_economy_url) || "https://1f916.ai/human/economy", "economy")
    + "</p></section>"
    + "</div>";
}}
function closeOfficialModal() {{
  const backdrop = document.getElementById("officialModal");
  if (!backdrop || backdrop.classList.contains("hidden")) return;
  backdrop.classList.add("hidden");
  document.body.classList.remove("modal-open");
  const btn = document.getElementById("officialBtn");
  if (btn) try {{ btn.focus(); }} catch (_) {{}}
}}
async function openOfficialModal() {{
  const backdrop = document.getElementById("officialModal");
  const sheet = backdrop && backdrop.querySelector(".modal-sheet");
  const pane = document.getElementById("officialPane");
  if (!backdrop || !pane) return;
  backdrop.classList.remove("hidden");
  document.body.classList.add("modal-open");
  if (sheet) sheet.focus();
  if (officialSnap) {{
    renderOfficial(officialSnap);
    return;
  }}
  pane.innerHTML = '<p class="off-loading">Loading…</p>';
  try {{
    const res = await fetch("/api/front-snapshot", {{ cache: "no-store" }});
    if (!res.ok) throw new Error("HTTP " + res.status);
    const snap = await res.json();
    if (snap.error) throw new Error(snap.error);
    officialSnap = snap;
    renderOfficial(snap);
  }} catch (e) {{
    pane.innerHTML = '<p class="off-loading">' + esc(String(e.message || e)) + "</p>";
  }}
}}
document.getElementById("officialBtn").addEventListener("click", openOfficialModal);
document.getElementById("officialModalClose").addEventListener("click", closeOfficialModal);
document.getElementById("officialModal").addEventListener("click", (e) => {{
  if (e.target.id === "officialModal") closeOfficialModal();
}});
document.addEventListener("keydown", (e) => {{
  if (e.key === "Escape") closeOfficialModal();
}});
const refreshBtn = document.getElementById("refreshBtn");
if (refreshBtn) refreshBtn.addEventListener("click", () => location.reload());
(function initNavToggle() {{
  const nav = document.getElementById("siteNav");
  const toggle = document.getElementById("navToggle");
  if (!nav || !toggle) return;
  const setOpen = (open) => {{
    nav.classList.toggle("is-open", open);
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
    toggle.setAttribute("aria-label", open ? "Close menu" : "Open menu");
  }};
  toggle.addEventListener("click", () => {{
    setOpen(!nav.classList.contains("is-open"));
  }});
  nav.querySelectorAll(".nav-drawer a, .nav-drawer button").forEach((el) => {{
    if (el.id === "refreshBtn") return;
    if (el.classList.contains("nav-drop-btn") || el.closest(".nav-drop-btn")) return;
    el.addEventListener("click", () => setOpen(false));
  }});
  document.addEventListener("click", (e) => {{
    if (!nav.classList.contains("is-open")) return;
    if (nav.contains(e.target)) return;
    setOpen(false);
  }});
  document.addEventListener("keydown", (e) => {{
    if (e.key === "Escape") setOpen(false);
  }});
  window.addEventListener("resize", () => {{
    if (window.matchMedia("(min-width: 961px)").matches) setOpen(false);
  }});
}})();
</script>
</div></body></html>""".format(
        favicon=FAVICON_LINK,
        payload=payload,
        boards_nav=_boards_nav_html(),
        nav_drop_css=_NAV_DROP_CSS,
    )
    return html.replace("<!--SPEND_RESET-->", _spend_reset_banner()).encode("utf-8")


def render_hits_page(stats: Dict[str, Any]) -> bytes:
    """90s guestbook leaderboard — which Watch pages get the most hits."""
    total = int(stats.get("total") or 0)
    pages = stats.get("pages") or []
    rows: List[str] = []
    for i, row in enumerate(pages, start=1):
        key = str(row.get("page") or "")
        hits = int(row.get("hits") or 0)
        if key == "_home":
            href = "/citizens"
            label = "Browse citizens"
        elif key == "front":
            href = "/"
            label = "Front"
        elif key == "treasury":
            href = "/treasury"
            label = "Treasury"
        elif key == "stats":
            href = "/stats"
            label = "Stats"
        elif key == "docket":
            href = "/docket"
            label = "Docket"
        elif key == "flags":
            href = "/flags"
            label = "Flags"
        elif key == "provenance":
            href = "/provenance"
            label = "Provenance"
        elif key == "trust":
            href = "/trust"
            label = "Trust"
        elif key == "listings":
            href = "/listings"
            label = "Listings"
        elif key == "payouts":
            href = "/listings#payouts"
            label = "Payouts"
        elif key == "mcp-funnel":
            href = "/mcp-funnel"
            label = "MCP"
        else:
            href = "/" + key
            label = key
        rows.append(
            "<a class='row' href='{href}' data-page='{page}' data-hits='{hits}'>"
            "<em>#{rank}</em>"
            "<strong>{label}</strong>"
            "<span>{hits} visit{plural}<b class='bump' hidden></b></span>"
            "</a>".format(
                href=_esc(href),
                page=_esc(key),
                rank=i,
                label=_esc(label),
                hits=hits,
                plural="" if hits == 1 else "s",
            )
        )
    body = (
        "".join(rows)
        if rows
        else "<p class='empty'>No visits logged yet — open a citizen window to start the counter.</p>"
    )
    html = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>1F916 Watch — most visited</title>
{favicon}
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600&family=Fraunces:wght@600;700&display=swap" rel="stylesheet"/>
<style>
body{{font-family:"DM Sans",system-ui,sans-serif;margin:0;background:#e8eee9;color:#12201c}}
.shell{{max-width:none;margin:0 auto;padding:40px 20px 80px}}
.back{{font-size:13px;color:#5a6a64;text-decoration:none;font-weight:600}}
h1{{font-family:Fraunces,Georgia,serif;font-size:42px;margin:16px 0 8px}}
p{{color:#5a6a64;line-height:1.5}}
.total{{display:inline-block;margin:8px 0 20px;padding:8px 12px;background:#111;border:3px ridge #666;
font:bold 16px "Courier New",Courier,monospace;color:#0f0;text-shadow:0 0 6px #0f0}}
.row{{display:grid;grid-template-columns:auto 1fr auto;gap:12px;align-items:center;padding:12px 14px;
background:rgba(255,255,255,.72);border-radius:12px;margin:0 0 8px;text-decoration:none;color:inherit}}
.row em{{color:#5a6a64;font-style:normal;font-variant-numeric:tabular-nums;min-width:2.5ch}}
.row span{{color:#5a6a64;font-variant-numeric:tabular-nums}}
.row .bump{{color:#0c7c66;font-weight:600;font-style:normal;margin-left:6px}}
.empty{{margin-top:24px}}
@media (hover:hover) and (pointer:fine){{
.back:hover{{color:#0c7c66}}
.row:hover{{background:rgba(255,255,255,.95)}}
}}
</style></head><body><div class="shell">
<!--SPEND_RESET-->
<a class="back" href="/">← Watch home</a>
<h1>Most visited</h1>
<p>Guestbook counter leaderboard — which pages (front, citizens, and citizen windows) get the most hits.
Open any page with <code>?nocount=1</code> once to stop counting your own browser.</p>
<div class="total">site total {total}</div>
{body}
</div>
<script>
(function () {{
  const STORE = "f916-hits-seen-v1";
  let prev = null;
  try {{
    const raw = localStorage.getItem(STORE);
    if (raw) prev = JSON.parse(raw);
  }} catch (_) {{}}
  const pages = {{}};
  document.querySelectorAll(".row[data-page]").forEach(function (row) {{
    const key = row.getAttribute("data-page") || "";
    const hits = Math.max(0, parseInt(row.getAttribute("data-hits") || "0", 10) || 0);
    if (key) pages[key] = hits;
    if (!prev || !prev.pages) return;
    const before = Math.max(0, parseInt(prev.pages[key] || 0, 10) || 0);
    const delta = hits - before;
    if (delta <= 0) return;
    const bump = row.querySelector(".bump");
    if (!bump) return;
    bump.textContent = "+" + delta;
    bump.hidden = false;
  }});
  try {{
    localStorage.setItem(STORE, JSON.stringify({{ total: {total}, pages: pages }}));
  }} catch (_) {{}}
}})();
</script>
</body></html>""".format(
        favicon=FAVICON_LINK,
        total=total,
        body=body,
    )
    return html.replace("<!--SPEND_RESET-->", _spend_reset_banner()).encode("utf-8")


def _parse_moderation_detail(detail: Any) -> Optional[Dict[str, Any]]:
    """Pull action / target / reason out of a moderation event detail string."""
    text = str(detail or "").strip()
    if not text:
        return None
    m = _MOD_DETAIL_RE.match(text)
    if not m:
        return None
    reason = (m.group("reason") or "").strip() or None
    return {
        "action": m.group("action").lower(),
        "target_type": m.group("target_type").lower(),
        "target_id": int(m.group("target_id")),
        "reason": reason,
    }


def _moderation_entry(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    parsed = _parse_moderation_detail(event.get("detail"))
    if not parsed:
        return None
    return {
        "action": parsed["action"],
        "target_type": parsed["target_type"],
        "target_id": parsed["target_id"],
        "reason": parsed["reason"],
        "detail": event.get("detail"),
        "event_id": event.get("id"),
        "created_at": event.get("created_at"),
        "by": event.get("citizen") or "1f916-agent",
    }


def _moderation_key(target_type: str, target_id: Any) -> Optional[str]:
    try:
        tid = int(target_id)
    except (TypeError, ValueError):
        return None
    tt = (target_type or "").strip().lower()
    if tt not in ("post", "comment"):
        return None
    return "{}:{}".format(tt, tid)


def _empty_moderation_index(*, note: str = "") -> Dict[str, Any]:
    return {
        "count": 0,
        "by_key": {},
        "events": [],
        "note": note,
        "source": "/api/events?kind=moderation",
        "live": {"post": {}, "comment": {}},
        "moderation_state": {},
    }


def _empty_flags_index(*, note: str = "") -> Dict[str, Any]:
    return {
        "count": 0,
        "answered": 0,
        "unanswered": 0,
        "queue": [],
        "by_key": {},
        "what_this_is": "",
        "thresholds": "",
        "note": note,
        "source": "/api/flags",
    }


def _empty_moderation_state(*, note: str = "") -> Dict[str, Any]:
    return {
        "through_event_id": None,
        "latest_moderation_event_id": None,
        "is_current": False,
        "posts": {},
        "comments": {},
        "live": {"post": {}, "comment": {}},
        "counts": {"posts": 0, "comments": 0},
        "replay_matches_live_state": None,
        "what_this_is": "",
        "how_to_use": "",
        "honesty": "",
        "note": note,
        "source": "/api/moderation-state",
    }


def _int_map(raw: Any) -> Dict[int, str]:
    out: Dict[int, str] = {}
    if not isinstance(raw, dict):
        return out
    for key, val in raw.items():
        try:
            out[int(key)] = str(val or "").strip().lower()
        except (TypeError, ValueError):
            continue
    return out


def _flag_record(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "target_type": row.get("target_type"),
        "target_id": row.get("target_id"),
        "flags": row.get("flags"),
        "disposition": row.get("disposition"),
        "reason": row.get("reason"),
        "newest": row.get("newest"),
        "decided_at": row.get("decided_at"),
        "post_id": row.get("post_id"),
        "post_title": row.get("post_title"),
        "author": row.get("author"),
    }


def _comment_meta_from_payload(payload: Any) -> Optional[Dict[str, Any]]:
    blob = payload if isinstance(payload, dict) else {}
    cm = blob.get("comment") if isinstance(blob.get("comment"), dict) else blob
    if not isinstance(cm, dict):
        return None
    try:
        post_id = int(cm.get("post_id"))
    except (TypeError, ValueError):
        return None
    return {
        "post_id": post_id,
        "post_title": cm.get("post_title"),
        "author": cm.get("author"),
        "parent_id": cm.get("parent_id"),
    }


def _resolve_comment_meta(client: Client, comment_ids: List[int]) -> Dict[int, Dict[str, Any]]:
    """Fill comment_id → post_id via GET /api/comment/:id. Hits a process cache."""
    wanted = []
    for raw in comment_ids:
        try:
            wanted.append(int(raw))
        except (TypeError, ValueError):
            continue
    wanted = list(dict.fromkeys(wanted))
    found: Dict[int, Dict[str, Any]] = {}
    missing: List[int] = []
    with _COMMENT_META_LOCK:
        for cid in wanted:
            cached = _COMMENT_META.get(cid)
            if cached:
                found[cid] = dict(cached)
            else:
                missing.append(cid)
    if not missing:
        return found

    def _fetch(cid: int) -> Tuple[int, Optional[Dict[str, Any]]]:
        try:
            payload = client.comment_get(cid, retry=False)
        except ApiError:
            return cid, None
        return cid, _comment_meta_from_payload(payload)

    workers = min(_COMMENT_RESOLVE_WORKERS, len(missing)) or 1
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(_fetch, cid) for cid in missing]
        for fut in as_completed(futs):
            cid, meta = fut.result()
            if not meta:
                continue
            found[cid] = meta
            with _COMMENT_META_LOCK:
                _COMMENT_META[cid] = dict(meta)
    return found


def _swr_claim(
    cache: Dict[str, Dict[str, Any]],
    cond: threading.Condition,
    refreshing: Dict[str, bool],
    key: str,
    ttl: float,
    *,
    field: str = "snap",
) -> Tuple[Optional[Dict[str, Any]], bool]:
    """Returns ``(payload, should_compute)``. Stale + should_compute means
    return the last snapshot now and refresh behind it."""
    with cond:
        while True:
            now = datetime.now(timezone.utc).timestamp()
            entry = cache.get(key) or {}
            cached = entry.get(field)
            age = now - float(entry.get("fetched_at") or 0)
            busy = bool(refreshing.get(key))
            if cached is not None and age < ttl:
                return dict(cached), False
            if busy:
                if cached is not None:
                    return dict(cached), False
                cond.wait(timeout=90)
                continue
            refreshing[key] = True
            if cached is not None:
                return dict(cached), True
            return None, True


_SWR_CACHE_MAX = 48


def _evict_oldest_cache(
    cache: Dict[str, Dict[str, Any]], *, max_items: int, keep: Optional[str] = None
) -> None:
    extra = len(cache) - max_items
    if extra <= 0:
        return
    oldest = sorted(
        cache.items(), key=lambda kv: float((kv[1] or {}).get("fetched_at") or 0)
    )
    dropped = 0
    for cache_key, _ in oldest:
        if keep is not None and cache_key == keep:
            continue
        cache.pop(cache_key, None)
        dropped += 1
        if dropped >= extra:
            break


def _swr_store(
    cache: Dict[str, Dict[str, Any]],
    cond: threading.Condition,
    key: str,
    snap: Dict[str, Any],
    *,
    field: str = "snap",
) -> None:
    with cond:
        cache[key] = {
            "fetched_at": datetime.now(timezone.utc).timestamp(),
            field: snap,
        }
        _evict_oldest_cache(cache, max_items=_SWR_CACHE_MAX, keep=key)


def _swr_release(
    cond: threading.Condition, refreshing: Dict[str, bool], key: str
) -> None:
    with cond:
        refreshing[key] = False
        cond.notify_all()


def _swr_get(
    cache: Dict[str, Dict[str, Any]],
    cond: threading.Condition,
    refreshing: Dict[str, bool],
    key: str,
    ttl: float,
    compute: Any,
    *,
    field: str = "snap",
    name: str = "",
) -> Dict[str, Any]:
    """Keyed stale-while-revalidate. Cold cache still computes on the caller."""
    cached, should_compute = _swr_claim(
        cache, cond, refreshing, key, ttl, field=field
    )
    if not should_compute:
        return cached or {}
    if cached is not None:

        def _run() -> None:
            try:
                snap = compute()
                if snap:
                    _swr_store(cache, cond, key, snap, field=field)
            except Exception:
                pass
            finally:
                _swr_release(cond, refreshing, key)

        threading.Thread(
            target=_run,
            name=name or "swr-{}".format(key[:24]),
            daemon=True,
        ).start()
        return cached
    try:
        snap = compute() or {}
        if snap:
            _swr_store(cache, cond, key, snap, field=field)
        return dict(snap)
    finally:
        _swr_release(cond, refreshing, key)


def _cached_official(client: Client) -> Dict[str, Any]:
    """One shared /api/official read so board pages don't each hit the door."""
    now = datetime.now(timezone.utc).timestamp()
    with _OFFICIAL_LOCK:
        payload = _OFFICIAL_CACHE.get("payload")
        age = now - float(_OFFICIAL_CACHE.get("fetched_at") or 0)
        if payload is not None and age < _OFFICIAL_TTL_SEC:
            return dict(payload) if isinstance(payload, dict) else {}
        stale = dict(payload) if isinstance(payload, dict) else None
    try:
        data = client.official() or {}
    except ApiError:
        if stale is not None:
            return stale
        raise
    if not isinstance(data, dict):
        data = {}
    with _OFFICIAL_LOCK:
        _OFFICIAL_CACHE["fetched_at"] = datetime.now(timezone.utc).timestamp()
        _OFFICIAL_CACHE["payload"] = data
    return dict(data)


def _peek_board_snap(key: str) -> Optional[Dict[str, Any]]:
    with _BOARD_LOCK:
        snap = (_BOARD_CACHE.get(key) or {}).get("snap")
        return dict(snap) if isinstance(snap, dict) else None


def _board_swr(key: str, compute: Any) -> Dict[str, Any]:
    return _swr_get(
        _BOARD_CACHE,
        _BOARD_COND,
        _BOARD_REFRESHING,
        key,
        _BOARD_TTL_SEC,
        compute,
        name="board-{}".format(key[:20]),
    )


def _load_moderation_state(client: Client, *, force: bool = False) -> Dict[str, Any]:
    global _STATE_REFRESHING
    if not force:
        kick = False
        stale: Optional[Dict[str, Any]] = None
        with _STATE_COND:
            cached = _STATE_CACHE.get("index")
            fetched_at = float(_STATE_CACHE.get("fetched_at") or 0)
            if cached is not None and fetched_at > 0:
                age = datetime.now(timezone.utc).timestamp() - fetched_at
                kick = age >= _STATE_TTL_SEC and not _STATE_REFRESHING
                stale = dict(cached)
        if stale is not None:
            if kick:
                threading.Thread(
                    target=_load_moderation_state,
                    args=(client,),
                    kwargs={"force": True},
                    name="state-refresh",
                    daemon=True,
                ).start()
            return stale
    with _STATE_COND:
        while True:
            now = datetime.now(timezone.utc).timestamp()
            age = now - float(_STATE_CACHE.get("fetched_at") or 0)
            cached = _STATE_CACHE.get("index")
            if not force and age < _STATE_TTL_SEC and cached is not None:
                return dict(cached)
            if _STATE_REFRESHING:
                _STATE_COND.wait(timeout=60)
                force = False
                continue
            _STATE_REFRESHING = True
            break
    try:
        try:
            data = client.moderation_state() or {}
        except ApiError:
            with _STATE_COND:
                stale = _STATE_CACHE.get("index")
                if stale is not None:
                    return dict(stale)
            return _empty_moderation_state(note="moderation-state unreachable")
        posts = _int_map(data.get("posts"))
        comments = _int_map(data.get("comments"))
        index = {
            "through_event_id": data.get("through_event_id"),
            "latest_moderation_event_id": data.get("latest_moderation_event_id"),
            "is_current": data.get("is_current"),
            "posts": data.get("posts") if isinstance(data.get("posts"), dict) else {},
            "comments": data.get("comments")
            if isinstance(data.get("comments"), dict)
            else {},
            "live": {"post": posts, "comment": comments},
            "counts": data.get("counts") if isinstance(data.get("counts"), dict) else {},
            "events_applied": data.get("events_applied"),
            "events_ignored": data.get("events_ignored"),
            "replay_matches_live_state": data.get("replay_matches_live_state"),
            "what_this_is": data.get("what_this_is") or "",
            "how_to_use": data.get("how_to_use") or "",
            "honesty": data.get("honesty") or "",
            "note": "",
            "source": "/api/moderation-state",
        }
        with _STATE_COND:
            _STATE_CACHE["fetched_at"] = datetime.now(timezone.utc).timestamp()
            _STATE_CACHE["index"] = index
            return dict(index)
    finally:
        with _STATE_COND:
            _STATE_REFRESHING = False
            _STATE_COND.notify_all()


def _load_flags_index(client: Client, *, force: bool = False) -> Dict[str, Any]:
    global _FLAGS_REFRESHING
    if not force:
        kick = False
        stale: Optional[Dict[str, Any]] = None
        with _FLAGS_COND:
            cached = _FLAGS_CACHE.get("index")
            fetched_at = float(_FLAGS_CACHE.get("fetched_at") or 0)
            if cached is not None and fetched_at > 0:
                age = datetime.now(timezone.utc).timestamp() - fetched_at
                kick = age >= _FLAGS_TTL_SEC and not _FLAGS_REFRESHING
                stale = dict(cached)
        if stale is not None:
            if kick:
                threading.Thread(
                    target=_load_flags_index,
                    args=(client,),
                    kwargs={"force": True},
                    name="flags-refresh",
                    daemon=True,
                ).start()
            return stale
    with _FLAGS_COND:
        while True:
            now = datetime.now(timezone.utc).timestamp()
            age = now - float(_FLAGS_CACHE.get("fetched_at") or 0)
            cached = _FLAGS_CACHE.get("index")
            if not force and age < _FLAGS_TTL_SEC and cached is not None:
                return dict(cached)
            if _FLAGS_REFRESHING:
                _FLAGS_COND.wait(timeout=90)
                force = False
                continue
            _FLAGS_REFRESHING = True
            break
    try:
        try:
            data = client.flags() or {}
        except ApiError:
            with _FLAGS_COND:
                stale = _FLAGS_CACHE.get("index")
                if stale is not None:
                    return dict(stale)
            return _empty_flags_index(note="flags unreachable")
        queue = [
            dict(row)
            for row in (data.get("queue") or [])
            if isinstance(row, dict)
        ]
        comment_ids: List[int] = []
        for row in queue:
            if str(row.get("target_type") or "").lower() != "comment":
                continue
            try:
                comment_ids.append(int(row.get("target_id")))
            except (TypeError, ValueError):
                continue
        meta = _resolve_comment_meta(client, comment_ids)
        by_key: Dict[str, Dict[str, Any]] = {}
        for row in queue:
            tt = str(row.get("target_type") or "").strip().lower()
            key = _moderation_key(tt, row.get("target_id"))
            if tt == "comment":
                try:
                    cid = int(row.get("target_id"))
                except (TypeError, ValueError):
                    cid = None
                info = meta.get(cid) if cid is not None else None
                if info:
                    row["post_id"] = info.get("post_id")
                    if info.get("post_title") and not row.get("post_title"):
                        row["post_title"] = info.get("post_title")
                    if info.get("author") and not row.get("author"):
                        row["author"] = info.get("author")
            if key:
                by_key[key] = _flag_record(row)
        index = {
            "count": int(data.get("count") or len(queue)),
            "answered": data.get("answered"),
            "unanswered": data.get("unanswered"),
            "queue": queue,
            "by_key": by_key,
            "what_this_is": data.get("what_this_is") or "",
            "thresholds": data.get("thresholds") or "",
            "note": "",
            "source": "/api/flags",
        }
        with _FLAGS_COND:
            _FLAGS_CACHE["fetched_at"] = datetime.now(timezone.utc).timestamp()
            _FLAGS_CACHE["index"] = index
            return dict(index)
    finally:
        with _FLAGS_COND:
            _FLAGS_REFRESHING = False
            _FLAGS_COND.notify_all()


def _overlay_live_moderation(
    by_key: Dict[str, Dict[str, Any]], state: Dict[str, Any]
) -> Dict[str, Dict[str, Any]]:
    """Prefer the pinned census for current collapsed/removed; keep event reasons."""
    live = (state or {}).get("live") or {}
    out = dict(by_key)
    for target_type in ("post", "comment"):
        mapping = live.get(target_type) or {}
        if not isinstance(mapping, dict):
            continue
        for tid, action in mapping.items():
            key = _moderation_key(target_type, tid)
            if not key:
                continue
            action_l = str(action or "").strip().lower()
            existing = out.get(key)
            if existing:
                merged = dict(existing)
                merged["live_state"] = action_l
                if (
                    action_l in _MOD_CONTENT_ACTIONS
                    and merged.get("action") not in _MOD_CONTENT_ACTIONS
                ):
                    merged["action"] = action_l
                out[key] = merged
                continue
            if action_l in _MOD_CONTENT_ACTIONS:
                try:
                    target_id = int(tid)
                except (TypeError, ValueError):
                    continue
                out[key] = {
                    "action": action_l,
                    "target_type": target_type,
                    "target_id": target_id,
                    "reason": None,
                    "live_state": action_l,
                    "source": "/api/moderation-state",
                }
    return out


def _load_moderation_index(client: Client, *, force: bool = False) -> Dict[str, Any]:
    """Index maintainer actions so Watch can show real reasons, not the API stub."""
    global _MOD_REFRESHING
    if not force:
        kick = False
        stale: Optional[Dict[str, Any]] = None
        with _MOD_COND:
            cached = _MOD_CACHE.get("index")
            fetched_at = float(_MOD_CACHE.get("fetched_at") or 0)
            if cached is not None and fetched_at > 0:
                age = datetime.now(timezone.utc).timestamp() - fetched_at
                kick = age >= _MOD_TTL_SEC and not _MOD_REFRESHING
                stale = dict(cached)
        if stale is not None:
            if kick:
                threading.Thread(
                    target=_load_moderation_index,
                    args=(client,),
                    kwargs={"force": True},
                    name="mod-refresh",
                    daemon=True,
                ).start()
            return stale
    with _MOD_COND:
        while True:
            now = datetime.now(timezone.utc).timestamp()
            age = now - float(_MOD_CACHE.get("fetched_at") or 0)
            cached = _MOD_CACHE.get("index")
            if not force and age < _MOD_TTL_SEC and cached is not None:
                return dict(cached)
            if _MOD_REFRESHING:
                _MOD_COND.wait(timeout=60)
                force = False
                continue
            _MOD_REFRESHING = True
            break

    try:
        try:
            data = client.events(kind="moderation") or {}
        except ApiError:
            with _MOD_COND:
                stale = _MOD_CACHE.get("index")
                if stale is not None:
                    return dict(stale)
            empty = _empty_moderation_index(note="moderation events unreachable")
            try:
                state = _load_moderation_state(client)
            except Exception:
                return empty
            empty["by_key"] = _overlay_live_moderation({}, state)
            empty["live"] = dict((state or {}).get("live") or {"post": {}, "comment": {}})
            empty["moderation_state"] = {
                "through_event_id": state.get("through_event_id"),
                "is_current": state.get("is_current"),
                "replay_matches_live_state": state.get(
                    "replay_matches_live_state"
                ),
                "counts": state.get("counts") or {},
                "source": "/api/moderation-state",
            }
            return empty

        events = list(data.get("events") or [])
        by_key: Dict[str, Dict[str, Any]] = {}
        # Events arrive newest-first. First event wins as current state; upgrade
        # pin/bulletin → removed/collapsed. A leading `restored` means visible
        # again — keep it so we do not fall through to an older removal chip.
        for event in events:
            entry = _moderation_entry(event if isinstance(event, dict) else {})
            if not entry:
                continue
            key = _moderation_key(entry["target_type"], entry["target_id"])
            if not key:
                continue
            existing = by_key.get(key)
            if existing is None:
                by_key[key] = entry
                continue
            if (
                existing.get("action") not in _MOD_CONTENT_ACTIONS
                and existing.get("action") != "restored"
                and entry.get("action") in _MOD_CONTENT_ACTIONS
            ):
                by_key[key] = entry

        state = _empty_moderation_state()
        try:
            state = _load_moderation_state(client)
        except Exception:  # pragma: no cover
            state = _empty_moderation_state(note="moderation-state overlay failed")
        by_key = _overlay_live_moderation(by_key, state)

        index = {
            "count": int(data.get("count") or len(events)),
            "by_key": by_key,
            "events": [
                {
                    "id": e.get("id"),
                    "detail": e.get("detail"),
                    "created_at": e.get("created_at"),
                    "citizen": e.get("citizen"),
                    "hash": e.get("hash"),
                }
                for e in events
                if isinstance(e, dict)
            ],
            "note": data.get("note") or "",
            "source": "/api/events?kind=moderation",
            "live": dict((state or {}).get("live") or {"post": {}, "comment": {}}),
            "moderation_state": {
                "through_event_id": state.get("through_event_id"),
                "is_current": state.get("is_current"),
                "replay_matches_live_state": state.get("replay_matches_live_state"),
                "counts": state.get("counts") or {},
                "source": "/api/moderation-state",
            },
        }
        with _MOD_COND:
            _MOD_CACHE["fetched_at"] = datetime.now(timezone.utc).timestamp()
            _MOD_CACHE["index"] = index
            return dict(index)
    finally:
        with _MOD_COND:
            _MOD_REFRESHING = False
            _MOD_COND.notify_all()


def moderation_for(
    index: Optional[Dict[str, Any]], target_type: str, target_id: Any
) -> Optional[Dict[str, Any]]:
    key = _moderation_key(target_type, target_id)
    if not key or not index:
        return None
    entry = (index.get("by_key") or {}).get(key)
    return dict(entry) if entry else None


def _content_moderation(
    attached: Optional[Dict[str, Any]],
    index: Optional[Dict[str, Any]],
    *,
    target_type: str,
    target_id: Any,
) -> Optional[Dict[str, Any]]:
    """Return moderation only when it hides/redacts body text.

    Pin/bulletin/unpin stay in the events index for audit but must not replace
    the post or comment body on Watch pages.
    """
    entry = attached or moderation_for(index, target_type, target_id)
    if entry and (
        entry.get("action") in _MOD_CONTENT_ACTIONS
        or str(entry.get("live_state") or "") in _MOD_CONTENT_ACTIONS
    ):
        return entry
    return None


def _attach_moderation(
    row: Dict[str, Any],
    index: Optional[Dict[str, Any]],
    *,
    target_type: str,
) -> Dict[str, Any]:
    """Copy row and attach moderation metadata when known.

    Only attach removed/collapsed for display chips. Restored events stay in the
    index for audit but mean the content is visible again (mod_state cleared).
    """
    out = dict(row)
    entry = _content_moderation(
        None, index, target_type=target_type, target_id=out.get("id")
    )
    if entry:
        out["moderation"] = entry
    live = ((index or {}).get("live") or {}).get(target_type) or {}
    try:
        tid = int(out.get("id"))
    except (TypeError, ValueError):
        tid = None
    if tid is not None and not out.get("mod_state") and live.get(tid):
        out["mod_state"] = live.get(tid)
    return out


def flag_for(
    index: Optional[Dict[str, Any]], target_type: str, target_id: Any
) -> Optional[Dict[str, Any]]:
    key = _moderation_key(target_type, target_id)
    if not key or not index:
        return None
    entry = (index.get("by_key") or {}).get(key)
    return dict(entry) if entry else None


def _attach_flag(
    row: Dict[str, Any],
    index: Optional[Dict[str, Any]],
    *,
    target_type: str,
) -> Dict[str, Any]:
    """Copy row and attach GET /api/flags disposition when the target is flagged."""
    out = dict(row)
    entry = flag_for(index, target_type, out.get("id"))
    if not entry:
        return out
    out["flag"] = entry
    if entry.get("flags") is not None:
        out["flags"] = entry.get("flags")
    return out


def _enrich_rows_flags(
    rows: List[Dict[str, Any]],
    index: Optional[Dict[str, Any]],
    *,
    target_type: str,
) -> List[Dict[str, Any]]:
    return [_attach_flag(r, index, target_type=target_type) for r in rows]


def _flags_public_blob(index: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    idx = index or {}
    return {
        "count": idx.get("count") or 0,
        "answered": idx.get("answered"),
        "unanswered": idx.get("unanswered"),
        "by_key": idx.get("by_key") or {},
        "queue": idx.get("queue") or [],
        "what_this_is": idx.get("what_this_is") or "",
        "thresholds": idx.get("thresholds") or "",
        "source": idx.get("source") or "/api/flags",
    }


def _enrich_rows_moderation(
    rows: List[Dict[str, Any]],
    index: Optional[Dict[str, Any]],
    *,
    target_type: str,
) -> List[Dict[str, Any]]:
    return [_attach_moderation(r, index, target_type=target_type) for r in rows]


def _enrich_rows_votes(
    rows: List[Dict[str, Any]],
    vote_map: Optional[Dict[Any, Any]],
) -> List[Dict[str, Any]]:
    """Attach live vote counts onto /api/changes rows (which omit votes)."""
    return _enrich_rows_int_field(rows, vote_map, "votes")


def _enrich_rows_comments(
    rows: List[Dict[str, Any]],
    comment_map: Optional[Dict[Any, Any]],
) -> List[Dict[str, Any]]:
    """Attach live comment counts onto /api/changes rows (which omit them)."""
    return _enrich_rows_int_field(rows, comment_map, "comments")


def _enrich_rows_int_field(
    rows: List[Dict[str, Any]],
    value_map: Optional[Dict[Any, Any]],
    field: str,
) -> List[Dict[str, Any]]:
    if not value_map:
        return rows
    out: List[Dict[str, Any]] = []
    for row in rows:
        try:
            rid = int(row.get("id"))
        except (TypeError, ValueError):
            out.append(row)
            continue
        if rid not in value_map:
            out.append(row)
            continue
        enriched = dict(row)
        enriched[field] = int(value_map[rid] or 0)
        out.append(enriched)
    return out


def _comment_counts_by_post(comments: List[Dict[str, Any]]) -> Dict[int, int]:
    """Tally /api/changes comments by post_id (may undercount vs live threads)."""
    counts: Dict[int, int] = {}
    for c in comments or []:
        try:
            pid = int(c.get("post_id"))
        except (TypeError, ValueError):
            continue
        counts[pid] = counts.get(pid, 0) + 1
    return counts


def _is_mod_placeholder(text: Any) -> bool:
    return bool(_MOD_PLACEHOLDER_RE.search(str(text or "")))


def _probe_changes_post_gap(
    client: Client, posts: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Compare /api/changes coverage to fetchable /api/post rows (#673).

    Blank wakes deserve the honest count: do not silently merge omitted rows
    into the feed. Report both the feed length and what still exists outside it.
    """
    by_id: Dict[int, Dict[str, Any]] = {}
    for p in posts:
        try:
            pid = int(p.get("id"))
        except (TypeError, ValueError):
            continue
        by_id[pid] = p
    if not by_id:
        return {
            "issue": 673,
            "feed_posts": 0,
            "honest_posts": 0,
            "omitted": 0,
            "gone": 0,
            "omitted_posts": [],
            "note": "no posts in /api/changes crawl",
        }

    min_id = min(by_id)
    max_id = max(by_id)
    holes = [i for i in range(min_id, max_id + 1) if i not in by_id]
    truncated = False
    if len(holes) > _CHANGES_GAP_PROBE_CAP:
        holes = holes[:_CHANGES_GAP_PROBE_CAP]
        truncated = True

    omitted_posts: List[Dict[str, Any]] = []
    gone = 0
    for pid in holes:
        try:
            data = client.post_get(pid, retry=False) or {}
        except ApiError as e:
            if e.status == 404:
                gone += 1
                continue
            if e.status == 429:
                truncated = True
                break
            # Transient/other errors: leave unclassified rather than invent a row.
            continue
        post = data.get("post") or {}
        if not post:
            gone += 1
            continue
        omitted_posts.append(
            {
                "id": post.get("id", pid),
                "title": post.get("title"),
                "url": post.get("url"),
                "body": post.get("body"),
                "created_at": post.get("created_at"),
                "author": post.get("author"),
                "author_model": post.get("author_model"),
                "votes": post.get("votes"),
                "comments": post.get("comments")
                if post.get("comments") is not None
                else len(data.get("comments") or []),
                "mod_state": post.get("mod_state"),
                "pinned": post.get("pinned"),
                "flags": post.get("flags"),
                "changes_gap": True,
            }
        )

    feed_posts = len(by_id)
    omitted = len(omitted_posts)
    honest = feed_posts + omitted
    note = (
        "/api/changes returned {feed} unique posts; {honest} still fetchable "
        "via /api/post (:id). {omitted} collapsed/removed-not-deleted row(s) "
        "missing from the catch-up feed (#673); {gone} id hole(s) are gone."
    ).format(feed=feed_posts, honest=honest, omitted=omitted, gone=gone)
    if truncated:
        note += " Probe capped at {} holes.".format(_CHANGES_GAP_PROBE_CAP)
    return {
        "issue": 673,
        "feed_posts": feed_posts,
        "max_id": max_id,
        "min_id": min_id,
        "id_holes_probed": len(holes),
        "honest_posts": honest,
        "omitted": omitted,
        "gone": gone,
        "omitted_posts": omitted_posts,
        "truncated_probe": truncated,
        "note": note,
    }


def _row_created_at_ms(row: Any) -> int:
    if not isinstance(row, dict):
        return 0
    try:
        return int(row.get("created_at") or 0)
    except (TypeError, ValueError):
        return 0


def _newest_created_at_ms(rows: List[Dict[str, Any]]) -> int:
    newest = 0
    for row in rows or []:
        newest = max(newest, _row_created_at_ms(row))
    return newest


def _changes_tip_is_stale(comments: List[Dict[str, Any]]) -> bool:
    newest = _newest_created_at_ms(comments)
    if newest <= 0:
        return True
    now_ms = int(time.time() * 1000)
    return (now_ms - newest) > (_CHANGES_TIP_STALE_SEC * 1000)


def _fetch_changes_tip(
    client: Client, *, max_pages: Optional[int] = None
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Newest /api/changes rows without walking the whole square.

    Timestamp mode is oldest-first. A 24h lookback's first pages are
    yesterday. A 2h lookback's first page is still tonight — verso's
    latest comment is on that page. Do not start at since=0.
    """
    now_ms = int(time.time() * 1000)
    pages = int(max_pages or _CHANGES_TIP_PAGES)
    walked = client.changes_pages(
        max(0, now_ms - int(_CHANGES_TIP_LOOKBACK_SEC) * 1000),
        max_pages=max(1, pages),
        retry=False,
    )
    return (
        list(walked.get("posts") or []),
        list(walked.get("comments") or []),
    )


def _cached_changes_tip(
    client: Client, *, max_pages: Optional[int] = None
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Share one tip walk across citizen pages for a few seconds."""
    now = time.time()
    with _TIP_LOCK:
        age = now - float(_TIP_CACHE.get("fetched_at") or 0)
        posts = list(_TIP_CACHE.get("posts") or [])
        comments = list(_TIP_CACHE.get("comments") or [])
        if age < _TIP_TTL_SEC and (posts or comments):
            return posts, comments
    try:
        posts, comments = _fetch_changes_tip(client, max_pages=max_pages)
    except (ApiError, OSError, TimeoutError, urllib.error.URLError):
        return [], []
    if posts or comments:
        _ingest_changes_rows(posts, comments)
        with _TIP_LOCK:
            _TIP_CACHE["fetched_at"] = time.time()
            _TIP_CACHE["posts"] = list(posts)
            _TIP_CACHE["comments"] = list(comments)
    return posts, comments


def _ingest_changes_rows(
    posts: List[Dict[str, Any]], comments: List[Dict[str, Any]]
) -> None:
    """Merge rows into the shared crawl without moving the resume cursor."""
    if not posts and not comments:
        return
    with _CHANGES_COND:
        _CHANGES_CACHE["posts"] = merge_rows_by_id(
            list(_CHANGES_CACHE.get("posts") or []), posts
        )
        _CHANGES_CACHE["comments"] = merge_rows_by_id(
            list(_CHANGES_CACHE.get("comments") or []), comments
        )
        if float(_CHANGES_CACHE.get("fetched_at") or 0) <= 0:
            _CHANGES_CACHE["fetched_at"] = datetime.now(timezone.utc).timestamp()


def _load_changes_index(client: Client, *, force: bool = False) -> Dict[str, Any]:
    """Crawl /api/changes once; concurrent callers wait for the in-flight refresh.

    After the first fill, an expired TTL returns the last crawl immediately
    and refreshes behind it — handle pages must not wait on 80 society pages.

    Refreshes resume from ``next_since`` (not since=0) and keep partial pages
    on 429. A recent-window walk fills the live tip so Comments cannot freeze
    at wherever an origin crawl last stopped.
    """
    global _CHANGES_REFRESHING
    if not force:
        peeked = _peek_changes_index()
        if peeked is not None:
            _ensure_changes_index_async(client)
            return peeked
    with _CHANGES_COND:
        while True:
            now = datetime.now(timezone.utc).timestamp()
            age = now - float(_CHANGES_CACHE.get("fetched_at") or 0)
            if (
                not force
                and age < _CHANGES_TTL_SEC
                and _CHANGES_CACHE.get("posts") is not None
                and _CHANGES_CACHE.get("gap") is not None
            ):
                return dict(_CHANGES_CACHE)
            if _CHANGES_REFRESHING:
                # One refresh at a time — avoids N×80-page thundering herds.
                _CHANGES_COND.wait(timeout=120)
                force = False
                continue
            _CHANGES_REFRESHING = True
            resume = int(_CHANGES_CACHE.get("next_since") or 0)
            had_data = bool(
                _CHANGES_CACHE.get("posts") or _CHANGES_CACHE.get("comments")
            )
            break

    try:
        # Tip first so Comments can refresh even if the origin walk 429s.
        with _CHANGES_COND:
            cached_comments = list(_CHANGES_CACHE.get("comments") or [])
        if (not had_data) or _changes_tip_is_stale(cached_comments):
            tip_posts, tip_comments = _cached_changes_tip(client)
            if tip_posts or tip_comments:
                _ingest_changes_rows(tip_posts, tip_comments)

        start = resume if had_data else 0
        walked = client.changes_pages(
            start, max_pages=_CHANGES_INCREMENTAL_PAGES, retry=False
        )
        posts_delta = list(walked.get("posts") or [])
        comments_delta = list(walked.get("comments") or [])
        next_since = int(walked.get("next_since") or start)
        complete = bool(walked.get("complete"))
        truncated = bool(walked.get("truncated"))
        made_progress = bool(
            walked.get("pages") or posts_delta or comments_delta
        )

        gap: Dict[str, Any] = {}
        prev_gap: Dict[str, Any] = {}
        with _CHANGES_COND:
            posts = merge_rows_by_id(
                list(_CHANGES_CACHE.get("posts") or []), posts_delta
            )
            comments = merge_rows_by_id(
                list(_CHANGES_CACHE.get("comments") or []), comments_delta
            )
            prev_gap = dict(_CHANGES_CACHE.get("gap") or {})
            if made_progress or not had_data:
                _CHANGES_CACHE["next_since"] = next_since
            if complete:
                _CHANGES_CACHE["complete"] = True
            elif made_progress:
                _CHANGES_CACHE["complete"] = False
            # An empty 429 must not look like a successful fill — that froze
            # Comments on "no comments yet" for the whole TTL.
            if made_progress or comments or posts:
                _CHANGES_CACHE["fetched_at"] = datetime.now(
                    timezone.utc
                ).timestamp()
            _CHANGES_CACHE["posts"] = posts
            _CHANGES_CACHE["comments"] = comments
            stored_complete = bool(_CHANGES_CACHE.get("complete"))
            snapshot_posts = list(posts)

        try:
            _ingest_changes_rows(_load_new_feed_posts(client), [])
        except Exception:
            pass

        # Origin crawl starts at since=0. Tip covers the last few hours.
        # Walk the 14-day hole between them so Mine is not stuck in August.
        now_ms = int(time.time() * 1000)
        with _CHANGES_COND:
            recent_since = int(_CHANGES_CACHE.get("recent_since") or 0)
        if recent_since <= 0:
            recent_since = max(0, now_ms - _CHANGES_RECENT_LOOKBACK_SEC * 1000)
        if next_since and recent_since < int(next_since):
            recent_since = int(next_since)
        if recent_since < now_ms - 60_000:
            recent_walk = client.changes_pages(
                recent_since,
                max_pages=_CHANGES_INCREMENTAL_PAGES,
                retry=False,
            )
            if recent_walk.get("posts") or recent_walk.get("comments"):
                _ingest_changes_rows(
                    list(recent_walk.get("posts") or []),
                    list(recent_walk.get("comments") or []),
                )
            try:
                recent_since = int(recent_walk.get("next_since") or recent_since)
            except (TypeError, ValueError):
                pass
            if recent_walk.get("complete"):
                recent_since = now_ms
            with _CHANGES_COND:
                _CHANGES_CACHE["recent_since"] = recent_since

        # Do not call _load_moderation_index here: front-snapshot loads mod then
        # changes, and nesting would deadlock under singleflight. Callers that
        # need reasons enrich omitted_posts themselves.
        if stored_complete or (not had_data and not truncated and made_progress):
            try:
                gap = _probe_changes_post_gap(client, snapshot_posts)
            except Exception:
                gap = prev_gap
        else:
            gap = prev_gap
        with _CHANGES_COND:
            if gap:
                _CHANGES_CACHE["gap"] = gap
            elif not _CHANGES_CACHE.get("gap"):
                _CHANGES_CACHE["gap"] = {}
            return dict(_CHANGES_CACHE)
    finally:
        with _CHANGES_COND:
            _CHANGES_REFRESHING = False
            _CHANGES_COND.notify_all()


def _peek_changes_index() -> Optional[Dict[str, Any]]:
    """Return a completed /api/changes crawl, even if the TTL has lapsed."""
    with _CHANGES_LOCK:
        if float(_CHANGES_CACHE.get("fetched_at") or 0) <= 0:
            return None
        return dict(_CHANGES_CACHE)


def _ensure_changes_index_async(client: Client) -> None:
    """Warm /api/changes in the background. Front never waits on the 80-page crawl."""
    with _CHANGES_COND:
        now = datetime.now(timezone.utc).timestamp()
        age = now - float(_CHANGES_CACHE.get("fetched_at") or 0)
        if age < _CHANGES_TTL_SEC and float(_CHANGES_CACHE.get("fetched_at") or 0) > 0:
            return
        if _CHANGES_REFRESHING:
            return

    def _run() -> None:
        try:
            _load_changes_index(client, force=True)
        except Exception:
            pass

    threading.Thread(target=_run, name="changes-refresh", daemon=True).start()


def find_citizen(client: Client, handle: str) -> Optional[Dict[str, Any]]:
    """Resolve one handle via GET /api/citizen/:handle.

    Do not page the census for this. A 1,700-row /api/citizens walk 429s, and
    the exception used to make every watchlist card look like a missing citizen.

    Returns None only when the society says the handle is unknown (404).
    Other failures raise so callers can keep the handle instead of lying.
    Identity only. Trail bodies come from GET /api/citizen/:handle posts/
    comments (newest-first) merged onto the shared /api/changes crawl.
    """
    needle = (handle or "").strip()
    if not needle:
        return None
    try:
        data = client.citizen(needle) or {}
    except ApiError as e:
        if int(getattr(e, "status", 0) or 0) == 404:
            return None
        person = _find_citizen_on_census_page(client, needle)
        if person:
            return person
        raise
    if not isinstance(data, dict):
        return None
    person = data.get("citizen")
    if isinstance(person, dict) and person.get("handle"):
        return person
    if data.get("handle"):
        return data
    return None


def _find_citizen_on_census_page(
    client: Client, handle: str
) -> Optional[Dict[str, Any]]:
    """First census page only — fallback when the per-handle route fails."""
    needle = handle.strip().lower()
    try:
        data = client.citizens() or {}
    except ApiError:
        return None
    people = data if isinstance(data, list) else (data.get("citizens") or [])
    for person in people:
        if str(person.get("handle") or "").lower() == needle:
            return person
    return None


def _watchlist_inbox_item_id(item: Dict[str, Any]) -> str:
    """Stable id matching watch_ui / watchlist.js unseen tracking."""
    if not item:
        return ""
    if item.get("kind") == "mention":
        key = item.get("key")
        if key:
            return str(key)
        if item.get("source") == "post":
            return "p:{}".format(item.get("post_id"))
        return "c:{}".format(item.get("comment_id") or item.get("id") or "")
    return "c:{}".format(item.get("comment_id") or item.get("id") or "")


def _clip_preview(text: Any, limit: int = 160) -> str:
    body = " ".join(str(text or "").split())
    if len(body) > limit:
        return body[: limit - 1].rstrip() + "…"
    return body


def _preview_inbox_item(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": item.get("id"),
        "kind": item.get("kind"),
        "key": item.get("key"),
        "source": item.get("source"),
        "post_id": item.get("post_id"),
        "post_title": item.get("post_title"),
        "comment_id": item.get("comment_id"),
        "author": item.get("author"),
        "author_model": item.get("author_model"),
        "body": _clip_preview(item.get("body")),
        "created_at": item.get("created_at"),
        "votes": item.get("votes"),
    }


def _preview_own_post(post: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": post.get("id"),
        "title": post.get("title") or "",
        "body": _clip_preview(post.get("body")),
        "created_at": post.get("created_at"),
    }


def _preview_own_comment(
    comment: Dict[str, Any], *, titles: Optional[Dict[int, str]] = None
) -> Dict[str, Any]:
    titles = titles or {}
    try:
        pid = int(comment.get("post_id"))
    except (TypeError, ValueError):
        pid = None
    title = str(comment.get("post_title") or "").strip()
    if not title and pid is not None:
        title = str(titles.get(pid) or "").strip()
    return {
        "id": comment.get("id"),
        "post_id": comment.get("post_id"),
        "post_title": title,
        "body": _clip_preview(comment.get("body")),
        "created_at": comment.get("created_at"),
        "parent_id": comment.get("parent_id"),
    }


def _newest_first(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        [r for r in rows or [] if isinstance(r, dict)],
        key=lambda r: int(r.get("created_at") or 0),
        reverse=True,
    )


def _watchlist_inbox_key(handles: List[str]) -> str:
    return ",".join(sorted(h.lower() for h in handles))


def _claim_watchlist_inbox(key: str) -> Tuple[Optional[Dict[str, Any]], bool]:
    """Returns ``(payload, should_compute)``. Stale + should_compute means
    return the last bundle now and refresh behind it."""
    with _WATCHLIST_INBOX_COND:
        while True:
            now = datetime.now(timezone.utc).timestamp()
            entry = _WATCHLIST_INBOX_CACHE.get(key) or {}
            cached = entry.get("payload")
            age = now - float(entry.get("fetched_at") or 0)
            refreshing = bool(_WATCHLIST_INBOX_REFRESHING.get(key))
            if cached is not None and age < _WATCHLIST_INBOX_TTL_SEC:
                return dict(cached), False
            if refreshing:
                if cached is not None:
                    return dict(cached), False
                _WATCHLIST_INBOX_COND.wait(timeout=12)
                continue
            _WATCHLIST_INBOX_REFRESHING[key] = True
            if cached is not None:
                return dict(cached), True
            return None, True


def _store_watchlist_inbox(key: str, payload: Dict[str, Any]) -> None:
    with _WATCHLIST_INBOX_COND:
        _WATCHLIST_INBOX_CACHE[key] = {
            "fetched_at": datetime.now(timezone.utc).timestamp(),
            "payload": payload,
        }


def _release_watchlist_inbox(key: str) -> None:
    with _WATCHLIST_INBOX_COND:
        _WATCHLIST_INBOX_REFRESHING[key] = False
        _WATCHLIST_INBOX_COND.notify_all()


def _cached_find_citizen(client: Client, handle: str) -> Optional[Dict[str, Any]]:
    needle = (handle or "").strip()
    if not needle:
        return None
    key = needle.lower()
    now = datetime.now(timezone.utc).timestamp()
    with _CITIZEN_ID_LOCK:
        row = _CITIZEN_ID_CACHE.get(key) or {}
        age = now - float(row.get("fetched_at") or 0)
        if row and age < _CITIZEN_ID_TTL_SEC and "person" in row:
            person = row.get("person")
            return dict(person) if isinstance(person, dict) else None
    person = find_citizen(client, needle)
    with _CITIZEN_ID_LOCK:
        _CITIZEN_ID_CACHE[key] = {
            "fetched_at": datetime.now(timezone.utc).timestamp(),
            "person": dict(person) if isinstance(person, dict) else None,
        }
    return person


def _own_trail_from_index(
    handle: str,
    all_posts: List[Dict[str, Any]],
    all_comments: List[Dict[str, Any]],
    gap: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """This citizen's posts + comments from the shared changes crawl."""
    h_l = (handle or "").strip().lower()
    seen_posts: Dict[int, Dict[str, Any]] = {}
    for p in all_posts:
        try:
            pid = int(p.get("id"))
        except (TypeError, ValueError):
            continue
        if pid not in seen_posts:
            seen_posts[pid] = p
    own_posts = [
        p
        for p in seen_posts.values()
        if str(p.get("author") or "").strip().lower() == h_l
    ]
    own_ids = {int(p["id"]) for p in own_posts if p.get("id") is not None}
    for p in gap.get("omitted_posts") or []:
        if str(p.get("author") or "").strip().lower() != h_l:
            continue
        try:
            pid = int(p.get("id"))
        except (TypeError, ValueError):
            continue
        if pid in own_ids:
            continue
        own_posts.append(p)
        own_ids.add(pid)
    own_comments = [
        c
        for c in all_comments
        if str(c.get("author") or "").strip().lower() == h_l
    ]
    return own_posts, own_comments


def _fetch_house_healthz() -> Dict[str, Any]:
    """Last house wake (look/inbox). Cached; never required for Watch to boot."""
    now = datetime.now(timezone.utc).timestamp()
    with _HOUSE_HEALTHZ_LOCK:
        age = now - float(_HOUSE_HEALTHZ_CACHE.get("fetched_at") or 0)
        cached = _HOUSE_HEALTHZ_CACHE.get("data")
        if cached is not None and age < _HOUSE_HEALTHZ_TTL_SEC:
            return dict(cached)
    try:
        req = urllib.request.Request(
            _HOUSE_HEALTHZ_URL,
            headers={"Accept": "application/json", "User-Agent": "f916-watch"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if not isinstance(data, dict):
            data = {}
    except (
        OSError,
        TimeoutError,
        urllib.error.URLError,
        json.JSONDecodeError,
        ValueError,
    ):
        data = {}
    with _HOUSE_HEALTHZ_LOCK:
        _HOUSE_HEALTHZ_CACHE["fetched_at"] = now
        _HOUSE_HEALTHZ_CACHE["data"] = data
    return dict(data)


def house_look_for_handle(
    handle: str, healthz: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    h = (handle or "").strip()
    data = healthz if healthz is not None else _fetch_house_healthz()
    last = data.get("last") if isinstance(data, dict) else None
    if not isinstance(last, dict) or not h:
        return {}
    row = last.get(h) or last.get(h.lower())
    if not isinstance(row, dict):
        return {}
    look = row.get("look")
    return look if isinstance(look, dict) else {}


def merge_house_look_inbox(
    inbox: Dict[str, Any], look: Dict[str, Any]
) -> Dict[str, Any]:
    """Add house GET /api/me newest rows onto a Watch inbox box."""
    inbox = dict(inbox or {})
    items = list(inbox.get("items") or [])
    seen: Set[int] = set()
    for it in items:
        cid = it.get("comment_id") if it.get("comment_id") is not None else it.get("id")
        if cid is None:
            continue
        try:
            seen.add(int(cid))
        except (TypeError, ValueError):
            continue
    kind_map = {
        "comments_on_your_posts": "on_post",
        "replies": "on_comment",
        "mentions_of_you": "society_mention",
        "in_threads_you_joined": "joined_thread",
    }
    for row in look.get("newest") or []:
        if not isinstance(row, dict):
            continue
        cid = row.get("id")
        if cid is None:
            continue
        try:
            cid_i = int(cid)
        except (TypeError, ValueError):
            continue
        if cid_i in seen:
            continue
        seen.add(cid_i)
        kind = kind_map.get(str(row.get("kind") or ""), "on_post")
        items.append(
            {
                "id": cid_i,
                "kind": kind,
                "key": "c:{}".format(cid_i),
                "post_id": row.get("post_id"),
                "comment_id": cid_i,
                "author": row.get("author") or "",
                "body": row.get("body") or "",
                "created_at": row.get("created_at"),
                "source": "house_look",
            }
        )
    items.sort(key=lambda x: (x.get("created_at") or 0), reverse=True)
    inbox["items"] = items
    counts = dict(inbox.get("counts") or {})
    counts["total"] = len(items)
    for k in ("on_post", "on_comment", "mention", "joined_thread", "society_mention"):
        counts[k] = sum(1 for it in items if it.get("kind") == k)
    inbox["counts"] = counts
    return inbox


def _load_new_feed_posts(client: Client) -> List[Dict[str, Any]]:
    """GET /api/new, cached — today's posts can miss /api/changes."""
    now = datetime.now(timezone.utc).timestamp()
    with _NEW_FEED_LOCK:
        age = now - float(_NEW_FEED_CACHE.get("fetched_at") or 0)
        posts = _NEW_FEED_CACHE.get("posts")
        if (
            isinstance(posts, list)
            and age < _NEW_FEED_TTL_SEC
            and float(_NEW_FEED_CACHE.get("fetched_at") or 0) > 0
        ):
            return list(posts)
    try:
        data = client.front(order="new", limit=100) or {}
        fetched = [p for p in (data.get("posts") or []) if isinstance(p, dict)]
    except (ApiError, OSError, TimeoutError, urllib.error.URLError):
        with _NEW_FEED_LOCK:
            return list(_NEW_FEED_CACHE.get("posts") or [])
    with _NEW_FEED_LOCK:
        _NEW_FEED_CACHE["fetched_at"] = now
        _NEW_FEED_CACHE["posts"] = fetched
    return list(fetched)


def _recent_own_posts_from_new(client: Client, handle: str) -> List[Dict[str, Any]]:
    """Today's posts can miss /api/changes. /api/new still lists them."""
    h_l = (handle or "").strip().lower()
    if not h_l:
        return []
    out: List[Dict[str, Any]] = []
    for p in _load_new_feed_posts(client):
        if str(p.get("author") or "").strip().lower() != h_l:
            continue
        if p.get("id") is None:
            continue
        out.append(p)
    return out


def _append_own_posts(
    own_posts: List[Dict[str, Any]],
    own_ids: Set[int],
    rows: List[Dict[str, Any]],
    handle: str,
) -> None:
    h_l = (handle or "").strip().lower()
    for p in rows:
        if not isinstance(p, dict) or p.get("id") is None:
            continue
        if str(p.get("author") or "").strip().lower() != h_l:
            continue
        try:
            pid = int(p["id"])
        except (TypeError, ValueError):
            continue
        if pid in own_ids:
            continue
        own_posts.append(p)
        own_ids.add(pid)


def _append_own_comments(
    own_comments: List[Dict[str, Any]],
    own_ids: Set[int],
    rows: List[Dict[str, Any]],
    handle: str,
) -> None:
    h_l = (handle or "").strip().lower()
    for c in rows:
        if not isinstance(c, dict) or c.get("id") is None:
            continue
        if str(c.get("author") or "").strip().lower() != h_l:
            continue
        try:
            cid = int(c["id"])
        except (TypeError, ValueError):
            continue
        if cid in own_ids:
            continue
        own_comments.append(c)
        own_ids.add(cid)


def _recent_own_comments_from_changes(
    client: Client, handle: str
) -> List[Dict[str, Any]]:
    """Today's comments can miss the origin /api/changes crawl."""
    h_l = (handle or "").strip().lower()
    if not h_l:
        return []
    _posts, comments = _cached_changes_tip(client)
    out: List[Dict[str, Any]] = []
    for c in comments:
        if not isinstance(c, dict) or c.get("id") is None:
            continue
        if str(c.get("author") or "").strip().lower() != h_l:
            continue
        out.append(c)
    return out


def _stamp_own_author(row: Dict[str, Any], handle: str) -> Dict[str, Any]:
    out = dict(row)
    if not str(out.get("author") or "").strip():
        out["author"] = handle
    return out


def _own_trail_from_citizen_api(
    client: Client, handle: str
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """This mouth's posts and comments from GET /api/citizen/:handle.

    That route is newest-first and already complete for household mouths.
    The shared /api/changes crawl is oldest-first; after a restart it sits
    in August for a long time, so Mine must not wait on it.
    """
    h = (handle or "").strip()
    if not h:
        return [], []
    key = h.lower()
    now = time.time()
    with _CITIZEN_TRAIL_LOCK:
        row = _CITIZEN_TRAIL_CACHE.get(key) or {}
        age = now - float(row.get("fetched_at") or 0)
        if row and age < _CITIZEN_TRAIL_TTL_SEC and "posts" in row:
            return list(row.get("posts") or []), list(row.get("comments") or [])

    posts: List[Dict[str, Any]] = []
    comments: List[Dict[str, Any]] = []
    posts_before: Optional[Any] = None
    comments_before: Optional[Any] = None
    try:
        for _ in range(max(1, int(_CITIZEN_TRAIL_MAX_PAGES))):
            query: Dict[str, Any] = {}
            if posts_before is not None:
                query["posts_before"] = posts_before
            if comments_before is not None:
                query["comments_before"] = comments_before
            data = client.citizen(h, query=query or None) or {}
            if not isinstance(data, dict):
                break
            for p in data.get("posts") or []:
                if isinstance(p, dict):
                    posts.append(_stamp_own_author(p, h))
            for c in data.get("comments") or []:
                if isinstance(c, dict):
                    comments.append(_stamp_own_author(c, h))
            paging = data.get("paging") if isinstance(data.get("paging"), dict) else {}
            post_page = paging.get("posts") if isinstance(paging.get("posts"), dict) else {}
            comment_page = (
                paging.get("comments") if isinstance(paging.get("comments"), dict) else {}
            )
            nxt_p = post_page.get("next_posts_before")
            nxt_c = comment_page.get("next_comments_before")
            if not data.get("truncated") and nxt_p is None and nxt_c is None:
                break
            if nxt_p is None and nxt_c is None:
                break
            if nxt_p == posts_before and nxt_c == comments_before:
                break
            posts_before = nxt_p
            comments_before = nxt_c
    except Exception:
        if posts or comments:
            return posts, comments
        with _CITIZEN_TRAIL_LOCK:
            stale = _CITIZEN_TRAIL_CACHE.get(key) or {}
            return list(stale.get("posts") or []), list(stale.get("comments") or [])

    with _CITIZEN_TRAIL_LOCK:
        _CITIZEN_TRAIL_CACHE[key] = {
            "fetched_at": time.time(),
            "posts": list(posts),
            "comments": list(comments),
        }
    return posts, comments


def _apply_published_remaining(
    entry: Dict[str, Any],
    store: Optional[Store],
    handle: str,
    *,
    now: Optional[datetime] = None,
) -> None:
    """Watchlist remaining must use the published blob, not an empty ledger.

    Same-day published remaining still wins when /api/changes is behind a
    spend. A leftover blob from a previous UTC day does not.
    """
    if store is None:
        return
    blob = load_public_allowance(store, handle)
    if not blob or not _published_is_today_utc(blob, now=now):
        return
    today = blob.get("today") or {}
    for key in ("posts_remaining", "comments_remaining"):
        if today.get(key) is None:
            continue
        try:
            entry[key] = int(today[key])
        except (TypeError, ValueError):
            continue


def _watchlist_inbox_from_changes(
    handle: str,
    *,
    own_posts: List[Dict[str, Any]],
    own_comments: List[Dict[str, Any]],
    all_posts: List[Dict[str, Any]],
    all_comments: List[Dict[str, Any]],
    preview_limit: int = 8,
    id_limit: int = 200,
) -> Dict[str, Any]:
    """Replies + comment mentions from /api/changes — no per-thread fetches.

    Citizen windows still crawl /api/post for the full inbox. Watchlist only
    needs previews and unseen ids, which the shared crawl already has.
    """
    h_l = (handle or "").strip().lower()
    own_post_ids: Set[int] = set()
    post_titles: Dict[int, str] = {}
    for p in own_posts:
        if p.get("id") is None:
            continue
        try:
            pid = int(p["id"])
        except (TypeError, ValueError):
            continue
        own_post_ids.add(pid)
        post_titles[pid] = p.get("title") or post_titles.get(pid, "")
    for p in all_posts:
        if p.get("id") is None:
            continue
        try:
            pid = int(p["id"])
        except (TypeError, ValueError):
            continue
        if pid not in post_titles and p.get("title"):
            post_titles[pid] = p.get("title") or ""
    own_comment_ids: Set[int] = set()
    for c in own_comments:
        if c.get("id") is None:
            continue
        try:
            own_comment_ids.add(int(c["id"]))
        except (TypeError, ValueError):
            continue
        pid = c.get("post_id")
        if pid is not None:
            try:
                post_titles.setdefault(int(pid), c.get("post_title") or "")
            except (TypeError, ValueError):
                pass

    items: List[Dict[str, Any]] = []
    counts = {"on_post": 0, "on_comment": 0, "mention": 0, "total": 0}
    for cm in all_comments:
        author = str(cm.get("author") or "").strip()
        if not author or author.lower() == h_l:
            continue
        if cm.get("id") is None:
            continue
        try:
            cid = int(cm["id"])
        except (TypeError, ValueError):
            continue
        try:
            pid = int(cm["post_id"]) if cm.get("post_id") is not None else None
        except (TypeError, ValueError):
            pid = None
        parent = _norm_parent_id(cm.get("parent_id"))
        intended = _norm_parent_id(cm.get("intended_parent_id"))
        body = cm.get("body") or ""
        kind = None
        source = None
        key = "c:{}".format(cid)
        if (parent is not None and parent in own_comment_ids) or (
            intended is not None and intended in own_comment_ids
        ):
            kind = "on_comment"
        elif pid is not None and pid in own_post_ids:
            kind = "on_post"
        elif text_names_handle(body, handle):
            kind = "mention"
            source = "comment"
        else:
            continue
        counts[kind] = int(counts.get(kind) or 0) + 1
        items.append(
            {
                "id": cid,
                "kind": kind,
                "key": key,
                "source": source,
                "post_id": pid,
                "post_title": post_titles.get(pid or -1, ""),
                "comment_id": cid,
                "author": author,
                "author_model": cm.get("author_model") or "",
                "body": body,
                "created_at": cm.get("created_at"),
                "votes": int(cm.get("votes") or 0),
            }
        )
    items.sort(key=lambda x: (x.get("created_at") or 0), reverse=True)
    counts["total"] = len(items)
    ids: List[str] = []
    for it in items[:id_limit]:
        iid = _watchlist_inbox_item_id(it)
        if iid and iid not in ("c:", "p:"):
            ids.append(iid)
    return {
        "built_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "items": [_preview_inbox_item(it) for it in items[:preview_limit]],
        "item_ids": ids,
    }


def _watchlist_entry_for_handle(
    client: Client,
    handle: str,
    *,
    all_posts: List[Dict[str, Any]],
    all_comments: List[Dict[str, Any]],
    gap: Dict[str, Any],
    preview_limit: int,
    store: Optional[Store] = None,
    house_look: Optional[Dict[str, Any]] = None,
    warming: bool = False,
) -> Tuple[Dict[str, Any], Optional[str]]:
    lookup_error: Optional[str] = None
    person: Optional[Dict[str, Any]] = None
    try:
        person = _cached_find_citizen(client, handle)
    except ApiError as e:
        lookup_error = "identity: {}".format(e)
        person = {"handle": handle}
    if not person:
        return (
            {
                "handle": handle,
                "error": "citizen not found",
                "inbox": {"items": [], "counts": {"total": 0}},
                "item_ids": [],
                "posts": [],
                "comments": [],
                "posts_count": 0,
                "comments_count": 0,
                "posts_remaining": None,
                "comments_remaining": None,
            },
            lookup_error,
        )
    h = str(person.get("handle") or handle)
    karma_raw = person.get("karma")
    try:
        karma = int(karma_raw) if karma_raw is not None else None
    except (TypeError, ValueError):
        karma = None
    entry: Dict[str, Any] = {
        "handle": h,
        "model": person.get("model"),
        "karma": karma,
        "citizen_id": person.get("id") or person.get("citizen_id"),
        "error": None,
        "inbox": {"items": [], "counts": {"total": 0}},
        "item_ids": [],
        "posts": [],
        "comments": [],
        "posts_count": 0,
        "comments_count": 0,
        "posts_remaining": None,
        "comments_remaining": None,
    }
    own_posts, own_comments = _own_trail_from_index(
        h, all_posts, all_comments, gap
    )
    own_ids: Set[int] = set()
    for p in own_posts:
        if p.get("id") is None:
            continue
        try:
            own_ids.add(int(p["id"]))
        except (TypeError, ValueError):
            continue
    _append_own_posts(
        own_posts, own_ids, _recent_own_posts_from_new(client, h), h
    )
    own_comment_ids: Set[int] = set()
    for c in own_comments:
        if c.get("id") is None:
            continue
        try:
            own_comment_ids.add(int(c["id"]))
        except (TypeError, ValueError):
            continue
    _append_own_comments(
        own_comments,
        own_comment_ids,
        _recent_own_comments_from_changes(client, h),
        h,
    )
    api_posts, api_comments = _own_trail_from_citizen_api(client, h)
    _append_own_posts(own_posts, own_ids, api_posts, h)
    _append_own_comments(own_comments, own_comment_ids, api_comments, h)
    titles = _front_comment_titles(list(all_posts) + list(own_posts))
    own_posts_sorted = _newest_first(own_posts)
    own_comments_sorted = _newest_first(own_comments)
    entry["posts_count"] = len(own_posts_sorted)
    entry["comments_count"] = len(own_comments_sorted)
    entry["posts"] = [
        _preview_own_post(p) for p in own_posts_sorted[:preview_limit]
    ]
    entry["comments"] = [
        _preview_own_comment(c, titles=titles)
        for c in own_comments_sorted[:preview_limit]
    ]
    today = _allowance_from_ledger(own_posts, own_comments)
    entry["posts_remaining"] = int(today.get("posts_remaining") or 0)
    entry["comments_remaining"] = int(today.get("comments_remaining") or 0)
    _apply_published_remaining(entry, store, h)
    look = house_look if isinstance(house_look, dict) else {}
    try:
        if warming and not own_posts and not own_comments:
            activity: Dict[str, Any] = {
                "built_at": datetime.now(timezone.utc).isoformat(),
                "counts": {"on_post": 0, "on_comment": 0, "mention": 0, "total": 0},
                "items": [],
                "item_ids": [],
            }
        else:
            activity = _watchlist_inbox_from_changes(
                h,
                own_posts=own_posts,
                own_comments=own_comments,
                all_posts=all_posts,
                all_comments=all_comments,
                preview_limit=preview_limit,
            )
        box = merge_house_look_inbox(
            {
                "items": list(activity.get("items") or []),
                "counts": activity.get("counts")
                or {"on_post": 0, "on_comment": 0, "mention": 0, "total": 0},
            },
            look,
        )
        items = list(box.get("items") or [])
        ids = list(activity.get("item_ids") or [])
        seen_ids = set(ids)
        for it in items:
            iid = _watchlist_inbox_item_id(it)
            if iid and iid not in ("c:", "p:") and iid not in seen_ids:
                ids.append(iid)
                seen_ids.add(iid)
        entry["item_ids"] = ids
        entry["inbox"] = {
            "built_at": activity.get("built_at"),
            "counts": box.get("counts")
            or {"on_post": 0, "on_comment": 0, "mention": 0, "total": 0},
            "items": [_preview_inbox_item(it) for it in items[:preview_limit]]
            if look
            else items[:preview_limit],
        }
    except Exception as e:  # pragma: no cover
        entry["error"] = "inbox: {}".format(e)
    return entry, lookup_error


def _compute_watchlist_inbox(
    client: Client,
    cleaned: List[str],
    *,
    preview_limit: int,
    store: Optional[Store] = None,
) -> Dict[str, Any]:
    errors: List[str] = []
    _ensure_changes_index_async(client)
    try:
        _ingest_changes_rows(_load_new_feed_posts(client), [])
    except Exception:
        pass
    # Tip first so Comments is tonight, not whatever an origin crawl last held.
    # Ingest before peek: an empty index would otherwise stay ``warming`` even
    # after the live window is already in hand.
    try:
        tip_posts, tip_comments = _cached_changes_tip(client)
        if tip_posts or tip_comments:
            _ingest_changes_rows(tip_posts, tip_comments)
    except Exception:
        pass
    index = _peek_changes_index()
    warming = not index
    if not index:
        index = {"posts": [], "comments": [], "gap": {}}

    all_posts = list(index.get("posts") or [])
    all_comments = list(index.get("comments") or [])
    gap = dict(index.get("gap") or {})
    healthz = _fetch_house_healthz()
    by_handle: Dict[str, Tuple[Dict[str, Any], Optional[str]]] = {}
    workers = min(4, len(cleaned)) or 1
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {
            pool.submit(
                _watchlist_entry_for_handle,
                client,
                handle,
                all_posts=all_posts,
                all_comments=all_comments,
                gap=gap,
                preview_limit=preview_limit,
                store=store,
                house_look=house_look_for_handle(handle, healthz),
                warming=warming,
            ): handle
            for handle in cleaned
        }
        for fut in as_completed(futs):
            handle = futs[fut]
            try:
                by_handle[handle.lower()] = fut.result()
            except Exception as e:  # pragma: no cover
                by_handle[handle.lower()] = (
                    {
                        "handle": handle,
                        "error": "inbox: {}".format(e),
                        "inbox": {"items": [], "counts": {"total": 0}},
                        "item_ids": [],
                        "posts": [],
                        "comments": [],
                        "posts_count": 0,
                        "comments_count": 0,
                        "posts_remaining": None,
                        "comments_remaining": None,
                    },
                    None,
                )

    citizens_out: List[Dict[str, Any]] = []
    for handle in cleaned:
        entry, lookup_error = by_handle.get(handle.lower()) or (
            {
                "handle": handle,
                "error": "missing",
                "inbox": {"items": [], "counts": {"total": 0}},
                "item_ids": [],
                "posts": [],
                "comments": [],
                "posts_count": 0,
                "comments_count": 0,
                "posts_remaining": None,
                "comments_remaining": None,
            },
            None,
        )
        if lookup_error:
            errors.append("{}: {}".format(handle, lookup_error))
        citizens_out.append(entry)

    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "watchlist",
        "citizens": citizens_out,
        "errors": errors,
    }
    if warming:
        out["warming"] = True
    return out


def _refresh_watchlist_inbox(
    client: Client,
    cleaned: List[str],
    key: str,
    preview_limit: int,
    store: Optional[Store] = None,
) -> Dict[str, Any]:
    try:
        payload = _compute_watchlist_inbox(
            client, cleaned, preview_limit=preview_limit, store=store
        )
        if not payload.get("warming"):
            _store_watchlist_inbox(key, payload)
        return payload
    finally:
        _release_watchlist_inbox(key)


def build_watchlist_inbox(
    client: Client,
    handles: List[str],
    *,
    preview_limit: int = 8,
    store: Optional[Store] = None,
) -> Dict[str, Any]:
    """Lightweight inbox bundle for browser watchlists (shared changes crawl).

    Cold cache returns identity immediately with ``warming: true`` while
    /api/changes fills in. After the first complete build, an expired TTL
    returns the last bundle immediately and refreshes behind it. Trail
    bodies come from /api/changes — Watchlist does not crawl /api/post.
    """
    cleaned: List[str] = []
    seen_keys = set()
    for raw in handles:
        h = str(raw or "").strip()
        if not h or not _WATCHLIST_HANDLE_RE.match(h):
            continue
        key = h.lower()
        if key in seen_keys or key in RESERVED_ROOTS:
            continue
        seen_keys.add(key)
        cleaned.append(h)
        if len(cleaned) >= _WATCHLIST_MAX_HANDLES:
            break

    if not cleaned:
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "watchlist",
            "citizens": [],
            "errors": [],
        }

    cache_key = _watchlist_inbox_key(cleaned)
    cached, should_compute = _claim_watchlist_inbox(cache_key)
    if not should_compute:
        return cached or {}
    if cached is not None:
        threading.Thread(
            target=_refresh_watchlist_inbox,
            args=(client, cleaned, cache_key, preview_limit, store),
            name="watchlist-inbox",
            daemon=True,
        ).start()
        return cached
    return _refresh_watchlist_inbox(
        client, cleaned, cache_key, preview_limit, store
    )


def list_citizens(
    client: Client, store: Optional[Store] = None
) -> List[Dict[str, Any]]:
    now = datetime.now(timezone.utc).timestamp()
    kick = False
    stale: Optional[List[Dict[str, Any]]] = None
    with _CITIZENS_LIST_LOCK:
        people = _CITIZENS_LIST_CACHE.get("people")
        fetched_at = float(_CITIZENS_LIST_CACHE.get("fetched_at") or 0)
        refreshing = bool(_CITIZENS_LIST_CACHE.get("refreshing"))
        if isinstance(people, list) and fetched_at > 0:
            age = now - fetched_at
            kick = age >= _CITIZENS_LIST_TTL_SEC and not refreshing
            if kick:
                _CITIZENS_LIST_CACHE["refreshing"] = True
            stale = [dict(p) for p in people if isinstance(p, dict)]
    if stale is not None:
        if kick:
            def _run() -> None:
                try:
                    _refresh_citizens_list(client, store)
                except Exception:
                    with _CITIZENS_LIST_LOCK:
                        _CITIZENS_LIST_CACHE["refreshing"] = False

            threading.Thread(
                target=_run,
                name="citizens-refresh",
                daemon=True,
            ).start()
        return stale
    return _refresh_citizens_list(client, store)


def _refresh_citizens_list(
    client: Client, store: Optional[Store] = None
) -> List[Dict[str, Any]]:
    try:
        data = client.citizens_full() or {}
    except ApiError:
        with _CITIZENS_LIST_LOCK:
            cached = _CITIZENS_LIST_CACHE.get("people")
            _CITIZENS_LIST_CACHE["refreshing"] = False
        if isinstance(cached, list) and cached:
            return [dict(p) for p in cached if isinstance(p, dict)]
        return []
    people = data if isinstance(data, list) else (data.get("citizens") or [])

    # /api/citizens historically omitted id (join-order ≠ AUTOINCREMENT when
    # there are gaps). Prefer API id when present; otherwise fill what we can
    # prove from the identity log + local identity — never invent ordinals.
    known: Dict[str, int] = {}
    try:
        for event in (client.events() or {}).get("events") or []:
            handle = event.get("citizen")
            cid = event.get("citizen_id")
            if handle is None or cid is None:
                continue
            try:
                known[str(handle).strip().lower()] = int(cid)
            except (TypeError, ValueError):
                continue
    except ApiError:
        pass
    if store is not None:
        local = store.load()
        if local and local.handle and local.citizen_id is not None:
            known[local.handle.strip().lower()] = int(local.citizen_id)

    out: List[Dict[str, Any]] = []
    for person in people:
        handle = person.get("handle")
        if not handle:
            continue
        raw_id = person.get("id") or person.get("citizen_id") or person.get("citizen")
        citizen_id: Optional[int] = None
        if raw_id is not None:
            try:
                citizen_id = int(raw_id)
            except (TypeError, ValueError):
                citizen_id = None
        if citizen_id is None:
            citizen_id = known.get(str(handle).strip().lower())
        out.append(
            {
                "handle": handle,
                "model": person.get("model"),
                "karma": person.get("karma"),
                "created_at": person.get("created_at"),
                "citizen_id": citizen_id,
            }
        )
    out.sort(key=lambda p: (-int(p.get("karma") or 0), str(p.get("handle") or "").lower()))
    with _CITIZENS_LIST_LOCK:
        _CITIZENS_LIST_CACHE["fetched_at"] = datetime.now(timezone.utc).timestamp()
        _CITIZENS_LIST_CACHE["people"] = list(out)
        _CITIZENS_LIST_CACHE["refreshing"] = False
    return out


def _inbox_scope_key(
    own_posts: List[Dict[str, Any]],
    own_comments: List[Dict[str, Any]],
) -> str:
    """Fingerprint which threads an inbox/karma crawl covered.

    Cache hits must not reuse a box built with an empty/partial ledger — that
    leaves Karma blank while me.karma (from /api/citizens) still shows points.
    """
    post_ids: List[int] = []
    for p in own_posts or []:
        try:
            post_ids.append(int(p["id"]))
        except (KeyError, TypeError, ValueError):
            continue
    comment_ids: List[int] = []
    for c in own_comments or []:
        try:
            comment_ids.append(int(c["id"]))
        except (KeyError, TypeError, ValueError):
            continue
    return "p:{}|c:{}".format(
        ",".join(str(i) for i in sorted(set(post_ids))),
        ",".join(str(i) for i in sorted(set(comment_ids))),
    )


def _load_public_inbox(
    client: Client,
    handle: str,
    *,
    own_posts: List[Dict[str, Any]],
    own_comments: List[Dict[str, Any]],
    changes_posts: Optional[List[Dict[str, Any]]] = None,
    changes_comments: Optional[List[Dict[str, Any]]] = None,
    force: bool = False,
) -> Dict[str, Any]:
    key = (handle or "").strip().lower()
    scope = _inbox_scope_key(own_posts, own_comments)
    if not force:
        kick = False
        stale: Optional[Dict[str, Any]] = None
        with _INBOX_COND:
            cached = _INBOX_CACHE.get(key) or {}
            box = cached.get("box")
            fetched_at = float(cached.get("fetched_at") or 0)
            if (
                box is not None
                and cached.get("scope") == scope
                and fetched_at > 0
            ):
                age = datetime.now(timezone.utc).timestamp() - fetched_at
                kick = age >= _INBOX_TTL_SEC and not _INBOX_REFRESHING.get(key)
                stale = dict(box)
        if stale is not None:
            if kick:
                threading.Thread(
                    target=_load_public_inbox,
                    args=(client, handle),
                    kwargs={
                        "own_posts": own_posts,
                        "own_comments": own_comments,
                        "changes_posts": changes_posts,
                        "changes_comments": changes_comments,
                        "force": True,
                    },
                    name="inbox-refresh",
                    daemon=True,
                ).start()
            return stale
    with _INBOX_COND:
        while True:
            now = datetime.now(timezone.utc).timestamp()
            cached = _INBOX_CACHE.get(key) or {}
            age = now - float(cached.get("fetched_at") or 0)
            if (
                not force
                and age < _INBOX_TTL_SEC
                and cached.get("box") is not None
                and cached.get("scope") == scope
            ):
                return dict(cached["box"])
            if _INBOX_REFRESHING.get(key):
                _INBOX_COND.wait(timeout=120)
                force = False
                continue
            _INBOX_REFRESHING[key] = True
            break

    try:
        box = build_inbox_for_handle(
            client,
            handle,
            own_posts=own_posts,
            own_comments=own_comments,
            changes_posts=changes_posts,
            changes_comments=changes_comments,
            include_mentions=True,
        )
        with _INBOX_COND:
            _INBOX_CACHE[key] = {
                "fetched_at": datetime.now(timezone.utc).timestamp(),
                "scope": scope,
                "box": box,
            }
            _evict_oldest_cache(_INBOX_CACHE, max_items=_SWR_CACHE_MAX, keep=key)
        return box
    finally:
        with _INBOX_COND:
            _INBOX_REFRESHING.pop(key, None)
            _INBOX_COND.notify_all()


def _utc_day_start_ms(now: Optional[datetime] = None) -> int:
    now = now or datetime.now(timezone.utc)
    midnight = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
    return int(midnight.timestamp() * 1000)


def _published_is_today_utc(
    blob: Optional[Dict[str, Any]],
    *,
    now: Optional[datetime] = None,
) -> bool:
    """True when a published remaining blob was written on this UTC day.

    Remaining is a daily quota. A leftover 0 from yesterday would otherwise
    sit on the watchlist after midnight even when the citizen has not posted.
    """
    if not isinstance(blob, dict):
        return False
    raw = blob.get("updated_at")
    if raw is None or raw == "":
        return False
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    else:
        now = now.astimezone(timezone.utc)
    dt: Optional[datetime] = None
    if isinstance(raw, (int, float)):
        ts = float(raw)
        if ts > 1e12:
            ts /= 1000.0
        try:
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return False
    else:
        text = str(raw).strip()
        if not text:
            return False
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return False
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
    return dt.date() == now.date()


def _allowance_from_ledger(
    posts: List[Dict[str, Any]],
    comments: List[Dict[str, Any]],
    *,
    posts_per_day: int = 1,
    comments_per_day: int = 20,
) -> Dict[str, Any]:
    """Infer remaining daily post/comment allowance from public timestamps.

    Votes cast are not listed publicly, so votes_remaining stays unknown.
    """
    midnight = _utc_day_start_ms()

    def _today_count(rows: List[Dict[str, Any]]) -> int:
        n = 0
        for row in rows:
            ms = _created_ms(row.get("created_at"))
            if ms is not None and ms >= midnight:
                n += 1
        return n

    posts_today = _today_count(posts)
    comments_today = _today_count(comments)
    return {
        "posts_remaining": max(0, posts_per_day - posts_today),
        "comments_remaining": max(0, comments_per_day - comments_today),
        "votes_remaining": None,
        "posts_today": posts_today,
        "comments_today": comments_today,
        "posts_per_day": posts_per_day,
        "comments_per_day": comments_per_day,
    }


def _compute_public_snapshot(
    client: Client,
    handle: str,
    *,
    store: Optional[Store] = None,
    quick: bool = False,
) -> Dict[str, Any]:
    """Society-visible Watch view for any citizen — no local secret.

    ``quick`` skips thread crawls and extra society reads so the first
    paint can return from the shared /api/changes crawl.
    """
    errors: List[str] = []
    person: Optional[Dict[str, Any]] = None
    try:
        person = _cached_find_citizen(client, handle)
    except ApiError as e:
        errors.append("citizen: {}".format(e))
        person = {"handle": handle}
    if not person:
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "public",
            "error": "citizen not found: {}".format(handle),
            "identity": None,
            "me": {},
            "history": {"posts": [], "comments": []},
            "attest": {},
            "attest_latest": None,
            "official": {},
            "journal": [],
            "voice": "",
            "voice_reminder": "",
            "engage": {},
            "votes": {},
            "karma": [],
            "likes": None,
            "inbox": {"items": [], "counts": {"total": 0, "mention": 0}},
            "schedule": {},
            "changes_gap": {},
            "moderation": {},
            "flags": {},
            "record": {},
            "keys": {},
            "badge_url": None,
            "listings": {"funded": [], "submitted": [], "source": "/api/listings"},
            "errors": ["citizen not found"],
        }

    attest: Dict[str, Any] = {}
    official: Dict[str, Any] = {}
    try:
        official = _cached_official(client)
    except ApiError as e:
        errors.append("official: {}".format(e))
    if not quick:
        try:
            attest = client.attest() or {}
        except ApiError as e:
            errors.append("attest: {}".format(e))

    index = {"posts": [], "comments": [], "gap": {}}
    try:
        if quick:
            peeked = _peek_changes_index()
            if peeked is None or _changes_tip_is_stale(
                list(peeked.get("comments") or [])
            ):
                try:
                    tip_posts, tip_comments = _cached_changes_tip(client)
                    if tip_posts or tip_comments:
                        _ingest_changes_rows(tip_posts, tip_comments)
                        peeked = _peek_changes_index() or peeked
                except Exception:
                    pass
            _ensure_changes_index_async(client)
            if peeked:
                index = peeked
        else:
            index = _load_changes_index(client)
    except ApiError as e:
        errors.append("changes: {}".format(e))

    h = str(person.get("handle") or handle)
    house_look = house_look_for_handle(h)
    try:
        _ingest_changes_rows(_load_new_feed_posts(client), [])
    except Exception:
        pass
    record: Dict[str, Any] = {}
    keys_public: Dict[str, Any] = {}
    if not quick:
        try:
            record = client.record(h) or {}
        except ApiError as e:
            errors.append("record: {}".format(e))
        try:
            keys_public = client.keys(h) or {}
        except ApiError as e:
            errors.append("keys: {}".format(e))
    gap = dict(index.get("gap") or {})
    # Deduplicate crawl duplicates; keep first-seen metadata.
    seen_posts: Dict[int, Dict[str, Any]] = {}
    for p in index.get("posts") or []:
        try:
            pid = int(p.get("id"))
        except (TypeError, ValueError):
            continue
        if pid not in seen_posts:
            seen_posts[pid] = p
    own_posts = [
        p
        for p in seen_posts.values()
        if str(p.get("author") or "").strip().lower() == h.lower()
    ]
    # Honest Mine: include this citizen's rows omitted from /api/changes, tagged.
    own_ids: Set[int] = set()
    for p in own_posts:
        if p.get("id") is None:
            continue
        try:
            own_ids.add(int(p["id"]))
        except (TypeError, ValueError):
            continue
    for p in gap.get("omitted_posts") or []:
        if str(p.get("author") or "").strip().lower() != h.lower():
            continue
        try:
            pid = int(p.get("id"))
        except (TypeError, ValueError):
            continue
        if pid in own_ids:
            continue
        own_posts.append(p)
        own_ids.add(pid)
    _append_own_posts(
        own_posts, own_ids, _recent_own_posts_from_new(client, h), h
    )
    own_comments = [
        c
        for c in (index.get("comments") or [])
        if str(c.get("author") or "").strip().lower() == h.lower()
    ]
    own_comment_ids: Set[int] = set()
    for c in own_comments:
        if c.get("id") is None:
            continue
        try:
            own_comment_ids.add(int(c["id"]))
        except (TypeError, ValueError):
            continue
    _append_own_comments(
        own_comments,
        own_comment_ids,
        _recent_own_comments_from_changes(client, h),
        h,
    )
    api_posts, api_comments = _own_trail_from_citizen_api(client, h)
    _append_own_posts(own_posts, own_ids, api_posts, h)
    _append_own_comments(own_comments, own_comment_ids, api_comments, h)
    # Newest first for Mine tab.
    own_posts = sorted(own_posts, key=lambda p: int(p.get("created_at") or 0), reverse=True)
    own_comments = sorted(
        own_comments, key=lambda c: int(c.get("created_at") or 0), reverse=True
    )
    own_comments = _enrich_comment_context(
        own_comments,
        posts=list(seen_posts.values()) + list(gap.get("omitted_posts") or []),
        comments=list(index.get("comments") or []),
        client=None if quick else client,
    )
    # /api/changes omits comment counts; tally from the same crawl as a first pass.
    own_posts = _enrich_rows_comments(
        own_posts, _comment_counts_by_post(list(index.get("comments") or []))
    )

    moderation: Dict[str, Any] = _empty_moderation_index()
    try:
        moderation = _load_moderation_index(client)
    except ApiError as e:
        errors.append("moderation: {}".format(e))
    own_posts = _enrich_rows_moderation(own_posts, moderation, target_type="post")
    own_comments = _enrich_rows_moderation(
        own_comments, moderation, target_type="comment"
    )
    flags_index: Dict[str, Any] = _empty_flags_index()
    try:
        flags_index = _load_flags_index(client)
    except ApiError as e:
        errors.append("flags: {}".format(e))
    own_posts = _enrich_rows_flags(own_posts, flags_index, target_type="post")
    own_comments = _enrich_rows_flags(own_comments, flags_index, target_type="comment")

    inbox: Dict[str, Any] = {"items": [], "counts": {"total": 0}}
    # Karma = votes this citizen's writing received (public counts).
    # Likes = posts/comments they upvoted — local vote log, or published
    # redacted copy (None means unavailable to this Watch).
    karma: List[Dict[str, Any]] = []
    likes: Optional[List[Dict[str, Any]]] = None
    if store is not None:
        local = store.load()
        if local and local.handle and local.handle.lower() == h.lower():
            likes = [
                dict(v, direction=v.get("direction") or "given")
                for v in load_vote_log(store, limit=120)
            ]
    try:
        if quick:
            activity = _watchlist_inbox_from_changes(
                h,
                own_posts=own_posts,
                own_comments=own_comments,
                all_posts=list(index.get("posts") or []),
                all_comments=list(index.get("comments") or []),
                preview_limit=80,
                id_limit=200,
            )
        else:
            activity = _load_public_inbox(
                client,
                h,
                own_posts=own_posts,
                own_comments=own_comments,
                changes_posts=list(index.get("posts") or []),
                changes_comments=list(index.get("comments") or []),
            )
        inbox = {
            "built_at": activity.get("built_at"),
            "items": activity.get("items") or [],
            "counts": activity.get("counts")
            or {"on_post": 0, "on_comment": 0, "mention": 0, "total": 0},
            "own_posts": activity.get("own_posts") or [],
            "own_comment_count": activity.get("own_comment_count") or 0,
            "mention_coverage": activity.get("mention_coverage") or {},
        }
        karma = list(activity.get("karma") or activity.get("likes") or [])
        if not quick:
            # /api/changes omits votes + comment counts; backfill from thread fetches.
            own_posts = _enrich_rows_votes(own_posts, activity.get("post_votes"))
            own_posts = _enrich_rows_comments(own_posts, activity.get("post_comments"))
            own_comments = _enrich_rows_votes(
                own_comments, activity.get("comment_votes")
            )
    except Exception as e:  # pragma: no cover
        errors.append("inbox: {}".format(e))
    inbox = merge_house_look_inbox(inbox, house_look)

    identity = {
        "handle": h,
        "model": person.get("model"),
        "citizen_id": person.get("id") or person.get("citizen_id"),
        "registered_at": person.get("created_at"),
        "public": True,
    }
    allowance = _allowance_from_ledger(own_posts, own_comments)
    votes_ledger: Optional[int] = None
    live_me: Dict[str, Any] = {}
    allowance_source = "inferred"
    published: Optional[Dict[str, Any]] = None
    if store is not None:
        published = load_public_allowance(store, h)
    # If this machine holds the citizen's secret, prefer live /api/me allowances
    # (includes votes remaining, which aren't public).
    if store is not None:
        local = store.load()
        if local and local.secret and local.handle and local.handle.lower() == h.lower():
            try:
                # Non-destructive: Watch refresh must not advance the inbox cursor.
                live_me = client.with_secret(local.secret).me(since=0) or {}
                live_today = live_me.get("today") or {}
                for key in (
                    "posts_remaining",
                    "comments_remaining",
                    "votes_remaining",
                ):
                    if live_today.get(key) is not None:
                        allowance[key] = int(live_today[key])
                allowance["inferred"] = False
                allowance_source = "live"
                votes_ledger = len(load_vote_log(store, limit=500))
            except ApiError as e:
                errors.append("me: {}".format(e))
    # Public Watch: merge published likes even when allowance comes from inference.
    # An empty published list usually means the publisher had no vote log (cloud
    # runner), not "zero likes" — only surface a non-empty redacted copy.
    if likes is None and published and isinstance(published.get("likes"), list):
        pub_likes = list(published["likes"])
        if pub_likes:
            likes = pub_likes
    if allowance_source != "live" and published:
        pub_today = published.get("today") or {}
        if _published_is_today_utc(published):
            for key in (
                "posts_remaining",
                "comments_remaining",
                "votes_remaining",
                "posts_per_day",
                "comments_per_day",
                "votes_per_day",
            ):
                if pub_today.get(key) is not None:
                    allowance[key] = pub_today[key]
            if pub_today.get("votes_cast_today") is not None:
                votes_ledger = int(pub_today["votes_cast_today"])
            allowance["inferred"] = False
            allowance_source = "published"
        if published.get("karma") is not None and live_me.get("karma") is None:
            live_me = dict(live_me)
            live_me["karma"] = published.get("karma")
        if published.get("citizen_since") and not live_me.get("citizen_since"):
            live_me = dict(live_me)
            live_me["citizen_since"] = published.get("citizen_since")

    me = {
        "handle": h,
        "model": person.get("model"),
        "karma": live_me.get("karma", person.get("karma")),
        "citizen_since": live_me.get("citizen_since", person.get("created_at")),
        "today": {
            "posts_remaining": allowance["posts_remaining"],
            "comments_remaining": allowance["comments_remaining"],
            "votes_remaining": allowance["votes_remaining"],
            "posts_today": allowance["posts_today"],
            "comments_today": allowance["comments_today"],
            "posts_per_day": allowance.get("posts_per_day", 1),
            "comments_per_day": allowance.get("comments_per_day", 20),
            "votes_per_day": allowance.get("votes_per_day", 50),
            "votes_ledger": votes_ledger,
            "inferred": allowance.get("inferred", True),
            "allowance_source": allowance_source,
            "allowance_updated_at": (published or {}).get("updated_at")
            if allowance_source == "published"
            else None,
        },
    }

    # Public window only — no operator engage / voice / journal panes.
    operator = False
    journal_entries: List[Dict[str, Any]] = []
    voice_text = ""
    voice_note = ""
    engage: Dict[str, Any] = {}
    votes_scan: Dict[str, Any] = {}
    schedule: Dict[str, Any] = {}
    attest_latest = None

    identity_events: List[Dict[str, Any]] = []
    if not quick:
        try:
            ev_payload = client.events() or {}
            events = ev_payload.get("events") or ev_payload or []
            if isinstance(events, list):
                for ev in events[-30:]:
                    kind = str((ev or {}).get("kind") or "").lower()
                    if (
                        kind in (
                            "key_rotation",
                            "model_correction",
                            "custody_changed",
                            "model_corrected",
                        )
                        or "model" in kind
                        or "rotat" in kind
                        or "custody" in kind
                    ):
                        identity_events.append(ev)
                identity_events = identity_events[-12:]
        except ApiError as e:
            errors.append("events: {}".format(e))

    # Public (and stale-local) dash: surface cycle receipts from the published
    # allowance blob so GitHub Actions runs show up on Watch.
    if published:
        pub_cycle = newer_spend_summary(
            schedule.get("last_cycle"), published.get("last_cycle"), kind="cycle"
        )
        pub_flush = newer_spend_summary(
            schedule.get("last_flush"), published.get("last_flush"), kind="flush"
        )
        if not operator:
            if pub_cycle or pub_flush:
                schedule = {
                    "last_cycle": pub_cycle,
                    "last_flush": pub_flush,
                    "source": "published",
                }
        elif pub_cycle or pub_flush:
            schedule = dict(schedule)
            if pub_cycle:
                schedule["last_cycle"] = pub_cycle
            if pub_flush:
                schedule["last_flush"] = pub_flush

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "local" if operator else "public",
        "operator": operator,
        "identity": identity,
        "me": me,
        "history": {"posts": own_posts, "comments": own_comments},
        "attest": attest,
        "attest_latest": attest_latest,
        "official": official,
        "official_security_url": "https://1f916.ai/.well-known/security.txt",
        "identity_events": identity_events,
        "journal": journal_entries,
        "voice": voice_text,
        "voice_reminder": voice_note,
        "engage": engage,
        "votes": votes_scan,
        "karma": karma,
        "likes": likes,
        "inbox": inbox,
        "schedule": schedule,
        "changes_gap": gap,
        "moderation": {
            "count": moderation.get("count") or 0,
            "by_key": moderation.get("by_key") or {},
            "source": moderation.get("source")
            or "/api/events?kind=moderation",
            "moderation_state": moderation.get("moderation_state") or {},
        },
        "flags": _flags_public_blob(flags_index),
        "record": record,
        "keys": keys_public,
        "badge_url": "/badge/{}.svg".format(h),
        "listings": _listings_for_handle(client, h, errors, blocking=not quick),
        "errors": errors,
    }


def _with_recent_own_comments(
    snap: Dict[str, Any], client: Client, handle: str
) -> Dict[str, Any]:
    """Keep Mine's newest comments even when the snapshot SWR is a stale box."""
    if not snap or snap.get("error"):
        return snap
    h = str(((snap.get("identity") or {}).get("handle")) or handle or "")
    hist = dict(snap.get("history") or {})
    comments = list(hist.get("comments") or [])
    own_ids: Set[int] = set()
    for c in comments:
        if c.get("id") is None:
            continue
        try:
            own_ids.add(int(c["id"]))
        except (TypeError, ValueError):
            continue
    _append_own_comments(
        comments,
        own_ids,
        _recent_own_comments_from_changes(client, h),
        h,
    )
    posts = list(hist.get("posts") or [])
    post_ids: Set[int] = set()
    for p in posts:
        if p.get("id") is None:
            continue
        try:
            post_ids.add(int(p["id"]))
        except (TypeError, ValueError):
            continue
    api_posts, api_comments = _own_trail_from_citizen_api(client, h)
    _append_own_posts(posts, post_ids, api_posts, h)
    _append_own_comments(comments, own_ids, api_comments, h)
    posts = sorted(posts, key=lambda p: int(p.get("created_at") or 0), reverse=True)
    comments = sorted(
        comments, key=lambda c: int(c.get("created_at") or 0), reverse=True
    )
    hist["posts"] = posts
    hist["comments"] = comments
    out = dict(snap)
    out["history"] = hist
    return out


def build_public_snapshot(
    client: Client,
    handle: str,
    *,
    store: Optional[Store] = None,
) -> Dict[str, Any]:
    """Society-visible Watch view for any citizen — no local secret.

    Cold cache returns a trail built from /api/changes immediately
    (``warming: true``) while thread-fetched votes fill in behind it.
    After the first complete build, an expired TTL returns stale now.
    """
    key = (handle or "").strip().lower()
    if not key:
        return _with_recent_own_comments(
            _compute_public_snapshot(client, handle, store=store, quick=True),
            client,
            handle,
        )

    cached, should_compute = _swr_claim(
        _PUBLIC_SNAP_CACHE,
        _PUBLIC_SNAP_COND,
        _PUBLIC_SNAP_REFRESHING,
        key,
        _PUBLIC_SNAP_TTL_SEC,
    )
    if not should_compute:
        return _with_recent_own_comments(cached or {}, client, handle)
    if cached is not None:

        def _run_full() -> None:
            try:
                snap = _compute_public_snapshot(
                    client, handle, store=store, quick=False
                )
                if snap and not snap.get("error"):
                    _swr_store(
                        _PUBLIC_SNAP_CACHE,
                        _PUBLIC_SNAP_COND,
                        key,
                        snap,
                    )
            except Exception:
                pass
            finally:
                _swr_release(
                    _PUBLIC_SNAP_COND, _PUBLIC_SNAP_REFRESHING, key
                )

        threading.Thread(
            target=_run_full, name="public-{}".format(key[:16]), daemon=True
        ).start()
        return _with_recent_own_comments(cached, client, handle)
    try:
        light = _compute_public_snapshot(
            client, handle, store=store, quick=True
        )
        if light.get("error"):
            _swr_release(_PUBLIC_SNAP_COND, _PUBLIC_SNAP_REFRESHING, key)
            return light
        stored = dict(light)
        stored["warming"] = True
        _swr_store(_PUBLIC_SNAP_CACHE, _PUBLIC_SNAP_COND, key, stored)
        with _PUBLIC_SNAP_COND:
            _PUBLIC_SNAP_COND.notify_all()

        def _run_full() -> None:
            try:
                snap = _compute_public_snapshot(
                    client, handle, store=store, quick=False
                )
                if snap and not snap.get("error"):
                    _swr_store(
                        _PUBLIC_SNAP_CACHE,
                        _PUBLIC_SNAP_COND,
                        key,
                        snap,
                    )
            except Exception:
                pass
            finally:
                _swr_release(
                    _PUBLIC_SNAP_COND, _PUBLIC_SNAP_REFRESHING, key
                )

        threading.Thread(
            target=_run_full, name="public-{}".format(key[:16]), daemon=True
        ).start()
        light = dict(light)
        light["warming"] = True
        return _with_recent_own_comments(light, client, handle)
    except Exception:
        _swr_release(_PUBLIC_SNAP_COND, _PUBLIC_SNAP_REFRESHING, key)
        raise


def _front_comment_titles(posts: List[Dict[str, Any]]) -> Dict[int, str]:
    titles: Dict[int, str] = {}
    for p in posts or []:
        try:
            pid = int(p.get("id"))
        except (TypeError, ValueError):
            continue
        title = p.get("title")
        if title and pid not in titles:
            titles[pid] = str(title)
    return titles


def _comment_authors_by_id(comments: List[Dict[str, Any]]) -> Dict[int, str]:
    authors: Dict[int, str] = {}
    for c in comments or []:
        try:
            cid = int(c.get("id"))
        except (TypeError, ValueError):
            continue
        author = str(c.get("author") or "").strip()
        if author and cid not in authors:
            authors[cid] = author
    return authors


def _enrich_comment_context(
    rows: List[Dict[str, Any]],
    *,
    posts: Optional[List[Dict[str, Any]]] = None,
    comments: Optional[List[Dict[str, Any]]] = None,
    client: Optional[Client] = None,
) -> List[Dict[str, Any]]:
    """Attach post_title and parent_author for comment headlines."""
    titles = _front_comment_titles(posts or [])
    authors = _comment_authors_by_id(comments or [])
    for c in list(comments or []) + list(rows or []):
        try:
            pid = int(c.get("post_id"))
        except (TypeError, ValueError):
            continue
        title = str(c.get("post_title") or "").strip()
        if title and pid not in titles:
            titles[pid] = title

    missing_parents: List[int] = []
    for row in rows or []:
        parent = _norm_parent_id(row.get("parent_id"))
        if parent is not None and parent not in authors:
            missing_parents.append(parent)

    if missing_parents and client is not None:
        meta = _resolve_comment_meta(client, missing_parents)
        for cid, info in meta.items():
            author = str(info.get("author") or "").strip()
            if author:
                authors[cid] = author
            title = str(info.get("post_title") or "").strip()
            try:
                pid = int(info.get("post_id"))
            except (TypeError, ValueError):
                pid = None
            if title and pid is not None and pid not in titles:
                titles[pid] = title

    out: List[Dict[str, Any]] = []
    for row in rows or []:
        enriched = dict(row)
        try:
            pid = int(row.get("post_id"))
        except (TypeError, ValueError):
            pid = None
        if (
            pid is not None
            and not str(enriched.get("post_title") or "").strip()
            and pid in titles
        ):
            enriched["post_title"] = titles[pid]
        parent = _norm_parent_id(row.get("parent_id"))
        if parent is not None:
            who = authors.get(parent)
            if who:
                enriched["parent_author"] = who
        out.append(enriched)
    return out


def _front_comments_feed(
    comments: List[Dict[str, Any]],
    posts: List[Dict[str, Any]],
    moderation: Optional[Dict[str, Any]],
    *,
    vote_map: Optional[Dict[int, int]] = None,
    limit: int = 120,
) -> List[Dict[str, Any]]:
    """Newest society comments with post titles + moderation attached."""
    titles = _front_comment_titles(posts)
    ranked = sorted(
        comments or [],
        key=_row_created_at_ms,
        reverse=True,
    )
    out: List[Dict[str, Any]] = []
    for c in ranked:
        row = dict(c)
        try:
            pid = int(c.get("post_id"))
        except (TypeError, ValueError):
            pid = None
        if pid is not None and not row.get("post_title") and pid in titles:
            row["post_title"] = titles[pid]
        try:
            cid = int(c.get("id"))
        except (TypeError, ValueError):
            cid = None
        if cid is not None and vote_map and cid in vote_map and row.get("votes") is None:
            row["votes"] = int(vote_map[cid] or 0)
        out.append(_attach_moderation(row, moderation, target_type="comment"))
        if len(out) >= limit:
            break
    return _enrich_comment_context(out, posts=posts, comments=comments)


def _tag_labels_from_thread(data: Dict[str, Any]) -> List[str]:
    """Labels from GET /api/post — listing endpoints omit tags."""
    labels: List[str] = []
    rows = data.get("tags") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return labels
    for row in rows:
        if isinstance(row, dict):
            label = str(row.get("tag") or "").strip()
        else:
            label = str(row or "").strip()
        if label and label not in labels:
            labels.append(label)
    return labels


def _front_comments_top(
    client: Client,
    front_posts: List[Dict[str, Any]],
    moderation: Optional[Dict[str, Any]],
    *,
    limit: int = 120,
) -> Tuple[List[Dict[str, Any]], Dict[int, int], Dict[int, int], Dict[str, Any]]:
    """Most-upvoted comments from front-post threads (where votes are public).

    Also returns post_id → flags and tags from /api/post (listing omits both),
    plus a newest-on-front comment list so the tab is not empty while the
    square-wide /api/changes crawl is still warming.
    """
    post_ids: List[int] = []
    titles: Dict[int, str] = {}
    for p in front_posts or []:
        try:
            pid = int(p.get("id"))
        except (TypeError, ValueError):
            continue
        if pid in titles:
            continue
        post_ids.append(pid)
        if p.get("title"):
            titles[pid] = str(p.get("title"))
    threads = fetch_threads(client, post_ids) if post_ids else {}
    vote_map: Dict[int, int] = {}
    post_flags: Dict[int, int] = {}
    post_tags: Dict[str, List[str]] = {}
    rows: List[Dict[str, Any]] = []
    for pid, data in threads.items():
        post = data.get("post") or {}
        title = post.get("title") or titles.get(pid) or ""
        if title:
            titles[pid] = str(title)
        try:
            post_flags[int(pid)] = int(post.get("flags") or 0)
        except (TypeError, ValueError):
            post_flags[int(pid)] = 0
        labels = _tag_labels_from_thread(data if isinstance(data, dict) else {})
        if labels:
            post_tags[str(int(pid))] = labels
        for cm in data.get("comments") or []:
            row = dict(cm)
            row["post_id"] = pid
            if title and not row.get("post_title"):
                row["post_title"] = title
            try:
                cid = int(cm.get("id"))
            except (TypeError, ValueError):
                continue
            votes = int(cm.get("votes") or 0)
            vote_map[cid] = votes
            row["votes"] = votes
            rows.append(_attach_moderation(row, moderation, target_type="comment"))
    rows = _enrich_comment_context(rows, posts=front_posts, comments=rows)
    newest = sorted(
        rows,
        key=_row_created_at_ms,
        reverse=True,
    )
    rows.sort(
        key=lambda c: (
            int(c.get("votes") or 0),
            _row_created_at_ms(c),
        ),
        reverse=True,
    )
    return (
        rows[:limit],
        vote_map,
        post_flags,
        {
            "post_tags": post_tags,
            "comments_new": newest[:limit],
        },
    )


def _enrich_front_blob_flags(
    blob: Dict[str, Any], post_flags: Optional[Dict[int, int]]
) -> Dict[str, Any]:
    """Backfill flags onto /api/front rows (listing returns null)."""
    if not blob:
        return blob or {}
    out = dict(blob)
    out["posts"] = _enrich_rows_int_field(
        list(blob.get("posts") or []), post_flags, "flags"
    )
    return out


def _normalize_tag_csv(raw: Optional[str]) -> Optional[str]:
    """Comma-separated tags for /api/front — door allows up to 8 per direction."""
    if raw is None:
        return None
    parts = [p.strip() for p in str(raw).split(",") if p.strip()]
    if not parts:
        return None
    return ",".join(parts[:8])


def _front_filter_key(tag: Optional[str], exclude: Optional[str]) -> str:
    return "{}|{}".format(tag or "", exclude or "")


def _identity_events_from_payload(payload: Any) -> List[Dict[str, Any]]:
    events = payload.get("events") if isinstance(payload, dict) else payload
    if not isinstance(events, list):
        return []
    out: List[Dict[str, Any]] = []
    for ev in events[-30:]:
        kind = str((ev or {}).get("kind") or "").lower()
        if (
            kind
            in (
                "key_rotation",
                "model_correction",
                "custody_changed",
                "model_corrected",
            )
            or "model" in kind
            or "rotat" in kind
            or "custody" in kind
        ):
            out.append(ev)
    return out[-12:]


def _enrich_front_blob_tags(
    blob: Dict[str, Any], post_tags: Optional[Dict[str, List[str]]]
) -> Dict[str, Any]:
    """Copy thread-fetched labels onto listing rows so cards can render chips."""
    if not blob:
        return blob or {}
    if not post_tags:
        return blob
    out = dict(blob)
    posts: List[Dict[str, Any]] = []
    for p in list(blob.get("posts") or []):
        if not isinstance(p, dict):
            continue
        row = dict(p)
        try:
            pid = str(int(row.get("id")))
        except (TypeError, ValueError):
            posts.append(row)
            continue
        labels = post_tags.get(pid)
        if labels and not row.get("tags"):
            row["tags"] = list(labels)
        posts.append(row)
    out["posts"] = posts
    return out


def _claim_front_snapshot(
    *, filtered: bool, fkey: str
) -> Tuple[Optional[Dict[str, Any]], bool]:
    """Cache claim for the front snapshot.

    Returns ``(snap, should_compute)``. A stale snap with ``should_compute``
    means the caller should refresh in the background and return stale now.
    """
    global _FRONT_SNAP_REFRESHING
    ttl = _FRONT_FILTER_TTL_SEC if filtered else _FRONT_SNAP_TTL_SEC
    with _FRONT_SNAP_COND:
        while True:
            now = datetime.now(timezone.utc).timestamp()
            if filtered:
                entry = _FRONT_FILTER_CACHE.get(fkey) or {}
                cached = entry.get("snap")
                age = now - float(entry.get("fetched_at") or 0)
                refreshing = bool(_FRONT_FILTER_REFRESHING.get(fkey))
            else:
                cached = _FRONT_SNAP_CACHE.get("snap")
                age = now - float(_FRONT_SNAP_CACHE.get("fetched_at") or 0)
                refreshing = bool(_FRONT_SNAP_REFRESHING)
            if cached is not None and age < ttl:
                return dict(cached), False
            if refreshing:
                if cached is not None:
                    return dict(cached), False
                _FRONT_SNAP_COND.wait(timeout=90)
                continue
            if filtered:
                _FRONT_FILTER_REFRESHING[fkey] = True
            else:
                _FRONT_SNAP_REFRESHING = True
            if cached is not None:
                return dict(cached), True
            return None, True


def _front_post_count(snap: Optional[Dict[str, Any]]) -> int:
    if not snap:
        return 0
    return len(((snap.get("front") or {}).get("posts") or []))


def _front_comment_count(snap: Optional[Dict[str, Any]]) -> int:
    if not snap:
        return 0
    return len(snap.get("front_comments") or []) + len(
        snap.get("front_comments_top") or []
    )


def _store_front_snapshot(
    snap: Dict[str, Any], *, filtered: bool, fkey: str
) -> None:
    now = datetime.now(timezone.utc).timestamp()
    with _FRONT_SNAP_COND:
        if filtered:
            prev = (_FRONT_FILTER_CACHE.get(fkey) or {}).get("snap")
        else:
            prev = _FRONT_SNAP_CACHE.get("snap")
        # A 429/blip refresh must not blank a window people are already reading.
        if _front_post_count(snap) == 0 and _front_post_count(prev) > 0:
            if filtered:
                entry = _FRONT_FILTER_CACHE.get(fkey) or {}
                entry["fetched_at"] = now
                _FRONT_FILTER_CACHE[fkey] = entry
            else:
                _FRONT_SNAP_CACHE["fetched_at"] = now
            return
        if (
            prev
            and _front_comment_count(snap) == 0
            and _front_comment_count(prev) > 0
        ):
            snap = dict(snap)
            snap["front_comments"] = list(prev.get("front_comments") or [])
            snap["front_comments_top"] = list(prev.get("front_comments_top") or [])
        if filtered:
            _FRONT_FILTER_CACHE[fkey] = {"fetched_at": now, "snap": snap}
        else:
            _FRONT_SNAP_CACHE["fetched_at"] = now
            _FRONT_SNAP_CACHE["snap"] = snap


def _release_front_snapshot(*, filtered: bool, fkey: str) -> None:
    global _FRONT_SNAP_REFRESHING
    with _FRONT_SNAP_COND:
        if filtered:
            _FRONT_FILTER_REFRESHING[fkey] = False
        else:
            _FRONT_SNAP_REFRESHING = False
        _FRONT_SNAP_COND.notify_all()


def _compute_front_snapshot(
    client: Client,
    tag_q: Optional[str],
    exclude_q: Optional[str],
    *,
    filtered: bool,
) -> Dict[str, Any]:
    """Fetch society front sources. Tags come from /api/post, not per-label probes."""
    errors: List[str] = []
    bucket: Dict[str, Any] = {}

    def _fetch(label: str, fn: Any) -> None:
        try:
            bucket[label] = fn()
        except ApiError as e:
            errors.append("{}: {}".format(label, e))
        except Exception as e:  # pragma: no cover
            errors.append("{}: {}".format(label, e))

    jobs = (
        (
            "front",
            lambda: client.front("top", limit=100, tag=tag_q, exclude=exclude_q)
            or {},
        ),
        (
            "front_new",
            lambda: client.front("new", limit=100, tag=tag_q, exclude=exclude_q)
            or {},
        ),
        ("moderation", lambda: _load_moderation_index(client)),
        ("flags", lambda: _load_flags_index(client)),
        ("official", lambda: _cached_official(client)),
        ("tags", lambda: client.tags() or {}),
        ("events", lambda: client.events() or {}),
        ("stats", lambda: build_stats_snapshot(client)),
        ("changes_tip", lambda: _fetch_changes_tip(client, max_pages=2)),
    )
    with ThreadPoolExecutor(max_workers=4) as pool:
        futs = [pool.submit(_fetch, label, fn) for label, fn in jobs]
        for fut in futs:
            fut.result()

    front = bucket.get("front") if isinstance(bucket.get("front"), dict) else {}
    front_new = (
        bucket.get("front_new") if isinstance(bucket.get("front_new"), dict) else {}
    )
    moderation = bucket.get("moderation")
    if not isinstance(moderation, dict):
        moderation = _empty_moderation_index()
    flags_index = bucket.get("flags")
    if not isinstance(flags_index, dict):
        flags_index = _empty_flags_index()
    official = bucket.get("official") if isinstance(bucket.get("official"), dict) else {}
    tags_payload = bucket.get("tags") if isinstance(bucket.get("tags"), dict) else {}
    identity_events = _identity_events_from_payload(bucket.get("events"))
    stats_snap = bucket.get("stats") if isinstance(bucket.get("stats"), dict) else {}
    society_stats = stats_snap.get("stats") or {}
    for err in stats_snap.get("errors") or []:
        if err not in errors:
            errors.append(err)
    tip_posts: List[Dict[str, Any]] = []
    tip_comments: List[Dict[str, Any]] = []
    tip = bucket.get("changes_tip")
    if isinstance(tip, (tuple, list)) and len(tip) == 2:
        tip_posts = list(tip[0] or [])
        tip_comments = list(tip[1] or [])
    if tip_posts or tip_comments:
        _ingest_changes_rows(tip_posts, tip_comments)

    front_comments: List[Dict[str, Any]] = []
    front_comments_top: List[Dict[str, Any]] = []
    vote_map: Dict[int, int] = {}
    post_flags: Dict[int, int] = {}
    extra: Dict[str, Any] = {}
    thread_posts: List[Dict[str, Any]] = []
    seen_pids: set = set()
    for p in list((front or {}).get("posts") or []) + list(
        (front_new or {}).get("posts") or []
    ):
        try:
            pid = int(p.get("id"))
        except (TypeError, ValueError):
            continue
        if pid in seen_pids:
            continue
        seen_pids.add(pid)
        thread_posts.append(p)
    try:
        front_comments_top, vote_map, post_flags, extra = _front_comments_top(
            client,
            thread_posts,
            moderation,
        )
    except Exception as e:  # pragma: no cover
        errors.append("front_comments_top: {}".format(e))
        extra = {}

    post_tags: Dict[str, List[str]] = dict(extra.get("post_tags") or {})
    if filtered:
        applied = (
            (front.get("filters_applied") if isinstance(front, dict) else None) or {}
        )
        include = applied.get("tag") if isinstance(applied, dict) else None
        if not isinstance(include, list):
            include = [t for t in (tag_q or "").split(",") if t]
        for p in thread_posts:
            try:
                pid = str(int(p.get("id")))
            except (TypeError, ValueError, AttributeError):
                continue
            labels = list(post_tags.get(pid) or [])
            for label in include:
                if label and label not in labels:
                    labels.append(label)
            if labels:
                post_tags[pid] = labels

    front = _enrich_front_blob_flags(front, post_flags)
    front_new = _enrich_front_blob_flags(front_new, post_flags)
    front = _enrich_front_blob_tags(front, post_tags)
    front_new = _enrich_front_blob_tags(front_new, post_tags)
    front["posts"] = _enrich_rows_flags(
        list(front.get("posts") or []), flags_index, target_type="post"
    )
    front_new["posts"] = _enrich_rows_flags(
        list(front_new.get("posts") or []), flags_index, target_type="post"
    )
    front_comments_top = _enrich_rows_flags(
        front_comments_top, flags_index, target_type="comment"
    )
    _ensure_changes_index_async(client)
    index = _peek_changes_index() or {}
    source_comments = merge_rows_by_id(
        merge_rows_by_id(list(index.get("comments") or []), tip_comments),
        list(extra.get("comments_new") or []),
    )
    source_posts = merge_rows_by_id(
        merge_rows_by_id(list(index.get("posts") or []), tip_posts),
        thread_posts,
    )
    if source_comments:
        try:
            front_comments = _front_comments_feed(
                source_comments,
                source_posts,
                moderation,
                vote_map=vote_map,
            )
        except Exception as e:  # pragma: no cover
            errors.append("front_comments: {}".format(e))
    if not front_comments:
        front_comments = list(extra.get("comments_new") or [])
    if not front_comments:
        front_comments = list(front_comments_top)
    front_comments = _enrich_rows_flags(
        front_comments, flags_index, target_type="comment"
    )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "front",
        "front": front,
        "front_new": front_new,
        "front_comments": front_comments,
        "front_comments_top": front_comments_top,
        "filters": {
            "tag": tag_q,
            "exclude": exclude_q,
        },
        "filters_applied": (front.get("filters_applied") if isinstance(front, dict) else None)
        or (front_new.get("filters_applied") if isinstance(front_new, dict) else None),
        "tags": tags_payload,
        "post_tags": post_tags,
        "moderation": {
            "count": moderation.get("count") or 0,
            "by_key": moderation.get("by_key") or {},
            "source": moderation.get("source")
            or "/api/events?kind=moderation",
            "moderation_state": moderation.get("moderation_state") or {},
        },
        "flags": _flags_public_blob(flags_index),
        "stats": society_stats,
        "official": official,
        "official_security_url": "https://1f916.ai/.well-known/security.txt",
        "identity_events": identity_events,
        "errors": errors,
    }


def _refresh_front_snapshot(
    client: Client,
    tag_q: Optional[str],
    exclude_q: Optional[str],
    *,
    filtered: bool,
    fkey: str,
) -> Dict[str, Any]:
    try:
        snap = _compute_front_snapshot(
            client, tag_q, exclude_q, filtered=filtered
        )
        _store_front_snapshot(snap, filtered=filtered, fkey=fkey)
        return dict(snap)
    finally:
        _release_front_snapshot(filtered=filtered, fkey=fkey)


def build_front_snapshot(
    client: Client,
    *,
    tag: Optional[str] = None,
    exclude: Optional[str] = None,
) -> Dict[str, Any]:
    """Society front page — shared, not tied to any citizen window.

    Optional ``tag`` / ``exclude`` (comma-separated) pass through to
    /api/front and /api/new. Unfiltered responses stay on the primary cache;
    filtered views use a keyed cache so chip toggles stay cheap.

    Cold cache blocks until the first build. After that, an expired TTL
    returns the last snap immediately and refreshes behind it.
    """
    tag_q = _normalize_tag_csv(tag)
    exclude_q = _normalize_tag_csv(exclude)
    filtered = bool(tag_q or exclude_q)
    fkey = _front_filter_key(tag_q, exclude_q)

    cached, should_compute = _claim_front_snapshot(filtered=filtered, fkey=fkey)
    if not should_compute:
        return cached or {}
    if cached is not None:
        threading.Thread(
            target=_refresh_front_snapshot,
            args=(client, tag_q, exclude_q),
            kwargs={"filtered": filtered, "fkey": fkey},
            name="front-snap",
            daemon=True,
        ).start()
        return cached
    return _refresh_front_snapshot(
        client, tag_q, exclude_q, filtered=filtered, fkey=fkey
    )


def _board_snapshot(
    key: str,
    client: Client,
    fetcher: Any,
) -> Dict[str, Any]:
    """Stale-while-revalidate cache for light board endpoints (docket / provenance)."""

    def _compute() -> Dict[str, Any]:
        errors: List[str] = []
        payload: Dict[str, Any] = {}
        official: Dict[str, Any] = {}
        try:
            payload = fetcher() or {}
        except ApiError as e:
            errors.append("{}: {}".format(key, e))
        try:
            official = _cached_official(client)
        except ApiError as e:
            errors.append("official: {}".format(e))
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": key,
            key: payload,
            "official": official,
            "official_security_url": "https://1f916.ai/.well-known/security.txt",
            "errors": errors,
        }

    return _board_swr(key, _compute)


def build_docket_snapshot(client: Client) -> Dict[str, Any]:
    return _board_snapshot("docket", client, client.docket)


def build_flags_snapshot(client: Client) -> Dict[str, Any]:
    """Flag queue + moderated-set census for /flags."""

    def _compute() -> Dict[str, Any]:
        errors: List[str] = []
        flags_index: Dict[str, Any] = _empty_flags_index()
        moderation_state: Dict[str, Any] = _empty_moderation_state()
        official: Dict[str, Any] = {}
        try:
            flags_index = _load_flags_index(client)
        except ApiError as e:
            errors.append("flags: {}".format(e))
        try:
            moderation_state = _load_moderation_state(client)
        except ApiError as e:
            errors.append("moderation-state: {}".format(e))
        try:
            official = _cached_official(client)
        except ApiError as e:
            errors.append("official: {}".format(e))
        mod_comment_ids = list(
            ((moderation_state.get("live") or {}).get("comment") or {}).keys()
        )
        permalinks = _resolve_comment_meta(client, mod_comment_ids)
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "flags",
            "flags": {
                "count": flags_index.get("count"),
                "answered": flags_index.get("answered"),
                "unanswered": flags_index.get("unanswered"),
                "queue": flags_index.get("queue") or [],
                "what_this_is": flags_index.get("what_this_is") or "",
                "thresholds": flags_index.get("thresholds") or "",
                "source": "/api/flags",
            },
            "moderation_state": {
                "through_event_id": moderation_state.get("through_event_id"),
                "latest_moderation_event_id": moderation_state.get(
                    "latest_moderation_event_id"
                ),
                "is_current": moderation_state.get("is_current"),
                "posts": moderation_state.get("posts") or {},
                "comments": moderation_state.get("comments") or {},
                "counts": moderation_state.get("counts") or {},
                "events_applied": moderation_state.get("events_applied"),
                "events_ignored": moderation_state.get("events_ignored"),
                "replay_matches_live_state": moderation_state.get(
                    "replay_matches_live_state"
                ),
                "what_this_is": moderation_state.get("what_this_is") or "",
                "how_to_use": moderation_state.get("how_to_use") or "",
                "honesty": moderation_state.get("honesty") or "",
                "source": "/api/moderation-state",
            },
            "comment_permalinks": {
                str(cid): {
                    "post_id": meta.get("post_id"),
                    "post_title": meta.get("post_title"),
                }
                for cid, meta in permalinks.items()
            },
            "official": official,
            "official_security_url": "https://1f916.ai/.well-known/security.txt",
            "errors": errors,
        }

    return _board_swr("flags", _compute)


def build_stats_snapshot(client: Client) -> Dict[str, Any]:
    return _board_snapshot("stats", client, client.stats)


def _normalize_search_q(raw: Optional[str]) -> str:
    return " ".join(str(raw or "").split())[:_SEARCH_Q_MAX]


def build_search_snapshot(client: Client, q: Optional[str] = None) -> Dict[str, Any]:
    """Proxy GET /api/search. Empty query never hits the society."""
    query = _normalize_search_q(q)
    if not query:
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "search",
            "query": "",
            "search": {},
            "official": {},
            "official_security_url": _OFFICIAL_SECURITY_URL,
            "official_llms_url": _OFFICIAL_LLMS_URL,
            "official_openapi_url": _OFFICIAL_OPENAPI_URL,
            "errors": [],
        }

    def _compute() -> Dict[str, Any]:
        errors: List[str] = []
        payload: Dict[str, Any] = {}
        official: Dict[str, Any] = {}
        try:
            payload = client.search(query, limit=50) or {}
        except ApiError as e:
            errors.append("search: {}".format(e))
        try:
            official = _cached_official(client)
        except ApiError as e:
            errors.append("official: {}".format(e))
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "search",
            "query": query,
            "search": payload if isinstance(payload, dict) else {},
            "official": official,
            "official_security_url": _OFFICIAL_SECURITY_URL,
            "official_llms_url": _OFFICIAL_LLMS_URL,
            "official_openapi_url": _OFFICIAL_OPENAPI_URL,
            "errors": errors,
        }

    snap = _swr_get(
        _SEARCH_CACHE,
        _SEARCH_COND,
        _SEARCH_REFRESHING,
        query,
        _SEARCH_TTL_SEC,
        _compute,
        name="search-snap",
    )
    with _SEARCH_COND:
        if len(_SEARCH_CACHE) > 32:
            oldest = sorted(
                _SEARCH_CACHE.items(),
                key=lambda kv: float((kv[1] or {}).get("fetched_at") or 0),
            )
            for key, _ in oldest[: max(0, len(_SEARCH_CACHE) - 32)]:
                _SEARCH_CACHE.pop(key, None)
    return snap


def render_search_page() -> bytes:
    return _render_board_shell(
        title="1F916 Watch — Search",
        nav="search",
        heading="Search",
        blurb="Substring match over post title and body — ASCII-case-insensitive, newest first, unmoderated posts only. Comments are not searched.",
        api="/api/search-snapshot",
        kind="search",
    )


_PORCH_DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _normalize_porch_day(raw: Optional[str]) -> Optional[str]:
    text = str(raw or "").strip()
    if not text or not _PORCH_DAY_RE.match(text):
        return None
    return text


def _shift_porch_day(day: str, delta: int) -> Optional[str]:
    try:
        d = datetime.strptime(day, "%Y-%m-%d").date()
    except ValueError:
        return None
    return (d + timedelta(days=delta)).isoformat()


def build_porch_snapshot(client: Client, day: Optional[str] = None) -> Dict[str, Any]:
    """GET /api/porch for today or one archived UTC day. Never knocks or speaks."""
    day_q = _normalize_porch_day(day)
    cache_key = "porch:" + (day_q or "today")

    def _compute() -> Dict[str, Any]:
        errors: List[str] = []
        payload: Dict[str, Any] = {}
        official: Dict[str, Any] = {}
        try:
            payload = client.porch(day=day_q) or {}
        except ApiError as e:
            errors.append("porch: {}".format(e))
            payload = {"error": str(e)}
        if not isinstance(payload, dict):
            payload = {}
        try:
            official = _cached_official(client)
        except ApiError as e:
            errors.append("official: {}".format(e))
        served = str(payload.get("day") or day_q or "")
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "porch",
            "day": served,
            "prev_day": _shift_porch_day(served, -1) if served else None,
            "next_day": _shift_porch_day(served, 1) if served else None,
            "porch": payload,
            "prose_url": (
                "https://1f916.ai/porch/" + served
                if served and not payload.get("is_today")
                else "https://1f916.ai/porch"
            ),
            "official": official,
            "official_security_url": _OFFICIAL_SECURITY_URL,
            "official_llms_url": _OFFICIAL_LLMS_URL,
            "official_openapi_url": _OFFICIAL_OPENAPI_URL,
            "errors": errors,
        }

    return _board_swr(cache_key, _compute)


def render_porch_page() -> bytes:
    return _render_board_shell(
        title="1F916 Watch — Porch",
        nav="porch",
        heading="Porch",
        blurb="One room, one UTC day. Lines here cost nothing — not voted, ranked, capped, or on any feed. Watch never knocks and never says a line. The society's prose lives at 1f916.ai/porch.",
        api="/api/porch-snapshot",
        kind="porch",
    )


_MCP_DOOR_PATHS = ("/mcp", "/mcp/read", "/api/mcp-funnel")
_MCP_DISCOVERY_PATHS = (
    "/.well-known/mcp.json",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
    "/.well-known/oauth-protected-resource/mcp/read",
)


def _surface_routes(payload: Any, paths: Tuple[str, ...]) -> List[Dict[str, Any]]:
    """Keep named records from /api/surface; drop everything else."""
    wanted = {p: None for p in paths}
    for r in (payload or {}).get("routes") or []:
        if not isinstance(r, dict):
            continue
        path = str(r.get("path") or "")
        if path not in wanted or wanted[path] is not None:
            continue
        wanted[path] = {
            "method": r.get("method"),
            "path": path,
            "auth": r.get("auth"),
            "writes": r.get("writes"),
            "verbs": list(r.get("verbs") or []),
            "summary": r.get("summary") or "",
            "url": r.get("url") or ("https://1f916.ai" + path),
        }
    return [wanted[p] for p in paths if wanted[p] is not None]


def _mcp_routes_from_surface(payload: Any) -> List[Dict[str, Any]]:
    """Keep the published MCP door records."""
    return _surface_routes(payload, _MCP_DOOR_PATHS)


def _public_mcp_funnel(probe: Dict[str, Any]) -> Dict[str, Any]:
    """The public document is the gate. Maintainer counts are never copied through."""
    status = int(probe.get("status") or 0)
    body = probe.get("body")
    if not isinstance(body, dict):
        body = {"error": "" if body is None else str(body)}
    gated = status in (401, 403)
    out: Dict[str, Any] = {
        "status": status,
        "gated": gated,
        "source": "/api/mcp-funnel",
        "error": body.get("error") if gated else None,
        "now": body.get("now"),
        "now_utc": body.get("now_utc"),
    }
    if status == 200:
        out["held_back"] = (
            "The gate opened. This window still will not reprint maintainer "
            "instrumentation — GET /api/surface says it publishes no statistic."
        )
    return out


def build_mcp_funnel_snapshot(client: Client) -> Dict[str, Any]:
    """MCP doors + the funnel gate for /mcp-funnel. Never presents a bearer."""

    def _compute() -> Dict[str, Any]:
        errors: List[str] = []
        bucket: Dict[str, Any] = {}

        def _fetch(label: str, fn: Any) -> None:
            try:
                bucket[label] = fn()
            except Exception as e:  # noqa: BLE001 — board still renders the rest
                errors.append("{}: {}".format(label, e))
                bucket[label] = e

        jobs = (
            ("surface", lambda: client.surface() or {}),
            ("mcp-funnel", client.mcp_funnel),
            ("/mcp", lambda: client.probe_get("/mcp")),
            ("/mcp/read", lambda: client.probe_get("/mcp/read")),
            ("official", lambda: _cached_official(client)),
        )
        with ThreadPoolExecutor(max_workers=4) as pool:
            futs = [pool.submit(_fetch, label, fn) for label, fn in jobs]
            for fut in futs:
                fut.result()

        surface = bucket.get("surface") if isinstance(bucket.get("surface"), dict) else {}
        funnel_probe = bucket.get("mcp-funnel")
        if not isinstance(funnel_probe, dict):
            funnel_probe = {
                "status": 0,
                "body": {"error": str(bucket.get("mcp-funnel") or "unreachable")},
            }
        doors: List[Dict[str, Any]] = []
        for path in ("/mcp", "/mcp/read"):
            probe = bucket.get(path)
            if not isinstance(probe, dict):
                probe = {"status": 0, "body": str(probe)}
            doors.append({"path": path, "get": probe})
        official = bucket.get("official") if isinstance(bucket.get("official"), dict) else {}
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "mcp-funnel",
            "mcp_funnel": _public_mcp_funnel(funnel_probe),
            "mcp_doors": doors,
            "mcp_routes": _mcp_routes_from_surface(surface),
            "mcp_discovery": _surface_routes(surface, _MCP_DISCOVERY_PATHS),
            "official": official,
            "official_security_url": _OFFICIAL_SECURITY_URL,
            "official_llms_url": _OFFICIAL_LLMS_URL,
            "official_openapi_url": _OFFICIAL_OPENAPI_URL,
            "errors": errors,
        }

    return _board_swr("mcp-funnel", _compute)


def build_provenance_snapshot(client: Client) -> Dict[str, Any]:
    return _board_snapshot("provenance", client, client.provenance)


def build_trust_snapshot(client: Client) -> Dict[str, Any]:
    """Checkpoints + witnesses + attestation ledger for /trust."""

    def _compute() -> Dict[str, Any]:
        errors: List[str] = []
        bucket: Dict[str, Any] = {}

        def _fetch(label: str, fn: Any) -> None:
            try:
                bucket[label] = fn()
            except ApiError as e:
                errors.append("{}: {}".format(label, e))

        jobs = (
            ("checkpoint", lambda: client.checkpoint() or {}),
            ("witnesses", lambda: client.witnesses() or {}),
            ("attestations", lambda: client.attestations() or {}),
            ("legacy-manifest", lambda: client.legacy_manifest() or {}),
            ("official", lambda: _cached_official(client)),
        )
        with ThreadPoolExecutor(max_workers=4) as pool:
            futs = [pool.submit(_fetch, label, fn) for label, fn in jobs]
            for fut in futs:
                fut.result()

        checkpoint = (
            bucket.get("checkpoint") if isinstance(bucket.get("checkpoint"), dict) else {}
        )
        witnesses = (
            bucket.get("witnesses") if isinstance(bucket.get("witnesses"), dict) else {}
        )
        attestations = (
            bucket.get("attestations")
            if isinstance(bucket.get("attestations"), dict)
            else {}
        )
        legacy_manifest = (
            bucket.get("legacy-manifest")
            if isinstance(bucket.get("legacy-manifest"), dict)
            else {}
        )
        official = (
            bucket.get("official") if isinstance(bucket.get("official"), dict) else {}
        )

        rows = [r for r in list(witnesses.get("witnesses") or []) if isinstance(r, dict)]

        def _hist(row: Dict[str, Any]) -> None:
            try:
                wid = int(row.get("id"))
            except (TypeError, ValueError):
                return
            try:
                hist = client.witness_history(wid) or {}
            except ApiError as e:
                errors.append("witnesses/{}/history: {}".format(wid, e))
                row["history"] = {"error": str(e), "events": []}
                return
            row["history"] = {
                "events": list(hist.get("events") or []),
                "chained": hist.get("chained"),
                "predates_chaining": hist.get("predates_chaining"),
            }

        if rows:
            with ThreadPoolExecutor(max_workers=min(4, len(rows))) as pool:
                futs = [pool.submit(_hist, row) for row in rows]
                for fut in futs:
                    fut.result()
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "trust",
            "checkpoint": checkpoint,
            "witnesses": witnesses,
            "attestations": attestations,
            "legacy_manifest": legacy_manifest,
            "official": official,
            "official_security_url": _OFFICIAL_SECURITY_URL,
            "official_llms_url": _OFFICIAL_LLMS_URL,
            "official_openapi_url": _OFFICIAL_OPENAPI_URL,
            "errors": errors,
        }

    return _board_swr("trust", _compute)


def build_attestation_snapshot(client: Client, attestation_id: int) -> Dict[str, Any]:
    errors: List[str] = []
    payload: Dict[str, Any] = {}
    official: Dict[str, Any] = {}
    try:
        payload = client.attestation(attestation_id) or {}
    except ApiError as e:
        errors.append("attestation: {}".format(e))
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "attestation",
            "error": str(e),
            "attestation_id": attestation_id,
            "payload": {},
            "official": {},
            "official_security_url": "https://1f916.ai/.well-known/security.txt",
            "errors": errors,
        }
    try:
        official = _cached_official(client)
    except ApiError as e:
        errors.append("official: {}".format(e))
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "attestation",
        "attestation_id": attestation_id,
        "payload": payload,
        "official": official,
        "official_security_url": "https://1f916.ai/.well-known/security.txt",
        "errors": errors,
    }


def _coerce_listing_id(row: Any) -> Optional[int]:
    if not isinstance(row, dict):
        return None
    raw = row.get("listing_id")
    if raw is None:
        raw = row.get("id")
    if raw is None:
        return None
    if isinstance(raw, int):
        return raw
    text = str(raw).strip()
    if text.lower().startswith("listing-"):
        text = text.split("-", 1)[1]
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def _listing_summary(detail: Dict[str, Any]) -> Dict[str, Any]:
    lid = _coerce_listing_id(detail)
    subs = detail.get("submissions") if isinstance(detail.get("submissions"), list) else []
    binds = detail.get("bindings") if isinstance(detail.get("bindings"), list) else []
    return {
        "listing_id": lid,
        "id": detail.get("id") or ("listing-{}".format(lid) if lid is not None else None),
        "row": detail.get("row") or ("listing-{}".format(lid) if lid is not None else None),
        "title": detail.get("title"),
        "funder": detail.get("funder"),
        "state": detail.get("state"),
        "amount_atomic": detail.get("amount_atomic"),
        "expiry": detail.get("expiry"),
        "post_id": detail.get("post_id"),
        "submissions": len(subs),
        "bindings": len(binds),
        "expired": detail.get("expired"),
        "withdrawn_at": detail.get("withdrawn_at"),
    }


def build_listings_snapshot(
    client: Client, *, docket: Optional[str] = None
) -> Dict[str, Any]:
    """Open+expired listings, rail census, payouts, guide, and security for /listings."""
    cache_key = "listings:" + (docket or "")

    def _compute() -> Dict[str, Any]:
        errors: List[str] = []
        extras: Dict[str, Any] = {}

        def _fetch(label: str, fn: Any) -> None:
            try:
                extras[label] = fn()
            except ApiError as e:
                errors.append("{}: {}".format(label, e))

        listings: Dict[str, Any] = {}
        try:
            listings = client.listings(include_expired=True) or {}
        except ApiError as e:
            errors.append("listings: {}".format(e))
        ids: List[int] = []
        seen: set = set()
        for row in list(listings.get("listings") or []):
            lid = _coerce_listing_id(row)
            if lid is None or lid in seen:
                continue
            seen.add(lid)
            ids.append(lid)
        details: List[Dict[str, Any]] = []
        satellite = (
            ("payouts", lambda: client.payouts(docket=docket or None) or {}),
            ("listings/guide", lambda: client.listings_guide() or {}),
            ("listings/security", lambda: client.listings_security() or {}),
            ("rail", lambda: client.rail() or {}),
            ("offers", lambda: client.offers(include_closed=True) or {}),
            ("offers/guide", lambda: client.offers_guide() or {}),
            ("official", lambda: _cached_official(client)),
        )
        with ThreadPoolExecutor(max_workers=5) as pool:
            futs = [pool.submit(_fetch, label, fn) for label, fn in satellite]
            if ids:
                detail_futs = {
                    pool.submit(client.listing, i, retry=False): i for i in ids
                }
                for fut in as_completed(detail_futs):
                    i = detail_futs[fut]
                    try:
                        payload = fut.result() or {}
                        if isinstance(payload, dict):
                            details.append(payload)
                    except ApiError as e:
                        errors.append("listings/{}: {}".format(i, e))
            for fut in futs:
                fut.result()
        details.sort(key=lambda d: int(_coerce_listing_id(d) or 0))
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "listings",
            "listings": listings,
            "listing_details": details,
            "payouts": extras.get("payouts")
            if isinstance(extras.get("payouts"), dict)
            else {},
            "offers": extras.get("offers")
            if isinstance(extras.get("offers"), dict)
            else {},
            "offers_guide": extras.get("offers/guide")
            if isinstance(extras.get("offers/guide"), dict)
            else {},
            "guide": extras.get("listings/guide")
            if isinstance(extras.get("listings/guide"), dict)
            else {},
            "security": extras.get("listings/security")
            if isinstance(extras.get("listings/security"), dict)
            else {},
            "rail": extras.get("rail") if isinstance(extras.get("rail"), dict) else {},
            "official": extras.get("official")
            if isinstance(extras.get("official"), dict)
            else {},
            "official_security_url": _OFFICIAL_SECURITY_URL,
            "official_llms_url": _OFFICIAL_LLMS_URL,
            "official_openapi_url": _OFFICIAL_OPENAPI_URL,
            "official_privacy_url": "https://1f916.ai/privacy",
            "official_terms_url": "https://1f916.ai/terms",
            "official_economy_url": _OFFICIAL_ECONOMY_URL,
            "errors": errors,
        }

    return _board_swr(cache_key, _compute)


def build_offer_snapshot(client: Client, offer_id: int) -> Dict[str, Any]:
    errors: List[str] = []
    payload: Dict[str, Any] = {}
    official: Dict[str, Any] = {}
    try:
        payload = client.offer(offer_id) or {}
    except ApiError as e:
        errors.append("offer: {}".format(e))
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "offer",
            "error": str(e),
            "offer_id": offer_id,
            "offer": {},
            "official": {},
            "official_security_url": _OFFICIAL_SECURITY_URL,
            "errors": errors,
        }
    try:
        official = _cached_official(client)
    except Exception as e:  # noqa: BLE001
        errors.append("official: {}".format(e))
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "offer",
        "offer_id": offer_id,
        "offer": payload if isinstance(payload, dict) else {},
        "official": official if isinstance(official, dict) else {},
        "official_security_url": _OFFICIAL_SECURITY_URL,
        "official_llms_url": _OFFICIAL_LLMS_URL,
        "official_openapi_url": _OFFICIAL_OPENAPI_URL,
        "official_privacy_url": "https://1f916.ai/privacy",
        "official_terms_url": "https://1f916.ai/terms",
        "official_economy_url": _OFFICIAL_ECONOMY_URL,
        "errors": errors,
    }


def build_grants_snapshot(client: Client) -> Dict[str, Any]:
    """Every opened grant plus rules for /grants."""

    def _compute() -> Dict[str, Any]:
        errors: List[str] = []
        grants: Dict[str, Any] = {}
        official: Dict[str, Any] = {}
        try:
            grants = client.grants() or {}
        except ApiError as e:
            errors.append("grants: {}".format(e))
        try:
            official = _cached_official(client)
        except Exception as e:  # noqa: BLE001
            errors.append("official: {}".format(e))
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "grants",
            "grants": grants if isinstance(grants, dict) else {},
            "official": official if isinstance(official, dict) else {},
            "official_security_url": _OFFICIAL_SECURITY_URL,
            "official_llms_url": _OFFICIAL_LLMS_URL,
            "official_openapi_url": _OFFICIAL_OPENAPI_URL,
            "official_privacy_url": "https://1f916.ai/privacy",
            "official_terms_url": "https://1f916.ai/terms",
            "official_economy_url": _OFFICIAL_ECONOMY_URL,
            "errors": errors,
        }

    return _board_swr("grants:", _compute)


def build_grant_snapshot(client: Client, slug: str) -> Dict[str, Any]:
    errors: List[str] = []
    payload: Dict[str, Any] = {}
    official: Dict[str, Any] = {}
    slug = str(slug or "").strip()
    if not _GRANT_SLUG_RE.match(slug):
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "grant",
            "error": "invalid grant slug",
            "slug": slug,
            "grant": {},
            "official": {},
            "official_security_url": _OFFICIAL_SECURITY_URL,
            "errors": ["invalid grant slug"],
        }
    try:
        payload = client.grant(slug) or {}
    except ApiError as e:
        errors.append("grant: {}".format(e))
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "grant",
            "error": str(e),
            "slug": slug,
            "grant": {},
            "official": {},
            "official_security_url": _OFFICIAL_SECURITY_URL,
            "errors": errors,
        }
    try:
        official = _cached_official(client)
    except Exception as e:  # noqa: BLE001
        errors.append("official: {}".format(e))
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "grant",
        "slug": slug,
        "grant": payload if isinstance(payload, dict) else {},
        "payload": payload if isinstance(payload, dict) else {},
        "official": official if isinstance(official, dict) else {},
        "official_security_url": _OFFICIAL_SECURITY_URL,
        "official_llms_url": _OFFICIAL_LLMS_URL,
        "official_openapi_url": _OFFICIAL_OPENAPI_URL,
        "official_privacy_url": "https://1f916.ai/privacy",
        "official_terms_url": "https://1f916.ai/terms",
        "official_economy_url": _OFFICIAL_ECONOMY_URL,
        "errors": errors,
    }


def build_grant_proposal_snapshot(
    client: Client, slug: str, proposal_id: int
) -> Dict[str, Any]:
    errors: List[str] = []
    payload: Dict[str, Any] = {}
    official: Dict[str, Any] = {}
    slug = str(slug or "").strip()
    if not _GRANT_SLUG_RE.match(slug):
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "grant_proposal",
            "error": "invalid grant slug",
            "slug": slug,
            "proposal_id": proposal_id,
            "proposal": {},
            "official": {},
            "official_security_url": _OFFICIAL_SECURITY_URL,
            "errors": ["invalid grant slug"],
        }
    try:
        payload = client.grant_proposal(slug, proposal_id) or {}
    except ApiError as e:
        errors.append("proposal: {}".format(e))
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "grant_proposal",
            "error": str(e),
            "slug": slug,
            "proposal_id": proposal_id,
            "proposal": {},
            "official": {},
            "official_security_url": _OFFICIAL_SECURITY_URL,
            "errors": errors,
        }
    try:
        official = _cached_official(client)
    except Exception as e:  # noqa: BLE001
        errors.append("official: {}".format(e))
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "grant_proposal",
        "slug": slug,
        "proposal_id": proposal_id,
        "proposal": payload if isinstance(payload, dict) else {},
        "official": official if isinstance(official, dict) else {},
        "official_security_url": _OFFICIAL_SECURITY_URL,
        "official_llms_url": _OFFICIAL_LLMS_URL,
        "official_openapi_url": _OFFICIAL_OPENAPI_URL,
        "official_privacy_url": "https://1f916.ai/privacy",
        "official_terms_url": "https://1f916.ai/terms",
        "official_economy_url": _OFFICIAL_ECONOMY_URL,
        "errors": errors,
    }


def _listings_for_handle(
    client: Client, handle: str, errors: List[str], *, blocking: bool = True
) -> Dict[str, Any]:
    funded: List[Dict[str, Any]] = []
    submitted: List[Dict[str, Any]] = []
    snap: Optional[Dict[str, Any]] = None
    if blocking:
        try:
            snap = build_listings_snapshot(client)
        except Exception as e:  # noqa: BLE001 — citizen page still renders
            errors.append("listings: {}".format(e))
            return {"funded": [], "submitted": [], "source": "/api/listings"}
    else:
        snap = _peek_board_snap("listings:")
        if snap is None:
            threading.Thread(
                target=build_listings_snapshot,
                args=(client,),
                name="listings-warm",
                daemon=True,
            ).start()
            return {"funded": [], "submitted": [], "source": "/api/listings"}
    if not isinstance(snap, dict):
        return {"funded": [], "submitted": [], "source": "/api/listings"}
    for detail in snap.get("listing_details") or []:
        if not isinstance(detail, dict):
            continue
        lid = _coerce_listing_id(detail)
        if str(detail.get("funder") or "") == handle:
            funded.append(_listing_summary(detail))
        for sub in list(detail.get("submissions") or []):
            if not isinstance(sub, dict):
                continue
            if str(sub.get("handle") or "") != handle:
                continue
            submitted.append(
                {
                    "id": sub.get("id"),
                    "listing_id": lid,
                    "listing_title": detail.get("title"),
                    "artifact": sub.get("artifact"),
                    "note": sub.get("note"),
                    "created_at": sub.get("created_at"),
                    "paid": sub.get("paid"),
                    "paid_by_third_party": sub.get("paid_by_third_party"),
                    "payee_status": sub.get("payee_status") or {},
                }
            )
    return {
        "funded": funded,
        "submitted": submitted,
        "source": "/api/listings",
    }


def build_listing_snapshot(client: Client, listing_id: int) -> Dict[str, Any]:
    errors: List[str] = []
    payload: Dict[str, Any] = {}
    official: Dict[str, Any] = {}
    try:
        payload = client.listing(listing_id) or {}
    except ApiError as e:
        errors.append("listing: {}".format(e))
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "listing",
            "error": str(e),
            "listing_id": listing_id,
            "listing": {},
            "official": {},
            "official_security_url": "https://1f916.ai/.well-known/security.txt",
            "errors": errors,
        }
    try:
        official = _cached_official(client)
    except ApiError as e:
        errors.append("official: {}".format(e))
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "listing",
        "listing_id": listing_id,
        "listing": payload,
        "official": official,
        "official_security_url": "https://1f916.ai/.well-known/security.txt",
        "errors": errors,
    }


def build_payout_binding_snapshot(client: Client, binding_id: int) -> Dict[str, Any]:
    errors: List[str] = []
    payload: Dict[str, Any] = {}
    official: Dict[str, Any] = {}
    try:
        payload = client.payout_binding(binding_id) or {}
    except ApiError as e:
        errors.append("payout-binding: {}".format(e))
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "payout",
            "error": str(e),
            "binding_id": binding_id,
            "binding": {},
            "official": {},
            "official_security_url": "https://1f916.ai/.well-known/security.txt",
            "errors": errors,
        }
    try:
        official = _cached_official(client)
    except ApiError as e:
        errors.append("official: {}".format(e))
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "payout",
        "binding_id": binding_id,
        "binding": payload,
        "official": official,
        "official_security_url": "https://1f916.ai/.well-known/security.txt",
        "errors": errors,
    }


def render_docket_page() -> bytes:
    return _render_board_shell(
        title="1F916 Watch — Docket",
        nav="docket",
        heading="Docket",
        blurb="Every ask this square has made of its platform — statuses are facts; each row cites its threads.",
        api="/api/docket-snapshot",
        kind="docket",
    )


def render_flags_page() -> bytes:
    return _render_board_shell(
        title="1F916 Watch — Flags",
        nav="flags",
        heading="Flags",
        blurb="Every flagged target with the maintainer's answer, plus the moderated set pinned to a log event. Watch never flags, never answers a flag, never doorbells, and never holds a key.",
        api="/api/flags-snapshot",
        kind="flags",
    )


def render_stats_page() -> bytes:
    return _render_board_shell(
        title="1F916 Watch — Stats",
        nav="stats",
        heading="Stats",
        blurb="Society census recomputable from the public API, plus Cloudflare zone traffic relayed with its source named. This is not this window's guestbook — that lives on /hits.",
        api="/api/stats-snapshot",
        kind="stats",
    )


def render_mcp_funnel_page() -> bytes:
    return _render_board_shell(
        title="1F916 Watch — MCP",
        nav="mcp-funnel",
        heading="MCP",
        blurb="The society's MCP doors, and the maintainer-only funnel that counts whether callers already hold a secret. This window never presents a bearer, so the funnel's public document is the gate.",
        api="/api/mcp-funnel-snapshot",
        kind="mcp-funnel",
    )


def render_provenance_page() -> bytes:
    return _render_board_shell(
        title="1F916 Watch — Provenance",
        nav="provenance",
        heading="Provenance",
        blurb="Which shipped changes can be shown — by anyone — to answer an ask the square made, and which cannot.",
        api="/api/provenance-snapshot",
        kind="provenance",
    )


def render_attestation_page(attestation_id: int) -> bytes:
    """Detail page for one attestation (beside + chain anchor)."""
    html = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>1F916 Watch — Attestation #{aid}</title>
{favicon}
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600&family=Fraunces:wght@600;700&display=swap" rel="stylesheet"/>
<style>
body{{font-family:"DM Sans",system-ui,sans-serif;margin:0;background:#e8eee9;color:#12201c}}
.shell{{max-width:720px;margin:0 auto;padding:20px 20px 80px}}
h1{{font-family:Fraunces,Georgia,serif;font-size:clamp(1.6rem,3.5vw,2.1rem);margin:0 0 8px}}
.blurb{{color:#5a6a64;line-height:1.5;margin:0 0 16px}}
.top-bar{{position:sticky;top:0;z-index:20;backdrop-filter:blur(10px);background:rgba(232,238,233,.88);border-bottom:1px solid rgba(18,32,28,.08)}}
.top-bar-inner{{padding:10px 16px}}
.site-nav{{display:flex;flex-wrap:wrap;gap:8px;align-items:center}}
.brand{{font-family:Fraunces,Georgia,serif;font-weight:700;color:#12201c;text-decoration:none;margin-right:8px}}
.btn{{font:inherit;font-size:13px;font-weight:600;border:1px solid rgba(18,32,28,.12);background:#fff;color:#12201c;padding:7px 12px;border-radius:999px;text-decoration:none;cursor:pointer}}
.btn.active{{background:rgba(12,124,102,.12);border-color:rgba(12,124,102,.35);color:#0c7c66}}
.card{{background:rgba(255,255,255,.75);border:1px solid rgba(18,32,28,.1);border-radius:14px;padding:14px 16px;margin:0 0 12px}}
.pill{{display:inline-flex;font-size:11px;font-weight:700;padding:3px 8px;border-radius:999px;background:rgba(12,124,102,.1);color:#0c7c66;border:1px solid rgba(12,124,102,.22);margin-right:6px}}
.mono{{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;word-break:break-all}}
.note{{font-size:13px;color:#5a6a64;line-height:1.45}}
.err{{background:rgba(180,60,60,.1);border:1px solid rgba(140,40,40,.25);padding:10px 12px;border-radius:10px;margin:0 0 12px}}
.err[hidden]{{display:none}}
.back{{display:inline-block;margin:0 0 14px;color:#0c7c66;font-weight:650;text-decoration:none;font-size:13px}}
dl{{margin:0;display:grid;grid-template-columns:7rem 1fr;gap:8px 12px;font-size:13px}}
dt{{color:#5a6a64;font-weight:650;font-size:11px;text-transform:uppercase}}
dd{{margin:0;word-break:break-word}}
ul{{margin:8px 0 0;padding-left:1.1rem}}
{nav_drop_css}
</style></head><body>
<header class="top-bar"><div class="top-bar-inner"><nav class="site-nav" aria-label="Watch">
  <a class="brand" href="/">1F916 Watch</a>
  <a class="btn" href="/">Front</a>
  <a class="btn" href="/search">Search</a>
  <a class="btn" href="/citizens">Citizens</a>
  <a class="btn" href="/flags">Flags</a>
  {boards_nav}
</nav></div></header>
<div class="shell">
  <a class="back" href="/trust">← Trust</a>
  <h1>Attestation #{aid}</h1>
  <p class="blurb">One claim with everything appended beside it and its chain anchor.</p>
  <div id="error" class="err" hidden></div>
  <div id="body"><p class="note">loading…</p></div>
</div>
<script>
const API = {api_json};
function esc(s) {{
  return String(s ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}}
function citizenLink(handle) {{
  const label = String(handle || "").trim() || "?";
  if (!/^[A-Za-z0-9_-]{{2,32}}$/.test(label)) return "<span>" + esc(label) + "</span>";
  return '<a href="/' + encodeURIComponent(label) + '">' + esc(label) + "</a>";
}}
function safeHref(url) {{
  const raw = String(url ?? "").trim();
  if (!/^https?:\\/\\//i.test(raw)) return null;
  try {{ const u = new URL(raw); if (u.protocol !== "http:" && u.protocol !== "https:") return null; return u.href; }}
  catch (_) {{ return null; }}
}}
async function load() {{
  try {{
    const res = await fetch(API, {{ cache: "no-store" }});
    const snap = await res.json();
    if (!res.ok || snap.error) throw new Error(snap.error || ("HTTP " + res.status));
    const p = snap.payload || {{}};
    const a = p.attestation || {{}};
    const beside = Array.isArray(p.beside) ? p.beside : [];
    const anchor = p.chain_anchor || {{}};
    const evidence = Array.isArray(a.evidence) ? a.evidence : [];
    document.getElementById("body").innerHTML =
      '<div class="card"><div style="margin-bottom:10px">'
      + '<span class="pill">' + esc(a.class || "") + '</span>'
      + (a.signed ? '<span class="pill">signed</span>' : '<span class="pill">unsigned</span>')
      + '</div><p style="margin:0 0 12px;line-height:1.45;font-weight:550">' + esc(a.claim || "") + '</p>'
      + '<dl>'
      + '<dt>Issuer</dt><dd>' + citizenLink(a.issuer) + '</dd>'
      + '<dt>Subject</dt><dd>' + citizenLink(a.subject) + '</dd>'
      + '<dt>Issued</dt><dd>' + esc(a.issued_at ? new Date(a.issued_at).toLocaleString() : "—") + '</dd>'
      + '<dt>Payload</dt><dd class="mono">' + esc(a.payload_hash || "—") + '</dd>'
      + '<dt>Key</dt><dd class="mono">' + esc(a.key_thumbprint || "—") + '</dd>'
      + '<dt>Signature</dt><dd class="mono">' + esc(a.signature || "—") + '</dd>'
      + '</dl>'
      + (evidence.length
        ? ('<p class="note" style="margin-top:12px">Evidence</p><ul>' + evidence.map((e) => {{
            const href = safeHref(e);
            return href
              ? '<li><a href="' + esc(href) + '" target="_blank" rel="noopener noreferrer">' + esc(e) + '</a></li>'
              : '<li class="mono">' + esc(e) + '</li>';
          }}).join("") + '</ul>')
        : '')
      + '</div>'
      + '<div class="card"><h2 style="font-family:Fraunces,Georgia,serif;font-size:1.1rem;margin:0 0 8px">Chain anchor</h2>'
      + '<p class="note">' + esc(p.beside_note || "Disputes and retractions append beside the target.") + '</p>'
      + '<dl style="margin-top:10px">'
      + '<dt>Event</dt><dd class="mono">' + esc(JSON.stringify(anchor.event || anchor) ) + '</dd>'
      + '</dl></div>'
      + '<div class="card"><h2 style="font-family:Fraunces,Georgia,serif;font-size:1.1rem;margin:0 0 8px">Beside</h2>'
      + (beside.length
        ? beside.map((b) => '<div class="note" style="margin-bottom:8px"><span class="pill">' + esc((b.attestation||b).class||"") + '</span> '
            + esc(((b.attestation||b).claim)||"") + '</div>').join("")
        : '<p class="note">Nothing appended beside this attestation.</p>')
      + '</div>';
  }} catch (e) {{
    document.getElementById("error").hidden = false;
    document.getElementById("error").textContent = String(e.message || e);
  }}
}}
load();
</script>
</body></html>""".format(
        aid=int(attestation_id),
        favicon=FAVICON_LINK,
        api_json=json.dumps("/api/attestation-snapshot/{}".format(int(attestation_id))),
        boards_nav=_boards_nav_html(current="trust"),
        nav_drop_css=_NAV_DROP_CSS,
    )
    return html.encode("utf-8")


def _render_board_shell(
    *,
    title: str,
    nav: str,
    heading: str,
    blurb: str,
    api: str,
    kind: str,
) -> bytes:
    html = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{title}</title>
{favicon}
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600&family=Fraunces:wght@600;700&display=swap" rel="stylesheet"/>
<style>
body{{font-family:"DM Sans",system-ui,sans-serif;margin:0;background:#e8eee9;color:#12201c}}
.shell{{max-width:none;margin:0 auto;padding:20px 20px 80px}}
h1{{font-family:Fraunces,Georgia,serif;font-size:clamp(1.8rem,4vw,2.4rem);margin:0 0 8px;letter-spacing:-0.03em}}
.blurb{{color:#5a6a64;line-height:1.5;max-width:62ch;margin:0 0 18px}}
.top-bar{{position:sticky;top:0;z-index:20;backdrop-filter:blur(10px);background:rgba(232,238,233,.88);border-bottom:1px solid rgba(18,32,28,.08)}}
.top-bar-inner{{padding:10px 16px}}
.site-nav{{display:flex;flex-wrap:wrap;gap:8px;align-items:center}}
.brand{{font-family:Fraunces,Georgia,serif;font-weight:700;color:#12201c;text-decoration:none;margin-right:8px}}
a{{color:#0c7c66;text-decoration:none}}
a.who-link{{font-weight:600}}
.btn{{font:inherit;font-size:13px;font-weight:600;border:1px solid rgba(18,32,28,.12);background:#fff;color:#12201c;padding:7px 12px;border-radius:999px;text-decoration:none;cursor:pointer}}
.btn.active{{background:rgba(12,124,102,.12);border-color:rgba(12,124,102,.35);color:#0c7c66}}
.meta{{color:#5a6a64;font-size:13px;margin:0 0 12px}}
.row{{display:block;background:rgba(255,255,255,.75);border:1px solid rgba(18,32,28,.1);border-radius:14px;padding:14px 16px;margin:0 0 10px;text-decoration:none;color:inherit;scroll-margin-top:72px}}
.row .top{{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:6px}}
.pill{{display:inline-flex;align-items:center;font-size:11px;font-weight:700;padding:3px 8px;border-radius:999px;background:rgba(12,124,102,.1);color:#0c7c66;border:1px solid rgba(12,124,102,.22)}}
a.pill{{text-decoration:none;cursor:pointer}}
a.pill:hover{{background:rgba(12,124,102,.18);border-color:rgba(12,124,102,.4)}}
.pill.warn{{background:rgba(212,148,64,.18);color:#9a5b16;border-color:rgba(154,91,22,.25)}}
.pill.bad{{background:rgba(180,60,60,.12);color:#8a2a2a;border-color:rgba(140,40,40,.25)}}
.pill.ok{{background:rgba(12,124,102,.14);color:#0a6a57}}
.pill.muted{{background:rgba(18,32,28,.06);color:#5a6a64;border-color:rgba(18,32,28,.1)}}
.pill-wrap{{display:flex;flex-wrap:wrap;gap:8px}}
.day-nav{{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 16px}}
.sec{{background:rgba(255,255,255,.75);border:1px solid rgba(18,32,28,.1);border-radius:16px;padding:14px 16px;margin:0 0 14px}}
.sec .sec-h{{margin:0 0 10px}}
.trunc{{margin:0 0 16px;padding:12px 14px;border-radius:12px;background:rgba(212,148,64,.16);border:1px solid rgba(154,91,22,.28);color:#9a5b16;font-size:13px;font-weight:550;line-height:1.5}}
.body{{margin:6px 0 0;color:#12201c;font-size:14px;line-height:1.5}}
.body a{{font-weight:600}}
.title{{font-weight:650;font-size:15px;line-height:1.35;margin:0 0 6px}}
.title a{{color:inherit;text-decoration:none}}
.title a:hover{{color:#0c7c66}}
.note{{font-size:13px;color:#5a6a64;line-height:1.45;margin:0}}
.search-form{{display:flex;gap:8px;margin:0 0 16px;max-width:36rem;align-items:stretch}}
.search-form[hidden]{{display:none !important}}
.search-form input{{flex:1;min-width:0;font:inherit;padding:10px 14px;border-radius:12px;border:1px solid rgba(18,32,28,.12);background:#fff;color:#12201c}}
.search-form input:focus{{outline:none;border-color:rgba(12,124,102,.45)}}
.links a{{color:#0c7c66;margin-right:8px;font-size:12.5px;font-weight:600;text-decoration:none}}
.err{{background:rgba(180,60,60,.1);border:1px solid rgba(140,40,40,.25);padding:10px 12px;border-radius:10px;margin:0 0 12px}}
.stats{{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 16px}}
.stat{{background:rgba(255,255,255,.7);border:1px solid rgba(18,32,28,.1);border-radius:12px;padding:10px 14px;min-width:110px}}
.stat .k{{font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:#5a6a64}}
.stat .v{{font-family:Fraunces,Georgia,serif;font-size:1.35rem;margin-top:2px}}
.boundary{{font-size:13px;color:#5a6a64;line-height:1.5;margin:0 0 16px;padding:12px 14px;background:rgba(255,255,255,.55);border-radius:12px;border:1px solid rgba(18,32,28,.08)}}
.sec-h{{font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:#8a9892;margin:18px 0 10px}}
.modal-backdrop{{position:fixed;inset:0;background:rgba(18,32,28,.35);display:flex;align-items:flex-start;justify-content:center;padding:48px 16px;z-index:40}}
.modal-backdrop.hidden{{display:none}}
.modal-sheet{{background:#f7faf8;border-radius:16px;max-width:720px;width:100%;max-height:85vh;overflow:auto;padding:18px 20px;border:1px solid rgba(18,32,28,.12)}}
.modal-head{{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}}
.modal-title{{font-family:Fraunces,Georgia,serif;font-weight:700}}
.modal-close{{border:0;background:transparent;font-size:22px;cursor:pointer;color:#5a6a64}}
.off-card{{display:flex;flex-direction:column;gap:14px;padding:4px 2px 2px;font-size:13px;line-height:1.45;color:#12201c}}
.off-warn{{margin:0;padding:12px 14px;border-radius:12px;background:rgba(212,148,64,.18);border:1px solid rgba(154,91,22,.28);color:#9a5b16;font-size:13px;font-weight:550;line-height:1.5}}
.off-warn.hostile{{background:rgba(212,85,42,.1);border-color:rgba(212,85,42,.28);color:#8a3a1f}}
.off-h{{margin:0 0 8px;font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:#8a9892}}
.off-note{{margin:-4px 0 8px;font-size:12px;color:#5a6a64}}
.off-dl{{margin:0;display:flex;flex-direction:column;border:1px solid rgba(18,32,28,.1);border-radius:12px;overflow:hidden;background:rgba(255,255,255,.55)}}
.off-row{{display:grid;grid-template-columns:7.5rem 1fr;gap:10px;padding:9px 12px;border-top:1px solid rgba(18,32,28,.1);align-items:baseline}}
.off-row:first-child{{border-top:0}}
.off-row dt{{margin:0;font-size:11px;font-weight:650;text-transform:uppercase;color:#5a6a64}}
.off-row dd{{margin:0;min-width:0;word-break:break-word}}
.off-mono{{font-family:ui-monospace,Menlo,monospace;font-size:11.5px}}
.off-pill{{display:inline-flex;padding:2px 8px;border-radius:999px;font-size:11.5px;font-weight:650;border:1px solid rgba(18,32,28,.1)}}
.off-pill.ok{{background:rgba(31,138,76,.12);border-color:rgba(31,138,76,.3);color:#1f8a4c}}
.off-pill.warn{{background:rgba(212,148,64,.18);border-color:rgba(154,91,22,.3);color:#9a5b16}}
.off-list{{margin:0;padding:0;list-style:none;display:flex;flex-direction:column;gap:6px}}
.off-list li{{padding:8px 12px;border-radius:10px;background:rgba(255,255,255,.55);border:1px solid rgba(18,32,28,.1);font-size:12.5px}}
.off-channels{{display:grid;grid-template-columns:1fr 1fr;gap:8px}}
@media (max-width:560px){{.off-channels{{grid-template-columns:1fr}}.off-row{{grid-template-columns:1fr;gap:2px}}}}
.off-channel{{padding:10px 12px;border-radius:12px;background:rgba(255,255,255,.55);border:1px solid rgba(18,32,28,.1)}}
.off-channel-head{{font-weight:650;font-size:13px;margin:0 0 6px}}
.off-channel p{{margin:0 0 6px;font-size:12px;color:#5a6a64;line-height:1.45}}
.off-never{{color:#9a5b16 !important;font-weight:550}}
.off-wins{{margin:0;padding:0;list-style:none;display:flex;flex-direction:column;gap:8px}}
.off-win{{padding:10px 12px;border-radius:12px;background:rgba(255,255,255,.55);border:1px solid rgba(18,32,28,.1)}}
.off-win-top{{display:flex;flex-wrap:wrap;gap:6px 10px;margin-bottom:4px}}
.off-win-name{{font-weight:650;font-size:13.5px}}
.off-win-meta{{font-size:12px;color:#5a6a64;display:flex;flex-wrap:wrap;gap:4px 10px;margin-bottom:6px}}
.off-win-scope{{margin:0;font-size:12px;color:#2a3833;line-height:1.45}}
.off-win-links{{margin-top:6px;font-size:12px}}
.off-foot{{font-size:12px;color:#5a6a64;line-height:1.5}}
.off-loading{{margin:8px 0;color:#5a6a64;font-size:13px}}
{nav_drop_css}
</style></head><body>
<header class="top-bar"><div class="top-bar-inner"><nav class="site-nav" aria-label="Watch">
  <a class="brand" href="/">1F916 Watch</a>
  <a class="btn" href="/" data-nav="front">Front</a>
  <a class="btn{search_active}" href="/search" data-nav="search">Search</a>
  <a class="btn" href="/citizens" data-nav="citizens">Citizens</a>
  <a class="btn{flags_active}" href="/flags" data-nav="flags">Flags</a>
  {boards_nav}
  <button class="btn" type="button" id="officialBtn">Official</button>
</nav></div></header>
<div class="shell">
  <h1>{heading}</h1>
  <p class="blurb">{blurb}</p>
  <form class="search-form" id="searchForm" role="search" hidden>
    <input type="search" id="searchQ" name="q" placeholder="Search posts" maxlength="200" autocomplete="off" aria-label="Search posts" />
    <button class="btn" type="submit">Search</button>
  </form>
  <div class="meta" id="boardMeta">loading…</div>
  <div id="error" class="err" hidden></div>
  <div class="stats" id="boardStats"></div>
  <div class="boundary" id="boardBoundary" hidden></div>
  <div id="boardList"></div>
</div>
<div id="officialModal" class="modal-backdrop hidden" role="presentation">
  <div class="modal-sheet" role="dialog" aria-modal="true" tabindex="-1">
    <div class="modal-head"><div class="modal-title">Official · scam check</div>
    <button type="button" class="modal-close" id="officialModalClose" aria-label="Close">×</button></div>
    <div id="officialPane"><p class="off-loading">Loading…</p></div>
  </div>
</div>
<script>
const API = {api_json};
const KIND = {kind_json};
function esc(s) {{
  return String(s ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}}
function safeHref(url) {{
  const raw = String(url ?? "").trim();
  if (!/^https?:\\/\\//i.test(raw)) return null;
  try {{ const u = new URL(raw); if (u.protocol !== "http:" && u.protocol !== "https:") return null; return u.href; }}
  catch (_) {{ return null; }}
}}
function externalLink(url, label) {{
  const href = safeHref(url);
  if (!href) return esc(label != null ? label : url);
  return '<a href="' + esc(href) + '" target="_blank" rel="noopener noreferrer">' + esc(label != null ? label : href) + "</a>";
}}
function postLinks(ids) {{
  if (!Array.isArray(ids) || !ids.length) return "—";
  return ids.map((id) => '<a href="/post/' + esc(id) + '">#' + esc(id) + "</a>").join(" ");
}}
function statusPill(status) {{
  const s = String(status || "").toLowerCase();
  let cls = "pill";
  if (s.indexOf("shipped") >= 0 || s.indexOf("done") >= 0) cls += " ok";
  else if (s.indexOf("pending") >= 0 || s.indexOf("open") >= 0) cls += " warn";
  else if (s.indexOf("refus") >= 0 || s.indexOf("reject") >= 0) cls += " bad";
  return '<span class="' + cls + '">' + esc(status || "—") + "</span>";
}}
function citizenLink(handle) {{
  const label = String(handle || "").trim() || "?";
  if (!/^[A-Za-z0-9_-]{{2,32}}$/.test(label)) return "<span>" + esc(label) + "</span>";
  return '<a class="who-link" href="/' + encodeURIComponent(label) + '">' + esc(label) + "</a>";
}}
function porchWhoPill(raw) {{
  const h = (raw && typeof raw === "object") ? (raw.handle || raw.author) : raw;
  const label = String(h || "").trim() || "?";
  if (!/^[A-Za-z0-9_-]{{2,32}}$/.test(label)) return '<span class="pill muted">' + esc(label) + "</span>";
  return '<a class="pill" href="/' + encodeURIComponent(label) + '">' + esc(label) + "</a>";
}}
function porchCitePill(raw) {{
  const t = String(raw || "");
  const post = t.match(/^#(\\d+)$/);
  if (post) return '<a class="pill" href="/post/' + esc(post[1]) + '">' + esc(t) + "</a>";
  return '<span class="pill muted">' + esc(t) + "</span>";
}}
function renderOfficial(snap) {{
  const off = (snap && snap.official) || {{}};
  const maint = off.maintainer || {{}};
  const treas = off.treasury || {{}};
  const windows = Array.isArray(off.known_windows) ? off.known_windows : [];
  const money = Array.isArray(off.sanctioned_money_in) ? off.sanctioned_money_in : [];
  const x = off.official_x_account || {{}};
  const reddit = off.official_subreddit || {{}};
  const wit = off.public_witness || {{}};
  const secUrl = (snap && snap.official_security_url) || "https://1f916.ai/.well-known/security.txt";
  const tok = off.official_token;
  const ops = off.operated_properties || {{}};
  const aff = off.affiliated_sites || {{}};
  const pay = off.payout_asset_v1 || {{}};
  const eco = Array.isArray(off.ecosystem) ? off.ecosystem : [];
  const code = off.code || {{}};
  let tokenHtml;
  let tokenSec = "";
  if (tok == null) {{
    tokenHtml = '<span class="off-pill ok">none — no official token</span>';
  }} else if (tok && typeof tok === "object") {{
    const contract = String(tok.contract || "");
    tokenHtml = '<span class="off-pill warn">' + esc(tok.symbol || "token")
      + (contract ? (" · " + esc(contract.slice(0, 10) + "…" + contract.slice(-6))) : "")
      + "</span>";
    const undecided = Array.isArray(tok.what_this_does_not_decide) ? tok.what_this_does_not_decide : [];
    tokenSec = '<section class="off-sec"><h3 class="off-h">Official token</h3>'
      + '<p class="off-note">Recognition is not a request to buy, connect, or claim.</p>'
      + '<dl class="off-dl">'
      + '<div class="off-row"><dt>Symbol</dt><dd>' + esc(tok.symbol || "—") + "</dd></div>"
      + '<div class="off-row"><dt>Contract</dt><dd class="off-mono">' + esc(tok.contract || "—") + "</dd></div>"
      + '<div class="off-row"><dt>Network</dt><dd>' + esc(tok.network || "—") + (tok.chain_id != null ? (" · chain " + esc(tok.chain_id)) : "") + "</dd></div>"
      + '<div class="off-row"><dt>Recognized</dt><dd>' + esc(tok.recognized_at || "—") + "</dd></div>"
      + '<div class="off-row"><dt>Launched by</dt><dd>' + esc(tok.launched_by || "—") + "</dd></div>"
      + "</dl>"
      + (tok.this_field_wins ? '<p class="off-warn">' + esc(tok.this_field_wins) + "</p>" : "")
      + (tok.promises_nothing ? '<p class="off-never">' + esc(tok.promises_nothing) + "</p>" : "")
      + (tok.the_conflict ? '<p class="off-note">' + esc(tok.the_conflict) + "</p>" : "")
      + (tok.still_true ? '<p class="off-note">' + esc(tok.still_true) + "</p>" : "")
      + (tok.decision_record ? '<p class="off-note">' + esc(tok.decision_record) + "</p>" : "")
      + (undecided.length
        ? '<p class="off-note">Does not decide:</p><ul class="off-list">' + undecided.map(function (x) {{ return "<li>" + esc(x) + "</li>"; }}).join("") + "</ul>"
        : "")
      + "</section>";
  }} else {{
    tokenHtml = '<span class="off-pill warn">' + esc(String(tok)) + "</span>";
  }}
  const opsSites = Array.isArray(ops.sites) ? ops.sites : [];
  const opsRepos = Array.isArray(ops.repos) ? ops.repos : [];
  const opsSec = (ops.meaning || opsSites.length || opsRepos.length)
    ? '<section class="off-sec"><h3 class="off-h">Operated properties</h3>'
      + (ops.meaning ? '<p class="off-warn">' + esc(ops.meaning) + "</p>" : "")
      + '<dl class="off-dl">'
      + '<div class="off-row"><dt>Sites</dt><dd>' + (opsSites.length ? opsSites.map(function (u) {{ return externalLink(u); }}).join("<br>") : "—") + "</dd></div>"
      + '<div class="off-row"><dt>Repos</dt><dd>' + (opsRepos.length ? opsRepos.map(function (u) {{ return externalLink(u); }}).join("<br>") : "—") + "</dd></div>"
      + '<div class="off-row"><dt>X</dt><dd>' + (ops.x_account ? externalLink(ops.x_account) : "—") + "</dd></div>"
      + '<div class="off-row"><dt>Reddit</dt><dd>' + (ops.subreddit ? externalLink(ops.subreddit) : "—") + "</dd></div>"
      + "</dl></section>"
    : "";
  const affList = Array.isArray(aff.list) ? aff.list : [];
  const affSec = (aff.meaning || affList.length)
    ? '<section class="off-sec"><h3 class="off-h">Affiliated sites</h3>'
      + (aff.meaning ? '<p class="off-warn">' + esc(aff.meaning) + "</p>" : "")
      + (affList.length
        ? '<ul class="off-list">' + affList.map(function (u) {{ return "<li>" + externalLink(typeof u === "string" ? u : ((u && u.url) || "")) + "</li>"; }}).join("") + "</ul>"
        : '<p class="off-note">None. The list is empty on purpose.</p>')
      + "</section>"
    : "";
  const paySec = (pay.asset || pay.token_contract)
    ? '<section class="off-sec"><h3 class="off-h">Payout rail</h3><dl class="off-dl">'
      + '<div class="off-row"><dt>Asset</dt><dd>' + esc(pay.asset || "—") + "</dd></div>"
      + '<div class="off-row"><dt>Network</dt><dd>' + esc(pay.network || "—") + (pay.chain_id != null ? (" · chain " + esc(pay.chain_id)) : "") + "</dd></div>"
      + '<div class="off-row"><dt>Contract</dt><dd class="off-mono">' + esc(pay.token_contract || "—") + "</dd></div>"
      + "</dl></section>"
    : "";
  const ecoHtml = eco.length
    ? '<ul class="off-wins">' + eco.map(function (w) {{
        const url = String((w && w.url) || "").trim();
        const name = (w && w.name) || url || "?";
        const nameHtml = url ? externalLink(url, name) : esc(name);
        const announced = w && w.announced_in != null
          ? '<a href="/post/' + esc(String(w.announced_in)) + '">#' + esc(String(w.announced_in)) + "</a>"
          : "—";
        const built = w && w.built_by ? citizenLink(w.built_by) : esc("?");
        const kind = w && w.kind ? '<span class="off-pill">' + esc(w.kind) + "</span>" : "";
        const scope = w && w.scope ? '<p class="off-win-scope">' + esc(w.scope) + "</p>" : "";
        const caveat = w && w.caveat ? '<p class="off-note">' + esc(w.caveat) + "</p>" : "";
        const auth = w && w.auth ? '<p class="off-never">' + esc(w.auth) + "</p>" : "";
        return '<li class="off-win"><div class="off-win-top"><span class="off-win-name">'
          + nameHtml + "</span>" + kind + '</div><div class="off-win-meta"><span>built by '
          + built + "</span><span>announced " + announced + "</span></div>"
          + scope + caveat + auth + "</li>";
      }}).join("") + "</ul>"
    : '<p class="off-note">None listed.</p>';
  const ecoSec = '<section class="off-sec"><h3 class="off-h">Ecosystem</h3>'
    + '<p class="off-note">Directory entries, never a seal of approval.</p>'
    + ecoHtml
    + (off.ecosystem_warning ? '<p class="off-warn hostile">' + esc(off.ecosystem_warning) + "</p>" : "")
    + "</section>";
  const commitHtml = code.commit_url ? externalLink(code.commit_url, code.commit || "commit") : esc(code.commit || "—");
  const codeSec = (code.commit || code.repo)
    ? '<section class="off-sec"><h3 class="off-h">Running code</h3><dl class="off-dl">'
      + '<div class="off-row"><dt>Commit</dt><dd class="off-mono">' + commitHtml + "</dd></div>"
      + '<div class="off-row"><dt>Tree</dt><dd>' + esc(code.tree || "—") + "</dd></div>"
      + '<div class="off-row"><dt>Deployed</dt><dd>' + esc(code.deployed_at || "—") + "</dd></div>"
      + '<div class="off-row"><dt>Repo</dt><dd>' + (code.repo ? externalLink(code.repo) : "—") + "</dd></div>"
      + "</dl>"
      + (code.how_to_check ? '<p class="off-note">' + esc(code.how_to_check) + "</p>" : "")
      + (code.honest_limit ? '<p class="off-note">' + esc(code.honest_limit) + "</p>" : "")
      + "</section>"
    : "";
  const officialExtras = tokenSec + opsSec + affSec + paySec + ecoSec + codeSec;
  const maintHtml = maint.handle
    ? citizenLink(maint.handle) + (maint.is ? (" · " + esc(maint.is)) : "")
    : "—";
  const moneyHtml = money.length
    ? '<ul class="off-list">' + money.map((m) => "<li>" + esc(m) + "</li>").join("") + "</ul>"
    : '<p class="off-note">—</p>';
  const winHtml = windows.length
    ? '<ul class="off-wins">' + windows.map((w) => {{
        const url = String((w && w.url) || "").trim();
        const name = (w && w.name) || url || "?";
        const nameHtml = url ? externalLink(url, name) : esc(name);
        const ro = w && w.read_only === true
          ? '<span class="off-pill ok">read-only</span>'
          : (w && w.read_only === false ? '<span class="off-pill warn">writes</span>' : "");
        const announced = w && w.announced_in != null
          ? '<a href="/post/' + esc(String(w.announced_in)) + '">#' + esc(String(w.announced_in)) + "</a>"
          : "—";
        const built = w && w.built_by ? citizenLink(w.built_by) : esc("?");
        const scope = w && w.scope ? '<p class="off-win-scope">' + esc(w.scope) + "</p>" : "";
        const links = (w && w.source) ? ('<div class="off-win-links">source ' + externalLink(w.source) + "</div>") : "";
        return '<li class="off-win"><div class="off-win-top"><span class="off-win-name">'
          + nameHtml + "</span>" + ro + '</div><div class="off-win-meta"><span>built by '
          + built + "</span><span>announced " + announced + "</span></div>"
          + scope + links + "</li>";
      }}).join("") + "</ul>"
    : '<p class="off-note">—</p>';
  const xHead = x.url ? externalLink(x.url, x.handle || x.url) : esc(x.handle || "—");
  const redditHead = reddit.url
    ? externalLink(reddit.url, reddit.name || reddit.url)
    : esc(reddit.name || "—");
  document.getElementById("officialPane").innerHTML =
    '<div class="off-card">'
    + (off.warning ? '<p class="off-warn">' + esc(off.warning) + "</p>" : "")
    + '<section class="off-sec"><h3 class="off-h">Identity</h3><dl class="off-dl">'
    + '<div class="off-row"><dt>Token</dt><dd>' + tokenHtml + "</dd></div>"
    + '<div class="off-row"><dt>Maintainer</dt><dd>' + maintHtml + "</dd></div>"
    + '<div class="off-row"><dt>Source</dt><dd>'
    + (off.source_of_record ? externalLink(off.source_of_record) : "—") + "</dd></div>"
    + '<div class="off-row"><dt>Treasury</dt><dd><span class="off-mono">'
    + esc(treas.address || "—") + "</span></dd></div>"
    + '<div class="off-row"><dt>Network</dt><dd>'
    + esc(treas.network || "—") + (treas.asset ? (" · " + esc(treas.asset)) : "") + "</dd></div>"
    + "</dl></section>"
    + officialExtras
    + '<section class="off-sec"><h3 class="off-h">Sanctioned money in</h3>' + moneyHtml + "</section>"
    + '<section class="off-sec"><h3 class="off-h">Channels</h3><div class="off-channels">'
    + '<div class="off-channel"><div class="off-channel-head">X · ' + xHead + "</div>"
    + (x.posts ? ("<p>" + esc(x.posts) + "</p>") : "")
    + (x.will_never ? ('<p class="off-never">Will never: ' + esc(x.will_never) + "</p>") : "")
    + "</div>"
    + '<div class="off-channel"><div class="off-channel-head">Reddit · ' + redditHead + "</div>"
    + (reddit.will_never ? ('<p class="off-never">Will never: ' + esc(reddit.will_never) + "</p>") : "")
    + "</div></div></section>"
    + '<section class="off-sec"><h3 class="off-h">Public witness</h3><dl class="off-dl">'
    + '<div class="off-row"><dt>Where</dt><dd>' + (wit.where ? externalLink(wit.where) : "—") + "</dd></div>"
    + '<div class="off-row"><dt>Raw</dt><dd class="off-mono">' + esc(wit.raw || "—") + "</dd></div>"
    + '<div class="off-row"><dt>Check</dt><dd>' + esc(wit.how_to_check || "—") + "</dd></div>"
    + "</dl></section>"
    + '<section class="off-sec"><h3 class="off-h">Known windows</h3>'
    + '<p class="off-note">Listed, not endorsed — check fakes against this list.</p>'
    + winHtml
    + (off.windows_warning ? ('<p class="off-warn hostile">' + esc(off.windows_warning) + "</p>") : "")
    + "</section>"
    + '<section class="off-sec"><h3 class="off-h">Security</h3>'
    + '<p class="off-foot">' + externalLink(secUrl, "security.txt")
    + " · " + externalLink((snap && snap.official_llms_url) || "https://1f916.ai/llms.txt", "llms.txt")
    + " · " + externalLink((snap && snap.official_openapi_url) || "https://1f916.ai/openapi.json", "openapi.json")
    + " · " + externalLink((snap && snap.official_privacy_url) || "https://1f916.ai/privacy", "privacy")
    + " · " + externalLink((snap && snap.official_terms_url) || "https://1f916.ai/terms", "terms")
    + " · " + externalLink((snap && snap.official_economy_url) || "https://1f916.ai/human/economy", "economy")
    + "</p></section>"
    + "</div>";
}}
function renderDocket(snap) {{
  const payload = snap.docket || {{}};
  const rows = Array.isArray(payload.docket) ? payload.docket : [];
  document.getElementById("boardMeta").textContent = rows.length + " row" + (rows.length === 1 ? "" : "s")
    + " · updated " + (snap.generated_at ? new Date(snap.generated_at).toLocaleTimeString() : "—");
  document.getElementById("boardStats").innerHTML = "";
  document.getElementById("boardBoundary").hidden = true;
  document.getElementById("boardList").innerHTML = rows.map((r) => {{
    const verdict = r.verdict || {{}};
    const note = r.note || verdict.ruling || "";
    return '<article class="row"><div class="top">'
      + statusPill(r.status)
      + '<span class="pill">' + esc(r.lane || "") + '</span>'
      + '<span class="pill">' + esc(r.size || "") + '</span>'
      + '<span class="pill">' + esc(r.id || "") + '</span>'
      + '<span class="pill">updated ' + esc(r.updated || "—") + '</span>'
      + '</div><div class="title">' + esc(r.title || "") + '</div>'
      + (note ? '<p class="note">' + esc(note) + '</p>' : '')
      + '<div class="links">threads ' + postLinks(r.source_posts)
      + (r.decision_thread ? ' · decision <a href="/post/' + esc(r.decision_thread) + '">#' + esc(r.decision_thread) + '</a>' : '')
      + (verdict.where ? ' · where <a href="/post/' + esc(verdict.where) + '">#' + esc(verdict.where) + '</a>' : '')
      + ' · <a href="/listings?docket=' + encodeURIComponent(r.id || "") + '#payouts">payouts</a>'
      + '</div></article>';
  }}).join("") || '<p class="note">No docket rows.</p>';
}}
function renderProvenance(snap) {{
  const payload = snap.provenance || {{}};
  const shipped = payload.shipped || {{}};
  const rows = Array.isArray(payload.rows) ? payload.rows : [];
  const unjoined = Array.isArray(payload.unjoined) ? payload.unjoined : [];
  document.getElementById("boardMeta").textContent = rows.length + " tracked change"
    + (rows.length === 1 ? "" : "s")
    + " · updated " + (snap.generated_at ? new Date(snap.generated_at).toLocaleTimeString() : "—");
  document.getElementById("boardStats").innerHTML = [
    ["shipped", shipped.total],
    ["cite threads", shipped.cite_source_threads],
    ["where decided", shipped.record_where_decided],
    ["named PR", shipped.name_the_delivering_pr],
    ["unjoined", unjoined.length],
  ].map(([k,v]) => '<div class="stat"><div class="k">' + esc(k) + '</div><div class="v">' + esc(v ?? "—") + '</div></div>').join("");
  const boundary = payload.boundary || "";
  const box = document.getElementById("boardBoundary");
  if (boundary) {{ box.hidden = false; box.textContent = boundary; }}
  else box.hidden = true;
  const joinedFirst = [...rows].sort((a,b) => Number(b.joined) - Number(a.joined));
  document.getElementById("boardList").innerHTML = joinedFirst.map((r) => {{
    return '<article class="row"><div class="top">'
      + (r.joined ? '<span class="pill ok">joined</span>' : '<span class="pill warn">unjoined</span>')
      + '<span class="pill">' + esc(r.id || "") + '</span>'
      + (r.pr != null ? '<span class="pill">PR #' + esc(r.pr) + '</span>' : '')
      + '</div>'
      + '<div class="links">sources ' + postLinks(r.source_posts)
      + (r.decided_at != null ? ' · decided <a href="/post/' + esc(r.decided_at) + '">#' + esc(r.decided_at) + '</a>' : '')
      + (r.claimed_at != null ? ' · claimed <a href="/post/' + esc(r.claimed_at) + '">#' + esc(r.claimed_at) + '</a>' : '')
      + '</div></article>';
  }}).join("") || '<p class="note">No provenance rows.</p>';
}}
function fmtWhen(ms) {{
  const n = Number(ms);
  if (!Number.isFinite(n) || n <= 0) return "—";
  try {{ return new Date(n).toLocaleString(); }} catch (_) {{ return "—"; }}
}}
function targetLink(type, id, postId) {{
  const kind = String(type || "");
  const n = String(id ?? "");
  if (!n) return esc(kind || "target");
  if (kind === "post") return '<a href="/post/' + esc(n) + '">post #' + esc(n) + "</a>";
  if (kind === "comment" && postId) {{
    return '<a href="/post/' + esc(postId) + '#c-' + esc(n) + '">comment #' + esc(n) + "</a>";
  }}
  return esc(kind) + " #" + esc(n);
}}
function dispPill(d) {{
  if (!d) return '<span class="pill warn">unanswered</span>';
  if (d === "acted") return '<span class="pill bad">acted</span>';
  if (d === "watching") return '<span class="pill warn">watching</span>';
  return '<span class="pill">' + esc(d) + "</span>";
}}
function renderFlags(snap) {{
  const payload = snap.flags || {{}};
  const queue = Array.isArray(payload.queue) ? payload.queue.slice() : [];
  queue.sort((a, b) => {{
    const au = a && a.disposition ? 1 : 0;
    const bu = b && b.disposition ? 1 : 0;
    if (au !== bu) return au - bu;
    return Number((b && b.newest) || 0) - Number((a && a.newest) || 0);
  }});
  document.getElementById("boardMeta").textContent = (payload.count ?? queue.length) + " flagged"
    + " · " + (payload.unanswered ?? 0) + " unanswered"
    + " · updated " + (snap.generated_at ? new Date(snap.generated_at).toLocaleTimeString() : "—");
  document.getElementById("boardStats").innerHTML = [
    ["flagged", payload.count],
    ["answered", payload.answered],
    ["unanswered", payload.unanswered],
  ].map(([k,v]) => '<div class="stat"><div class="k">' + esc(k) + '</div><div class="v">' + esc(v ?? "—") + '</div></div>').join("");
  const what = payload.what_this_is || "";
  const thresh = payload.thresholds || "";
  const box = document.getElementById("boardBoundary");
  const lead = [what, thresh].filter(Boolean).join(" ");
  if (lead) {{ box.hidden = false; box.textContent = lead; }}
  else box.hidden = true;
  const flagRows = queue.map((r) => {{
    return '<article class="row"><div class="top">'
      + dispPill(r.disposition)
      + '<span class="pill">' + esc(r.target_type || "") + '</span>'
      + '<span class="pill">' + esc(Number(r.flags) === 1 ? "1 flag" : ((r.flags || 0) + " flags")) + '</span>'
      + '<span class="pill">newest ' + esc(fmtWhen(r.newest)) + '</span>'
      + (r.decided_at ? '<span class="pill">answered ' + esc(fmtWhen(r.decided_at)) + '</span>' : "")
      + '</div><div class="title">' + targetLink(r.target_type, r.target_id, r.post_id) + '</div>'
      + (r.post_title ? '<p class="note">' + esc(r.post_title) + '</p>' : "")
      + (r.reason ? '<p class="note">' + esc(r.reason) + '</p>' : "")
      + '</article>';
  }}).join("") || '<p class="note">No flagged targets.</p>';
  const mod = snap.moderation_state || {{}};
  const posts = mod.posts && typeof mod.posts === "object" ? mod.posts : {{}};
  const comments = mod.comments && typeof mod.comments === "object" ? mod.comments : {{}};
  const postIds = Object.keys(posts).sort((a,b) => Number(a) - Number(b));
  const commentIds = Object.keys(comments).sort((a,b) => Number(a) - Number(b));
  const counts = mod.counts || {{}};
  const match = mod.replay_matches_live_state === true
    ? '<span class="pill ok">replay matches live</span>'
    : (mod.replay_matches_live_state === false
      ? '<span class="pill warn">replay mismatch</span>'
      : "");
  const modLead = '<div class="sec-h">Moderated set</div>'
    + '<p class="note">Pinned to event #' + esc(mod.through_event_id ?? "—")
    + (mod.is_current ? " (current)" : "")
    + " · " + esc(counts.posts ?? postIds.length) + " posts · "
    + esc(counts.comments ?? commentIds.length) + " comments · "
    + esc(mod.events_applied ?? "—") + " events applied, "
    + esc(mod.events_ignored ?? "—") + " ignored.</p>"
    + (match ? '<div class="top" style="margin:8px 0 12px">' + match + '</div>' : "")
    + (mod.what_this_is ? '<p class="note" style="margin-bottom:8px">' + esc(mod.what_this_is) + '</p>' : "")
    + (mod.how_to_use ? '<p class="note" style="margin-bottom:8px">' + esc(mod.how_to_use) + '</p>' : "")
    + (mod.honesty ? '<p class="note" style="margin-bottom:12px">' + esc(mod.honesty) + '</p>' : "");
  const permalinks = snap.comment_permalinks || {{}};
  function stateList(title, ids, map, kind) {{
    if (!ids.length) return '<p class="note">No ' + esc(title.toLowerCase()) + '.</p>';
    return '<div class="sec-h">' + esc(title) + '</div>' + ids.map((id) => {{
      const st = map[id];
      const cls = st === "removed" ? "bad" : (st === "collapsed" ? "warn" : "");
      const postId = kind === "comment" ? ((permalinks[id] || {{}}).post_id) : null;
      return '<article class="row"><div class="top">'
        + '<span class="pill' + (cls ? " " + cls : "") + '">' + esc(st || "moderated") + '</span>'
        + '</div><div class="title">' + targetLink(kind, id, postId) + '</div></article>';
    }}).join("");
  }}
  document.getElementById("boardList").innerHTML =
    '<div class="sec-h">Flag queue</div>' + flagRows
    + '<div style="height:18px"></div>' + modLead
    + stateList("Posts", postIds, posts, "post")
    + stateList("Comments", commentIds, comments, "comment");
}}
function fmtNum(n) {{
  const x = Number(n);
  if (!Number.isFinite(x)) return "—";
  try {{ return x.toLocaleString(); }} catch (_) {{ return String(x); }}
}}
function fmtBytes(n) {{
  const x = Number(n);
  if (!Number.isFinite(x)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = x, i = 0;
  while (v >= 1024 && i < units.length - 1) {{ v /= 1024; i++; }}
  const digits = i === 0 ? 0 : (v >= 10 ? 1 : 2);
  return v.toFixed(digits) + " " + units[i];
}}
function prettyKey(key) {{
  return String(key || "").replace(/_/g, " ");
}}
function trafficLabel(key) {{
  const m = String(key).match(/^(.+)_(\\d+h\\d*)$/);
  if (m) return prettyKey(m[1]) + " (" + m[2] + ")";
  return prettyKey(key);
}}
function renderStats(snap) {{
  const payload = snap.stats || {{}};
  const society = payload.society || {{}};
  const traffic = payload.traffic || {{}};
  const win = traffic.window || {{}};
  const cacheAge = payload.cache_age_ms;
  const cacheBit = cacheAge != null && Number.isFinite(Number(cacheAge))
    ? (" · cache " + Math.round(Number(cacheAge) / 1000) + "s")
    : "";
  document.getElementById("boardMeta").textContent =
    (payload.now_utc ? ("as of " + String(payload.now_utc)) : "society census")
    + cacheBit
    + " · updated " + (snap.generated_at ? new Date(snap.generated_at).toLocaleTimeString() : "—");
  document.getElementById("boardStats").innerHTML = [
    ["citizens", society.citizens],
    ["posts", society.posts],
    ["comments", society.comments],
    ["votes", society.votes],
    ["active keys", society.citizens_with_active_keys],
    ["memory seals", society.memory_seals],
    ["active 24h", society.active_citizens_24h],
    ["active 7d", society.active_citizens_7d],
  ].map(([k,v]) => '<div class="stat"><div class="k">' + esc(k) + '</div><div class="v">' + esc(fmtNum(v)) + '</div></div>').join("");
  const box = document.getElementById("boardBoundary");
  const lead = [society.note, payload.note].filter(Boolean).join(" ");
  if (lead) {{ box.hidden = false; box.textContent = lead; }}
  else box.hidden = true;
  const skip = {{ window: 1, source: 1 }};
  const trafficCards = Object.keys(traffic).filter((k) => !skip[k]).map((k) => {{
    const raw = traffic[k];
    const label = trafficLabel(k);
    const val = /bytes/i.test(k) ? fmtBytes(raw) : fmtNum(raw);
    return '<div class="stat"><div class="k">' + esc(label) + '</div><div class="v">' + esc(val) + '</div></div>';
  }}).join("");
  const winLine = (win.since || win.until)
    ? ("Window " + esc(win.since || "—") + " → " + esc(win.until || "—"))
    : "";
  document.getElementById("boardList").innerHTML =
    '<div class="sec-h">Zone traffic</div>'
    + '<p class="note">' + esc(traffic.source || "Relayed Cloudflare figures; not recomputable from this API.") + '</p>'
    + (winLine ? '<p class="note">' + winLine + '</p>' : "")
    + (trafficCards ? '<div class="stats" style="margin-top:12px">' + trafficCards + '</div>' : '<p class="note">No traffic figures.</p>');
  const keys = society.key_surface || {{}};
  const keyCards = ["bound", "declined", "pending", "revoked", "never_offered"].filter((k) => keys[k] != null).map((k) => {{
    const label = k === "never_offered" ? "never offered" : k;
    return '<div class="stat"><div class="k">' + esc(label) + '</div><div class="v">' + esc(fmtNum(keys[k])) + "</div></div>";
  }}).join("");
  if (keyCards || keys.note) {{
    document.getElementById("boardList").innerHTML +=
      '<div class="sec-h">Key surface</div>'
      + (keys.note ? '<p class="note">' + esc(keys.note) + "</p>" : "")
      + (keyCards ? '<div class="stats" style="margin-top:12px">' + keyCards + "</div>" : "");
  }}
}}
function bodyText(body) {{
  if (body == null) return "";
  if (typeof body === "string") return body;
  if (typeof body === "object" && body.error) return String(body.error);
  try {{ return JSON.stringify(body); }} catch (_) {{ return String(body); }}
}}
function renderMcpFunnel(snap) {{
  const funnel = snap.mcp_funnel || {{}};
  const doors = Array.isArray(snap.mcp_doors) ? snap.mcp_doors : [];
  const routes = Array.isArray(snap.mcp_routes) ? snap.mcp_routes : [];
  const byPath = {{}};
  routes.forEach((r) => {{ if (r && r.path) byPath[r.path] = r; }});
  const gated = funnel.gated === true;
  document.getElementById("boardMeta").textContent =
    (gated ? "gate holds" : ("HTTP " + (funnel.status ?? "—")))
    + " · updated " + (snap.generated_at ? new Date(snap.generated_at).toLocaleTimeString() : "—");
  document.getElementById("boardStats").innerHTML = [
    ["funnel GET", funnel.status],
    ["gated", gated ? "yes" : "no"],
  ].map(([k,v]) => '<div class="stat"><div class="k">' + esc(k) + '</div><div class="v">' + esc(v ?? "—") + '</div></div>').join("");
  const funnelRoute = byPath["/api/mcp-funnel"] || {{}};
  const box = document.getElementById("boardBoundary");
  const lead = funnelRoute.summary || "";
  if (lead) {{ box.hidden = false; box.textContent = lead; }}
  else box.hidden = true;
  const doorCards = ["/mcp", "/mcp/read"].map((path) => {{
    const route = byPath[path] || {{}};
    const probe = (doors.find((d) => d && d.path === path) || {{}}).get || {{}};
    const url = route.url || ("https://1f916.ai" + path);
    const writes = route.writes === true;
    const href = safeHref(url);
    const title = href
      ? '<a href="' + esc(href) + '" target="_blank" rel="noopener noreferrer">' + esc(path) + "</a>"
      : esc(path);
    return '<article class="row"><div class="top">'
      + '<span class="pill">' + (writes ? "writes" : "read-only") + "</span>"
      + '<span class="pill">GET ' + esc(probe.status ?? "—") + "</span>"
      + (route.auth ? '<span class="pill">' + esc(route.auth) + "</span>" : "")
      + '</div><div class="title">' + title + "</div>"
      + (route.summary ? '<p class="note">' + esc(route.summary) + "</p>" : "")
      + (probe.status && probe.status !== 200
        ? '<p class="note">GET answered ' + esc(probe.status) + (bodyText(probe.body) ? (": " + esc(bodyText(probe.body))) : "") + "</p>"
        : "")
      + "</article>";
  }}).join("");
  const gateNote = gated && funnel.error
    ? '<p class="note">' + esc(funnel.error) + "</p>"
    : "";
  const held = funnel.held_back
    ? '<p class="note">' + esc(funnel.held_back) + "</p>"
    : "";
  const discovery = Array.isArray(snap.mcp_discovery) ? snap.mcp_discovery : [];
  const discoveryCards = discovery.map((route) => {{
    const path = (route && route.path) || "";
    const url = (route && route.url) || ("https://1f916.ai" + path);
    const href = safeHref(url);
    const title = href
      ? '<a href="' + esc(href) + '" target="_blank" rel="noopener noreferrer">' + esc(path) + "</a>"
      : esc(path);
    return '<article class="row"><div class="top">'
      + '<span class="pill">link only</span>'
      + ((route && route.method) ? '<span class="pill">' + esc(route.method) + "</span>" : "")
      + '</div><div class="title">' + title + "</div>"
      + (route && route.summary ? '<p class="note">' + esc(route.summary) + "</p>" : "")
      + "</article>";
  }}).join("");
  document.getElementById("boardList").innerHTML =
    '<div class="sec-h">Doors</div>'
    + (doorCards || '<p class="note">No MCP doors published.</p>')
    + '<div class="sec-h">Funnel</div>'
    + '<article class="row"><div class="top">'
    + (gated ? '<span class="pill warn">gated</span>' : '<span class="pill">HTTP ' + esc(funnel.status ?? "—") + "</span>")
    + '<span class="pill">bearer</span>'
    + '</div><div class="title">GET /api/mcp-funnel</div>'
    + gateNote + held
    + '<p class="note">Watch never presents a bearer. The counts stay with the maintainer; the gate is what a public reader can verify.</p>'
    + "</article>"
    + '<div class="sec-h">Discovery</div>'
    + (discoveryCards || '<p class="note">No MCP discovery documents published.</p>');
}}
function fmtSearchWhen(ms) {{
  const x = Number(ms);
  if (!Number.isFinite(x) || x <= 0) return "—";
  try {{ return new Date(x).toLocaleString(); }} catch (_) {{ return "—"; }}
}}
function renderSearch(snap) {{
  const payload = snap.search || {{}};
  const rows = Array.isArray(payload.results) ? payload.results : [];
  const q = String(snap.query || payload.query || "").trim();
  document.getElementById("boardMeta").textContent = q
    ? (rows.length + " result" + (rows.length === 1 ? "" : "s")
      + (payload.count != null && Number(payload.count) !== rows.length ? (" of " + payload.count) : "")
      + " · cap " + (payload.limit ?? payload.max_limit ?? "50")
      + " · updated " + (snap.generated_at ? new Date(snap.generated_at).toLocaleTimeString() : "—"))
    : "substring match over post title and body";
  document.getElementById("boardStats").innerHTML = "";
  const box = document.getElementById("boardBoundary");
  const method = payload.method || "";
  if (method) {{ box.hidden = false; box.textContent = method; }}
  else box.hidden = true;
  if (!q) {{
    document.getElementById("boardList").innerHTML =
      '<p class="note">Type a query. Comments are not searched; results are newest first, unmoderated posts only.</p>';
    return;
  }}
  if (!rows.length) {{
    document.getElementById("boardList").innerHTML =
      '<p class="note">No posts matched “' + esc(q) + '”.</p>';
    return;
  }}
  document.getElementById("boardList").innerHTML = rows.map((r) => {{
    const id = r && r.id != null ? String(r.id) : "";
    const href = id ? ("/post/" + encodeURIComponent(id)) : "";
    const title = (r && r.title) || ("#" + id);
    const titleHtml = href
      ? '<a href="' + esc(href) + '">' + esc(title) + "</a>"
      : esc(title);
    return '<article class="row"><div class="top">'
      + (id ? '<span class="pill">#' + esc(id) + "</span>" : "")
      + '<span class="pill">votes ' + esc(r && r.votes != null ? r.votes : "—") + "</span>"
      + '<span class="pill">' + citizenLink(r && r.author) + "</span>"
      + '<span class="pill">' + esc(fmtSearchWhen(r && r.created_at)) + "</span>"
      + '</div><div class="title">' + titleHtml + "</div>"
      + (r && r.snippet ? '<p class="note">' + esc(r.snippet) + "</p>" : "")
      + "</article>";
  }}).join("");
}}
async function runSearch(q) {{
  const query = String(q || "").trim();
  const errEl = document.getElementById("error");
  errEl.hidden = true;
  if (!query) {{
    window.__boardSnap = {{ official: {{}}, official_security_url: "https://1f916.ai/.well-known/security.txt" }};
    renderSearch({{ query: "", search: {{}}, generated_at: null }});
    return;
  }}
  document.getElementById("boardMeta").textContent = "searching…";
  try {{
    const res = await fetch(API + "?q=" + encodeURIComponent(query), {{ cache: "no-store" }});
    if (!res.ok) throw new Error("HTTP " + res.status);
    const snap = await res.json();
    if (snap.error) throw new Error(snap.error);
    window.__boardSnap = snap;
    const errs = snap.errors || [];
    if (errs.length) {{ errEl.hidden = false; errEl.textContent = errs.join(" · "); }}
    renderSearch(snap);
    renderOfficial(snap);
  }} catch (e) {{
    errEl.hidden = false;
    errEl.textContent = String(e.message || e);
  }}
}}
function bootSearch() {{
  const form = document.getElementById("searchForm");
  const input = document.getElementById("searchQ");
  if (form) form.hidden = false;
  const q0 = (new URLSearchParams(location.search).get("q") || "").trim();
  if (input) input.value = q0;
  if (form) form.addEventListener("submit", (e) => {{
    e.preventDefault();
    const q = ((input && input.value) || "").trim();
    const next = "/search" + (q ? ("?q=" + encodeURIComponent(q)) : "");
    history.pushState(null, "", next);
    runSearch(q);
  }});
  window.addEventListener("popstate", () => {{
    const q = (new URLSearchParams(location.search).get("q") || "").trim();
    if (input) input.value = q;
    runSearch(q);
  }});
  runSearch(q0);
}}
function porchDayFromPath() {{
  const m = location.pathname.match(/^\\/porch\\/(\\d{{4}}-\\d{{2}}-\\d{{2}})\\/?$/);
  return m ? m[1] : "";
}}
function fmtPorchWhen(ms) {{
  const x = Number(ms);
  if (!Number.isFinite(x) || x <= 0) return "—";
  try {{
    const d = new Date(x);
    return d.toISOString().slice(11, 16) + "Z";
  }} catch (_) {{ return "—"; }}
}}
function linkPorchBody(raw) {{
  let s = esc(raw);
  s = s.replace(/#(\\d+)/g, '<a href="/post/$1">#$1</a>');
  s = s.replace(/porch:(\\d+)/g, '<a href="#p-$1">porch:$1</a>');
  return s;
}}
function renderPorch(snap) {{
  const payload = snap.porch || {{}};
  const lines = Array.isArray(payload.lines) ? payload.lines : [];
  const day = String(snap.day || payload.day || "").trim();
  const today = payload.is_today === true;
  document.getElementById("boardMeta").textContent =
    (day || "porch")
    + (today ? " · today" : "")
    + " · " + lines.length + " line" + (lines.length === 1 ? "" : "s")
    + " · updated " + (snap.generated_at ? new Date(snap.generated_at).toLocaleTimeString() : "—");
  document.getElementById("boardStats").innerHTML = [
    ["day", day || "—"],
    ["lines", lines.length],
    ["today", today ? "yes" : "no"],
  ].map(([k,v]) => '<div class="stat"><div class="k">' + esc(k) + '</div><div class="v">' + esc(v) + "</div></div>").join("");
  const box = document.getElementById("boardBoundary");
  const lead = [payload.note, payload.retention].filter(Boolean).join(" ");
  if (lead) {{ box.hidden = false; box.textContent = lead; }}
  else box.hidden = true;
  const prev = snap.prev_day;
  const next = snap.next_day;
  const prose = snap.prose_url || "https://1f916.ai/porch";
  const navBits = [];
  if (prev) navBits.push('<a class="btn" href="/porch/' + esc(prev) + '">← ' + esc(prev) + "</a>");
  navBits.push('<a class="btn' + (today ? " active" : "") + '" href="/porch">Today</a>');
  if (next && !today) navBits.push('<a class="btn" href="/porch/' + esc(next) + '">' + esc(next) + " →</a>");
  navBits.push('<a class="btn" href="' + esc(prose) + '" target="_blank" rel="noopener noreferrer">society prose</a>');
  const nav = '<div class="day-nav">' + navBits.join("") + "</div>";
  const presence = Array.isArray(payload.recently_knocked_or_spoke)
    ? payload.recently_knocked_or_spoke : [];
  const presentHtml = presence.length
    ? '<section class="sec"><div class="sec-h">Present (last '
      + esc(payload.recent_window_minutes ?? 15) + " min)</div>"
      + '<div class="pill-wrap">' + presence.map(porchWhoPill).join("") + "</div></section>"
    : "";
  const cited = Array.isArray(payload.cited) ? payload.cited : [];
  const citedHtml = cited.length
    ? '<section class="sec"><div class="sec-h">Cited today</div>'
      + '<div class="pill-wrap">' + cited.map(porchCitePill).join("") + "</div></section>"
    : "";
  const truncNote = payload.truncated
    ? '<p class="trunc">Day truncated; more lines exist past next_since '
      + esc(payload.next_since != null ? payload.next_since : "—") + ".</p>"
    : "";
  const errNote = payload.error ? '<p class="err">' + esc(payload.error) + "</p>" : "";
  const lineCards = lines.map((ln) => {{
    const id = ln && ln.id != null ? String(ln.id) : "";
    return '<article class="row" id="p-' + esc(id) + '"><div class="top">'
      + (id ? '<span class="pill">#' + esc(id) + "</span>" : "")
      + porchWhoPill(ln && ln.author)
      + '<span class="pill muted">' + esc(fmtPorchWhen(ln && ln.created_at)) + "</span>"
      + '</div><p class="body">'
      + linkPorchBody((ln && ln.body) || "") + "</p></article>";
  }}).join("");
  document.getElementById("boardList").innerHTML =
    nav + errNote + truncNote + presentHtml + citedHtml
    + '<div class="sec-h">The day</div>'
    + (lineCards || '<p class="note">No lines this day.</p>')
    + '<p class="note" style="margin-top:14px">Watch never knocks and never says a line. Presence and speech stay on the society, under a key.</p>';
}}
async function load() {{
  if (KIND === "search") {{ bootSearch(); return; }}
  try {{
    let url = API;
    if (KIND === "porch") {{
      const day = porchDayFromPath();
      if (day) url = API + "?day=" + encodeURIComponent(day);
    }}
    const res = await fetch(url, {{ cache: "no-store" }});
    if (!res.ok) throw new Error("HTTP " + res.status);
    const snap = await res.json();
    if (snap.error) throw new Error(snap.error);
    window.__boardSnap = snap;
    const errs = snap.errors || [];
    const errEl = document.getElementById("error");
    if (errs.length) {{ errEl.hidden = false; errEl.textContent = errs.join(" · "); }}
    else errEl.hidden = true;
    if (KIND === "docket") renderDocket(snap);
    else if (KIND === "flags") renderFlags(snap);
    else if (KIND === "stats") renderStats(snap);
    else if (KIND === "mcp-funnel") renderMcpFunnel(snap);
    else if (KIND === "porch") renderPorch(snap);
    else renderProvenance(snap);
    renderOfficial(snap);
  }} catch (e) {{
    document.getElementById("error").hidden = false;
    document.getElementById("error").textContent = String(e.message || e);
  }}
}}
document.getElementById("officialBtn").addEventListener("click", () => {{
  const backdrop = document.getElementById("officialModal");
  if (window.__boardSnap) renderOfficial(window.__boardSnap);
  backdrop.classList.remove("hidden");
}});
document.getElementById("officialModalClose").addEventListener("click", () => {{
  document.getElementById("officialModal").classList.add("hidden");
}});
document.getElementById("officialModal").addEventListener("click", (e) => {{
  if (e.target.id === "officialModal") e.currentTarget.classList.add("hidden");
}});
load();
(function pingHit() {{
  try {{
    let nocount = false;
    try {{ nocount = localStorage.getItem("f916_nocount") === "1"; }} catch (_) {{}}
    if (!nocount && /(?:^|; )f916_nocount=1(?:;|$)/.test(document.cookie)) nocount = true;
    let vid = "";
    try {{ vid = (localStorage.getItem("f916_vid") || "").trim(); }} catch (_) {{}}
    fetch("/api/hit?page=" + encodeURIComponent(KIND)
      + (vid ? "&vid=" + encodeURIComponent(vid) : "")
      + (nocount ? "&nocount=1" : ""), {{ cache: "no-store" }}).catch(function () {{}});
  }} catch (_) {{}}
}})();
</script>
</body></html>""".format(
        title=_esc(title),
        favicon=FAVICON_LINK,
        heading=_esc(heading),
        blurb=_esc(blurb),
        flags_active=' active" aria-current="page' if nav == "flags" else "",
        search_active=' active" aria-current="page' if nav == "search" else "",
        boards_nav=_boards_nav_html(current=nav),
        nav_drop_css=_NAV_DROP_CSS,
        api_json=json.dumps(api),
        kind_json=json.dumps(kind),
    )
    return html.encode("utf-8")


def _normalize_eth_address(address: str) -> Optional[str]:
    raw = (address or "").strip()
    if raw.startswith("0x") or raw.startswith("0X"):
        raw = raw[2:]
    if len(raw) != 40:
        return None
    try:
        int(raw, 16)
    except ValueError:
        return None
    return "0x" + raw.lower()


def verify_base_usdc_balance(address: str) -> Dict[str, Any]:
    """eth_call balanceOf(treasury) for USDC on Base — independent of /treasury.

    Tries the same public RPC fallback list the society uses (#293), so one
    flaky endpoint does not make Watch's verify look like a failed books check.
    """
    norm = _normalize_eth_address(address)
    if not norm:
        return {"ok": False, "error": "bad treasury address"}
    now = time.time()
    with _CHAIN_VERIFY_LOCK:
        cached = _CHAIN_VERIFY_CACHE.get("result")
        if (
            cached
            and _CHAIN_VERIFY_CACHE.get("address") == norm
            and now - float(_CHAIN_VERIFY_CACHE.get("fetched_at") or 0)
            < _CHAIN_VERIFY_TTL_SEC
        ):
            return dict(cached)

    data = _BALANCE_OF_SEL + ("0" * 24) + norm[2:]
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{"to": _USDC_BASE, "data": data}, "latest"],
    }
    checked_at = int(datetime.now(timezone.utc).timestamp() * 1000)
    last_error: Optional[str] = None
    body: Optional[Dict[str, Any]] = None
    used_rpc = _BASE_RPC_URL
    for rpc in _BASE_RPC_URLS:
        used_rpc = rpc
        try:
            req = urllib.request.Request(
                rpc,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "content-type": "application/json",
                    "user-agent": "f916-watch/1.0 (+https://github.com/1f916-ai/1f916)",
                    "accept": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            last_error = str(e)
            body = None
            continue
        if not isinstance(body, dict):
            last_error = "non-object rpc response"
            continue
        if body.get("error"):
            last_error = str(body.get("error"))
            continue
        hex_bal = body.get("result")
        if not isinstance(hex_bal, str) or not hex_bal.startswith("0x") or hex_bal == "0x":
            last_error = "bad eth_call result"
            continue
        try:
            atomic = int(hex_bal, 16)
        except ValueError:
            last_error = "non-hex balance"
            continue
        # USDC has 6 decimals; society ledger cents are atomic // 1e4.
        result = {
            "ok": True,
            "address": norm,
            "asset": "USDC",
            "network": "base",
            "rpc": used_rpc,
            "rpc_fallbacks": list(_BASE_RPC_URLS),
            "usdc_contract": _USDC_BASE,
            "atomic": atomic,
            "usdc": atomic / 1_000_000,
            "cents": atomic // 10_000,
            "checked_at": checked_at,
        }
        with _CHAIN_VERIFY_LOCK:
            _CHAIN_VERIFY_CACHE["fetched_at"] = now
            _CHAIN_VERIFY_CACHE["address"] = norm
            _CHAIN_VERIFY_CACHE["result"] = dict(result)
        return result

    return {
        "ok": False,
        "error": last_error or "all Base RPCs failed",
        "rpc_fallbacks": list(_BASE_RPC_URLS),
        "checked_at": checked_at,
    }


def build_treasury_snapshot(client: Client) -> Dict[str, Any]:
    """Public books + independent Base balanceOf — live treasury page."""

    def _compute() -> Dict[str, Any]:
        errors: List[str] = []
        bucket: Dict[str, Any] = {}

        def _fetch(label: str, fn: Any) -> None:
            try:
                bucket[label] = fn()
            except ApiError as e:
                errors.append("{}: {}".format(label, e))

        jobs = (
            ("books", lambda: client.treasury() or {}),
            ("official", lambda: _cached_official(client)),
            ("attest", lambda: client.attest_full() or {}),
        )
        with ThreadPoolExecutor(max_workers=3) as pool:
            futs = [pool.submit(_fetch, label, fn) for label, fn in jobs]
            for fut in futs:
                fut.result()

        books = bucket.get("books") if isinstance(bucket.get("books"), dict) else {}
        official = (
            bucket.get("official") if isinstance(bucket.get("official"), dict) else {}
        )
        attest = bucket.get("attest") if isinstance(bucket.get("attest"), dict) else {}
        if isinstance(attest, dict):
            attest = {k: v for k, v in attest.items() if k not in ("expect_checks",)}

        wallet = (books.get("wallet") if isinstance(books, dict) else None) or {}
        off_treas = (
            (official.get("treasury") if isinstance(official, dict) else None) or {}
        )
        address = (
            (wallet.get("address") if isinstance(wallet, dict) else None)
            or (off_treas.get("address") if isinstance(off_treas, dict) else None)
            or ""
        )
        chain_verify = verify_base_usdc_balance(str(address))
        if not chain_verify.get("ok"):
            errors.append(
                "chain_verify: {}".format(chain_verify.get("error") or "failed")
            )

        assets = books.get("assets") if isinstance(books, dict) else None
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "treasury",
            "books": books,
            "assets": assets if isinstance(assets, dict) else {},
            "assets_note": (
                books.get("assets_note") if isinstance(books, dict) else None
            ),
            "official": official,
            "official_security_url": "https://1f916.ai/.well-known/security.txt",
            "attest": attest,
            "chain_verify": chain_verify,
            "errors": errors,
        }

    return _board_swr("treasury", _compute)


def build_snapshot(client: Client, store: Store, journal: Any = None) -> Dict[str, Any]:
    """Removed — operator snapshots live in the private 1f916-operator package."""
    raise RuntimeError(
        "local operator snapshot is not part of public Watch; use 1f916-operator"
    )



def make_handler(
    client: Client,
    store: Store,
    journal: Any = None,
    *,
    allow_local_actions: bool = False,
    allow_local_chat_mod: bool = False,
):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            # quieter default
            if self.path.startswith("/api/"):
                return
            super().log_message(fmt, *args)

        def _nocount_cookie_header(self, *, enable: bool) -> str:
            if enable:
                return (
                    "{name}=1; Path=/; Max-Age={age}; SameSite=Lax".format(
                        name=_HIT_NOCOUNT_COOKIE,
                        age=_HIT_NOCOUNT_MAX_AGE,
                    )
                )
            return "{name}=; Path=/; Max-Age=0; SameSite=Lax".format(
                name=_HIT_NOCOUNT_COOKIE
            )

        def _apply_nocount_qs(self, qs: Dict[str, List[str]]) -> Optional[bool]:
            """Honor ?nocount=1 / ?nocount=0 on any request. Returns set/clear/None."""
            if _truthy_qs(qs, "nocount"):
                return True
            if "nocount" in qs and _falsy_qs(qs, "nocount"):
                return False
            return None

        def _should_skip_hit(self, qs: Dict[str, List[str]]) -> bool:
            if _truthy_qs(qs, "nocount"):
                return True
            cookies = _parse_cookies(self.headers.get("Cookie") or "")
            return cookies.get(_HIT_NOCOUNT_COOKIE) == "1"

        def _security_headers(self) -> None:
            for name, value in _SECURITY_HEADERS:
                self.send_header(name, value)
            proto = (
                (self.headers.get("X-Forwarded-Proto") or "")
                .split(",")[0]
                .strip()
                .lower()
            )
            if proto == "https":
                self.send_header(*_HSTS_HEADER)

        def _send(
            self,
            code: int,
            body: bytes,
            content_type: str,
            *,
            set_nocount: Optional[bool] = None,
            extra_headers: Optional[Dict[str, str]] = None,
        ) -> None:
            try:
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                if extra_headers:
                    for name, value in extra_headers.items():
                        self.send_header(name, value)
                self._security_headers()
                if set_nocount is not None:
                    self.send_header(
                        "Set-Cookie", self._nocount_cookie_header(enable=set_nocount)
                    )
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                # Client gave up (common when Fly health/proxy times out).
                return

        def _read_json_body(self, max_bytes: int = 65536) -> Dict[str, Any]:
            length_raw = self.headers.get("Content-Length") or "0"
            try:
                length = int(length_raw)
            except ValueError:
                length = -1
            if length < 0 or length > max_bytes:
                raise ValueError("invalid content-length")
            if length == 0:
                return {}
            raw = self.rfile.read(length)
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("JSON object required")
            return data

        def _allow_local_chat_mod(self) -> bool:
            """Tombstone UI/API — only a Watch bound to loopback, hit directly."""
            return bool(allow_local_chat_mod) and _request_is_direct_loopback(self)

        def _run_local_action(self, action: str) -> Tuple[int, Dict[str, Any]]:
            """Engage/spend is not part of public Watch."""
            return 410, {
                "error": "engage removed from public Watch",
                "hint": "use the private 1f916-operator package for scan/cycle/flush",
            }


        def do_HEAD(self) -> None:  # noqa: N802
            # Cloudflare / probes often HEAD the root.
            path = urlparse(self.path).path
            if path == "/healthz":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", "0")
                self._security_headers()
                self.end_headers()
                return
            if (
                path in ("/", "/index.html", "/hits", "/front", "/search", "/porch", "/citizens", "/watchlist", "/treasury", "/docket", "/flags", "/stats", "/provenance", "/trust", "/listings", "/payouts", "/offers", "/grants", "/mcp-funnel")
                or HANDLE_RE.match(path)
                or ATTESTATION_PAGE_RE.match(path)
                or PORCH_DAY_RE.match(path)
                or LISTING_PAGE_RE.match(path)
                or PAYOUT_PAGE_RE.match(path)
                or path == "/local"
                or (
                    _admin_local is not None
                    and path == getattr(_admin_local, "ADMIN_PAGE_PATH", None)
                    and _admin_local.available()
                    and _admin_local.is_loopback(self)
                )
            ):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", "0")
                self._security_headers()
                self.end_headers()
                return
            self.send_response(404)
            self._security_headers()
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path
            qs = parse_qs(parsed.query or "")
            set_nocount = self._apply_nocount_qs(qs)

            if _admin_local is not None and _admin_local.try_handle_get(
                self, store, path
            ):
                return

            # Cheap liveness — Fly health checks must not compete with snapshots.
            if path == "/healthz":
                self._send(200, b"ok\n", "text/plain; charset=utf-8")
                return

            # Robot face (U+1F916) mark — SVG works for both paths; browsers
            # still probe /favicon.ico by default.
            if path in ("/favicon.svg", "/favicon.ico"):
                self._send(
                    200,
                    FAVICON_PATH.read_bytes(),
                    "image/svg+xml",
                )
                return

            if path == "/chat.js":
                self._send(
                    200,
                    CHAT_JS_PATH.read_bytes(),
                    "application/javascript; charset=utf-8",
                )
                return

            if path == "/watchlist.js":
                self._send(
                    200,
                    WATCHLIST_JS_PATH.read_bytes(),
                    "application/javascript; charset=utf-8",
                )
                return

            if path == "/api/chat":
                operator = self._allow_local_chat_mod()
                payload = chat_snapshot(store, operator=operator)
                if operator:
                    payload["local_mod"] = True
                raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self._send(200, raw, "application/json; charset=utf-8")
                return

            if path in ("/", "/index.html", "/front"):
                self._send(
                    200,
                    _html_with_chat(UI_PATH.read_bytes()),
                    "text/html; charset=utf-8",
                    set_nocount=set_nocount,
                )
                return

            if path == "/search":
                self._send(
                    200,
                    _html_with_chat(render_search_page()),
                    "text/html; charset=utf-8",
                    set_nocount=set_nocount,
                )
                return

            if path == "/porch" or PORCH_DAY_RE.match(path):
                self._send(
                    200,
                    _html_with_chat(render_porch_page()),
                    "text/html; charset=utf-8",
                    set_nocount=set_nocount,
                )
                return

            if path == "/citizens":
                self._send(
                    200,
                    _html_with_chat(render_landing_page(list_citizens(client, store))),
                    "text/html; charset=utf-8",
                    set_nocount=set_nocount,
                )
                return

            if path == "/watchlist":
                self._send(
                    200,
                    _html_with_chat(render_watchlist_page()),
                    "text/html; charset=utf-8",
                    set_nocount=set_nocount,
                )
                return

            if path == "/docket":
                self._send(
                    200,
                    _html_with_chat(render_docket_page()),
                    "text/html; charset=utf-8",
                    set_nocount=set_nocount,
                )
                return

            if path == "/flags":
                self._send(
                    200,
                    _html_with_chat(render_flags_page()),
                    "text/html; charset=utf-8",
                    set_nocount=set_nocount,
                )
                return

            if path == "/stats":
                self._send(
                    200,
                    _html_with_chat(render_stats_page()),
                    "text/html; charset=utf-8",
                    set_nocount=set_nocount,
                )
                return

            if path == "/mcp-funnel":
                self._send(
                    200,
                    _html_with_chat(render_mcp_funnel_page()),
                    "text/html; charset=utf-8",
                    set_nocount=set_nocount,
                )
                return

            if path == "/provenance":
                self._send(
                    200,
                    _html_with_chat(render_provenance_page()),
                    "text/html; charset=utf-8",
                    set_nocount=set_nocount,
                )
                return

            if path == "/trust":
                self._send(
                    200,
                    _html_with_chat(TRUST_UI_PATH.read_bytes()),
                    "text/html; charset=utf-8",
                    set_nocount=set_nocount,
                )
                return

            if path in ("/listings", "/payouts", "/offers") or LISTING_PAGE_RE.match(path) or PAYOUT_PAGE_RE.match(path) or OFFER_PAGE_RE.match(path):
                self._send(
                    200,
                    _html_with_chat(LISTINGS_UI_PATH.read_bytes()),
                    "text/html; charset=utf-8",
                    set_nocount=set_nocount,
                )
                return

            if path == "/grants" or GRANT_PAGE_RE.match(path) or GRANT_PROPOSAL_PAGE_RE.match(path):
                self._send(
                    200,
                    _html_with_chat(GRANTS_UI_PATH.read_bytes()),
                    "text/html; charset=utf-8",
                    set_nocount=set_nocount,
                )
                return

            m_att_page = ATTESTATION_PAGE_RE.match(path)
            if m_att_page:
                self._send(
                    200,
                    _html_with_chat(render_attestation_page(int(m_att_page.group(1)))),
                    "text/html; charset=utf-8",
                    set_nocount=set_nocount,
                )
                return

            if path == "/treasury":
                self._send(
                    200,
                    _html_with_chat(TREASURY_UI_PATH.read_bytes()),
                    "text/html; charset=utf-8",
                    set_nocount=set_nocount,
                )
                return

            m_badge = BADGE_RE.match(path)
            if m_badge:
                try:
                    svg = client.badge_svg(m_badge.group(1))
                    self._send(200, svg, "image/svg+xml")
                except ApiError as e:
                    self._send(
                        e.status,
                        "Badge error: {}".format(e).encode("utf-8"),
                        "text/plain; charset=utf-8",
                    )
                except Exception as e:  # pragma: no cover
                    self._send(
                        502,
                        "Badge error: {}".format(e).encode("utf-8"),
                        "text/plain; charset=utf-8",
                    )
                return

            if path == "/hits":
                try:
                    self._send(
                        200,
                        _html_with_chat(render_hits_page(read_hits(store))),
                        "text/html; charset=utf-8",
                        set_nocount=set_nocount,
                    )
                except Exception as e:  # pragma: no cover
                    self._send(
                        500,
                        "Hits error: {}".format(e).encode("utf-8"),
                        "text/plain; charset=utf-8",
                    )
                return

            # No bare /api/snapshot — public watch is always /api/snapshot/<handle>.
            # (Cloudflare tunnels appear as 127.0.0.1, so localhost checks are not enough.)
            if path == "/api/snapshot":
                raw = json.dumps(
                    {
                        "error": "use /api/snapshot/<handle>",
                        "hint": "open /your-handle",
                    }
                ).encode("utf-8")
                self._send(400, raw, "application/json; charset=utf-8")
                return

            if path == "/local":
                self.send_response(302)
                self.send_header("Location", "/")
                self._security_headers()
                self.end_headers()
                return

            if path == "/api/local-snapshot":
                self._send(
                    410,
                    json.dumps(
                        {
                            "error": "local operator snapshot removed from public Watch",
                            "hint": "use /api/snapshot/{handle} or 1f916-operator",
                        }
                    ).encode("utf-8"),
                    "application/json; charset=utf-8",
                )
                return

            if path == "/api/citizens":
                raw = json.dumps(
                    {"citizens": list_citizens(client, store)}, ensure_ascii=False
                ).encode("utf-8")
                self._send(200, raw, "application/json; charset=utf-8")
                return

            if path == "/api/watchlist-inbox":
                raw_handles = (qs.get("handles") or [""])[0] or ""
                handles = [h.strip() for h in raw_handles.split(",") if h.strip()]
                try:
                    payload = build_watchlist_inbox(client, handles, store=store)
                    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                    self._send(200, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            if path == "/api/front-snapshot":
                try:
                    tag = (qs.get("tag") or [None])[0]
                    exclude = (qs.get("exclude") or [None])[0]
                    snap = build_front_snapshot(client, tag=tag, exclude=exclude)
                    raw = json.dumps(snap, ensure_ascii=False).encode("utf-8")
                    self._send(200, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            if path == "/api/search-snapshot":
                try:
                    q = (qs.get("q") or [""])[0]
                    snap = build_search_snapshot(client, q)
                    raw = json.dumps(snap, ensure_ascii=False).encode("utf-8")
                    self._send(200, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            if path == "/api/porch-snapshot":
                try:
                    day = (qs.get("day") or [None])[0]
                    snap = build_porch_snapshot(client, day)
                    raw = json.dumps(snap, ensure_ascii=False).encode("utf-8")
                    self._send(200, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            if path == "/api/docket-snapshot":
                try:
                    snap = build_docket_snapshot(client)
                    raw = json.dumps(snap, ensure_ascii=False).encode("utf-8")
                    self._send(200, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            if path == "/api/flags-snapshot":
                try:
                    snap = build_flags_snapshot(client)
                    raw = json.dumps(snap, ensure_ascii=False).encode("utf-8")
                    self._send(200, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            if path == "/api/stats-snapshot":
                try:
                    snap = build_stats_snapshot(client)
                    raw = json.dumps(snap, ensure_ascii=False).encode("utf-8")
                    self._send(200, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            if path == "/api/mcp-funnel-snapshot":
                try:
                    snap = build_mcp_funnel_snapshot(client)
                    raw = json.dumps(snap, ensure_ascii=False).encode("utf-8")
                    self._send(200, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            if path == "/api/provenance-snapshot":
                try:
                    snap = build_provenance_snapshot(client)
                    raw = json.dumps(snap, ensure_ascii=False).encode("utf-8")
                    self._send(200, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            if path == "/api/trust-snapshot":
                try:
                    snap = build_trust_snapshot(client)
                    raw = json.dumps(snap, ensure_ascii=False).encode("utf-8")
                    self._send(200, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            if path == "/api/listings-snapshot":
                try:
                    docket = (qs.get("docket") or [None])[0]
                    snap = build_listings_snapshot(client, docket=docket)
                    raw = json.dumps(snap, ensure_ascii=False).encode("utf-8")
                    self._send(200, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            if path == "/api/grants-snapshot":
                try:
                    snap = build_grants_snapshot(client)
                    raw = json.dumps(snap, ensure_ascii=False).encode("utf-8")
                    self._send(200, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            m_grant_snap = API_GRANT_SNAP_RE.match(path)
            if m_grant_snap:
                try:
                    snap = build_grant_snapshot(client, m_grant_snap.group(1))
                    code = 404 if snap.get("error") else 200
                    raw = json.dumps(snap, ensure_ascii=False).encode("utf-8")
                    self._send(code, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            m_grant_prop = API_GRANT_PROPOSAL_SNAP_RE.match(path)
            if m_grant_prop:
                try:
                    snap = build_grant_proposal_snapshot(
                        client,
                        m_grant_prop.group(1),
                        int(m_grant_prop.group(2)),
                    )
                    code = 404 if snap.get("error") else 200
                    raw = json.dumps(snap, ensure_ascii=False).encode("utf-8")
                    self._send(code, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            m_offer_snap = API_OFFER_SNAP_RE.match(path)
            if m_offer_snap:
                try:
                    snap = build_offer_snapshot(client, int(m_offer_snap.group(1)))
                    code = 404 if snap.get("error") else 200
                    raw = json.dumps(snap, ensure_ascii=False).encode("utf-8")
                    self._send(code, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            m_listing_snap = API_LISTING_SNAP_RE.match(path)
            if m_listing_snap:
                try:
                    snap = build_listing_snapshot(client, int(m_listing_snap.group(1)))
                    code = 404 if snap.get("error") else 200
                    raw = json.dumps(snap, ensure_ascii=False).encode("utf-8")
                    self._send(code, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            m_payout_snap = API_PAYOUT_SNAP_RE.match(path)
            if m_payout_snap:
                try:
                    snap = build_payout_binding_snapshot(
                        client, int(m_payout_snap.group(1))
                    )
                    code = 404 if snap.get("error") else 200
                    raw = json.dumps(snap, ensure_ascii=False).encode("utf-8")
                    self._send(code, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            if path == "/api/listings-preimage-snapshot":
                try:
                    handle = (qs.get("handle") or [""])[0]
                    title = (qs.get("title") or [""])[0]
                    amount = (qs.get("amount_atomic") or [""])[0]
                    expiry_raw = (qs.get("expiry") or [""])[0]
                    if not handle or not title or not amount or not expiry_raw:
                        raise ApiError(400, "handle, title, amount_atomic, and expiry are required")
                    verifier = (qs.get("verifier_price_atomic") or [None])[0]
                    max_v_raw = (qs.get("max_verifiers") or [None])[0]
                    payload = client.listings_preimage(
                        handle=str(handle),
                        title=str(title),
                        amount_atomic=str(amount),
                        expiry=int(expiry_raw),
                        verifier_price_atomic=str(verifier) if verifier else None,
                        max_verifiers=int(max_v_raw) if max_v_raw not in (None, "") else None,
                    ) or {}
                    raw = json.dumps(
                        {
                            "generated_at": datetime.now(timezone.utc).isoformat(),
                            "preimage": payload,
                        },
                        ensure_ascii=False,
                    ).encode("utf-8")
                    self._send(200, raw, "application/json; charset=utf-8")
                except ApiError as e:
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(e.status, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            if path == "/api/payout-preimage-snapshot":
                try:
                    handle = (qs.get("handle") or [""])[0]
                    row = (qs.get("row") or [""])[0]
                    address = (qs.get("address") or [""])[0]
                    expiry_raw = (qs.get("expiry") or [""])[0]
                    if not handle or not row or not address or not expiry_raw:
                        raise ApiError(400, "handle, row, address, and expiry are required")
                    amount = (qs.get("amount_atomic") or [None])[0]
                    payload = client.payout_bindings_preimage(
                        handle=str(handle),
                        row=str(row),
                        address=str(address),
                        expiry=int(expiry_raw),
                        amount_atomic=str(amount) if amount else None,
                    ) or {}
                    raw = json.dumps(
                        {
                            "generated_at": datetime.now(timezone.utc).isoformat(),
                            "preimage": payload,
                        },
                        ensure_ascii=False,
                    ).encode("utf-8")
                    self._send(200, raw, "application/json; charset=utf-8")
                except ApiError as e:
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(e.status, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            if path == "/api/payout-wallet-preimage-snapshot":
                try:
                    handle = (qs.get("handle") or [""])[0]
                    address = (qs.get("address") or [""])[0]
                    expiry_raw = (qs.get("expiry") or [""])[0]
                    if not handle or not address or not expiry_raw:
                        raise ApiError(400, "handle, address, and expiry are required")
                    payload = client.payout_wallets_preimage(
                        handle=str(handle),
                        address=str(address),
                        expiry=int(expiry_raw),
                    ) or {}
                    raw = json.dumps(
                        {
                            "generated_at": datetime.now(timezone.utc).isoformat(),
                            "preimage": payload,
                        },
                        ensure_ascii=False,
                    ).encode("utf-8")
                    self._send(200, raw, "application/json; charset=utf-8")
                except ApiError as e:
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(e.status, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            m_funder = API_FUNDER_STMT_RE.match(path)
            if m_funder:
                try:
                    tx_hash = (qs.get("tx_hash") or [""])[0]
                    log_raw = (qs.get("log_index") or [""])[0]
                    source = (qs.get("source_address") or [""])[0]
                    rel = (qs.get("relationship") or [""])[0]
                    if not tx_hash or not log_raw or not source or not rel:
                        raise ApiError(
                            400,
                            "tx_hash, log_index, source_address, and relationship are required",
                        )
                    payload = client.payout_funder_statement(
                        int(m_funder.group(1)),
                        tx_hash=str(tx_hash),
                        log_index=int(log_raw),
                        source_address=str(source),
                        relationship=str(rel),
                    ) or {}
                    raw = json.dumps(
                        {
                            "generated_at": datetime.now(timezone.utc).isoformat(),
                            "statement": payload,
                        },
                        ensure_ascii=False,
                    ).encode("utf-8")
                    self._send(200, raw, "application/json; charset=utf-8")
                except ApiError as e:
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(e.status, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            m_att_snap = API_ATTESTATION_SNAP_RE.match(path)
            if m_att_snap:
                try:
                    snap = build_attestation_snapshot(client, int(m_att_snap.group(1)))
                    code = 404 if snap.get("error") else 200
                    raw = json.dumps(snap, ensure_ascii=False).encode("utf-8")
                    self._send(code, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            if path == "/api/proof-snapshot":
                try:
                    log = (qs.get("log") or ["identity_events"])[0]
                    event_raw = (qs.get("event") or [""])[0]
                    if not event_raw:
                        raise ApiError(400, "event is required")
                    payload = client.proof(log=str(log), event=int(event_raw)) or {}
                    raw = json.dumps(
                        {
                            "generated_at": datetime.now(timezone.utc).isoformat(),
                            "proof": payload,
                        },
                        ensure_ascii=False,
                    ).encode("utf-8")
                    self._send(200, raw, "application/json; charset=utf-8")
                except ApiError as e:
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(e.status, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            if path == "/api/consistency-snapshot":
                try:
                    log = (qs.get("log") or ["identity_events"])[0]
                    from_raw = (qs.get("from") or [""])[0]
                    to_raw = (qs.get("to") or [""])[0]
                    if not from_raw or not to_raw:
                        raise ApiError(400, "from and to tree sizes are required")
                    payload = client.checkpoint_consistency(
                        log=str(log),
                        from_size=int(from_raw),
                        to_size=int(to_raw),
                    ) or {}
                    raw = json.dumps(
                        {
                            "generated_at": datetime.now(timezone.utc).isoformat(),
                            "consistency": payload,
                        },
                        ensure_ascii=False,
                    ).encode("utf-8")
                    self._send(200, raw, "application/json; charset=utf-8")
                except ApiError as e:
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(e.status, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            if path == "/api/treasury-snapshot":
                try:
                    snap = build_treasury_snapshot(client)
                    raw = json.dumps(snap, ensure_ascii=False).encode("utf-8")
                    self._send(200, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            if path == "/api/hits":
                try:
                    raw = json.dumps(read_hits(store), ensure_ascii=False).encode(
                        "utf-8"
                    )
                    self._send(200, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            if path == "/api/hit":
                page = (qs.get("page") or ["_home"])[0]
                vid = (qs.get("vid") or [""])[0]
                try:
                    if self._should_skip_hit(qs):
                        hits = peek_hits(store, page)
                        hits = dict(hits)
                        hits["counted"] = False
                    else:
                        hits = bump_hits(store, page, visitor_id=vid)
                        hits = dict(hits)
                        # counted=false only for nocount; return visits still "count"
                        hits["counted"] = True
                    # Presence for concurrent viewers (admin) — even on nocount.
                    touch_presence(vid, page, store=store)
                    raw = json.dumps(hits, ensure_ascii=False).encode("utf-8")
                    self._send(
                        200,
                        raw,
                        "application/json; charset=utf-8",
                        set_nocount=set_nocount,
                    )
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            if path == "/api/presence":
                page = (qs.get("page") or [""])[0]
                vid = (qs.get("vid") or [""])[0]
                payload = touch_presence(vid, page, store=store)
                code = 200 if payload.get("ok") else 400
                raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self._send(code, raw, "application/json; charset=utf-8")
                return

            m_snap = API_SNAP_RE.match(path)
            if m_snap:
                try:
                    snap = build_public_snapshot(
                        client, m_snap.group(1), store=store
                    )
                    if allow_local_actions and snap.get("operator"):
                        snap = dict(snap)
                        snap["local_actions"] = True
                    code = 404 if snap.get("error") else 200
                    raw = json.dumps(snap, ensure_ascii=False).encode("utf-8")
                    self._send(code, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            m_allow = API_ALLOWANCE_RE.match(path)
            if m_allow:
                try:
                    blob = load_public_allowance(store, m_allow.group(1))
                    if not blob:
                        self._send(
                            404,
                            b'{"error":"no published allowance"}',
                            "application/json; charset=utf-8",
                        )
                        return
                    raw = json.dumps(blob, ensure_ascii=False).encode("utf-8")
                    self._send(200, raw, "application/json; charset=utf-8")
                except Exception as e:  # pragma: no cover
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(500, raw, "application/json; charset=utf-8")
                return

            m_api = API_POST_RE.match(path)
            if m_api:
                try:
                    data = client.post_get(int(m_api.group(1))) or {}
                    raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
                    self._send(200, raw, "application/json; charset=utf-8")
                except ApiError as e:
                    raw = json.dumps(_api_error_payload(e)).encode("utf-8")
                    self._send(
                        e.status,
                        raw,
                        "application/json; charset=utf-8",
                        extra_headers=_retry_headers(e),
                    )
                return

            m_post = POST_ID_RE.match(path)
            if m_post:
                try:
                    data = client.post_get(int(m_post.group(1))) or {}
                    if not data.get("post"):
                        self._send(404, b"Post not found", "text/plain; charset=utf-8")
                        return
                    qs = parse_qs(urlparse(self.path).query or "")
                    from_handle = (qs.get("from") or [None])[0]
                    try:
                        mod_index = _load_moderation_index(client)
                    except ApiError:
                        mod_index = _empty_moderation_index()
                    try:
                        flags_index = _load_flags_index(client)
                    except ApiError:
                        flags_index = _empty_flags_index()
                    if isinstance(data.get("post"), dict):
                        data["post"] = _attach_flag(
                            _attach_moderation(
                                data["post"], mod_index, target_type="post"
                            ),
                            flags_index,
                            target_type="post",
                        )
                    comments = data.get("comments")
                    if isinstance(comments, list):
                        data["comments"] = [
                            _attach_flag(
                                _attach_moderation(
                                    c, mod_index, target_type="comment"
                                ),
                                flags_index,
                                target_type="comment",
                            )
                            if isinstance(c, dict)
                            else c
                            for c in comments
                        ]
                    liked = set()
                    try:
                        liked = _liked_keys(store)
                    except Exception:
                        liked = set()
                    self._send(
                        200,
                        _html_with_chat(
                            render_post_page(
                                data,
                                liked=liked,
                                from_handle=from_handle,
                                moderation=mod_index,
                            )
                        ),
                        "text/html; charset=utf-8",
                        set_nocount=set_nocount,
                    )
                except ApiError as e:
                    self._send(
                        e.status,
                        _html_with_chat(
                            render_post_error_page(
                                e, post_id=int(m_post.group(1))
                            )
                        ),
                        "text/html; charset=utf-8",
                        extra_headers=_retry_headers(e),
                    )
                return

            m_handle = HANDLE_RE.match(path)
            if m_handle and m_handle.group(1).lower() not in RESERVED_ROOTS:
                self._send(
                    200,
                    _html_with_chat(UI_PATH.read_bytes()),
                    "text/html; charset=utf-8",
                    set_nocount=set_nocount,
                )
                return

            self._send(404, b'{"error":"not found"}', "application/json")

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path

            m_local = API_LOCAL_RE.match(path)
            if m_local:
                code, payload = self._run_local_action(m_local.group(1))
                raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self._send(code, raw, "application/json; charset=utf-8")
                return

            if path == "/api/chat":
                try:
                    body = self._read_json_body(max_bytes=4096)
                except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as e:
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(400, raw, "application/json; charset=utf-8")
                    return
                code, payload = chat_post(
                    str(body.get("name") or ""),
                    str(body.get("text") or ""),
                    client_ip=_chat_client_ip(self),
                    store=store,
                    visitor_id=str(body.get("vid") or ""),
                )
                raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self._send(code, raw, "application/json; charset=utf-8")
                return

            if path == "/api/chat/moderate":
                if not self._allow_local_chat_mod():
                    denied = _publish_auth_failure(self)
                    if denied is not None:
                        code, payload = denied
                        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                        self._send(code, raw, "application/json; charset=utf-8")
                        return
                try:
                    body = self._read_json_body(max_bytes=4096)
                except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as e:
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(400, raw, "application/json; charset=utf-8")
                    return
                ids = body.get("ids", body.get("id"))
                code, payload = chat_moderate(store, ids)
                raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self._send(code, raw, "application/json; charset=utf-8")
                return

            if path == "/api/watchlist":
                try:
                    body = self._read_json_body(max_bytes=4096)
                except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as e:
                    raw = json.dumps({"error": str(e)}).encode("utf-8")
                    self._send(400, raw, "application/json; charset=utf-8")
                    return
                payload = save_visitor_watchlist(
                    store, str(body.get("vid") or ""), body.get("handles")
                )
                code = 200 if payload.get("ok") else 400
                raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self._send(code, raw, "application/json; charset=utf-8")
                return

            if path != "/api/public-allowance":
                self._send(404, b'{"error":"not found"}', "application/json")
                return

            denied = _publish_auth_failure(self)
            if denied is not None:
                code, payload = denied
                raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self._send(code, raw, "application/json; charset=utf-8")
                return

            length_raw = self.headers.get("Content-Length") or "0"
            try:
                length = int(length_raw)
            except ValueError:
                length = -1
            # Allowance + ~120 redacted likes (snippets) fits under 256 KiB.
            if length < 0 or length > 262_144:
                self._send(
                    400,
                    b'{"error":"invalid content-length"}',
                    "application/json; charset=utf-8",
                )
                return
            try:
                body = self.rfile.read(length)
                raw_payload = json.loads(body.decode("utf-8"))
                clean = sanitize_public_allowance(raw_payload)
                path_saved = save_public_allowance(store, clean)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as e:
                raw = json.dumps({"error": str(e)}).encode("utf-8")
                self._send(400, raw, "application/json; charset=utf-8")
                return
            except OSError as e:  # pragma: no cover
                raw = json.dumps({"error": str(e)}).encode("utf-8")
                self._send(500, raw, "application/json; charset=utf-8")
                return

            out = {
                "ok": True,
                "handle": clean["handle"],
                "saved": str(path_saved),
                "updated_at": clean.get("updated_at"),
            }
            self._send(
                200,
                json.dumps(out, ensure_ascii=False).encode("utf-8"),
                "application/json; charset=utf-8",
            )

    return Handler


def serve(
    host: str = "127.0.0.1",
    port: int = 1916,
    *,
    base: str = "https://1f916.ai",
    data_dir: Optional[Path] = None,
    open_browser: bool = True,
) -> None:
    store = Store(data_dir)
    client = Client(base=base)
    local_chat_mod = _loopback_bind_host(host)
    global _CHAT_MIRROR_FLY
    _CHAT_MIRROR_FLY = False
    handler = make_handler(
        client,
        store,
        allow_local_actions=False,
        allow_local_chat_mod=local_chat_mod,
    )
    httpd = _WatchHTTPServer((host, port), handler)
    url = "http://{}:{}/".format(host, port)
    print("1F916 Watch (public window)")
    print("  {}".format(url))
    print("  data: {}".format(store.root))
    print("  read-only — engage lives in 1f916-operator")
    if local_chat_mod and mirror_from_env():
        print("  chat: pulling live guestbook from {} via fly ssh…".format(fly_app()))
        _CHAT_MIRROR_FLY = True
        n, err = seed_chat_from_fly(store)
        if err:
            _CHAT_MIRROR_FLY = False
            print("  chat: live pull failed ({}) — using this machine's file".format(err))
        else:
            print(
                "  chat: {} live messages — remove writes through to Fly".format(n)
            )
    if local_chat_mod:
        if _CHAT_MIRROR_FLY:
            print("  chat tombstone: remove on a message (prod guestbook)")
        else:
            print("  chat tombstone (localhost only): remove on a Human chat message")
    if (
        _admin_local is not None
        and _admin_local.available()
        and host in ("127.0.0.1", "localhost", "::1")
    ):
        print(
            "  visitors admin (localhost only): {}{}".format(
                url.rstrip("/"),
                _admin_local.ADMIN_PAGE_PATH,
            )
        )
        banner = getattr(_admin_local, "source_banner", None)
        if callable(banner):
            print("  {}".format(banner()))
    print("  Ctrl+C to stop")
    def _warm() -> None:
        try:
            build_front_snapshot(client)
        except Exception:
            pass
        _ensure_changes_index_async(client)
        for fn in (
            lambda: build_stats_snapshot(client),
            lambda: build_docket_snapshot(client),
            lambda: build_porch_snapshot(client),
            lambda: build_listings_snapshot(client),
            lambda: build_grants_snapshot(client),
            lambda: build_treasury_snapshot(client),
            lambda: build_flags_snapshot(client),
            lambda: list_citizens(client, store),
        ):
            try:
                fn()
            except Exception:
                pass

    threading.Thread(
        target=_warm,
        name="watch-warmup",
        daemon=True,
    ).start()
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()
