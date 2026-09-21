"""Small safe Markdown → HTML helper (no external deps)."""

from __future__ import annotations

import html
import re
from typing import List, Optional
from urllib.parse import urlparse


_FENCE = re.compile(r"```([a-zA-Z0-9_+-]*)\n?([\s\S]*?)```")
_CODE = re.compile(r"`([^`\n]+)`")
_LINK = re.compile(r"\[([^\]]+)\]\((https?://[^)\s]+)\)")
_BOLD = re.compile(r"\*\*([^*]+)\*\*")
_ITALIC = re.compile(r"(?<!\*)\*([^*]+)\*(?!\*)")
_URL = re.compile(r"(?<![\"'=])(https?://[^\s<]+)")
_TAG_OR_TEXT = re.compile(r"(<[^>]+>)|([^<]+)")
# @handle → /{handle}. Avoid email local-parts (user@host) via lookbehind.
_MENTION = re.compile(
    r"(?<![A-Za-z0-9._%+-])@([A-Za-z0-9][A-Za-z0-9_-]{1,31})(?![A-Za-z0-9_-])"
)
_MENTION_RESERVED = frozenset(
    {
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
    }
)


def safe_href(url: str) -> Optional[str]:
    """Return a normalized http(s) URL, or None if it must stay plain text.

    Watch renders markdown links (unlike Observer, which refuses clickable
    citizen URLs). The scheme gate is the floor under that extra phishing
    surface — javascript:/data:/etc. never become hrefs.

    ``url`` may already have been HTML-escaped (esc-before-link); undo the
    basic entities before parsing so ``&`` in query strings survives.
    """
    raw = html.unescape((url or "").strip())
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        return None
    try:
        parsed = urlparse(raw)
    except Exception:
        return None
    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.netloc:
        return None
    return parsed.geturl()


def highlight_handle(html_text: str, handle: Optional[str]) -> str:
    """Wrap whole-token handle matches in <mark class='mention-hl'> (text nodes only)."""
    h = (handle or "").strip()
    if not h or len(h) < 2 or not html_text:
        return html_text or ""
    pat = re.compile(
        r"(?<![A-Za-z0-9_-])(" + re.escape(h) + r")(?![A-Za-z0-9_-])",
        re.IGNORECASE,
    )

    def repl(m: re.Match) -> str:
        if m.group(1):
            return m.group(1)
        return pat.sub(r"<mark class='mention-hl'>\1</mark>", m.group(2) or "")

    return _TAG_OR_TEXT.sub(repl, html_text)


def _map_outside_anchors(text: str, fn) -> str:
    """Apply ``fn`` to plain stretches, leaving <a>/<code>/<pre> blocks intact."""
    parts: List[str] = []
    last = 0
    for m in re.finditer(
        r"<a\b[^>]*>[\s\S]*?</a>|<code>[\s\S]*?</code>|<pre\b[^>]*>[\s\S]*?</pre>",
        text,
    ):
        parts.append(fn(text[last : m.start()]))
        parts.append(m.group(0))
        last = m.end()
    parts.append(fn(text[last:]))
    return "".join(parts)


def _mention_sub(text: str) -> str:
    def mention(m: re.Match) -> str:
        handle = m.group(1)
        if handle.lower() in _MENTION_RESERVED:
            return m.group(0)
        return '<a class="who-link" href="/{}">@{}</a>'.format(
            html.escape(handle, quote=True), html.escape(handle)
        )

    return _MENTION.sub(mention, text)


def link_mentions(html_text: str) -> str:
    """Turn @handle tokens into /{handle} links (outside existing anchors/code)."""
    if not html_text:
        return html_text or ""
    return _map_outside_anchors(html_text, _mention_sub)


def _inline(text: str) -> str:
    """text must already be HTML-escaped, except we allow our own tags later."""

    def link(m: re.Match) -> str:
        href = safe_href(m.group(2))
        if not href:
            return "{} ({})".format(m.group(1), html.escape(m.group(2)))
        return '<a href="{}" target="_blank" rel="noopener noreferrer">{}</a>'.format(
            html.escape(href, quote=True), m.group(1)
        )

    text = _LINK.sub(link, text)
    text = _CODE.sub(lambda m: "<code>{}</code>".format(m.group(1)), text)
    text = _BOLD.sub(lambda m: "<strong>{}</strong>".format(m.group(1)), text)
    text = _ITALIC.sub(lambda m: "<em>{}</em>".format(m.group(1)), text)

    def autolink(m: re.Match) -> str:
        raw = m.group(1).rstrip(".,);]")
        href = safe_href(raw)
        if not href:
            return html.escape(raw)
        return '<a href="{}" target="_blank" rel="noopener noreferrer">{}</a>'.format(
            html.escape(href, quote=True), html.escape(href)
        )

    # URLs first so https://…/@handle stays one external link; then @mentions
    # only in leftover plain text (never inside <a>/<code>).
    text = _map_outside_anchors(text, lambda chunk: _URL.sub(autolink, chunk))
    return link_mentions(text)


def to_html(text: str, *, highlight: Optional[str] = None) -> str:
    """Render a Markdown-ish body to sanitized HTML.

    When ``highlight`` is a citizen handle, wrap whole-token matches in
    ``<mark class='mention-hl'>`` so Watch can light up name-drops.
    """
    if not text:
        return ""
    raw = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not raw:
        return ""

    fences: List[str] = []

    def stash_fence(m: re.Match) -> str:
        lang = m.group(1) or ""
        code = html.escape(m.group(2).rstrip("\n"))
        cls = ' class="lang-{}"'.format(html.escape(lang)) if lang else ""
        fences.append("<pre><code{}>{}</code></pre>".format(cls, code))
        return "@@FENCE{}@@".format(len(fences) - 1)

    raw = _FENCE.sub(stash_fence, raw)
    lines = html.escape(raw).split("\n")

    blocks: List[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue

        if line.startswith("@@FENCE") and line.endswith("@@"):
            blocks.append(line)
            i += 1
            continue

        hm = re.match(r"^(#{1,4})\s+(.+)$", line)
        if hm:
            level = len(hm.group(1))
            blocks.append(
                "<h{0}>{1}</h{0}>".format(level, _inline(hm.group(2)))
            )
            i += 1
            continue

        if line.startswith("&gt;"):
            quoted: List[str] = []
            while i < len(lines) and lines[i].startswith("&gt;"):
                quoted.append(re.sub(r"^&gt;\s?", "", lines[i]))
                i += 1
            blocks.append(
                "<blockquote>{}</blockquote>".format(
                    "<br>".join(_inline(q) for q in quoted)
                )
            )
            continue

        if re.match(r"^([-*+] |\d+\. )", line):
            items: List[str] = []
            ordered = bool(re.match(r"^\d+\. ", line))
            while i < len(lines) and re.match(r"^([-*+] |\d+\. )", lines[i]):
                item = re.sub(r"^([-*+] |\d+\. )", "", lines[i])
                items.append("<li>{}</li>".format(_inline(item)))
                i += 1
            tag = "ol" if ordered else "ul"
            blocks.append("<{0}>{1}</{0}>".format(tag, "".join(items)))
            continue

        para: List[str] = [line]
        i += 1
        while i < len(lines) and lines[i].strip():
            nxt = lines[i]
            if (
                nxt.startswith("@@FENCE")
                or re.match(r"^(#{1,4})\s+", nxt)
                or nxt.startswith("&gt;")
                or re.match(r"^([-*+] |\d+\. )", nxt)
            ):
                break
            para.append(nxt)
            i += 1
        blocks.append("<p>{}</p>".format(_inline("<br>".join(para))))

    html_out = "\n".join(blocks)
    for idx, fence in enumerate(fences):
        html_out = html_out.replace("@@FENCE{}@@".format(idx), fence)
    return highlight_handle(html_out, highlight)
