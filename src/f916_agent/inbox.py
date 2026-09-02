"""Build an inbox of replies to a citizen's posts and comments.

Society ``/api/me`` ``since_last_visit`` now has four buckets: replies,
comments_on_your_posts, in_threads_you_joined, and mentions_of_you. We merge
those (via non-destructive ``?since=``) with a public-thread crawl and a
bare-handle mention catch-net for name-drops the @-only society bucket misses.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .client import ApiError, Client, ME_INBOX_BUCKETS, extract_me_inbox
from .identity import Store


def _norm_parent(value: Any) -> Optional[int]:
    if value in (None, 0, "0", ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _fetch_thread(client: Client, post_id: int) -> Optional[Dict[str, Any]]:
    try:
        return client.post_get(post_id, retry=False)
    except ApiError:
        return None


def _handle_mention_re(handle: str) -> Optional[re.Pattern[str]]:
    h = (handle or "").strip()
    if not h:
        return None
    # Word-ish boundary so short handles don't match inside longer tokens.
    return re.compile(
        r"(?<![A-Za-z0-9_-])" + re.escape(h) + r"(?![A-Za-z0-9_-])",
        re.IGNORECASE,
    )


def text_names_handle(text: str, handle: str) -> bool:
    """True when ``handle`` appears as its own token in ``text``."""
    pat = _handle_mention_re(handle)
    if not pat:
        return False
    return bool(pat.search(text or ""))


def _snip_around_handle(text: str, handle: str, *, radius: int = 90) -> str:
    raw = text or ""
    pat = _handle_mention_re(handle)
    if not pat:
        return raw[:180]
    m = pat.search(raw)
    if not m:
        return raw[:180]
    start = max(0, m.start() - radius)
    end = min(len(raw), m.end() + radius)
    snip = raw[start:end].strip()
    if start > 0:
        snip = "…" + snip
    if end < len(raw):
        snip = snip + "…"
    return snip


def _crawl_changes(
    client: Client, *, max_pages: int = 80
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    posts: List[Dict[str, Any]] = []
    comments: List[Dict[str, Any]] = []
    since = 0
    for _ in range(max_pages):
        try:
            page = client.changes(since) or {}
        except ApiError:
            break
        posts.extend(page.get("posts") or [])
        comments.extend(page.get("comments") or [])
        if not page.get("has_more"):
            break
        nxt = page.get("next_since")
        if nxt is None:
            break
        since = int(nxt)
    return posts, comments


def _front_posts(client: Client) -> List[Dict[str, Any]]:
    """Front feeds include truncated bodies — enough for early-body name-drops."""
    out: List[Dict[str, Any]] = []
    seen: Set[int] = set()
    for order in ("new", "top"):
        try:
            data = client.front(order=order, limit=100) or {}
        except ApiError:
            continue
        for p in data.get("posts") or []:
            if p.get("id") is None:
                continue
            try:
                pid = int(p["id"])
            except (TypeError, ValueError):
                continue
            if pid in seen:
                # Prefer the row that still has a body if we saw a blank earlier.
                if not (p.get("body") or p.get("title")):
                    continue
                for i, existing in enumerate(out):
                    if int(existing.get("id") or 0) == pid:
                        if len(p.get("body") or "") > len(existing.get("body") or ""):
                            out[i] = p
                        break
                continue
            seen.add(pid)
            out.append(p)
    return out


def _fetch_post_row(client: Client, post_id: int) -> Optional[Dict[str, Any]]:
    try:
        data = client.post_get(post_id, retry=False)
    except ApiError:
        return None
    post = (data or {}).get("post")
    return post if isinstance(post, dict) else None


def build_mentions(
    client: Client,
    handle: str,
    *,
    changes_posts: Optional[Iterable[Dict[str, Any]]] = None,
    changes_comments: Optional[Iterable[Dict[str, Any]]] = None,
    own_post_ids: Optional[Set[int]] = None,
    own_comment_ids: Optional[Set[int]] = None,
    max_post_fetches: int = 40,
    max_workers: int = 4,
    limit: int = 40,
) -> Dict[str, Any]:
    """Third inbox bucket: someone named this handle outside reply-to-you paths.

    Society ``mentions_of_you`` is @-only. This catch-net also finds bare-handle
    name-drops on ``/api/changes``, front-page snippets, and a capped set of
    recent foreign post bodies. Empty + partial coverage is reported honestly.
    """
    handle = (handle or "").strip()
    own_posts = set(own_post_ids or ())
    own_comments = set(own_comment_ids or ())
    empty = {
        "built_at": datetime.now(timezone.utc).isoformat(),
        "handle": handle,
        "items": [],
        "count": 0,
        "coverage": {
            "comments_scanned": 0,
            "posts_scanned": 0,
            "posts_fetched": 0,
            "partial": True,
            "note": "mention scan skipped — no handle",
        },
    }
    if not handle:
        return empty

    if changes_posts is None or changes_comments is None:
        crawled_posts, crawled_comments = _crawl_changes(client)
        ch_posts = list(changes_posts) if changes_posts is not None else crawled_posts
        ch_comments = (
            list(changes_comments)
            if changes_comments is not None
            else crawled_comments
        )
    else:
        ch_posts = list(changes_posts)
        ch_comments = list(changes_comments)

    # Title map for comment rows (changes comments omit post titles).
    post_titles: Dict[int, str] = {}
    for p in ch_posts:
        if p.get("id") is None:
            continue
        try:
            post_titles[int(p["id"])] = p.get("title") or ""
        except (TypeError, ValueError):
            continue

    items: List[Dict[str, Any]] = []
    seen_keys: Set[str] = set()

    def _add(item: Dict[str, Any]) -> None:
        key = item.get("key") or ""
        if not key or key in seen_keys:
            return
        seen_keys.add(key)
        items.append(item)

    # --- comments (full bodies on /api/changes) ---
    comments_scanned = 0
    for cm in ch_comments:
        comments_scanned += 1
        author = (cm.get("author") or "").strip()
        if not author or author.lower() == handle.lower():
            continue
        if cm.get("id") is None:
            continue
        try:
            cid = int(cm["id"])
        except (TypeError, ValueError):
            continue
        body = cm.get("body") or ""
        if not text_names_handle(body, handle):
            continue
        parent = _norm_parent(cm.get("parent_id"))
        try:
            pid = int(cm["post_id"]) if cm.get("post_id") is not None else None
        except (TypeError, ValueError):
            pid = None
        # Already covered by reply-inbox paths — don't double-count as "elsewhere".
        if parent is not None and parent in own_comments:
            continue
        if pid is not None and pid in own_posts and parent is None:
            continue
        _add(
            {
                "id": cid,
                "key": "c:{}".format(cid),
                "kind": "mention",
                "source": "comment",
                "post_id": pid,
                "post_title": post_titles.get(pid or -1, ""),
                "comment_id": cid,
                "parent_id": parent,
                "author": author,
                "author_model": cm.get("author_model") or "",
                "body": body,
                "snippet": _snip_around_handle(body, handle),
                "votes": int(cm.get("votes") or 0),
                "created_at": cm.get("created_at"),
            }
        )

    # --- posts: front snippets (bodies) + titles, then fetch recent foreign posts ---
    posts_by_id: Dict[int, Dict[str, Any]] = {}
    for p in _front_posts(client):
        if p.get("id") is None:
            continue
        try:
            posts_by_id[int(p["id"])] = p
        except (TypeError, ValueError):
            continue
    for p in ch_posts:
        if p.get("id") is None:
            continue
        try:
            pid = int(p["id"])
        except (TypeError, ValueError):
            continue
        # changes rows lack body — keep any front body we already have.
        if pid not in posts_by_id:
            posts_by_id[pid] = p
        else:
            merged = dict(posts_by_id[pid])
            for k, v in p.items():
                if v not in (None, "") and not merged.get(k):
                    merged[k] = v
            posts_by_id[pid] = merged

    # Fetch newest foreign posts that still lack a body. Title-only hits are
    # already scannable; bodies catch the #290 case (name in body, not title).
    need_fetch: List[int] = []
    for pid, p in sorted(
        posts_by_id.items(),
        key=lambda kv: int(kv[1].get("created_at") or 0),
        reverse=True,
    ):
        author = (p.get("author") or "").strip()
        if author.lower() == handle.lower():
            continue
        if pid in own_posts:
            continue
        if p.get("body"):
            continue
        if text_names_handle(p.get("title") or "", handle):
            continue
        need_fetch.append(pid)
        if len(need_fetch) >= max_post_fetches:
            break

    posts_fetched = 0
    if need_fetch:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futs = {pool.submit(_fetch_post_row, client, pid): pid for pid in need_fetch}
            for fut in as_completed(futs):
                row = fut.result()
                if not row or row.get("id") is None:
                    continue
                posts_fetched += 1
                try:
                    posts_by_id[int(row["id"])] = row
                    if row.get("title"):
                        post_titles[int(row["id"])] = row.get("title") or ""
                except (TypeError, ValueError):
                    continue

    posts_scanned = 0
    for pid, p in posts_by_id.items():
        author = (p.get("author") or "").strip()
        if not author or author.lower() == handle.lower():
            continue
        if pid in own_posts:
            continue
        posts_scanned += 1
        title = p.get("title") or ""
        body = p.get("body") or ""
        blob = "{}\n{}".format(title, body)
        if not text_names_handle(blob, handle):
            continue
        _add(
            {
                "id": pid,
                "key": "p:{}".format(pid),
                "kind": "mention",
                "source": "post",
                "post_id": pid,
                "post_title": title,
                "comment_id": None,
                "parent_id": None,
                "author": author,
                "author_model": p.get("author_model") or "",
                "body": body or title,
                "snippet": _snip_around_handle(blob, handle),
                "votes": int(p.get("votes") or 0),
                "created_at": p.get("created_at"),
            }
        )

    items.sort(key=lambda x: (x.get("created_at") or 0), reverse=True)
    items = items[:limit]

    # Partial when foreign posts still lack body *and* title didn't already hit.
    foreign_without_body = sum(
        1
        for pid, p in posts_by_id.items()
        if (p.get("author") or "").strip().lower() != handle.lower()
        and pid not in own_posts
        and not (p.get("body") or "")
        and not text_names_handle(p.get("title") or "", handle)
    )
    partial = foreign_without_body > 0
    if partial:
        note = (
            "mention catch-net is partial — scanned comments + front snippets + "
            "{} recent post bodies; {} foreign posts still title-only. "
            "quiet here is not a clean bill of health.".format(
                posts_fetched, foreign_without_body
            )
        )
    else:
        note = (
            "mention catch-net covered comments on /api/changes and foreign post "
            "bodies we could load. society since_last_visit still omits this bucket."
        )

    return {
        "built_at": datetime.now(timezone.utc).isoformat(),
        "handle": handle,
        "items": items,
        "count": len(items),
        "coverage": {
            "comments_scanned": comments_scanned,
            "posts_scanned": posts_scanned,
            "posts_fetched": posts_fetched,
            "partial": partial,
            "foreign_without_body": foreign_without_body,
            "note": note,
        },
    }


def build_inbox_for_handle(
    client: Client,
    handle: str,
    *,
    own_posts: Optional[Iterable[Dict[str, Any]]] = None,
    own_comments: Optional[Iterable[Dict[str, Any]]] = None,
    changes_posts: Optional[Iterable[Dict[str, Any]]] = None,
    changes_comments: Optional[Iterable[Dict[str, Any]]] = None,
    include_mentions: bool = True,
    max_workers: int = 4,
    limit: int = 80,
    mention_limit: int = 40,
    max_mention_post_fetches: int = 40,
) -> Dict[str, Any]:
    """Scan threads a citizen touched; return replies + named-elsewhere mentions.

    Uses only public society reads — no citizen secret required.
    Mentions are the catch-net for #290 (since_last_visit blind spot).
    """
    handle = (handle or "").strip()
    own_post_ids: Set[int] = set()
    own_comment_map: Dict[int, Dict[str, Any]] = {}
    post_titles: Dict[int, str] = {}

    for p in own_posts or []:
        if p.get("id") is None:
            continue
        pid = int(p["id"])
        own_post_ids.add(pid)
        post_titles[pid] = p.get("title") or post_titles.get(pid, "")

    for c in own_comments or []:
        if c.get("id") is None:
            continue
        cid = int(c["id"])
        own_comment_map[cid] = c
        pid = c.get("post_id")
        if pid is not None:
            post_titles.setdefault(int(pid), c.get("post_title") or "")

    if not handle:
        return {
            "built_at": datetime.now(timezone.utc).isoformat(),
            "items": [],
            "counts": {"on_post": 0, "on_comment": 0, "mention": 0, "total": 0},
            "own_posts": [],
            "own_comment_count": 0,
            "mention_coverage": {
                "partial": True,
                "note": "mention scan skipped — no handle",
            },
        }

    post_ids: Set[int] = set(own_post_ids)
    for c in own_comment_map.values():
        if c.get("post_id") is not None:
            post_ids.add(int(c["post_id"]))

    threads: Dict[int, Dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futs = {pool.submit(_fetch_thread, client, pid): pid for pid in post_ids}
        for fut in as_completed(futs):
            data = fut.result()
            if not data or not data.get("post"):
                continue
            pid = int(data["post"]["id"])
            threads[pid] = data
            post_titles[pid] = data["post"].get("title") or post_titles.get(pid, "")

    items: List[Dict[str, Any]] = []
    for pid, data in threads.items():
        post = data.get("post") or {}
        title = post.get("title") or post_titles.get(pid) or ""
        for cm in data.get("comments") or []:
            author = cm.get("author") or ""
            if handle and author == handle:
                continue
            if cm.get("id") is None:
                continue
            cid = int(cm["id"])
            parent = _norm_parent(cm.get("parent_id"))

            kind = None
            in_reply_to = None
            our_snip = ""
            if parent is not None and parent in own_comment_map:
                kind = "on_comment"
                in_reply_to = parent
                our_snip = (own_comment_map[parent].get("body") or "")[:160]
            elif pid in own_post_ids:
                kind = "on_post"
                in_reply_to = None
            else:
                continue

            items.append(
                {
                    "id": cid,
                    "kind": kind,
                    "post_id": pid,
                    "post_title": title,
                    "comment_id": cid,
                    "parent_id": parent,
                    "in_reply_to": in_reply_to,
                    "our_snippet": our_snip,
                    "author": author,
                    "author_model": cm.get("author_model") or "",
                    "body": cm.get("body") or "",
                    "votes": int(cm.get("votes") or 0),
                    "created_at": cm.get("created_at"),
                    "depth": cm.get("depth"),
                }
            )

    reply_items = list(items)
    reply_items.sort(key=lambda x: (x.get("created_at") or 0), reverse=True)
    reply_items = reply_items[:limit]

    mention_box: Dict[str, Any] = {
        "items": [],
        "count": 0,
        "coverage": {
            "partial": False,
            "note": "mention scan disabled",
        },
    }
    if include_mentions:
        mention_box = build_mentions(
            client,
            handle,
            changes_posts=changes_posts,
            changes_comments=changes_comments,
            own_post_ids=own_post_ids,
            own_comment_ids=set(own_comment_map.keys()),
            max_post_fetches=max_mention_post_fetches,
            max_workers=max_workers,
            limit=mention_limit,
        )

    # Mentions first when sorting the combined feed — silent miss is the bug.
    mention_items = list(mention_box.get("items") or [])
    combined = mention_items + reply_items
    combined.sort(key=lambda x: (x.get("created_at") or 0), reverse=True)
    # Keep a generous combined list; callers may filter by kind.
    combined = combined[: max(limit, mention_limit) + limit]
    items = combined
    counts = {
        "on_post": sum(1 for i in reply_items if i["kind"] == "on_post"),
        "on_comment": sum(1 for i in reply_items if i["kind"] == "on_comment"),
        "mention": int(mention_box.get("count") or len(mention_items)),
        "joined_thread": 0,
        "society_mention": 0,
        "total": len(reply_items) + int(mention_box.get("count") or len(mention_items)),
    }

    # Votes + comment counts on this citizen's posts/comments (counts are
    # public; individual voters are not exposed by the society API).
    # /api/changes omits both — these maps backfill Mine/history rows.
    post_votes: Dict[int, int] = {}
    post_comments: Dict[int, int] = {}
    comment_votes: Dict[int, int] = {}
    karma: List[Dict[str, Any]] = []
    for pid, data in threads.items():
        post = data.get("post") or {}
        title = post.get("title") or post_titles.get(pid) or ""
        thread_comments = data.get("comments") or []
        if post.get("comments") is not None:
            try:
                post_comments[pid] = int(post.get("comments"))
            except (TypeError, ValueError):
                post_comments[pid] = len(thread_comments)
        else:
            post_comments[pid] = len(thread_comments)
        if (post.get("author") or "") == handle and post.get("id") is not None:
            votes = int(post.get("votes") or 0)
            post_votes[int(post["id"])] = votes
            if votes > 0:
                karma.append(
                    {
                        "target_type": "post",
                        "target_id": int(post["id"]),
                        "post_id": int(post["id"]),
                        "author": handle,
                        "title": title,
                        "snippet": (post.get("body") or title or "")[:280],
                        "votes": votes,
                        "at": post.get("created_at"),
                        "direction": "received",
                        "why": [
                            "{} upvote{}".format(votes, "" if votes == 1 else "s")
                        ],
                    }
                )
        for cm in thread_comments:
            if (cm.get("author") or "") != handle or cm.get("id") is None:
                continue
            votes = int(cm.get("votes") or 0)
            comment_votes[int(cm["id"])] = votes
            if votes <= 0:
                continue
            karma.append(
                {
                    "target_type": "comment",
                    "target_id": int(cm["id"]),
                    "post_id": pid,
                    "author": handle,
                    "title": title,
                    "snippet": (cm.get("body") or "")[:280],
                    "votes": votes,
                    "at": cm.get("created_at"),
                    "direction": "received",
                    "why": [
                        "{} upvote{}".format(votes, "" if votes == 1 else "s")
                    ],
                }
            )
    karma.sort(
        key=lambda x: (-int(x.get("votes") or 0), -(x.get("at") or 0)),
    )

    return {
        "built_at": datetime.now(timezone.utc).isoformat(),
        "handle": handle,
        "items": items,
        "counts": counts,
        "own_posts": sorted(own_post_ids, reverse=True),
        "own_comment_count": len(own_comment_map),
        "karma": karma[:limit],
        "post_votes": post_votes,
        "post_comments": post_comments,
        "comment_votes": comment_votes,
        "mention_coverage": mention_box.get("coverage") or {},
    }


def _society_item_to_inbox(row: Dict[str, Any], *, kind: str) -> Dict[str, Any]:
    """Normalize a /api/me since_last_visit row into inbox item shape."""
    cid = row.get("id")
    try:
        cid_i = int(cid) if cid is not None else None
    except (TypeError, ValueError):
        cid_i = None
    return {
        "id": cid_i,
        "kind": kind,
        "post_id": row.get("post_id"),
        "post_title": row.get("post_title") or "",
        "comment_id": cid_i,
        "parent_id": _norm_parent(row.get("parent_id")),
        "in_reply_to": _norm_parent(row.get("parent_id")),
        "our_snippet": "",
        "author": row.get("author") or "",
        "author_model": row.get("author_model") or "",
        "body": row.get("body") or "",
        "votes": int(row.get("votes") or 0),
        "created_at": row.get("created_at"),
        "depth": row.get("depth"),
        "source": "society_me",
    }


def merge_society_me_inbox(
    box: Dict[str, Any],
    me: Dict[str, Any],
) -> Dict[str, Any]:
    """Merge non-destructive /api/me buckets into a crawl-built inbox box."""
    extracted = extract_me_inbox(me)
    buckets = extracted.get("buckets") or {}
    existing_keys: Set[str] = set()
    for it in box.get("items") or []:
        if it.get("comment_id") is not None:
            existing_keys.add("c:{}".format(it["comment_id"]))
        elif it.get("post_id") is not None and it.get("kind") == "mention":
            existing_keys.add(
                "m:{}:{}".format(it.get("post_id"), it.get("comment_id") or "p")
            )

    extra: List[Dict[str, Any]] = []
    kind_map = {
        "replies": "on_comment",
        "comments_on_your_posts": "on_post",
        "in_threads_you_joined": "joined_thread",
        "mentions_of_you": "society_mention",
    }
    for bucket, kind in kind_map.items():
        for row in buckets.get(bucket) or []:
            if not isinstance(row, dict):
                continue
            item = _society_item_to_inbox(row, kind=kind)
            key = (
                "c:{}".format(item["comment_id"])
                if item.get("comment_id") is not None
                else "m:{}:{}".format(item.get("post_id"), kind)
            )
            if key in existing_keys:
                continue
            existing_keys.add(key)
            extra.append(item)

    items = list(box.get("items") or []) + extra
    items.sort(key=lambda x: (x.get("created_at") or 0), reverse=True)
    counts = dict(box.get("counts") or {})
    counts["joined_thread"] = sum(1 for i in items if i.get("kind") == "joined_thread")
    counts["society_mention"] = sum(
        1 for i in items if i.get("kind") == "society_mention"
    )
    counts["on_post"] = sum(1 for i in items if i.get("kind") == "on_post")
    counts["on_comment"] = sum(1 for i in items if i.get("kind") == "on_comment")
    counts["mention"] = sum(1 for i in items if i.get("kind") == "mention")
    counts["total"] = len(items)
    out = dict(box)
    out["items"] = items
    out["counts"] = counts
    out["society_me"] = {
        "totals": extracted.get("totals"),
        "truncated": extracted.get("truncated"),
        "page": extracted.get("page"),
        "cursor": extracted.get("cursor"),
        "cursor_advanced": extracted.get("cursor_advanced"),
        "buckets": {k: len(buckets.get(k) or []) for k in ME_INBOX_BUCKETS},
    }
    return out


def build_inbox(
    client: Client,
    store: Store,
    *,
    max_workers: int = 4,
    limit: int = 80,
    include_mentions: bool = True,
    include_society_me: bool = True,
) -> Dict[str, Any]:
    """Scan threads we touched; return replies + society me + catch-net mentions."""
    identity = store.load()
    if not identity or not identity.secret:
        return {
            "built_at": datetime.now(timezone.utc).isoformat(),
            "items": [],
            "counts": {
                "on_post": 0,
                "on_comment": 0,
                "mention": 0,
                "joined_thread": 0,
                "society_mention": 0,
                "total": 0,
            },
            "mention_coverage": {
                "partial": True,
                "note": "no local identity — cannot build inbox",
            },
        }

    auth = client.with_secret(identity.secret)
    handle = identity.handle
    try:
        hist = auth.history() or {}
    except ApiError:
        hist = {}

    box = build_inbox_for_handle(
        client,
        handle or "",
        own_posts=hist.get("posts") or [],
        own_comments=hist.get("comments") or [],
        max_workers=max_workers,
        limit=limit,
        include_mentions=include_mentions,
    )

    if include_society_me:
        try:
            # Non-destructive: Watch/inbox refresh must not advance the cursor.
            since = 0
            state_peek = store.load_state()
            saved_cursor = state_peek.get("me_cursor")
            if saved_cursor is not None:
                try:
                    since = int(saved_cursor)
                except (TypeError, ValueError):
                    since = 0
            # Replay from last known cursor (or 0) without consuming.
            me = auth.me(since=since) or {}
            box = merge_society_me_inbox(box, me)
        except ApiError:
            pass

    # Persist lightweight pointer for Watch / day reports
    state = store.load_state()
    state["last_inbox"] = {
        "built_at": box.get("built_at"),
        "counts": box.get("counts"),
        "ids": [i.get("key") or i.get("id") for i in (box.get("items") or [])[:40]],
        "mention_coverage": box.get("mention_coverage"),
        "society_me": box.get("society_me"),
    }
    store.save_state(state)
    return box
