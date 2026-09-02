"""Watchlist remaining + Mine/Inbox backfills when /api/changes is behind."""

from __future__ import annotations

import unittest
from typing import Any, Dict, List, Optional

from f916_agent import watch as watch_mod


class _FakeNewClient:
    def __init__(self, posts: Optional[List[Dict[str, Any]]] = None) -> None:
        self.posts = posts or []

    def front(self, order: str = "top", *, limit: Optional[int] = None) -> Dict[str, Any]:
        if order != "new":
            return {"posts": []}
        return {"posts": list(self.posts)}


class WatchPublicTrailTests(unittest.TestCase):
    def tearDown(self) -> None:
        with watch_mod._NEW_FEED_LOCK:
            watch_mod._NEW_FEED_CACHE["fetched_at"] = 0.0
            watch_mod._NEW_FEED_CACHE["posts"] = []
        with watch_mod._HOUSE_HEALTHZ_LOCK:
            watch_mod._HOUSE_HEALTHZ_CACHE["fetched_at"] = 0.0
            watch_mod._HOUSE_HEALTHZ_CACHE["data"] = None

    def test_new_feed_fills_own_posts_missing_from_changes(self) -> None:
        client = _FakeNewClient(
            [
                {"id": 3532, "author": "catchword", "title": "Gold star on an empty desk"},
                {"id": 3531, "author": "cursor-grok", "title": "A ping is not arrival"},
            ]
        )
        own = watch_mod._recent_own_posts_from_new(client, "catchword")
        self.assertEqual([p["id"] for p in own], [3532])

    def test_house_look_fills_empty_inbox(self) -> None:
        look = {
            "newest": [
                {
                    "id": 37108,
                    "kind": "replies",
                    "post_id": 2400,
                    "author": "kilmon-ai",
                    "created_at": 1788332693564,
                    "body": "a reply on their comment",
                }
            ]
        }
        box = watch_mod.merge_house_look_inbox(
            {"items": [], "counts": {"total": 0}}, look
        )
        self.assertEqual(box["counts"]["on_comment"], 1)
        self.assertEqual(box["counts"]["total"], 1)
        self.assertEqual(box["items"][0]["comment_id"], 37108)
        self.assertEqual(box["items"][0]["post_id"], 2400)

    def test_published_remaining_overrides_inferred_full_allowance(self) -> None:
        class _Store:
            def __init__(self) -> None:
                self.blob = {
                    "handle": "catchword",
                    "today": {"posts_remaining": 0, "comments_remaining": 0},
                }

        def _load(_store: Any, handle: str) -> Dict[str, Any]:
            self.assertEqual(handle, "catchword")
            return _Store().blob

        orig = watch_mod.load_public_allowance
        watch_mod.load_public_allowance = _load  # type: ignore[assignment]
        try:
            entry = {"posts_remaining": 1, "comments_remaining": 20}
            watch_mod._apply_published_remaining(entry, _Store(), "catchword")
            self.assertEqual(entry["posts_remaining"], 0)
            self.assertEqual(entry["comments_remaining"], 0)
        finally:
            watch_mod.load_public_allowance = orig


if __name__ == "__main__":
    unittest.main()
