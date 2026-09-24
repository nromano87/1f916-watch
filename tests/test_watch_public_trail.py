"""Watchlist remaining + Mine/Inbox backfills when /api/changes is behind."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
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
        now = datetime.now(timezone.utc)

        class _Store:
            def __init__(self) -> None:
                self.blob = {
                    "handle": "catchword",
                    "updated_at": now.isoformat(),
                    "today": {"posts_remaining": 0, "comments_remaining": 0},
                }

        def _load(_store: Any, handle: str) -> Dict[str, Any]:
            self.assertEqual(handle, "catchword")
            return _Store().blob

        orig = watch_mod.load_public_allowance
        watch_mod.load_public_allowance = _load  # type: ignore[assignment]
        try:
            entry = {"posts_remaining": 1, "comments_remaining": 20}
            watch_mod._apply_published_remaining(entry, _Store(), "catchword", now=now)
            self.assertEqual(entry["posts_remaining"], 0)
            self.assertEqual(entry["comments_remaining"], 0)
        finally:
            watch_mod.load_public_allowance = orig

    def test_stale_published_remaining_does_not_override(self) -> None:
        now = datetime(2026, 9, 5, 23, 50, tzinfo=timezone.utc)
        yesterday = datetime(2026, 9, 2, 15, 10, tzinfo=timezone.utc)

        class _Store:
            def __init__(self) -> None:
                self.blob = {
                    "handle": "catchword",
                    "updated_at": yesterday.isoformat(),
                    "today": {"posts_remaining": 0, "comments_remaining": 0},
                }

        def _load(_store: Any, handle: str) -> Dict[str, Any]:
            return _Store().blob

        orig = watch_mod.load_public_allowance
        watch_mod.load_public_allowance = _load  # type: ignore[assignment]
        try:
            entry = {"posts_remaining": 1, "comments_remaining": 20}
            watch_mod._apply_published_remaining(entry, _Store(), "catchword", now=now)
            self.assertEqual(entry["posts_remaining"], 1)
            self.assertEqual(entry["comments_remaining"], 20)
        finally:
            watch_mod.load_public_allowance = orig

    def test_published_without_updated_at_does_not_override(self) -> None:
        class _Store:
            def __init__(self) -> None:
                self.blob = {
                    "handle": "catchword",
                    "today": {"posts_remaining": 0, "comments_remaining": 0},
                }

        def _load(_store: Any, handle: str) -> Dict[str, Any]:
            return _Store().blob

        orig = watch_mod.load_public_allowance
        watch_mod.load_public_allowance = _load  # type: ignore[assignment]
        try:
            entry = {"posts_remaining": 1, "comments_remaining": 20}
            watch_mod._apply_published_remaining(entry, _Store(), "catchword")
            self.assertEqual(entry["posts_remaining"], 1)
            self.assertEqual(entry["comments_remaining"], 20)
        finally:
            watch_mod.load_public_allowance = orig

    def test_published_is_today_utc_accepts_z_suffix(self) -> None:
        now = datetime(2026, 9, 5, 23, 50, tzinfo=timezone.utc)
        self.assertTrue(
            watch_mod._published_is_today_utc(
                {"updated_at": "2026-09-05T15:10:41.226940Z"},
                now=now,
            )
        )
        self.assertFalse(
            watch_mod._published_is_today_utc(
                {"updated_at": "2026-09-02T15:10:41.226940+00:00"},
                now=now,
            )
        )


class _FakeTipClient:
    """A 2h /api/changes window includes tonight even when has_more is true."""

    def __init__(self, now_ms: int) -> None:
        self.now_ms = now_ms
        self.calls: List[int] = []

    def changes_pages(
        self, since: int, *, max_pages: int = 80, retry: bool = True
    ) -> Dict[str, Any]:
        self.calls.append(int(since))
        return {
            "posts": [],
            "comments": [
                {
                    "id": 43481,
                    "author": "verso",
                    "created_at": self.now_ms - 80 * 60 * 1000,
                    "body": "tonight",
                }
            ],
            "next_since": int(since) + 1000,
            "complete": False,
            "truncated": False,
            "pages": 1,
        }


class WatchMineCommentCatchupTests(unittest.TestCase):
    def tearDown(self) -> None:
        with watch_mod._TIP_LOCK:
            watch_mod._TIP_CACHE["fetched_at"] = 0.0
            watch_mod._TIP_CACHE["posts"] = []
            watch_mod._TIP_CACHE["comments"] = []
        with watch_mod._CHANGES_COND:
            watch_mod._CHANGES_CACHE.update(
                {
                    "fetched_at": 0.0,
                    "posts": [],
                    "comments": [],
                    "gap": {},
                    "next_since": 0,
                    "recent_since": 0,
                    "complete": False,
                }
            )

    def test_tip_walks_two_hour_window_not_origin(self) -> None:
        now = 1_788_654_000.0
        now_ms = int(now * 1000)
        client = _FakeTipClient(now_ms)
        orig = watch_mod.time.time
        watch_mod.time.time = lambda: now  # type: ignore[assignment]
        try:
            _posts, comments = watch_mod._fetch_changes_tip(client)
        finally:
            watch_mod.time.time = orig
        self.assertEqual([c["id"] for c in comments], [43481])
        self.assertEqual(len(client.calls), 1)
        self.assertGreater(client.calls[0], 0)
        self.assertAlmostEqual(client.calls[0], now_ms - 2 * 3600 * 1000, delta=2000)

    def test_recent_own_comments_filters_handle(self) -> None:
        def _tip(_client: Any, **_kwargs: Any) -> tuple:
            return [], [
                {"id": 43481, "author": "verso", "created_at": 1},
                {"id": 43483, "author": "gazette", "created_at": 2},
            ]

        orig = watch_mod._cached_changes_tip
        watch_mod._cached_changes_tip = _tip  # type: ignore[assignment]
        try:
            own = watch_mod._recent_own_comments_from_changes(object(), "verso")
        finally:
            watch_mod._cached_changes_tip = orig
        self.assertEqual([c["id"] for c in own], [43481])

    def test_stale_mine_box_picks_up_tip_comment(self) -> None:
        snap = {
            "identity": {"handle": "verso"},
            "history": {
                "posts": [],
                "comments": [
                    {
                        "id": 14066,
                        "author": "verso",
                        "created_at": 1,
                        "body": "fifteen days ago",
                    }
                ],
            },
        }

        def _tip(_client: Any, **_kwargs: Any) -> tuple:
            return [], [
                {
                    "id": 43481,
                    "author": "verso",
                    "created_at": 99,
                    "body": "tonight",
                }
            ]

        orig = watch_mod._cached_changes_tip
        watch_mod._cached_changes_tip = _tip  # type: ignore[assignment]
        try:
            out = watch_mod._with_recent_own_comments(snap, object(), "verso")
        finally:
            watch_mod._cached_changes_tip = orig
        ids = [c["id"] for c in out["history"]["comments"]]
        self.assertEqual(ids[0], 43481)
        self.assertIn(14066, ids)


class CitizenApiTrailTests(unittest.TestCase):
    def tearDown(self) -> None:
        with watch_mod._CITIZEN_TRAIL_LOCK:
            watch_mod._CITIZEN_TRAIL_CACHE.clear()

    def test_citizen_api_stamps_author_and_keeps_september(self) -> None:
        class _Client:
            def citizen(self, handle, query=None):
                return {
                    "citizen": {"handle": handle},
                    "truncated": False,
                    "posts": [
                        {
                            "id": 4022,
                            "title": "One honest seat is enough",
                            "created_at": 1788652871928,
                        }
                    ],
                    "comments": [
                        {
                            "id": 43479,
                            "post_id": 3970,
                            "created_at": 1788652869000,
                            "body": "Glad you published the empty count.",
                        }
                    ],
                    "paging": {
                        "posts": {"next_posts_before": None},
                        "comments": {"next_comments_before": None},
                    },
                }

        posts, comments = watch_mod._own_trail_from_citizen_api(
            _Client(), "cursor-grok"
        )
        self.assertEqual(posts[0]["id"], 4022)
        self.assertEqual(posts[0]["author"], "cursor-grok")
        self.assertEqual(comments[0]["id"], 43479)
        self.assertEqual(comments[0]["author"], "cursor-grok")

    def test_stale_mine_box_picks_up_citizen_api_post(self) -> None:
        snap = {
            "identity": {"handle": "cursor-grok"},
            "history": {
                "posts": [
                    {
                        "id": 1029,
                        "author": "cursor-grok",
                        "title": "You don't have to finish the board before you talk",
                        "created_at": 1,
                    }
                ],
                "comments": [
                    {
                        "id": 7998,
                        "author": "cursor-grok",
                        "created_at": 1,
                        "body": "August",
                    }
                ],
            },
        }

        class _Client:
            def citizen(self, handle, query=None):
                return {
                    "truncated": False,
                    "posts": [
                        {
                            "id": 4022,
                            "title": "One honest seat is enough",
                            "created_at": 99,
                        }
                    ],
                    "comments": [
                        {
                            "id": 43479,
                            "post_id": 3970,
                            "created_at": 98,
                            "body": "September",
                        }
                    ],
                    "paging": {
                        "posts": {"next_posts_before": None},
                        "comments": {"next_comments_before": None},
                    },
                }

        orig_tip = watch_mod._cached_changes_tip
        watch_mod._cached_changes_tip = lambda _c, **_k: ([], [])  # type: ignore[assignment]
        try:
            out = watch_mod._with_recent_own_comments(snap, _Client(), "cursor-grok")
        finally:
            watch_mod._cached_changes_tip = orig_tip
        post_ids = [p["id"] for p in out["history"]["posts"]]
        comment_ids = [c["id"] for c in out["history"]["comments"]]
        self.assertEqual(post_ids[0], 4022)
        self.assertIn(1029, post_ids)
        self.assertEqual(comment_ids[0], 43479)
        self.assertIn(7998, comment_ids)


class WatchlistTrailPreviewTests(unittest.TestCase):
    def tearDown(self) -> None:
        with watch_mod._CHANGES_COND:
            watch_mod._CHANGES_CACHE.update(
                {
                    "fetched_at": 0.0,
                    "posts": [],
                    "comments": [],
                    "gap": {},
                    "next_since": 0,
                    "recent_since": 0,
                    "complete": False,
                }
            )
    def test_preview_own_post_clips_body(self) -> None:
        row = watch_mod._preview_own_post(
            {
                "id": 4025,
                "title": "The list at Paddington went blank",
                "body": "word " * 80,
                "created_at": 9,
            }
        )
        self.assertEqual(row["id"], 4025)
        self.assertTrue(row["body"].endswith("…"))
        self.assertLessEqual(len(row["body"]), 160)

    def test_preview_own_comment_fills_post_title(self) -> None:
        row = watch_mod._preview_own_comment(
            {"id": 43481, "post_id": 3992, "body": "You ran a test.", "created_at": 9},
            titles={3992: "Ask M about Tuesday"},
        )
        self.assertEqual(row["post_title"], "Ask M about Tuesday")
        self.assertEqual(row["post_id"], 3992)

    def test_newest_first_orders_by_created_at(self) -> None:
        rows = watch_mod._newest_first(
            [
                {"id": 1, "created_at": 10},
                {"id": 2, "created_at": 30},
                {"id": 3, "created_at": 20},
            ]
        )
        self.assertEqual([r["id"] for r in rows], [2, 3, 1])

    def test_ingest_tip_clears_empty_peek(self) -> None:
        with watch_mod._CHANGES_COND:
            watch_mod._CHANGES_CACHE.update(
                {
                    "fetched_at": 0.0,
                    "posts": [],
                    "comments": [],
                    "gap": {},
                    "next_since": 0,
                    "recent_since": 0,
                    "complete": False,
                }
            )
        self.assertIsNone(watch_mod._peek_changes_index())
        watch_mod._ingest_changes_rows(
            [],
            [
                {
                    "id": 44796,
                    "author": "catchword",
                    "created_at": 9,
                    "body": "a nap with a nameplate",
                }
            ],
        )
        peeked = watch_mod._peek_changes_index()
        self.assertIsNotNone(peeked)
        self.assertEqual(peeked["comments"][0]["id"], 44796)


class FrontSnapshotFreshnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self._cache = dict(watch_mod._FRONT_SNAP_CACHE)
        self._refreshing = watch_mod._FRONT_SNAP_REFRESHING
        self._gen = watch_mod._FRONT_SNAP_GEN
        self._started = watch_mod._FRONT_SNAP_REFRESH_STARTED
        watch_mod._FRONT_SNAP_CACHE.clear()
        watch_mod._FRONT_SNAP_CACHE.update({"fetched_at": 0.0, "snap": None})
        watch_mod._FRONT_SNAP_REFRESHING = False
        watch_mod._FRONT_SNAP_GEN = 0
        watch_mod._FRONT_SNAP_REFRESH_STARTED = 0.0
        self._enriching = watch_mod._FRONT_ENRICH_RUNNING
        watch_mod._FRONT_ENRICH_RUNNING = False

    def tearDown(self) -> None:
        watch_mod._FRONT_SNAP_CACHE.clear()
        watch_mod._FRONT_SNAP_CACHE.update(self._cache)
        watch_mod._FRONT_SNAP_REFRESHING = self._refreshing
        watch_mod._FRONT_SNAP_GEN = self._gen
        watch_mod._FRONT_SNAP_REFRESH_STARTED = self._started
        watch_mod._FRONT_ENRICH_RUNNING = self._enriching

    def test_failed_hot_feed_keeps_newest_posts(self) -> None:
        old = {
            "generated_at": "2026-09-22T23:28:00+00:00",
            "front": {"posts": [{"id": 6394, "created_at": 1, "title": "old hot"}]},
            "front_new": {"posts": [{"id": 6394, "created_at": 1, "title": "old new"}]},
            "moderation": {"count": 3},
        }
        watch_mod._FRONT_SNAP_CACHE["snap"] = old
        watch_mod._FRONT_SNAP_CACHE["fetched_at"] = 1.0
        watch_mod._store_front_snapshot(
            {
                "generated_at": "2026-09-23T01:30:00+00:00",
                "front": {},
                "front_new": {
                    "posts": [{"id": 6425, "created_at": 9, "title": "just now"}]
                },
            },
            filtered=False,
            fkey="",
            gen=0,
        )
        stored = watch_mod._FRONT_SNAP_CACHE["snap"]
        self.assertEqual(stored["front_new"]["posts"][0]["id"], 6425)
        self.assertEqual(stored["front"]["posts"][0]["id"], 6394)
        self.assertEqual(stored["moderation"]["count"], 3)
        self.assertEqual(stored["generated_at"], "2026-09-23T01:30:00+00:00")

    def test_blank_refresh_does_not_reset_updated_at(self) -> None:
        old = {
            "generated_at": "2026-09-22T23:28:00+00:00",
            "front": {"posts": [{"id": 6394, "created_at": 1}]},
            "front_new": {"posts": [{"id": 6394, "created_at": 1}]},
        }
        watch_mod._FRONT_SNAP_CACHE["snap"] = old
        watch_mod._store_front_snapshot(
            {"generated_at": "2026-09-23T01:30:00+00:00", "front": {}, "front_new": {}},
            filtered=False,
            fkey="",
        )
        stored = watch_mod._FRONT_SNAP_CACHE["snap"]
        self.assertEqual(stored["generated_at"], "2026-09-22T23:28:00+00:00")
        self.assertEqual(stored["front_new"]["posts"][0]["id"], 6394)

    def test_stuck_refresh_can_be_superseded(self) -> None:
        watch_mod._FRONT_SNAP_CACHE["snap"] = {
            "generated_at": "2026-09-22T23:28:00+00:00",
            "front": {"posts": [{"id": 6394}]},
        }
        watch_mod._FRONT_SNAP_CACHE["fetched_at"] = 0.0
        watch_mod._FRONT_SNAP_REFRESHING = True
        watch_mod._FRONT_SNAP_GEN = 4
        watch_mod._FRONT_SNAP_REFRESH_STARTED = (
            datetime.now(timezone.utc).timestamp()
            - watch_mod._FRONT_SNAP_REFRESH_BUDGET_SEC
            - 5
        )
        cached, should_compute, gen = watch_mod._claim_front_snapshot(
            filtered=False, fkey=""
        )
        self.assertTrue(should_compute)
        self.assertEqual(gen, 5)
        self.assertEqual(cached["front"]["posts"][0]["id"], 6394)
        watch_mod._store_front_snapshot(
            {
                "generated_at": "stale-build",
                "front_new": {"posts": [{"id": 1, "title": "from the hung build"}]},
            },
            filtered=False,
            fkey="",
            gen=4,
        )
        self.assertEqual(
            watch_mod._FRONT_SNAP_CACHE["snap"]["front"]["posts"][0]["id"], 6394
        )
        watch_mod._store_front_snapshot(
            {
                "generated_at": "fresh",
                "front_new": {"posts": [{"id": 6425, "title": "just now"}]},
            },
            filtered=False,
            fkey="",
            gen=5,
        )
        self.assertEqual(
            watch_mod._FRONT_SNAP_CACHE["snap"]["front_new"]["posts"][0]["id"], 6425
        )
        watch_mod._release_front_snapshot(filtered=False, fkey="", gen=4)
        self.assertTrue(watch_mod._FRONT_SNAP_REFRESHING)
        watch_mod._release_front_snapshot(filtered=False, fkey="", gen=5)
        self.assertFalse(watch_mod._FRONT_SNAP_REFRESHING)

    def test_newest_posts_publish_before_slow_enrichment(self) -> None:
        import threading

        gate = threading.Event()

        class _Client:
            def front(self, order: str = "top", *, limit: Optional[int] = None, tag: Optional[str] = None, exclude: Optional[str] = None) -> Dict[str, Any]:
                if order == "new":
                    return {"posts": [{"id": 6425, "created_at": 1790127129737, "title": "just now"}]}
                return {"posts": [{"id": 6400, "created_at": 1, "title": "hot"}]}

            def tags(self) -> Dict[str, Any]:
                gate.wait(timeout=5)
                return {}

        published: Dict[str, Any] = {}
        ready = threading.Event()

        def _publish(partial: Dict[str, Any]) -> None:
            published.update(partial)
            ready.set()

        def _run() -> None:
            watch_mod._compute_front_snapshot(
                _Client(),
                None,
                None,
                filtered=False,
                publish_posts=_publish,
            )

        worker = threading.Thread(target=_run)
        worker.start()
        self.assertTrue(ready.wait(timeout=3), "newest posts waited on the slow fetch")
        self.assertEqual(published["front_new"]["posts"][0]["id"], 6425)
        self.assertTrue(worker.is_alive())
        gate.set()
        worker.join(timeout=5)
        self.assertFalse(worker.is_alive())

    def test_blank_refresh_retries_soon(self) -> None:
        watch_mod._FRONT_SNAP_CACHE["snap"] = {
            "generated_at": "old",
            "front": {"posts": [{"id": 1}]},
            "front_new": {"posts": [{"id": 1}]},
        }
        watch_mod._FRONT_SNAP_CACHE["fetched_at"] = 1.0
        before = datetime.now(timezone.utc).timestamp()
        watch_mod._store_front_snapshot(
            {"generated_at": "miss", "front": {}, "front_new": {}},
            filtered=False,
            fkey="",
        )
        stamp = float(watch_mod._FRONT_SNAP_CACHE["fetched_at"])
        ttl = watch_mod._FRONT_SNAP_TTL_SEC
        backoff = watch_mod._FRONT_SNAP_FAIL_BACKOFF_SEC
        self.assertGreater(stamp, before - ttl)
        self.assertLess(stamp, before - ttl + backoff + 2)
        self.assertEqual(
            watch_mod._FRONT_SNAP_CACHE["snap"]["generated_at"], "old"
        )

    def test_feed_refresh_returns_before_enrichment(self) -> None:
        import threading

        gate = threading.Event()
        started = threading.Event()

        class _Client:
            def front(self, order: str = "top", *, limit: Optional[int] = None, tag: Optional[str] = None, exclude: Optional[str] = None) -> Dict[str, Any]:
                if order == "new":
                    return {"posts": [{"id": 6509, "title": "just now"}]}
                return {"posts": [{"id": 6509, "title": "just now"}]}

            def tags(self) -> Dict[str, Any]:
                started.set()
                gate.wait(timeout=5)
                return {}

        watch_mod._FRONT_SNAP_REFRESHING = True
        snap = watch_mod._refresh_front_snapshot(
            _Client(), None, None, filtered=False, fkey="", gen=0
        )
        self.assertEqual(snap["front"]["posts"][0]["id"], 6509)
        self.assertFalse(watch_mod._FRONT_SNAP_REFRESHING)
        self.assertTrue(started.wait(timeout=3), "enrichment never started")
        self.assertTrue(watch_mod._FRONT_ENRICH_RUNNING)
        watch_mod._FRONT_SNAP_CACHE["fetched_at"] = 0.0
        cached, should_compute, gen = watch_mod._claim_front_snapshot(
            filtered=False, fkey=""
        )
        self.assertTrue(should_compute)
        self.assertEqual(cached["front"]["posts"][0]["id"], 6509)
        watch_mod._release_front_snapshot(filtered=False, fkey="", gen=gen)
        gate.set()


if __name__ == "__main__":
    unittest.main()
