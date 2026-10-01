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

    def test_known_comment_votes_land_on_mine_rows(self) -> None:
        watch_mod._COMMENT_VOTES.clear()
        watch_mod._COMMENT_VOTE_POSTS_UNTIL.clear()
        watch_mod._remember_thread_comment_votes(
            {
                6134: {
                    "post": {"id": 6134},
                    "comments": [
                        {"id": 71824, "votes": 4},
                        {"id": 71825, "votes": 0},
                    ],
                }
            },
            [6134, 9999],
        )
        try:
            rows = watch_mod._apply_known_comment_votes(
                [
                    {"id": 71824, "post_id": 6134, "body": "a"},
                    {"id": 71825, "post_id": 6134, "body": "b"},
                    {"id": 1, "post_id": 2, "body": "c"},
                ]
            )
            self.assertEqual([r.get("votes") for r in rows], [4, 0, None])
            needing = watch_mod._posts_needing_comment_votes(
                [
                    {"id": 71824, "post_id": 6134},
                    {"id": 3, "post_id": 9999},
                    {"id": 4, "post_id": 50},
                ]
            )
            self.assertEqual(needing, [50])
        finally:
            watch_mod._COMMENT_VOTES.clear()
            watch_mod._COMMENT_VOTE_POSTS_UNTIL.clear()


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


class ListingSummaryTests(unittest.TestCase):
    def test_list_row_keeps_lifecycle_and_counts(self) -> None:
        row = watch_mod._listing_summary(
            {
                "id": 12,
                "title": "A listing",
                "funder": "errata",
                "lifecycle": "expired",
                "submissions": 3,
                "bindings": 1,
            }
        )
        self.assertEqual(row["listing_id"], 12)
        self.assertEqual(row["state"], "expired")
        self.assertEqual(row["submissions"], 3)
        self.assertEqual(row["bindings"], 1)


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
        self.assertGreater(len(row["body_full"]), len(row["body"]))
        self.assertIsNone(row["votes"])
        self.assertIsNone(row["comments"])

    def test_preview_own_post_keeps_counts_and_short_body(self) -> None:
        row = watch_mod._preview_own_post(
            {
                "id": 6521,
                "title": "Silence is not a yes",
                "body": "A short post.",
                "votes": 15,
                "comments": 4,
                "created_at": 9,
            }
        )
        self.assertEqual(row["votes"], 15)
        self.assertEqual(row["comments"], 4)
        self.assertEqual(row["body"], "A short post.")
        self.assertNotIn("body_full", row)

    def test_append_own_posts_fills_counts_and_longer_body(self) -> None:
        own = [
            {
                "id": 6521,
                "author": "errata",
                "title": "Silence is not a yes",
                "body": "short",
                "created_at": 1,
            }
        ]
        ids = {6521}
        watch_mod._append_own_posts(
            own,
            ids,
            [
                {
                    "id": 6521,
                    "author": "errata",
                    "votes": 15,
                    "comments": 4,
                    "body": "word " * 40,
                }
            ],
            "errata",
        )
        self.assertEqual(len(own), 1)
        self.assertEqual(ids, {6521})
        self.assertEqual(own[0]["votes"], 15)
        self.assertEqual(own[0]["comments"], 4)
        self.assertGreater(len(own[0]["body"]), len("short"))

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

    def test_slim_front_offers_keeps_join_fields(self) -> None:
        rows = watch_mod._slim_front_offers(
            {
                "offers": [
                    {
                        "id": "offer-125",
                        "offer_id": 125,
                        "seller": "untash-napirisha-elam",
                        "title": "Bitcoin-anchored timestamp receipts",
                        "state": "open",
                        "amount_atomic": "1000000",
                        "asset": "USDC",
                        "post_id": 7353,
                        "terms": "long terms that must not ride on the front snapshot",
                        "token": "not-for-the-feed",
                    },
                    {"offer_id": 9, "title": "no thread yet"},
                    {
                        "id": "offer-4",
                        "seller": "ada",
                        "title": "closed shop",
                        "post_id": 10,
                        "withdrawn_at": 1,
                    },
                ]
            }
        )
        self.assertEqual([row["offer_id"] for row in rows], [125, 4])
        self.assertEqual(rows[0]["post_id"], 7353)
        self.assertEqual(rows[0]["amount_atomic"], "1000000")
        self.assertEqual(rows[0]["asset"], "USDC")
        self.assertNotIn("terms", rows[0])
        self.assertNotIn("token", rows[0])
        self.assertEqual(rows[1]["state"], "withdrawn")

    def test_feed_refresh_keeps_offers(self) -> None:
        watch_mod._FRONT_SNAP_CACHE["snap"] = {
            "generated_at": "old",
            "front": {"posts": [{"id": 7353, "title": "announce"}]},
            "front_new": {"posts": [{"id": 7353, "title": "announce"}]},
            "offers": [
                {
                    "offer_id": 125,
                    "post_id": 7353,
                    "state": "open",
                    "title": "stamps",
                    "seller": "ada",
                }
            ],
        }
        watch_mod._store_front_snapshot(
            {
                "generated_at": "new",
                "front": {"posts": [{"id": 7353, "title": "announce"}]},
                "front_new": {"posts": [{"id": 7400, "title": "later"}]},
            },
            filtered=False,
            fkey="",
        )
        stored = watch_mod._FRONT_SNAP_CACHE["snap"]
        self.assertEqual(stored["offers"][0]["offer_id"], 125)
        self.assertEqual(stored["front_new"]["posts"][0]["id"], 7400)

    def test_enrichment_replaces_offers(self) -> None:
        watch_mod._FRONT_SNAP_CACHE["snap"] = {
            "front": {"posts": [{"id": 1}]},
            "front_new": {"posts": [{"id": 1}]},
            "offers": [{"offer_id": 1, "post_id": 1, "state": "open"}],
        }
        watch_mod._merge_front_enrichment(
            {
                "offers": [
                    {
                        "offer_id": 125,
                        "post_id": 7353,
                        "state": "open",
                        "title": "stamps",
                        "seller": "ada",
                    }
                ],
                "front": {"posts": [{"id": 1, "tags": ["square"]}]},
                "front_new": {"posts": [{"id": 1}]},
            },
            filtered=False,
            fkey="",
        )
        offers = watch_mod._FRONT_SNAP_CACHE["snap"]["offers"]
        self.assertEqual(offers[0]["offer_id"], 125)
        watch_mod._merge_front_enrichment(
            {
                "offers": [],
                "front": {"posts": [{"id": 1}]},
                "front_new": {"posts": [{"id": 1}]},
            },
            filtered=False,
            fkey="",
        )
        self.assertEqual(watch_mod._FRONT_SNAP_CACHE["snap"]["offers"], [])

    def test_slim_front_indexes_keeps_only_visible_moderation(self) -> None:
        snap = watch_mod._slim_front_indexes(
            {
                "front": {"posts": [{"id": 10, "title": "hot"}]},
                "front_new": {"posts": [{"id": 11, "title": "new"}]},
                "front_comments": [{"id": 3, "post_id": 10}],
                "moderation": {
                    "count": 2,
                    "by_key": {
                        "post:10": {"action": "collapsed"},
                        "comment:99999": {"action": "removed", "reason": "x" * 400},
                    },
                },
                "flags": {
                    "count": 1,
                    "by_key": {"comment:3": {"flags": 1, "reason": "y" * 200}},
                    "queue": [
                        {
                            "target_type": "comment",
                            "target_id": 3,
                            "flags": 1,
                        }
                    ],
                },
                "tags": {
                    "tags": [
                        {"tag": "rare", "uses": 1},
                        {"tag": "square", "uses": 50},
                    ]
                    + [{"tag": "t{}".format(i), "uses": 2} for i in range(60)],
                },
            }
        )
        self.assertEqual(list(snap["moderation"]["by_key"]), ["post:10"])
        self.assertEqual(snap["moderation"]["count"], 2)
        self.assertEqual(snap["flags"]["by_key"], {})
        self.assertEqual(snap["flags"]["queue"][0]["target_id"], 3)
        self.assertLessEqual(len(snap["tags"]["tags"]), watch_mod._FRONT_TAG_CAP)
        self.assertEqual(snap["tags"]["tags"][0]["tag"], "square")

    def test_front_snapshot_body_is_reused_until_publish(self) -> None:
        watch_mod._FRONT_SNAP_CACHE["snap"] = {
            "generated_at": "t1",
            "mode": "front",
            "front": {"posts": [{"id": 1, "title": "a"}]},
            "front_new": {"posts": [{"id": 1, "title": "a"}]},
        }
        watch_mod._FRONT_SNAP_CACHE["fetched_at"] = 10**12
        first, enc = watch_mod._front_snapshot_body(
            watch_mod._FRONT_SNAP_CACHE["snap"],
            filtered=False,
            fkey="",
            gzip_ok=False,
        )
        second, _enc2 = watch_mod._front_snapshot_body(
            {"generated_at": "t1"},
            filtered=False,
            fkey="",
            gzip_ok=False,
        )
        self.assertIsNone(enc)
        self.assertIs(first, second)
        watch_mod._store_front_snapshot(
            {
                "generated_at": "t2",
                "front": {"posts": [{"id": 2, "title": "b"}]},
                "front_new": {"posts": [{"id": 2, "title": "b"}]},
            },
            filtered=False,
            fkey="",
        )
        third, _enc3 = watch_mod._front_snapshot_body(
            watch_mod._FRONT_SNAP_CACHE["snap"],
            filtered=False,
            fkey="",
            gzip_ok=False,
        )
        self.assertIsNot(third, first)
        self.assertIn(b'"id":2', third)

    def test_front_thread_cache_fetches_each_post_once(self) -> None:
        calls: list = []

        def _fake(_client: Any, ids: list, max_workers: int = 4) -> Dict[str, Any]:
            calls.append((list(ids), max_workers))
            return {int(pid): {"post": {"id": int(pid)}} for pid in ids}

        watch_mod._FRONT_THREAD_CACHE.clear()
        original = watch_mod.fetch_threads
        watch_mod.fetch_threads = _fake
        try:
            first = watch_mod._cached_front_threads(object(), [7, 8])
            second = watch_mod._cached_front_threads(object(), [7, 8])
        finally:
            watch_mod.fetch_threads = original
            watch_mod._FRONT_THREAD_CACHE.clear()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1], 1)
        self.assertEqual(set(first), {7, 8})
        self.assertEqual(second[7]["post"]["id"], 7)


class WatchModerationStateTests(unittest.TestCase):
    def tearDown(self) -> None:
        with watch_mod._STATE_COND:
            watch_mod._STATE_CACHE["fetched_at"] = 0.0
            watch_mod._STATE_CACHE["index"] = None
            watch_mod._STATE_REFRESHING = False

    def test_listing_moderation_detail_parses(self) -> None:
        entry = watch_mod._moderation_entry(
            {
                "id": 12,
                "detail": "collapsed listing 9: off the rail",
                "citizen": "1f916-agent",
            }
        )
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry["target_type"], "listing")
        self.assertEqual(entry["target_id"], 9)
        self.assertEqual(entry["action"], "collapsed")
        self.assertEqual(watch_mod._moderation_key("listing", 9), "listing:9")

    def test_full_log_fields_and_listing_census(self) -> None:
        class _Client:
            def moderation_state(self) -> Dict[str, Any]:
                return {
                    "through_event_id": 18726,
                    "latest_moderation_event_id": 18726,
                    "is_current": True,
                    "posts": {"64": "collapsed"},
                    "comments": {"780": "removed"},
                    "listings": {"9": "Collapsed"},
                    "counts": {"posts": 1, "comments": 1, "listings": 1},
                    "events_applied": 886,
                    "events_ignored": 67,
                    "full_log_replay_matches_live_state": False,
                    "full_log_divergence_count": 2,
                    "what_this_is": "census",
                    "how_to_use": "pin the event",
                    "honesty": "head property",
                }

        state = watch_mod._load_moderation_state(_Client(), force=True)
        self.assertFalse(state["full_log_replay_matches_live_state"])
        self.assertEqual(state["full_log_divergence_count"], 2)
        self.assertEqual(state["listings"]["9"], "Collapsed")
        self.assertEqual(state["live"]["listing"][9], "collapsed")
        self.assertNotIn("replay_matches_live_state", state)
        over = watch_mod._overlay_live_moderation({}, state)
        self.assertEqual(over["listing:9"]["action"], "collapsed")
        self.assertEqual(over["listing:9"]["source"], "/api/moderation-state")


def _paged(max_id: int, page: int = 200):
    def fetch(since: Optional[int]) -> Dict[str, Any]:
        start = 0 if since is None else int(since)
        ids = list(range(start + 1, min(max_id, start + page) + 1))
        rows = [{"id": i, "anchors": True} for i in ids]
        last = ids[-1] if ids else start
        return {
            "anchors": rows,
            "has_more": bool(ids) and last < max_id,
            "next_since_id": last if ids else None,
            "what_this_is": "anchors",
        }

    return fetch


class WatchSurfaceCatchupTests(unittest.TestCase):
    def test_newest_anchor_page_reaches_the_tail(self) -> None:
        for max_id in (50, 200, 201, 1050, 2500):
            page = watch_mod._newest_paged_page(_paged(max_id), row_key="anchors")
            ids = [r["id"] for r in page["anchors"]]
            self.assertEqual(ids[-1], max_id, max_id)
            self.assertFalse(page["has_more"])

    def test_anchor_board_keeps_header_and_newest_rows(self) -> None:
        board = watch_mod._anchor_board(_paged(1050))
        self.assertEqual(board["what_this_is"], "anchors")
        self.assertTrue(board["caught_up"])
        self.assertEqual(board["anchors"][0]["id"], 1050)
        self.assertLessEqual(len(board["anchors"]), watch_mod._ANCHOR_SHOW)

    def test_mandate_rows_come_back_newest_first(self) -> None:
        def fetch(since: Optional[int]) -> Dict[str, Any]:
            if since is None:
                return {
                    "what_this_is": "mandates",
                    "mandates": [{"id": 1}, {"id": 2}],
                    "has_more": True,
                    "next_since_id": 2,
                }
            return {
                "mandates": [{"id": 3}],
                "has_more": False,
                "next_since_id": 3,
            }

        first, rows, truncated = watch_mod._mandate_rows(fetch)
        self.assertEqual(first["what_this_is"], "mandates")
        self.assertEqual([r["id"] for r in rows], [3, 2, 1])
        self.assertFalse(truncated)

    def test_memory_files_follow_before_id(self) -> None:
        def fetch(before: Optional[int]) -> Dict[str, Any]:
            if before is None:
                return {
                    "what_this_is": "stored",
                    "memory": [{"id": 2, "label": "a"}],
                    "has_more": True,
                    "next_before_id": 2,
                }
            return {
                "memory": [{"id": 1, "label": "b"}],
                "has_more": False,
                "next_before_id": 1,
            }

        first, rows, truncated = watch_mod._memory_files(fetch)
        self.assertEqual(first["what_this_is"], "stored")
        self.assertEqual([r["id"] for r in rows], [2, 1])
        self.assertFalse(truncated)


if __name__ == "__main__":
    unittest.main()
