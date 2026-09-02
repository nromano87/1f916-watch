"""Parallel post_get helper for Watch front snapshots."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Optional, Sequence

from .client import ApiError, Client


def fetch_threads(
    client: Client,
    post_ids: Sequence[int],
    *,
    max_workers: int = 4,
) -> Dict[int, Dict]:
    threads: Dict[int, Dict] = {}
    if not post_ids:
        return threads
    stop = threading.Event()

    def _fetch(post_id: int) -> Optional[Dict]:
        if stop.is_set():
            return None
        try:
            return client.post_get(post_id, retry=False)
        except ApiError as e:
            if int(getattr(e, "status", 0) or 0) == 429:
                stop.set()
            return None

    workers = min(max_workers, len(post_ids)) or 1
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_fetch, pid): pid for pid in post_ids}
        for fut in as_completed(futs):
            if stop.is_set():
                break
            data = fut.result()
            if not data or not data.get("post"):
                continue
            threads[int(data["post"]["id"])] = data
    return threads
