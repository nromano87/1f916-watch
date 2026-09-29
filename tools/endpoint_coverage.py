#!/usr/bin/env python3
"""Endpoint coverage check against GET /api/surface.

The problem this exists for: every citizen-built window on this square drifts.
A new endpoint ships, the window keeps rendering the old shape, and nobody
notices until a human reads a stale page.

The fix is not "remember to update the window." It is to make the drift a red
build, measured against a contract the society publishes about itself
(GET /api/surface).

Two directions, both load-bearing:
  UNCOVERED  published by the society, absent here  -> the window fell behind
  STALE      declared here, no longer published     -> the window calls a ghost

Every entry that is deliberately not rendered must carry a `why`. An absence
with a reason is a decision; an absence without one is a bug wearing a
decision's clothes.

If /api/surface is unavailable this FAILS rather than falling back to the door.
A weaker source silently substituted for a stronger one is exactly the false
green this file exists to prevent.

Exit codes:
  0 — coverage current
  1 — uncovered / stale / unreasoned (drift)
  2 — could not fetch /api/surface (check did not run)
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "coverage" / "coverage.json"
ORIGIN = os.environ.get("SOCIETY_ORIGIN", "https://1f916.ai").rstrip("/")
_PARAM = re.compile(r":[A-Za-z_]\w*")


def normalize(path: str) -> str:
    return _PARAM.sub(":param", path)


def parse_surface(payload: Dict[str, Any]) -> Set[str]:
    out: Set[str] = set()
    for r in payload.get("routes") or []:
        if not isinstance(r, dict):
            continue
        method = r.get("method")
        path = r.get("path")
        if not method or not path:
            continue
        out.add("{} {}".format(method, normalize(str(path))))
    return out


def load_manifest(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def fetch_surface() -> Tuple[int, Any]:
    url = "{}/api/surface".format(ORIGIN)
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception as e:  # noqa: BLE001 — network failure is exit 2
        print("GET /api/surface failed: {}".format(e), file=sys.stderr)
        return 0, None


def check_path(root: Any, path: str) -> List[str]:
    """Resolve one field path against a response. Returns failure strings."""
    parts = path.split(".")
    cursors: List[Tuple[Any, str]] = [(root, "")]

    for raw_part in parts:
        is_array = raw_part.endswith("[]")
        key = raw_part[:-2] if is_array else raw_part
        nxt: List[Tuple[Any, str]] = []

        for value, at in cursors:
            if value is None or not isinstance(value, dict):
                return [
                    '{} — nothing at "{}" to read "{}" from'.format(
                        path, at or "(root)", key
                    )
                ]
            if key not in value:
                where = " under {}".format(at) if at else " at the top level"
                return ['{} — missing "{}"{}'.format(path, key, where)]
            child = value[key]
            child_at = "{}.{}".format(at, key) if at else key

            if is_array:
                if not isinstance(child, list):
                    kind = "null" if child is None else type(child).__name__
                    return [
                        '{} — "{}" is {}, expected an array'.format(
                            path, child_at, kind
                        )
                    ]
                for i, item in enumerate(child):
                    nxt.append((item, "{}[{}]".format(child_at, i)))
            else:
                nxt.append((child, child_at))

        cursors = nxt
        if not cursors:
            return []
    return []


def substitute(path: str) -> str:
    import time

    now = time.time()
    since = str(int(now * 1000) - 86_400_000)
    expiry30 = str(int(now) + 7 * 86_400)
    return path.replace("{{since24h}}", since).replace("{{expiry30d}}", expiry30)


def run_coverage(manifest_path: Path) -> int:
    status, payload = fetch_surface()
    if status != 200 or not isinstance(payload, dict):
        print(
            "GET /api/surface answered {}. Refusing to fall back to a weaker "
            "source — this is not a pass.".format(status or "error"),
            file=sys.stderr,
        )
        return 2

    surface = parse_surface(payload)
    manifest = load_manifest(manifest_path)
    endpoints = manifest.get("endpoints") or []
    declared: Dict[str, Dict[str, Any]] = {}
    for e in endpoints:
        key = "{} {}".format(e.get("method"), normalize(str(e.get("path"))))
        declared[key] = e

    uncovered = sorted(k for k in surface if k not in declared)
    stale = sorted(k for k in declared if k not in surface)
    unreasoned = [
        e
        for e in endpoints
        if e.get("surface") is None and not e.get("why")
    ]

    rendered = sum(1 for e in endpoints if e.get("surface") is not None)
    declined = len(endpoints) - rendered

    print(
        "society publishes: {}   this window declares: {}".format(
            len(surface), len(declared)
        )
    )
    print(
        "rendered here: {}   deliberately not rendered: {}\n".format(
            rendered, declined
        )
    )

    failed = False
    if uncovered:
        failed = True
        print(
            "UNCOVERED — published by the society, missing from this window ({}):".format(
                len(uncovered)
            ),
            file=sys.stderr,
        )
        for k in uncovered:
            print("  + {}".format(k), file=sys.stderr)
        print("", file=sys.stderr)
    if stale:
        failed = True
        print(
            "STALE — declared here, no longer published ({}):".format(len(stale)),
            file=sys.stderr,
        )
        for k in stale:
            print("  - {}".format(k), file=sys.stderr)
        print("", file=sys.stderr)
    if unreasoned:
        failed = True
        print(
            "UNREASONED — declared not-rendered with no `why` ({}):".format(
                len(unreasoned)
            ),
            file=sys.stderr,
        )
        for e in unreasoned:
            print(
                "  ? {} {}".format(e.get("method"), e.get("path")),
                file=sys.stderr,
            )
        print("", file=sys.stderr)

    if not failed:
        print("Coverage is current against everything the society publishes.")
        return 0
    return 1


def _fetch_smoke_body(url: str) -> Any:
    """GET one probe. A 429 is a rate limit, not a schema miss, so wait and retry."""
    import time

    delay = 1.0
    last_error: Optional[BaseException] = None
    for attempt in range(6):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "f916-watch",
                },
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            last_error = e
            if e.code not in (429, 503) or attempt == 5:
                raise
            retry_after = e.headers.get("Retry-After") if e.headers else None
            try:
                wait = float(retry_after) if retry_after else delay
            except (TypeError, ValueError):
                wait = delay
            time.sleep(min(max(wait, 0.5), 20.0))
            delay = min(delay * 2, 16.0)
    if last_error is not None:
        raise last_error
    raise RuntimeError(url)


def run_smoke(manifest_path: Path) -> int:
    """Fetch rendered endpoints and assert declared `requires` fields exist."""
    import time

    manifest = load_manifest(manifest_path)
    targets = [
        e
        for e in (manifest.get("endpoints") or [])
        if e.get("surface") is not None
        and isinstance(e.get("requires"), list)
        and e["requires"]
    ]

    failed = 0
    checked = 0
    for entry in targets:
        path = substitute(str(entry.get("probe") or entry.get("path")))
        url = "{}{}".format(ORIGIN, path)
        try:
            body = _fetch_smoke_body(url)
        except Exception as e:  # noqa: BLE001
            print(
                "FAIL {} {} — {} at {}".format(
                    entry.get("method"), entry.get("path"), e, path
                ),
                file=sys.stderr,
            )
            failed += 1
        else:
            checked += 1
            misses: List[str] = []
            for field in entry["requires"]:
                misses.extend(check_path(body, field))
            if misses:
                failed += 1
                print(
                    "FAIL {} {} — schema drift:".format(
                        entry.get("method"), entry.get("path")
                    ),
                    file=sys.stderr,
                )
                for m in misses:
                    print("  · {}".format(m), file=sys.stderr)
            else:
                print(
                    "ok {} {} ({} fields)".format(
                        entry.get("method"), entry.get("path"), len(entry["requires"])
                    )
                )
        time.sleep(0.2)

    print("\n{} endpoint(s) smoke-checked, {} failure(s).".format(checked, failed))
    return 1 if failed else 0


def main(argv: Optional[List[str]] = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    smoke = False
    if args and args[0] == "--smoke":
        smoke = True
        args = args[1:]
    manifest = Path(args[0]) if args else DEFAULT_MANIFEST
    if smoke:
        return run_smoke(manifest)
    return run_coverage(manifest)


if __name__ == "__main__":
    sys.exit(main())
