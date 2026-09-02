"""Pull/push Human chat against the live Fly volume (localhost operator only)."""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

_FLY_DUMP_PY = r"""
import json, os
root = os.environ.get("F916_HOME", "/data")
path = os.path.join(root, "public_chat.json")
data = {}
try:
    with open(path, "r", encoding="utf-8") as fh:
        loaded = json.load(fh)
    if isinstance(loaded, dict):
        data = loaded
except (OSError, json.JSONDecodeError):
    data = {}
print(json.dumps(data, separators=(",", ":")))
"""

_FLY_WRITE_PY = r"""
import base64, fcntl, json, os
root = os.environ.get("F916_HOME", "/data")
data = json.loads(base64.b64decode("__PAYLOAD__").decode("utf-8"))
if not isinstance(data, dict):
    raise SystemExit("payload was not an object")
path = os.path.join(root, "public_chat.json")
lock_path = os.path.join(root, "public_chat.lock")
tmp = path + ".push-tmp"
os.makedirs(root, exist_ok=True)
with open(lock_path, "a+", encoding="utf-8") as lockf:
    fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
print("ok")
"""

_RESTART_LOCK = threading.Lock()
_RESTART_TIMER: Optional[threading.Timer] = None


def mirror_from_env() -> bool:
    """False when the operator opted into this machine's F916_HOME only."""
    raw = (os.environ.get("F916_ADMIN_SOURCE") or "fly").strip().lower()
    return raw not in ("local", "here", "disk", "home")


def fly_app() -> str:
    return (
        os.environ.get("F916_ADMIN_FLY_APP")
        or os.environ.get("FLY_APP")
        or "f916-watch"
    ).strip() or "f916-watch"


def _fly_bin() -> str:
    for name in ("fly", "flyctl"):
        found = shutil.which(name)
        if found:
            return found
    home_bin = Path.home() / ".fly" / "bin"
    for name in ("fly", "flyctl"):
        candidate = home_bin / name
        if candidate.is_file():
            return str(candidate)
    return "fly"


def _fly_env() -> Dict[str, str]:
    env = os.environ.copy()
    env.setdefault("FLY_NO_UPDATE_CHECK", "1")
    return env


def _run_remote_python(script: str, *, timeout: float = 60.0) -> subprocess.CompletedProcess:
    fly = _fly_bin()
    b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
    remote = "python3 -c 'import base64; exec(base64.b64decode(\"{}\").decode())'".format(
        b64
    )
    return subprocess.run(
        [fly, "ssh", "console", "-a", fly_app(), "-C", remote],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=_fly_env(),
    )


def fetch_fly_chat() -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Return (public_chat.json object, error)."""
    try:
        proc = _run_remote_python(_FLY_DUMP_PY, timeout=60.0)
    except FileNotFoundError:
        return None, "flyctl not found"
    except subprocess.TimeoutExpired:
        return None, "fly ssh timed out"
    except OSError as e:
        return None, str(e)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "fly ssh failed").strip().splitlines()
        hint = err[-1] if err else "fly ssh failed"
        return None, hint[:240]
    raw = (proc.stdout or "").strip()
    if not raw:
        return None, "empty fly ssh stdout"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find("{")
        end = raw.rfind("}")
        if start < 0 or end <= start:
            return None, "bad fly dump"
        try:
            data = json.loads(raw[start : end + 1])
        except json.JSONDecodeError as e:
            return None, "bad fly dump: {}".format(e)
    if not isinstance(data, dict):
        return None, "fly dump was not an object"
    return data, None


def push_fly_chat(data: Dict[str, Any]) -> Optional[str]:
    """Write public_chat.json on the live volume. None on success."""
    blob = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    payload = base64.b64encode(blob).decode("ascii")
    script = _FLY_WRITE_PY.replace("__PAYLOAD__", payload)
    try:
        proc = _run_remote_python(script, timeout=90.0)
    except FileNotFoundError:
        return "flyctl not found"
    except subprocess.TimeoutExpired:
        return "fly ssh timed out"
    except OSError as e:
        return str(e)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "fly ssh failed").strip().splitlines()
        hint = err[-1] if err else "fly ssh failed"
        return hint[:240]
    out = (proc.stdout or "").strip().splitlines()
    if not out or out[-1].strip() != "ok":
        return "fly write did not confirm"
    return None


def _restart_now() -> None:
    fly = _fly_bin()
    app = fly_app()
    try:
        proc = subprocess.run(
            [fly, "apps", "restart", app],
            capture_output=True,
            text=True,
            timeout=120.0,
            env=_fly_env(),
        )
    except Exception as e:  # pragma: no cover
        print("  chat: fly restart failed: {}".format(e))
        return
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "restart failed").strip().splitlines()
        hint = err[-1] if err else "restart failed"
        print("  chat: fly restart failed: {}".format(hint[:240]))
        return
    print("  chat: restarted {} so prod reloads the guestbook".format(app))


def schedule_fly_restart(*, delay: float = 4.0) -> None:
    """Bounce the live app after a short idle so several removes share one restart."""
    global _RESTART_TIMER
    with _RESTART_LOCK:
        if _RESTART_TIMER is not None:
            _RESTART_TIMER.cancel()
        timer = threading.Timer(max(1.0, delay), _restart_now)
        timer.daemon = True
        _RESTART_TIMER = timer
        timer.start()
