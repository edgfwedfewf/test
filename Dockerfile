FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential git curl ca-certificates libssl-dev zlib1g-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/TelegramMessenger/MTProxy.git /tmp/MTProxy \
    && make -C /tmp/MTProxy \
    && install -m 0755 /tmp/MTProxy/objs/bin/mtproto-proxy /usr/local/bin/mtproto-proxy \
    && rm -rf /tmp/MTProxy

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY . .

# ── Plugins ───────────────────────────────────────────────────────────────────
# Downloads the plugin repository, extracts every valid plugin manifest (*.json
# with id + hooks) and moves them into plugins/installed/.
# Supports:
#   1. GitHub repo URL   https://github.com/<user>/<repo>
#   2. Direct ZIP URL    https://example.com/plugins.zip
#   3. Single JSON file  https://example.com/plugins.json
# Failures are non-fatal so a missing/broken repo can never break the build.
ARG PLUGIN_REPO_URL=""
ENV PLUGIN_REPO_URL=${PLUGIN_REPO_URL}
RUN mkdir -p plugins/installed && \
    python3 - <<'PYEOF'
import json, os, sys, zipfile, urllib.request, tempfile, pathlib

url = os.environ.get("PLUGIN_REPO_URL", "").strip()
if not url:
    print("plugins: no PLUGIN_REPO_URL set — skipping")
    sys.exit(0)

DEST = pathlib.Path("plugins/installed")
DEST.mkdir(parents=True, exist_ok=True)

MAX_BYTES = 16 * 1024 * 1024
HDRS = {"User-Agent": "Mozilla/5.0 (SpiderPanel)"}


def _is_manifest(data: dict) -> bool:
    return isinstance(data, dict) and bool(data.get("id")) and bool(data.get("hooks"))


def _install_json_bytes(raw: bytes, label: str) -> int:
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception:
        return 0
    count = 0
    candidates = obj if isinstance(obj, list) else [obj]
    for item in candidates:
        if not _is_manifest(item):
            continue
        pid = str(item["id"])
        (DEST / f"{pid}.json").write_bytes(
            json.dumps(item, ensure_ascii=False, indent=2).encode("utf-8"))
        count += 1
    if count:
        print(f"plugins: +{count} from {label}")
    return count


def _install_zip(raw: bytes, label: str) -> int:
    count = 0
    with tempfile.TemporaryDirectory() as td:
        zp = pathlib.Path(td, "r.zip")
        zp.write_bytes(raw)
        with zipfile.ZipFile(zp) as zf:
            zf.extractall(pathlib.Path(td, "x"))
        for jf in pathlib.Path(td, "x").rglob("*.json"):
            try:
                count += _install_json_bytes(jf.read_bytes(), str(jf.name))
            except Exception:
                pass
    if count:
        print(f"plugins: +{count} manifests from {label}")
    return count


def _fetch(u: str) -> bytes:
    req = urllib.request.Request(u, headers=HDRS)
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read(MAX_BYTES)


total = 0
try:
    if "github.com/" in url and not url.endswith((".zip", ".json")):
        # Normalise github.com/... -> github.com/... and try main then master
        base = url.rstrip("/").removesuffix(".git")
        for branch in ("main", "master"):
            zip_url = f"{base}/archive/refs/heads/{branch}.zip"
            try:
                raw = _fetch(zip_url)
                total += _install_zip(raw, zip_url)
                break
            except Exception as exc:
                print(f"plugins: {zip_url} -> {exc}")
    elif url.endswith(".zip"):
        total += _install_zip(_fetch(url), url)
    else:
        total += _install_json_bytes(_fetch(url), url)
except Exception as exc:
    print(f"plugins: repo download skipped ({exc})")

print(f"plugins: {total} installed into {DEST}")
PYEOF

# Keep the bundled set visible in /data as well, so a mounted state volume
# still ships with the built-in plugins.
RUN mkdir -p /data/plugins/bundled /data/plugins/installed /data/plugins/user && \
    cp -n plugins/bundled/*.json /data/plugins/bundled/ 2>/dev/null || true

RUN python -m py_compile main.py


# SpiderPanel panel port is fixed at 8080.
EXPOSE 8080
EXPOSE 443

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
