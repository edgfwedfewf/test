"""
SpiderPanel Plugin Engine  (apiVersion: spiderpanel.plugin/v1)

Self-contained, dependency-free. Imports nothing from `main` so it can be
unit-tested and reloaded on its own.

WHAT A PLUGIN IS
----------------
A plugin is ONE plain JSON file. No Python, no rebuild needed for behaviour:
the panel reads these files at startup and applies their rules to the objects
it produces (client configs, inbounds, users, settings, xray server config).

Manifest shape
--------------
{
  "apiVersion": "spiderpanel.plugin/v1",
  "id":        "tls-server-chatgpt",        # unique, [a-z0-9._-]
  "name":      "TLS server -> chatgpt.com",
  "description": "one-line summary",         # REQUIRED (max 400 chars)
  "details":   ["longer explanation...",     # optional, shown inside the
                 "more context..."],          # accordion body (string or list)
  "version":   "1.0.0",
  "author":    "amir",
  "enabledByDefault": false,
  "minPanelVersion":  "8.0",
  "hooks": {
     "config":     [ <rule>, ... ],   # every generated client config string
     "inbound":    [ <rule>, ... ],   # inbound dicts on create/update
     "user":       [ <rule>, ... ],   # user dicts on create/update
     "settings":   [ <rule>, ... ],   # panel settings dict on read
     "xray":       [ <rule>, ... ],   # xray server config.json dict
     "subscription": [ <rule>, ... ]  # the whole subscription text
  }
}

  * `description` is MANDATORY — a manifest without it fails validation, so the
    panel can always render a meaningful accordion row.
  * `details` is optional and carries the long explanation (bullet list).

RULE SHAPE
----------
{
  "match": { ... },        # optional. ALL keys must match, else rule skipped
  "set":   { ... },        # set fields / query params (supports {placeholders})
  "remove": [ "alpn" ],    # drop fields / query params
  "rename": { "from": "to" }   # rename a field / query param
}

`match` / `set` work on two object kinds:

  * config STRINGS  -> match/set address the URL:
        "scheme", "server" (host part of the authority), "port", "uuid",
        "remark", and any query param: "security", "type", "sni", "host",
        "path", "fp", "alpn", "mode", ...
        Plus two write-only targets in `set`:
        "server"  -> the authority host (the address the client connects to)
        "port"    -> the authority port

  * dict OBJECTS    -> dotted paths are supported:
        "reality_settings.sni", "ws_settings.path", "domain", ...

CONDITIONS
----------
  * value        : string / number / bool  -> equality
  * list of them : OR  ("security": ["tls", "reality"])
  * key ending in "~"  : regex search      ("path~": "^/ws/")
  * "*"                : always matches
  * "exists": ["a","b"] : field must be present
  * "missing": ["a"]    : field must be absent

PLACEHOLDERS in `set` values: {server} {port} {uuid} {remark} {scheme}
{security} {type} {sni} {path} {host} or {any.other.field}  -> current value.
A missing placeholder leaves the text untouched.

SAFETY
------
  * a file is ignored (never crash the panel) if it is not valid JSON,
    bigger than MAX_FILE_BYTES, or fails schema validation
  * rules that raise are skipped and logged, the panel keeps working
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, quote

API_VERSION = "spiderpanel.plugin/v1"
HOOKS = ("config", "inbound", "user", "settings", "xray", "subscription")
MAX_FILE_BYTES = 256 * 1024
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_SAFE_FMT = re.compile(r"\{([a-z0-9_.]{1,40})\}")

# ---------------------------------------------------------------- validation


def _is_rule(r) -> bool:
    if not isinstance(r, dict):
        return False
    for k in ("match", "when", "set", "params", "remove", "rename"):
        if k in r:
            return True
    return False


def validate_manifest(raw, source: str = "") -> list[str]:
    """Return a list of human-readable errors. Empty list == plugin is good."""
    errs: list[str] = []
    where = f"[{source}] " if source else ""

    if not isinstance(raw, dict):
        return [f"{where}manifest must be a JSON object"]

    av = str(raw.get("apiVersion") or raw.get("api_version") or "")
    if av and av != API_VERSION:
        errs.append(f"{where}apiVersion {av!r} is not supported (expected {API_VERSION!r})")
    if not av:
        errs.append(f"{where}missing apiVersion ({API_VERSION})")

    pid = raw.get("id")
    if not pid:
        errs.append(f"{where}missing id")
    elif not ID_RE.match(str(pid)):
        errs.append(f"{where}id {pid!r} must match {ID_RE.pattern}")

    if not raw.get("name"):
        errs.append(f"{where}missing name")

    # Every plugin MUST carry a description so the panel can always show what a
    # plugin does in its accordion. `details` is the optional long version.
    desc = raw.get("description")
    if not desc or not str(desc).strip():
        errs.append(f"{where}missing description (every plugin must explain what it does)")
    elif len(str(desc)) > 400:
        errs.append(f"{where}description is too long (max 400 chars, use `details` for the long text)")
    if "details" in raw and not isinstance(raw["details"], (str, list)):
        errs.append(f"{where}details must be a string or an array of strings")

    hooks = raw.get("hooks")
    if not isinstance(hooks, dict) or not hooks:
        errs.append(f"{where}hooks must be a non-empty object")
        return errs

    unknown = [k for k in hooks if k not in HOOKS]
    if unknown:
        errs.append(f"{where}unknown hook(s): {', '.join(sorted(unknown))} "
                    f"(valid: {', '.join(HOOKS)})")
    for name, rules in hooks.items():
        if name not in HOOKS:
            continue
        if not isinstance(rules, list):
            errs.append(f"{where}hooks.{name} must be an array")
            continue
        if not rules:
            errs.append(f"{where}hooks.{name} is empty")
        for i, r in enumerate(rules):
            if not _is_rule(r):
                errs.append(f"{where}hooks.{name}[{i}] needs at least one of "
                            "match / set / remove / rename")
                continue
            for key in ("match", "when"):
                if key in r and not isinstance(r[key], (dict, str)):
                    errs.append(f"{where}hooks.{name}[{i}].{key} must be an object")
            for key in ("set", "params", "rename"):
                if key in r and not isinstance(r[key], dict):
                    errs.append(f"{where}hooks.{name}[{i}].{key} must be an object")
            for key in ("remove",):
                if key in r and not isinstance(r[key], list):
                    errs.append(f"{where}hooks.{name}[{i}].remove must be an array")
    return errs


# ---------------------------------------------------------------- registry


class Plugin:
    __slots__ = ("id", "name", "version", "author", "description", "details",
                 "enabled", "readonly", "source", "hooks", "min_panel_version",
                 "enabled_by_default", "raw", "error")

    def __init__(self, raw: dict, source: str, enabled: bool, readonly: bool = False):
        self.id = str(raw["id"])
        self.name = str(raw.get("name") or self.id)
        self.version = str(raw.get("version") or "0.0.0")
        self.author = str(raw.get("author") or "")
        self.description = str(raw.get("description") or "")
        self.details = raw.get("details") or []
        if isinstance(self.details, str):
            self.details = [self.details]
        self.min_panel_version = str(raw.get("minPanelVersion") or "")
        self.enabled_by_default = bool(raw.get("enabledByDefault", False))
        self.hooks = raw.get("hooks") or {}
        self.raw = raw
        self.source = source
        self.enabled = enabled
        self.readonly = readonly
        self.error = ""

    def rules(self, hook: str) -> list:
        r = self.hooks.get(hook)
        return r if isinstance(r, list) else []

    def public(self) -> dict:
        return {
            "id": self.id, "name": self.name, "version": self.version,
            "author": self.author, "description": self.description,
            "details": self.details,
            "enabled": self.enabled, "enabledByDefault": self.enabled_by_default,
            "readonly": self.readonly, "source": self.source,
            "hooks": sorted(self.hooks.keys()),
            "ruleCount": sum(len(v) for v in self.hooks.values() if isinstance(v, list)),
            "minPanelVersion": self.min_panel_version,
            "error": self.error,
        }


class Registry:
    """In-memory set of loaded plugins. Reload is atomic (swap the dict)."""

    def __init__(self):
        self.plugins: dict[str, Plugin] = {}
        self.errors: list[str] = []
        self.loaded_at = ""

    # -- loading ---------------------------------------------------------
    def load_dir(self, directory: Path, state: dict | None = None,
                 replace: bool = True) -> dict:
        state = state or {}
        found: dict[str, Plugin] = {}
        errs: list[str] = []
        directory = Path(directory)
        files = sorted(directory.glob("*.json")) if directory.is_dir() else []
        for path in files:
            try:
                size = path.stat().st_size
                if size > MAX_FILE_BYTES:
                    errs.append(f"{path.name}: file too large ({size} bytes)")
                    continue
                raw = json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:                                   # noqa: BLE001
                errs.append(f"{path.name}: {type(exc).__name__}: {exc}")
                continue
            bad = validate_manifest(raw, path.name)
            if bad:
                errs.extend(bad)
                continue
            pid = str(raw["id"])
            if pid in found:
                errs.append(f"{path.name}: duplicate id {pid!r} — ignored")
                continue
            enabled = state[pid] if pid in state else bool(raw.get("enabledByDefault", False))
            ro = bool(raw.get("readonly", False))
            found[pid] = Plugin(raw, str(path), bool(enabled), ro)
        if replace:
            self.plugins = found
            self.errors = errs
        else:
            self.plugins.update(found)
            self.errors = (self.errors + errs)[-50:]
        return {
            "loaded": len(found),
            "enabled": sum(1 for p in found.values() if p.enabled),
            "errors": errs,
            "files": [p.name for p in files],
        }

    def get(self, pid: str):
        return self.plugins.get(str(pid))

    def list_public(self) -> list:
        return [p.public() for p in sorted(self.plugins.values(), key=lambda x: x.id)]

    def active(self, hook: str) -> list:
        return [p for p in sorted(self.plugins.values(), key=lambda x: x.id)
                if p.enabled and p.rules(hook)]

    # -- application -----------------------------------------------------
    def apply_hook(self, hook: str, value, ctx: dict | None = None):
        """Run every enabled plugin's rules for `hook` over `value`.

        `value` is a str (config / subscription) or a dict (inbound / user /
        settings / xray). Returns the possibly-modified value. Never raises.
        """
        if value is None:
            return value
        plugins = self.active(hook)
        if not plugins:
            return value
        # dict hooks get one working copy, mutated in place by each rule
        work = value if isinstance(value, str) else json.loads(json.dumps(value, default=str))
        applied = 0
        for plugin in plugins:
            for rule in plugin.rules(hook):
                try:
                    if isinstance(work, str):
                        new = _apply_rule_str(work, rule, ctx or {})
                    else:
                        new = _apply_rule_obj(work, rule, ctx or {})
                    if new is not None and new != work:
                        work = new
                        applied += 1
                except Exception as exc:                              # noqa: BLE001
                    _log(f"plugin {plugin.id} hook {hook} skipped: {type(exc).__name__}: {exc}")
        if applied and ctx is not None:
            ctx.setdefault("_plugins", []).append([p.id for p in plugins if p.rules(hook)])
        return work


# ------------------------------------------------------------------ helpers
_LOGGED: set[str] = set()


def _log(msg: str) -> None:
    if msg in _LOGGED:
        return
    _LOGGED.add(msg)
    try:
        import logging
        logging.getLogger("spider.plugins").warning(msg)
    except Exception:                                                  # pragma: no cover
        pass


def _get_path(obj, path: str):
    cur = obj
    for part in str(path).split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None, False
    return cur, True


def _set_path(obj, path: str, value) -> None:
    parts = str(path).split(".")
    cur = obj
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value


def _del_path(obj, path: str) -> None:
    parts = str(path).split(".")
    cur = obj
    for part in parts[:-1]:
        if not isinstance(cur, dict) or part not in cur:
            return
        cur = cur[part]
    if isinstance(cur, dict):
        cur.pop(parts[-1], None)


def _match_one(actual, expected) -> bool:
    if expected == "*":
        return True
    if isinstance(expected, list):
        return any(_match_one(actual, e) for e in expected)
    if isinstance(expected, bool) or isinstance(expected, (int, float)):
        return str(actual).strip().lower() == str(expected).strip().lower()
    return str(actual if actual is not None else "").strip().lower() == str(expected).strip().lower()


def _expand(match: dict) -> dict:
    """Normalise a match block: 'or' / 'and' groups + regex keys."""
    out = {"and": [], "or": []}
    if not isinstance(match, dict):
        return out
    for key, val in match.items():
        if key == "and" and isinstance(val, dict):
            out["and"].append(_expand(val))
        elif key == "or" and isinstance(val, list):
            for sub in val:
                if isinstance(sub, dict):
                    out["or"].append(_expand(sub))
        elif key == "exists" and isinstance(val, list):
            out["and"].append({"__exists__": val})
        elif key == "missing" and isinstance(val, list):
            out["and"].append({"__missing__": val})
        else:
            out["and"].append({key: val})
    return out


def _test(exp, fields) -> bool:
    """fields: callable(name) -> (value, present)"""
    for group in exp["and"]:
        for key, val in group.items():
            if key == "__exists__":
                if not all(fields(v)[1] for v in val):
                    return False
                continue
            if key == "__missing__":
                if any(fields(v)[1] for v in val):
                    return False
                continue
            if key.endswith("~"):
                actual = str(fields(key[:-1])[0] or "")
                try:
                    if not re.search(str(val), actual, re.I):
                        return False
                except re.error:
                    return False
                continue
            if key.endswith("$eq"):
                if str(val) != str(fields(key[:-3])[0] or ""):
                    return False
                continue
            if key.endswith("$ne"):
                if str(val) == str(fields(key[:-3])[0] or ""):
                    return False
                continue
            if key.endswith("$in"):
                actual = str(fields(key)[0] or "")
                opts = val if isinstance(val, list) else [val]
                if not any(actual == str(o).strip() for o in opts):
                    return False
                continue
            actual, present = fields(key)
            if not present and val not in (None, "", "*"):
                return False
            if not _match_one(actual, val):
                return False
    if exp["or"]:
        return any(_test(g, fields) for g in exp["or"])
    return True


def _fmt(value, fields) -> str:
    """Replace {placeholders} using live field values."""
    if not isinstance(value, str) or "{" not in value:
        return value

    def sub(m):
        got = fields(m.group(1))[0]
        return str(got) if got not in (None, "") else m.group(0)

    return _SAFE_FMT.sub(sub, value)


# ------------------------------------------------------------ config strings

_SCHEME_PORT_DEFAULT = {"vless": "443", "vmess": "443", "trojan": "443",
                        "ss": "443", "shadowsocks": "443"}

# Characters that stay readable inside a query value (RFC3986 unreserved plus
# the delimiters that are safe in a query). Deliberately EXCLUDED:
#   &  -> would split the query into a new pair
#   +  -> parse_qsl decodes '+' as space
#   #  -> would start the fragment
#   %  -> must be re-encoded so an existing %2F is not double-read
#   " { } [ ] | \ ^ < > and spaces -> would break naive parsers
_QUERY_SAFE = "-._~!$'()*,;=:@/?"
_FRAG_KEEP_PCT = re.compile(r"%[0-9A-Fa-f]{2}")


def _enc_val(v) -> str:
    """Percent-encode a query value (already decoded by parse_qsl)."""
    return quote(str(v), safe=_QUERY_SAFE)


def _enc_frag(v) -> str:
    """Percent-encode a fragment, preserving any existing valid %XX sequences.

    urlsplit() does NOT decode the fragment, so a remark built as
    quote("Spider-میر") arrives here already encoded — re-encoding the '%'
    would corrupt it into %25D9%85.
    """
    s = str(v)
    out = []
    i = 0
    while i < len(s):
        m = _FRAG_KEEP_PCT.match(s, i)
        if m:
            out.append(m.group(0))
            i = m.end()
            continue
        c = s[i]
        if c.isascii() and (c.isalnum() or c in _QUERY_SAFE):
            out.append(c)
        else:
            out.append(quote(c, safe=""))
        i += 1
    return "".join(out)


class _Cfg:
    """Parsed client config URL (vless://uuid@host:port?query#remark)."""

    def __init__(self, s: str):
        self.original = s
        self.ok = False
        self.scheme = ""
        self.uuid = ""
        self.host = ""
        self.port = ""
        self.remark = ""
        self.query: list[list[str]] = []
        self.extra = ""      # unparsed remainder (non URL-like configs)
        self._base = ("", "", "", "", "")
        if "://" not in s:
            self.extra = s
            return
        try:
            parts = urlsplit(s)
        except Exception:                                                  # noqa: BLE001
            self.extra = s
            return
        self.scheme = (parts.scheme or "").lower()
        self.remark = parts.fragment or ""
        netloc = parts.netloc or ""
        userinfo, _, hostport = netloc.rpartition("@")
        if hostport:
            self.uuid = userinfo
            host, sep, port = hostport.partition(":")
            self.host = host
            self.port = port if sep else _SCHEME_PORT_DEFAULT.get(self.scheme, "")
        else:
            self.host = netloc
        self.query = [list(kv) for kv in parse_qsl(parts.query, keep_blank_values=True)]
        self.ok = bool(self.host)

    def param(self, name: str):
        for k, v in self.query:
            if k.lower() == str(name).lower():
                return v, True
        return None, False

    def field(self, name: str):
        n = str(name).lower()
        if n in ("scheme", "proto", "protocol"):
            return self.scheme, True
        if n in ("server", "address", "add", "host_address", "addr"):
            return self.host, True
        if n in ("port",):
            return self.port, True
        if n in ("uuid", "id", "user"):
            return self.uuid, True
        if n in ("remark", "name"):
            return self.remark, True
        if n == "host":
            # "host" means the Host header / SNI-ish param, and falls back to
            # the authority host so matches behave like an admin expects.
            got = self.param("host")
            v = got[0] if got[1] else self.host
            return v, True
        got = self.param(n)
        if got[1]:
            return got
        if n == "type":
            return self.param("type")
        return "", False

    def set_field(self, name: str, value) -> None:
        n = str(name).lower()
        sval = str(value)
        if n in ("server", "address", "addr", "add"):
            if ":" in sval and not sval.endswith(":"):
                h, _, p = sval.rpartition(":")
                self.host, self.port = h, p
            else:
                self.host = sval
            return
        if n == "port":
            self.port = sval
            return
        if n in ("scheme", "proto", "protocol"):
            self.scheme = sval
            return
        if n in ("remark", "name"):
            self.remark = sval
            return
        # everything else is a query param
        for pair in self.query:
            if pair[0].lower() == n:
                pair[1] = sval
                return
        self.query.append([n if n != "type" else "type", sval])

    def del_field(self, name: str) -> None:
        n = str(name).lower()
        if n in ("server", "address", "addr", "port", "scheme", "proto",
                 "protocol", "remark", "name"):
            return
        self.query = [p for p in self.query if p[0].lower() != n]

    def rename_param(self, old: str, new: str) -> None:
        for pair in self.query:
            if pair[0].lower() == str(old).lower():
                pair[0] = str(new)
                return

    def rebuild(self) -> str:
        if not self.ok:
            return self.original
        hostport = self.host + (f":{self.port}" if self.port else "")
        netloc = (f"{self.uuid}@{hostport}" if self.uuid else hostport)
        pairs = "&".join(f"{k}={_enc_val(v)}" for k, v in self.query)
        frag = f"#{_enc_frag(self.remark)}" if self.remark else ""
        return f"{self.scheme}://{netloc}?{pairs}{frag}"


def _cfg_fields(cfg: _Cfg):
    def fields(name):
        v, present = cfg.field(name)
        return ("" if v is None else v), present
    return fields


def _apply_rule_str(value: str, rule: dict, ctx: dict) -> str:
    if "://" in value:
        cfg = _Cfg(value)
        if not cfg.ok:
            return value
        fields = _cfg_fields(cfg)
        if not _test(_expand(rule.get("match") or rule.get("when") or {}), fields):
            return value
        for old, new in (rule.get("rename") or {}).items():
            cfg.rename_param(old, new)
        for key, val in (rule.get("set") or rule.get("params") or {}).items():
            cfg.set_field(key, _fmt(val, fields))
        for key in (rule.get("remove") or []):
            cfg.del_field(key)
        return cfg.rebuild()

    # subscription text: split it into lines and treat each line as a config
    out = []
    for line in value.splitlines():
        if line.strip().startswith(("vless://", "vmess://", "trojan://", "ss://")):
            out.append(_apply_rule_str(line, rule, ctx))
        else:
            out.append(line)
    return "\n".join(out)


def _apply_rule_obj(obj: dict, rule: dict, ctx: dict) -> dict:
    if not isinstance(obj, dict):
        return obj

    def fields(name):
        v, present = _get_path(obj, name)
        if isinstance(v, (dict, list)):
            try:
                v = json.dumps(v, separators=(",", ":"))
            except Exception:                                            # noqa: BLE001
                v = str(v)
        return (v if v is not None else ""), present

    if not _test(_expand(rule.get("match") or rule.get("when") or {}), fields):
        return obj
    for key, val in (rule.get("set") or rule.get("params") or {}).items():
        _set_path(obj, key, _fmt(val, fields))
    for key in (rule.get("remove") or []):
        _del_path(obj, key)
    for old, new in (rule.get("rename") or {}).items():
        got, present = _get_path(obj, old)
        if present:
            _set_path(obj, new, got)
            _del_path(obj, old)
    return obj


# ---------------------------------------------------------------- disk utils


def write_plugin(directory: Path, raw: dict, source: str = "manual") -> dict:
    """Validate and store one manifest as <id>.json. Returns {ok, path|errors}."""
    errs = validate_manifest(raw, source)
    if errs:
        return {"ok": False, "errors": errs}
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{raw['id']}.json"
    body = json.dumps(raw, ensure_ascii=False, indent=2) + "\n"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(body, encoding="utf-8")
    tmp.replace(path)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    except OSError:
        pass
    return {"ok": True, "path": str(path), "id": str(raw["id"])}


def delete_plugin(directory: Path, pid: str) -> bool:
    if not ID_RE.match(str(pid)):
        return False
    path = Path(directory) / f"{pid}.json"
    if path.is_file():
        try:
            path.unlink()
            return True
        except OSError:
            return False
    return False


def parse_bundle(text: str) -> tuple[list, list]:
    """Accept whatever a repository may serve and split it into manifests.

    Supported:
      1. one manifest object          {apiVersion, id, hooks...}
      2. a bare list of manifests     [ {...}, {...} ]
      3. an index:  {"apiVersion":"spiderpanel.index/v1",
                     "plugins":[{"id":..,"url":..,"sha256":..}, ...]}
      4. {"plugins": [...]} / {"items": [...]} / {"manifests": [...]}

    Returns (manifests, index_entries) — index entries still need downloading.
    """
    manifests: list = []
    index_entries: list = []
    data = json.loads(text)
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("hooks"):
                manifests.append(item)
            elif isinstance(item, dict) and (item.get("url") or item.get("path")):
                index_entries.append(item)
        return manifests, index_entries
    if not isinstance(data, dict):
        return manifests, index_entries
    if data.get("hooks") and data.get("id"):
        manifests.append(data)
        return manifests, index_entries
    for key in ("plugins", "items", "manifests", "entries", "files"):
        arr = data.get(key)
        if not isinstance(arr, list):
            continue
        for item in arr:
            if not isinstance(item, dict):
                continue
            if item.get("hooks"):
                manifests.append(item)
            elif item.get("url") or item.get("path") or item.get("raw_url"):
                index_entries.append(item)
    return manifests, index_entries


__all__ = [
    "API_VERSION", "HOOKS", "Registry", "Plugin", "validate_manifest",
    "write_plugin", "delete_plugin", "parse_bundle", "MAX_FILE_BYTES",
]
