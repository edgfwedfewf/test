"""
SpiderPanel link generator — the single place that turns an inbound + a user
into a share link.

WHY THIS FILE EXISTS
--------------------
The panel supports four link protocols (vless / vmess / trojan / shadowsocks)
and seven transports (tcp / ws / grpc / http / kcp / httpupgrade / xhttp).
That is 4 x 7 = 28 combinations, and the Security/Transport block of a share
link differs for every one of them. Building those strings inline inside a
14k-line main.py made half of them silently wrong.

The shapes here follow the reference implementation used by the Blue Knight
gate (a battle-tested Xray/sing-box panel): the same server, port, UUID,
path and TLS block are reused for every protocol, and only the *envelope*
scheme/base64 layout changes.

  vless://uuid@host:port?...#remark
  vmess://base64(json)#remark
  trojan://password@host:port?...#remark
  ss://base64(method:password)@host:port#remark   (or SIP002 with ?plugin=)

This module is deliberately dependency-free and pure: give it a dict, get a
string back. main.py owns every decision about *which* inbound/engine to use;
this file only renders.
"""

from __future__ import annotations

import base64
import json
from urllib.parse import quote, urlsplit

# ── Public path convention ────────────────────────────────────────────────────
# /all/{uuid}     → every TLS-family inbound (served by the relay or by Xray)
# /reality/{uuid} → every Reality inbound (always Xray)
TLS_PATH_PREFIX = "/all"
REALITY_PATH_PREFIX = "/reality"

# Link protocols an admin may pick for an inbound's generated links.
LINK_PROTOCOLS = ("vless", "vmess", "trojan", "shadowsocks")

# Transports Xray-core really implements on the wire. `tcp` and `kcp` carry no
# HTTP path; the rest are path-addressed.
TRANSPORTS = ("tcp", "ws", "grpc", "http", "kcp", "httpupgrade", "xhttp")

# Transport-specific link params
PATH_TRANSPORTS = ("ws", "grpc", "http", "httpupgrade", "xhttp")

# http/2 and gRPC need an ALPN of h2; WS/HTTPUpgrade must stay on http/1.1.
H2_TRANSPORTS = ("grpc", "http")

# Reality can only be layered on VLESS — Xray implements it as a VLESS security.
REALITY_PROTOCOLS = ("vless",)

DEFAULT_FINGERPRINT = "chrome"
DEFAULT_REALITY_SNI = "is1-ssl.mzstatic.com"

# Transports the FastAPI relay can terminate itself. Everything else (tcp,
# grpc, http, kcp, httpupgrade) is served by the Xray core, which really
# speaks them. (HTTPUpgrade looks like WS but uses a different upgrade
# handshake the relay does not implement — it must go to Xray.)
RELAY_TRANSPORTS = ("ws", "xhttp")


def b64(data: bytes | str, urlsafe: bool = False) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    if urlsafe:
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    return base64.b64encode(data).decode("ascii")


def _quote(v) -> str:
    return quote(str(v), safe="")


def inbound_is_reality(inbound: dict | None) -> bool:
    if not inbound:
        return False
    return (str(inbound.get("protocol") or "").lower() == "reality"
            or str(inbound.get("security") or "").lower() == "reality")


def transport_of(inbound: dict | None, fallback: str = "ws") -> str:
    net = str((inbound or {}).get("network") or "").strip().lower()
    if net in TRANSPORTS:
        return net
    return fallback if fallback in TRANSPORTS else "ws"


def security_of(inbound: dict | None) -> str:
    """tls | reality | none — what the client must put in `security=`."""
    if inbound_is_reality(inbound):
        return "reality"
    sec = str((inbound or {}).get("security") or "").strip().lower()
    return sec if sec in ("tls", "none") else "tls"


def path_for(inbound: dict | None, config_uuid: str) -> str:
    """Resolve the stored `{uuid}` template into the concrete public path.

    The stored value keeps the literal `{uuid}` placeholder so editing an
    inbound never rewrites every user's record; this substitutes it.
    """
    reality = inbound_is_reality(inbound)
    prefix = REALITY_PATH_PREFIX if reality else TLS_PATH_PREFIX
    transport = transport_of(inbound)

    template = ""
    if inbound:
        if transport == "ws":
            template = str((inbound.get("ws_settings") or {}).get("path") or "")
        elif transport == "xhttp":
            template = str((inbound.get("xhttp_settings") or {}).get("path") or "")
        elif transport == "grpc":
            template = str((inbound.get("grpc_settings") or {}).get("serviceName") or "")
        elif transport == "httpupgrade":
            template = str((inbound.get("httpupgrade_settings") or {}).get("path") or "")
        elif transport == "http":
            template = str((inbound.get("http_settings") or {}).get("path") or "")
        elif transport == "kcp":
            template = str((inbound.get("kcp_settings") or {}).get("seed") or "")
        template = template or str(inbound.get("path") or "")

    template = (template or "").strip()

    if transport == "kcp":
        # MKCP has no path; the "seed" doubles as the shared secret.
        return template or ("reality" if reality else "all")

    if transport in ("tcp",) and security_of(inbound) != "none":
        # Plain TCP-over-TLS has no path to address; keep an empty one so the
        # caller can omit the query parameter entirely.
        if template in ("", "/"):
            return ""

    if not template or template in ("/", "{uuid}", "/{uuid}", prefix, prefix + "/"):
        template = f"{prefix}/{{uuid}}"
    if not template.startswith("/"):
        template = "/" + template
    return template.replace("{uuid}", config_uuid)


def grpc_service_name(inbound: dict | None, config_uuid: str) -> str:
    """Xray calls `/{serviceName}/{stream}`, so serviceName must have no slash."""
    return path_for(inbound, config_uuid).lstrip("/")


def _host_of(inbound: dict | None, settings_domain: str = "") -> str:
    return (str((inbound or {}).get("external_domain") or "").strip()
            or str((inbound or {}).get("domain") or "").strip()
            or str(settings_domain or "").strip())


def _alpn_for(transport: str, inbound: dict | None = None) -> str:
    """ALPN advertised in the link's `alpn=` parameter.

    Transport decides the *shape* (WS/HTTPUpgrade are HTTP/1.1 only — offering
    h2 to a WS endpoint makes the handshake fail), but Reality always negotiates
    against the real origin server, so it offers h2 there regardless of the
    transport the panel carries the stream over.
    """
    explicit = str((inbound or {}).get("alpn") or "").strip()
    if explicit:
        return explicit
    if security_of(inbound) == "reality":
        # Handshake goes to the real origin; h2 is what it actually supports.
        return "h2,http/1.1"
    if transport in H2_TRANSPORTS:
        return "h2"
    if transport == "xhttp":
        return "h2,http/1.1"
    # WS / HTTPUpgrade are HTTP/1.1 only — advertising h2 breaks them.
    return "http/1.1"


def _xhttp_mode(inbound: dict | None) -> str:
    xs = (inbound or {}).get("xhttp_settings") or {}
    mode = str(xs.get("mode") or "stream-up").strip().lower()
    if mode not in ("auto", "packet-up", "stream-up", "stream-one"):
        mode = "stream-up"
    if mode == "auto":
        # Recent Xray builds misbehave when one side forces a concrete mode and
        # the other advertises `auto`; pin both ends to stream-up.
        mode = "stream-up"
    return mode


def _xhttp_extra(inbound: dict | None) -> str:
    xs = (inbound or {}).get("xhttp_settings") or {}
    extra = {"xPaddingBytes": xs.get("xPaddingBytes", "100-1000")}
    if _xhttp_mode(inbound) == "packet-up":
        extra["scMaxEachPostBytes"] = xs.get("scMaxEachPostBytes", "1000000")
    return _quote(json.dumps(extra, separators=(",", ":"), ensure_ascii=False))


# ── shared per-transport query fragment ───────────────────────────────────────

def transport_query(ctx: dict) -> str:
    """Return "&type=...&..." — everything after the security block."""
    transport = ctx["transport"]
    path = ctx.get("path") or ""
    host_header = ctx.get("host_header") or ctx.get("host") or ""

    if transport == "ws":
        q = "&type=ws"
        if host_header:
            q += f"&host={_quote(host_header)}"
        q += f"&path={_quote(path)}"
        return q

    if transport == "httpupgrade":
        q = "&type=httpupgrade"
        if host_header:
            q += f"&host={_quote(host_header)}"
        q += f"&path={_quote(path)}"
        return q

    if transport == "xhttp":
        q = "&type=xhttp"
        if host_header:
            q += f"&host={_quote(host_header)}"
        q += (f"&path={_quote(path)}"
              f"&mode={ctx['xhttp_mode']}"
              f"&extra={ctx['xhttp_extra']}")
        return q

    if transport == "grpc":
        # Xray builds the method as "/<serviceName>/<stream>".
        return f"&type=grpc&serviceName={_quote(ctx['service_name'])}&mode=gun"

    if transport == "http":
        # Xray's HTTP/2 transport.
        q = "&type=http"
        if host_header:
            q += f"&host={_quote(host_header)}"
        q += f"&path={_quote(path)}"
        return q

    if transport == "kcp":
        seed = ctx.get("kcp_seed") or ""
        q = "&type=kcp&headerType=none"
        if seed:
            q += f"&seed={_quote(seed)}"
        return q

    # tcp
    header_type = ctx.get("tcp_header_type") or "none"
    q = f"&type=tcp&headerType={_quote(header_type)}"
    if header_type == "http" and ctx.get("request_path"):
        q += f"&path={_quote(ctx['request_path'])}"
    return q


def security_query(ctx: dict) -> str:
    """Return "&security=..." plus the TLS / Reality block (or nothing)."""
    security = ctx["security"]
    if security == "reality":
        q = f"&security=reality&sni={_quote(ctx['sni'])}&fp={_quote(ctx['fp'])}"
        q += f"&pbk={_quote(ctx['pbk'])}&sid={_quote(ctx['sid'])}"
        q += f"&spx={_quote(ctx.get('spx') or '/')}"
        q += f"&alpn={_quote(ctx.get('alpn') or 'h2,http/1.1')}"
        return q

    if security == "tls":
        q = f"&security=tls&sni={_quote(ctx['sni'])}&fp={_quote(ctx['fp'])}"
        alpn = ctx.get("alpn") or ""
        if alpn:
            q += f"&alpn={_quote(alpn)}"
        if ctx.get("allow_insecure"):
            q += "&allowInsecure=1"
        if ctx.get("pcs"):
            q += f"&pcs={_quote(ctx['pcs'])}"
        if ctx.get("fragment"):
            # fp/cs/fm from the Fragment+Fingerprint plugin shape.
            for key in ("fp", "cs", "fm"):
                if ctx.get(key):
                    q += f"&{key}={_quote(ctx[key])}"
        if ctx.get("sni_spoof"):
            q += f"&sni={_quote(ctx['sni_spoof'])}"
        return q

    return "&security=none"


# ── protocol envelopes ────────────────────────────────────────────────────────

def _base(ctx: dict) -> dict:
    return {
        "host": ctx["host"],
        "port": str(ctx["port"]),
        "uuid": ctx["uuid"],
        "remark": ctx["remark"],
        "path": ctx.get("path") or "",
        "host_header": ctx.get("host_header") or ctx["host"],
        "sni": ctx["sni"],
        "fp": ctx["fp"],
        "alpn": ctx.get("alpn") or "",
        "security": ctx["security"],
        "transport": ctx["transport"],
        "xhttp_mode": ctx.get("xhttp_mode") or "stream-up",
        "xhttp_extra": ctx.get("xhttp_extra") or "{}",
        "service_name": ctx.get("service_name") or "",
        "kcp_seed": ctx.get("kcp_seed") or "",
        "tcp_header_type": ctx.get("tcp_header_type") or "none",
        "request_path": ctx.get("request_path") or "",
        "pbk": ctx.get("pbk") or "",
        "sid": ctx.get("sid") or "",
        "spx": ctx.get("spx") or "/",
        "allow_insecure": ctx.get("allow_insecure", False),
        "pcs": ctx.get("pcs") or "",
        "sni_spoof": ctx.get("sni_spoof") or "",
    }


def build_vless(ctx: dict) -> str:
    """vless://uuid@host:port?encryption=none&security=...&type=...#remark"""
    b = _base(ctx)
    q = "encryption=none" + security_query(ctx) + transport_query(ctx)
    frag = f"#{quote(b['remark'], safe='')}" if b["remark"] else ""
    return f"vless://{b['uuid']}@{b['host']}:{b['port']}?{q}{frag}"


def build_trojan(ctx: dict) -> str:
    """trojan://password@host:port?security=...&type=...#remark

    Trojan is a TLS-only protocol in every mainstream client — a
    `security=none` Trojan link is rejected by v2rayN/mihomo. The panel still
    emits one when asked, but the config carries TLS.
    """
    b = _base(ctx)
    security = b["security"] if b["security"] != "none" else "tls"
    local = dict(ctx)
    local["security"] = security
    q = security_query(local).lstrip("&") + transport_query(ctx)
    frag = f"#{quote(b['remark'], safe='')}" if b["remark"] else ""
    return f"trojan://{b['uuid']}@{b['host']}:{b['port']}?{q}{frag}"


def build_vmess(ctx: dict) -> str:
    """vmess://base64(JSON) — the classic v2rayN envelope.

    The JSON mirrors the same server/port/path/TLS block the VLESS link uses,
    so switching an inbound's protocol never changes what the server serves.
    """
    b = _base(ctx)
    transport = b["transport"]
    security = b["security"]

    net = transport
    if transport == "xhttp":
        net = "xhttp"
    elif transport == "httpupgrade":
        net = "httpupgrade"

    doc = {
        "v": "2",
        "ps": b["remark"],
        "add": b["host"],
        "port": b["port"],
        "id": b["uuid"],
        "aid": "0",
        "scy": "auto",
        "net": net,
        "type": "none",
        "host": b["host_header"],
        "path": b["path"],
        "tls": "tls" if security == "tls" else "",
        "sni": b["sni"],
        "fp": b["fp"],
        "alpn": b["alpn"],
    }
    if transport == "grpc":
        doc["path"] = b["service_name"]
    if transport == "kcp":
        doc["type"] = "srtp"
        doc["path"] = b["kcp_seed"]
    if transport == "tcp" and b["tcp_header_type"] == "http":
        doc["type"] = "http"
    if transport == "xhttp":
        doc["mode"] = b["xhttp_mode"]
        doc["extra"] = b["xhttp_extra"]
    if security == "reality":
        # Reality is VLESS-only in Xray; vmess cannot carry it.
        doc["tls"] = ""
        doc.pop("extra", None)
    if b["allow_insecure"]:
        doc["allowInsecure"] = 1
    if b["pcs"]:
        doc["pcs"] = b["pcs"]

    payload = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
    return "vmess://" + b64(payload)


def build_shadowsocks(ctx: dict) -> str:
    """ss://  — SIP002, optionally with a v2ray-plugin for path-addressed links.

    Shadowsocks has no TLS of its own; over a TLS inbound the link advertises
    the plugin with `tls=1`, and over a bare inbound it stays plain. The
    password reuses the user's config UUID so the identity is never split.
    """
    b = _base(ctx)
    method = ctx.get("ss_method") or "aes-256-gcm"
    password = ctx.get("ss_password") or b["uuid"]
    transport = b["transport"]

    userinfo = b64(f"{method}:{password}")
    frag = f"#{quote(b['remark'], safe='')}" if b["remark"] else ""

    if transport in PATH_TRANSPORTS:
        opts = [f"mode=websocket" if transport == "ws" else f"mode={transport}"]
        opts.append(f"host={b['host_header']}")
        opts.append(f"path={b['path'] or '/'}")
        opts.append("mux=0")
        if b["security"] == "tls":
            opts.append("tls=1")
            opts.append(f"server={b['sni']}")
        plugin_opts = ";".join(opts)
        plugin = "v2ray-plugin;" + plugin_opts
        return (f"ss://{userinfo}@{b['host']}:{b['port']}"
                f"/?plugin={_quote(plugin)}{frag}")

    # Plain (no plugin) — tcp without TLS.
    return f"ss://{userinfo}@{b['host']}:{b['port']}{frag}"


BUILDERS = {
    "vless": build_vless,
    "vmess": build_vmess,
    "trojan": build_trojan,
    "shadowsocks": build_shadowsocks,
}


def build(protocol: str, ctx: dict) -> str:
    """Render one link. Unknown protocols fall back to VLESS."""
    builder = BUILDERS.get(str(protocol or "").strip().lower())
    if builder is None:
        if not ctx.get("host") or not ctx.get("port"):
            return ""
        return build_vless(ctx)
    if not ctx.get("host") or not ctx.get("port"):
        return ""
    try:
        return builder(ctx)
    except Exception:
        # A malformed optional block must never blank out a working config.
        return build_vless(ctx)


def normalize_protocol(protocol, inbound: dict | None = None) -> str:
    """Pick the link protocol for an inbound, honouring Reality's VLESS-only rule."""
    p = str(protocol or "").strip().lower()
    if p in LINK_PROTOCOLS:
        if inbound_is_reality(inbound) and p not in REALITY_PROTOCOLS:
            return "vless"
        return p
    return "vless"


def allowed_protocols(inbound: dict | None) -> tuple[str, ...]:
    """Protocols the admin may select for this inbound."""
    if inbound_is_reality(inbound):
        return REALITY_PROTOCOLS
    return LINK_PROTOCOLS


# ── one authoritative block: transport + security, for links AND Xray ─────────
#
# The share link and the server config used to be written out separately, which
# is exactly how they drifted apart (a link saying `?a=1` against a server
# listening on `/xhttp-siz10/...`). `build_block()` computes both shapes from
# the inbound ONCE, so client and server cannot disagree.
#
# Xray matches paths differently per transport, and the block encodes that:
#   ws / httpupgrade → EXACT match, so both sides carry `/all/{uuid}`
#   grpc             → the client calls `/{serviceName}/{stream}`
#   xhttp            → PREFIX match, then Xray appends its own session segment.
#                      With `{uuid}` in the template each user gets their own
#                      session namespace, which is what lets the relay and any
#                      per-user accounting see the UUID in the URL.
#   tcp / kcp        → no HTTP path at all

def _clean(value: str) -> str:
    """Drop `?query` — v2rayN appends it client-side, the server must not echo it."""
    return str(value or "").split("?", 1)[0].strip()


def link_transport(inbound: dict | None, config_uuid: str) -> tuple[str, dict]:
    """(type_name, params) exactly as they appear after `security=` in a link."""
    transport = transport_of(inbound)
    path = _clean(path_for(inbound, config_uuid))

    if transport == "ws":
        return "ws", {"path": path}
    if transport == "httpupgrade":
        return "httpupgrade", {"path": path}
    if transport == "xhttp":
        return "xhttp", {
            "path": path,
            "mode": _xhttp_mode(inbound),
            "extra": _xhttp_extra(inbound),
        }
    if transport == "grpc":
        return "grpc", {"serviceName": path.lstrip("/"), "mode": "gun"}
    if transport == "http":
        return "http", {"path": path}
    if transport == "kcp":
        seed = str((inbound or {}).get("kcp_settings") or {}).get("seed") if False else \
            str(((inbound or {}).get("kcp_settings") or {}).get("seed") or "")
        return "kcp", {"headerType": "none", "seed": seed}
    header = str(((inbound or {}).get("tcp_settings") or {}).get("headerType") or "none")
    params = {"headerType": header}
    if header == "http":
        params["path"] = _clean(str(((inbound or {}).get("tcp_settings") or {}).get("path") or "/"))
        params["host"] = str(((inbound or {}).get("tcp_settings") or {}).get("host") or "")
    return "tcp", params


def server_transport(inbound: dict | None) -> tuple[str, dict]:
    """(network_name, settings_dict, settings_key) for Xray's streamSettings."""
    transport = transport_of(inbound)

    if transport == "ws":
        return "ws", {
            "path": _clean(path_for(inbound, "{uuid}")),
            "headers": {},
        }, "wsSettings"

    if transport == "httpupgrade":
        return "httpupgrade", {
            "path": _clean(path_for(inbound, "{uuid}")),
            "host": str(((inbound or {}).get("httpupgrade_settings") or {}).get("host") or ""),
        }, "httpupgradeSettings"

    if transport == "xhttp":
        xs = (inbound or {}).get("xhttp_settings") or {}
        mode = _xhttp_mode(inbound)
        return "xhttp", {
            "path": _clean(path_for(inbound, "{uuid}")),
            "host": str(xs.get("host") or ""),
            "mode": mode,
            "xPaddingBytes": xs.get("xPaddingBytes", "100-1000"),
            "scMaxEachPostBytes": xs.get("scMaxEachPostBytes", "1000000"),
            "scMaxBufferedPosts": xs.get("scMaxBufferedPosts", 30),
            "scStreamUpServerSecs": xs.get("scStreamUpServerSecs", "20-80"),
        }, "xhttpSettings"

    if transport == "grpc":
        gs = (inbound or {}).get("grpc_settings") or {}
        return "grpc", {
            "serviceName": _clean(path_for(inbound, "{uuid}")).lstrip("/"),
            "authority": str(gs.get("authority") or ""),
            "multiMode": True,          # links advertise mode=gun
            "initialWindows": int(gs.get("initialWindows") or 65536),
            "idleTimeout": int(gs.get("idleTimeout") or 60),
            "healthCheckTimeout": int(gs.get("healthCheckTimeout") or 20),
        }, "grpcSettings"

    if transport == "http":
        hs = (inbound or {}).get("http_settings") or {}
        return "http", {
            "path": _clean(path_for(inbound, "{uuid}")),
            "host": str(hs.get("host") or ""),
        }, "httpSettings"

    if transport == "kcp":
        ks = (inbound or {}).get("kcp_settings") or {}
        return "kcp", {
            "header": {"type": str(ks.get("headerType") or "none"),
                       "request": {"path": [str(ks.get("path") or "/")]}},
            "seed": str(ks.get("seed") or ""),
        }, "kcpSettings"

    ts = (inbound or {}).get("tcp_settings") or {}
    header_type = str(ts.get("headerType") or "none")
    tcp: dict = {"header": {"type": header_type}}
    if header_type == "http":
        tcp["header"]["request"] = {
            "path": [str(ts.get("path") or "/")],
            "headers": {"Host": str(ts.get("host") or "")},
        }
    return "tcp", tcp, "tcpSettings"


def link_security(inbound: dict | None, reality: dict | None = None) -> tuple[str, dict]:
    """(security_name, params) for a share link's `security=` block.

    `reality` carries the resolved pbk/sid/spx for a Reality inbound; the caller
    (main.py) owns key derivation because that needs the panel's keypair code.
    """
    security = security_of(inbound)
    if security == "none":
        return "none", {}

    reality = reality or {}
    if security == "reality":
        return "reality", {
            "sni": reality.get("sni") or DEFAULT_REALITY_SNI,
            "fp": reality.get("fp") or DEFAULT_FINGERPRINT,
            "pbk": reality.get("pbk") or "",
            "sid": reality.get("sid") or "",
            "spx": reality.get("spx") or "/",
            "alpn": reality.get("alpn") or "h2,http/1.1",
        }
    return "tls", {
        "sni": reality.get("sni") or "",
        "fp": reality.get("fp") or DEFAULT_FINGERPRINT,
        "alpn": reality.get("alpn") or "",
    }


def engine_for(inbound: dict | None, *, edge_tls: bool = False) -> str:
    """Which process actually serves this inbound: 'relay' or 'xray'.

    Rules, in order:
      * Reality is always Xray — only Xray implements it.
      * Plain HTTP (security=none) goes to the relay: there is no TLS to
        terminate, so uvicorn can speak it directly on the panel port.
      * Transports the relay really speaks (ws / httpupgrade / xhttp) with VLESS
        go to the relay when a TLS edge sits in front of the panel
        (Railway/Codespaces), because that edge already terminates TLS.
      * Everything else — tcp / grpc / http / kcp, vmess/trojan/shadowsocks,
        or TLS with no edge in front — goes to Xray, which terminates TLS
        itself using the certificate the panel provisions with ACME.
    """
    if inbound_is_reality(inbound):
        return "xray"
    if not inbound:
        return "relay"
    proto = str(inbound.get("protocol") or "vless").lower()
    if proto == "worker":
        return "worker"
    if proto == "telegram":
        return "telegram"
    if proto == "node":
        return "node"
    if proto not in ("vless",):
        # The relay only parses the VLESS request header.
        return "xray"
    transport = transport_of(inbound)
    if transport not in RELAY_TRANSPORTS:
        return "xray"
    if security_of(inbound) == "none":
        # Plain HTTP straight into the panel port — no TLS to terminate.
        return "relay"
    return "relay" if edge_tls else "xray"


__all__ = [
    "LINK_PROTOCOLS", "TRANSPORTS", "PATH_TRANSPORTS", "H2_TRANSPORTS",
    "TLS_PATH_PREFIX", "REALITY_PATH_PREFIX", "DEFAULT_FINGERPRINT",
    "inbound_is_reality", "transport_of", "security_of", "path_for",
    "grpc_service_name", "build", "build_vless", "build_vmess",
    "build_trojan", "build_shadowsocks", "normalize_protocol",
    "allowed_protocols", "engine_for", "transport_query", "security_query",
    "_xhttp_mode", "_xhttp_extra", "_alpn_for", "_host_of",
]
