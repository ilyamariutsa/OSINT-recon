"""Активные проверки (включаются флажком): HTTP(S)-опрос, TLS-сертификаты, TCP-порты."""
import asyncio
import html
import re
import ssl
from datetime import datetime, timezone

import httpx

from . import config
from .fingerprints import SCAN_PORTS, TAKEOVER, detect_tech

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
SEC_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options",
               "x-content-type-options"]


def _title(body: str) -> str:
    m = _TITLE.search(body)
    return re.sub(r"\s+", " ", html.unescape(m.group(1))).strip()[:160] if m else ""


async def _fetch(client: httpx.AsyncClient, url: str) -> dict:
    async with client.stream("GET", url) as r:
        body = b""
        async for chunk in r.aiter_bytes():
            body += chunk
            if len(body) > 250_000:
                break
        text = body.decode(r.encoding or "utf-8", "replace") if body else ""
        hdrs = {k.lower(): v for k, v in r.headers.items()}
        chain = [str(x.url) for x in r.history]
        return {"status": r.status_code, "final_url": str(r.url), "headers": hdrs, "body": text,
                "redirects": chain}


async def http_probe(hosts: list[str], concurrency: int = 40, out: dict | None = None) -> dict[str, dict]:
    """Для каждого хоста: https → http; статус, заголовок, сервер, технологии, редиректы."""
    out = {} if out is None else out
    limits = httpx.Limits(max_connections=concurrency * 2, max_keepalive_connections=0)
    async with httpx.AsyncClient(verify=False, follow_redirects=True, max_redirects=6, limits=limits,
                                 timeout=httpx.Timeout(10, connect=5),
                                 headers={"User-Agent": config.USER_AGENT, "Accept": "*/*"}) as client:
        sem = asyncio.Semaphore(concurrency)

        async def one(host: str):
            async with sem:
                res = None
                for scheme in ("https", "http"):
                    try:
                        r = await asyncio.wait_for(_fetch(client, f"{scheme}://{host}/"), 25)
                    except (httpx.HTTPError, asyncio.TimeoutError, ssl.SSLError, OSError, ValueError):
                        continue
                    hdr_blob = "\n".join(f"{k}: {v}" for k, v in r["headers"].items())
                    title = _title(r["body"])
                    blob = (hdr_blob + "\n<title>" + title + "</title>\n" + r["body"][:60000]).lower()
                    tech = detect_tech(blob)
                    res = {
                        "url": f"{scheme}://{host}/", "scheme": scheme, "status": r["status"],
                        "final_url": r["final_url"], "title": title,
                        "server": r["headers"].get("server", "")[:80],
                        "powered_by": r["headers"].get("x-powered-by", "")[:80],
                        "content_type": r["headers"].get("content-type", "").split(";")[0][:60],
                        "length": len(r["body"]),
                        "tech": sorted({t for t, _ in tech}),
                        "tech_cat": {t: c for t, c in tech},
                        "missing_sec_headers": [h for h in SEC_HEADERS if h not in r["headers"]]
                        if scheme == "https" else [],
                        "redirects": len(r["redirects"]),
                        "body_sample": r["body"][:4000],
                    }
                    if scheme == "http":
                        res["http_only"] = True
                    break
                if res:
                    out[host] = res

        await asyncio.gather(*(one(h) for h in hosts))
    return out


# ---------------- TLS ----------------

def _parse_cert(der: bytes) -> dict:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID, NameOID

    c = x509.load_der_x509_certificate(der)

    def name_attr(n, oid):
        v = n.get_attributes_for_oid(oid)
        return v[0].value if v else ""

    try:
        san = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        dns_names = san.get_values_for_type(x509.DNSName)
    except Exception:
        dns_names = []
    try:
        nb, na = c.not_valid_before_utc, c.not_valid_after_utc
    except AttributeError:
        nb = c.not_valid_before.replace(tzinfo=timezone.utc)
        na = c.not_valid_after.replace(tzinfo=timezone.utc)
    return {
        "subject_cn": name_attr(c.subject, NameOID.COMMON_NAME),
        "subject_org": name_attr(c.subject, NameOID.ORGANIZATION_NAME),
        "issuer_cn": name_attr(c.issuer, NameOID.COMMON_NAME),
        "issuer_org": name_attr(c.issuer, NameOID.ORGANIZATION_NAME),
        "not_before": nb.isoformat(timespec="seconds"), "not_after": na.isoformat(timespec="seconds"),
        "days_left": (na - datetime.now(timezone.utc)).days,
        "self_signed": c.issuer == c.subject,
        "san": sorted(set(dns_names))[:200],
    }


def _host_matches(host: str, names: list[str]) -> bool:
    for n in names:
        n = n.lower()
        if n == host or (n.startswith("*.") and host.endswith(n[1:]) and host.count(".") == n.count(".")):
            return True
    return False


async def tls_info(host: str, port: int = 443, timeout: float = 8) -> dict | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout)
    except (OSError, asyncio.TimeoutError, ssl.SSLError, ValueError):
        return None
    try:
        sslobj = writer.get_extra_info("ssl_object")
        der = sslobj.getpeercert(binary_form=True) if sslobj else None
        proto = sslobj.version() if sslobj else None
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 3)
        except Exception:
            pass
    if not der:
        return None
    try:
        info = _parse_cert(der)
    except Exception:
        return None
    names = info["san"] or ([info["subject_cn"]] if info["subject_cn"] else [])
    info["hostname_match"] = _host_matches(host, names)
    info["expired"] = info["days_left"] < 0
    info["protocol"] = proto
    return info


async def tls_scan(hosts: list[str], concurrency: int = 50, out: dict | None = None) -> dict[str, dict]:
    sem = asyncio.Semaphore(concurrency)
    out = {} if out is None else out

    async def one(h):
        async with sem:
            r = await tls_info(h)
            if r:
                out[h] = r

    await asyncio.gather(*(one(h) for h in hosts))
    return out


# ---------------- порты ----------------

async def port_scan(ips: list[str], ports: list[int] | None = None, concurrency: int = 400,
                    timeout: float = 1.8, out: dict | None = None) -> dict[str, list[int]]:
    """TCP connect к типовым портам (без эксплуатации, только факт открытия)."""
    ports = ports or SCAN_PORTS
    sem = asyncio.Semaphore(concurrency)
    out = {} if out is None else out

    async def one(ip, port):
        async with sem:
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
                w.close()
                out[ip] = sorted(set(out.get(ip, [])) | {port})
            except (OSError, asyncio.TimeoutError, ValueError):
                pass

    await asyncio.gather(*(one(ip, p) for ip in ips for p in ports))
    return out


# ---------------- захват поддоменов ----------------

def takeover_service(cnames: list[str]) -> tuple[str, str | None] | None:
    for cn in cnames:
        c = cn.lower().rstrip(".")
        for suffix, svc, fp in TAKEOVER:
            if c == suffix or c.endswith("." + suffix) or (suffix.startswith("s3") and suffix in c):
                return svc, fp
    return None


def takeover_check(host: str, rinfo: dict, http: dict | None) -> dict | None:
    """Кандидат на захват: CNAME на внешний сервис + NXDOMAIN цели или отпечаток «ресурс свободен»."""
    cn = rinfo.get("cname") or []
    if not cn:
        return None
    svc = takeover_service(cn)
    dangling = rinfo.get("status") == "dangling"
    if svc:
        name, fp = svc
        if fp and http and re.search(fp, http.get("body_sample", ""), re.I | re.S):
            return {"host": host, "cname": cn[-1], "service": name, "confidence": "high",
                    "reason": "ответ сервиса: ресурс не занят"}
        if dangling:
            return {"host": host, "cname": cn[-1], "service": name, "confidence": "high",
                    "reason": "CNAME указывает на несуществующее имя (NXDOMAIN)"}
        return None
    if dangling:
        return {"host": host, "cname": cn[-1], "service": "—", "confidence": "medium",
                "reason": "висячий CNAME: цель не резолвится"}
    return None
