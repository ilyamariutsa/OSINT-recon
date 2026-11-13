"""Данные регистрации домена: RDAP → нативный whois (TCP 43) → whois CLI."""
import asyncio
import re
import shutil

import httpx


def _empty(source: str) -> dict:
    return {
        "source": source, "registrar": None, "registrant_org": None,
        "registrant_inn": None, "created": None, "updated": None, "expires": None,
        "statuses": [], "nameservers": [], "error": None,
    }


def _fmt_date(value) -> str | None:
    if not value:
        return None
    return str(value).replace("T", " ").split(".")[0].strip()


# ---------------- RDAP ----------------

async def _from_rdap(domain: str, client: httpx.AsyncClient) -> dict:
    r = await client.get(f"https://rdap.org/domain/{domain}", timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"RDAP HTTP {r.status_code}")
    d = r.json()
    events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events") or []}
    registrar, registrant = None, None
    for ent in d.get("entities") or []:
        roles = ent.get("roles") or []
        vcard = ent.get("vcardArray") or []
        for f in (vcard[1] if len(vcard) > 1 else []):
            if isinstance(f, list) and f and f[0] in ("fn", "org"):
                if "registrar" in roles and not registrar:
                    registrar = f[3] if len(f) > 3 else None
                if "registrant" in roles and not registrant:
                    registrant = f[3] if len(f) > 3 else None
    res = _empty("rdap")
    res.update({
        "registrar": registrar,
        "registrant_org": registrant,
        "created": _fmt_date(events.get("registration")),
        "updated": _fmt_date(events.get("last changed")),
        "expires": _fmt_date(events.get("expiration")),
        "statuses": [str(s) for s in (d.get("status") or [])][:10],
        "nameservers": sorted({str(ns.get("ldhName", "")).rstrip(".").lower()
                               for ns in d.get("nameservers") or [] if ns.get("ldhName")}),
    })
    return res


# ---------------- нативный whois по TCP 43 ----------------

async def _tcp_whois(server: str, query: str, timeout: int = 15) -> str:
    r, w = await asyncio.open_connection(server, 43)
    w.write((query + "\r\n").encode())
    await w.drain()
    buf = bytearray()
    try:
        while len(buf) < 200_000:
            chunk = await asyncio.wait_for(r.read(4096), timeout=timeout)
            if not chunk:
                break
            buf += chunk
    except asyncio.TimeoutError:
        pass
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    return buf.decode("utf-8", "replace")


async def _from_tcp_whois(domain: str) -> dict:
    boot = await _tcp_whois("whois.iana.org", domain)
    m = re.search(r"(?im)^whois:\s+(\S+)", boot) or re.search(r"(?im)^refer:\s+(\S+)", boot)
    if not m:
        raise RuntimeError("IANA: whois-сервер не найден для TLD")
    text = await _tcp_whois(m.group(1), domain)
    if not text.strip():
        raise RuntimeError("пустой ответ whois-сервера")
    if re.search(r"(?i)no (matching )?(domain|object|entries?) found|not found", text[:2000]) \
            and "domain:" not in text.lower():
        raise RuntimeError("домен не найден в whois")
    return _parse_whois_text(text)


# Только пробелы/табуляции между меткой и значением: \s* пересекал бы переносы строк
# и захватывал следующую метку (баг «registrant_org = taxpayer-id:»).
_WHOIS_PATTERNS = {
    "registrar": r"^[ \t]*(?:registrar|Регистратор(?:-организация)?)[ \t]*:[ \t]*(.+?)[ \t]*$",
    "registrant_org": r"^[ \t]*(?:registrant organization|organization|org(?:anization)?(?: name)?|org-name|owner-organization|holder|организация)[ \t]*:[ \t]*(.+?)[ \t]*$",
    "registrant_inn": r"^[ \t]*(?:taxpayer-id|taxpayer number|inn|ИНН)[ \t]*:[ \t]*([0-9]{10,12})[ \t]*$",
    "created": r"^[ \t]*(?:creation date|created(?: on)?|registered(?: on)?|registration time)[ \t]*:[ \t]*(.+?)[ \t]*$",
    "updated": r"^[ \t]*(?:updated date|changed|modified)[ \t]*:[ \t]*(.+?)[ \t]*$",
    "expires": r"^[ \t]*(?:paid-till|registry expiry date|expiration(?: date)?|expires?(?: on)?|expiry date)[ \t]*:[ \t]*(.+?)[ \t]*$",
}


def _parse_whois_text(text: str) -> dict:
    res = _empty("whois")

    def first(pat: str):
        m = re.search(pat, text, re.I | re.M)
        if not m:
            return None
        v = m.group(1).strip()
        return v or None  # пустая строка после strip → нет данных

    for key, pat in _WHOIS_PATTERNS.items():
        res[key] = first(pat)
        if key == "registrar" and res[key] and res[key].startswith("http"):
            res[key] = None  # tcinet отдаёт ссылку на заявку вместо регистратора
        if key == "updated" and res[key] and res[key].lower().startswith("on "):
            res[key] = None  # «Last updated on …» — служебный футер, а не дата изменения
    res["nameservers"] = sorted({
        m.group(1).strip().rstrip(".").lower()
        for m in re.finditer(r"^[ \t]*(?:nserver|name server|nameserver)[ \t]*:[ \t]*(\S+)", text, re.I | re.M)
    })[:10]
    res["statuses"] = [m.group(1).strip() for m in
                       re.finditer(r"^[ \t]*(?:domain status|state|status)[ \t]*:[ \t]*(.+?)[ \t]*$", text, re.I | re.M)][:10]
    return res


# ---------------- whois CLI (фолбэк) ----------------

async def _from_whois_cli(domain: str) -> dict:
    if not shutil.which("whois"):
        raise RuntimeError("утилита whois недоступна")
    proc = await asyncio.create_subprocess_exec(
        "whois", domain,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
    except asyncio.TimeoutError:
        proc.kill()
        raise RuntimeError("таймаут whois")
    text = out.decode("utf-8", "replace")
    if not text.strip():
        raise RuntimeError("whois: пустой ответ")
    return _parse_whois_text(text)


async def fetch_whois(domain: str, collector, client: httpx.AsyncClient) -> dict:
    errs = []
    for fn in (_from_rdap_factory(client), _from_tcp_whois, _from_whois_cli):
        try:
            return await fn(domain)
        except Exception as e:
            errs.append(f"{getattr(fn, '__name__', 'rdap')}: {e}")
    res = _empty("none")
    res["error"] = "; ".join(errs)[:300]
    return res


def _from_rdap_factory(client):
    async def _rdap(domain):
        return await _from_rdap(domain, client)
    _rdap.__name__ = "rdap"
    return _rdap
