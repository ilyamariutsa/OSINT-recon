"""Обогащение IP: ip-api.com (батч), RDAP (резерв), Shodan InternetDB (порты/CVE без ключа). С кэшем."""
import asyncio
import ipaddress
import time

import httpx

_CACHE: dict[str, tuple[float, dict]] = {}
_IDB_CACHE: dict[str, tuple[float, dict]] = {}
CACHE_TTL = 12 * 3600

_FIELDS = "status,message,country,countryCode,city,isp,org,as,asname,reverse,proxy,hosting,mobile,query"


def _minimal() -> dict:
    return {"country": "", "countryCode": "", "city": "", "isp": "", "org": "",
            "as": "", "asname": "", "reverse": "", "proxy": False, "mobile": False,
            "hosting": False, "source": "—"}


def is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


async def _rdap_fallback(ips: list[str], result: dict[str, dict], client: httpx.AsyncClient) -> None:
    sem = asyncio.Semaphore(6)

    async def one(ip: str) -> None:
        async with sem:
            try:
                r = await client.get(f"https://rdap.org/ip/{ip}", timeout=20)
                if r.status_code != 200:
                    return
                d = r.json()
                info = _minimal()
                info.update({"country": d.get("country") or "", "countryCode": d.get("country") or "",
                             "org": d.get("name") or "", "source": "rdap"})
                if d.get("startAddress") and d.get("endAddress"):
                    info["range"] = f'{d["startAddress"]} — {d["endAddress"]}'
                result[ip] = info
                _CACHE[ip] = (time.time(), info)
            except (httpx.HTTPError, ValueError):
                pass

    await asyncio.gather(*(one(ip) for ip in ips))


async def enrich(ips: list[str], client: httpx.AsyncClient) -> dict[str, dict]:
    """Справка по каждому IP: страна, организация, AS, PTR, признаки хостинга/прокси."""
    now = time.time()
    result: dict[str, dict] = {}
    missing: list[str] = []
    for ip in ips:
        cached = _CACHE.get(ip)
        if cached and now - cached[0] < CACHE_TTL:
            result[ip] = cached[1]
        else:
            missing.append(ip)

    public = [ip for ip in missing if is_public(ip)]
    for ip in missing:
        if not is_public(ip):
            info = _minimal()
            info["org"] = "частная/служебная сеть"
            result[ip] = info

    chunks = [public[i:i + 100] for i in range(0, len(public), 100)]
    for i, chunk in enumerate(chunks):
        ok = False
        try:
            r = await client.post(f"http://ip-api.com/batch?fields={_FIELDS}&lang=ru",
                                  json=chunk, timeout=25)
            if r.status_code == 200:
                for row in r.json():
                    ip = row.get("query")
                    if not ip:
                        continue
                    if row.get("status") != "success":
                        info = _minimal()
                    else:
                        info = {
                            "country": row.get("country") or "", "countryCode": row.get("countryCode") or "",
                            "city": row.get("city") or "", "isp": row.get("isp") or "",
                            "org": row.get("org") or "", "as": row.get("as") or "",
                            "asname": row.get("asname") or "", "reverse": row.get("reverse") or "",
                            "proxy": bool(row.get("proxy")), "mobile": bool(row.get("mobile")),
                            "hosting": bool(row.get("hosting")), "source": "ip-api",
                        }
                    result[ip] = info
                    _CACHE[ip] = (time.time(), info)
                ok = True
            elif r.status_code == 429:
                await asyncio.sleep(30)
        except (httpx.HTTPError, ValueError):
            pass
        if not ok:
            await _rdap_fallback(chunk[:120], result, client)
        elif i < len(chunks) - 1:
            await asyncio.sleep(4.2)  # лимит 15 батчей/мин
    for ip in missing:
        result.setdefault(ip, _minimal())
    return result


async def internetdb(ips: list[str], client: httpx.AsyncClient, limit: int = 600) -> dict:
    """Shodan InternetDB: открытые порты, CPE, CVE, теги — без ключа. Быстрый отказ, если сервис недоступен."""
    targets = [ip for ip in ips if is_public(ip)][:limit]
    out: dict[str, dict] = {}
    if not targets:
        return {"available": True, "data": out}
    now = time.time()

    async def fetch(ip: str, timeout: float) -> dict | None:
        cached = _IDB_CACHE.get(ip)
        if cached and now - cached[0] < CACHE_TTL:
            return cached[1]
        r = await client.get(f"https://internetdb.shodan.io/{ip}", timeout=timeout)
        if r.status_code == 404:
            data = {}
        elif r.status_code == 200:
            d = r.json()
            data = {k: d.get(k) or [] for k in ("ports", "cpes", "vulns", "tags", "hostnames")}
        else:
            raise RuntimeError(f"HTTP {r.status_code}")
        _IDB_CACHE[ip] = (time.time(), data)
        return data

    try:  # пробный запрос: в некоторых сетях Shodan заблокирован
        first = await fetch(targets[0], httpx.Timeout(10, connect=6))
        if first:
            out[targets[0]] = first
    except (httpx.HTTPError, RuntimeError, ValueError) as e:
        return {"available": False, "error": f"недоступен из этой сети ({e.__class__.__name__})", "data": out}

    sem = asyncio.Semaphore(8)
    errors = 0

    async def one(ip):
        nonlocal errors
        if errors > 15:
            return
        async with sem:
            try:
                d = await fetch(ip, 15)
                if d:
                    out[ip] = d
            except (httpx.HTTPError, RuntimeError, ValueError):
                errors += 1

    await asyncio.gather(*(one(ip) for ip in targets[1:]))
    return {"available": True, "data": out, "checked": len(targets)}


async def asn_prefixes(asns: list[str], client: httpx.AsyncClient) -> dict[str, list[str]]:
    """Анонсируемые префиксы AS (RIPEstat)."""
    out: dict[str, list[str]] = {}

    async def one(asn: str):
        try:
            r = await client.get("https://stat.ripe.net/data/announced-prefixes/data.json",
                                 params={"resource": asn}, timeout=30)
            prefixes = [p.get("prefix") for p in (r.json().get("data") or {}).get("prefixes") or []]
            out[asn] = sorted({p for p in prefixes if p}, key=lambda p: (":" in p, p))
        except (httpx.HTTPError, ValueError):
            pass

    await asyncio.gather(*(one(a) for a in asns[:10]))
    return out
