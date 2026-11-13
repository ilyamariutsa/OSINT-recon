"""Пассивные источники субдоменов/IP. Каждая функция: fn(domain, collector, client)."""
import asyncio
import json
import re
from urllib.parse import urlparse

import httpx

from . import config


async def _get(client: httpx.AsyncClient, url: str, timeout: float = 30, headers: dict | None = None,
               retries: int = 1, ok=(200,)) -> httpx.Response:
    """GET с повтором на 429/5xx и сетевых ошибках."""
    last = None
    for attempt in range(retries + 1):
        try:
            r = await client.get(url, timeout=timeout, headers=headers)
            if r.status_code in ok:
                return r
            last = f"HTTP {r.status_code}"
            if r.status_code in (401, 403) and headers:
                last += " (проверьте API-ключ)"
            if r.status_code not in (429, 500, 502, 503, 504, 520, 522, 524):
                break
        except httpx.HTTPError as e:
            last = e.__class__.__name__
        if attempt < retries:
            await asyncio.sleep(3 + attempt * 3)
    raise RuntimeError(last or "нет ответа")


async def _get_json(client, url, timeout=30, headers=None, retries=1):
    r = await _get(client, url, timeout=timeout, headers=headers, retries=retries)
    try:
        return r.json()
    except ValueError:
        raise RuntimeError("ответ не JSON (сервис вернул HTML/ошибку)")


def _hosts_from_text(domain: str, text: str) -> set[str]:
    pat = re.compile(r"(?<![a-z0-9_.\-])((?:[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?\.)+"
                     + re.escape(domain) + r")(?![a-z0-9\-])", re.I)
    return {m.lower() for m in pat.findall(text)}


# ---------------- без ключей ----------------

async def src_crtsh(domain, collector, client):
    """Certificate Transparency: crt.sh (медленный, до минуты)."""
    r = await _get(client, f"https://crt.sh/?q=%25.{domain}&output=json", timeout=60, retries=2,
                   ok=(200, 404))
    if r.status_code == 404:  # crt.sh так отвечает, когда сертификатов нет
        return
    try:
        rows = r.json()
    except ValueError:
        raise RuntimeError("crt.sh вернул не-JSON (перегружен)")
    for row in rows:
        for name in str(row.get("name_value", "")).split("\n"):
            collector.add_host(name, source="crt.sh")
        collector.add_host(row.get("common_name"), source="crt.sh")


async def src_certspotter(domain, collector, client):
    """Cert Spotter: CT-логи (без ключа — ограниченная выдача)."""
    data = await _get_json(
        client, f"https://api.certspotter.com/v1/issuances?domain={domain}"
                f"&include_subdomains=true&expand=dns_names", timeout=40, retries=0)
    if isinstance(data, dict):
        raise RuntimeError(str(data.get("message") or data.get("error") or "ограничение без ключа"))
    for item in data:
        for name in item.get("dns_names") or []:
            collector.add_host(name, source="certspotter")


async def src_hackertarget(domain, collector, client):
    """HackerTarget hostsearch: 'host,ip' построчно."""
    r = await _get(client, f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=30)
    text = r.text
    if "API count exceeded" in text or "exceeded" in text[:200].lower():
        raise RuntimeError("исчерпан суточный лимит бесплатных запросов")
    for line in text.splitlines():
        if "," in line:
            host, _, ip = line.strip().partition(",")
            collector.add_host(host, ip=ip.strip(), source="hackertarget")


def _otx_headers():
    k = config.key("otx")
    return {"X-OTX-API-KEY": k} if k else None


async def src_otx_pdns(domain, collector, client):
    """AlienVault OTX: пассивный DNS (без ключа часто 429)."""
    try:
        data = await _get_json(
            client, f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=45, headers=_otx_headers(), retries=2)
    except RuntimeError as e:
        if "429" in str(e) and not config.key("otx"):
            raise RuntimeError("лимит анонимного доступа — добавьте бесплатный ключ OTX в настройках")
        raise
    for item in data.get("passive_dns") or []:
        ip = item.get("address") if item.get("record_type") in ("A", "AAAA", None) else None
        collector.add_host(item.get("hostname"), ip=ip, source="otx")


async def src_otx_urls(domain, collector, client):
    """AlienVault OTX: известные URL по домену."""
    data = await _get_json(
        client, f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500",
        timeout=45, headers=_otx_headers(), retries=2)
    for item in data.get("url_list") or []:
        collector.add_host(urlparse(item.get("url", "")).hostname, source="otx")


async def src_urlscan(domain, collector, client):
    """urlscan.io: история сканов страниц домена."""
    k = config.key("urlscan")
    data = await _get_json(client, f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000",
                           timeout=40, headers={"API-Key": k} if k else None)
    for item in data.get("results") or []:
        page = item.get("page") or {}
        collector.add_host(page.get("domain"), ip=page.get("ip"), source="urlscan")
        task = item.get("task") or {}
        collector.add_host(task.get("domain"), source="urlscan")


async def src_wayback(domain, collector, client):
    """Wayback Machine CDX: хосты из архивных URL (может быть медленно)."""
    r = await _get(client, f"https://web.archive.org/cdx/search/cdx?url=*.{domain}"
                           f"&output=txt&fl=original&collapse=urlkey&limit=40000",
                   timeout=90, retries=0)
    for line in r.text.splitlines():
        host = urlparse(line.strip()).hostname
        collector.add_host(host, source="wayback")


async def src_rapiddns(domain, collector, client):
    """RapidDNS: пассивный DNS по субдоменам (HTML)."""
    r = await _get(client, f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=50, retries=0)
    for host in _hosts_from_text(domain, r.text):
        collector.add_host(host, source="rapiddns")


async def src_anubis(domain, collector, client):
    """AnubisDB: база субдоменов."""
    data = await _get_json(client, f"https://anubisdb.com/anubis/subdomains/{domain}", timeout=45)
    if not isinstance(data, list):
        raise RuntimeError("неожиданный формат ответа")
    for name in data:
        collector.add_host(name, source="anubis")


async def src_subdomain_center(domain, collector, client):
    """subdomain.center: агрегированная база субдоменов."""
    data = await _get_json(client, f"https://api.subdomain.center/?domain={domain}", timeout=60)
    if not isinstance(data, list):
        raise RuntimeError("неожиданный формат ответа")
    for name in data:
        collector.add_host(name, source="subdomain.center")


async def src_dnsrepo(domain, collector, client):
    """DNSRepo (noc.org): пассивный DNS."""
    r = await _get(client, f"https://dnsrepo.noc.org/?search=.{domain}", timeout=40)
    for host in _hosts_from_text(domain, r.text):
        collector.add_host(host, source="dnsrepo")


async def src_commoncrawl(domain, collector, client):
    """Common Crawl: хосты из свежего индекса веб-краула."""
    idx_list = await _get_json(client, "https://index.commoncrawl.org/collinfo.json", timeout=20)
    if not idx_list:
        raise RuntimeError("список индексов пуст")
    errors = []
    for idx in [x.get("id") for x in idx_list[:1] if x.get("id")]:
        try:
            r = await _get(client, f"https://index.commoncrawl.org/{idx}-index?url=*.{domain}"
                                   f"&output=json&fl=url&limit=3000", timeout=50, retries=1,
                           ok=(200, 404))
        except RuntimeError as e:
            errors.append(str(e))
            continue
        for line in r.text.splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            collector.add_host(urlparse(obj.get("url", "")).hostname, source="commoncrawl")
        return
    raise RuntimeError("; ".join(errors) or "индекс недоступен")


# ---------------- с ключами ----------------

async def src_netlas(domain, collector, client):
    """Netlas.io: домены + A-записи."""
    data = await _get_json(
        client, f"https://app.netlas.io/api/domains/?q=domain:*.{domain}&size=400&source_type=include",
        timeout=40, headers={"X-API-Key": config.key("netlas")})
    for item in data.get("items") or data.get("domains") or []:
        d = item.get("data") or item
        name = d.get("domain")
        collector.add_host(name, source="netlas")
        for ip in (d.get("a") or d.get("last_a_record") or [])[:4]:
            collector.add_host(name, ip=ip, source="netlas")


async def src_whoisxml(domain, collector, client):
    """WhoisXML API: субдомены."""
    data = await _get_json(
        client, f"https://subdomains.whoisxmlapi.com/api/v1?apiKey={config.key('whoisxml')}"
                f"&domainName={domain}", timeout=40)
    for rec in (data.get("result") or {}).get("records") or []:
        collector.add_host(rec.get("domain") if isinstance(rec, dict) else rec, source="whoisxml")


async def src_shodan(domain, collector, client):
    """Shodan DNS-перечисление."""
    data = await _get_json(
        client, f"https://api.shodan.io/dns/domain/{domain}?key={config.key('shodan')}", timeout=40)
    for item in data.get("data") or []:
        sub = item.get("subdomain")
        name = f"{sub}.{domain}" if sub else domain
        ip = item.get("value") if item.get("type") in ("A", "AAAA") else None
        collector.add_host(name, ip=ip, source="shodan")
    for sub in data.get("subdomains") or []:
        collector.add_host(f"{sub}.{domain}", source="shodan")


async def src_virustotal(domain, collector, client):
    """VirusTotal: субдомены (до 10 страниц по 40)."""
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    hdr = {"x-apikey": config.key("virustotal")}
    for _ in range(10):
        data = await _get_json(client, url, timeout=40, headers=hdr)
        for item in data.get("data") or []:
            collector.add_host(item.get("id"), source="virustotal")
        url = (data.get("links") or {}).get("next")
        if not url:
            break
        await asyncio.sleep(16)  # публичный ключ: 4 запроса/мин


async def src_securitytrails(domain, collector, client):
    """SecurityTrails: субдомены."""
    data = await _get_json(
        client, f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=false",
        timeout=40, headers={"APIKEY": config.key("securitytrails")})
    for prefix in data.get("subdomains") or []:
        collector.add_host(f"{prefix}.{domain}", source="securitytrails")


async def src_chaos(domain, collector, client):
    """ProjectDiscovery Chaos: база субдоменов."""
    data = await _get_json(client, f"https://dns.projectdiscovery.io/dns/{domain}/subdomains",
                           timeout=40, headers={"Authorization": config.key("chaos")})
    for prefix in data.get("subdomains") or []:
        collector.add_host(f"{prefix}.{domain}", source="chaos")


async def src_fullhunt(domain, collector, client):
    """FullHunt: поверхность атаки домена."""
    data = await _get_json(client, f"https://fullhunt.io/api/v1/domain/{domain}/subdomains",
                           timeout=40, headers={"X-API-KEY": config.key("fullhunt")})
    for name in data.get("hosts") or []:
        collector.add_host(name, source="fullhunt")


async def src_bevigil(domain, collector, client):
    """BeVigil: субдомены из мобильных приложений."""
    data = await _get_json(client, f"https://osint.bevigil.com/api/{domain}/subdomains/",
                           timeout=40, headers={"X-Access-Token": config.key("bevigil")})
    for name in data.get("subdomains") or []:
        collector.add_host(name, source="bevigil")


FREE = [
    ("crt.sh", src_crtsh, "Certificate Transparency (crt.sh)"),
    ("certspotter", src_certspotter, "Cert Spotter CT-логи"),
    ("hackertarget", src_hackertarget, "HackerTarget hostsearch"),
    ("otx", src_otx_pdns, "AlienVault OTX пассивный DNS"),
    ("otx-urls", src_otx_urls, "AlienVault OTX URL"),
    ("urlscan", src_urlscan, "urlscan.io история сканов"),
    ("wayback", src_wayback, "Web Archive CDX"),
    ("rapiddns", src_rapiddns, "RapidDNS пассивный DNS"),
    ("anubis", src_anubis, "AnubisDB"),
    ("subdomain.center", src_subdomain_center, "subdomain.center"),
    ("dnsrepo", src_dnsrepo, "DNSRepo пассивный DNS"),
    ("commoncrawl", src_commoncrawl, "Common Crawl индекс"),
]

KEYED = [
    ("virustotal", src_virustotal, "VirusTotal"),
    ("securitytrails", src_securitytrails, "SecurityTrails"),
    ("shodan", src_shodan, "Shodan DNS"),
    ("netlas", src_netlas, "Netlas.io"),
    ("chaos", src_chaos, "ProjectDiscovery Chaos"),
    ("fullhunt", src_fullhunt, "FullHunt"),
    ("bevigil", src_bevigil, "BeVigil"),
    ("whoisxml", src_whoisxml, "WhoisXML API"),
]


def build() -> list[dict]:
    """Список источников с метаданными (включая зависящие от ключей)."""
    defs = [{"name": n, "fn": fn, "desc": d, "group": "passive"} for n, fn, d in FREE]
    for name, fn, desc in KEYED:
        has = bool(config.key(name))
        defs.append({"name": name, "fn": fn if has else None, "group": "passive",
                     "desc": desc + (" (ключ)" if has else " — нужен API-ключ (Настройки)")})
    return defs
