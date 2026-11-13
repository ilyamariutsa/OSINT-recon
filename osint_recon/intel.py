"""Разведданные: утечки через инфостилеры (Hudson Rock), реквизиты с сайта, AS организации (RIPEstat)."""
import asyncio
import html
import re
from collections import Counter
from urllib.parse import urlparse

import httpx

from . import config


async def hudsonrock(domain: str, collector, client: httpx.AsyncClient) -> dict:
    """Hudson Rock Cavalier: сколько сотрудников/пользователей домена засветились в логах инфостилеров."""
    r = await client.get("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain",
                         params={"domain": domain}, timeout=40)
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code}")
    d = r.json()
    data = d.get("data") or {}
    emp_urls = [u for u in data.get("employees_urls") or [] if isinstance(u, dict)]
    cli_urls = [u for u in data.get("clients_urls") or [] if isinstance(u, dict)]
    for u in emp_urls + cli_urls:
        collector.add_host(urlparse(u.get("url") or "").hostname, source="hudsonrock")

    def _date(v):
        v = (v or "")[:10]
        return None if not v or v.startswith("1970") else v

    return {
        "employees": d.get("employees") or 0, "users": d.get("users") or 0,
        "third_parties": d.get("third_parties") or 0, "total": d.get("total") or 0,
        "last_employee": _date(d.get("last_employee_compromised")),
        "last_user": _date(d.get("last_user_compromised")),
        "employee_urls": [{"url": u.get("url"), "count": u.get("occurrence")} for u in emp_urls[:30]],
        "user_urls": [{"url": u.get("url"), "count": u.get("occurrence")} for u in cli_urls[:30]],
        "user_passwords": d.get("userPasswords") or {},
        "employee_passwords": d.get("employeePasswords") or {},
        "families": {k: v for k, v in (d.get("stealerFamilies") or {}).items() if k != "total"},
        "third_party_domains": d.get("thirdPartyDomains") if isinstance(d.get("thirdPartyDomains"), list)
        else ([d["thirdPartyDomains"]] if d.get("thirdPartyDomains") else []),
    }


# ---------------- реквизиты с сайта ----------------

def inn_valid(inn: str) -> bool:
    if not inn or not inn.isdigit():
        return False
    d = [int(x) for x in inn]
    if len(d) == 10:
        k = [2, 4, 10, 3, 5, 9, 4, 6, 8]
        return sum(a * b for a, b in zip(k, d)) % 11 % 10 == d[9]
    if len(d) == 12:
        k1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        k2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        return (sum(a * b for a, b in zip(k1, d)) % 11 % 10 == d[10]
                and sum(a * b for a, b in zip(k2, d)) % 11 % 10 == d[11])
    return False


def ogrn_valid(ogrn: str) -> bool:
    if not ogrn or not ogrn.isdigit():
        return False
    if len(ogrn) == 13:
        return int(ogrn[:12]) % 11 % 10 == int(ogrn[12])
    if len(ogrn) == 15:
        return int(ogrn[:14]) % 13 % 10 == int(ogrn[14])
    return False


SITE_PATHS = ["/", "/contacts", "/contacts/", "/kontakty/", "/about/", "/o-kompanii/", "/company/",
              "/rekvizity/", "/requisites/", "/about/requisites/", "/privacy/", "/policy/",
              "/politika-konfidencialnosti/", "/oferta/", "/legal/"]
_INN_RE = re.compile(r"ИНН(?:\s*/\s*КПП)?[\s:№.\-]*([0-9]{10}|[0-9]{12})(?![0-9])", re.I)
_OGRN_RE = re.compile(r"ОГРН(?:ИП)?[\s:№.\-]*([0-9]{13}|[0-9]{15})(?![0-9])", re.I)
_ORG_RE = re.compile(r"\b(ООО|АО|ПАО|ЗАО|НАО|ИП|ФГУП|ГУП|МУП|АНО|ФГБУ|ГБУ)\s*[«\"“„']([^»\"”'<>]{2,80})[»\"”']")
_EMAIL_RE = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", re.I)
_PHONE_RE = re.compile(r"(?:\+7|8)[\s(\-]*\d{3}[\s)\-]*\d{3}[\s\-]*\d{2}[\s\-]*\d{2}")


def _plain(text: str) -> str:
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"[\s ]+", " ", html.unescape(text))


async def site_requisites(domain: str) -> dict:
    """Реквизиты организации с сайта: ИНН/ОГРН (с проверкой контрольных сумм), названия юрлиц, e-mail, телефоны."""
    inns, ogrns, orgs, emails, phones = Counter(), Counter(), Counter(), Counter(), Counter()
    inn_pages: dict[str, list[str]] = {}
    checked = 0
    async with httpx.AsyncClient(verify=False, follow_redirects=True, max_redirects=5,
                                 timeout=httpx.Timeout(15, connect=7),
                                 headers={"User-Agent": config.USER_AGENT,
                                          "Accept-Language": "ru-RU,ru;q=0.9"}) as c:
        base = None
        for cand in (f"https://{domain}", f"https://www.{domain}", f"http://{domain}"):
            try:
                r = await c.get(cand + "/")
                if r.status_code < 500:
                    base = f"{r.url.scheme}://{r.url.host}"
                    break
            except (httpx.HTTPError, ValueError):
                continue
        if not base:
            return {"checked": 0, "error": "сайт недоступен"}
        sem = asyncio.Semaphore(4)

        async def one(path):
            nonlocal checked
            async with sem:
                try:
                    r = await c.get(base + path)
                except (httpx.HTTPError, ValueError):
                    return
                if r.status_code != 200 or "html" not in r.headers.get("content-type", "html"):
                    return
                checked += 1
                t = _plain(r.text[:800_000])
                for m in _INN_RE.findall(t):
                    if inn_valid(m):
                        inns[m] += 1
                        inn_pages.setdefault(m, []).append(path)
                for m in _OGRN_RE.findall(t):
                    if ogrn_valid(m):
                        ogrns[m] += 1
                for form, name in _ORG_RE.findall(t):
                    orgs[f"{form} «{name.strip()}»"] += 1
                for e in _EMAIL_RE.findall(t):
                    e = e.lower()
                    if not e.endswith((".png", ".jpg", ".svg", ".webp", ".gif")):
                        emails[e] += 1
                for p in _PHONE_RE.findall(t):
                    phones[re.sub(r"[^\d+]", "", p)] += 1

        await asyncio.gather(*(one(p) for p in SITE_PATHS))
    return {
        "base": base, "checked": checked,
        "inns": [{"inn": k, "count": v, "pages": sorted(set(inn_pages.get(k, [])))[:5]}
                 for k, v in inns.most_common(5)],
        "ogrns": [k for k, _ in ogrns.most_common(5)],
        "orgs": [k for k, _ in orgs.most_common(8)],
        "emails": [k for k, _ in emails.most_common(20)],
        "phones": [k for k, _ in phones.most_common(10)],
    }


# ---------------- AS организации ----------------

async def ripe_search(term: str, client: httpx.AsyncClient) -> list[dict]:
    """Поиск AS по ключевому слову (название организации/бренда) в RIPEstat."""
    if not term or len(term) < 3:
        return []
    r = await client.get("https://stat.ripe.net/data/searchcomplete/data.json",
                         params={"resource": term}, timeout=25)
    out = []
    for cat in (r.json().get("data") or {}).get("categories") or []:
        if cat.get("category") != "ASNs":
            continue
        for s in cat.get("suggestions") or []:
            out.append({"asn": s.get("value"), "name": s.get("description") or s.get("label")})
    return out[:15]


# ---------------- транслитерация бренда ----------------

_TR = [("shch", "щ"), ("sch", "щ"), ("zh", "ж"), ("kh", "х"), ("ts", "ц"), ("ch", "ч"), ("sh", "ш"),
       ("yu", "ю"), ("ya", "я"), ("yo", "ё"), ("ye", "е"), ("ck", "к"), ("ph", "ф"), ("th", "т"),
       ("qu", "кв"), ("x", "кс"), ("w", "в"), ("q", "к"), ("j", "дж"), ("a", "а"), ("b", "б"),
       ("c", "к"), ("d", "д"), ("e", "е"), ("f", "ф"), ("g", "г"), ("h", "х"), ("i", "и"), ("k", "к"),
       ("l", "л"), ("m", "м"), ("n", "н"), ("o", "о"), ("p", "п"), ("r", "р"), ("s", "с"), ("t", "т"),
       ("u", "у"), ("v", "в"), ("y", "ы"), ("z", "з")]


def translit(word: str) -> str:
    w = word.lower()
    if w.endswith("sky"):
        return translit(w[:-3]) + "ский"
    out, i = "", 0
    while i < len(w):
        for lat, cyr in _TR:
            if w.startswith(lat, i):
                out += cyr
                i += len(lat)
                break
        else:
            out += w[i]
            i += 1
    return re.sub(r"([аеиоуыэюя])ы", r"\1й", out)


def brand_label(domain: str) -> str:
    parts = domain.split(".")
    lbl = parts[-3] if len(parts) >= 3 and ".".join(parts[-2:]) in ("com.ru", "net.ru", "org.ru", "msk.ru", "spb.ru") \
        else (parts[-2] if len(parts) >= 2 else parts[0])
    return re.sub(r"[^a-zа-яё0-9]", "", lbl.lower())
