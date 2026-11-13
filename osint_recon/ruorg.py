"""РФ-обогащение: ЕГРЮЛ (egrul.nalog.ru), бухотчётность ФНС (bo.nalog.gov.ru),
Федресурс (best effort), поиск связанных организаций («дочек») по ключевому слову."""
import asyncio
import re

import httpx

EGRL = "https://egrul.nalog.ru"
BO = "https://bo.nalog.gov.ru"
FEDRESURS = "https://fedresurs.ru"

STATUS_MAP = {
    "ACTIVE": "Действующая",
    "LIQUIDATION_STAGE": "Ликвидация",
    "LIQUIDATED": "Ликвидирована",
    "CEASED": "Прекратила деятельность",
    "REORGANIZATION": "Реорганизация",
    "IN_THE_PROCESS_OF_REORGANIZATION": "В процессе реорганизации",
    "IN_THE_PROCESS_OF_LIQUIDATION": "В процессе ликвидации",
    "BANKRUPTCY": "Банкротство",
    "IN_THE_PROCESS_OF_BANKRUPTCY": "В процессе банкротства",
    "INACTIVE": "Недействующая",
}

_LEGAL_FORMS = (
    r"^(ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ|ПУБЛИЧНОЕ АКЦИОНЕРНОЕ ОБЩЕСТВО|"
    r"АКЦИОНЕРНОЕ ОБЩЕСТВО|НЕПУБЛИЧНОЕ АКЦИОНЕРНОЕ ОБЩЕСТВО|"
    r"ФЕДЕРАЛЬНОЕ ГОСУДАРСТВЕННОЕ (БЮДЖЕТНОЕ|КАЗЁННОЕ|АВТОНОМНОЕ) УЧРЕЖДЕНИЕ|"
    r"ГОСУДАРСТВЕННОЕ (БЮДЖЕТНОЕ|КАЗЁННОЕ|АВТОНОМНОЕ) УЧРЕЖДЕНИЕ|"
    r"МУНИЦИПАЛЬНОЕ (БЮДЖЕТНОЕ|КАЗЁННОЕ|АВТОНОМНОЕ) УЧРЕЖДЕНИЕ|ЧАСТНОЕ УЧРЕЖДЕНИЕ|"
    r"ИНДИВИДУАЛЬНЫЙ ПРЕДПРИНИМАТЕЛЬ)\s*"
)

_ABBR = {"ООО", "АО", "ПАО", "ЗАО", "НАО", "НКО", "ФГУП", "МУП", "ГУП", "ФГБУ", "ФГБОУ",
         "ФГКУ", "ФГАОУ", "МБОУ", "САО", "ТСЖ", "ЖСК", "КФХ", "СПК", "ОПЕРАТОР", "ГРУППА",
         "КОМПАНИЙ", "КОМПАНИЯ", "ХОЛДИНГ", "УПРАВЛЕНИЕ", "ЦЕНТР", "ОТДЕЛЕНИЕ", "ФИЛИАЛ"}


def base_keyword(name: str) -> str:
    """Первое значимое слово названия организации без орг-правовой формы."""
    n = re.sub(r"[«»\"'„“”\[\]()]", " ", (name or "").upper())
    n = re.sub(_LEGAL_FORMS, " ", n)
    words = [w for w in re.split(r"[\s.,\-–—]+", n)
             if len(w) >= 3 and not w.isdigit() and w not in _ABBR]
    return words[0] if words else ""


def _strip_tags(s: str | None) -> str | None:
    return re.sub(r"</?[a-z]+>", "", s) if s else s


async def egrul_search(client: httpx.AsyncClient, query: str, limit: int = 20) -> list[dict]:
    """Поиск в ЕГРЮЛ. Надёжно работает по ИНН/ОГРН; по названию — best effort."""
    payload = {"vyp3CaptchaToken": "", "page": "", "query": query, "region": "",
               "PreventChromeAutocomplete": ""}
    tok, last_err = None, None
    for attempt in range(2):  # сервис часто огрызается HTML-ошибкой с первого раза
        try:
            r = await client.post(f"{EGRL}/", data=payload, timeout=30)
            tok = r.json().get("t")
            break
        except ValueError as e:  # не-JSON (HTML «Ошибка», капча, лимит)
            last_err = f"ЕГРЮЛ вернул не-JSON ({e.__class__.__name__})"
        except httpx.HTTPError as e:
            last_err = f"ЕГРЮЛ недоступен ({e.__class__.__name__})"
        if attempt == 0:
            await asyncio.sleep(2)
    if not tok:
        raise RuntimeError(last_err or "ЕГРЮЛ: токен не получен (возможна капча)")
    r2 = await client.get(f"{EGRL}/search-result/{tok}", timeout=30)
    try:
        rows = r2.json().get("rows") or []
    except ValueError:
        raise RuntimeError("ЕГРЮЛ: не удалось получить результаты по токену")
    return [{
        "inn": x.get("i"), "ogrn": x.get("o"), "name": _strip_tags(x.get("n")),
        "short_name": _strip_tags(x.get("c")), "kpp": x.get("p"),
        "reg_date": x.get("r"), "region": x.get("rn"), "director": x.get("g"),
        "total": x.get("tot"),
    } for x in rows[:limit]]


async def bo_search(client: httpx.AsyncClient, query: str, limit: int = 10) -> list[dict]:
    """Поиск организаций в бухотчётности ФНС (bo.nalog.gov.ru)."""
    r = await client.get(f"{BO}/advanced-search/organizations/search",
                         params={"query": query, "page": 0, "pageSize": limit}, timeout=30)
    out = []
    for c in r.json().get("content") or []:
        addr = ", ".join(x for x in [c.get("index"), c.get("region"),
                                     c.get("city") or c.get("settlement"), c.get("street"),
                                     c.get("house")] if x)
        bfo = c.get("bfo") or {}
        out.append({
            "inn": c.get("inn"), "ogrn": c.get("ogrn"),
            "name": _strip_tags(c.get("shortName")) or c.get("shortName"),
            "address": addr or None, "okved": c.get("okved2"),
            "status": STATUS_MAP.get(c.get("statusCode"), c.get("statusCode")),
            "status_date": c.get("statusDate"),
            "bfo_period": bfo.get("period"), "revenue": bfo.get("gainSum"),
            "bo_id": c.get("id"),
        })
    return out


async def fedresurs_summary(client: httpx.AsyncClient, inn: str) -> dict:
    """Сообщения Федресурса по ИНН (банкротства, залоги, ликвидация). Best effort."""
    r = await client.post(f"{FEDRESURS}/backend/sfactmessages/search", json={
        "searchString": inn, "limit": 12, "offset": 0, "sortDirection": "desc"}, timeout=12)
    try:
        d = r.json()
    except ValueError:
        raise RuntimeError("недоступен с этого IP (антибот/ограничение)")
    msgs = []
    for m in (d.get("items") or d.get("content") or [])[:12]:
        msgs.append({
            "date": (m.get("datePublish") or m.get("date") or "")[:10],
            "type": m.get("type") or m.get("messageType") or "",
            "title": (m.get("title") or m.get("messageTitle") or "")[:160],
        })
    return {"total": d.get("total"), "messages": msgs}


def _norm(s: str | None) -> str:
    return re.sub(r"\s+", " ", (s or "")).strip().upper()


_FORM_WORDS = re.compile(
    r"\b(ООО|АО|ПАО|ЗАО|НАО|НКО|ФГУП|МУП|ГУП|ИП|ОПЕРАТОР|ГРУППА|КОМПАНИЙ|КОМПАНИЯ|"
    r"ХОЛДИНГ|ИНН|ОГРН)\b")


def _clean_name(name: str | None) -> str:
    """Название без кавычек и орг-правовых слов — для сравнения с ключевым словом."""
    n = re.sub(r"[«»\"'„“”]", "", _norm(name))
    n = re.sub(_LEGAL_FORMS, " ", n)
    n = _FORM_WORDS.sub(" ", n)
    return re.sub(r"\s+", " ", n).strip()


def pick_org(bo_rows: list[dict], inn: str | None, org_name: str | None) -> dict | None:
    """Выбрать наиболее подходящую организацию: по ИНН, затем по близости названия."""
    if not bo_rows:
        return None
    if inn:
        for r in bo_rows:
            if r.get("inn") == inn:
                return r
    kw = base_keyword(org_name or "")
    if kw:
        clean = _clean_name(org_name)
        def rank(r: dict) -> tuple[int, int]:
            cn = _clean_name(r.get("name"))
            if cn == kw or clean == cn:
                return (0, 0)            # точное совпадение бренда
            if cn.startswith(kw + " ") or cn.endswith(" " + kw):
                return (1, len(cn))      # бренд + уточнение
            return (2, len(cn))          # бренд содержится в названии
        return min(bo_rows, key=rank)
    return bo_rows[0]


async def org_profile(domain: str, whois: dict | None, manual_query: str | None,
                      client: httpx.AsyncClient, site: dict | None = None,
                      brand: str | None = None) -> dict:
    """Карточка организации РФ + возможные связанные («дочки»).

    Порядок привязки: подсказка пользователя (ИНН/название) → ИНН из whois → ИНН с сайта →
    организация из whois → кандидаты по названию домена (транслитерация)."""
    whois_org = (whois or {}).get("registrant_org")
    whois_inn = (whois or {}).get("registrant_inn")
    manual_inn = manual_query if (manual_query or "").isdigit() else None
    manual_name = manual_query if manual_query and not manual_query.isdigit() else None
    site_inns = [x["inn"] for x in (site or {}).get("inns") or []]
    site_inn = site_inns[0] if site_inns else None

    res: dict = {
        "query": manual_query or whois_inn or site_inn or whois_org or None,
        "basis": None, "org": None, "candidates": [], "affiliates": [], "brand_candidates": [],
        "fedresurs": None, "notes": [], "site_inns": site_inns,
    }
    official_name = None
    inn = manual_inn or whois_inn or site_inn

    async def by_inn(value: str, label: str) -> str | None:
        try:
            rows = await egrul_search(client, value)
        except Exception as e:
            res["notes"].append(f"ЕГРЮЛ по ИНН {value}: {e}")
            rows = []
        if rows:
            res["candidates"] = rows[:10]
            res["notes"].append(f"ЕГРЮЛ по ИНН {value} ({label}): найдено {len(rows)}")
            return rows[0].get("name") or rows[0].get("short_name")
        try:  # bo.nalog иногда находит и по ИНН
            alt = await bo_search(client, value, 10)
            if alt:
                res["notes"].append(f"bo.nalog.gov.ru по ИНН {value} ({label}): найдено {len(alt)}")
                return alt[0].get("name")
        except Exception:
            pass
        res["notes"].append(f"По ИНН {value} ({label}) организация не найдена")
        return None

    if manual_inn:
        res["basis"] = "ИНН указан вручную"
        official_name = await by_inn(manual_inn, "указан вручную")
    elif manual_name:
        res["basis"] = "название указано вручную"
        official_name = manual_name
        try:
            res["candidates"] = (await egrul_search(client, manual_name))[:10]
        except Exception:
            res["candidates"] = []  # поиск по названию в ЕГРЮЛ часто закрыт — не критично
    if not official_name and whois_inn:
        res["basis"] = "ИНН регистранта из whois"
        official_name = await by_inn(whois_inn, "whois")
    if not official_name and site_inn and site_inn != manual_inn:
        res["basis"] = "ИНН с сайта " + ", ".join((site or {}).get("inns", [{}])[0].get("pages") or [])
        official_name = await by_inn(site_inn, "с сайта")
        inn = site_inn
    if not official_name and whois_org:
        res["basis"] = "организация-регистрант из whois"
        official_name = whois_org
        res["notes"].append(f"Организация взята из whois: «{whois_org}»")

    if not official_name:
        kw_lat = brand or ""
        if kw_lat and len(kw_lat) >= 4:
            from .intel import translit
            kw = translit(kw_lat).upper()
            try:
                rows = await bo_search(client, kw, 10)
                res["brand_candidates"] = rows
                if rows:
                    res["notes"].append(
                        f"Регистрант скрыт, ИНН на сайте не найден. По названию домена «{kw_lat}» → «{kw}» "
                        f"найдены кандидаты ({len(rows)}). Проверьте и перезапустите сбор с нужным ИНН.")
            except Exception as e:
                res["notes"].append(f"bo.nalog.gov.ru: {e}")
        if not res["brand_candidates"]:
            res["notes"].append("Организация не определена: регистрант скрыт в whois, ИНН на сайте не найден. "
                                "Укажите ИНН или название при запуске сбора.")
        return res

    kw = base_keyword(official_name)
    if not kw:
        res["notes"].append(f"Не удалось выделить ключевое слово из названия: {official_name}")
        return res

    try:
        bo_rows = await bo_search(client, kw, 25)
    except Exception as e:
        res["notes"].append(f"bo.nalog.gov.ru недоступен: {e}")
        bo_rows = []

    chosen = None
    if bo_rows:
        chosen = pick_org(bo_rows, inn, official_name)
        res["org"] = chosen
        if chosen and not inn and chosen.get("inn"):
            res["notes"].append(f"Совпадение по названию, ИНН {chosen['inn']} — проверьте на checko.ru / rusprofile.ru")
        res["affiliates"] = [r for r in bo_rows
                             if not (chosen and r.get("inn") == chosen.get("inn"))][:20]
    else:
        res["notes"].append(f"bo.nalog.gov.ru: по «{kw}» ничего не найдено "
                            f"(у банков и госорганов отчётности в ФНС нет)")
        if res["candidates"]:
            c0 = res["candidates"][0]
            res["org"] = {"inn": c0.get("inn"), "ogrn": c0.get("ogrn"),
                          "name": c0.get("short_name") or c0.get("name"), "address": c0.get("region"),
                          "status": None, "director": c0.get("director")}

    target_inn = (res["org"] or {}).get("inn") or inn
    if target_inn:
        try:
            res["fedresurs"] = await fedresurs_summary(client, target_inn)
        except Exception as e:
            res["fedresurs"] = {"total": None, "messages": [], "error": f"недоступен: {str(e)[:80]}"}
    if res["org"] and not res["org"].get("director"):
        for c in res["candidates"]:
            if c.get("inn") == res["org"].get("inn"):
                res["org"]["director"] = c.get("director")
                res["org"]["kpp"] = c.get("kpp")
                res["org"]["reg_date"] = c.get("reg_date")
    return res
