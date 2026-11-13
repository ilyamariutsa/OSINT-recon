"""Правила оценки: из собранных данных — список находок с критичностью и рекомендациями."""
from datetime import datetime, timezone

from .fingerprints import PORTS

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_LABEL = {"critical": "Критично", "high": "Высокий", "medium": "Средний", "low": "Низкий", "info": "Инфо"}


def _f(sev, cat, title, detail="", items=None, rec=""):
    return {"sev": sev, "cat": cat, "title": title, "detail": detail, "items": (items or [])[:300],
            "count": len(items or []), "rec": rec}


def build(r: dict) -> list[dict]:
    out: list[dict] = []
    hosts = r.get("hosts") or []
    ips = {i["ip"]: i for i in r.get("ips") or []}
    ip_hosts: dict[str, list[str]] = {}
    for h in hosts:
        for ip in h.get("current_ips") or []:
            ip_hosts.setdefault(ip, []).append(h["name"])

    # --- DNS ---
    axfr = r.get("axfr") or {}
    if axfr.get("vulnerable"):
        out.append(_f("critical", "DNS", "Разрешена передача зоны (AXFR)",
                      "Любой может выгрузить все DNS-записи домена.",
                      [f'{v["ns"]} ({v.get("ip")}) — {v.get("records")} записей' for v in axfr["vulnerable"]],
                      "Запретить AXFR для всех, кроме вторичных NS (allow-transfer)."))
    tk = r.get("takeover") or []
    hi = [t for t in tk if t.get("confidence") == "high"]
    md = [t for t in tk if t.get("confidence") != "high"]
    if hi:
        out.append(_f("high", "DNS", "Возможен захват поддоменов (subdomain takeover)",
                      "CNAME указывает на внешний сервис, где ресурс не занят — его может зарегистрировать "
                      "посторонний и разместить контент на вашем поддомене.",
                      [f'{t["host"]} → {t["cname"]} ({t["service"]}: {t["reason"]})' for t in hi],
                      "Удалить висячие CNAME или занять ресурс на стороне сервиса."))
    if md:
        out.append(_f("medium", "DNS", "Висячие CNAME-записи",
                      "CNAME ссылается на несуществующее имя. Проверьте, нельзя ли зарегистрировать цель.",
                      [f'{t["host"]} → {t["cname"]}' for t in md], "Удалить неиспользуемые записи."))
    priv = sorted({f'{h["name"]} → {ip}' for h in hosts for ip in h.get("current_ips") or []
                   if ips.get(ip, {}).get("private")})
    if priv:
        out.append(_f("low", "DNS", "Внутренние IP-адреса в публичном DNS",
                      "Раскрывают адресацию внутренней сети.", priv,
                      "Вынести внутренние имена в отдельную (split-horizon) зону."))
    if r.get("wildcard"):
        out.append(_f("info", "DNS", "Wildcard DNS", "Любое имя в зоне резолвится — результаты перебора "
                      "отфильтрованы по этим адресам.", sorted(r["wildcard"])))
    dns = r.get("dns") or {}
    if dns and not dns.get("CAA"):
        out.append(_f("info", "DNS", "Нет CAA-записи",
                      "Сертификат на домен может выпустить любой удостоверяющий центр.", [],
                      "Добавить CAA с разрешёнными УЦ."))

    # --- почта ---
    em = r.get("email") or {}
    for iss in em.get("issues") or []:
        out.append(_f(iss["sev"], "Почта", iss["text"], "", [],
                      "Настроить SPF с -all, DMARC p=reject (или quarantine), DKIM-подпись."))

    # --- домен ---
    w = r.get("whois") or {}
    exp = _parse_date(w.get("expires"))
    if exp:
        days = (exp - datetime.now(timezone.utc)).days
        if days < 0:
            out.append(_f("high", "Домен", f"Срок регистрации домена истёк ({w.get('expires')})"))
        elif days < 30:
            out.append(_f("high", "Домен", f"Регистрация домена истекает через {days} дн.",
                          f"Дата: {w.get('expires')}", [], "Продлить регистрацию, включить автопродление."))
        elif days < 60:
            out.append(_f("medium", "Домен", f"Регистрация домена истекает через {days} дн.",
                          f"Дата: {w.get('expires')}"))

    # --- утечки ---
    hr = r.get("leaks") or {}
    if hr.get("employees"):
        out.append(_f("high", "Утечки", f"Скомпрометированы устройства сотрудников: {hr['employees']}",
                      "Учётные данные корпоративных ресурсов найдены в логах инфостилеров (Hudson Rock). "
                      f"Последний случай: {hr.get('last_employee') or '—'}.",
                      [f'{u["url"]} ({u["count"]})' for u in hr.get("employee_urls") or []],
                      "Сбросить пароли затронутых учёток, включить MFA, проверить устройства."))
    if hr.get("users"):
        out.append(_f("medium" if hr["users"] > 50 else "low", "Утечки",
                      f"Учётки пользователей/клиентов в логах инфостилеров: {hr['users']}",
                      f"Последний случай: {hr.get('last_user') or '—'}. Риск credential stuffing.",
                      [f'{u["url"]} ({u["count"]})' for u in hr.get("user_urls") or []],
                      "Защита от перебора и подстановки паролей, MFA, мониторинг входов."))

    # --- сеть: порты и CVE ---
    port_items: dict[str, list[str]] = {}
    port_sev: dict[str, str] = {}
    vulns: list[str] = []
    for ip, info in ips.items():
        hn = ", ".join(ip_hosts.get(ip, [])[:3])
        for p in sorted(set((info.get("ports") or []))):
            svc, sev = PORTS.get(p, (f"порт {p}", "info"))
            if SEV_ORDER[sev] > SEV_ORDER["medium"]:
                continue
            key = f"{svc} ({p}/tcp)"
            port_items.setdefault(key, []).append(f"{ip}:{p}" + (f" — {hn}" if hn else ""))
            port_sev[key] = sev
        if info.get("vulns"):
            vulns.append(f'{ip}{(" — " + hn) if hn else ""}: {", ".join(info["vulns"][:12])}'
                         + (f' и ещё {len(info["vulns"]) - 12}' if len(info["vulns"]) > 12 else ""))
    for key in sorted(port_items, key=lambda k: SEV_ORDER[port_sev[k]]):
        out.append(_f(port_sev[key], "Сеть", f"Доступен из интернета: {key}",
                      "Сервис не должен быть открыт наружу без необходимости.", port_items[key],
                      "Закрыть доступ на межсетевом экране или ограничить по IP/VPN."))
    if vulns:
        out.append(_f("high", "Сеть", f"Известные уязвимости (CVE) по данным Shodan: {len(vulns)} IP",
                      "Сопоставление версий ПО с CVE без эксплуатации — требует ручной проверки.", vulns,
                      "Обновить ПО, проверить применимость CVE."))

    # --- веб ---
    web = r.get("web") or []
    by_cat: dict[str, list[str]] = {}
    for s in web:
        for t, c in (s.get("tech_cat") or {}).items():
            if c in ("admin", "remote", "devops", "mail"):
                by_cat.setdefault(c, []).append(f'{s["host"]} — {t} [{s.get("status")}]')
    if by_cat.get("admin"):
        out.append(_f("medium", "Веб", "Панели администрирования доступны из интернета", "",
                      by_cat["admin"], "Ограничить доступ по VPN/IP, включить MFA."))
    if by_cat.get("remote"):
        out.append(_f("medium", "Веб", "Шлюзы удалённого доступа (VPN/VDI/SSO)",
                      "Частая цель подбора паролей и эксплуатации известных уязвимостей.",
                      by_cat["remote"], "Своевременно обновлять, MFA, мониторинг входов."))
    if by_cat.get("devops"):
        out.append(_f("low", "Веб", "Инструменты разработки и мониторинга снаружи", "",
                      by_cat["devops"], "Проверить, нужен ли внешний доступ; закрыть анонимный доступ."))
    if by_cat.get("mail"):
        out.append(_f("low", "Веб", "Веб-интерфейсы почты", "Цель фишинга и подбора паролей.",
                      by_cat["mail"], "MFA, защита от перебора."))
    listing = [f'{s["host"]}' for s in web if "Directory listing" in (s.get("tech") or [])]
    if listing:
        out.append(_f("medium", "Веб", "Открыт листинг каталогов", "", listing,
                      "Отключить autoindex/Directory Browsing."))
    http_only = [s["host"] for s in web if s.get("http_only")]
    if http_only:
        out.append(_f("low", "Веб", "Сайты без HTTPS", "Данные передаются в открытом виде.", http_only,
                      "Включить HTTPS и редирект с HTTP."))
    tls = r.get("tls") or {}
    expired = [f'{h} (до {v["not_after"][:10]})' for h, v in tls.items() if v.get("expired")]
    soon = [f'{h} — {v["days_left"]} дн.' for h, v in tls.items() if 0 <= (v.get("days_left") or 99) < 21]
    selfs = [h for h, v in tls.items() if v.get("self_signed")]
    mism = [f'{h} (CN={v.get("subject_cn")})' for h, v in tls.items()
            if not v.get("hostname_match") and not v.get("self_signed")]
    if expired:
        out.append(_f("medium", "TLS", "Просроченные TLS-сертификаты", "", expired, "Обновить сертификаты."))
    if soon:
        out.append(_f("low", "TLS", "TLS-сертификаты истекают в ближайшие 3 недели", "", soon))
    if selfs:
        out.append(_f("low", "TLS", "Самоподписанные сертификаты", "", selfs))
    if mism:
        out.append(_f("low", "TLS", "Сертификат не соответствует имени хоста", "", mism))

    dev = sorted({h["name"] for h in hosts if h.get("alive") and h.get("dev")})
    if dev:
        out.append(_f("low", "Периметр", "Тестовые/старые окружения доступны из интернета",
                      "dev/test/stage/old-хосты часто хуже защищены.", dev,
                      "Закрыть доступ извне или выключить неиспользуемые окружения."))
    out.sort(key=lambda f: (SEV_ORDER[f["sev"]], -f["count"]))
    return out


def _parse_date(v):
    if not v:
        return None
    s = str(v).strip().replace("Z", "").replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y.%m.%d", "%d.%m.%Y", "%d-%b-%Y"):
        try:
            return datetime.strptime(s[:19] if " " in s else s[:10], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def counts(findings: list[dict]) -> dict:
    c = {k: 0 for k in SEV_ORDER}
    for f in findings:
        c[f["sev"]] += 1
    return c
