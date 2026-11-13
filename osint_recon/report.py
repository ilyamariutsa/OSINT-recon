"""Экспорт: HTML-отчёт (печать/PDF из браузера) и XLSX-книга."""
import html
import io

from .findings import SEV_LABEL

E = lambda v: html.escape("" if v is None else str(v))  # noqa: E731
SEV_COLOR = {"critical": "#b91c1c", "high": "#dc2626", "medium": "#d97706", "low": "#2563eb", "info": "#64748b"}


def _table(head: list[str], rows: list[list], limit: int = 1500) -> str:
    if not rows:
        return '<p class="muted">Нет данных</p>'
    out = ["<table><thead><tr>", *[f"<th>{E(h)}</th>" for h in head], "</tr></thead><tbody>"]
    for r in rows[:limit]:
        out.append("<tr>" + "".join(f"<td>{c if isinstance(c, Raw) else E(c)}</td>" for c in r) + "</tr>")
    out.append("</tbody></table>")
    if len(rows) > limit:
        out.append(f'<p class="muted">Показаны первые {limit} из {len(rows)} — полный список в XLSX/CSV.</p>')
    return "".join(out)


class Raw(str):
    pass


def safe_cell(v):
    """Значение для XLSX/CSV: строки с =,+,-,@ не должны исполняться как формулы."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return "да" if v else ""
    if isinstance(v, (int, float)):
        return v
    s = str(v)[:32000]
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def html_report(r: dict) -> str:
    s = r.get("summary") or {}
    fc = s.get("findings") or {}
    org = (r.get("org") or {}).get("org") or {}
    w = r.get("whois") or {}
    em = r.get("email") or {}
    lk = r.get("leaks") or {}
    title = r.get("domain_unicode") or r.get("domain")
    parts = [f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>OSINT-отчёт — {E(title)}</title>
<style>
body{{font:13px/1.5 "Segoe UI",system-ui,sans-serif;color:#0f172a;margin:32px auto;max-width:1100px;padding:0 20px}}
h1{{font-size:24px;margin:0 0 4px}} h2{{font-size:17px;margin:28px 0 10px;border-bottom:2px solid #e2e8f0;padding-bottom:4px}}
h3{{font-size:14px;margin:16px 0 6px}} .muted{{color:#64748b}} table{{border-collapse:collapse;width:100%;margin:6px 0 10px;font-size:12px}}
th,td{{border:1px solid #e2e8f0;padding:4px 7px;text-align:left;vertical-align:top;word-break:break-word}} th{{background:#f1f5f9}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin:12px 0}}
.card{{border:1px solid #e2e8f0;border-radius:8px;padding:10px}} .card b{{font-size:20px;display:block}}
.sev{{display:inline-block;color:#fff;border-radius:4px;padding:1px 7px;font-size:11px;font-weight:600}}
.f{{border:1px solid #e2e8f0;border-left-width:4px;border-radius:6px;padding:8px 12px;margin:8px 0;page-break-inside:avoid}}
.f ul{{margin:4px 0 0 18px;padding:0;font-family:Consolas,monospace;font-size:11.5px}}
.kv td:first-child{{width:220px;background:#f8fafc;color:#475569}}
@media print{{body{{margin:0}} h2{{page-break-after:avoid}}}}
</style></head><body>
<h1>OSINT-отчёт: {E(title)}</h1>
<div class="muted">Сбор: {E((r.get('started_at') or '').replace('T', ' ').replace('+00:00', '')[:16])} UTC · длительность {E(r.get('duration_sec'))} с ·
активные проверки: {'да' if (r.get('options') or {}).get('active') else 'нет'}{' · <b>результат неполный</b>' if r.get('partial') else ''}</div>
<div class="cards">"""]
    for k, v in [("Субдомены", s.get("subdomains")), ("Живые хосты", s.get("alive")),
                 ("Уникальные IP", s.get("unique_ips")), ("Веб-сервисы", s.get("web")),
                 ("Открытые порты", s.get("open_ports")), ("Связанные домены", s.get("related_domains")),
                 ("Утечки: сотрудники", s.get("leaked_employees")), ("Утечки: пользователи", s.get("leaked_users"))]:
        parts.append(f'<div class="card"><b>{E(v if v is not None else "—")}</b>{E(k)}</div>')
    parts.append("</div><div>" + " ".join(
        f'<span class="sev" style="background:{SEV_COLOR[k]}">{SEV_LABEL[k]}: {fc.get(k, 0)}</span>'
        for k in SEV_LABEL) + "</div>")

    parts.append("<h2>Находки</h2>")
    for f in r.get("findings") or []:
        items = "".join(f"<li>{E(i)}</li>" for i in f["items"][:40])
        more = f'<li class="muted">… и ещё {f["count"] - 40}</li>' if f["count"] > 40 else ""
        parts.append(f'<div class="f" style="border-left-color:{SEV_COLOR[f["sev"]]}">'
                     f'<span class="sev" style="background:{SEV_COLOR[f["sev"]]}">{SEV_LABEL[f["sev"]]}</span> '
                     f'<b>{E(f["title"])}</b> <span class="muted">· {E(f["cat"])}</span>'
                     f'{"<div>" + E(f["detail"]) + "</div>" if f["detail"] else ""}'
                     f'{"<div class=muted>Рекомендация: " + E(f["rec"]) + "</div>" if f["rec"] else ""}'
                     f'{"<ul>" + items + more + "</ul>" if items else ""}</div>')
    if not r.get("findings"):
        parts.append('<p class="muted">Находок нет.</p>')

    parts.append("<h2>Организация</h2>")
    if org:
        parts.append(_table(["Поле", "Значение"], [
            ["Наименование", org.get("name")], ["ИНН / ОГРН", f'{org.get("inn") or "—"} / {org.get("ogrn") or "—"}'],
            ["Адрес", org.get("address")], ["ОКВЭД", org.get("okved")], ["Статус", org.get("status")],
            ["Руководитель", org.get("director")],
            ["Выручка (ФНС)", f'{org.get("revenue")} тыс. ₽ за {org.get("bfo_period")}' if org.get("revenue") else "—"],
            ["Основание привязки", (r.get("org") or {}).get("basis")]]).replace("<table>", '<table class="kv">'))
    else:
        parts.append(f'<p class="muted">{E("; ".join((r.get("org") or {}).get("notes") or []) or "Не определена")}</p>')
    aff = (r.get("org") or {}).get("affiliates") or []
    if aff:
        parts.append("<h3>Возможные связанные юрлица</h3>" + _table(
            ["Наименование", "ИНН", "Адрес", "Статус", "Выручка, тыс. ₽"],
            [[a.get("name"), a.get("inn"), a.get("address"), a.get("status"), a.get("revenue")] for a in aff]))

    parts.append("<h2>Регистрация домена и почта</h2>" + _table(["Поле", "Значение"], [
        ["Регистратор", w.get("registrar")], ["Регистрант", w.get("registrant_org")],
        ["Создан", w.get("created")], ["Истекает", w.get("expires")],
        ["NS", ", ".join(w.get("nameservers") or [])],
        ["SPF", (em.get("spf") or {}).get("record")], ["DMARC", (em.get("dmarc") or {}).get("record")],
        ["DKIM-селекторы", ", ".join(em.get("dkim_selectors") or []) or "не найдены"],
        ["MTA-STS / TLS-RPT", f'{"да" if em.get("mta_sts") else "нет"} / {"да" if em.get("tls_rpt") else "нет"}'],
        ["Сервисы (по TXT)", ", ".join(x["service"] for x in r.get("services") or []) or "—"],
    ]).replace("<table>", '<table class="kv">'))

    if lk:
        parts.append("<h2>Утечки (логи инфостилеров)</h2>" + _table(["Показатель", "Значение"], [
            ["Сотрудники", lk.get("employees")], ["Пользователи", lk.get("users")],
            ["Сторонние сервисы", lk.get("third_parties")], ["Последний случай (сотр.)", lk.get("last_employee")],
            ["Последний случай (польз.)", lk.get("last_user")]]).replace("<table>", '<table class="kv">'))

    hosts = sorted(r.get("hosts") or [], key=lambda h: (not h["alive"], h["name"]))
    parts.append(f"<h2>Хосты ({len(hosts)})</h2>" + _table(
        ["Хост", "Статус", "IP (текущие)", "CNAME", "HTTP", "Источники"],
        [[h["name"], "живой" if h["alive"] else h["status"], ", ".join(h["current_ips"][:4]),
          ", ".join(h["cname"][-1:]),
          f'{h["http"]["status"]} {h["http"]["title"][:60]}' if h.get("http") else "",
          ", ".join(h["sources"])] for h in hosts]))
    web = r.get("web") or []
    if web:
        parts.append(f"<h2>Веб-сервисы ({len(web)})</h2>" + _table(
            ["URL", "Код", "Заголовок", "Сервер", "Технологии", "TLS до"],
            [[w_["final_url"], w_["status"], w_["title"], w_["server"], ", ".join(w_["tech"]),
              (w_.get("tls") or {}).get("not_after", "")[:10]] for w_ in web]))
    ips = r.get("ips") or []
    parts.append(f"<h2>IP-адреса ({len(ips)})</h2>" + _table(
        ["IP", "Текущий", "Страна", "Организация", "AS", "Порты", "CVE", "Хосты"],
        [[i["ip"], "да" if i.get("current") else "", i.get("country"), i.get("org") or i.get("isp"),
          i.get("as"), ", ".join(map(str, i.get("ports") or [])), ", ".join((i.get("vulns") or [])[:5]),
          ", ".join(i.get("hosts")[:3])] for i in ips]))
    rel = r.get("related_domains") or []
    if rel:
        parts.append("<h2>Связанные домены</h2>" + _table(["Домен", "Через"],
                                                         [[x["domain"], ", ".join(x["via"])] for x in rel]))
    parts.append("<h2>Источники</h2>" + _table(
        ["Источник", "Назначение", "Статус", "Записей", "Время, с", "Ошибка"],
        [[p["name"], p["desc"], p["status"], p["count"], p["elapsed"], p.get("error") or ""] for p in r.get("sources") or []]))
    parts.append('<p class="muted">Сформировано OSINT Recon. Данные из открытых источников; '
                 'находки требуют ручной проверки.</p></body></html>')
    return "".join(parts)


def xlsx_report(r: dict) -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    wb = Workbook()
    hdr_fill = PatternFill("solid", fgColor="1F2937")
    hdr_font = Font(color="FFFFFF", bold=True)

    def sheet(title, head, rows, widths=None):
        ws = wb.create_sheet(title)
        ws.append(head)
        for c in ws[1]:
            c.fill, c.font = hdr_fill, hdr_font
        for row in rows:
            ws.append([safe_cell(v) for v in row])
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions
        for i, w in enumerate(widths or [], 1):
            ws.column_dimensions[get_column_letter(i)].width = w
        return ws

    s = r.get("summary") or {}
    ws = wb.active
    ws.title = "Сводка"
    for k, v in [("Домен", r.get("domain_unicode")), ("Начало (UTC)", r.get("started_at")),
                 ("Длительность, с", r.get("duration_sec")), ("Субдомены", s.get("subdomains")),
                 ("Живые хосты", s.get("alive")), ("Уникальные IP", s.get("unique_ips")),
                 ("Веб-сервисы", s.get("web")), ("Открытые порты", s.get("open_ports")),
                 ("Захват поддоменов", s.get("takeover")), ("Утечки: сотрудники", s.get("leaked_employees")),
                 ("Утечки: пользователи", s.get("leaked_users"))] + \
            [(f"Находки: {SEV_LABEL[k]}", (s.get("findings") or {}).get(k, 0)) for k in SEV_LABEL]:
        ws.append([k, v])
    ws.column_dimensions["A"].width = 28
    ws.column_dimensions["B"].width = 40
    for c in ws["A"]:
        c.font = Font(bold=True)

    sheet("Находки", ["Критичность", "Категория", "Находка", "Описание", "Рекомендация", "Кол-во", "Объекты"],
          [[SEV_LABEL[f["sev"]], f["cat"], f["title"], f["detail"], f["rec"], f["count"], "\n".join(f["items"])]
           for f in r.get("findings") or []], [12, 12, 50, 50, 40, 8, 70])
    for row in wb["Находки"].iter_rows(min_row=2):
        for c in row:
            c.alignment = Alignment(wrap_text=True, vertical="top")
    sheet("Хосты", ["Хост", "Живой", "Статус DNS", "Текущие IP", "Все IP", "CNAME", "HTTP-код", "Заголовок",
                    "Технологии", "Источники"],
          [[h["name"], "да" if h["alive"] else "", h["status"], ", ".join(h["current_ips"]), ", ".join(h["ips"]),
            " → ".join(h["cname"]), (h.get("http") or {}).get("status"), (h.get("http") or {}).get("title"),
            ", ".join((h.get("http") or {}).get("tech") or []), ", ".join(h["sources"])]
           for h in r.get("hosts") or []], [42, 7, 11, 30, 30, 40, 9, 40, 30, 40])
    sheet("IP", ["IP", "Текущий", "Страна", "Город", "Организация", "ISP", "AS", "PTR", "CDN", "Порты", "CVE",
                 "Хосты"],
          [[i["ip"], "да" if i.get("current") else "", i.get("country"), i.get("city"), i.get("org"), i.get("isp"),
            i.get("as"), i.get("reverse"), "да" if i.get("cdn") else "", ", ".join(map(str, i.get("ports") or [])),
            ", ".join(i.get("vulns") or []), ", ".join(i.get("hosts") or [])] for i in r.get("ips") or []],
          [16, 8, 14, 14, 30, 30, 30, 30, 6, 20, 30, 50])
    sheet("Веб", ["URL", "Итоговый URL", "Код", "Заголовок", "Сервер", "Технологии", "Нет заголовков защиты",
                  "TLS издатель", "TLS до"],
          [[w["url"], w["final_url"], w["status"], w["title"], w["server"], ", ".join(w["tech"]),
            ", ".join(w.get("missing_sec_headers") or []), (w.get("tls") or {}).get("issuer_org"),
            (w.get("tls") or {}).get("not_after")] for w in r.get("web") or []], [40, 40, 6, 40, 20, 40, 40, 20, 20])
    o = r.get("org") or {}
    orgs = ([o["org"]] if o.get("org") else []) + (o.get("affiliates") or []) + (o.get("brand_candidates") or [])
    sheet("Юрлица", ["Наименование", "ИНН", "ОГРН", "Адрес", "ОКВЭД", "Статус", "Период", "Выручка, тыс. ₽"],
          [[x.get("name"), x.get("inn"), x.get("ogrn"), x.get("address"), x.get("okved"), x.get("status"),
            x.get("bfo_period"), x.get("revenue")] for x in orgs], [45, 14, 16, 50, 10, 16, 8, 16])
    sheet("Провайдеры", ["Организация", "Страна", "IP", "Хостов", "Хостер РФ", "CDN", "Примеры хостов"],
          [[g["org"], g["country"], g["ip_count"], g["host_count"], "да" if g["rf_hoster"] else "",
            "да" if g.get("cdn") else "", ", ".join(g["sample_hosts"])] for g in r.get("orgs") or []],
          [40, 14, 6, 8, 10, 6, 60])
    dns_rows = [[k, v] for k, vals in (r.get("dns") or {}).items() for v in vals]
    sheet("DNS", ["Тип", "Значение"], dns_rows, [10, 100])
    sheet("Связанные домены", ["Домен", "Через"],
          [[x["domain"], ", ".join(x["via"])] for x in r.get("related_domains") or []], [40, 30])
    sheet("Источники", ["Источник", "Назначение", "Статус", "Записей", "Время, с", "Ошибка"],
          [[p["name"], p["desc"], p["status"], p["count"], p["elapsed"], p.get("error")] for p in r.get("sources") or []],
          [18, 45, 10, 9, 9, 60])
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()
