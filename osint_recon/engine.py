"""Оркестратор сканирования: фазы, источники, объединение, находки, сохранение."""
import asyncio
import ipaddress
import json
import os
import time
from datetime import datetime, timezone

import httpx

from . import config, dnsmgr, findings, intel, ipinfo, probe, ruorg, sources, whoisx
from .collector import Collector
from .fingerprints import DEV_LABELS

RF_HOSTERS = [
    "yandex", "selectel", "timeweb", "reg.ru", "rucenter", "nic.ru", "cloud.ru", "sbercloud",
    "rostelecom", "beeline", "vimpelcom", "megafon", "tele2", "t2 mobile", "firstvds", "mts",
    "spaceweb", "sweb", "masterhost", "jino", "netangels", "beget", "ruweb", "sprinthost",
    "ddos-guard", "stormwall", "qrator", "vk.cloud", "vk cloud", "mail.ru", "ihor", "servicepipe",
    "dataline", "ixcellerate", "mastertel", "ertelecom", "er-telecom", "transtelecom", "ttk",
]
RU_TLDS = (".ru", ".su", ".xn--p1ai", ".moscow", ".xn--80adxhks", ".tatar", ".xn--d1acj3b")
# CDN и сервисы защиты: за их IP стоят чужие серверы, порты по ним не сканируются
CDN_ORGS = ["cloudflare", "akamai", "fastly", "cloudfront", "ddos-guard", "qrator", "stormwall",
            "incapsula", "imperva", "stackpath", "cdnvideo", "ngenix", "gcore", "g-core", "variti",
            "servicepipe", "edgecast", "edgio", "limelight", "sucuri"]


class ScanState:
    def __init__(self, sid: str, domain: str, org_hint: str | None = None,
                 active: bool = False, brute: bool = True, fast: bool = True):
        self.id = sid
        self.domain = domain
        self.org_hint = (org_hint or "").strip() or None
        self.active = active
        self.brute = brute
        self.fast = fast
        self.status = "running"  # running | done | error | cancelled
        self.phase = "Подготовка"
        self.started_at = datetime.now(timezone.utc)
        self.finished_at: datetime | None = None
        self.progress: list[dict] = []
        self.data: dict = {}
        self.result: dict | None = None
        self.error: str | None = None
        self.task: asyncio.Task | None = None
        self.col: Collector | None = None


def _ip_key(ip: str):
    a = ipaddress.ip_address(ip)
    return (a.version, int(a))


def _unicode_domain(domain: str) -> str:
    try:
        import idna
        return ".".join(str(idna.decode(label)) for label in domain.split("."))
    except Exception:
        return domain


def _org_key(info: dict) -> str:
    return (info.get("org") or info.get("isp") or info.get("asname")
            or (info.get("as") or "").split(" ")[0] or "Неизвестные / прочие")


def _hay(info: dict) -> str:
    return " ".join([info.get("org") or "", info.get("isp") or "", info.get("asname") or "",
                     info.get("as") or ""]).lower()


def _is_rf_hoster(info: dict) -> bool:
    return any(h in _hay(info) for h in RF_HOSTERS)


def _is_cdn(info: dict) -> bool:
    return any(h in _hay(info) for h in CDN_ORGS)


def _as_key(info: dict) -> str:
    asf = (info.get("as") or "").strip()
    return asf.split(" ")[0] if asf else (info.get("asname") or "")


def save(sid: str, result: dict) -> None:
    try:
        os.makedirs(config.SCANS_DIR, exist_ok=True)
        path = os.path.join(config.SCANS_DIR, sid + ".json")
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False)
        os.replace(tmp, path)
    except OSError:
        pass


def _add_step(state: ScanState, name: str, desc: str, group: str, skipped: str | None = None) -> None:
    state.progress.append({"name": name, "desc": desc, "group": group,
                           "status": "skipped" if skipped else "pending", "count": 0,
                           "elapsed": None, "error": skipped})


FAST_SKIP = {"wayback", "commoncrawl", "rapiddns"}  # медленные и нестабильные — только в полном режиме

# таймауты шагов, с: (быстрый, полный)
T = {
    "passive": (30, 130), "dns": (25, 60), "email": (30, 90), "axfr": (25, 90), "whois": (30, 60),
    "site": (30, 90), "leaks": (30, 60), "dns-brute": (60, 300), "dns-perm": (0, 300),
    "resolve-final": (90, 420), "ip-enrich": (60, 240), "internetdb": (40, 240), "ru-org": (60, 150),
    "http": (90, 360), "tls": (60, 240), "ports": (120, 400), "asn": (20, 90),
}


async def run_scan(state: ScanState) -> None:
    domain = state.domain
    col = Collector(domain)
    state.col = col
    D = state.data
    D["resolved"] = {}
    fast = state.fast
    to = lambda k: T[k][0 if fast else 1]  # noqa: E731
    client = httpx.AsyncClient(
        headers={"User-Agent": config.USER_AGENT, "Accept": "application/json, text/*, */*"},
        follow_redirects=True, timeout=30, limits=httpx.Limits(max_connections=60))

    defs = sources.build()
    for d in defs:
        skip = None if d["fn"] else "нет API-ключа (Настройки)"
        if fast and d["name"] in FAST_SKIP:
            skip = "только в полном режиме"
        _add_step(state, d["name"], d["desc"], "Пассивные источники", skip)
    steps = [
        ("dns", "Записи корня (A/AAAA/MX/NS/SOA/TXT/CAA), wildcard", "DNS"),
        ("email", "Почта: SPF / DMARC / DKIM / MTA-STS", "DNS"),
        ("axfr", "Попытка передачи зоны (AXFR) с NS", "DNS"),
        ("dns-brute", "Перебор словаря (~450 префиксов)", "DNS"),
        ("dns-perm", "Мутации найденных имён", "DNS"),
        ("resolve", "Резолв всех хостов, CNAME, захват поддоменов", "DNS"),
        ("whois", "Регистрация домена (RDAP / whois)", "Домен и организация"),
        ("site", "Реквизиты с сайта: ИНН, ОГРН, контакты", "Домен и организация"),
        ("leaks", "Утечки: логи инфостилеров (Hudson Rock)", "Домен и организация"),
        ("ru-org", "Организация РФ: ЕГРЮЛ / ФНС / Федресурс + «дочки»", "Домен и организация"),
        ("ip-enrich", "IP: страна, провайдер, AS (ip-api / RDAP)", "IP и сеть"),
        ("internetdb", "IP: открытые порты и CVE (Shodan InternetDB)", "IP и сеть"),
        ("asn", "AS и сети организации (RIPEstat)", "IP и сеть"),
    ]
    for name, desc, grp in steps:
        skip = None
        if name in ("dns-brute", "dns-perm") and not state.brute:
            skip = "перебор выключен"
        elif name == "dns-perm" and fast:
            skip = "только в полном режиме"
        _add_step(state, name, desc, grp, skip)
    for name, desc in [("http", "HTTP(S): статус, заголовок, технологии"),
                       ("tls", "TLS-сертификаты: срок, издатель, SAN"),
                       ("ports", "TCP-порты (типовые сервисы)")]:
        _add_step(state, name, desc, "Активные проверки",
                  None if state.active else "выключено")
    idx = {p["name"]: i for i, p in enumerate(state.progress)}

    async def step(name: str, coro_fn, timeout: float = 240):
        p = state.progress[idx[name]]
        if p["status"] == "skipped":
            return None
        p["status"] = "running"
        t0 = time.monotonic()
        try:
            res = await asyncio.wait_for(coro_fn(), timeout)
            p["status"] = "ok"
            if isinstance(res, tuple):
                res, p["count"] = res
            elif p["group"] == "Пассивные источники":
                p["count"] = col.count_for(name if name != "otx-urls" else "otx")
            return res
        except asyncio.TimeoutError:
            p["status"] = "error"
            p["error"] = f"не уложился в {int(timeout)} с"
            if p["group"] == "Пассивные источники":
                p["count"] = col.count_for(name if name != "otx-urls" else "otx")
        except asyncio.CancelledError:
            p["status"] = "error"
            p["error"] = "отменено"
            raise
        except Exception as e:  # источник падает — скан продолжается
            p["status"] = "error"
            p["error"] = (str(e)[:200] or e.__class__.__name__)
        finally:
            p["elapsed"] = round(time.monotonic() - t0, 1)
        return None

    # фоновый резолв: имена резолвятся по мере появления, пока идёт пассивный сбор
    rp = state.progress[idx["resolve"]]
    stop_resolve = asyncio.Event()
    inflight: set[str] = set()

    def alive_count() -> int:
        return sum(1 for v in list(D["resolved"].values()) if v["status"] == "ok")

    async def resolve_worker(res):
        while True:
            room = config.MAX_RESOLVE_HOSTS - len(inflight)
            pending = [n for n in list(col.hosts) if n not in inflight][:min(800, max(room, 0))]
            if pending:
                inflight.update(pending)
                await dnsmgr.resolve_hosts(pending, res, out=D["resolved"])
                for n in pending:
                    for ip in (D["resolved"].get(n) or {}).get("ips") or []:
                        col.add_host(n, ip=ip)
                rp["count"] = alive_count()
            elif stop_resolve.is_set():
                return
            else:
                try:
                    await asyncio.wait_for(stop_resolve.wait(), 1.0)
                except asyncio.TimeoutError:
                    pass

    worker = None
    try:
        res, nameservers = await dnsmgr.make_resolver()
        D["resolvers"] = nameservers
        rp["status"] = "running"
        t_resolve = time.monotonic()
        worker = asyncio.create_task(resolve_worker(res))

        # ---------- фаза 1: пассивный сбор + DNS + перебор + whois/сайт/утечки (всё параллельно) ----------
        state.phase = "Сбор"

        async def dns_chain():
            async def records():
                D["dns"] = await dnsmgr.dns_records(domain, col, res)
                D["wildcard"] = sorted(await dnsmgr.detect_wildcard(domain, res))
                return D["dns"], sum(len(v) for v in D["dns"].values())
            await step("dns", records, to("dns"))
            dns = D.get("dns") or {}

            async def email():
                D["email"] = await dnsmgr.email_security(domain, dns, res)
                return D["email"], len(D["email"]["issues"])

            async def axfr():
                D["axfr"] = await dnsmgr.try_axfr(domain, dns.get("NS") or [], res, col)
                return D["axfr"], len(D["axfr"]["vulnerable"])

            async def brute():
                st = await dnsmgr.dns_brute(domain, col, res, set(D.get("wildcard") or []),
                                            with_permutations=False)
                D["brute"] = st
                return st, st["wordlist"]
            await asyncio.gather(step("email", email, to("email")), step("axfr", axfr, to("axfr")),
                                 step("dns-brute", brute, to("dns-brute")))

        async def whois_step():
            w = await whoisx.fetch_whois(domain, col, client)
            D["whois"] = w
            if w.get("error") and not (w.get("registrar") or w.get("created")):
                raise RuntimeError(w["error"])
            return w, 1

        async def site_step():
            s = await intel.site_requisites(domain)
            D["site"] = s
            if s.get("error"):
                raise RuntimeError(s["error"])
            return s, len(s.get("inns") or [])

        async def leaks_step():
            D["leaks"] = await intel.hudsonrock(domain, col, client)
            return D["leaks"], D["leaks"]["employees"] + D["leaks"]["users"]

        def src_runner(fn):
            return lambda: fn(domain, col, client)

        tasks = [step(d["name"], src_runner(d["fn"]), to("passive")) for d in defs if d["fn"]]
        tasks += [dns_chain(), step("whois", whois_step, to("whois")), step("site", site_step, to("site")),
                  step("leaks", leaks_step, to("leaks"))]
        await asyncio.gather(*tasks)
        wildcard = set(D.get("wildcard") or [])

        # ---------- фаза 2 (полный режим): мутации найденных имён ----------
        if not fast:
            state.phase = "Мутации имён"

            async def perm():
                st = await dnsmgr.dns_brute(domain, col, res, wildcard, known=list(col.hosts),
                                            with_wordlist=False)
                (D.get("brute") or {}).update(permutations_tried=st["permutations_tried"],
                                              permutations=st["permutations"])
                return st, st["permutations"]
            await step("dns-perm", perm, to("dns-perm"))

        # ---------- фаза 3: дорезолвить оставшееся ----------
        state.phase = "Резолв хостов"
        stop_resolve.set()
        try:
            await asyncio.wait_for(asyncio.shield(worker), to("resolve-final"))
            rp["status"] = "ok"
        except asyncio.TimeoutError:
            worker.cancel()
            rp["status"] = "error"
            rp["error"] = "проверены не все имена (лимит времени)"
        rp["count"] = alive_count()
        rp["elapsed"] = round(time.monotonic() - t_resolve, 1)

        passive = _passive_names(col)
        alive = [n for n, v in D["resolved"].items() if v["status"] == "ok"
                 and not (wildcard and set(v["ips"]) <= wildcard and n not in passive)]
        current_ips = sorted({ip for n in alive for ip in D["resolved"][n]["ips"]}, key=_ip_key)

        # ---------- фаза 4: обогащение и активные проверки ----------
        state.phase = "Обогащение"
        all_ips = sorted(col.ips, key=_ip_key)
        cur_set = set(current_ips)
        ordered_ips = current_ips + [ip for ip in all_ips if ip not in cur_set]
        capped = ordered_ips[:config.MAX_IPS_ENRICH]
        D["ips_info"], D["http"], D["tls"], D["ports"] = {}, {}, {}, {}

        async def enrich():
            D["ips_info"] = await ipinfo.enrich(capped, client)
            return None, len(D["ips_info"])

        async def idb():
            r = await ipinfo.internetdb(current_ips, client)
            D["internetdb"] = r
            if not r.get("available"):
                raise RuntimeError(r.get("error") or "недоступен")
            return r, len(r["data"])

        async def ruorg_step():
            site = D.get("site") or {}
            ru_like = domain.endswith(RU_TLDS) or any(p.startswith(("+7", "8")) and len(p) >= 11
                                                      for p in site.get("phones") or [])
            r = await ruorg.org_profile(domain, D.get("whois"), state.org_hint, client, site=site,
                                        brand=intel.brand_label(domain) if ru_like else None)
            D["org"] = r
            n = (1 if r.get("org") else 0) + len(r.get("affiliates") or [])
            p = state.progress[idx["ru-org"]]
            if not r.get("org") and r.get("notes"):
                p["error"] = "; ".join(r["notes"])[:200]
            return r, n

        probe_hosts = sorted(alive, key=lambda n: (n.count("."), len(n)))[:config.MAX_PROBE_HOSTS]

        async def http_step():
            await probe.http_probe(probe_hosts, out=D["http"])
            return None, len(D["http"])

        async def tls_step():
            await probe.tls_scan(probe_hosts, out=D["tls"])
            return None, len(D["tls"])

        async def ports_step():
            await step_done("ip-enrich")
            info = D.get("ips_info") or {}
            targets = [ip for ip in current_ips if ipinfo.is_public(ip) and not _is_cdn(info.get(ip) or {})]
            targets = targets[:config.MAX_PORTSCAN_IPS]
            D["ports_targets"] = len(targets)
            await probe.port_scan(targets, out=D["ports"])
            return None, sum(len(v) for v in D["ports"].values())

        async def asn_step():
            await step_done("ip-enrich", "ru-org")
            info = D.get("ips_info") or {}
            brand = intel.brand_label(domain)
            org = (D.get("org") or {}).get("org") or {}
            kw = ruorg.base_keyword(org.get("name") or "")
            marks = [m for m in {brand, intel.translit(brand) if brand else "", (kw or "").lower()}
                     if m and len(m) >= 4]
            own: dict[str, str] = {}
            for i in info.values():
                asn = _as_key(i)
                if asn and any(m in _hay(i) for m in marks):
                    own[asn] = i.get("asname") or i.get("org") or ""
            try:
                for s in await intel.ripe_search(brand, client):
                    if s.get("asn") and any(m in (s.get("name") or "").lower() for m in marks):
                        own.setdefault(s["asn"], s.get("name") or "")
            except Exception:
                pass
            prefixes = await ipinfo.asn_prefixes(list(own), client)
            D["asn"] = [{"asn": a, "name": n, "prefixes": prefixes.get(a, [])} for a, n in own.items()]
            return None, len(D["asn"])

        async def step_done(*names):
            while any(state.progress[idx[n]]["status"] in ("pending", "running") for n in names):
                await asyncio.sleep(0.3)

        await asyncio.gather(step("ip-enrich", enrich, to("ip-enrich")), step("internetdb", idb, to("internetdb")),
                             step("ru-org", ruorg_step, to("ru-org")), step("http", http_step, to("http")),
                             step("tls", tls_step, to("tls")), step("ports", ports_step, to("ports")),
                             step("asn", asn_step, to("asn") + to("ru-org")))

        # ---------- фаза 5: новые имена из TLS SAN ----------
        new_names = set()
        for h, t in (D.get("tls") or {}).items():
            for n in t.get("san") or []:
                if col.add_host(n, source="tls-san"):
                    new_names.add(col.normalize(n))
        if new_names:
            try:
                await asyncio.wait_for(dnsmgr.resolve_hosts(sorted(x for x in new_names if x)[:500], res,
                                                            out=D["resolved"]), 30)
            except asyncio.TimeoutError:
                pass
            for n in new_names:
                for ip in (D["resolved"].get(n) or {}).get("ips") or []:
                    col.add_host(n, ip=ip)

        state.phase = "Формирование отчёта"
        state.result = build_result(state, col)
        save(state.id, state.result)
        state.status = "done"
    except asyncio.CancelledError:
        state.status = "cancelled"
        state.error = "сбор остановлен пользователем"
        try:
            state.result = build_result(state, col, partial=True)
            save(state.id, state.result)
        except Exception:
            pass
    except Exception as e:
        state.status = "error"
        state.error = repr(e)[:500]
        try:
            state.result = build_result(state, col, partial=True)
            save(state.id, state.result)
        except Exception:
            pass
    finally:
        if worker and not worker.done():
            worker.cancel()
        state.finished_at = datetime.now(timezone.utc)
        await client.aclose()


def _passive_names(col: Collector) -> set[str]:
    return {n for n, h in col.hosts.items() if h["sources"] - {"dns-brute", "dns-perm"}}


def build_result(state: ScanState, col: Collector, partial: bool = False) -> dict:
    D = state.data
    domain = state.domain
    resolved = D.get("resolved") or {}
    wildcard = set(D.get("wildcard") or [])
    ips_info: dict = D.get("ips_info") or {}
    idb = (D.get("internetdb") or {}).get("data") or {}
    ports = D.get("ports") or {}
    http = D.get("http") or {}
    tls = D.get("tls") or {}

    takeover = []
    hosts_list = []
    for h in sorted(col.hosts.values(), key=lambda h: h["name"]):
        r = resolved.get(h["name"]) or {}
        status = r.get("status") or "unchecked"
        cur = sorted(set(r.get("ips") or []), key=_ip_key)
        is_wild = bool(wildcard) and bool(cur) and set(cur) <= wildcard
        tk = probe.takeover_check(h["name"], r, http.get(h["name"])) if r else None
        if tk:
            takeover.append(tk)
        sub = h["name"][: -len(domain)].rstrip(".")
        web = http.get(h["name"])
        hosts_list.append({
            "name": h["name"],
            "ips": sorted(h["ips"], key=_ip_key),
            "current_ips": cur,
            "cname": r.get("cname") or [],
            "status": status,
            "alive": status == "ok",
            "wildcard": is_wild,
            "dev": bool(sub and DEV_LABELS.search(sub)),
            "sources": sorted(h["sources"]),
            "http": {"status": web["status"], "title": web["title"], "url": web["final_url"],
                     "tech": web["tech"]} if web else None,
        })

    cur_all = {ip for h in hosts_list for ip in h["current_ips"]}
    all_ips = sorted(col.ips, key=_ip_key)
    ip_hosts: dict[str, set[str]] = {}
    for h in hosts_list:
        for ip in h["ips"]:
            ip_hosts.setdefault(ip, set()).add(h["name"])

    ips_out = []
    for ip in all_ips[:config.MAX_IPS_ENRICH * 2]:
        info = dict(ips_info.get(ip) or {})
        d = idb.get(ip) or {}
        open_ports = sorted(set((d.get("ports") or []) + (ports.get(ip) or [])))
        ips_out.append({
            "ip": ip, **info,
            "current": ip in cur_all,
            "private": not ipinfo.is_public(ip),
            "cdn": _is_cdn(info) if info else False,
            "ports": open_ports, "vulns": d.get("vulns") or [], "cpes": d.get("cpes") or [],
            "tags": d.get("tags") or [], "idb_hostnames": d.get("hostnames") or [],
            "hosts": sorted(ip_hosts.get(ip, set()))[:20], "host_count": len(ip_hosts.get(ip, set())),
        })

    groups: dict[str, dict] = {}
    for row in ips_out:
        if not row.get("source"):
            continue
        org = _org_key(row)
        g = groups.setdefault(org, {"org": org, "country": "", "ips": set(), "hosts": set(), "rf": False,
                                    "cdn": False})
        g["ips"].add(row["ip"])
        g["hosts"] |= set(row["hosts"])
        g["country"] = g["country"] or row.get("country") or row.get("countryCode") or ""
        g["rf"] = g["rf"] or _is_rf_hoster(row)
        g["cdn"] = g["cdn"] or row["cdn"]
    orgs = sorted(({"org": g["org"], "country": g["country"], "ip_count": len(g["ips"]),
                    "host_count": len(g["hosts"]), "rf_hoster": g["rf"], "cdn": g["cdn"],
                    "sample_ips": sorted(g["ips"], key=_ip_key)[:5], "sample_hosts": sorted(g["hosts"])[:5]}
                   for g in groups.values()), key=lambda g: (-g["ip_count"], -g["host_count"]))

    as_groups: dict[str, dict] = {}
    for row in ips_out:
        if not row.get("source"):
            continue
        key = _as_key(row) or "—"
        g = as_groups.setdefault(key, {"as": key, "org": row.get("asname") or row.get("org") or "",
                                       "country": row.get("country") or "", "ips": set(), "hosts": set()})
        g["ips"].add(row["ip"])
        g["hosts"] |= set(row["hosts"])
    as_summary = sorted(({"as": g["as"], "org": g["org"] or "—", "country": g["country"],
                          "ip_count": len(g["ips"]), "host_count": len(g["hosts"]),
                          "sample_hosts": sorted(g["hosts"])[:4]} for g in as_groups.values()),
                        key=lambda g: (-g["ip_count"], -g["host_count"]))

    web = []
    for host, s in sorted(http.items()):
        web.append({"host": host, **{k: v for k, v in s.items() if k != "body_sample"},
                    "tls": {k: tls[host].get(k) for k in ("issuer_org", "issuer_cn", "not_after", "days_left",
                                                          "self_signed", "hostname_match", "subject_org",
                                                          "protocol")} if host in tls else None})

    refs = dnsmgr.dns_refs_from_records(domain, D.get("dns") or {},
                                        ((D.get("email") or {}).get("dmarc") or {}).get("record"))
    for h in hosts_list:  # CNAME на сторонние домены — подрядчики/SaaS
        for cn in h["cname"]:
            reg = dnsmgr.registrable(cn)
            if reg and reg != domain:
                refs.setdefault(reg, [])
                if "CNAME" not in refs[reg]:
                    refs[reg] = sorted(refs[reg] + ["CNAME"])
    related = [{"domain": d, "via": v} for d, v in sorted(refs.items())]

    flags = {"hosting": 0, "proxy": 0, "mobile": 0}
    for info in ips_info.values():
        for k in flags:
            if info.get(k):
                flags[k] += 1

    finished = datetime.now(timezone.utc)
    result = {
        "id": state.id, "version": config.VERSION, "partial": partial,
        "domain": domain, "domain_unicode": _unicode_domain(domain),
        "org_hint": state.org_hint, "options": {"active": state.active, "brute": state.brute,
                                               "mode": "fast" if state.fast else "full"},
        "started_at": state.started_at.isoformat(timespec="seconds"),
        "finished_at": finished.isoformat(timespec="seconds"),
        "duration_sec": round((finished - state.started_at).total_seconds(), 1),
        "resolvers": D.get("resolvers"),
        "hosts": hosts_list, "ips": ips_out, "orgs": orgs, "as_summary": as_summary,
        "related_domains": related, "dns": D.get("dns") or {}, "wildcard": sorted(wildcard),
        "email": D.get("email"), "services": dnsmgr.services_from_txt((D.get("dns") or {}).get("TXT") or []),
        "axfr": D.get("axfr"), "whois": D.get("whois"), "org": D.get("org"), "site": D.get("site"),
        "leaks": D.get("leaks"), "asn": D.get("asn") or [], "web": web, "tls": tls,
        "takeover": takeover, "brute": D.get("brute"),
        "internetdb_available": (D.get("internetdb") or {}).get("available"),
        "ports_targets": D.get("ports_targets"),
        "ip_flags": flags, "sources": state.progress,
    }
    result["findings"] = findings.build(result)
    fc = findings.counts(result["findings"])
    result["summary"] = {
        "hosts": len(hosts_list),
        "subdomains": len(hosts_list) - (1 if domain in col.hosts else 0),
        "alive": sum(1 for h in hosts_list if h["alive"] and not h["wildcard"]),
        "with_ip": sum(1 for h in hosts_list if h["ips"]),
        "unique_ips": len(cur_all), "ip_total_found": len(all_ips),
        "orgs": len(orgs), "related_domains": len(related),
        "affiliates": len(((D.get("org") or {}).get("affiliates")) or []),
        "web": len(web), "open_ports": sum(len(r["ports"]) for r in ips_out),
        "takeover": len(takeover),
        "leaked_employees": (D.get("leaks") or {}).get("employees", 0),
        "leaked_users": (D.get("leaks") or {}).get("users", 0),
        "findings": fc,
        "risk": next((k for k in ("critical", "high", "medium", "low") if fc.get(k)), "info"),
        "sources_ok": sum(1 for p in state.progress if p["status"] == "ok"),
        "sources_total": sum(1 for p in state.progress if p["status"] != "skipped"),
    }
    return result
