"""DNS: записи корня, почтовая безопасность, AXFR, wildcard, перебор, резолв всех хостов, CNAME/захват."""
import asyncio
import random
import re
import string

import dns.asyncquery
import dns.asyncresolver
import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

from . import config

DNS_ERRORS = (dns.exception.DNSException, OSError, asyncio.TimeoutError, ValueError)


# ---------------- резолвер ----------------

async def _probe_ns(ns: str, n: int = 16) -> tuple[int, float]:
    """Надёжность сервера под нагрузкой: сколько из n параллельных запросов получили ответ, медиана задержки."""
    loop = asyncio.get_running_loop()

    async def one(i):
        name = "example.com" if i == 0 else f"{_rand_label(10)}.example.com"
        q = dns.message.make_query(name, "A")
        t = loop.time()
        try:
            await dns.asyncquery.udp(q, ns, timeout=2.0)
            return loop.time() - t
        except DNS_ERRORS:
            return None

    times = [t for t in await asyncio.gather(*(one(i) for i in range(n))) if t is not None]
    return len(times), (sorted(times)[len(times) // 2] if times else 99.0)


async def make_resolver(mode: str | None = None) -> tuple[dns.asyncresolver.Resolver, list[str]]:
    """Резолвер из самых надёжных серверов: мёртвые (отключённый VPN) и «теряющие» запросы отбрасываются."""
    mode = mode or config.option("dns_mode") or "public"
    try:
        system = list(dns.resolver.Resolver().nameservers)
    except Exception:
        system = []
    first, second = (config.PUBLIC_RESOLVERS, system) if mode == "public" else (system, config.PUBLIC_RESOLVERS)
    chosen: list[str] = []
    for group in (first, second):
        cands = [ns for ns in dict.fromkeys(group) if ns not in chosen]
        if not cands:
            continue
        scores = await asyncio.gather(*(_probe_ns(ns) for ns in cands))
        ranked = sorted(zip(cands, scores), key=lambda x: (-x[1][0], x[1][1]))
        best = ranked[0][1][0] if ranked else 0
        chosen += [ns for ns, (ok, _) in ranked if ok >= max(1, best - 1) and ok >= 12][:3]
        if chosen:
            break
    if not chosen:
        chosen = config.PUBLIC_RESOLVERS[:3]
    r = dns.asyncresolver.Resolver(configure=False)
    r.nameservers = chosen
    r.rotate = len(chosen) > 1
    r.timeout = 2.5
    r.lifetime = 7.0
    r.cache = dns.resolver.Cache()
    return r, chosen


def _single(res: dns.asyncresolver.Resolver) -> dns.asyncresolver.Resolver:
    """Резолвер для повторного прохода: те же серверы, бо́льшие таймауты (вызывается с малой параллельностью)."""
    r = dns.asyncresolver.Resolver(configure=False)
    r.nameservers = list(res.nameservers)
    r.rotate = len(r.nameservers) > 1
    r.timeout, r.lifetime = 3.0, 12.0
    r.cache = res.cache
    return r


async def _resolve(res, name: str, rdtype: str) -> list[str]:
    try:
        ans = await res.resolve(name, rdtype)
        return sorted({r.to_text().rstrip(".") if rdtype not in ("MX", "TXT", "SOA", "CAA") else r.to_text()
                       for r in ans})
    except DNS_ERRORS:
        return []


# ---------------- регистрируемый домен ----------------

_SECOND_LEVEL = {
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "com.br",
    "com.tr", "com.cn", "com.ua", "co.il", "co.in", "co.kr", "com.kz", "org.kz", "co.za",
    "com.ru", "net.ru", "org.ru", "pp.ru", "msk.ru", "spb.ru", "nov.ru", "edu.ru", "gov.ru",
    "msk.su", "com.by", "org.by", "com.am", "org.am", "co.am", "com.ge",
    "amazonaws.com", "cloudfront.net", "azurewebsites.net", "herokuapp.com", "github.io",
    "yandexcloud.net", "appspot.com", "blogspot.com",
}


def registrable(host: str | None) -> str | None:
    """Выделить регистрируемый домен из имени хоста (эвристика)."""
    if not host:
        return None
    h = host.strip().strip(".").lower()
    if not h or h.endswith(".arpa") or h in ("localhost",):
        return None
    labels = h.split(".")
    if len(labels) < 2 or not all(lbl.replace("_", "x").replace("-", "x").isalnum() for lbl in labels):
        return None
    tail = ".".join(labels[-2:])
    if len(labels) >= 3 and tail in _SECOND_LEVEL:
        tail = ".".join(labels[-3:])
    return tail


# ---------------- записи корня ----------------

DKIM_SELECTORS = [
    "default", "dkim", "mail", "selector1", "selector2", "google", "k1", "k2", "k3", "s1", "s2",
    "smtp", "mx", "key1", "key2", "dk", "yandex", "mailru", "mail-ru", "sendpulse", "unisender",
    "us", "mailchimp", "mandrill", "sendgrid", "sg", "zoho", "amazonses", "pm", "fm1", "protonmail",
    "everlytickey1", "cm", "sib", "mta", "email", "corp", "exchange", "dkim1", "beget", "timeweb",
]


async def dns_records(domain: str, collector, res) -> dict:
    """Записи корневого домена + связанные домены; вершина попадает в список хостов."""
    types = ["A", "AAAA", "MX", "NS", "SOA", "CAA", "TXT"]
    vals = await asyncio.gather(*(_resolve(res, domain, t) for t in types))
    records = {t: v for t, v in zip(types, vals) if v}
    if "TXT" in records:
        records["TXT"] = sorted(_txt(t) for t in records["TXT"])[:40]
    for ip in records.get("A", []) + records.get("AAAA", []):
        collector.add_host(domain, ip=ip, source="dns")
    return records


def _txt(v: str) -> str:
    """'"part1" "part2"' → 'part1part2'."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', v)
    return "".join(parts) if parts else v.strip('"')


async def email_security(domain: str, records: dict, res) -> dict:
    """SPF / DMARC / DKIM / MTA-STS / TLS-RPT / BIMI с оценкой."""
    spf_all = [t for t in records.get("TXT", []) if t.lower().startswith("v=spf1")]
    dmarc_raw, mta_sts, tlsrpt, bimi = await asyncio.gather(
        _resolve(res, f"_dmarc.{domain}", "TXT"), _resolve(res, f"_mta-sts.{domain}", "TXT"),
        _resolve(res, f"_smtp._tls.{domain}", "TXT"), _resolve(res, f"default._bimi.{domain}", "TXT"))
    dmarc_all = [_txt(t) for t in dmarc_raw if _txt(t).lower().startswith("v=dmarc1")]

    async def dkim_one(sel: str):
        v = await _resolve(res, f"{sel}._domainkey.{domain}", "TXT")
        txt = " ".join(_txt(x) for x in v)
        return sel if ("p=" in txt.lower() or "k=rsa" in txt.lower() or "v=dkim1" in txt.lower()) else None

    sem = asyncio.Semaphore(15)

    async def dkim_guarded(sel):
        async with sem:
            return await dkim_one(sel)

    dkim_found = [s for s in await asyncio.gather(*(dkim_guarded(s) for s in DKIM_SELECTORS)) if s]

    issues: list[dict] = []
    spf = {"record": spf_all[0] if spf_all else None, "all": None, "lookups": 0}
    has_mx = bool(records.get("MX")) and not any(m.split()[-1] == "." for m in records.get("MX", []))
    if len(spf_all) > 1:
        issues.append({"sev": "medium", "text": "Несколько SPF-записей — SPF недействителен (permerror)"})
    if not spf_all:
        issues.append({"sev": "medium" if has_mx else "low",
                       "text": "Нет SPF-записи — домен можно подделывать в поле From"})
    else:
        rec = spf_all[0].lower()
        m = re.search(r"([~?+-]?)all\b", rec)
        q = (m.group(1) or "+") if m else None
        spf["all"] = {"-": "-all (жёстко)", "~": "~all (мягко)", "?": "?all (нейтрально)",
                      "+": "+all (разрешено всем)"}.get(q) if q else "нет all (нейтрально)"
        spf["lookups"] = len(re.findall(r"\b(include|a|mx|ptr|exists|redirect)[:=]?", rec))
        if q == "+":
            issues.append({"sev": "high", "text": "SPF с +all — отправлять от имени домена может кто угодно"})
        elif q in ("?", None):
            issues.append({"sev": "medium", "text": "SPF без запрета (?all / нет all) — защиты от подделки нет"})
        elif q == "~":
            issues.append({"sev": "info", "text": "SPF ~all (softfail) — письма с подделкой помечаются, но доходят"})
        if spf["lookups"] > 10:
            issues.append({"sev": "low", "text": f"SPF: ~{spf['lookups']} DNS-запросов (лимит 10) — риск permerror"})
    dmarc = {"record": dmarc_all[0] if dmarc_all else None, "p": None, "sp": None, "pct": None, "rua": None}
    if not dmarc_all:
        issues.append({"sev": "medium", "text": "Нет DMARC — получатели не отклоняют поддельные письма"})
    else:
        tags = dict(re.findall(r"(\w+)\s*=\s*([^;]+)", dmarc_all[0]))
        tags = {k.lower(): v.strip() for k, v in tags.items()}
        dmarc.update(p=tags.get("p"), sp=tags.get("sp"), pct=tags.get("pct"), rua=tags.get("rua"))
        p = (tags.get("p") or "").lower()
        if p == "none":
            issues.append({"sev": "low", "text": "DMARC p=none — только мониторинг, подделка не блокируется"})
        elif p == "quarantine" and tags.get("pct") not in (None, "100"):
            issues.append({"sev": "info", "text": f"DMARC quarantine применяется к {tags.get('pct')}% писем"})
    if has_mx and not dkim_found:
        issues.append({"sev": "info", "text": "DKIM не найден среди типовых селекторов (селектор может быть нестандартным)"})
    return {
        "spf": spf, "dmarc": dmarc, "dkim_selectors": dkim_found,
        "mta_sts": bool([t for t in mta_sts if "sts" in t.lower()]),
        "tls_rpt": bool([t for t in tlsrpt if "tlsrpt" in t.lower()]),
        "bimi": bool(bimi), "has_mx": has_mx, "issues": issues,
    }


def dns_refs_from_records(domain: str, records: dict, dmarc: str | None = None) -> dict[str, list[str]]:
    """Связанные домены: MX, NS, SOA, SPF include/redirect, DMARC rua/ruf."""
    refs: dict[str, set[str]] = {}

    def ref(host: str | None, via: str) -> None:
        d = registrable(host)
        if d and d != domain and "." in d:
            refs.setdefault(d, set()).add(via)

    for mx in records.get("MX") or []:
        parts = mx.split()
        if parts and parts[-1] != ".":
            ref(parts[-1], "MX")
    for ns in records.get("NS") or []:
        ref(ns, "NS")
    for soa in records.get("SOA") or []:
        parts = soa.split()
        if parts:
            ref(parts[0], "SOA")
            if len(parts) > 1:
                ref(parts[1].rstrip("."), "SOA (email)")
    for t in (records.get("TXT") or []) + ([dmarc] if dmarc else []):
        for m in re.finditer(r"(?:include|redirect)[:=]\s*([a-z0-9_.\-]+\.[a-z]{2,})", t, re.I):
            ref(m.group(1).strip("."), "SPF")
        for m in re.finditer(r"(?:rua|ruf)=[^;]*?@([a-z0-9_.\-]+\.[a-z]{2,})", t, re.I):
            ref(m.group(1), "DMARC")
    return {d: sorted(v) for d, v in sorted(refs.items())}


VERIFICATION_PATTERNS = [
    (r"^google-site-verification=", "Google Workspace / Search Console"),
    (r"^yandex-verification:", "Яндекс (Вебмастер/360)"),
    (r"^ms=ms", "Microsoft 365"), (r"^mscid=", "Microsoft 365"),
    (r"^facebook-domain-verification=", "Facebook / Meta"),
    (r"^apple-domain-verification=", "Apple"),
    (r"^atlassian-domain-verification=", "Atlassian"),
    (r"^docusign=", "DocuSign"), (r"^adobe-idp-site-verification=", "Adobe"),
    (r"^globalsign-domain-verification=", "GlobalSign"),
    (r"^stripe-verification=", "Stripe"), (r"^zoom-domain-verification", "Zoom"),
    (r"^mailru-verification:", "Mail.ru"), (r"^mailru-domain:", "VK WorkSpace / Mail.ru для бизнеса"),
    (r"^yandex-domain:", "Яндекс 360"), (r"^miro-verification=", "Miro"),
    (r"^hubspot-developer-verification=", "HubSpot"), (r"^slack-domain-verification=", "Slack"),
    (r"^dropbox-domain-verification=", "Dropbox"), (r"^openai-domain-verification=", "OpenAI"),
    (r"^teamviewer-sso-verification=", "TeamViewer"), (r"^webexdomainverification", "Webex"),
    (r"^cisco-ci-domain-verification=", "Cisco"), (r"^knowbe4-site-verification=", "KnowBe4"),
    (r"^citrix-verification-code=", "Citrix"), (r"^amazonses:", "Amazon SES"),
    (r"^_?github-challenge", "GitHub"), (r"^gitlab-", "GitLab"), (r"^bitrix", "1С-Битрикс"),
    (r"^sendpulse", "SendPulse"), (r"^unisender", "UniSender"), (r"^jetbrains", "JetBrains"),
    (r"^v=spf1.*include:_spf\.google\.com", "Google Workspace (почта)"),
    (r"^v=spf1.*include:spf\.protection\.outlook\.com", "Microsoft 365 (почта)"),
    (r"^v=spf1.*include:_spf\.yandex\.net", "Яндекс 360 (почта)"),
    (r"^v=spf1.*include:_spf\.mail\.ru", "VK WorkSpace / Mail.ru (почта)"),
]


def services_from_txt(txt: list[str]) -> list[dict]:
    out: dict[str, str] = {}
    for t in txt:
        for pat, svc in VERIFICATION_PATTERNS:
            if re.search(pat, t.strip(), re.I) and svc not in out:
                out[svc] = t[:120]
    return [{"service": k, "record": v} for k, v in out.items()]


# ---------------- AXFR ----------------

async def try_axfr(domain: str, ns_list: list[str], res, collector) -> dict:
    """Попытка передачи зоны с каждого NS (классическая ошибка конфигурации)."""
    results = []

    async def one(ns: str):
        ips = await _resolve(res, ns, "A")
        for ip in ips[:2]:
            try:
                z = await asyncio.wait_for(asyncio.to_thread(
                    lambda: dns.zone.from_xfr(dns.query.xfr(ip, domain, timeout=6, lifetime=15))), 20)
                names = []
                for n in z.nodes.keys():
                    fq = (str(n) + "." + domain) if str(n) != "@" else domain
                    names.append(fq)
                    collector.add_host(fq, source="axfr")
                results.append({"ns": ns, "ip": ip, "allowed": True, "records": len(names)})
                return
            except Exception as e:  # отказ — нормальное поведение
                err = e.__class__.__name__
        results.append({"ns": ns, "allowed": False, "error": err if ips else "NS не резолвится"})

    await asyncio.gather(*(one(ns) for ns in ns_list[:6]))
    return {"tested": len(results), "vulnerable": [r for r in results if r.get("allowed")],
            "results": results}


# ---------------- wildcard ----------------

def _rand_label(n: int = 14) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


async def detect_wildcard(domain: str, res) -> set[str]:
    """IP, на которые резолвятся несуществующие имена (wildcard DNS)."""
    found: set[str] = set()
    for _ in range(3):
        name = f"{_rand_label()}.{domain}"
        a, aaaa = await asyncio.gather(_resolve(res, name, "A"), _resolve(res, name, "AAAA"))
        found |= set(a + aaaa)
    return found


# ---------------- резолв хостов ----------------

async def resolve_full(res, name: str) -> dict:
    """A/AAAA + цепочка CNAME; для пустых ответов — проверка «висячего» CNAME."""
    out = {"ips": [], "cname": [], "status": "nxdomain"}

    async def q(rdtype):
        try:
            ans = await res.resolve(name, rdtype)
            chain = [rr.target.to_text().rstrip(".") for rrset in ans.response.answer
                     if rrset.rdtype == dns.rdatatype.CNAME for rr in rrset]
            return [r.to_text() for r in ans], chain, "ok"
        except dns.resolver.NXDOMAIN:
            return [], [], "nxdomain"
        except dns.resolver.NoAnswer:
            return [], [], "noanswer"
        except DNS_ERRORS:
            return [], [], "error"

    (a, ca, sa), (aaaa, c6, s6) = await asyncio.gather(q("A"), q("AAAA"))
    out["ips"] = sorted(set(a + aaaa))
    out["cname"] = ca or c6
    if out["ips"]:
        out["status"] = "ok"
    else:
        out["status"] = "noanswer" if "noanswer" in (sa, s6) else ("error" if "error" in (sa, s6) else "nxdomain")
        try:  # висячий CNAME: CNAME есть, а цель не резолвится
            ans = await res.resolve(name, "CNAME")
            out["cname"] = [r.target.to_text().rstrip(".") for r in ans]
            out["status"] = "dangling"
        except DNS_ERRORS:
            pass
    return out


async def resolve_hosts(names: list[str], res, concurrency: int = 80,
                        out: dict[str, dict] | None = None) -> dict[str, dict]:
    """Резолв списка имён; сбойные ответы перепроверяются вторым проходом.
    out заполняется по мере ответов — при прерывании по таймауту готовое не теряется."""
    out = {} if out is None else out

    async def run(batch, resolver, conc):
        sem = asyncio.Semaphore(conc)

        async def one(n):
            async with sem:
                out[n] = await resolve_full(resolver, n)
        await asyncio.gather(*(one(n) for n in batch))

    await run(names, res, concurrency)
    retry = [n for n in names if (out.get(n) or {}).get("status") == "error"]
    if retry:
        await run(retry, _single(res), 30)
    return out


# ---------------- перебор ----------------

PREFIXES = """
www www1 www2 www3 mail mail1 mail2 mail3 smtp smtp1 smtp2 pop pop3 imap mx mx1 mx2 mx3 mx4 mx01 mx02
ns ns1 ns2 ns3 ns4 ns5 dns dns1 dns2 vpn vpn1 vpn2 vpn3 ssl-vpn sslvpn openvpn remote rdp rdg rdweb
rds ts gateway gw gw1 gw2 ftp sftp ftps ssh api api1 api2 api3 apis api-dev api-test api-stage
apigw app apps app1 app2 mobile m web web1 web2 webmail webdisk autodiscover autoconfig portal my
lk cabinet account accounts auth sso login id idp adfs sts oauth oidc keycloak cdn cdn1 cdn2 static
static1 assets img images media video videos files file download downloads upload uploads storage s3
minio backup backups db db1 db2 database sql mysql postgres pgsql mongo redis cache memcached
elastic es kibana grafana prometheus alertmanager zabbix nagios monitor monitoring status uptime
metrics logs log graylog sentry dev dev1 dev2 devel develop development test test1 test2 tst
testing stage stage1 staging stg uat qa qa1 preprod pre prod production beta alpha demo demo1
sandbox lab labs new old legacy v1 v2 v3 next edge proxy proxy1 internal intranet extranet corp
office ad dc dc1 dc2 jenkins ci cd build git gitlab github bitbucket repo repos registry harbor
nexus artifactory sonar sonarqube docker k8s kube kubernetes rancher argocd argo vault consul
confluence wiki docs doc help helpdesk support servicedesk sd faq kb training lms edu learn jira
tracker bugs redmine youtrack pm crm erp hr hrm 1c 1c-web bitrix b24 bitrix24 sed edo doc-flow
directum elma shop store cart checkout pay payment payments billing invoice order orders client
clients customer customers partner partners b2b b2c dealer dealers affiliate blog news press forum
community chat messenger social share cloud nextcloud owncloud private secure ssl ca pki cert certs
crl ocsp email newsletter notify notifications push ws wss socket realtime stream streaming live tv
radio play game games data bigdata ml ai analytics bi report reports dash dashboard admin
administrator admin1 adm panel cpanel whm plesk isp ispmanager manage manager console cp master
main core node node1 node2 worker agent relay exchange owa outlook lync skype sip voip pbx asterisk
meet conference video-conf jitsi zoom webinar siem soc fw firewall router nas print scan fax mdm
mam citrix vdi horizon view workspace rd remoteapp otrs glpi itsm search solr api-gateway graphql
gql rest soap ws1 service services svc backend frontend front back origin origin-www lb lb1 haproxy
nginx apache iis tomcat jboss weblogic wildfly sharepoint portal2 extranet2 kerio zimbra roundcube
mailgw mailgate antispam spam relay1 smtp-out out in mta mta1 mta2 postfix webmail2 owa2 mobile-api
m-api ios android apk update updates upgrade mirror repo-mirror pkg packages npm pypi maven
geo maps map tiles gis time ntp ntp1 ldap ldaps radius tacacs nac wifi guest hotspot cam camera
cctv nvr dvr video-surveillance iot scada hmi plc opc mes erp-test crm-test test-api dev-api
staging-api api-staging preprod-api uat-api stage-api old-www www-old new-www www-new beta-www
""".split()

MUTATIONS = ["dev", "test", "stage", "staging", "stg", "uat", "qa", "preprod", "prod", "old", "new",
             "beta", "demo", "int", "internal", "api", "admin", "v2", "2", "1", "backup", "bak", "tmp"]


def permutations(domain: str, known: list[str], limit: int = 1500) -> list[str]:
    """Мутации найденных имён (alterx-подобно): api → api-dev, dev-api, api2, api.dev …"""
    labels: dict[str, int] = {}
    for h in known:
        if h == domain or not h.endswith("." + domain):
            continue
        first = h[: -len(domain) - 1].split(".")[-1]
        if 2 <= len(first) <= 20 and not any(ch.isdigit() for ch in first[:1]):
            labels[first] = labels.get(first, 0) + 1
    top = [lbl for lbl, _ in sorted(labels.items(), key=lambda x: -x[1])][:60]
    known_set = set(known)
    out: list[str] = []
    for lbl in top:
        for m in MUTATIONS:
            if m == lbl:
                continue
            for cand in (f"{lbl}-{m}", f"{m}-{lbl}", f"{lbl}{m}" if m.isdigit() else None):
                if cand:
                    fq = f"{cand}.{domain}"
                    if fq not in known_set:
                        out.append(fq)
    seen = set()
    uniq = [x for x in out if not (x in seen or seen.add(x))]
    return uniq[:limit]


async def dns_brute(domain: str, collector, res, wildcard: set[str], known: list[str] | None = None,
                    with_permutations: bool = True, with_wordlist: bool = True) -> dict:
    """Перебор словаря + мутаций найденных имён; wildcard-ответы отбрасываются."""
    words = sorted(set(PREFIXES)) if with_wordlist else []
    names = [f"{w}.{domain}" for w in words]
    perm = permutations(domain, known or []) if with_permutations else []
    names += perm
    hits = {"wordlist": 0, "permutations": 0}
    perm_set = set(perm)
    errors: list[str] = []

    async def a_only(resolver, name: str) -> tuple[set[str], str]:
        """A, затем AAAA только если имя существует (NXDOMAIN по A — имени нет)."""
        try:
            ans = await resolver.resolve(name, "A")
            return {r.to_text() for r in ans}, "ok"
        except dns.resolver.NXDOMAIN:
            return set(), "nx"
        except dns.resolver.NoAnswer:
            try:
                ans = await resolver.resolve(name, "AAAA")
                return {r.to_text() for r in ans}, "ok"
            except DNS_ERRORS:
                return set(), "nx"
        except DNS_ERRORS:
            return set(), "error"

    def record(name, ips):
        if ips and not (wildcard and ips <= wildcard):
            src = "dns-perm" if name in perm_set else "dns-brute"
            for ip in ips:
                collector.add_host(name, ip=ip, source=src)
            hits["permutations" if name in perm_set else "wordlist"] += 1

    async def run(batch, resolver, conc, collect_errors):
        sem = asyncio.Semaphore(conc)

        async def one(name):
            async with sem:
                ips, st = await a_only(resolver, name)
            if st == "error" and collect_errors:
                errors.append(name)
            record(name, ips)
        await asyncio.gather(*(one(n) for n in batch))

    await run(names, res, 60, True)
    if errors:
        await run(errors, _single(res), 30, False)
    return {"tried": len(names), "wordlist": len(words), "permutations_tried": len(perm),
            "retried": len(errors), **hits}
