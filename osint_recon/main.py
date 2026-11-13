"""HTTP API + раздача интерфейса."""
import asyncio
import csv
import io
import json
import os
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel

from . import config, engine, report
from .intel import inn_valid

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?)+\Z", re.I)
SID_RE = re.compile(r"^[a-z0-9._-]{3,120}\Z", re.I)
STATIC = os.path.join(os.path.dirname(__file__), "static")
SCANS: dict[str, engine.ScanState] = {}


@asynccontextmanager
async def lifespan(_app):
    os.makedirs(config.SCANS_DIR, exist_ok=True)
    yield
    for st in SCANS.values():
        if st.task and not st.task.done():
            st.task.cancel()


app = FastAPI(title="OSINT Recon", version=config.VERSION, docs_url="/api/docs", redoc_url=None,
              lifespan=lifespan)


class ScanRequest(BaseModel):
    domain: str
    org_hint: str | None = None
    active: bool | None = None
    brute: bool | None = None
    mode: str | None = None  # fast | full


class SettingsPatch(BaseModel):
    keys: dict[str, str | None] | None = None
    dns_mode: str | None = None
    active_default: bool | None = None
    brute_default: bool | None = None
    mode_default: str | None = None


def normalize_domain(raw: str) -> str:
    d = (raw or "").strip().lower()
    if "://" in d:
        d = urlparse(d).hostname or ""
    d = d.split("/")[0].split("?")[0].split(":")[0].strip(".").strip()
    if d.startswith("www.") and d.count(".") >= 2:
        d = d[4:]
    try:
        d = d.encode("idna").decode("ascii").lower()  # IDN (.рф и др.) → punycode
    except (UnicodeError, UnicodeDecodeError):
        raise ValueError("некорректный IDN-домен")
    if not DOMAIN_RE.match(d):
        raise ValueError("некорректный домен: ожидается имя вида example.com")
    return d


def normalize_org_hint(raw: str | None) -> str | None:
    v = (raw or "").strip()
    if not v:
        return None
    digits = re.sub(r"\D", "", v)
    if digits and len(digits) == len(re.sub(r"[\s\-.]", "", v)):
        if len(digits) not in (10, 12):
            raise ValueError("ИНН должен содержать 10 или 12 цифр")
        if not inn_valid(digits):
            raise ValueError(f"ИНН {digits} не проходит проверку контрольной суммы")
        return digits
    if len(v) >= 3:
        return v[:200]
    raise ValueError("укажите ИНН (10 или 12 цифр) либо название организации (от 3 символов)")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(os.path.join(STATIC, "index.html"), headers={"Cache-Control": "no-store"})


@app.get("/favicon.ico", include_in_schema=False)
async def favicon() -> FileResponse:
    return FileResponse(os.path.join(STATIC, "app.ico"))


@app.get("/icon.png", include_in_schema=False)
async def icon() -> FileResponse:
    return FileResponse(os.path.join(STATIC, "icon.png"))


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok", "version": config.VERSION, "data_dir": config.DATA_DIR}


@app.get("/api/settings")
async def get_settings() -> dict:
    return config.public_settings()


@app.post("/api/settings")
async def set_settings(p: SettingsPatch) -> dict:
    if p.dns_mode is not None and p.dns_mode not in ("public", "system"):
        raise HTTPException(400, "dns_mode: public | system")
    if p.mode_default is not None and p.mode_default not in ("fast", "full"):
        raise HTTPException(400, "mode_default: fast | full")
    config.save_settings(p.model_dump(exclude_none=True))
    return config.public_settings()


@app.post("/api/scan")
async def create_scan(req: ScanRequest) -> dict:
    try:
        domain = normalize_domain(req.domain)
        org_hint = normalize_org_hint(req.org_hint)
    except ValueError as e:
        raise HTTPException(400, str(e))
    active = sum(1 for s in SCANS.values() if s.status == "running")
    if active >= config.MAX_CONCURRENT_SCANS:
        raise HTTPException(429, f"уже идёт {active} сбор(а); дождитесь завершения")
    mode = req.mode or config.option("mode_default") or "fast"
    if mode not in ("fast", "full"):
        raise HTTPException(400, "mode: fast | full")
    sid = f"{domain}_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}_{uuid.uuid4().hex[:6]}"
    st = engine.ScanState(sid, domain, org_hint=org_hint, fast=mode == "fast",
                          active=bool(config.option("active_default") if req.active is None else req.active),
                          brute=bool(config.option("brute_default") if req.brute is None else req.brute))
    SCANS[sid] = st
    st.task = asyncio.create_task(engine.run_scan(st))
    return {"id": sid, "domain": domain}


def _load_result(sid: str) -> dict | None:
    st = SCANS.get(sid)
    if st is not None and st.result is not None:
        return st.result
    path = os.path.join(config.SCANS_DIR, sid + ".json")
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None
    return None


def _check_sid(sid: str) -> None:
    if not SID_RE.match(sid) or ".." in sid:
        raise HTTPException(404, "скан не найден")


def _live(st: engine.ScanState) -> dict:
    """Живые счётчики и последние найденные живые хосты — показываются во время сбора."""
    resolved = list((st.data.get("resolved") or {}).items())
    alive = [n for n, v in resolved if v.get("status") == "ok"]
    return {"hosts": len(st.col.hosts) if st.col else 0, "ips": len(st.col.ips) if st.col else 0,
            "alive": len(alive), "checked": len(resolved),
            "elapsed": round((datetime.now(timezone.utc) - st.started_at).total_seconds()),
            "recent": alive[-14:][::-1]}


@app.get("/api/scan/{sid}")
async def get_scan(sid: str, light: bool = False) -> dict:
    _check_sid(sid)
    st = SCANS.get(sid)
    if st is not None:
        out = {"id": st.id, "domain": st.domain, "status": st.status, "phase": st.phase,
               "active": st.active, "started_at": st.started_at.isoformat(timespec="seconds"),
               "progress": st.progress, "error": st.error,
               "mode": "fast" if st.fast else "full", "found": _live(st)}
        if st.finished_at:
            out["finished_at"] = st.finished_at.isoformat(timespec="seconds")
        if st.result is not None and not light:
            out["result"] = st.result
        return out
    data = _load_result(sid)
    if data is not None:
        return {"id": sid, "domain": data.get("domain"), "status": "done",
                "progress": data.get("sources", []), "result": data}
    raise HTTPException(404, "скан не найден")


@app.post("/api/scan/{sid}/cancel")
async def cancel_scan(sid: str) -> dict:
    _check_sid(sid)
    st = SCANS.get(sid)
    if not st or st.status != "running" or not st.task:
        raise HTTPException(409, "скан не выполняется")
    st.task.cancel()
    return {"ok": True}


@app.delete("/api/scan/{sid}")
async def delete_scan(sid: str) -> dict:
    _check_sid(sid)
    st = SCANS.get(sid)
    if st and st.status == "running":
        raise HTTPException(409, "сначала остановите сбор")
    SCANS.pop(sid, None)
    path = os.path.join(config.SCANS_DIR, sid + ".json")
    if os.path.isfile(path):
        os.remove(path)
    return {"ok": True}


@app.get("/api/scans")
async def list_scans(limit: int = 50) -> list[dict]:
    items: list[dict] = []
    seen: set[str] = set()
    for st in SCANS.values():
        items.append({"id": st.id, "domain": st.domain, "status": st.status,
                      "started_at": st.started_at.isoformat(timespec="seconds"),
                      "summary": (st.result.get("summary") if st.result else {})})
        seen.add(st.id)
    if os.path.isdir(config.SCANS_DIR):
        files = sorted((fn for fn in os.listdir(config.SCANS_DIR) if fn.endswith(".json")),
                       key=lambda fn: os.path.getmtime(os.path.join(config.SCANS_DIR, fn)), reverse=True)
        for fn in files[:200]:
            sid = fn[:-5]
            if sid in seen:
                continue
            data = _load_result(sid)
            if data:
                items.append({"id": sid, "domain": data.get("domain"),
                              "status": "partial" if data.get("partial") else "done",
                              "started_at": data.get("started_at"), "summary": data.get("summary", {})})
    items.sort(key=lambda x: x.get("started_at") or "", reverse=True)
    return items[:max(1, min(limit, 200))]


def _download(payload, media: str, filename: str) -> Response:
    return Response(payload, media_type=media,
                    headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}"})


def _csv(rows: list[list], filename: str) -> Response:
    buf = io.StringIO()
    csv.writer(buf, delimiter=";").writerows([[report.safe_cell(v) for v in r] for r in rows])
    return _download("﻿" + buf.getvalue(), "text/csv; charset=utf-8", filename)


@app.get("/api/scan/{sid}/export")
async def export_scan(sid: str, format: str = "json"):
    _check_sid(sid)
    r = _load_result(sid)
    if r is None:
        st = SCANS.get(sid)
        if st is not None and st.status == "running":
            raise HTTPException(409, "скан ещё выполняется")
        raise HTTPException(404, "скан не найден")
    base = f'osint_{r.get("domain")}_{(r.get("started_at") or "")[:10]}'
    if format == "json":
        return _download(json.dumps(r, ensure_ascii=False, indent=2), "application/json", base + ".json")
    if format == "html":
        return _download(report.html_report(r), "text/html; charset=utf-8", base + ".html")
    if format == "html_view":
        return HTMLResponse(report.html_report(r))
    if format == "xlsx":
        return _download(report.xlsx_report(r),
                         "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", base + ".xlsx")
    if format == "hosts_txt":
        alive = [h["name"] for h in r.get("hosts", []) if h.get("alive")]
        return _download("\n".join(alive) + "\n", "text/plain; charset=utf-8", base + "_alive_hosts.txt")
    if format == "all_hosts_txt":
        return _download("\n".join(h["name"] for h in r.get("hosts", [])) + "\n", "text/plain; charset=utf-8",
                         base + "_all_hosts.txt")
    if format == "ips_txt":
        ips = [i["ip"] for i in r.get("ips", []) if i.get("current") and not i.get("private")]
        return _download("\n".join(ips) + "\n", "text/plain; charset=utf-8", base + "_ips.txt")
    if format == "hosts_csv":
        rows = [["host", "alive", "dns_status", "current_ips", "all_ips", "cname", "http_status", "title", "sources"]]
        for h in r.get("hosts", []):
            rows.append([h["name"], int(h.get("alive", False)), h.get("status"), " ".join(h.get("current_ips", [])),
                         " ".join(h["ips"]), " ".join(h.get("cname", [])), (h.get("http") or {}).get("status"),
                         (h.get("http") or {}).get("title"), " ".join(h["sources"])])
        return _csv(rows, base + "_hosts.csv")
    if format == "ips_csv":
        rows = [["ip", "current", "country", "city", "org", "isp", "as", "ptr", "cdn", "ports", "cve", "hosts"]]
        for i in r.get("ips", []):
            rows.append([i.get("ip"), int(bool(i.get("current"))), i.get("country"), i.get("city"), i.get("org"),
                         i.get("isp"), i.get("as"), i.get("reverse"), int(bool(i.get("cdn"))),
                         " ".join(map(str, i.get("ports") or [])), " ".join(i.get("vulns") or []),
                         " ".join(i.get("hosts") or [])])
        return _csv(rows, base + "_ips.csv")
    raise HTTPException(400, "format: json | html | xlsx | hosts_txt | all_hosts_txt | ips_txt | hosts_csv | ips_csv")
