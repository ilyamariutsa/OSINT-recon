"""Конфигурация: каталог данных, настройки и API-ключи (файл settings.json + переменные окружения)."""
import json
import os
import threading

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERSION = "2.0"


def _default_data_dir() -> str:
    for env in ("OSINT_DATA_DIR", "DATA_DIR"):
        v = os.getenv(env, "").strip()
        if v:
            return v
    return os.path.join(APP_DIR, "data")


DATA_DIR = _default_data_dir()
SCANS_DIR = os.path.join(DATA_DIR, "scans")
SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")

# Ключи внешних сервисов: имя → (переменная окружения, подпись, где получить)
API_KEYS = {
    "shodan": ("SHODAN_API_KEY", "Shodan", "https://account.shodan.io/"),
    "virustotal": ("VT_API_KEY", "VirusTotal", "https://www.virustotal.com/gui/my-apikey"),
    "securitytrails": ("SECURITYTRAILS_API_KEY", "SecurityTrails", "https://securitytrails.com/app/account/credentials"),
    "netlas": ("NETLAS_API_KEY", "Netlas.io", "https://app.netlas.io/profile/"),
    "whoisxml": ("WHOISXML_API_KEY", "WhoisXML API", "https://user.whoisxmlapi.com/products"),
    "otx": ("OTX_API_KEY", "AlienVault OTX", "https://otx.alienvault.com/api"),
    "urlscan": ("URLSCAN_API_KEY", "urlscan.io", "https://urlscan.io/user/profile/"),
    "chaos": ("CHAOS_API_KEY", "ProjectDiscovery Chaos", "https://cloud.projectdiscovery.io/"),
    "fullhunt": ("FULLHUNT_API_KEY", "FullHunt", "https://fullhunt.io/user/settings/"),
    "bevigil": ("BEVIGIL_API_KEY", "BeVigil", "https://bevigil.com/osint-api"),
}

DEFAULTS = {
    "dns_mode": "public",          # public | system
    "active_default": False,       # активные проверки (HTTP/TLS/порты) по умолчанию
    "brute_default": True,         # перебор префиксов DNS по умолчанию
    "mode_default": "fast",        # fast (~1 мин) | full (~2 мин)
}

PUBLIC_RESOLVERS = ["77.88.8.8", "1.1.1.1", "8.8.8.8", "9.9.9.9", "77.88.8.1", "8.8.4.4"]

USER_AGENT = os.getenv(
    "SCANNER_UA",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0 Safari/537.36",
)
MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "3"))
MAX_IPS_ENRICH = int(os.getenv("MAX_IPS_ENRICH", "1500"))
MAX_RESOLVE_HOSTS = int(os.getenv("MAX_RESOLVE_HOSTS", "8000"))
MAX_PROBE_HOSTS = int(os.getenv("MAX_PROBE_HOSTS", "400"))
MAX_PORTSCAN_IPS = int(os.getenv("MAX_PORTSCAN_IPS", "256"))

_lock = threading.Lock()
_cache: dict = {"mtime": None, "data": {}}


def load_settings() -> dict:
    with _lock:
        try:
            mtime = os.path.getmtime(SETTINGS_PATH)
        except OSError:
            _cache.update(mtime=None, data={})
            return {}
        if _cache["mtime"] != mtime:
            try:
                with open(SETTINGS_PATH, encoding="utf-8") as f:
                    data = json.load(f)
                _cache.update(mtime=mtime, data=data if isinstance(data, dict) else {})
            except (OSError, json.JSONDecodeError):
                _cache.update(mtime=mtime, data={})
        return dict(_cache["data"])


def save_settings(patch: dict) -> dict:
    data = load_settings()
    keys = dict(data.get("keys") or {})
    for name, value in (patch.get("keys") or {}).items():
        if name not in API_KEYS or value is None:
            continue
        value = str(value).strip()
        if value:
            keys[name] = value
        else:
            keys.pop(name, None)
    data["keys"] = keys
    for k in DEFAULTS:
        if k in patch and patch[k] is not None:
            data[k] = patch[k]
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = SETTINGS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, SETTINGS_PATH)
    return data


def key(name: str) -> str:
    """API-ключ: сначала из настроек приложения, затем из переменной окружения."""
    v = ((load_settings().get("keys") or {}).get(name) or "").strip()
    if v:
        return v
    env = API_KEYS.get(name, ("",))[0]
    return os.getenv(env, "").strip() if env else ""


def option(name: str):
    return load_settings().get(name, DEFAULTS.get(name))


def public_settings() -> dict:
    """Настройки для интерфейса: ключи маскируются."""
    out = {"keys": {}, **{k: option(k) for k in DEFAULTS}}
    for name, (env, label, url) in API_KEYS.items():
        v = key(name)
        out["keys"][name] = {
            "label": label, "url": url, "env": env, "set": bool(v),
            "masked": (v[:3] + "…" + v[-3:]) if len(v) > 8 else ("•••" if v else ""),
        }
    return out
