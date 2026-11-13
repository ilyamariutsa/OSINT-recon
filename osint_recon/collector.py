"""Общий накопитель результатов: хосты (субдомены) и IP-адреса."""
import ipaddress
import re

_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$", re.I)
MAX_HOSTS = 50_000


def valid_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip().strip("[]()")))
    except ValueError:
        return None


class Collector:
    """Потокобезопасность не требуется: всё выполняется в одном event loop."""

    def __init__(self, domain: str):
        self.domain = domain.lower()
        self.suffix = "." + self.domain
        self.hosts: dict[str, dict] = {}
        self.ips: set[str] = set()

    def normalize(self, name: str | None) -> str | None:
        name = (name or "").strip().lower().rstrip(".").strip()
        while name.startswith("*."):
            name = name[2:]
        if name.startswith("%2a."):  # URL-кодированная «*.» из архивов
            name = name[4:]
        # только сам домен или его поддомены (а не «evil-example.com»)
        if not name or not (name == self.domain or name.endswith(self.suffix)):
            return None
        if len(name) > 253 or any(c in name for c in "/@ :\\"):
            return None
        if any(not _LABEL.match(lbl) or len(lbl) > 63 for lbl in name.split(".")):
            return None
        return name

    def add_host(self, name: str | None, ip: str | None = None, source: str | None = None) -> bool:
        """Добавить хост. Возвращает True, если хост новый."""
        host = self.normalize(name)
        if host is None:
            return False
        entry = self.hosts.get(host)
        is_new = entry is None
        if is_new:
            if len(self.hosts) >= MAX_HOSTS:
                return False
            entry = {"name": host, "ips": set(), "sources": set()}
            self.hosts[host] = entry
        vip = valid_ip(ip)
        if vip:
            entry["ips"].add(vip)
            self.ips.add(vip)
        if source:
            entry["sources"].add(source)
        return is_new

    def count_for(self, source: str) -> int:
        """Сколько хостов собрали данным источником."""
        return sum(1 for h in self.hosts.values() if source in h["sources"])
