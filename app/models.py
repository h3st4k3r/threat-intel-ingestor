from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, Optional, Literal
import hashlib
import json

ItemKind = Literal["vuln", "ioc", "news"]

def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()

@dataclass(frozen=True)
class BaseItem:
    kind: ItemKind
    source: str               # ej: "cisa_kev", "malwarebazaar", "rss_bleepingcomputer"
    source_id: str            # id propio de la fuente (cve, url, hash, etc.)
    title: str
    url: Optional[str]
    published_at: Optional[str]   # ISO 8601 si lo tienes
    collected_at: str             # ISO 8601 (ahora)
    raw: Dict[str, Any]           # payload original o parcialmente reducido

    def fingerprint(self) -> str:
        # estable e idempotente
        return _sha256(f"{self.kind}:{self.source}:{self.source_id}")

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

@dataclass(frozen=True)
class Vulnerability(BaseItem):
    cve: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    severity: Optional[str] = None

@dataclass(frozen=True)
class IOC(BaseItem):
    indicator: Optional[str] = None  # hash, ip, dominio, url, etc.
    ioc_type: Optional[str] = None   # "sha256", "ip", "domain"...

@dataclass(frozen=True)
class NewsItem(BaseItem):
    summary: Optional[str] = None

def now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
