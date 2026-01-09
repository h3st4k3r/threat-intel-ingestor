from __future__ import annotations
import requests
from typing import List
from app.models import Vulnerability, now_iso
from app.collectors.base import Collector
from app.http_client import make_session

class CisaKevCollector(Collector):
    name = "cisa_kev"

    def __init__(self, url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json") -> None:
        self.url = url
        self.s = make_session()

    def fetch(self) -> List[Vulnerability]:
        r = self.s.get(self.url, timeout=30)
        r.raise_for_status()
        data = r.json()
        out: List[Vulnerability] = []
        collected = now_iso()

        for v in data.get("vulnerabilities", []):
            cve = v.get("cveID")
            title = f"{cve} - {v.get('vulnerabilityName', '')}".strip(" -")
            out.append(
                Vulnerability(
                    kind="vuln",
                    source=self.name,
                    source_id=cve or title,
                    title=title or (cve or "CISA KEV item"),
                    url=v.get("notes") or None,
                    published_at=v.get("dateAdded"),
                    collected_at=collected,
                    raw=v,
                    cve=cve,
                    vendor=v.get("vendorProject"),
                    product=v.get("product"),
                    severity=None,
                )
            )
        return out
