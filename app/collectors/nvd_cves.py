from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from app.collectors.base import Collector
from app.http_client import make_session
from app.models import Vulnerability, now_iso

NVD_CVES_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _iso_utc_millis(dt: datetime) -> str:
    # Formato tipo: 2026-01-09T12:34:56.000Z (igual que tu PHP)
    dt = dt.astimezone(timezone.utc).replace(microsecond=0)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _first_text(descriptions: Any) -> str:
    if isinstance(descriptions, list):
        for d in descriptions:
            if isinstance(d, dict) and d.get("lang") in ("es", "en"):
                v = d.get("value")
                if isinstance(v, str) and v.strip():
                    return v.strip()
        for d in descriptions:
            if isinstance(d, dict):
                v = d.get("value")
                if isinstance(v, str) and v.strip():
                    return v.strip()
    return ""


def _extract_severity(cve_obj: Dict[str, Any]) -> Optional[str]:
    metrics = cve_obj.get("metrics") or {}

    for key in ("cvssMetricV40", "cvssMetricV4"):
        arr = metrics.get(key)
        if isinstance(arr, list) and arr:
            sev = (arr[0] or {}).get("baseSeverity")
            if isinstance(sev, str) and sev:
                return sev

    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key)
        if isinstance(arr, list) and arr:
            sev = (arr[0] or {}).get("baseSeverity")
            if isinstance(sev, str) and sev:
                return sev

    arr = metrics.get("cvssMetricV2")
    if isinstance(arr, list) and arr:
        sev = (arr[0] or {}).get("baseSeverity")
        if isinstance(sev, str) and sev:
            return sev

    return None


class NvdCveCollector(Collector):
    """
    NVD CVE API 2.0 por fecha de PUBLICACIÓN (pubStartDate/pubEndDate) y excluyendo rechazados (noRejected).
    Ventanas: day | week | month
    """
    name = "nvd_cves"

    def __init__(
        self,
        api_key: str,
        window: str = "day",          # day|week|month
        results_per_page: int = 2000, # máximo típico
        sleep_seconds: float = 6.0,   # NVD recomienda espaciar peticiones en automatismos
        timeout: int = 60,
        lite_raw: bool = True,        # guardar raw “ligero” para no inflar SQLite
    ) -> None:
        self.api_key = api_key.strip()
        self.window = window if window in ("day", "week", "month") else "day"
        self.results_per_page = results_per_page
        self.sleep_seconds = sleep_seconds
        self.timeout = timeout
        self.lite_raw = lite_raw

        self.s = make_session()
        if self.api_key:
            # API 2.0: apiKey en cabecera
            self.s.headers.update({"apiKey": self.api_key})  # :contentReference[oaicite:2]{index=2}

    def _window_range(self) -> tuple[str, str]:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=1 if self.window == "day" else 7 if self.window == "week" else 30)
        return _iso_utc_millis(start), _iso_utc_millis(end)

    def fetch(self) -> List[Vulnerability]:
        if not self.api_key:
            return []

        pub_start, pub_end = self._window_range()
        collected = now_iso()
        out: List[Vulnerability] = []

        start_index = 0

        while True:
            params = {
                "resultsPerPage": self.results_per_page,
                "startIndex": start_index,
                "pubStartDate": pub_start,
                "pubEndDate": pub_end,
                # En NVD este flag se usa como “excluir rechazados”.
                # En requests lo mandamos como presencia: noRejected=
                "noRejected": "",
            }

            r = self.s.get(NVD_CVES_ENDPOINT, params=params, timeout=self.timeout)
            r.raise_for_status()
            data = r.json()

            vulns = data.get("vulnerabilities") or []
            if not isinstance(vulns, list) or not vulns:
                break

            for item in vulns:
                cve_obj = (item or {}).get("cve") or {}
                cve_id = cve_obj.get("id")
                if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
                    continue

                published = cve_obj.get("published")
                last_modified = cve_obj.get("lastModified")

                desc = _first_text(cve_obj.get("descriptions"))
                sev = _extract_severity(cve_obj)

                title = f"{cve_id} - {desc}" if desc else cve_id
                if len(title) > 180:
                    title = title[:177] + "..."

                raw: Dict[str, Any]
                if self.lite_raw:
                    raw = {
                        "id": cve_id,
                        "published": published,
                        "lastModified": last_modified,
                        "descriptions": cve_obj.get("descriptions"),
                        "references": cve_obj.get("references"),
                        "metrics": cve_obj.get("metrics"),
                        "weaknesses": cve_obj.get("weaknesses"),
                    }
                else:
                    raw = item  # completo

                out.append(
                    Vulnerability(
                        kind="vuln",
                        source=self.name,
                        source_id=cve_id,
                        title=title,
                        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        published_at=published if isinstance(published, str) else (last_modified if isinstance(last_modified, str) else None),
                        collected_at=collected,
                        raw=raw,
                        cve=cve_id,
                        vendor=None,
                        product=None,
                        severity=sev,
                    )
                )

            total = data.get("totalResults")
            returned = data.get("resultsPerPage")
            if not isinstance(returned, int):
                returned = len(vulns)

            start_index += returned
            if isinstance(total, int) and start_index >= total:
                break

            time.sleep(self.sleep_seconds)

        return out
