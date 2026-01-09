from __future__ import annotations

from textwrap import shorten
import os
import config
from app.collectors.nvd_cves import NvdCveCollector
from app.storage import Storage
from app.runner import run_collectors
from app.collectors.cisa_kev import CisaKevCollector
from app.collectors.malwarebazaar import MalwareBazaarRecentCollector
from app.collectors.news_rss import RssCollector


def _print_preview(storage: Storage, limit: int = 10) -> None:
    rows = storage.fetch_recent(limit=limit)
    total = storage.total_items()

    print(f"\nBD: {total} items. Muestra (últimos {min(limit, len(rows))}):\n")

    w_kind, w_src, w_id, w_title = 6, 24, 20, 60
    header = f"{'tipo':<{w_kind}} {'fuente':<{w_src}} {'id':<{w_id}} {'título':<{w_title}}"
    print(header)
    print("-" * len(header))

    for r in rows:
        kind = (r["kind"] or "")[:w_kind]
        source = shorten(r["source"] or "", width=w_src, placeholder="…")
        sid = shorten(r["source_id"] or "", width=w_id, placeholder="…")
        title = shorten(r["title"] or "", width=w_title, placeholder="…")
        print(f"{kind:<{w_kind}} {source:<{w_src}} {sid:<{w_id}} {title:<{w_title}}")


def main() -> None:
    storage = Storage("intel.db")

    RSS_FEEDS = [
        # Vulnerabilidades / avisos
        ("cert_eu_advisories", "https://cert.europa.eu/publications/security-advisories-rss", "vuln"),
        ("cert_eu_guidance", "https://cert.europa.eu/publications/security-guidance-rss", "news"),
        ("cert_eu_threat_intel", "https://cert.europa.eu/publications/threat-intelligence-rss", "news"),
        ("incibe_vulns", "https://www.incibe.es/feed/vulnerabilities", "vuln"),
        ("cisco_psirt", "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", "vuln"),
        ("fortinet_psirt", "https://fortiguard.fortinet.com/rss/ir.xml", "vuln"),

        # Noticias / sector
        ("sans_isc", "https://isc.sans.edu/rssfeed_full.xml", "news"),
        ("thehackernews", "http://thehackernews.com/feeds/posts/default", "news"),
        ("theregister_security", "https://www.theregister.com/security/headlines.atom", "news"),
        ("krebs", "https://krebsonsecurity.com/feed/", "news"),
        ("malwarebytes_labs", "https://blog.malwarebytes.com/feed/", "news"),
        ("bleepingcomputer", "https://www.bleepingcomputer.com/feed/", "news"),
        ("securityweek", "https://www.securityweek.com/feed/", "news"),
    ]

    collectors = [
        CisaKevCollector(),
        MalwareBazaarRecentCollector(),
        RssCollector(feeds=RSS_FEEDS),
    ]


    collectors.append(
        NvdCveCollector(
            api_key=os.environ.get("NVD_API_KEY", config.nvd_api_key),
            window=os.environ.get("NVD_WINDOW", "day"),  # day|week|month
            lite_raw=True,
        )
    )

    results = run_collectors(collectors, storage)

    nuevos = sum(r[1] for r in results)
    repetidos = sum(r[2] for r in results)
    errores = [r for r in results if r[3] != "ok"]

    print(f"\nResumen: nuevos={nuevos}, repetidos={repetidos}, errores={len(errores)}")
    if errores:
        for name, _, _, st in errores:
            print(f" - {name}: {st}")

    _print_preview(storage, limit=10)


if __name__ == "__main__":
    main()
