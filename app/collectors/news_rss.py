from __future__ import annotations

import re
from typing import List, Optional, Sequence, Tuple

import feedparser

from app.collectors.base import Collector
from app.http_client import make_session
from app.models import BaseItem, NewsItem, Vulnerability, now_iso

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
FeedDef = Tuple[str, str, str]  # (source_name, feed_url, kind: "news"|"vuln")


class RssCollector(Collector):
    name = "rss"

    def __init__(
        self,
        feed_url: Optional[str] = None,
        source_name: Optional[str] = None,
        kind: str = "news",
        feeds: Optional[Sequence[FeedDef]] = None,
        limit_per_feed: int = 50,
        timeout: int = 30,
    ) -> None:
        """
        Compatible con:
        - Modo antiguo (1 feed): RssCollector("https://...", "bleepingcomputer", "news")
        - Modo nuevo (multi-feed): RssCollector(feeds=[("name","url","news"), ...])
        """
        self.limit_per_feed = limit_per_feed
        self.timeout = timeout
        self.s = make_session()

        if feeds is not None:
            self.feeds: List[FeedDef] = list(feeds)
        else:
            if not feed_url or not source_name:
                raise ValueError("Debes pasar (feed_url, source_name) o bien feeds=[...]")
            self.feeds = [(source_name, feed_url, kind)]

    def _fetch_feed(self, url: str, source_name: str) -> bytes:
        r = self.s.get(url, timeout=self.timeout, allow_redirects=True)
        r.raise_for_status()
        return r.content

    def fetch(self) -> List[BaseItem]:
        out: List[BaseItem] = []
        collected = now_iso()

        for source_name, feed_url, kind in self.feeds:
            try:
                content = self._fetch_feed(feed_url, source_name)
                d = feedparser.parse(content)
            except Exception as e:
                print(f"[rss_{source_name}] error leyendo feed: {e!r}")
                continue

            entries = getattr(d, "entries", []) or []
            if not entries:
                bozo = getattr(d, "bozo", None)
                print(f"[rss_{source_name}] feed sin entradas (bozo={bozo}) url={feed_url}")

            for entry in entries[: self.limit_per_feed]:
                url = getattr(entry, "link", None)
                title = (getattr(entry, "title", "") or "Entrada RSS").strip()
                published = getattr(entry, "published", None) or getattr(entry, "updated", None)
                summary = getattr(entry, "summary", None)

                guid = getattr(entry, "id", None) or getattr(entry, "guid", None)
                source_id = (guid or url or (title + "|" + (published or "")))[:500]
                source = f"rss_{source_name}"

                if kind == "vuln":
                    haystack = f"{title}\n{summary or ''}"
                    m = CVE_RE.search(haystack)
                    cve = m.group(0).upper() if m else None

                    out.append(
                        Vulnerability(
                            kind="vuln",
                            source=source,
                            source_id=source_id,
                            title=title,
                            url=url,
                            published_at=published,
                            collected_at=collected,
                            raw={
                                "title": title,
                                "link": url,
                                "published": published,
                                "summary": summary,
                                "feed_url": feed_url,
                            },
                            cve=cve,
                        )
                    )
                else:
                    out.append(
                        NewsItem(
                            kind="news",
                            source=source,
                            source_id=source_id,
                            title=title,
                            url=url,
                            published_at=published,
                            collected_at=collected,
                            raw={
                                "title": title,
                                "link": url,
                                "published": published,
                                "summary": summary,
                                "feed_url": feed_url,
                            },
                            summary=summary,
                        )
                    )

        return out
