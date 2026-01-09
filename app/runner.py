from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple
from app.collectors.base import Collector
from app.storage import Storage

Result = Tuple[str, int, int, str]  # (name, inserted, skipped, status)

def run_collectors(collectors: List[Collector], storage: Storage, max_workers_http: int = 8, max_workers_selenium: int = 2) -> List[Result]:
    http = [c for c in collectors if not c.needs_selenium()]
    sel = [c for c in collectors if c.needs_selenium()]

    def _run_one(c: Collector) -> Result:
        try:
            items = c.fetch()
            ins, sk = storage.upsert_many(items)
            return (c.name, ins, sk, "ok")
        except Exception as e:
            return (c.name, 0, 0, f"error: {e!r}")

    results: List[Result] = []

    with ThreadPoolExecutor(max_workers=max_workers_http) as ex:
        futs = [ex.submit(_run_one, c) for c in http]
        for f in as_completed(futs):
            r = f.result()
            results.append(r)
            name, ins, sk, st = r
            print(f"[{name}] {st} | nuevos={ins} repetidos={sk}")

    with ThreadPoolExecutor(max_workers=max_workers_selenium) as ex:
        futs = [ex.submit(_run_one, c) for c in sel]
        for f in as_completed(futs):
            r = f.result()
            results.append(r)
            name, ins, sk, st = r
            print(f"[{name}] {st} | nuevos={ins} repetidos={sk}")

    return results
