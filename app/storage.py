# app/storage.py
from __future__ import annotations
import sqlite3
import threading
from typing import Iterable, Tuple
from app.models import BaseItem
from typing import List, Dict, Any, Optional, Tuple

SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
  fingerprint TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  source TEXT NOT NULL,
  source_id TEXT NOT NULL,
  title TEXT NOT NULL,
  url TEXT,
  published_at TEXT,
  collected_at TEXT NOT NULL,
  json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_items_kind ON items(kind);
CREATE INDEX IF NOT EXISTS idx_items_source ON items(source);
    
CREATE TABLE IF NOT EXISTS state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

"""

class Storage:
    def __init__(self, path: str = "intel.db") -> None:
        self.path = path
        self._local = threading.local()

        # Inicializa esquema una vez (en el hilo principal) y cierra
        conn = sqlite3.connect(self.path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()

    def _conn(self) -> sqlite3.Connection:
        # Conexión por hilo
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30)  # check_same_thread=True por defecto
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            self._local.conn = conn
        return conn

    def upsert_many(self, items: Iterable[BaseItem]) -> Tuple[int, int]:
        inserted = 0
        skipped = 0
        conn = self._conn()
        cur = conn.cursor()

        for it in items:
            fp = it.fingerprint()
            try:
                cur.execute(
                    """INSERT INTO items
                       (fingerprint, kind, source, source_id, title, url, published_at, collected_at, json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (fp, it.kind, it.source, it.source_id, it.title, it.url, it.published_at, it.collected_at, it.to_json())
                )
                inserted += 1
            except sqlite3.IntegrityError:
                skipped += 1

        conn.commit()
        return inserted, skipped

    def total_items(self) -> int:
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM items")
        return int(cur.fetchone()[0])

    def get_state(self, key: str) -> Optional[str]:
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("SELECT value FROM state WHERE key = ?", (key,))
        row = cur.fetchone()
        return row[0] if row else None

    def set_state(self, key: str, value: str) -> None:
        conn = self._conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO state(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        conn.commit()

    def fetch_recent(self, limit: int = 10) -> List[Dict[str, Any]]:
        conn = self._conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT kind, source, source_id, title, published_at, collected_at
            FROM items
            ORDER BY collected_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cur.fetchall()
        out = []
        for kind, source, source_id, title, published_at, collected_at in rows:
            out.append({
                "kind": kind,
                "source": source,
                "source_id": source_id,
                "title": title,
                "published_at": published_at,
                "collected_at": collected_at,
            })
        return out

    def close_thread(self) -> None:
        # opcional: al final de cada hilo si quieres “limpiar”
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            finally:
                self._local.conn = None
