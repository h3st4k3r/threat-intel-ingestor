from __future__ import annotations
from contextlib import contextmanager
from queue import Queue
from typing import Iterator, Optional

class SeleniumPool:
    def __init__(self, size: int = 2, headless: bool = True) -> None:
        self.size = size
        self.headless = headless
        self._q: Queue = Queue(maxsize=size)
        self._init_done = False

    def _make_driver(self):
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options

        opts = Options()
        if self.headless:
            opts.add_argument("--headless=new")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--window-size=1400,900")
        return webdriver.Chrome(options=opts)

    def start(self) -> None:
        if self._init_done:
            return
        for _ in range(self.size):
            self._q.put(self._make_driver())
        self._init_done = True

    @contextmanager
    def acquire(self) -> Iterator:
        driver = self._q.get()
        try:
            yield driver
        finally:
            self._q.put(driver)

    def stop(self) -> None:
        while not self._q.empty():
            d = self._q.get_nowait()
            try:
                d.quit()
            except Exception:
                pass
