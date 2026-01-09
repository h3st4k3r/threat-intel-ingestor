from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Optional
from app.models import BaseItem

class Collector(ABC):
    name: str

    @abstractmethod
    def fetch(self) -> List[BaseItem]:
        ...

    def needs_selenium(self) -> bool:
        return False

    # opcional: para fuentes inestables
    def timeout_seconds(self) -> int:
        return 30
