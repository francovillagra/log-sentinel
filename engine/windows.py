"""Ventana deslizante por clave (IP) con memoria acotada, compartida por los detectores con estado.

Antes cada detector guardaba un `defaultdict(deque)` que crecía con cada IP distinta y nunca soltaba nada (medido: ~1,3 KB por IP;
500 000 IPs = 645 MB). Acá:
  - se recuerdan como máximo `max_keys` IPs (se olvida la menos reciente);
  - de cada IP se guardan como máximo `threshold` marcas de tiempo (no las de un ataque de millones de pedidos);
  - la marca es un float, no un objeto datetime.
"""
from bisect import bisect_left
from collections import OrderedDict
from datetime import datetime
from typing import Optional

_EPOCH = datetime(1970, 1, 1)


class _Entry:
    __slots__ = ("times", "last_alert")

    def __init__(self) -> None:
        self.times: list[float] = []
        self.last_alert: Optional[float] = None


class SlidingThreshold:
    """`hit(clave, ts)` registra un evento y devuelve cuántos hay en la ventana cuando se alcanza el umbral (una sola vez por
    ventana: después de avisar, esa clave calla `window_seconds`). Si no hay que avisar, devuelve None."""

    def __init__(self, threshold: int, window_seconds: float, max_keys: int) -> None:
        self.threshold = threshold
        self.window_seconds = float(window_seconds)
        self.max_keys = max_keys
        self._entries: "OrderedDict[str, _Entry]" = OrderedDict()

    def __len__(self) -> int:
        return len(self._entries)

    def hit(self, key: str, ts: datetime) -> Optional[int]:
        now = (ts - _EPOCH).total_seconds()
        entry = self._entries.get(key)
        if entry is None:
            entry = self._entries[key] = _Entry()
            if len(self._entries) > self.max_keys:
                self._entries.popitem(last=False)
        else:
            self._entries.move_to_end(key)

        times = entry.times
        stale = bisect_left(times, now - self.window_seconds)
        if stale:
            del times[:stale]
        times.append(now)
        if len(times) > self.threshold:
            del times[0]
        if len(times) < self.threshold:
            return None
        if entry.last_alert is not None and now - entry.last_alert < self.window_seconds:
            return None
        entry.last_alert = now
        return len(times)
