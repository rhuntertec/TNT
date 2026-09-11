"""Tiny in-process publish/subscribe bus.

Producers (ping workers, outage tracker, speed scheduler, discovery) publish
small JSON-able dicts; consumers (SSE hub, tray status) subscribe. Delivery is
synchronous on the publisher's thread, so subscribers must be quick and must
never raise (exceptions are logged and swallowed).
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Dict, List

log = logging.getLogger(__name__)

Subscriber = Callable[[Dict[str, Any]], None]


class EventBus:
    def __init__(self) -> None:
        self._subs: List[Subscriber] = []
        self._lock = threading.Lock()

    def subscribe(self, fn: Subscriber) -> Callable[[], None]:
        with self._lock:
            self._subs.append(fn)

        def unsubscribe() -> None:
            with self._lock:
                try:
                    self._subs.remove(fn)
                except ValueError:
                    pass

        return unsubscribe

    def publish(self, event_type: str, data: Dict[str, Any] | None = None, ts: float | None = None) -> Dict[str, Any]:
        event = {"type": event_type, "ts": ts if ts is not None else time.time(), "data": data or {}}
        with self._lock:
            subs = list(self._subs)
        for fn in subs:
            try:
                fn(event)
            except Exception:  # noqa: BLE001 - a bad subscriber must not break producers
                log.exception("event subscriber failed for %s", event_type)
        return event
