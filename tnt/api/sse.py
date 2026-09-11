"""Server-sent events hub.

``SseHub`` sits between the :class:`tnt.events.EventBus` and the HTTP handler
threads that serve ``GET /api/events``.  Every connected client owns a bounded
``queue.Queue`` (2000 entries).  Publishing is strictly non-blocking: when a
client's queue is full the oldest entry is discarded so a stalled browser can
never slow down the ping workers that publish events.

Wire format::

    event: ping.sample
    data: {"target_id": 1, "ts": 1.7e9, "ok": true, "rtt_ms": 20.0, "light": "green"}

The ``data`` line carries the event payload (``event["data"]``) with the bus
timestamp merged in as ``ts`` when the payload has none, so the ``hello`` event
``{"version", "ts"}`` and every other event share one shape.  A ``: ping``
comment line is written every 15 s as a keep-alive.
"""
from __future__ import annotations

import json
import logging
import queue
import threading
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger(__name__)

HEARTBEAT_S = 15.0
DEFAULT_QUEUE_SIZE = 2000

# Pushed into every client queue by close()/kick_all() so blocked handler
# threads wake up and finish promptly during shutdown.
STOP = None


def format_event(event_type: str, payload: Any) -> bytes:
    """Encode one SSE frame. Multi-line JSON is impossible (no indent) but a
    defensive split keeps the frame valid even if ``payload`` is a raw string."""
    text = payload if isinstance(payload, str) else json.dumps(payload, default=str, separators=(",", ":"))
    lines = "".join(f"data: {line}\n" for line in text.splitlines() or [""])
    return f"event: {event_type}\n{lines}\n".encode("utf-8")


def format_comment(text: str = "ping") -> bytes:
    return f": {text}\n\n".encode("utf-8")


def event_payload(event: Dict[str, Any]) -> Dict[str, Any]:
    """Payload sent on the ``data:`` line for a bus event ``{"type","ts","data"}``."""
    data = event.get("data")
    payload: Dict[str, Any] = dict(data) if isinstance(data, dict) else {"value": data}
    payload.setdefault("ts", event.get("ts"))
    return payload


class SseHub:
    """Fan-out of bus events to per-client queues (thread-safe)."""

    def __init__(self, bus: Any | None = None, maxsize: int = DEFAULT_QUEUE_SIZE) -> None:
        self._lock = threading.Lock()
        self._queues: List["queue.Queue[Any]"] = []
        self._maxsize = int(maxsize)
        self._unsub: Optional[Callable[[], None]] = None
        self._bus: Any | None = None
        self.dropped = 0          # events discarded because a client queue was full
        self.published = 0
        if bus is not None:
            self.attach(bus)

    # -- bus wiring --------------------------------------------------------
    def attach(self, bus: Any) -> None:
        """Subscribe to *bus* (idempotent for the same bus)."""
        with self._lock:
            if self._bus is bus and self._unsub is not None:
                return
            if self._unsub is not None:
                try:
                    self._unsub()
                except Exception:  # noqa: BLE001
                    log.debug("bus unsubscribe failed", exc_info=True)
            self._bus = bus
            self._unsub = bus.subscribe(self.publish)

    def detach(self) -> None:
        with self._lock:
            unsub, self._unsub, self._bus = self._unsub, None, None
        if unsub is not None:
            try:
                unsub()
            except Exception:  # noqa: BLE001
                log.debug("bus unsubscribe failed", exc_info=True)

    @property
    def attached(self) -> bool:
        with self._lock:
            return self._unsub is not None

    # -- clients -----------------------------------------------------------
    def subscribe(self) -> "queue.Queue[Any]":
        q: "queue.Queue[Any]" = queue.Queue(maxsize=self._maxsize)
        with self._lock:
            self._queues.append(q)
        return q

    def unsubscribe(self, q: "queue.Queue[Any]") -> None:
        with self._lock:
            try:
                self._queues.remove(q)
            except ValueError:
                pass

    def client_count(self) -> int:
        with self._lock:
            return len(self._queues)

    # -- publishing --------------------------------------------------------
    def publish(self, event: Dict[str, Any]) -> None:
        """EventBus subscriber: never blocks, never raises."""
        with self._lock:
            targets = list(self._queues)
            self.published += 1
        for q in targets:
            if not self._offer(q, event):
                with self._lock:
                    self.dropped += 1

    @staticmethod
    def _offer(q: "queue.Queue[Any]", item: Any) -> bool:
        """Non-blocking put; on overflow drop the oldest entry and retry once."""
        try:
            q.put_nowait(item)
            return True
        except queue.Full:
            pass
        try:
            q.get_nowait()
        except queue.Empty:
            pass
        try:
            q.put_nowait(item)
        except queue.Full:
            return False
        return False  # something was dropped even though the new item went in

    def kick_all(self) -> None:
        """Wake every client loop (used at shutdown)."""
        with self._lock:
            targets = list(self._queues)
        for q in targets:
            self._offer(q, STOP)

    def close(self) -> None:
        self.detach()
        self.kick_all()
