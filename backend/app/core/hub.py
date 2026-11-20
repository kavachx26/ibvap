"""
hub.py
------
In-process publish/subscribe for the command center.

Camera pipelines run in worker threads; dashboards are asyncio WebSocket
handlers. `publish()` is thread-safe: it hands each message to the event
loop with call_soon_threadsafe, and each subscriber has its own bounded
queue so one slow browser can never stall a camera pipeline (the oldest
message is dropped instead).
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Optional, Set

from app.core import storage


class Hub:
    def __init__(self) -> None:
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._subs: Set[asyncio.Queue] = set()
        self.published = 0

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)

    @property
    def subscriber_count(self) -> int:
        return len(self._subs)

    def _fanout(self, text: str) -> None:
        for q in list(self._subs):
            if q.full():
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            q.put_nowait(text)

    def publish(self, msg: dict[str, Any]) -> None:
        self.published += 1
        text = json.dumps(msg, default=str)
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            self._fanout(text)
        else:
            loop.call_soon_threadsafe(self._fanout, text)


hub = Hub()


def _on_alert(row: dict) -> None:
    hub.publish({"type": "alert", "alert": row, "sent_at": time.time()})


storage.on_alert_saved(_on_alert)
