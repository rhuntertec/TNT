"""Local HTTP API.

* :mod:`tnt.api.server` - ``ApiServer`` (stdlib ``ThreadingHTTPServer``), the
  request handler, static file serving, loopback check and the port preflight.
* :mod:`tnt.api.routes` - the ``Router`` and the ``/api`` route table.
* :mod:`tnt.api.sse` - the ``SseHub`` that fans EventBus events out to
  ``GET /api/events`` clients.
"""
from __future__ import annotations

from .routes import ApiError, Request, Response, Router, StreamResponse, build_routes, json_response
from .server import ApiServer, describe_port_owner, is_loopback, port_busy_message, preflight_port
from .sse import SseHub

__all__ = [
    "ApiError",
    "ApiServer",
    "Request",
    "Response",
    "Router",
    "SseHub",
    "StreamResponse",
    "build_routes",
    "describe_port_owner",
    "is_loopback",
    "json_response",
    "port_busy_message",
    "preflight_port",
]
