"""Speed tests: backends, one-shot runner, scheduler, patterns.

Public names (re-exported here):

* :class:`SpeedResult`, :class:`SpeedBackend` - result record and backend protocol
* :class:`CloudflareBackend` ("cloudflare", default) and :class:`FastComBackend`
  ("fastcom"), both built in (no external program)
* :func:`available_backends`, :func:`select_backend`, :func:`alternative_backend`,
  :func:`run_speedtest`
* :class:`SpeedScheduler` - periodic runner with ``status()``/``history()``/``patterns()``
* :func:`analyse_patterns` - pure analysis over speedtests rows
* rate limiting (see :mod:`tnt.speedtest.base`): :class:`Cooldown`,
  :func:`get_cooldown` / :func:`set_cooldown` / :func:`clear_cooldowns` /
  :func:`all_cooldowns` (the shared per-backend cooldown registry),
  :func:`parse_retry_after` / :func:`retry_after_s`, :func:`rate_limited_result`,
  :func:`is_rate_limited`

The selection/runner functions live in :mod:`tnt.speedtest.scheduler` (importing
them from the package ``__init__`` inside the scheduler would be circular).
"""
from __future__ import annotations

from .base import (
    BROWSER_UA,
    CANCELLED,
    DEFAULT_RETRY_AFTER_S,
    MAX_RETRY_AFTER_S,
    RATE_LIMIT_STATUSES,
    Cancelled,
    Cooldown,
    ProgressFn,
    RunGuard,
    SpeedBackend,
    SpeedResult,
    all_cooldowns,
    clear_cooldowns,
    failed_result,
    get_cooldown,
    is_rate_limited,
    parse_retry_after,
    rate_limited_result,
    retry_after_s,
    set_cooldown,
)
from .cloudflare import CloudflareBackend
from .fastcom import FastComBackend
from .patterns import analyse_patterns
from .scheduler import (
    BACKEND_ORDER,
    BACKENDS,
    DEFAULT_BACKEND,
    SpeedScheduler,
    alternative_backend,
    available_backends,
    get_backend,
    local_tz_offset_s,
    run_speedtest,
    select_backend,
)

__all__ = [
    "BROWSER_UA",
    "BACKENDS",
    "BACKEND_ORDER",
    "CANCELLED",
    "DEFAULT_BACKEND",
    "DEFAULT_RETRY_AFTER_S",
    "MAX_RETRY_AFTER_S",
    "RATE_LIMIT_STATUSES",
    "Cancelled",
    "Cooldown",
    "RunGuard",
    "CloudflareBackend",
    "FastComBackend",
    "ProgressFn",
    "SpeedBackend",
    "SpeedResult",
    "SpeedScheduler",
    "all_cooldowns",
    "alternative_backend",
    "analyse_patterns",
    "available_backends",
    "clear_cooldowns",
    "failed_result",
    "get_backend",
    "get_cooldown",
    "is_rate_limited",
    "local_tz_offset_s",
    "parse_retry_after",
    "rate_limited_result",
    "retry_after_s",
    "run_speedtest",
    "select_backend",
    "set_cooldown",
]
