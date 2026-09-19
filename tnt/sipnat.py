r"""STUN: what this network's NAT does to the ports SIP and RTP depend on (SIP page, §3.28).

The ALG check (:mod:`tnt.sipalg`) answers "is something rewriting my SIP".  This answers the other half of the same
complaint: **will the audio get back**, and **how long does a mapping live**.  Between them they cover almost every
"the phone rings but nobody can hear anybody" call.

Original code written from RFC 5389 / RFC 8489 (the 20-byte header, the magic cookie, the transaction id, and the
XOR-MAPPED-ADDRESS attribute) and RFC 5780 (what NAT behaviour discovery can and cannot be done from a client).
Nothing is taken from any other implementation.

Mapping behaviour, which is the one that matters
-------------------------------------------------
Send a Binding Request **from one local socket to two different STUN servers** and compare what each says it saw.

* The same public address and port from both - **endpoint-independent mapping**.  The NAT gives this socket one
  external port whoever it is talking to, so the far end can send RTP back to the port it learned from the SDP and
  it arrives.  This is what working voice looks like.
* A **different external port per server** - the NAT allocates per destination.  That is symmetric NAT, and it is
  the classic cause of one-way audio: the PBX sends its RTP to the port in your SDP, and that port only ever
  accepted traffic from the STUN server.  The audio goes out and nothing comes back.

That comparison needs no special server support at all, which is why it is the check this module leads with: any
two plain STUN servers do it.

What this deliberately does not claim
--------------------------------------
**Filtering behaviour** - the old "full cone / restricted / port restricted" taxonomy - needs the server to answer
from a different address on request (RFC 5780 ``CHANGE-REQUEST``), and most public servers ignore it.  Rather than
guess, :data:`MAPPINGS` has no filtering verdict and the page says filtering was not determined.  The RFC 3489 NAT
type names are deprecated for exactly this reason: they were widely reported and frequently wrong.

A result also only describes the path to the servers asked.  A PBX reached over a VPN or SD-WAN has its own NAT,
and this says nothing about that.

Binding lifetime (:meth:`StunChecker.lifetime`)
-----------------------------------------------
Get a mapping, go quiet, and ask again from the same local port: if the external port changed, the NAT dropped the
binding while nothing was using it.  Stepping the idle time up finds roughly where that happens, and the number
matters more than it looks - a NAT that forgets a UDP binding after 30 s, with a phone that re-registers every
3600 s, produces a site where outbound calls work and inbound ones fail, which is baffling until it is measured.
It is slow by nature, so it is its own call and never part of the quick check.

Ports
-----
The quick check runs from an ephemeral port by default.  The page can ask for UDP 5060 instead - the binding the
signalling itself uses - and, as in :mod:`tnt.sipalg`, that bind is best-effort and the result always reports the
port really used.
"""

from __future__ import annotations

import copy
import ipaddress
import logging
import threading
import os
import secrets
import socket
import struct
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

log = logging.getLogger(__name__)

__all__ = ["STUN_KEYS", "SERVER_KEYS", "LIFETIME_KEYS", "STEP_KEYS", "FINDING_KEYS", "MAPPINGS", "FINDING_IDS",
           "DEFAULT_SERVERS", "MAGIC_COOKIE", "BINDING_REQUEST", "BINDING_SUCCESS", "DEFAULT_TIMEOUT_S",
           "LIFETIME_STEPS_S", "build_binding_request", "parse_binding_response", "validate_server",
           "StunChecker", "NatError"]

STUN_KEYS = ("ts", "servers", "local_port", "requested_port", "bound", "mapping", "public", "port_preserved",
             "findings", "note")
SERVER_KEYS = ("host", "port", "answered", "mapped_ip", "mapped_port", "elapsed_ms", "error")
LIFETIME_KEYS = ("ts", "server", "local_port", "steps", "survived_s", "lost_at_s", "verdict", "findings")
STEP_KEYS = ("idle_s", "mapped_port", "kept", "error")
FINDING_KEYS = ("id", "level", "title", "detail", "advice", "evidence")

#: What the two servers' answers say about how this NAT allocates.  No filtering verdict: see the module docstring.
BUSY_TEXT = "a STUN test is already running"

MAPPINGS = ("endpoint-independent", "address-dependent", "none", "unknown")

FINDING_IDS: Tuple[str, ...] = (
    "nat.symmetric", "nat.cone", "nat.none", "nat.unknown", "nat.port", "nat.silent", "nat.lifetime",
    "nat.lifetime-short", "nat.lifetime-unknown",
)

#: Two operators, not two names for one: symmetric NAT is found by comparing what two *different* servers saw, so
#: a pair that resolved to the same host would silently answer "endpoint-independent" for every network.
DEFAULT_SERVERS: Tuple[Tuple[str, int], ...] = (("stun.l.google.com", 19302), ("stun.cloudflare.com", 3478))

MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_XOR_MAPPED_ADDRESS = 0x0020
_HEADER = 20
DEFAULT_TIMEOUT_S = 3.0
MAX_RESPONSE = 4096
MAX_HOST = 253
#: Idle periods the lifetime probe tries, in order.  Stops at the first one the mapping does not survive.
LIFETIME_STEPS_S: Tuple[int, ...] = (15, 30, 60, 120, 240)


class NatError(RuntimeError):
    """The check could not run; the message says why in words a person can act on."""


def validate_server(text: Any, port: Any = None) -> Tuple[str, int]:
    """``(host, port)`` of a STUN server, or ``ValueError`` with the text the page shows."""
    host = str(text or "").strip().rstrip(".")
    if host.startswith("stun:"):
        host = host.split(":", 1)[1]
    if host.startswith("[") and "]" in host:
        literal, _, tail = host.partition("]")
        host, port = literal[1:], (tail.lstrip(":") or port)
    elif host.count(":") == 1:
        host, _, tail = host.partition(":")
        port = tail or port
    if not host:
        raise ValueError("give a STUN server address")
    if len(host) > MAX_HOST or any(ch.isspace() for ch in host) or "/" in host:
        raise ValueError("that does not look like a host name or an IP address")
    number = 3478 if port in (None, "") else port
    if isinstance(number, bool) or (isinstance(number, float) and number != int(number)):
        raise ValueError("the port must be a whole number from 1 to 65535")
    try:
        number = int(number)
    except (TypeError, ValueError):
        raise ValueError("the port must be a whole number from 1 to 65535") from None
    if not 1 <= number <= 65535:
        raise ValueError("the port must be a whole number from 1 to 65535")
    return host, number


# --------------------------------------------------------------------------- the protocol
def build_binding_request() -> Tuple[bytes, bytes]:
    """A STUN Binding Request and its transaction id.

    Twenty bytes and no attributes: type, length, the magic cookie that tells a server this is RFC 5389 rather than
    the 1997 original, and 96 random bits that tie the answer to this question and nothing else."""
    transaction = secrets.token_bytes(12)
    return struct.pack(">HHI", BINDING_REQUEST, 0, MAGIC_COOKIE) + transaction, transaction


def _xor_address(family: int, raw: bytes, port: int, transaction: bytes) -> Tuple[Optional[str], int]:
    """XOR-MAPPED-ADDRESS undone: the port against the top half of the cookie, the address against the whole of it
    (and, for IPv6, the transaction id too)."""
    real_port = port ^ (MAGIC_COOKIE >> 16)
    key = struct.pack(">I", MAGIC_COOKIE) + transaction
    plain = bytes(a ^ b for a, b in zip(raw, key))
    try:
        if family == 0x01 and len(plain) == 4:
            return str(ipaddress.IPv4Address(plain)), real_port
        if family == 0x02 and len(plain) == 16:
            return str(ipaddress.IPv6Address(plain)), real_port
    except ValueError:
        return None, real_port
    return None, real_port


def parse_binding_response(data: bytes, transaction: bytes) -> Optional[Dict[str, Any]]:
    """The address a Binding Success Response says it saw, or None when *data* is not this question's answer.

    None rather than an exception for every kind of wrong: too short, not a success response, the wrong magic
    cookie, a transaction id that belongs to some other request, a truncated attribute.  A stale answer to an
    earlier probe has a different transaction id and is ignored, which is the point of having one."""
    raw = bytes(data)
    if len(raw) < _HEADER:
        return None
    kind, length, cookie = struct.unpack_from(">HHI", raw, 0)
    if cookie != MAGIC_COOKIE or raw[8:20] != transaction:
        return None
    if kind != BINDING_SUCCESS:
        return {"address": None, "port": None, "kind": kind, "attributes": []}
    at, end = _HEADER, min(len(raw), _HEADER + length)
    address: Optional[str] = None
    port: Optional[int] = None
    seen: List[int] = []
    while at + 4 <= end:
        attr_type, attr_len = struct.unpack_from(">HH", raw, at)
        at += 4
        if at + attr_len > end:
            break
        value = raw[at:at + attr_len]
        seen.append(attr_type)
        if attr_type in (ATTR_XOR_MAPPED_ADDRESS, ATTR_MAPPED_ADDRESS) and attr_len >= 8:
            family, raw_port = value[1], struct.unpack_from(">H", value, 2)[0]
            if attr_type == ATTR_XOR_MAPPED_ADDRESS:
                found, real_port = _xor_address(family, value[4:], raw_port, transaction)
            else:                                   # the pre-5389 form some servers still send alongside
                try:
                    found = str(ipaddress.ip_address(value[4:]))
                except ValueError:
                    found = None
                real_port = raw_port
            if found is not None and (address is None or attr_type == ATTR_XOR_MAPPED_ADDRESS):
                address, port = found, real_port
        at += attr_len + ((4 - attr_len % 4) % 4)   # attributes are padded to a multiple of four
    if address is None:
        return None
    return {"address": address, "port": port, "kind": kind, "attributes": seen}


# --------------------------------------------------------------------------- the checks
def _finding(ident: str, level: str, title: str, detail: Optional[str] = None, advice: Optional[str] = None,
             evidence: Any = None) -> Dict[str, Any]:
    return {"id": ident, "level": level, "title": title, "detail": detail, "advice": advice, "evidence": evidence}


_LEVELS = ("bad", "warn", "info", "good")


class StunChecker:
    """Asks two STUN servers what they see, and says what that means for voice.

    Module-level seams tests monkeypatch: ``_open_socket`` and ``_sleep``."""

    def __init__(self, *, timeout_s: float = DEFAULT_TIMEOUT_S, clock: Any = None) -> None:
        self._timeout = max(0.5, min(30.0, float(timeout_s)))
        self._clock = clock or time.time
        self._lock = threading.Lock()
        self._running = False
        self._last: Optional[Dict[str, Any]] = None

    # -- state, so a button can drive it ---------------------------------------------------------
    def last(self) -> Optional[Dict[str, Any]]:
        """The last quick check (a copy), or None.  The lifetime test is not kept here: it is a different
        question, it takes minutes, and it is never what the page shows by default."""
        with self._lock:
            return copy.deepcopy(self._last)

    def running(self) -> bool:
        return self._running

    def on_network_change(self, data: Any = None) -> None:
        """``net.changed``: a mapping seen through the old network says nothing about the new one."""
        with self._lock:
            self._last = None

    def check(self, servers: Optional[Sequence[Any]] = None, *, local_port: int = 0) -> Dict[str, Any]:
        """The quick check: both servers asked from one socket, and what the difference says.

        One at a time, and the lifetime test counts: both hold a local port for the length of the run, and the
        whole point of the comparison is that one socket is used throughout."""
        with self._lock:
            if self._running:
                raise RuntimeError(BUSY_TEXT)
            self._running = True
        try:
            result = self._check(servers, local_port)
        finally:
            with self._lock:
                self._running = False
        with self._lock:
            self._last = copy.deepcopy(result)
        return result

    def _check(self, servers: Optional[Sequence[Any]], local_port: int) -> Dict[str, Any]:
        wanted = [validate_server(*(entry if isinstance(entry, (tuple, list)) else (entry, None)))
                  for entry in (servers or DEFAULT_SERVERS)]
        if len(wanted) < 2:
            log.debug("only one STUN server given: mapping behaviour needs two to compare")
        sock = None
        rows: List[Dict[str, Any]] = []
        used_port = None
        bound = False
        try:
            sock, used_port, bound = _open_socket(local_port)
            for host, port in wanted:
                rows.append(self._ask(sock, host, port))
        except OSError as exc:
            raise NatError(_reason(exc)) from exc
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        return self._verdict(rows, used_port, local_port, bound)

    def _ask(self, sock: Any, host: str, port: int) -> Dict[str, Any]:
        row: Dict[str, Any] = {"host": host, "port": port, "answered": False, "mapped_ip": None,
                               "mapped_port": None, "elapsed_ms": None, "error": None}
        request, transaction = build_binding_request()
        started = float(self._clock())
        try:
            sock.settimeout(self._timeout)
            sock.sendto(request, (host, port))
            while True:
                data, _peer = sock.recvfrom(MAX_RESPONSE)
                answer = parse_binding_response(data, transaction)
                if answer is None:                  # someone else's answer, or rubbish: keep waiting
                    if float(self._clock()) - started >= self._timeout:
                        break
                    continue
                row["answered"] = answer.get("address") is not None
                row["mapped_ip"], row["mapped_port"] = answer.get("address"), answer.get("port")
                row["elapsed_ms"] = round((float(self._clock()) - started) * 1000.0, 1)
                break
        except socket.timeout:
            row["error"] = "no answer"
        except OSError as exc:
            row["error"] = _reason(exc)
        except Exception as exc:                    # noqa: BLE001 - one server that misbehaves is not the check
            row["error"] = str(exc) or "the request could not be sent"
            log.debug("STUN request to %s failed", host, exc_info=True)
        return row

    def _verdict(self, rows: List[Dict[str, Any]], used_port: Optional[int], wanted_port: int,
                 bound: bool) -> Dict[str, Any]:
        answered = [row for row in rows if row["answered"]]
        findings: List[Dict[str, Any]] = []
        public = answered[0]["mapped_ip"] if answered else None
        ports = {row["mapped_port"] for row in answered}
        addresses = {row["mapped_ip"] for row in answered}
        preserved = None
        if answered and used_port:
            preserved = used_port in ports and len(ports) == 1

        if not answered:
            mapping = "unknown"
            findings.append(_finding(
                "nat.silent", "warn", "No STUN server answered",
                "Neither server replied, so nothing is known about what this network does to a UDP mapping. "
                + "; ".join(f"{row['host']}: {row['error']}" for row in rows if row["error"]),
                "Check this PC can reach the internet on UDP. Some networks block STUN specifically, which is "
                "itself worth knowing - phones on that network cannot use it either."))
        elif len(answered) < 2:
            mapping = "unknown"
            findings.append(_finding(
                "nat.unknown", "warn", "Only one server answered",
                f"{answered[0]['host']} replied and the other did not, so the public address is known but the "
                "mapping behaviour is not: telling an endpoint-independent NAT from a symmetric one needs two "
                "different servers to compare.",
                "Try again, or set a second STUN server the site can reach."))
        elif public and _no_nat(public, used_port, ports, addresses):
            # checked before the endpoint-independent case, which it would otherwise match: "nothing is translating"
            # is a different and more reassuring statement than "the translation is well behaved"
            mapping = "none"
            findings.append(_finding(
                "nat.none", "good", "This PC is not behind NAT",
                f"Both servers saw {public} with the same port this socket is bound to. Nothing is translating, "
                "so nothing can mistranslate.", None))
        elif len(addresses) == 1 and len(ports) == 1:
            mapping = "endpoint-independent"
            findings.append(_finding(
                "nat.cone", "good", "The NAT keeps one port per socket",
                f"Both servers saw this PC as {public}:{next(iter(ports))}. The external port does not change with "
                "the destination, so audio sent back to the port in the SDP arrives.",
                None, {"mapped": sorted(f"{r['mapped_ip']}:{r['mapped_port']}" for r in answered)}))
        else:
            mapping = "address-dependent"
            findings.append(_finding(
                "nat.symmetric", "bad", "This NAT gives a different port per destination",
                "The two servers saw different external ports for the same socket - "
                + ", ".join(f"{row['host']} saw {row['mapped_ip']}:{row['mapped_port']}" for row in answered)
                + ". That is symmetric NAT. The port a phone puts in its SDP is only open to whoever it first "
                "talked to, so the far end's RTP arrives at a port that will not accept it.",
                "This is the classic one-way-audio network. Either the PBX has to do media relay (an SBC, or "
                "rport/comedia on the trunk), or the NAT has to be changed to keep one port per socket.",
                {"mapped": sorted(f"{r['mapped_ip']}:{r['mapped_port']}" for r in answered)}))

        if wanted_port and not bound:
            findings.append(_finding(
                "nat.port", "info", f"Port {wanted_port} could not be used for the test",
                f"The check asked to run from UDP {wanted_port} - the binding the signalling itself uses - and "
                f"could not have it, so it went out from {used_port} instead. Something else on this PC has it.",
                "Close whatever is using it and run again if the result needs to reflect that exact port."))
        return {"ts": float(self._clock()), "servers": rows, "local_port": used_port,
                "requested_port": wanted_port, "bound": bound, "mapping": mapping, "public": public,
                "port_preserved": preserved,
                "findings": sorted(findings, key=lambda f: _LEVELS.index(f["level"])), "note": None}

    # -- the slow one ----------------------------------------------------------------------------
    def lifetime(self, server: Any = None, *, steps: Iterable[int] = LIFETIME_STEPS_S,
                 local_port: int = 0) -> Dict[str, Any]:
        """How long a UDP mapping survives with nothing using it.

        Get a mapping, wait, ask again from the same socket, and see whether the external port is still the one it
        was.  Stops at the first idle period the mapping does not survive, so a NAT with a generous timeout costs
        the whole list and a mean one costs almost nothing.  Slow by nature: this is never part of the quick
        check."""
        with self._lock:
            if self._running:
                raise RuntimeError(BUSY_TEXT)
            self._running = True
        try:
            return self._lifetime(server, steps, local_port)
        finally:
            with self._lock:
                self._running = False

    def _lifetime(self, server: Any, steps: Iterable[int], local_port: int) -> Dict[str, Any]:
        host, port = validate_server(*(server if isinstance(server, (tuple, list)) else (server or DEFAULT_SERVERS[0][0], None if server else DEFAULT_SERVERS[0][1])))
        rows: List[Dict[str, Any]] = []
        survived: Optional[int] = None
        lost: Optional[int] = None
        sock = None
        used_port = None
        try:
            sock, used_port, _bound = _open_socket(local_port)
            first = self._ask(sock, host, port)
            if not first["answered"]:
                return self._lifetime_result(host, port, used_port, rows, None, None, "unknown",
                                             first.get("error"))
            baseline = first["mapped_port"]
            for idle in steps:
                _sleep(float(idle))
                again = self._ask(sock, host, port)
                kept = bool(again["answered"] and again["mapped_port"] == baseline)
                rows.append({"idle_s": int(idle), "mapped_port": again["mapped_port"], "kept": kept,
                             "error": again["error"]})
                if kept:
                    survived = int(idle)
                else:
                    lost = int(idle)
                    break
        except OSError as exc:
            raise NatError(_reason(exc)) from exc
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        verdict = "unknown" if survived is None and lost is None else ("short" if lost is not None else "long")
        return self._lifetime_result(host, port, used_port, rows, survived, lost, verdict, None)

    def _lifetime_result(self, host: str, port: int, local_port: Optional[int], rows: List[Dict[str, Any]],
                         survived: Optional[int], lost: Optional[int], verdict: str,
                         error: Optional[str]) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        if verdict == "unknown":
            findings.append(_finding(
                "nat.lifetime-unknown", "warn", "The mapping could not be measured",
                f"{host} did not answer" + (f" ({error})" if error else "") + ", so there is no mapping to watch.",
                "Try the quick check first: if that cannot reach a STUN server either, this network blocks it."))
        elif lost is not None:
            level = "bad" if lost <= 60 else "warn"
            findings.append(_finding(
                "nat.lifetime-short", level, f"A UDP mapping is dropped after about {lost} s of silence",
                (f"It survived {survived} s and was gone by {lost} s." if survived
                 else f"It was already gone after {lost} s.")
                + " Anything registering less often than that loses its inbound path between registrations.",
                f"Set the phones' registration interval - or the trunk's keep-alive - below {max(1, lost // 2)} s. "
                "This is the fault where outbound calls work and inbound ones fail for no visible reason.",
                {"survived_s": survived, "lost_at_s": lost}))
        else:
            findings.append(_finding(
                "nat.lifetime", "good", f"A UDP mapping survived {survived} s of silence",
                f"The external port was unchanged after {survived} s with nothing using it, which is the longest "
                "this check waited.",
                "Comfortable for a normal registration interval. The real timeout is at least this and may be "
                "longer - the check stops once it has an answer worth having.",
                {"survived_s": survived}))
        return {"ts": float(self._clock()), "server": f"{host}:{port}", "local_port": local_port, "steps": rows,
                "survived_s": survived, "lost_at_s": lost, "verdict": verdict,
                "findings": sorted(findings, key=lambda f: _LEVELS.index(f["level"]))}


def _no_nat(public: str, local_port: Optional[int], ports: Iterable[Any], addresses: Iterable[Any]) -> bool:
    """True when the address the servers saw is this socket's own, which means nothing translated it."""
    if local_port is None or len(set(ports)) != 1 or len(set(addresses)) != 1:
        return False
    return next(iter(set(ports))) == local_port and _is_routable(public)


def _is_routable(address: Any) -> bool:
    """An address that is not one a device is NATted out of.

    Uses :func:`tnt.sipalg.behind_nat` rather than ``ipaddress.is_private`` so there is one definition of "behind
    NAT" in the codebase - and because is_private also counts the documentation ranges, which stand in for public
    addresses throughout this project and would make the no-NAT case impossible to reach."""
    from . import sipalg
    natted = sipalg.behind_nat(address)
    if natted is None:
        return False
    try:
        value = ipaddress.ip_address(str(address))
    except ValueError:
        return False
    return not natted and not (value.is_loopback or value.is_link_local or value.is_unspecified)


def _reason(exc: BaseException) -> str:
    name = getattr(exc, "strerror", None) or str(exc)
    return str(name).strip() or type(exc).__name__


def _open_socket(local_port: int) -> Tuple[Any, int, bool]:
    """A UDP socket, bound to *local_port* where that is possible.  ``(socket, port really used, got what it asked
    for)`` - the caller reports the difference, because a result from another port describes another binding."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bound = False
    try:
        if local_port:
            try:
                sock.bind(("", int(local_port)))
                bound = True
            except OSError:
                sock.bind(("", 0))
        else:
            sock.bind(("", 0))
        return sock, int(sock.getsockname()[1]), bound
    except OSError:
        sock.close()
        raise


def _sleep(seconds: float) -> None:
    time.sleep(seconds)
