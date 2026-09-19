r"""SIP ALG detection: is something on the path editing the SIP as it goes past (SIP page, §3.28)?

A SIP ALG is the "helpful" Application Layer Gateway in most consumer and small-business routers.  It rewrites SIP
in flight - the Via, the Contact, the SDP connection line - trying to fix NAT on the phone's behalf, and it is the
single most common cause of one-way audio, failed registrations and calls that drop after exactly thirty seconds.
Turning it off is usually the fix.  Proving it is on is the hard part, and this module does it two ways.

The active check (:class:`AlgChecker`)
--------------------------------------
Send a SIP ``OPTIONS`` to a SIP server - the site's own PBX, SBC or registrar - and read what comes back.

This works against **any** RFC-compliant SIP server, with nothing installed at the far end, because of one fact:
a response echoes the request's ``Via``, ``Call-ID``, ``CSeq`` and ``From`` **verbatim as the server received
them** (RFC 3261 clause 8.2.6.2).  They are how the response is routed home and matched to its transaction, so a
server may not invent them.  That makes the response a mirror: send known values, read them back, and anything that
differs was changed in transit by something between here and there.  Two legal additions are not changes and are
excluded - a server appends ``received`` and ``rport`` to the top Via (RFC 3261 clause 18.2.1, RFC 3581) and a tag
to ``To``.

The probe runs twice, from **UDP 5060** and from an ephemeral port, because most ALGs only engage on 5060.  A
rewrite on 5060 that does not happen on the high port is as close to conclusive as this gets, and it also tells the
tech the workaround: move the phone off 5060.  Binding 5060 is best-effort - it is outside TNT's own port block and
a softphone on this PC will already hold it - so the result always says which source port each probe really used.

What a clean result does and does not mean
-------------------------------------------
It means nothing rewrote **this OPTIONS**, on **this path**, from **this port**.  It does not prove there is no
ALG: some only engage on ``INVITE`` or ``REGISTER``, some only once a call is up, and some only in one direction.
:data:`VERDICTS` therefore has ``clean`` rather than "none", and ``inconclusive`` for the case that matters most -
no answer at all, which is a firewall or a wrong address, not a clean bill of health.  SIP over TLS cannot be read
or rewritten by anything in the middle, so a TLS port gives ``moot``: the question does not apply.

Finding the server (RFC 3263)
------------------------------
A tech reads the SIP host out of a phone's configuration, and what is written there is usually the SIP *domain* -
``cpbx.example.net``, not a host with an A record.  A phone does not resolve that name directly either: it looks
up ``_sip._udp.<domain>`` and is told which servers to talk to and on which port.  So this does the same, and
falls back to the name itself when there is no SRV record.  Without it the check answered "that name does not
resolve" for the exact string the phones are configured with, which is true and useless.

The SRV target is what gets probed, and the result says which one it used, because the answer belongs to that
server rather than to the domain.

The passive check (:func:`passive_tells`)
------------------------------------------
Most of the time a tech has one capture, not two, and cannot send anything - so this reads a single capture's calls
for the marks an ALG leaves on its own:

* a **private-addressed device whose Contact or Via carries the public IP** - the phone did not write that;
* an **SDP connection line that is not the sender's own address**, which is the rewrite that causes one-way audio.

A **Content-Length that does not match the body** - the classic mark of a middlebox that rewrote a body and did not
re-count it - is reported per message by :func:`tnt.sipcalls.sip_headers` rather than here, because it needs the
raw bytes the header view already has.

Two-sided captures beat all of this - see :mod:`tnt.sipflow`, where the same message from both sides is compared
directly - but two-sided captures are rare and these tells need only one.

Nothing here is written to disk.  The active check sends SIP to the address the user typed and nowhere else.
"""

from __future__ import annotations

import copy
import ipaddress
import logging
import threading
import os
import random
import socket
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import sipcalls

log = logging.getLogger(__name__)

__all__ = ["PROBE_KEYS", "ALG_KEYS", "FINDING_KEYS", "CHANGE_KEYS", "TELL_KEYS", "VERDICTS", "FINDING_IDS",
           "SIP_PORT", "TLS_PORTS", "ECHOED_HEADERS", "DEFAULT_TIMEOUT_S", "MAX_RESPONSE",
           "AlgUnavailable", "AlgChecker", "build_options", "compare_echo", "passive_tells", "validate_target",
           "NATTED_RANGES", "behind_nat"]

#: ``bound``: True when the probe asked for a source port and got it, False when it asked and was refused,
#: and **None when it never got that far** - a name that does not resolve fails before any bind, and
#: reporting that as False would be a port conflict this check never looked for.
PROBE_KEYS = ("port", "bound", "requested_port", "answered", "status", "reason", "elapsed_ms", "received",
              "rport", "changes", "error")
ALG_KEYS = ("ts", "host", "port", "transport", "verdict", "probes", "changes", "public", "via_srv",
            "findings", "note")
#: How the server was found when a SIP domain was given rather than a host: the domain asked, the target
#: the SRV record named, and the port it gave.
SRV_KEYS = ("domain", "host", "port", "transport")
CHANGE_KEYS = ("header", "sent", "seen")
TELL_KEYS = ("id", "call", "message", "detail", "evidence")
FINDING_KEYS = ("id", "level", "title", "detail", "advice", "evidence")

#: ``alg`` - something rewrote the message.  ``clean`` - nothing rewrote this one, which is not the same as "no
#: ALG".  ``inconclusive`` - nothing answered, so nothing is known.  ``moot`` - TLS, which cannot be rewritten.
VERDICTS = ("alg", "clean", "inconclusive", "moot")

#: The headers a response carries back exactly as the server received them, and which therefore act as a mirror.
#: ``To`` is compared by URI alone because the server legitimately adds a tag to it.
ECHOED_HEADERS = ("via", "call-id", "cseq", "from", "to")

BUSY_TEXT = "a SIP ALG check is already running"

FINDING_IDS: Tuple[str, ...] = (
    "alg.rewritten", "alg.port", "alg.clean", "alg.silent", "alg.dns", "alg.srv", "alg.tls", "alg.contact",
    "alg.sdp", "alg.length",
)

SIP_PORT = 5060
TLS_PORTS = (5061, 5161)
DEFAULT_TIMEOUT_S = 4.0
MAX_RESPONSE = 65535
MAX_HOST = 253
#: Ports the probe asks for, in order.  5060 first because that is the one an ALG watches; the second is whatever
#: the OS hands out, which almost nothing inspects.
PROBE_PORTS = (5060, 0)


class AlgUnavailable(RuntimeError):
    """The check could not run at all; the message says why in words a person can act on."""


def validate_target(host: Any, port: Any = None) -> Tuple[str, int]:
    """``(host, port)`` for the SIP server to ask, or ``ValueError`` with the text the page shows."""
    text = str(host or "").strip().rstrip(".")
    if text.startswith("sip:") or text.startswith("sips:"):
        text = text.split(":", 1)[1]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    if text.startswith("[") and "]" in text:                       # [2001:db8::1]:5060
        literal, _, tail = text.partition("]")
        text, port = literal[1:], (tail.lstrip(":") or port)
    elif text.count(":") == 1:
        text, _, tail = text.partition(":")
        port = tail or port
    if not text:
        raise ValueError("give the address of the SIP server to test - the PBX, SBC or registrar")
    if len(text) > MAX_HOST:
        raise ValueError("that address is too long to be a host name")
    try:
        text.encode("ascii")
    except UnicodeEncodeError:
        try:
            text = text.encode("idna").decode("ascii")
        except Exception as exc:                                   # noqa: BLE001
            raise ValueError("that address is not a host name this can look up") from exc
    if any(ch.isspace() for ch in text) or "/" in text:
        raise ValueError("that does not look like a host name or an IP address")
    number = SIP_PORT if port in (None, "") else port
    if isinstance(number, bool) or (isinstance(number, float) and number != int(number)):
        raise ValueError("the port must be a whole number from 1 to 65535")
    try:
        number = int(number)
    except (TypeError, ValueError):
        raise ValueError("the port must be a whole number from 1 to 65535") from None
    if not 1 <= number <= 65535:
        raise ValueError("the port must be a whole number from 1 to 65535")
    return text, number


# --------------------------------------------------------------------------- the request, and the mirror
def _token(length: int = 10) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(alphabet) for _ in range(length))


def build_options(host: str, port: int, local_ip: str, local_port: int, *, tag: Optional[str] = None,
                  branch: Optional[str] = None, call_id: Optional[str] = None) -> Tuple[bytes, Dict[str, str]]:
    """One ``OPTIONS`` and the values the response has to give back untouched.

    ``OPTIONS`` is the right request for this: every SIP server answers it, it asks the far end only what it can do,
    and it rings nobody.  The markers are random per probe so a stale response from an earlier one cannot be
    mistaken for this one's."""
    tag = tag or _token(8)
    branch = branch or ("z9hG4bK" + _token(12))
    call_id = call_id or (_token(16) + "@" + local_ip)
    via = f"SIP/2.0/UDP {local_ip}:{local_port};branch={branch};rport"
    contact = f"<sip:tnt@{local_ip}:{local_port}>"
    from_header = f"<sip:tnt@{local_ip}>;tag={tag}"
    to_header = f"<sip:{host}>"
    message = (
        f"OPTIONS sip:{host}:{port} SIP/2.0\r\n"
        f"Via: {via}\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: {from_header}\r\n"
        f"To: {to_header}\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 OPTIONS\r\n"
        f"Contact: {contact}\r\n"
        f"User-Agent: TNT/SIP-ALG-check\r\n"
        f"Accept: application/sdp\r\n"
        f"Content-Length: 0\r\n\r\n"
    )
    sent = {"via": via, "call-id": call_id, "cseq": "1 OPTIONS", "from": from_header, "to": to_header,
            "contact": contact, "branch": branch}
    return message.encode("ascii", "replace"), sent


def _via_parts(value: str) -> Tuple[str, Dict[str, str]]:
    """A Via split into the part a proxy must not touch and the parameters it may add to."""
    head, _, tail = value.partition(";")
    params: Dict[str, str] = {}
    for item in tail.split(";"):
        if not item.strip():
            continue
        name, _, argument = item.partition("=")
        params[name.strip().lower()] = argument.strip()
    return " ".join(head.split()), params


def _uri_only(value: str) -> str:
    """A From/To value with its parameters dropped, so a tag the server added is not read as a rewrite."""
    return value.split(";", 1)[0].strip()


def compare_echo(sent: Dict[str, str], view: Dict[str, Any]) -> List[Dict[str, Any]]:
    """What the server gave back that is not what was sent: every entry is proof of rewriting in transit.

    A response repeats Via, Call-ID, CSeq and From exactly as received - they are how it finds its way home - so a
    difference cannot be the server being creative.  The two legal additions are excluded: ``received``/``rport``
    on the top Via, and a tag on ``To``."""
    headers = {}
    for header in view.get("headers") or []:
        headers.setdefault(str(header.get("name") or "").lower(), str(header.get("value") or ""))
    out: List[Dict[str, Any]] = []

    got_via = headers.get("via")
    if got_via is not None:
        want_head, want_params = _via_parts(sent["via"])
        got_head, got_params = _via_parts(got_via)
        if want_head != got_head:
            out.append({"header": "Via sent-by", "sent": want_head, "seen": got_head})
        if want_params.get("branch") and got_params.get("branch") != want_params.get("branch"):
            out.append({"header": "Via branch", "sent": want_params.get("branch"),
                        "seen": got_params.get("branch")})
    for name, key in (("call-id", "call-id"), ("cseq", "cseq")):
        got = headers.get(name)
        if got is not None and got.strip() != sent[key].strip():
            out.append({"header": name.title(), "sent": sent[key], "seen": got.strip()})
    for name in ("from", "to"):
        got = headers.get(name)
        if got is not None and _uri_only(got) != _uri_only(sent[name]):
            out.append({"header": name.title(), "sent": _uri_only(sent[name]), "seen": _uri_only(got)})
    return out


# --------------------------------------------------------------------------- the active check
def _finding(ident: str, level: str, title: str, detail: Optional[str] = None, advice: Optional[str] = None,
             evidence: Any = None) -> Dict[str, Any]:
    return {"id": ident, "level": level, "title": title, "detail": detail, "advice": advice, "evidence": evidence}


class AlgChecker:
    """Sends an OPTIONS to one SIP server from two source ports and reads what comes back.

    Module-level seams tests monkeypatch: ``_open_socket`` and ``_now``."""

    def __init__(self, *, timeout_s: float = DEFAULT_TIMEOUT_S, clock: Any = None, lookup: Any = None) -> None:
        self._timeout = max(0.5, min(30.0, float(timeout_s)))
        self._clock = clock or time.time
        self._lookup = lookup            # the SRV resolver; tnt.nettools.dns_lookup when not given
        self._lock = threading.Lock()
        self._running = False
        self._last: Optional[Dict[str, Any]] = None

    # -- state, so a button can drive it ---------------------------------------------------------
    def last(self) -> Optional[Dict[str, Any]]:
        """The last result (a copy), or None."""
        with self._lock:
            return copy.deepcopy(self._last)

    def running(self) -> bool:
        return self._running

    def on_network_change(self, data: Any = None) -> None:
        """``net.changed``: the kept result described the network this PC was on, not the one it is on now."""
        with self._lock:
            self._last = None

    def check(self, host: Any, port: Any = None, *, ports: Iterable[int] = PROBE_PORTS) -> Dict[str, Any]:
        """Run the check and return the ALG dict.  Raises ``ValueError`` for a bad address.

        One at a time: the first probe asks for source port 5060 and two runs would fight over the bind, which
        would read as the port being unavailable rather than as the button having been pressed twice."""
        with self._lock:
            if self._running:
                raise RuntimeError(BUSY_TEXT)
            self._running = True
        try:
            result = self._check(host, port, ports)
        finally:
            with self._lock:
                self._running = False
        with self._lock:
            self._last = copy.deepcopy(result)
        return result

    def _check(self, host: Any, port: Any, ports: Iterable[int]) -> Dict[str, Any]:
        target, number = validate_target(host, port)
        if os.name != "nt":
            log.debug("the SIP ALG check is running off Windows; nothing here depends on it")
        if number in TLS_PORTS:
            return self._moot(target, number)
        # what a phone would do with this name: ask for the SRV record before trying to resolve it directly.
        # The test is the *standard* port rather than "no port was given": the API fills the configured
        # sip.port in before this ever sees it, so "no port" never arrives here. 5060 means nothing special was
        # asked for; a tech who typed 5065 meant that exact server and is taken at their word.
        via_srv = None
        if number == SIP_PORT and not _is_address(target):
            for srv_host, srv_port, prefix in srv_targets(target, self._lookup):
                via_srv = {"domain": target, "host": srv_host, "port": srv_port,
                           "transport": "udp" if prefix == "_sip._udp." else prefix.strip("._").split(".")[-1]}
                target, number = srv_host, srv_port
                break
        probes = [self._probe(target, number, wanted) for wanted in ports]
        return self._verdict(target, number, probes, via_srv)

    def _moot(self, host: str, port: int) -> Dict[str, Any]:
        note = ("SIP over TLS is encrypted end to end: nothing in the path can read it, so nothing in the path can "
                "rewrite it. An ALG cannot apply here.")
        return {"ts": float(self._clock()), "host": host, "port": port, "transport": "tls", "verdict": "moot",
                "probes": [], "changes": [], "public": None, "via_srv": None,
                "findings": [_finding("alg.tls", "good", "This port is SIP over TLS", note,
                                      "If some devices at this site use TLS and others use UDP 5060, only the "
                                      "plain ones can be interfered with - test one of those.")],
                "note": note}

    def _probe(self, host: str, port: int, wanted_port: int) -> Dict[str, Any]:
        """One OPTIONS from one source port.  Never raises: a probe that cannot run says why and the other still
        runs, because the comparison between the two is most of the value."""
        row: Dict[str, Any] = {"port": None, "bound": None, "requested_port": wanted_port, "answered": False,
                               "status": None, "reason": None, "elapsed_ms": None, "received": None,
                               "rport": None, "changes": [], "error": None}
        sock = None
        try:
            sock, local_ip, local_port = _open_socket(host, port, wanted_port)
            row["port"] = local_port
            row["bound"] = wanted_port in (0, local_port)
            message, sent = build_options(host, port, local_ip, local_port)
            started = float(self._clock())
            sock.sendto(message, (host, port))
            sock.settimeout(self._timeout)
            deadline = started + self._timeout
            while True:
                try:
                    data, _peer = sock.recvfrom(MAX_RESPONSE)
                except socket.timeout:
                    break
                except OSError as exc:
                    row["error"] = _reason(exc)
                    break
                view = sipcalls.sip_headers(data)
                if view is None or view.get("kind") != "response":
                    if float(self._clock()) >= deadline:
                        break
                    continue
                row["answered"] = True
                row["elapsed_ms"] = round((float(self._clock()) - started) * 1000.0, 1)
                row["status"], row["reason"] = view.get("status"), view.get("reason")
                row["changes"] = compare_echo(sent, view)
                via = next((h["value"] for h in view["headers"] if h["name"] == "via"), "")
                _head, params = _via_parts(via)
                row["received"], row["rport"] = params.get("received"), params.get("rport")
                break
        except AlgUnavailable:
            raise
        except OSError as exc:
            row["error"] = _reason(exc)
        except Exception as exc:                                   # noqa: BLE001
            row["error"] = str(exc) or "the probe could not be sent"
            log.debug("the SIP ALG probe failed", exc_info=True)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        return row

    def _verdict(self, host: str, port: int, probes: List[Dict[str, Any]],
                 via_srv: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        answered = [probe for probe in probes if probe["answered"]]
        changed = [probe for probe in answered if probe["changes"]]
        every_change: List[Dict[str, Any]] = []
        for probe in changed:
            every_change.extend(probe["changes"])
        findings: List[Dict[str, Any]] = []
        public = next((probe["received"] for probe in answered if probe.get("received")), None)

        if not answered and _name_failed(probes):
            # nothing was sent at all: the name did not resolve, so there is no network result to interpret
            verdict = "inconclusive"
            findings.append(_finding(
                "alg.dns", "warn", f"{host} does not resolve from this PC",
                "The name could not be turned into an address, so nothing was sent and nothing was measured. "
                "This says where the name is looked up, not anything about SIP.",
                "Check the spelling, and whether this name only resolves on the customer's own network - a PBX "
                "behind a VPN or on an internal DNS zone will not resolve from here. The Tools page's DNS lookup "
                "asks a server directly, which says which of the two it is."))
        elif not answered:
            verdict = "inconclusive"
            findings.append(_finding(
                "alg.silent", "warn", "Nothing answered",
                f"No SIP response came back from {host}:{port} within {self._timeout:g} s"
                + (f" ({probes[0]['error']})" if probes and probes[0].get("error") else "")
                + ". That is not a clean result: with no reply there is nothing to compare.",
                "Check the address and that this PC is allowed to reach it on that port. A PBX that does not answer "
                "OPTIONS is also possible - try a registrar or SBC that does."))
        elif changed:
            verdict = "alg"
            fields = sorted({change["header"] for change in every_change})
            findings.append(_finding(
                "alg.rewritten", "bad", "Something on the path is rewriting SIP",
                f"The reply came back with {', '.join(fields)} different from what was sent. A SIP response repeats "
                "those headers exactly as the server received them - they are how it finds its way back - so a "
                "difference cannot be the server being creative. Something between this PC and "
                f"{host} edited the packet.",
                "This is a SIP ALG, an SBC or a firewall doing SIP inspection. On a router it is usually a tick box "
                "called SIP ALG or SIP Transformations: turn it off, reboot the phones, and test again.",
                every_change[:12]))
            on_5060 = next((p for p in changed if p["port"] == SIP_PORT), None)
            clean_high = next((p for p in answered if p["port"] != SIP_PORT and not p["changes"]), None)
            if on_5060 is not None and clean_high is not None:
                findings.append(_finding(
                    "alg.port", "bad", "It only happens on port 5060",
                    f"The same request from port {clean_high['port']} came back untouched. ALGs watch 5060 and "
                    "ignore everything else, which is what this looks like.",
                    "Until the ALG is off, moving the phones and the trunk to another port - 5065 is the usual "
                    "choice - sidesteps it entirely."))
        else:
            verdict = "clean"
            ports_used = ", ".join(str(probe["port"]) for probe in answered)
            findings.append(_finding(
                "alg.clean", "good", "Nothing rewrote this request",
                f"{host} answered from source port(s) {ports_used} and every header came back exactly as sent.",
                "That clears this path for this kind of request. It is not proof there is no ALG: some only engage "
                "on INVITE or REGISTER, or once a call is up. If calls still misbehave, capture a real one and "
                "look at it on the SIP page."))
        # only when the bind was really refused. `bound` is None when the probe failed before it got there
        # (a name that does not resolve), and calling that a port conflict would be a cause this never measured.
        if any(probe["requested_port"] == SIP_PORT and probe["bound"] is False for probe in probes):
            findings.append(_finding(
                "alg.port", "info", "Port 5060 could not be used for the test",
                "The probe asked for UDP 5060 - the port an ALG actually watches - and the bind was refused, so "
                "it went out from another port. Something else on this PC is using 5060, most likely a softphone.",
                "Close the softphone and run it again for a result that reflects what a phone would see."))
        note = None if answered else "no reply"
        if via_srv:
            findings.append(_finding(
                "alg.srv", "info", f"{via_srv['domain']} is a SIP domain, not a host",
                f"It publishes an SRV record, so this went to {via_srv['host']}:{via_srv['port']} - the server a "
                "phone configured with that domain would find and talk to. The answer belongs to that server.",
                None, {"domain": via_srv["domain"], "host": via_srv["host"], "port": via_srv["port"]}))
        return {"ts": float(self._clock()), "host": host, "port": port, "transport": "udp", "verdict": verdict,
                "probes": probes, "changes": every_change, "public": public, "via_srv": via_srv,
                "findings": sorted(findings, key=lambda f: ("bad", "warn", "info", "good").index(f["level"])),
                "note": note}


#: What a name that will not resolve looks like, whatever the OS calls it.
_DNS_ERRORS = ("getaddrinfo", "name or service not known", "no such host", "name does not resolve",
               "nodename nor servname", "temporary failure in name resolution", "unknown host")


def _name_failed(probes: Iterable[Dict[str, Any]]) -> bool:
    """Whether every probe failed because the host name would not resolve.

    Worth separating: nothing was sent, so nothing about the path was measured, and the fix is a DNS one rather
    than anything to do with SIP."""
    rows = [probe for probe in probes or []]
    if not rows:
        return False
    return all(any(mark in str(probe.get("error") or "").lower() for mark in _DNS_ERRORS) for probe in rows)


#: The SRV names a SIP client looks up, in the order RFC 3263 tries them.  UDP first because that is what this
#: check speaks; a domain that only publishes TCP or TLS is reported rather than probed over the wrong transport.
SRV_PREFIXES = ("_sip._udp.", "_sip._tcp.")


def srv_targets(domain: str, lookup: Any = None) -> List[Tuple[str, int, str]]:
    """``(host, port, prefix)`` for *domain*'s SIP SRV records, best first, or ``[]`` when it publishes none.

    Sorted the way RFC 2782 says to pick: lowest priority first, and a higher weight ahead of a lower one within
    the same priority.  A malformed record is skipped rather than allowed to sink the lookup - one bad row in a
    zone should not stop the other target being tried."""
    if lookup is None:
        from . import nettools

        lookup = nettools.dns_lookup
    out: List[Tuple[int, int, str, int, str]] = []
    for prefix in SRV_PREFIXES:
        try:
            answer = lookup(prefix + domain, record_type="SRV")
        except Exception:               # noqa: BLE001 - no SRV is a normal answer, and so is a broken resolver
            log.debug("the SRV lookup for %s%s failed", prefix, domain, exc_info=True)
            continue
        if not isinstance(answer, dict) or not answer.get("ok"):
            continue
        for record in answer.get("records") or []:
            if str(record.get("type") or "").upper() != "SRV":
                continue
            parts = str(record.get("value") or "").split()
            if len(parts) != 4:
                continue
            try:
                priority, weight, port = int(parts[0]), int(parts[1]), int(parts[2])
            except ValueError:
                continue
            target = parts[3].rstrip(".")
            if not target or target == "." or not 1 <= port <= 65535:
                continue               # "." is the RFC 2782 way of saying the service is not offered here
            out.append((priority, -weight, target, port, prefix))
        if out:
            break                      # UDP answered: do not mix transports in one result
    out.sort()
    return [(target, port, prefix) for _p, _w, target, port, prefix in out]


def _is_address(text: str) -> bool:
    """Whether *text* is already an IP literal, which has no SRV record to look up."""
    try:
        ipaddress.ip_address(str(text).strip().strip("[]"))
        return True
    except ValueError:
        return False


def _reason(exc: BaseException) -> str:
    """A socket failure in words, without leaking an address."""
    name = getattr(exc, "strerror", None) or str(exc)
    return str(name).strip() or type(exc).__name__


def _open_socket(host: str, port: int, wanted_port: int) -> Tuple[Any, str, int]:
    """A UDP socket bound to *wanted_port* where that is possible, and the local address it will send from.

    5060 is outside TNT's own port block and a softphone on this PC will already have it, so a refusal is expected
    and handled: the socket falls back to an ephemeral port and the caller reports which was really used, because
    the answer depends on it."""
    family = socket.AF_INET
    try:
        if isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address):
            family = socket.AF_INET6
    except ValueError:
        pass
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        if wanted_port:
            try:
                sock.bind(("", wanted_port))
            except OSError:
                pass                                # taken: the ephemeral bind below still gives a usable probe
        sock.connect((host, port))                  # so getsockname() reports the address this route really uses
        local_ip, local_port = sock.getsockname()[:2]
        sock.close()
        sock = socket.socket(family, socket.SOCK_DGRAM)
        if wanted_port:
            try:
                sock.bind(("", wanted_port))
                local_port = wanted_port
            except OSError:
                sock.bind(("", 0))
                local_port = sock.getsockname()[1]
        else:
            sock.bind(("", 0))
            local_port = sock.getsockname()[1]
        return sock, str(local_ip), int(local_port)
    except OSError:
        sock.close()
        raise


def _now() -> float:
    return time.time()


# --------------------------------------------------------------------------- the passive check
#: The ranges a device sits behind NAT in.  Deliberately not ``ipaddress.is_private``: that also counts the
#: documentation ranges, loopback and link-local, none of which is the thing being looked for, and it would make
#: 203.0.113.9 - a stand-in for a public address everywhere in this codebase - read as private.
NATTED_RANGES = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
_NATTED = tuple(ipaddress.ip_network(text) for text in NATTED_RANGES)


def behind_nat(address: Any) -> Optional[bool]:
    """True when an address is one a device would be NATted from, False when it is not, None when it is not an
    address at all."""
    try:
        value = ipaddress.ip_address(str(address))
    except ValueError:
        return None
    return any(value in network for network in _NATTED if network.version == value.version)


def passive_tells(calls: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The marks an ALG leaves that one capture can show, without sending anything.

    Two-sided captures beat this - :mod:`tnt.sipflow` compares the same message from both sides and needs no
    inference at all - but a tech usually has one capture, and these need only one:

    * a device on a private address whose own Contact carries a public one.  A phone writes its own Contact; it
      does not know the public address unless something told it, and an ALG rewriting the Contact is the usual
      reason it is there;
    * an SDP connection line that is not the sender's address, which is the rewrite that strands the audio.

    Each tell names the call and the message it came from so the page can point at the row."""
    out: List[Dict[str, Any]] = []
    for call in calls or []:
        for message in call.get("ladder") or call.get("messages") or []:
            src = str(message.get("src") or "").rsplit(":", 1)[0]
            contact = message.get("contact")
            if not contact or not src:
                continue
            host = _contact_host(contact)
            if host is None or host == src:
                continue
            sender_natted, contact_natted = behind_nat(src), behind_nat(host)
            if sender_natted is True and contact_natted is False:
                out.append({
                    "id": "alg.contact", "call": call.get("id"),
                    "message": message.get("label") or message.get("method"),
                    "detail": f"{src} is behind NAT but its Contact says {host}, which is not. A phone writes its "
                              "own Contact and does not know the address on the other side of the NAT unless "
                              "something put it there.",
                    "evidence": {"src": src, "contact": contact}})
    out.extend(_sdp_tells(calls))
    return out


def _sdp_tells(calls: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """An SDP connection line that is not the sender's own address.

    ``c=`` is where the sender tells the far end to send the audio.  A phone behind NAT writes its own private
    address there; if it says something else, something else wrote it - and that is precisely the rewrite that
    strands the audio, because the far end then sends RTP to an address with no pinhole open on it."""
    out: List[Dict[str, Any]] = []
    for call in calls or []:
        for message in call.get("ladder") or call.get("messages") or []:
            where = message.get("sdp_c")
            src = str(message.get("src") or "").rsplit(":", 1)[0]
            if not where or not src or str(where) == src:
                continue
            sender_natted, target_natted = behind_nat(src), behind_nat(where)
            if sender_natted is True and target_natted is False:
                out.append({
                    "id": "alg.sdp", "call": call.get("id"),
                    "message": message.get("label") or message.get("method"),
                    "detail": f"{src} asked for its audio at {where}, which is not its own address. That is the "
                              "rewrite that causes one-way audio: the far end sends RTP where it was told, and "
                              "nothing is listening there.",
                    "evidence": {"src": src, "sdp_c": where}})
    return out


def _contact_host(contact: Any) -> Optional[str]:
    text = str(contact or "")
    if "<" in text:
        text = text.split("<", 1)[1].split(">", 1)[0]
    text = text.split(";", 1)[0]
    if ":" in text and text.split(":", 1)[0] in ("sip", "sips"):
        text = text.split(":", 1)[1]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    if text.startswith("[") and "]" in text:
        return text[1:text.index("]")]
    return text.split(":", 1)[0].strip() or None
