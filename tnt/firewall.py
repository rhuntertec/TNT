"""Windows Firewall *program* rules through ``netsh advfirewall`` (shared plumbing).

Windows Firewall blocks inbound traffic to the installed service by default, so every
component that listens for LAN traffic (the DHCP server tool on UDP 67/68, the LAN peer
beacon on UDP 7132, the LAN throughput server on TCP 7133) needs an inbound-allow rule for
the service's own program path.  This module owns the netsh conventions those components
share so they are written once:

* ``netsh.exe`` is always taken from ``%SystemRoot%\\System32`` (never PATH or a setting:
  the service runs as LocalSystem and must only execute admin-controlled binaries);
* argv list (no shell), ``CREATE_NO_WINDOW``, ``stdin=DEVNULL``, a timeout, and the OEM
  code-page decoding of ``tnt.arp._decode_console`` (netsh writes cp437/cp850... like arp);
* :func:`ensure_rule` is idempotent: ``show rule name=<name> verbose`` first; missing ->
  ``add rule``; present for another program path (dev python vs. the installed exe),
  another port list (an older build), another protocol or, when a remote scope is asked
  for (``remote_ip="localsubnet"``, the TFTP server), another remote scope ->
  ``delete rule`` + ``add rule``.
  A rule that matches but is switched off or set to Block lets nothing in, so it is not
  "present": it is switched back on with ``set rule name=<name> dir=in new enable=yes
  action=allow`` (idempotent, locale-independent), and replaced when that fails.  The
  ``Enabled``/``Action`` values are localised too (Ja/Nein, Zulassen/Blockieren), so only
  an English ``Enabled: Yes`` + ``Action: Allow`` is trusted without the ``set``; an English
  ``No``/``Block`` is logged as a warning naming the rule.
  ``show rule`` output has *localised* labels, so the program path and the port list are
  recognised by their *shape* (a ``X:\\`` path, a bare comma-separated number list) rather
  than by label, and the remote scope by its value (``LocalSubnet`` is a keyword, not a label).
* Nothing here raises: every function returns ``(ok, error)`` or ``(rc, output)``.

Injectable seam: ``runner`` (a ``subprocess.run`` stand-in receiving the same keyword
arguments) so tests never run the real netsh.
"""
from __future__ import annotations

import importlib
import logging
import os
import subprocess
import sys
from typing import Any, Callable, Iterable, List, Optional, Sequence, Set, Tuple, Union

log = logging.getLogger(__name__)

__all__ = ["NETSH_TIMEOUT_S", "PROTOCOLS", "netsh_exe", "run_netsh", "normalize_ports", "ensure_rule", "delete_rule"]

NETSH_TIMEOUT_S = 20.0
PROTOCOLS = ("tcp", "udp")
_CREATE_NO_WINDOW: int = getattr(subprocess, "CREATE_NO_WINDOW", 0)

PortSpec = Union[int, str, Iterable[int]]


def _short(text: Any, limit: int = 120) -> str:
    s = str(text).strip().replace("\r", " ").replace("\n", " ")
    return s if len(s) <= limit else s[:limit] + "..."


# --- netsh plumbing -------------------------------------------------------------------------
def netsh_exe() -> str:
    """``netsh.exe`` from ``%SystemRoot%\\System32``; the bare name only when that file is
    missing (a non-Windows test box), never a path from PATH or a setting."""
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    cand = os.path.join(root, "System32", "netsh.exe")
    return cand if os.path.isfile(cand) else "netsh"


def _decode_console(raw: Any) -> str:
    """netsh writes the OEM code page like arp/sc; reuse the tolerant decoder (lazily
    imported so a fake ``tnt.arp`` in ``sys.modules`` is honoured)."""
    if isinstance(raw, str):
        return raw
    if not raw:
        return ""
    try:
        arp = importlib.import_module("tnt.arp")
        return arp._decode_console(bytes(raw))
    except Exception:  # noqa: BLE001
        return bytes(raw).decode("utf-8", errors="replace")


def run_netsh(args: Sequence[str], runner: Optional[Callable[..., Any]] = None,
              timeout_s: float = NETSH_TIMEOUT_S) -> Tuple[int, str]:
    """Run ``netsh <args>`` hidden; ``(returncode, combined output)``.  Never raises: launch
    failures come back as a non-zero code with the reason as the output."""
    argv = [netsh_exe(), *[str(a) for a in args]]
    run = runner or subprocess.run
    log.debug("running %s", subprocess.list2cmdline(argv))
    try:
        proc = run(argv, capture_output=True, timeout=timeout_s, check=False, stdin=subprocess.DEVNULL,
                   creationflags=_CREATE_NO_WINDOW)
    except FileNotFoundError:
        return 9009, "netsh.exe was not found"
    except subprocess.TimeoutExpired:
        return 1460, f"netsh timed out after {timeout_s:.0f} s"
    except OSError as exc:
        return 1, f"could not run netsh: {exc}"
    except Exception as exc:  # noqa: BLE001 - a broken runner seam must not escape
        return 1, f"netsh failed: {exc}"
    out = _decode_console(getattr(proc, "stdout", b"")) + _decode_console(getattr(proc, "stderr", b""))
    try:
        rc = int(getattr(proc, "returncode", 1))
    except (TypeError, ValueError):
        rc = 1
    return rc, out.strip()


# --- parsing "show rule ... verbose" -------------------------------------------------------
def _same_path(a: str, b: str) -> bool:
    try:
        return os.path.normcase(os.path.normpath(a)) == os.path.normcase(os.path.normpath(b))
    except (TypeError, ValueError):
        return False


def _values(output: str) -> List[str]:
    """The value part of every ``Label: value`` line (labels are localised, values are not)."""
    vals: List[str] = []
    for line in (output or "").splitlines():
        if ":" not in line:
            continue
        vals.append(line.split(":", 1)[1].strip())
    return vals


def _rule_programs(output: str) -> List[str]:
    """Program paths listed in ``show rule ... verbose`` output: every value that looks like
    a Windows path (``X:\\...``)."""
    return [v for v in _values(output) if len(v) > 3 and v[1:3] == ":\\"]


def _rule_ports(output: str) -> Set[int]:
    """Local ports listed in ``show rule ... verbose`` output: the only value that is a bare
    comma-separated number list is ``LocalPort`` (``RemotePort`` is ``Any`` for our rules)."""
    ports: Set[int] = set()
    for value in _values(output):
        parts = [p.strip() for p in value.split(",")]
        if parts and all(p.isdigit() for p in parts):
            ports.update(int(p) for p in parts)
    return ports


def _rule_protocol(output: str) -> Optional[str]:
    """``"tcp"``/``"udp"`` when the output names one (the value is a protocol name, not
    localised); ``None`` when it cannot be told."""
    for value in _values(output):
        low = value.lower()
        if low in PROTOCOLS:
            return low
    return None


def _rule_switched_on(output: str) -> Optional[bool]:
    """Whether ``show rule ... verbose`` output says the rule is enabled and allows: ``True`` for an English
    ``Enabled: Yes`` and ``Action: Allow`` on every rule listed, ``False`` when an English line says ``No`` or
    ``Block``, ``None`` when it cannot be told (a localised Windows translates labels and values alike)."""
    enabled: List[str] = []
    action: List[str] = []
    for line in (output or "").splitlines():
        if ":" not in line:
            continue
        label, value = (part.strip().casefold() for part in line.split(":", 1))
        if label == "enabled":
            enabled.append(value)
        elif label == "action":
            action.append(value)
    if any(v == "no" for v in enabled) or any(v == "block" for v in action):
        return False
    if enabled and action and all(v == "yes" for v in enabled) and all(v == "allow" for v in action):
        return True
    return None


def _rule_has_value(output: str, wanted: str) -> bool:
    """True when some value in ``show rule ... verbose`` output is exactly *wanted*, case-insensitively
    (``RemoteIP: LocalSubnet`` for ``remoteip=localsubnet``)."""
    want = str(wanted or "").strip().casefold()
    return bool(want) and any(v.casefold() == want for v in _values(output))


def normalize_ports(ports: PortSpec) -> Tuple[List[int], str]:
    """``67`` / ``"67,68"`` / ``[67, 68]`` -> ``([67, 68], "67,68")`` (order kept, duplicates
    dropped).  ``ValueError`` for an empty list or a port outside 1..65535."""
    if isinstance(ports, str):
        items: List[Any] = [p.strip() for p in ports.split(",") if p.strip()]
    elif isinstance(ports, int):
        items = [ports]
    else:
        items = list(ports or [])
    out: List[int] = []
    for p in items:
        try:
            n = int(p)
        except (TypeError, ValueError):
            raise ValueError(f"invalid port {p!r}") from None
        if not 1 <= n <= 65535:
            raise ValueError(f"port {n} out of range 1-65535")
        if n not in out:
            out.append(n)
    if not out:
        raise ValueError("no ports given for the firewall rule")
    return out, ",".join(str(n) for n in out)


# --- rules ----------------------------------------------------------------------------------
def ensure_rule(name: str, exe_path: Optional[str], protocol: str, ports: PortSpec,
                runner: Optional[Callable[..., Any]] = None, *,
                remote_ip: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """Make sure the inbound-allow *program* rule *name* (``protocol`` ``tcp``/``udp``, local
    *ports*) exists for *exe_path* (the running interpreter when ``None``).

    ``show rule name=<name> verbose`` first; missing -> ``add rule``; present for another
    program, port list or protocol -> ``delete rule`` + ``add rule``; present but switched off
    or set to Block (or on a localised Windows, where that cannot be read) -> ``set rule ...
    new enable=yes action=allow``, and delete + add when that fails.  Idempotent; returns
    ``(ok, error)`` and never raises.

    *remote_ip* (a netsh ``remoteip`` value such as ``"localsubnet"``) scopes the rule to those
    remote addresses: ``remoteip=<value>`` follows ``localport=`` in the ``add rule`` argv, and a
    present rule counts only when ``show rule`` lists exactly that value (case-insensitive);
    otherwise it is replaced.  ``None`` keeps the argv and the check exactly as they were.
    """
    exe = str(exe_path or sys.executable or "").strip()
    if not exe:
        return False, "no program path for the firewall rule"
    rule = str(name or "").strip()
    if not rule:
        return False, "no name for the firewall rule"
    proto = str(protocol or "").strip().lower()
    if proto not in PROTOCOLS:
        return False, f"unsupported firewall protocol {protocol!r}"
    remote = str(remote_ip).strip() if remote_ip is not None else ""
    if remote and (any(ch.isspace() for ch in remote) or "=" in remote or '"' in remote):
        return False, f"invalid remote address {remote_ip!r} for the firewall rule"
    try:
        wanted, ports_text = normalize_ports(ports)
    except ValueError as exc:
        return False, str(exc)
    try:
        rc, out = run_netsh(["advfirewall", "firewall", "show", "rule", f"name={rule}", "verbose"], runner)
        if rc == 0:
            progs = _rule_programs(out)
            have_proto = _rule_protocol(out)
            if any(_same_path(p, exe) for p in progs) and set(wanted) <= _rule_ports(out) \
                    and (have_proto is None or have_proto == proto) and (not remote or _rule_has_value(out, remote)):
                state = _rule_switched_on(out)
                if state is True:
                    return True, None
                # a disabled or blocking rule lets nothing in (the server would "start" and no device would
                # get an answer); the values are localised, so when they cannot be read switch it on anyway
                if state is False:
                    log.warning("firewall rule '%s' was switched off or set to Block; switching it back on", rule)
                src, sout = run_netsh(["advfirewall", "firewall", "set", "rule", f"name={rule}", "dir=in", "new",
                                       "enable=yes", "action=allow"], runner)
                if src == 0:
                    return True, None
                if state is None:
                    # The state could not be read, so there is no proof the rule is off, and a failed 'set' on a
                    # rule that exists is nearly always a caller without elevation, which would fail the delete
                    # and add the same way (or delete it and leave none).  Keep it, as before this check existed.
                    log.warning("could not make sure the firewall rule '%s' is switched on (%s); keeping it as it is",
                                rule, _short(sout))
                    return True, None
                log.warning("could not switch the firewall rule '%s' on (%s); replacing it", rule, _short(sout))
            if progs or out:
                # a rule with our name but another program / port list / protocol / remote scope: replace it
                drc, dout = run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={rule}"], runner)
                if drc != 0:
                    log.warning("could not delete the stale firewall rule '%s': %s", rule, _short(dout))
        add = ["advfirewall", "firewall", "add", "rule", f"name={rule}", "dir=in", "action=allow",
               f"program={exe}", f"protocol={proto}", f"localport={ports_text}"]
        if remote:
            add.append(f"remoteip={remote}")
        add.append("profile=any")
        arc, aout = run_netsh(add, runner)
        if arc != 0:
            return False, f"netsh exit {arc}: {_short(aout) or 'no output'}"
        log.info("firewall rule '%s' added for %s (%s %s)", rule, exe, proto, ports_text)
        return True, None
    except Exception as exc:  # noqa: BLE001
        log.exception("ensure_rule('%s') failed", rule)
        return False, str(exc)


def delete_rule(name: str, runner: Optional[Callable[..., Any]] = None) -> Tuple[bool, Optional[str]]:
    """Remove rule *name* (uninstaller helper).  ``(ok, error)``; never raises."""
    rule = str(name or "").strip()
    if not rule:
        return False, "no name for the firewall rule"
    try:
        rc, out = run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={rule}"], runner)
        if rc == 0:
            return True, None
        return False, f"netsh exit {rc}: {_short(out) or 'no output'}"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)
