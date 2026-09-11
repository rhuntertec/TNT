"""The loopback connection owner + admin token check (``tnt/peer.py``).

The decision is a pure function of ``(user_sid, [(sid, attributes)])`` so almost everything
here runs on any platform with no real token.  One guarded test makes a real loopback
connection from the test process to itself and asserts the owner lookup finds ``os.getpid()``;
it is skipped off Windows.
"""
from __future__ import annotations

import os
import socket
import sys

import pytest

from tnt import peer

EN = peer.SE_GROUP_ENABLED
DENY = peer.SE_GROUP_USE_FOR_DENY_ONLY
ENABLED_BY_DEFAULT = 0x00000002
ADMIN = peer.ADMINISTRATORS_SID          # S-1-5-32-544
SYSTEM = peer.LOCAL_SYSTEM_SID           # S-1-5-18
USERS = "S-1-5-32-545"                   # BUILTIN\Users
A_USER = "S-1-5-21-1111111111-2222222222-3333333333-1001"


# ---------------------------------------------------------------------------
# the pure decision: token_is_admin(user_sid, groups)
# ---------------------------------------------------------------------------
def test_local_system_is_admin():
    # SYSTEM (the service's own token) is allowed by its user SID alone, no groups needed
    assert peer.token_is_admin(SYSTEM, []) is True
    assert peer.token_is_admin(SYSTEM, None) is True
    assert peer.token_is_admin(SYSTEM.lower(), [(USERS, EN)]) is True   # SID compare is case-insensitive


def test_elevated_administrator_is_admin():
    # an elevated token: Administrators is a normal enabled group
    groups = [(A_USER, EN | ENABLED_BY_DEFAULT), (USERS, EN), (ADMIN, EN | ENABLED_BY_DEFAULT)]
    assert peer.token_is_admin(A_USER, groups) is True


def test_uac_filtered_administrator_is_admin():
    # the non-elevated token of an admin account: Administrators is present but deny-only
    groups = [(A_USER, EN | ENABLED_BY_DEFAULT), (USERS, EN | ENABLED_BY_DEFAULT), (ADMIN, DENY)]
    assert peer.token_is_admin(A_USER, groups) is True


def test_standard_user_is_not_admin():
    # a standard user has no Administrators SID at all
    groups = [(A_USER, EN | ENABLED_BY_DEFAULT), (USERS, EN | ENABLED_BY_DEFAULT)]
    assert peer.token_is_admin(A_USER, groups) is False


def test_administrators_present_but_no_relevant_flag_is_not_admin():
    # neither enabled nor deny-only -> not counted (faithful to the two flags we trust)
    assert peer.token_is_admin(A_USER, [(ADMIN, 0)]) is False
    assert peer.token_is_admin(A_USER, [(ADMIN, ENABLED_BY_DEFAULT)]) is False


def test_empty_and_garbage_input_is_not_admin():
    assert peer.token_is_admin("", []) is False
    assert peer.token_is_admin(None, None) is False
    assert peer.token_is_admin(None, []) is False
    # non-pair / non-int entries must not raise, just not match
    assert peer.token_is_admin(A_USER, [42, ("only-one",), (ADMIN, None), (ADMIN, "nope")]) is False
    assert peer.token_is_admin(123, [(456, 789)]) is False
    # a genuine admin still wins even amid garbage
    assert peer.token_is_admin(A_USER, [None, (ADMIN, EN), "junk"]) is True


# ---------------------------------------------------------------------------
# reveal_allowed(): fail closed
# ---------------------------------------------------------------------------
def test_reveal_allowed_is_unknown_off_windows(monkeypatch):
    monkeypatch.setattr(peer.sys, "platform", "linux")
    assert peer.reveal_allowed(("127.0.0.1", 5000), ("127.0.0.1", 7130)) == peer.UNKNOWN


def test_reveal_allowed_needs_both_ends():
    assert peer.reveal_allowed(None, ("127.0.0.1", 7130)) == peer.UNKNOWN
    assert peer.reveal_allowed(("127.0.0.1", 5000), None) == peer.UNKNOWN


def test_owner_pid_rejects_bad_endpoints():
    assert peer._owner_pid(("not-an-ip", 1), ("127.0.0.1", 2)) is None
    assert peer._owner_pid(("127.0.0.1", "x"), ("127.0.0.1", 2)) is None
    assert peer._owner_pid((), ()) is None
    # a v4 client with a v6 server (or vice versa) is never a real pair
    assert peer._owner_pid(("127.0.0.1", 1), ("::1", 2)) is None


# ---------------------------------------------------------------------------
# the real owner lookup -- Windows only, against a loopback socket we own
# ---------------------------------------------------------------------------
@pytest.mark.skipif(sys.platform != "win32", reason="GetExtendedTcpTable is Windows only")
@pytest.mark.parametrize("family,host", [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")])
def test_real_owner_lookup_finds_this_process(family, host):
    listener = socket.socket(family, socket.SOCK_STREAM)
    try:
        listener.bind((host, 0))
    except OSError:
        pytest.skip(f"{host} is not available on this machine")
    listener.listen(1)
    addr = listener.getsockname()
    client = socket.socket(family, socket.SOCK_STREAM)
    conn = None
    try:
        client.connect((addr[0], addr[1]))
        conn, _ = listener.accept()
        peer_end = (conn.getpeername()[0], conn.getpeername()[1])   # the client's local endpoint
        local_end = (conn.getsockname()[0], conn.getsockname()[1])  # the server's own endpoint
        pid = peer._owner_pid(peer_end, local_end)
        assert pid == os.getpid()
        # the token of this process can be read, so the answer is a real allowed/denied, not unknown
        assert peer.reveal_allowed(peer_end, local_end) in (peer.ALLOWED, peer.DENIED)
    finally:
        for s in (conn, client, listener):
            if s is not None:
                s.close()


@pytest.mark.skipif(sys.platform != "win32", reason="native token read is Windows only")
def test_real_token_sids_for_this_process():
    sids = peer._token_sids(os.getpid())
    assert sids is not None
    user_sid, groups = sids
    assert user_sid and user_sid.upper().startswith("S-1-")
    assert isinstance(groups, list) and all(len(g) == 2 for g in groups)
    # a PID that cannot exist fails closed rather than raising
    assert peer._token_sids(0) is None
    assert peer._token_sids(-1) is None
