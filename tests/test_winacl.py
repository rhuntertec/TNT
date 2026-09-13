r"""Folder security (``tnt/winacl.py``) and the foundation it rests on: ``paths.captures_dir()`` /
``paths.tftp_dir()``, the ``tftp`` settings section and the 429 error code.

``tnt.winacl._set_file_security`` is the only function that changes a real DACL, and tests/conftest.py
replaces it with a recorder for the whole session, so almost everything here runs against recorders or
fake DLLs. One test applies a real SDDL, to a folder in tmp_path. It is skipped unless this process's
token has Administrators enabled (an elevated shell), and it puts back a DACL giving this user full
control, so pytest can delete the folder.
"""
from __future__ import annotations

import ctypes
import os
import re
import sys
from ctypes import POINTER, byref, c_int, c_ulong, c_void_p, c_wchar_p

import pytest

from tnt import config, paths, winacl

DACL = winacl.DACL_SECURITY_INFORMATION
PROTECTED = winacl.PROTECTED_DACL_SECURITY_INFORMATION
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
FILE_DELETE_CHILD = 0x00000040
USERS_MODIFY = 0x001301BF                # what icacls calls "M"
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_PARAMETER = 87             # what Windows answers for an SDDL it cannot parse


def _recorder(monkeypatch):
    calls = []
    monkeypatch.setattr(winacl, "_set_file_security", lambda path, sddl: calls.append((path, sddl)))
    return calls


def _real_seam():
    real = getattr(winacl._set_file_security, "original", None)
    if real is None:
        pytest.fail("tests/conftest.py no longer guards tnt.winacl._set_file_security")
    return real


# ---------------------------------------------------------------------------
# the conftest guard and the SDDL strings
# ---------------------------------------------------------------------------
def test_conftest_guard_records_instead_of_changing_a_dacl(tmp_path):
    seam = winacl._set_file_security
    assert isinstance(getattr(seam, "calls", None), list) and callable(getattr(seam, "original", None)), \
        "tests/conftest.py must replace tnt.winacl._set_file_security for the whole session"
    folder = tmp_path / "captures"
    before = len(seam.calls)
    winacl.secure_dir(folder, winacl.CAPTURES_SDDL)
    assert seam.calls[before:] == [(str(folder), winacl.CAPTURES_SDDL)]
    # the folder kept the DACL it inherited (a real protected one would lock a non-elevated test out)
    (folder / "still-writable.bin").write_bytes(b"x")
    assert (folder / "still-writable.bin").read_bytes() == b"x"


def test_the_sddl_strings():
    assert winacl.CAPTURES_SDDL == "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    assert winacl.TFTP_SDDL == "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;BU)"
    assert set(winacl.__all__) == {"CAPTURES_SDDL", "TFTP_SDDL", "secure_dir"}
    # the TFTP root: Users may change files, but never the folder's DACL or owner
    users = re.fullmatch(r"D:P\(A;OICI;FA;;;SY\)\(A;OICI;FA;;;BA\)\(A;OICI;(0x[0-9a-f]+);;;BU\)", winacl.TFTP_SDDL)
    mask = int(users.group(1), 16)
    assert mask == USERS_MODIFY and not mask & (WRITE_DAC | WRITE_OWNER | FILE_DELETE_CHILD)
    assert DACL | PROTECTED == 0x80000004


# ---------------------------------------------------------------------------
# secure_dir: check, create, apply
# ---------------------------------------------------------------------------
def test_secure_dir_creates_the_folder_and_applies_the_exact_sddl(tmp_path, monkeypatch):
    calls = _recorder(monkeypatch)
    captures = tmp_path / "data" / "captures"                 # the parent does not exist yet either
    winacl.secure_dir(captures, winacl.CAPTURES_SDDL)
    assert captures.is_dir() and calls == [(str(captures), winacl.CAPTURES_SDDL)]
    # an existing folder is secured again (a DACL somebody changed is put back); a str path works the same
    winacl.secure_dir(str(captures), winacl.CAPTURES_SDDL)
    tftp = tmp_path / "data" / "tftp"
    winacl.secure_dir(tftp, winacl.TFTP_SDDL)
    assert calls == [(str(captures), winacl.CAPTURES_SDDL), (str(captures), winacl.CAPTURES_SDDL),
                     (str(tftp), winacl.TFTP_SDDL)]
    assert tftp.is_dir()


def test_secure_dir_refuses_a_reparse_point(tmp_path, monkeypatch):
    calls = _recorder(monkeypatch)
    checked = []

    def is_link(path):
        checked.append(path)
        return True

    monkeypatch.setattr(winacl, "_is_reparse_point", is_link)
    folder = tmp_path / "captures"
    folder.mkdir()
    with pytest.raises(OSError) as exc:
        winacl.secure_dir(folder, winacl.CAPTURES_SDDL)
    assert str(exc.value) == f"{folder} is a link"
    assert checked == [str(folder)] and calls == []
    # the check comes before anything is created
    missing = tmp_path / "tftp"
    with pytest.raises(OSError, match="is a link"):
        winacl.secure_dir(missing, winacl.TFTP_SDDL)
    assert not missing.exists() and calls == []


@pytest.mark.skipif(sys.platform != "win32", reason="junctions are an NTFS feature")
def test_a_real_junction_is_a_reparse_point_and_is_refused(tmp_path, monkeypatch):
    import _winapi

    calls = _recorder(monkeypatch)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    link = tmp_path / "captures"
    _winapi.CreateJunction(str(elsewhere), str(link))        # needs no privilege, unlike a symbolic link
    try:
        assert winacl._is_reparse_point(str(link)) is True
        with pytest.raises(OSError, match="is a link"):
            winacl.secure_dir(link, winacl.CAPTURES_SDDL)
        assert calls == []
    finally:
        os.rmdir(link)                                        # removes the junction, not the folder it points at
    (tmp_path / "file.bin").write_bytes(b"x")
    assert winacl._is_reparse_point(str(elsewhere)) is False
    assert winacl._is_reparse_point(str(tmp_path / "file.bin")) is False
    assert winacl._is_reparse_point(str(tmp_path / "missing")) is False


def test_secure_dir_fails_before_the_dacl_when_the_folder_cannot_be_made(tmp_path, monkeypatch):
    calls = _recorder(monkeypatch)
    blocker = tmp_path / "captures"
    blocker.write_bytes(b"a file, not a folder")
    with pytest.raises(OSError):
        winacl.secure_dir(blocker, winacl.CAPTURES_SDDL)
    with pytest.raises(OSError):
        winacl.secure_dir(blocker / "inner", winacl.CAPTURES_SDDL)
    assert calls == []


# ---------------------------------------------------------------------------
# the seam itself, against fake DLLs
# ---------------------------------------------------------------------------
class _FakeAdvapi:
    SD = 0x5A5A0                          # the "LocalAlloc'd" descriptor the conversion hands back

    def __init__(self, convert_error=0, set_error=0):
        self.convert_error, self.set_error = convert_error, set_error
        self.converted, self.applied = [], []

    def ConvertStringSecurityDescriptorToSecurityDescriptorW(self, sddl, revision, out, size):  # noqa: N802
        self.converted.append((sddl, revision, size))
        if self.convert_error:
            ctypes.set_last_error(self.convert_error)
            return 0
        out._obj.value = self.SD          # byref(c_void_p()): write the out parameter
        return 1

    def SetFileSecurityW(self, path, info, sd):  # noqa: N802
        self.applied.append((path, info, sd.value))
        if self.set_error:
            ctypes.set_last_error(self.set_error)
            return 0
        return 1


class _FakeKernel:
    def __init__(self):
        self.freed = []

    def LocalFree(self, handle):  # noqa: N802
        self.freed.append(handle.value)


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 error codes")
def test_the_seam_applies_a_protected_dacl_frees_the_descriptor_and_raises_oserror(tmp_path, monkeypatch):
    real = _real_seam()
    folder = str(tmp_path / "captures")

    advapi, kernel = _FakeAdvapi(), _FakeKernel()
    monkeypatch.setattr(winacl, "_dll", lambda: (advapi, kernel))
    real(folder, winacl.CAPTURES_SDDL)
    assert advapi.converted == [(winacl.CAPTURES_SDDL, winacl.SDDL_REVISION_1, None)]
    assert advapi.applied == [(folder, DACL | PROTECTED, _FakeAdvapi.SD)]
    assert kernel.freed == [_FakeAdvapi.SD]

    # SetFileSecurityW refused: OSError carrying the Win32 code, and the descriptor is still freed
    advapi, kernel = _FakeAdvapi(set_error=ERROR_ACCESS_DENIED), _FakeKernel()
    monkeypatch.setattr(winacl, "_dll", lambda: (advapi, kernel))
    with pytest.raises(OSError) as exc:
        real(folder, winacl.TFTP_SDDL)
    assert isinstance(exc.value, PermissionError) and exc.value.winerror == ERROR_ACCESS_DENIED
    assert "SetFileSecurityW failed" in str(exc.value) and exc.value.filename == folder
    assert kernel.freed == [_FakeAdvapi.SD]

    # an SDDL Windows does not accept: OSError, nothing applied and nothing to free
    advapi, kernel = _FakeAdvapi(convert_error=ERROR_INVALID_PARAMETER), _FakeKernel()
    monkeypatch.setattr(winacl, "_dll", lambda: (advapi, kernel))
    with pytest.raises(OSError) as exc:
        real(folder, "D:P(garbage")
    assert exc.value.winerror == ERROR_INVALID_PARAMETER and "ConvertStringSecurityDescriptor" in str(exc.value)
    assert advapi.applied == [] and kernel.freed == []


# ---------------------------------------------------------------------------
# the one real DACL (elevated shells only)
# ---------------------------------------------------------------------------
def _own_token():
    """``(user SID, [(group SID, attributes)])`` of this process's token, or None."""
    try:
        from tnt import peer

        return peer._token_sids(os.getpid())
    except Exception:  # noqa: BLE001 - no token, no real-DACL test
        return None


def _administrators_enabled(token):
    from tnt import peer

    return bool(token) and any(str(sid).upper() == peer.ADMINISTRATORS_SID and int(attrs) & peer.SE_GROUP_ENABLED
                               for sid, attrs in token[1])


def _dacl_of(path):
    """The DACL of *path* as an SDDL string."""
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.GetFileSecurityW.argtypes = [c_wchar_p, c_ulong, c_void_p, c_ulong, POINTER(c_ulong)]
    advapi.GetFileSecurityW.restype = c_int
    advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [c_void_p, c_ulong, c_ulong,
                                                                            POINTER(c_wchar_p), POINTER(c_ulong)]
    advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = c_int
    kernel.LocalFree.argtypes = [c_void_p]
    kernel.LocalFree.restype = c_void_p
    need = c_ulong(0)
    advapi.GetFileSecurityW(str(path), DACL, None, 0, byref(need))
    buf = ctypes.create_string_buffer(max(need.value, 1))
    if not advapi.GetFileSecurityW(str(path), DACL, buf, need.value, byref(need)):
        raise ctypes.WinError(ctypes.get_last_error())
    text = c_wchar_p()
    if not advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(buf, winacl.SDDL_REVISION_1, DACL, byref(text), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return text.value
    finally:
        kernel.LocalFree(ctypes.cast(text, c_void_p))


@pytest.mark.skipif(sys.platform != "win32", reason="a Windows DACL")
def test_a_real_protected_dacl_on_a_tmp_folder(tmp_path, monkeypatch):
    token = _own_token()
    if not _administrators_enabled(token):
        pytest.skip("applying a real SDDL needs a token with Administrators enabled (an elevated shell)")
    real = _real_seam()
    user_sid = token[0]
    folder = tmp_path / "captures"
    child = folder / "child.bin"
    monkeypatch.setattr(winacl, "_set_file_security", real)       # this test only
    try:
        winacl.secure_dir(folder, winacl.CAPTURES_SDDL)
        assert _dacl_of(folder) == winacl.CAPTURES_SDDL            # protected: the user's inherited ACE is gone
        child.write_bytes(b"x")                                    # Administrators (enabled here) have full control
        inherited = _dacl_of(child)
        assert "FA;;;SY)" in inherited and "FA;;;BA)" in inherited
        assert ";;;BU)" not in inherited and user_sid not in inherited
        winacl.secure_dir(folder, winacl.TFTP_SDDL)                # securing again replaces the DACL
        assert _dacl_of(folder) == winacl.TFTP_SDDL
    finally:
        if folder.is_dir():
            real(str(folder), f"D:(A;OICI;FA;;;{user_sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
        if child.exists():
            child.unlink()


# ---------------------------------------------------------------------------
# the foundation: paths, the tftp settings section, 429
# ---------------------------------------------------------------------------
def test_captures_and_tftp_folders_follow_data_dir_and_are_not_created_at_start(data_dir):
    assert paths.captures_dir() == data_dir / "captures"
    assert paths.tftp_dir() == data_dir / "tftp"
    # ensure_dirs() (the data_dir fixture, Engine.start) leaves both alone: a folder made there inherits Users read
    paths.ensure_dirs()
    assert not paths.captures_dir().exists() and not paths.tftp_dir().exists()


def test_the_test_run_never_touches_the_installed_data_folder(tmp_path):
    """tests/conftest.py defaults TNT_DATA_DIR to a folder of the run and lists the installed TNT's %ProgramData%\\TNT at the
    start and at the end of the run, by name, size and time only (no file is opened): what it reports, and what the installed
    service's own writes look like to it (nothing)."""
    from pathlib import Path

    import conftest

    assert conftest.REAL_DATA_ROOT == Path(os.environ.get("ProgramData") or r"C:\ProgramData") / "TNT"
    assert os.path.normcase(str(paths.data_dir())) != os.path.normcase(str(conftest.REAL_DATA_ROOT))
    root = tmp_path / "TNT"
    assert conftest.data_folder_listing(root) == {"top": None, "tftp": None, "captures": None}
    (root / "tftp").mkdir(parents=True)
    (root / "logs").mkdir()
    (root / "tnt.db").write_bytes(b"x")
    before = conftest.data_folder_listing(root)
    assert before == {"top": [("logs", True), ("tftp", True), ("tnt.db", False)], "tftp": [], "captures": None}
    # the running service: its database and side files, its log
    (root / "tnt.db").write_bytes(b"xy")
    (root / "tnt.db-wal").write_bytes(b"x")
    (root / "logs" / "tnt.log").write_bytes(b"a line")
    assert conftest.data_folder_changes(before, conftest.data_folder_listing(root)) == []
    # what a test must never do: new folders, a file in the TFTP root, a changed or added file there
    (root / "captures").mkdir()
    (root / "exports").mkdir()
    (root / "tftp" / "fw").mkdir()
    (root / "tftp" / "fw" / "a.bin").write_bytes(b"secret")
    after = conftest.data_folder_listing(root)
    changes = conftest.data_folder_changes(before, after)
    assert changes == ["added captures", "added exports", "added tftp/fw", "added tftp/fw/a.bin", "created captures"]
    assert not any("secret" in change for change in changes)
    (root / "tftp" / "fw" / "a.bin").write_bytes(b"secret, longer")
    (root / "tftp" / "fw" / "b.bin").write_bytes(b"")
    assert conftest.data_folder_changes(after, conftest.data_folder_listing(root)) == ["added tftp/fw/b.bin", "changed tftp/fw/a.bin"]


def _tftp(**section):
    return config.validate({"tftp": section})["tftp"]


def test_config_tftp_defaults_clamps_and_adapter_text(data_dir):
    assert config.DEFAULTS["tftp"] == {"adapter": "", "max_upload_mb": 4096}
    assert config.validate({})["tftp"] == config.DEFAULTS["tftp"]      # the defaults are a fixed point
    assert _tftp(max_upload_mb=0)["max_upload_mb"] == 1
    assert _tftp(max_upload_mb=10 ** 6)["max_upload_mb"] == 65536
    assert _tftp(max_upload_mb=512.9)["max_upload_mb"] == 512
    for bad in ("big", True, None, float("nan")):
        assert _tftp(max_upload_mb=bad)["max_upload_mb"] == 4096, bad
    assert _tftp(adapter="  Ethernet  ")["adapter"] == "Ethernet"
    assert _tftp(adapter=None)["adapter"] == "" and _tftp(adapter=7)["adapter"] == "7"
    c = config.Config().load()
    assert c.section("tftp") == {"adapter": "", "max_upload_mb": 4096}
    assert c.update({"tftp": {"adapter": "Ethernet", "max_upload_mb": 100}}) == {"tftp.adapter", "tftp.max_upload_mb"}
    assert config.Config().load().section("tftp") == {"adapter": "Ethernet", "max_upload_mb": 100}


def test_api_error_429_is_rate_limited():
    from tnt.api.routes import ApiError

    err = ApiError(429, None, "Too many checks: try again in 60 s", {"Retry-After": "60"})
    assert err.code == "rate_limited" and err.headers == {"Retry-After": "60"}
    assert err.to_dict() == {"error": {"code": "rate_limited", "message": "Too many checks: try again in 60 s"}}
