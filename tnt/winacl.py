r"""Folder security for the service's private folders: packet captures and the TFTP root.

Why this exists
---------------
The installer gives ``%ProgramData%\TNT`` a DACL that lets ``BUILTIN\Users`` read, and every new
subfolder inherits it.  Two folders need something else:

* ``captures`` (:func:`tnt.paths.captures_dir`) holds raw traffic, which can carry other users'
  sessions and cleartext credentials: SYSTEM and Administrators only (:data:`CAPTURES_SDDL`).
* ``tftp`` (:func:`tnt.paths.tftp_dir`) is the TFTP server's root, where technicians drop the files
  devices ask for: SYSTEM and Administrators full control, Users Modify (:data:`TFTP_SDDL`).

:func:`secure_dir` creates the folder and replaces its DACL with a *protected* one, so nothing is
inherited from ``%ProgramData%\TNT``; the ``OICI`` ACEs pass on to every file and subfolder created
inside.  It refuses a folder that is a reparse point (a junction or a symbolic link), and it raises
``OSError`` whenever the DACL cannot be set, so the caller decides: packet capture fails closed, the
TFTP server only warns.  Neither folder is in :func:`tnt.paths.ensure_dirs`; the component that uses
a folder creates and secures it when it needs it.

Test seam
---------
:func:`_set_file_security` is the only function here that changes a real DACL.  ``tests/conftest.py``
replaces it with a recorder for the whole test session: a protected SYSTEM + Administrators DACL would
lock a non-elevated test process out of its own temp folder (a UAC-filtered token holds Administrators
as deny-only), and pytest could not delete it.

Every Win32 function is declared with ``argtypes``/``restype`` (see :mod:`tnt.peer`), and the DLLs load
lazily, so importing this module never fails off Windows.
"""
from __future__ import annotations

import ctypes
import logging
import os
import stat
import sys
import threading
from ctypes import POINTER, byref, c_int, c_ulong, c_void_p, c_wchar_p
from typing import Any, Tuple, Union

log = logging.getLogger(__name__)

__all__ = ["CAPTURES_SDDL", "TFTP_SDDL", "secure_dir"]

#: SYSTEM and Administrators full control and nobody else; ``P`` (protected): nothing inherited from the
#: parent folder; ``OICI``: files (OI) and subfolders (CI) created inside inherit both ACEs.
CAPTURES_SDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
#: :data:`CAPTURES_SDDL` plus ``BUILTIN\Users`` Modify (``0x1301bf``: read, write, execute and delete, but
#: never WRITE_DAC or WRITE_OWNER), so a technician can drop files for devices without elevating.
TFTP_SDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;BU)"

# -- Win32 constants -------------------------------------------------------------------------
SDDL_REVISION_1 = 1
#: ``SECURITY_INFORMATION`` flags (winnt.h): replace the DACL, and mark it protected.
DACL_SECURITY_INFORMATION = 0x00000004
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000

_dll_lock = threading.Lock()
_advapi32: Any = None
_kernel32: Any = None


def _dll() -> Tuple[Any, Any]:
    """Load ``advapi32`` / ``kernel32`` lazily with every prototype declared."""
    global _advapi32, _kernel32
    with _dll_lock:
        if _advapi32 is None:
            a = ctypes.WinDLL("advapi32", use_last_error=True)
            a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [c_wchar_p, c_ulong, POINTER(c_void_p),
                                                                                POINTER(c_ulong)]
            a.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = c_int
            a.SetFileSecurityW.argtypes = [c_wchar_p, c_ulong, c_void_p]
            a.SetFileSecurityW.restype = c_int
            k = ctypes.WinDLL("kernel32", use_last_error=True)
            k.LocalFree.argtypes = [c_void_p]
            k.LocalFree.restype = c_void_p
            _advapi32, _kernel32 = a, k
        return _advapi32, _kernel32


def _win_error(what: str, path: str) -> OSError:
    """The ``OSError`` for the thread's last Win32 error after *what* failed on *path* (access denied
    becomes ``PermissionError``, a missing folder ``FileNotFoundError``)."""
    code = ctypes.get_last_error()
    return OSError(0, f"{what} failed: {ctypes.FormatError(code).strip().rstrip('.')}", path, code)


def _set_file_security(path: str, sddl: str) -> None:
    """Replace the DACL of *path* with the one in *sddl*, marked protected so nothing is inherited from
    the parent.  Raises ``OSError`` when Windows does not accept the SDDL or the DACL cannot be set.

    The module seam: tests/conftest.py replaces it with a recorder for the whole test session."""
    target = os.fspath(path)
    if sys.platform != "win32":
        raise OSError(f"cannot secure {target}: folder security needs Windows")
    advapi, kernel = _dll()
    sd = c_void_p()
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, byref(sd), None):
        raise _win_error("ConvertStringSecurityDescriptorToSecurityDescriptorW", target)
    try:
        if not advapi.SetFileSecurityW(target, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd):
            raise _win_error("SetFileSecurityW", target)
    finally:
        kernel.LocalFree(sd)        # the descriptor is LocalAlloc'd by the conversion


def _is_reparse_point(path: str) -> bool:
    """True when *path* exists and is a reparse point (a junction, a symbolic link, a mount point).  A
    missing path is not one; any other ``OSError`` (access denied) propagates."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    # a junction is not S_ISLNK: only the attribute tells
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def secure_dir(path: Union[str, os.PathLike], sddl: str) -> None:
    """Create the folder *path* (parents included) and give it the protected DACL *sddl*.

    Refuses a *path* that exists and is a reparse point with ``OSError("<path> is a link")``, so the DACL
    never lands on whatever a link points at.  On an existing folder the DACL is applied again, which puts
    back one somebody changed.  Raises ``OSError`` on any failure."""
    target = os.fspath(path)
    if _is_reparse_point(target):
        raise OSError(f"{target} is a link")
    os.makedirs(target, exist_ok=True)
    _set_file_security(target, sddl)
    log.debug("folder security applied to %s", target)
