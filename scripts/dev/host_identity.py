"""Read-only macOS host-child identity; no signal or release authority."""
import ctypes
import errno
import os
import re
import subprocess
import sys


class IdentityUnknown(RuntimeError):
    pass


class BSDInfo(ctypes.Structure):
    # macOS SDK sys/proc_info.h proc_bsdinfo, also used by pinned Effigy.
    _fields_ = [(name, ctypes.c_uint32) for name in (
        "flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid",
        "rgid", "svuid", "svgid", "reserved")]
    _fields_ += [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)]
    _fields_ += [(name, ctypes.c_uint32) for name in (
        "nfiles", "pgid", "jobc", "tdev", "tpgid")]
    _fields_ += [("nice", ctypes.c_int32), ("seconds", ctypes.c_uint64),
                ("microseconds", ctypes.c_uint64)]


def boot_identity():
    result = subprocess.run(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"],
                            capture_output=True, text=True, timeout=5, check=False)
    value = result.stdout.strip().upper()
    if result.returncode or not re.fullmatch(r"[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}", value):
        raise IdentityUnknown("boot identity unavailable")
    return value


def kernel_identity(pid):
    if sys.platform != "darwin" or type(pid) is not int or not 0 < pid < 2**31:
        raise IdentityUnknown("unsupported process identity")
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    read = library.proc_pidinfo
    read.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    read.restype = ctypes.c_int
    info = BSDInfo()
    ctypes.set_errno(0)
    size = read(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
    if size != ctypes.sizeof(info):
        if size == 0 and ctypes.get_errno() == errno.ESRCH:
            return None
        raise IdentityUnknown("kernel process identity unavailable")
    if info.pid != pid or not info.seconds or info.microseconds >= 1_000_000:
        raise IdentityUnknown("kernel process identity malformed")
    return {"pid": pid, "ppid": info.ppid, "pgid": info.pgid, "uid": info.uid,
            "boot_identity": boot_identity(), "start_identity": {
                "platform": "macos", "start_seconds": info.seconds,
                "start_microseconds": info.microseconds}}

