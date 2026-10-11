"""Read-only macOS pending-child identity proof; never signal or infer release."""
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


def match_role(state, role):
    pid = state.get(role + "_pid")
    start = state.get(role + "_start_identity")
    boot = state.get(role + "_boot_identity")
    if (type(pid) is not int or not isinstance(start, dict)
            or start.get("platform") != "macos"
            or type(start.get("start_seconds")) is not int or start["start_seconds"] <= 0
            or type(start.get("start_microseconds")) is not int
            or not 0 <= start["start_microseconds"] < 1_000_000
            or not isinstance(boot, str) or not boot):
        raise IdentityUnknown("incomplete precise recorded identity")
    live = kernel_identity(pid)
    if (live is None or live["start_identity"] != start
            or live["boot_identity"] != boot.upper() or live["uid"] != os.geteuid()):
        raise IdentityUnknown("recorded process identity does not match kernel")
    return live


def capture_starting(state, owner, runtime, domain):
    if (state.get("schema") != "effigy.managed.host-listener-state.v1"
            or state.get("status") != "starting" or state.get("owner") != owner
            or state.get("runtime_generation") != runtime or not re.fullmatch(r"[0-9a-f]{32}", str(state.get("generation")))
            or not re.fullmatch(r"[0-9a-f]{32}", str(runtime))
            or state.get("route_domain") != domain
            or any(state.get(key) is not None for key in
                   ("address", "internal_url", "public_url", "route_owner", "listener_pid"))):
        raise IdentityUnknown("not an unpublished pending generation")
    supervisor = match_role(state, "supervisor")
    child = match_role(state, "child")
    if child["pgid"] != child["pid"] or child["ppid"] != supervisor["pid"]:
        raise IdentityUnknown("pending child group or supervisor ancestry mismatch")
    members = []
    for pid in group_members(child["pgid"]):
        live = kernel_identity(pid)
        if (live is None or live["uid"] != os.geteuid() or live["boot_identity"] != child["boot_identity"]
                or live["pgid"] != child["pgid"]):
            raise IdentityUnknown("pending group identity unavailable")
        members.append(live)
    if child["pid"] not in [item["pid"] for item in members]:
        raise IdentityUnknown("pending child absent from group")
    by_pid = {item["pid"]: item for item in members}
    for item in members:
        seen = set()
        pid = item["pid"]
        while pid != child["pid"]:
            if pid in seen or pid not in by_pid:
                raise IdentityUnknown("foreign or unknown pending group ancestry")
            seen.add(pid)
            pid = by_pid[pid]["ppid"]
    return {"members": members, "owner": owner, "runtime_generation": runtime, "generation": state["generation"],
            "route_domain": domain, "status": "starting", "supervisor": supervisor, "child": child}


def group_members(pgid):
    result = subprocess.run(["/bin/ps", "-Ao", "pid=,ppid=,pgid="],
                            capture_output=True, text=True, timeout=5, check=False)
    if result.returncode:
        raise IdentityUnknown("group inventory unavailable")
    members = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 3 or not all(value.isdecimal() for value in fields):
            raise IdentityUnknown("group inventory malformed")
        pid, parent, group = map(int, fields)
        if group == pgid:
            members.append(pid)
    return sorted(members)


def require_absent(receipt):
    # Reused PIDs and changed boots remain held, even when the original has gone.
    if receipt.get("status") != "starting":
        raise IdentityUnknown("no pretermination pending receipt")
    for identity in [receipt["supervisor"], receipt["child"], *receipt["members"]]:
        if boot_identity() != identity["boot_identity"] or kernel_identity(identity["pid"]) is not None:
            raise IdentityUnknown("recorded generation absence unproven")
    if group_members(receipt["child"]["pgid"]):
        raise IdentityUnknown("recorded child group has survivors")


def cleared_terminal(state, receipt):
    if (state.get("status") not in ("stopped", "failed")
            or state.get("schema") != "effigy.managed.host-listener-state.v1"
            or any(state.get(key) != receipt[key] for key in
                   ("owner", "runtime_generation", "generation", "route_domain"))
            or any(state.get(key) is not None for key in (
                "address", "internal_url", "public_url", "route_owner", "child_pid",
                "child_boot_identity", "child_start_identity", "listener_pid",
                "listener_boot_identity", "listener_start_identity"))):
        raise IdentityUnknown("terminal generation not cleared and bound")
    for suffix, expected in (("pid", "pid"), ("boot_identity", "boot_identity"),
                             ("start_identity", "start_identity")):
        if state.get("supervisor_" + suffix) != receipt["supervisor"][expected]:
            raise IdentityUnknown("terminal supervisor generation changed")
    require_absent(receipt)
