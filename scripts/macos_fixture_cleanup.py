"""Retire only descendants of a still-owned, unprivileged fixture child on macOS."""
import ctypes
from contextlib import closing
import errno
import os
import select
import signal
import subprocess
import time


class _BSDShort(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in ["pid", "ppid", "pgid", "status"]] + [
        ("comm", ctypes.c_char * 16)] + [(name, ctypes.c_uint32) for name in [
            "flags", "uid", "gid", "ruid", "rgid", "svuid", "svgid", "reserved"]]


class _Darwin:
    Token = ctypes.c_uint32 * 8

    def __init__(self):
        self.proc = ctypes.CDLL("/usr/lib/libproc.dylib")
        self.system = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        self.self_port = ctypes.c_uint32.in_dll(self.system, "mach_task_self_").value
        self.proc.proc_listchildpids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        self.proc.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        self.proc.proc_signal_with_audittoken.argtypes = [ctypes.POINTER(self.Token), ctypes.c_int]
        self.system.task_name_for_pid.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.POINTER(ctypes.c_uint32)]
        self.system.task_info.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        self.system.mach_port_deallocate.argtypes = [ctypes.c_uint32, ctypes.c_uint32]

    def info(self, pid):
        value = _BSDShort()
        count = self.proc.proc_pidinfo(pid, 13, 0, ctypes.byref(value), ctypes.sizeof(value))
        if count == 0:
            return None
        if count != ctypes.sizeof(value) or value.pid != pid:
            raise RuntimeError("Incomplete fixture process identity")
        return value

    def children(self, pid):
        values = (ctypes.c_int * 65)()
        count = self.proc.proc_listchildpids(pid, values, ctypes.sizeof(values))
        if count < 0 or count >= len(values):
            raise RuntimeError("Fixture child enumeration exceeded its bound")
        return [value for value in values[:count] if value > 0]

    def token(self, pid):
        name = ctypes.c_uint32()
        if self.system.task_name_for_pid(self.self_port, pid, ctypes.byref(name)):
            raise RuntimeError("Fixture audit identity is unavailable")
        try:
            token, count = self.Token(), ctypes.c_uint32(8)
            if self.system.task_info(name.value, 15, ctypes.byref(token), ctypes.byref(count)) or count.value != 8:
                raise RuntimeError("Fixture audit identity is incomplete")
            if token[5] != pid or token[1] != os.geteuid() or token[3] != os.getuid():
                raise RuntimeError("Fixture audit identity has the wrong owner")
            return token
        finally:
            self.system.mach_port_deallocate(self.self_port, name.value)

    def send(self, token, number):
        result = self.proc.proc_signal_with_audittoken(ctypes.byref(token), number)
        if result not in (0, errno.ESRCH):
            raise OSError(result, "Fixture audit-token signal failed")
        return result == 0


def retire_owned_tree(process, grace_seconds=1):
    """Freeze parents before enumeration. Descendant signals use kernel-checked audit tokens, never borrowed PID kills.

    Native parents receive a chance to reap each layer before forced termination. The runner reaps its own child.
    Exit events establish descendant termination; they do not claim runner ownership of grandchildren's waits.
    """
    if os.geteuid() == 0 or process.poll() is not None:
        raise RuntimeError("Cleanup requires a still-owned, unprivileged fixture child")
    api, nodes, exited = _Darwin(), {}, set()
    root = api.info(process.pid)
    if root is None or root.ppid != os.getpid() or root.pgid != process.pid or os.getsid(process.pid) != process.pid:
        raise RuntimeError("Cleanup requires the runner's own private child session")
    with closing(select.kqueue()) as events:
        process.send_signal(signal.SIGSTOP)
        stopped = os.waitid(os.P_PID, process.pid, os.WSTOPPED | os.WEXITED | os.WNOWAIT)
        if stopped.si_code != os.CLD_STOPPED:
            process.wait(timeout=10)
            return {"trackedDescendants": 0, "observedExits": 0}

        def capture(parent, depth):
            if depth > 8:
                raise RuntimeError("Fixture process depth exceeded its bound")
            for pid in api.children(parent):
                info = api.info(pid)
                if info is None or info.status == 5:  # A frozen parent still owns any zombie's eventual wait.
                    continue
                if info.ppid != parent or pid in nodes or len(nodes) >= 64:
                    raise RuntimeError("Fixture descendant ownership changed")
                token = api.token(pid)
                nodes[pid] = (token, depth)
                if not api.send(token, signal.SIGSTOP):
                    raise RuntimeError("Fixture incarnation changed before suspension")
                deadline = time.monotonic() + 3
                while True:
                    info = api.info(pid)
                    if info is None or info.status == 5:
                        exited.add(pid)
                        break
                    if info.ppid != parent:
                        raise RuntimeError("Fixture descendant parent changed")
                    if info.status == 4:
                        if bytes(api.token(pid)) != bytes(token):
                            raise RuntimeError("Fixture incarnation changed during suspension")
                        events.control([select.kevent(pid, filter=select.KQ_FILTER_PROC,
                            flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE, fflags=select.KQ_NOTE_EXIT)], 0, 0)
                        capture(pid, depth + 1)
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Fixture descendant did not suspend")
                    time.sleep(0.001)

        def await_exits(wanted):
            deadline = time.monotonic() + grace_seconds
            while wanted - exited and time.monotonic() < deadline:
                for event in events.control(None, 64, max(0, deadline - time.monotonic())):
                    if event.flags & select.KQ_EV_ERROR or event.ident not in nodes or not event.fflags & select.KQ_NOTE_EXIT:
                        raise RuntimeError("Fixture exit observation failed")
                    exited.add(event.ident)

        try:
            capture(process.pid, 1)
            for depth in sorted({value[1] for value in nodes.values()}, reverse=True):
                layer = {pid for pid, (_, level) in nodes.items() if level == depth}
                if depth < max(value[1] for value in nodes.values()):
                    for pid in layer - exited:
                        api.send(nodes[pid][0], signal.SIGCONT)
                    await_exits(layer)  # Allow the native owners to reap the layer below.
                for pid in layer - exited:
                    api.send(nodes[pid][0], signal.SIGKILL)
                await_exits(layer)
                if layer - exited:
                    raise RuntimeError("Fixture descendants did not exit")
        except BaseException:
            # A partial snapshot grants no authority over unobserved descendants. Restore cooperative cleanup.
            for token, _ in nodes.values():
                try:
                    api.send(token, signal.SIGCONT)
                except OSError:
                    pass
            process.send_signal(signal.SIGCONT)
            process.send_signal(signal.SIGTERM)
            process.wait(timeout=10)
            raise
        process.send_signal(signal.SIGCONT)
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            # All captured descendants have exited. The direct child has not been reaped or reused.
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
    return {"trackedDescendants": len(nodes), "observedExits": len(exited)}
