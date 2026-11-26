"""
ECLIPSE - process memory scanner
Looks inside running processes for code that does not come from a file on disk, the way EDR products do:

  * threads whose start address lies in private (unbacked) executable memory -> CreateRemoteThread/shellcode
  * PE images present in private executable memory                           -> reflective / manual mapping
  * main image header in memory differing from the file on disk              -> process hollowing
  * main module not backed by an image section at all                        -> process hollowing
  * private RWX memory                                                       -> weak hint, only with others

Needs no driver. Without administrator rights only the user's own processes can be opened, which is
where user-level malware runs anyway.

scan_process(pid, exe=None, name="") -> list of (severity, category, title, detail)
"""
from __future__ import annotations

import ctypes
import os
import struct
from ctypes import wintypes

from engine import INFO, LOW, MED, HIGH, CRIT

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
THREAD_QUERY_INFORMATION = 0x0040
THREAD_QUERY_LIMITED_INFORMATION = 0x0800

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
EXEC_MASK = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
PAGE_GUARD = 0x100

ThreadQuerySetWin32StartAddress = 9

# programs that legitimately generate code at run time (JIT): private executable memory is normal there
JIT_HOSTS = {
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "opera_gx.exe", "vivaldi.exe",
    "msedgewebview2.exe", "iexplore.exe", "node.exe", "electron.exe", "code.exe", "cursor.exe", "discord.exe",
    "slack.exe", "teams.exe", "ms-teams.exe", "spotify.exe", "whatsapp.exe", "telegram.exe", "obsidian.exe",
    "notion.exe", "figma.exe", "steamwebhelper.exe", "epicwebhelper.exe", "java.exe", "javaw.exe",
    "dotnet.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "devenv.exe", "rider64.exe",
    "idea64.exe", "pycharm64.exe", "blender.exe", "unity.exe", "unityhub.exe", "godot.exe",
    "searchhost.exe", "searchapp.exe", "startmenuexperiencehost.exe", "widgets.exe", "phoneexperiencehost.exe",
    "msmpeng.exe", "mpdefendercoreservice.exe", "nissrv.exe", "claude.exe", "chatgpt.exe", "msteams.exe",
    "olk.exe", "outlook.exe", "lghub.exe", "nvcontainer.exe", "nvidia app.exe", "riotclientservices.exe",
    "leagueclientux.exe", "robloxplayerbeta.exe", "robloxstudiobeta.exe", "minecraft.exe",
}


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD), ("PartitionId", wintypes.WORD),
                ("RegionSize", ctypes.c_size_t), ("State", wintypes.DWORD), ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD)]


k32.OpenProcess.restype = wintypes.HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.OpenThread.restype = wintypes.HANDLE
k32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
k32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
psapi.EnumProcessModulesEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD,
                                       ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
psapi.GetMappedFileNameW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
ntdll.NtQueryInformationThread.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG,
                                           ctypes.POINTER(wintypes.ULONG)]
ntdll.NtQueryInformationThread.restype = ctypes.c_long

MAX_ADDR = 0x7FFFFFFEFFFF if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x7FFEFFFF


def _read(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    if k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)) and got.value:
        return buf.raw[:got.value]
    return b""


def _regions(h):
    """Committed memory regions of the process."""
    mbi = MBI()
    addr = 0
    size = ctypes.sizeof(mbi)
    while addr < MAX_ADDR:
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), size):
            break
        base = mbi.BaseAddress or 0
        if mbi.State == MEM_COMMIT:
            yield base, mbi.RegionSize, mbi.Protect, mbi.Type, mbi.AllocationBase or 0
        nxt = base + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt


def _query(h, addr):
    mbi = MBI()
    if k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        return mbi
    return None


def _looks_like_pe(b: bytes) -> bool:
    if len(b) < 0x40 or b[:2] != b"MZ":
        return False
    off = struct.unpack_from("<I", b, 0x3C)[0]
    return 0x40 <= off < len(b) - 4 and b[off:off + 4] == b"PE\x00\x00"


def _pe_fields(b: bytes):
    """Fields of a PE header that the loader never changes in memory."""
    if not _looks_like_pe(b):
        return None
    off = struct.unpack_from("<I", b, 0x3C)[0]
    try:
        machine, nsec, ts = struct.unpack_from("<HHI", b, off + 4)
        opt = off + 24
        entry = struct.unpack_from("<I", b, opt + 16)[0]
        size_img = struct.unpack_from("<I", b, opt + 56)[0]
        return machine, nsec, ts, entry, size_img
    except struct.error:
        return None


def _device_path(p):
    """C:\\x\\y.exe -> \\Device\\HarddiskVolumeN\\x\\y.exe (form GetMappedFileName returns)."""
    drive, rest = os.path.splitdrive(p)
    if not drive:
        return p.lower()
    buf = ctypes.create_unicode_buffer(512)
    if k32.QueryDosDeviceW(drive, buf, 512):
        return (buf.value + rest).lower()
    return p.lower()


def _main_module(h):
    arr = (wintypes.HMODULE * 1)()
    need = wintypes.DWORD()
    if psapi.EnumProcessModulesEx(h, arr, ctypes.sizeof(arr), ctypes.byref(need), 0x03):
        return arr[0] or None
    return None


def _thread_start(tid):
    h = k32.OpenThread(THREAD_QUERY_INFORMATION, False, tid) or \
        k32.OpenThread(THREAD_QUERY_LIMITED_INFORMATION, False, tid)
    if not h:
        return None
    try:
        addr = ctypes.c_void_p()
        if ntdll.NtQueryInformationThread(h, ThreadQuerySetWin32StartAddress, ctypes.byref(addr),
                                          ctypes.sizeof(addr), None) == 0:
            return addr.value
        return None
    finally:
        k32.CloseHandle(h)


def scan_process(pid, exe=None, name="", threads=None):
    """Returns (findings, status). status: "ok" | "denied" | "gone" | "skipped"."""
    name = (name or "").lower()
    if pid in (0, 4) or pid == os.getpid():
        return [], "skipped"
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        err = ctypes.get_last_error()
        return [], "gone" if err == 87 else "denied"
    out = []
    try:
        wow = wintypes.BOOL(False)
        k32.IsWow64Process(h, ctypes.byref(wow))
        if wow.value and ctypes.sizeof(ctypes.c_void_p) == 8:
            pass   # 32-bit process: the region walk still works from a 64-bit scanner

        jit = name in JIT_HOSTS
        priv_exec, rwx, pe_regions = [], 0, []
        image_ranges = []
        for base, size, prot, typ, abase in _regions(h):
            if prot & PAGE_GUARD:
                continue
            if typ == MEM_IMAGE:
                image_ranges.append((base, base + size))
                continue
            if not (prot & EXEC_MASK):
                continue
            if typ == MEM_PRIVATE or typ == MEM_MAPPED:
                priv_exec.append((base, size, prot, typ))
                if prot & PAGE_EXECUTE_READWRITE:
                    rwx += 1
                if base == abase:                 # start of an allocation: check for a PE header
                    head = _read(h, base, 0x400)
                    if _looks_like_pe(head):
                        pe_regions.append(base)

        # 1) PE image sitting in private executable memory (reflective DLL / manual map / RunPE)
        if pe_regions:
            out.append((HIGH if not jit else MED, "Injection",
                        "Executable image loaded straight into memory (not from a file)",
                        ", ".join(hex(a) for a in pe_regions[:4])))

        # 2) threads starting outside any loaded module
        unbacked = []
        for tid in (threads or []):
            start = _thread_start(tid)
            if not start:
                continue
            mbi = _query(h, start)
            if mbi and mbi.State == MEM_COMMIT and mbi.Type != MEM_IMAGE and mbi.Protect & EXEC_MASK:
                unbacked.append((tid, start))
        if unbacked:
            sev = MED if jit else HIGH
            out.append((sev, "Injection", "Thread running code that does not belong to any program file",
                        "; ".join(f"thread {t} at {hex(a)}" for t, a in unbacked[:4])))

        # 3) process hollowing: main module header vs file on disk
        if exe and os.path.isfile(exe):
            base = _main_module(h)
            if base:
                mbi = _query(h, base)
                if mbi and mbi.Type != MEM_IMAGE:
                    out.append((CRIT, "Injection", "Main program replaced in memory (process hollowing)",
                                f"module at {hex(base)} is not backed by {os.path.basename(exe)}"))
                else:
                    mapped = ctypes.create_unicode_buffer(1024)
                    if psapi.GetMappedFileNameW(h, ctypes.c_void_p(base), mapped, 1024):
                        # compare file names only: subst drives, junctions and network shares change the
                        # device prefix legitimately; a different executable name does not happen by accident
                        m_name = mapped.value.replace("/", "\\").rsplit("\\", 1)[-1].lower()
                        if m_name and m_name != os.path.basename(exe).lower():
                            out.append((HIGH, "Injection", "Main module mapped from a different file",
                                        f"{mapped.value} instead of {exe}"))
                    mem_fields = _pe_fields(_read(h, base, 0x1000))
                    try:
                        with open(exe, "rb") as f:
                            disk_fields = _pe_fields(f.read(0x1000))
                    except OSError:
                        disk_fields = None
                    if mem_fields and disk_fields and mem_fields != disk_fields:
                        out.append((CRIT, "Injection", "Program in memory differs from its file on disk "
                                    "(process hollowing)", f"memory {mem_fields} vs disk {disk_fields}"))
                    elif disk_fields and mem_fields is None:
                        out.append((HIGH, "Injection", "Program header erased in memory",
                                    "the PE header of the main module is missing"))

        # 4) RWX private memory: only a hint, reported when nothing else explains it
        if rwx and not jit:
            out.append((LOW if not out else MED, "Injection", "Writable + executable memory (often used by shellcode)",
                        f"{rwx} region{'s' if rwx != 1 else ''}"))
        elif priv_exec and not jit and not out:
            out.append((INFO, "Memory", "Private executable memory present",
                        f"{len(priv_exec)} region{'s' if len(priv_exec) != 1 else ''}"))
        return out, "ok"
    finally:
        k32.CloseHandle(h)


def scan_all(step=None, own_pids=()):
    """Memory scan of every process the current user can open. Returns {pid: (name, exe, findings)}."""
    import psutil
    results, denied = {}, 0
    procs = list(psutil.process_iter(["pid", "name", "exe"]))
    for i, p in enumerate(procs):
        pid = p.info["pid"]
        if pid in own_pids:
            continue
        if step and i % 10 == 0:
            step(f"Inspecting process memory ({i}/{len(procs)})")
        try:
            tids = [t.id for t in p.threads()]
        except Exception:
            tids = []
        f, st = scan_process(pid, p.info.get("exe"), p.info.get("name") or "", tids)
        if st == "denied":
            denied += 1
        if f:
            results[pid] = (p.info.get("name") or "?", p.info.get("exe") or "", f)
    return results, denied
