"""
ECLIPSE - ransomware shield (behaviour based)
Ransomware has to do one thing no matter how it is packed or obfuscated: rewrite lots of user files fast.
The shield watches the user's document folders through the kernel's change journal (ReadDirectoryChangesW)
and reacts to:

  * decoy (canary) files being modified or renamed  -> nothing legitimate ever touches them
  * a burst of files whose content no longer matches their type (a .docx that is not a ZIP any more,
    a .jpg without its JPEG header, a .txt that became random bytes) or that get an extra extension
  * ransom notes dropped in many folders

The process doing the writing is identified from I/O counters and open handles and SUSPENDED (reversible)
so the user decides whether to terminate it or let it continue.
"""
from __future__ import annotations

import ctypes
import hashlib
import math
import os
import queue
import re
import threading
import time
from collections import Counter, deque
from ctypes import wintypes

import psutil

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = wintypes.HANDLE
k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                            wintypes.DWORD, wintypes.HANDLE]
k32.ReadDirectoryChangesW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL,
                                      wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
                                      ctypes.c_void_p]
k32.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]

INVALID_HANDLE = wintypes.HANDLE(-1).value
FILE_LIST_DIRECTORY = 0x0001
SHARE_ALL = 0x1 | 0x2 | 0x4
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
NOTIFY = 0x1 | 0x8 | 0x10            # file name, size, last write
A_ADDED, A_REMOVED, A_MODIFIED, A_RENAMED_OLD, A_RENAMED_NEW = 1, 2, 3, 4, 5
FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM = 0x2, 0x4

WINDOW = 20.0              # seconds of activity considered together
BURST = 8                  # destroyed files inside WINDOW that trigger the shield
NOTE_BURST = 3             # ransom notes in different folders
COOLDOWN = 60.0

# what each type must start with: ransomware rewrites the whole file, header included
MAGIC = {
    ".docx": (b"PK",), ".xlsx": (b"PK",), ".pptx": (b"PK",), ".odt": (b"PK",), ".ods": (b"PK",),
    ".zip": (b"PK",), ".epub": (b"PK",),
    ".doc": (b"\xd0\xcf\x11\xe0",), ".xls": (b"\xd0\xcf\x11\xe0",), ".ppt": (b"\xd0\xcf\x11\xe0",),
    ".pdf": (b"%PDF",), ".jpg": (b"\xff\xd8\xff",), ".jpeg": (b"\xff\xd8\xff",), ".png": (b"\x89PNG",),
    ".gif": (b"GIF8",), ".bmp": (b"BM",), ".mp3": (b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"),
    ".rtf": (b"{\\rtf",), ".7z": (b"7z\xbc\xaf",), ".rar": (b"Rar!",), ".psd": (b"8BPS",),
    ".mp4": None, ".mov": None,   # header at offset 4 ("ftyp"): checked separately
}
TEXT_TYPES = {".txt", ".csv", ".md", ".json", ".xml", ".html", ".htm", ".ini", ".log", ".py", ".js", ".sql",
              ".c", ".cpp", ".h", ".java", ".cs"}
USER_TYPES = set(MAGIC) | TEXT_TYPES
SKIP_SUFFIX = (".tmp", ".crdownload", ".part", ".partial", ".download", ".lnk", ".~tmp", ".bak", ".swp",
               # legit "second extensions": photo sidecars, checksums, compressors replacing the original
               ".xmp", ".aae", ".thm", ".pp3", ".dop", ".on1", ".sig", ".asc", ".sha256", ".sha1", ".md5",
               ".gz", ".bz2", ".xz", ".zst", ".lz4", ".torrent", ".url", ".old", ".orig", ".backup")
NOTE_RE = re.compile(r"(readme|read_me|read-me|decrypt|recover|restore|how.?to|help.?(?:me|decrypt|restore)|"
                     r"ransom|_files_|your.?files|instructions?)[^\\/]*\.(txt|html?|hta|rtf|url)$", re.I)
# never suspended automatically: suspending these would freeze Windows or the user's sync clients
NEVER_SUSPEND = {"explorer.exe", "system", "svchost.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
                 "services.exe", "lsass.exe", "dwm.exe", "msmpeng.exe", "searchindexer.exe", "onedrive.exe",
                 "dropbox.exe", "googledrivefs.exe", "icloudrive.exe", "msedge.exe", "chrome.exe", "firefox.exe"}
CANARY_NAMES = ("!!!_eclipse_guard.docx", "zzz_eclipse_guard.xlsx")


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in Counter(b).values())


def destroyed(path: str):
    """Why this user file no longer looks like what its extension says ("" if it looks fine)."""
    ext = os.path.splitext(path)[1].lower()
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
    except OSError:
        return ""
    if len(head) < 16:
        return ""
    if ext in (".mp4", ".mov"):
        return "" if head[4:8] == b"ftyp" else "media header missing"
    sig = MAGIC.get(ext)
    if sig:
        return "" if head.startswith(sig) else f"{ext} header missing (content overwritten)"
    if ext in TEXT_TYPES:
        if b"\x00" in head[:512] and head[:2] not in (b"\xff\xfe", b"\xfe\xff"):
            if entropy(head) > 7.2:
                return "text file turned into random bytes"
        elif entropy(head) > 7.5:
            return "text file turned into random bytes"
    return ""


def known_folder(guid):
    class GUID(ctypes.Structure):
        _fields_ = [("a", ctypes.c_ulong), ("b", ctypes.c_ushort), ("c", ctypes.c_ushort), ("d", ctypes.c_ubyte * 8)]
    import uuid
    u = uuid.UUID(guid)
    g = GUID(u.time_low, u.time_mid, u.time_hi_version, (ctypes.c_ubyte * 8)(*u.bytes[8:]))
    p = ctypes.c_wchar_p()
    try:
        if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(g), 0, None, ctypes.byref(p)) == 0:
            v = p.value
            ctypes.windll.ole32.CoTaskMemFree(p)
            return v
    except Exception:
        pass
    return None


def default_folders():
    out = []
    for g in ("FDD39AD0-238F-46AF-ADB4-6C85480369C7",     # Documents
              "B4BFCC3A-DB2C-424C-B029-7FE99A87C641",     # Desktop
              "33E28130-4E1E-4676-835A-98395C3BC3BB"):    # Pictures
        p = known_folder(g)
        if p and os.path.isdir(p) and p not in out:
            out.append(p)
    return out


class RansomGuard:
    def __init__(self, folders=None, on_alert=None, canaries=True, own_pids=(), suspend=True,
                 protect_children=True):
        self.folders = [f for f in (folders or default_folders()) if os.path.isdir(f)]
        self.on_alert = on_alert or (lambda info: None)
        self.use_canaries, self.suspend = canaries, suspend
        self.protect_children = protect_children
        self.started = time.time()
        self.own = set(own_pids) | {os.getpid()}
        self.events = queue.Queue(maxsize=50000)
        self.stop_flag = threading.Event()
        self.handles, self.threads = [], []
        self.canaries = {}                    # normcase(path) -> sha256
        self.io = {}                          # pid -> deque[(t, write_bytes)]
        self.last_alert = 0.0
        self.last_suspended = False
        self.ignored = set()                  # pids the user allowed

    # ------------------------------------------------------------------ canaries
    def _canary_bytes(self, name):
        seed = hashlib.sha256(("eclipse-guard:" + name).encode()).digest()
        body = (seed * 512)[:12000]
        return b"PK\x03\x04" + body          # starts like a real Office file so header checks apply

    def plant_canaries(self):
        for d in self.folders:
            for n in CANARY_NAMES:
                p = os.path.join(d, n)
                data = self._canary_bytes(n)
                try:
                    if not os.path.isfile(p) or open(p, "rb").read() != data:
                        if os.path.isfile(p):
                            k32.SetFileAttributesW(p, 0x80)
                        with open(p, "wb") as f:
                            f.write(data)
                    k32.SetFileAttributesW(p, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
                    self.canaries[os.path.normcase(p)] = hashlib.sha256(data).hexdigest()
                except OSError:
                    pass

    def remove_canaries(self):
        for p in list(self.canaries):
            d, n = os.path.split(p)
            try:
                victims = [os.path.join(d, f) for f in os.listdir(d) if os.path.normcase(f).startswith(n)]
            except OSError:
                victims = [p]
            for v in victims:                  # the decoy and any renamed/encrypted copy of it
                try:
                    k32.SetFileAttributesW(v, 0x80)
                    os.remove(v)
                except OSError:
                    pass
        self.canaries.clear()

    def _canary_hit(self, path):
        """True if a decoy was changed (a deletion alone is only re-planted: users may clean up)."""
        exp = self.canaries.get(os.path.normcase(path))
        if exp is None:
            return False
        try:
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest() != exp
        except FileNotFoundError:
            return False
        except OSError:
            return True                       # locked by someone writing it right now

    # ------------------------------------------------------------------ watching
    def _watch(self, folder):
        h = k32.CreateFileW(folder, FILE_LIST_DIRECTORY, SHARE_ALL, None, OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS, None)
        if not h or h == INVALID_HANDLE:
            return
        self.handles.append(h)
        buf = ctypes.create_string_buffer(256 * 1024)
        got = wintypes.DWORD()
        try:
            while not self.stop_flag.is_set():
                ok = k32.ReadDirectoryChangesW(h, buf, len(buf), True, NOTIFY, ctypes.byref(got), None, None)
                if not ok or self.stop_flag.is_set():
                    break
                t = time.time()
                if got.value == 0:            # overflow: far too many changes to list = burst by itself
                    self._put((t, A_MODIFIED, folder, True))
                    continue
                raw = buf.raw[:got.value]
                off = 0
                while True:
                    nxt, action, ln = int.from_bytes(raw[off:off + 4], "little"), \
                        int.from_bytes(raw[off + 4:off + 8], "little"), int.from_bytes(raw[off + 8:off + 12], "little")
                    name = raw[off + 12:off + 12 + ln].decode("utf-16le", "ignore")
                    self._put((t, action, os.path.join(folder, name), False))
                    if not nxt:
                        break
                    off += nxt
        finally:
            k32.CloseHandle(h)

    def _put(self, ev):
        try:
            self.events.put_nowait(ev)
        except queue.Full:
            pass

    # ------------------------------------------------------------------ process attribution
    def _sample_io(self):
        now = time.time()
        for p in psutil.process_iter(["pid", "name"]):
            pid = p.info["pid"]
            if pid in self.own or pid in (0, 4):
                continue
            try:
                wb = p.io_counters().write_bytes
            except Exception:
                continue
            dq = self.io.get(pid)
            if dq is None:
                dq = self.io[pid] = deque(maxlen=20)
                try:   # born after the shield started: its counters started from zero at that moment
                    ct = p.create_time()
                    if ct > self.started:
                        dq.append((ct, 0))
                except Exception:
                    pass
            dq.append((now, wb))
        for pid in [x for x in self.io if not psutil.pid_exists(x)]:
            self.io.pop(pid, None)

    def _protected_tree(self):
        """Eclipse itself, the processes that started it and the ones it started: never suspended."""
        out = set(self.own)
        try:
            me = psutil.Process(os.getpid())
            out |= {p.pid for p in me.parents()}
            if self.protect_children:
                out |= {p.pid for p in me.children(recursive=True)}
        except Exception:
            pass
        return out

    @staticmethod
    def _user_writable(exe):
        e = os.path.normcase(exe or "")
        if not e:
            return False
        sysroots = [os.path.normcase(os.environ.get(v, "")) for v in
                    ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432")]
        sysroots = [s + os.sep for s in sysroots if s]
        return not e.startswith(tuple(sysroots))       # WindowsApps lives under Program Files too

    def _culprit(self, paths, canary=False):
        """Scores every process that wrote recently. Returns (pid, score, evidence) or (None, 0, [])."""
        self._sample_io()
        now = time.time()
        dmg_bytes = 0
        for p in paths:
            try:
                dmg_bytes += os.path.getsize(p)
            except OSError:
                pass
        dirs = {os.path.normcase(os.path.dirname(p)) for p in paths}
        protected = self._protected_tree()
        cands = []
        for pid, dq in self.io.items():
            if pid in protected:
                continue
            win = [wb for t, wb in dq if now - t <= WINDOW + 5]
            if len(win) >= 2 and win[-1] - win[0] > 0:
                cands.append((win[-1] - win[0], pid))
        cands.sort(reverse=True)
        best = (None, 0, [], False)
        for delta, pid in cands[:12]:
            score, ev = 0, []
            handle = writes = user = recent = False
            try:
                p = psutil.Process(pid)
                try:
                    handle = any(os.path.normcase(os.path.dirname(of.path)) in dirs for of in p.open_files())
                except Exception:
                    pass
                writes = bool(dmg_bytes) and delta >= 0.8 * dmg_bytes
                user = self._user_writable(p.exe())
                recent = now - p.create_time() < 600
            except Exception:
                continue
            if handle:
                score += 3
                ev.append("has the damaged files open")
            if writes:
                score += 2
                ev.append(f"wrote {delta // 1024} KB in the last {int(WINDOW)} s")
            if user:
                score += 1
                ev.append("runs from a user-writable folder")
            if recent:
                score += 1
                ev.append("started in the last 10 minutes")
            # strong enough to freeze it without asking: caught holding the files, or the only sensible
            # explanation of a multi-file burst (wrote it all, freshly started, from a user folder)
            strong = user and (handle or (writes and recent and (len(paths) >= 3 or canary)))
            if (strong, score) > (best[3], best[1]):
                best = (pid, score, ev, strong)
        return best

    def _act(self, reason, paths, canary=False):
        now = time.time()
        # after a process was frozen, stay quiet for a while; otherwise allow escalation every few seconds
        if now - self.last_alert < (COOLDOWN if self.last_suspended else 4.0):
            return
        self.last_alert = now
        self.last_suspended = False
        pid, score, evidence, strong = self._culprit(paths, canary)
        info = {"reason": reason, "files": [p for p in paths][:12], "count": len(paths), "pid": pid,
                "name": "", "exe": "", "cmdline": "", "suspended": False, "time": time.time(),
                "evidence": evidence, "confidence": score, "suspect": ""}
        if pid and not strong and score < 4:     # not enough evidence to name a culprit
            try:
                info["suspect"] = psutil.Process(pid).name()
            except Exception:
                pass
            info["pid"] = pid = None
        if pid and pid not in self.ignored:
            try:
                p = psutil.Process(pid)
                info.update(name=p.name(), exe=p.exe() or "", cmdline=" ".join(p.cmdline())[:500])
                # suspend only on strong evidence, and never Windows / installed (Program Files) programs:
                # for those the user gets the alert and decides
                if (self.suspend and strong and info["name"].lower() not in NEVER_SUSPEND
                        and self._user_writable(info["exe"]) and pid not in self._protected_tree()):
                    p.suspend()
                    info["suspended"] = True
                    self.last_suspended = True
            except Exception as e:
                info["error"] = str(e)[:200]
        try:
            self.on_alert(info)
        except Exception:
            pass

    # ------------------------------------------------------------------ analysis loop
    def _analyse(self):
        recent = deque()                      # (t, path, why)
        notes = deque()                       # (t, folder)
        pending = {}                          # path -> due time (let the writer finish before reading)
        last_io = 0.0
        while not self.stop_flag.is_set():
            try:
                t, action, path, overflow = self.events.get(timeout=0.5)
            except queue.Empty:
                t = action = path = None
                overflow = False
            now = time.time()
            if now - last_io > 2.0:
                self._sample_io()
                last_io = now
            if path:
                low = path.lower()
                ncp = os.path.normcase(path)
                if ncp in self.canaries:
                    pending[path] = now + 0.3         # changed -> alert; merely deleted -> re-plant
                elif action in (A_ADDED, A_RENAMED_NEW) and any(ncp.startswith(c + ".") for c in self.canaries):
                    # "decoy.docx" became "decoy.docx.locked" (or an encrypted copy appeared next to it)
                    self._act("A decoy file planted by Eclipse was encrypted/renamed: only ransomware does that",
                              [path], canary=True)
                elif overflow:
                    recent.append((now, path, "change-journal overflow (thousands of writes)"))
                elif not low.endswith(SKIP_SUFFIX) and "\\~$" not in low:
                    ext = os.path.splitext(low)[1]
                    if action in (A_RENAMED_NEW, A_ADDED):
                        inner = os.path.splitext(os.path.splitext(low)[0])[1]
                        if inner in USER_TYPES and ext not in USER_TYPES and 2 <= len(ext) <= 16 \
                                and ext not in SKIP_SUFFIX:
                            recent.append((now, path, f"files renamed with an extra extension ({ext})"))
                    if action in (A_ADDED, A_RENAMED_NEW) and NOTE_RE.search(os.path.basename(low)):
                        notes.append((now, os.path.dirname(low)))
                    if action in (A_MODIFIED, A_ADDED, A_RENAMED_NEW) and ext in USER_TYPES:
                        pending[path] = now + 0.6
            # check files whose writer had time to finish
            for p in [p for p, due in pending.items() if due <= now]:
                del pending[p]
                if os.path.normcase(p) in self.canaries:
                    if self._canary_hit(p):
                        self._act("A decoy file planted by Eclipse was modified: only ransomware does that", [p], canary=True)
                    elif not os.path.exists(p):
                        self.plant_canaries()
                    continue
                why = destroyed(p)
                if why:
                    recent.append((now, p, why))
            while recent and now - recent[0][0] > WINDOW:
                recent.popleft()
            while notes and now - notes[0][0] > WINDOW:
                notes.popleft()
            damaged = {p for _, p, _ in recent}
            note_dirs = {d for _, d in notes}
            if len(damaged) >= BURST or (len(note_dirs) >= NOTE_BURST and len(damaged) >= 3):
                why = Counter(w for _, _, w in recent).most_common(1)[0][0]
                reason = (f"{len(damaged)} files destroyed in {int(WINDOW)} seconds ({why})"
                          + (f", ransom notes in {len(note_dirs)} folders" if note_dirs else ""))
                self._act(reason, sorted(damaged))
                recent.clear()
                notes.clear()

    # ------------------------------------------------------------------ control
    def start(self):
        if self.use_canaries:
            self.plant_canaries()
        for f in self.folders:
            th = threading.Thread(target=self._watch, args=(f,), daemon=True)
            th.start()
            self.threads.append(th)
        th = threading.Thread(target=self._analyse, daemon=True)
        th.start()
        self.threads.append(th)
        return self

    def stop(self, remove_canaries=False):
        self.stop_flag.set()
        for h in list(self.handles):
            try:
                k32.CancelIoEx(h, None)
            except Exception:
                pass
        for th in self.threads:
            th.join(2)
        self.handles, self.threads = [], []
        if remove_canaries:
            self.remove_canaries()


def resume(pid):
    psutil.Process(pid).resume()
