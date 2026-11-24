"""
ECLIPSE - system scan (Quick / Full / Custom), in the style of classic antimalware scanners.

Pipeline
  1. enumerate   fast os.scandir walk; skips cloud-only OneDrive files, junction loops and huge caches
  2. fast pass   static heuristics on every candidate, in parallel worker PROCESSES (all CPU cores,
                 no Defender / PowerShell per file), skipping files unchanged since a previous clean scan
  3. verify      suspects only: digital signature + Windows Defender + full engine, to cut false positives
"""
from __future__ import annotations

import ctypes
import json
import os
import queue
import string
import threading
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, wait, FIRST_COMPLETED

import engine
import sysmon

nc = os.path.normcase
CACHE_VERSION = 4

# extensions analysed everywhere
SCAN_EXT = {".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".ocx", ".sys", ".msi", ".msp", ".bat", ".cmd",
            ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".jar", ".lnk", ".chm",
            ".scf", ".url", ".reg", ".xll", ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam",
            ".xlsb", ".doc", ".xls", ".ppt", ".rtf", ".pdf", ".zip", ".iso", ".img", ".vhd", ".vhdx", ".one",
            ".appx", ".msix", ".application", ".gadget", ".inf"}
# extra extensions only in "hot" folders (Downloads, Desktop, Temp, Startup...)
HOT_EXT = {".py", ".pyw", ".docx", ".xlsx", ".pptx", ".rar", ".7z", ".apk", ".txt"}
# magic bytes that make an unknown/disguised file worth a full look
MAGICS = (b"MZ", b"\xD0\xCF\x11\xE0", b"{\\rtf", b"%PDF", b"Rar!", b"7z\xBC\xAF", b"PK\x03\x04",
          b"L\x00\x00\x00\x01\x14\x02\x00")
MEDIA_EXT = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wav",
             ".flac", ".heic", ".svg", ".ico"}

SKIP_NAMES = {"node_modules", ".git", ".svn", ".hg", "__pycache__", "site-packages", "dist-packages", ".cache",
              "cache", "cache2", "code cache", "gpucache", "shadercache", "dawncache", "grshadercache",
              "service worker", "indexeddb", "cachestorage", "webcache", "inetcache", "crashpad", "logs",
              "winsxs", "servicing", "softwaredistribution", "assembly", "driverstore", "catroot", "catroot2",
              "winevt", "prefetch", "system volume information", "$windows.~bt", "$windows.~ws",
              "$winreagent", "windowsapps", "installer", "microsoft.net", "pkgs", "conda-meta", "locales",
              "onedrivetemp", "msocache", "packages"}
SKIP_ABS = {nc(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), p)) for p in
            ("WinSxS", "servicing", "SoftwareDistribution", "Installer", "assembly", "Logs", "System32\\DriverStore",
             "System32\\catroot", "System32\\catroot2", "System32\\winevt", "Panther", "Prefetch")}

# Windows "Recent items": shortcuts named like "photo.png.lnk" by design
SKIP_ABS.add(nc(os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Recent")))

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
CLOUD_ONLY = 0x400000 | 0x40000 | 0x1000      # RECALL_ON_DATA_ACCESS | RECALL_ON_OPEN | OFFLINE
MAX_SIZE = 120 * 1024 * 1024
FAST_SETTINGS = {"use_defender": False, "check_signature": False, "online_dns": False,
                 "follow_redirects": False, "vt_key": "", "max_read": 32 * 1024 * 1024, "max_str": 4 * 1024 * 1024}
SCRIPTY = {".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".ps1", ".psm1", ".bat", ".cmd"}
# bundled app/extension code: thousands of legit scripts that are never run by Windows Script Host
APP_CODE = tuple("\\" + d + "\\" for d in (
    "extensions", "resources", "webapps", "dist", "static", "app", "packages", "lib", "scripts", "modules",
    "plugins", "addons", "browsercache", "user data"))
# containers: inside program folders they are libraries/installers (jar, msi...), only worth a look where users drop files
CONTAINER_EXT = {".jar", ".zip", ".msi", ".msp", ".appx", ".msix", ".iso", ".img", ".vhd", ".vhdx", ".rar", ".7z"}

# ---- system-scan policy -------------------------------------------------------
# Static heuristics are tuned for single suspicious downloads. Across a whole disk most of them fire on
# ordinary software, so outside "hot" folders only strong evidence (or a pile of distinct behaviours) counts.
STRONG = {"Deceptive double extension", "Multiple spaces hiding the extension", "Disguised LNK shortcut",
          "Name identical to a Windows system process",
          "PowerShell in hidden window", "PowerShell with encoded command",
          "Copies itself to the Startup folder", "RTLO character in name (spoofed extension)"}
BEHAVIOUR = {"Typical keylogger APIs", "Keylogger (keystroke logging)", "Accesses passwords saved in the browser",
             "Webcam capture", "Microphone recording", "Screen capture", "Code injection APIs (into other processes)",
             "Autostart via registry (Run key)", "Checks for analysis tools", "Downloads files from the Internet",
             "Hardcoded IP:port address", "API anti-debug", "Creates a scheduled task", "Modifies Winlogon / IFEO",
             "ngrok tunnel / dynamic DNS (typical of RATs)", "Copies itself to the Startup folder",
             "Claims a well-known vendor but is not signed"}
NOISE = {"Potentially executable file type", "Compile date in the future (forged)"}
# installers / disk images legitimately embed executables
EMBEDS_PE = {".msi", ".msp", ".cab", ".iso", ".img", ".vhd", ".vhdx", ".7z", ".rar", ".msix", ".appx"}
# findings that a valid publisher signature cannot override
DEFINITIVE = {"Database", "Defender", "Deception"}
SIGNABLE = {".msi", ".msp", ".cab", ".ps1", ".psm1", ".vbs", ".js", ".wsf", ".appx", ".msix", ".cat"}
FAMILY = {"RAT", "Stealer"}
# admin-only locations: malware rarely gets there, and installers legitimately use scary-looking commands
PROTECTED = tuple(nc(p) + "\\" for p in {os.environ.get(k, "") for k in
                                       ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "SystemRoot")} if p)
SOURCE_EXT = {".py", ".pyw", ".txt", ".js", ".ts", ".json", ".md", ".cs", ".c", ".cpp", ".h", ".java", ".yar", ".yara"}


def apply_policy(r, hot, ftype=None):
    """Re-scores a ScanResult for a system scan. Returns the (possibly emptied) result."""
    ftype = ftype or r.meta.get("type", "")
    ext = os.path.splitext(r.target)[1].lower()
    # one finding per title (archives repeat the same hit for every member)
    best = {}
    for f in r.findings:
        if f.title not in best or f.score > best[f.title].score:
            best[f.title] = f
    fs = [f for f in best.values() if f.title not in NOISE]
    base = os.path.basename(r.target).lower()
    # bait words count only in the file's own name, not in names of archive members
    fs = [f for f in fs if not (f.title.startswith("Name typical of malware bait")
                                and (f.detail not in base or f.detail in ("loader", "patch")))]
    if ext in EMBEDS_PE:
        fs = [f for f in fs if f.title != "Executable hidden inside the file"]
    # a PE without extension (download caches, updaters) is only a disguise where users open files
    if not hot and ext not in engine.DECOY_EXT:
        fs = [f for f in fs if f.title != "Executable disguised as another file type"]
    # malware-family names: a file naming 3+ families is a list (AV database, security tool source), not malware
    fam = [f for f in fs if f.category in FAMILY]
    if fam and (len(fam) >= 3 or ftype not in ("PE", "OLE") or ext in SOURCE_EXT
                or (not hot and not any(f.category not in FAMILY and f.severity >= engine.MED for f in fs))):
        fs = [f for f in fs if f.category not in FAMILY]      # a lone family name in a library is a coincidence
    if ext == ".lnk" and not hot:                              # Start menu / app shortcuts: "license.txt.lnk"
        fs = [f for f in fs if f.title != "Deceptive double extension"]
    if nc(r.target).startswith(PROTECTED):
        fs = [f for f in fs if f.category in DEFINITIVE or f.severity <= engine.INFO
              or (f.category == "Deception" and f.title != "Deceptive double extension")]
    if ext in SOURCE_EXT and not hot:
        fs = [f for f in fs if f.title in STRONG and f.category != "Execution"]
    if not hot or ext in (".dll", ".ocx", ".sys", ".pyd", ".node"):   # libraries are never opened by the user
        behaviours = [f for f in fs if f.title in BEHAVIOUR]
        unsigned = not str(r.meta.get("signature", "")).startswith("Valid")
        keep_beh = unsigned and len(behaviours) >= 4
        fs = [f for f in fs if f.severity >= engine.CRIT or f.title in STRONG
              or (keep_beh and f.title in BEHAVIOUR) or f.severity <= engine.INFO]
    if not hot:
        real = [f for f in fs if f.severity > engine.INFO]
        if len(real) == 1 and real[0].category not in DEFINITIVE and real[0].category != "Deception"                 and real[0].severity > engine.HIGH:
            f = real[0]                       # one isolated indicator: worth a look, not a verdict
            fs[fs.index(f)] = engine.Finding(engine.HIGH, f.category, f.title, f.detail, 30)
    r.findings = fs
    r.bonus = min(r.bonus, 0)
    return r.finalize()


def fixed_drives():
    out = []
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    for i, letter in enumerate(string.ascii_uppercase):
        if mask & (1 << i):
            root = f"{letter}:\\"
            if ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)) == 3:   # DRIVE_FIXED
                out.append(root)
    return out


def _env(name, *sub):
    v = os.environ.get(name, "")
    return os.path.join(v, *sub) if v else ""


def hot_folders():
    home = os.path.expanduser("~")
    return [p for p in {
        sysmon.downloads_dir(), os.path.join(home, "Desktop"), _desktop(), sysmon.TEMP,
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp"), os.path.join(os.environ.get("PUBLIC", r"C:\Users\Public")),
        _env("APPDATA", r"Microsoft\Windows\Start Menu\Programs\Startup"),
        _env("ProgramData", r"Microsoft\Windows\Start Menu\Programs\Startup"),
    } if p and os.path.isdir(p)]


def _desktop():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") as k:
            return os.path.expandvars(winreg.QueryValueEx(k, "Desktop")[0])
    except OSError:
        return ""


def quick_targets():
    """(folder, max depth) pairs for a Quick scan: where malware actually lives."""
    home = os.path.expanduser("~")
    t = [(f, 6) for f in hot_folders()]
    t += [(_env("APPDATA"), 5), (_env("LOCALAPPDATA"), 4), (_env("ProgramData"), 3),
          (os.path.join(home, "Documents"), 3), (_desktop() or os.path.join(home, "Desktop"), 6)]
    for d in fixed_drives()[:1]:
        t.append((os.path.join(d, "$Recycle.Bin"), 3))
    seen, out = set(), []
    for p, dep in t:
        if p and os.path.isdir(p) and nc(p) not in seen:
            seen.add(nc(p))
            out.append((p, dep))
    return out


# --------------------------------------------------------------------------- #
#  Worker process side
# --------------------------------------------------------------------------- #
_FS = None


def _init(data_dir, self_dirs=None, self_exes=None):
    global _FS
    if self_dirs is not None:          # worker process: learn what Eclipse itself is
        engine.set_self(self_dirs, self_exes or [])
    try:
        import sys
        sys.setrecursionlimit(5000)
        # lower priority: the PC stays responsive during a full scan
        ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(), 0x00004000)
    except Exception:
        pass
    _FS = engine.FileScanner(FAST_SETTINGS, data_dir, engine.LinkScanner(FAST_SETTINGS, data_dir))


def _scan_batch(items):
    """items: [(path, magic_only, hot)] -> [(path, score, dict-or-None, error)]"""
    if _FS is None:
        _init(None)
    out = []
    for path, magic_only, hot in items:
        try:
            if magic_only:
                with open(path, "rb") as f:
                    head = f.read(8)
                # outside hot folders only a hidden executable is interesting (app data blobs are often zips)
                if not head.startswith(MAGICS if hot else (b"MZ",)):
                    out.append((path, -1, None, None))
                    continue
            r = _FS.scan(path)
            if os.path.basename(path).lower() in engine.SYSTEM_NAMES and sysmon.in_windows_dir(path):
                r.findings = [f for f in r.findings if "system process" not in f.title]
            apply_policy(r, hot)
            out.append((path, r.score, r.to_dict() if r.score >= 25 else None, None))
        except Exception as e:
            out.append((path, -2, None, str(e)[:200]))
    return out


# --------------------------------------------------------------------------- #
#  Scan controller (runs in a background thread of the GUI)
# --------------------------------------------------------------------------- #
class SystemScan:
    def __init__(self, mode, data_dir, settings, folders=None, workers=None):
        self.mode, self.data_dir, self.settings = mode, data_dir, dict(settings)
        self.folders = folders or []
        cpu = os.cpu_count() or 4
        self.workers = workers or max(2, min(10, cpu - 2))
        self.stop = False
        self.cancelled = False
        self.paused = False
        self.stats = {"found": 0, "scanned": 0, "cached": 0, "skipped": 0, "suspects": 0, "threats": 0,
                      "suspicious": 0, "errors": 0, "bytes": 0, "current": "", "phase": "Preparing",
                      "enum_done": False, "started": time.time(), "dirs": 0, "verified": 0, "verify_total": 0}
        self.detections = []
        self.cache_path = os.path.join(data_dir, "scan_cache.json")
        self.cache = self._load_cache()
        self.new_cache = {}
        self.on_detect = None
        self._q = queue.Queue(maxsize=20000)
        self._seen = set()
        self.hot = {nc(f) for f in hot_folders()}
        self.own_dir = nc(os.path.dirname(os.path.abspath(data_dir)))   # Eclipse's own folder (sources, quarantine)

    def _is_hot(self, p):
        p = nc(p)
        return any(p.startswith(h + "\\") for h in self.hot)

    # ---------------------------------------------------------------- cache
    def _fingerprint(self):
        return f"{CACHE_VERSION}|{len(engine.STRING_RULES)}|{len(engine.API_GROUPS)}|{len(engine.KNOWN_BAD_SHA256)}"

    def _load_cache(self):
        try:
            with open(self.cache_path, encoding="utf-8") as f:
                d = json.load(f)
            if d.get("fp") == self._fingerprint() and time.time() - d.get("t", 0) < 30 * 86400:
                return d.get("files", {})
        except Exception:
            pass
        return {}

    def _save_cache(self):
        files = dict(self.cache)
        files.update(self.new_cache)
        try:
            tmp = self.cache_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"fp": self._fingerprint(), "t": time.time(), "files": files}, f, separators=(",", ":"))
            os.replace(tmp, self.cache_path)
        except Exception:
            pass

    # ---------------------------------------------------------------- enumeration
    def _put(self, path, size, mtime, magic, hot=False):
        k = nc(path)
        if k in self._seen:
            return
        self._seen.add(k)
        if k.startswith(self.own_dir + "\\") or (engine.SELF["prefixes"] and k.startswith(engine.SELF["prefixes"])):
            return
        # "|h" = found clean under the stricter hot-folder rules, which also covers the normal rules
        sig = f"{size}|{int(mtime)}" + ("|h" if hot else "")
        cached = self.cache.get(k)
        if cached == sig or (not hot and cached == sig + "|h"):
            self.stats["cached"] += 1
            self.new_cache[k] = cached
            return
        self.stats["found"] += 1
        while not self.stop:
            try:
                self._q.put((path, magic, hot, size, sig), timeout=0.5)
                return
            except queue.Full:
                continue

    def _walk(self, root, max_depth, hot):
        stack = [(root, 0, hot)]
        while stack and not self.stop:
            d, depth, is_hot = stack.pop()
            if nc(d) in SKIP_ABS or nc(d) == self.own_dir:
                continue
            self.stats["dirs"] += 1
            try:
                it = os.scandir(d)
            except OSError:
                continue
            with it:
                for e in it:
                    if self.stop:
                        return
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    attrs = getattr(st, "st_file_attributes", 0)
                    if e.is_dir(follow_symlinks=False):
                        if attrs & FILE_ATTRIBUTE_REPARSE_POINT or depth + 1 > max_depth:
                            continue
                        if e.name.lower() in SKIP_NAMES:
                            continue
                        stack.append((e.path, depth + 1, is_hot and depth < 2))   # deep project trees are not "hot"
                        continue
                    if attrs & CLOUD_ONLY or attrs & FILE_ATTRIBUTE_REPARSE_POINT:
                        continue                       # never trigger OneDrive downloads
                    size = st.st_size
                    if size < 16 or size > MAX_SIZE:
                        continue
                    ext = os.path.splitext(e.name)[1].lower()
                    if ext in SCAN_EXT or (is_hot and ext in HOT_EXT):
                        if not is_hot and (ext in CONTAINER_EXT or
                                           (ext in SCRIPTY and any(x in nc(e.path) for x in APP_CODE))):
                            self.stats["skipped"] += 1
                            continue
                        self._put(e.path, size, st.st_mtime, False, is_hot)
                    elif is_hot or (self.mode != "full" and ext not in MEDIA_EXT and size < 40 * 1024 * 1024
                                    and (not ext or len(ext) > 5)):
                        # disguised executables: look at the first bytes
                        self._put(e.path, size, st.st_mtime, True, is_hot)
                    else:
                        self.stats["skipped"] += 1

    def _enumerate(self):
        try:
            if self.mode in ("quick", "full"):
                self.stats["phase"] = "Checking running programs and startup entries"
                for p in self._memory_targets():
                    try:
                        st = os.stat(p)
                        self._put(p, st.st_size, st.st_mtime, False, self._is_hot(p))
                    except OSError:
                        pass
            self.stats["phase"] = "Scanning files"
            if self.mode == "quick":
                for f, dep in quick_targets():
                    self._walk(f, dep, nc(f) in self.hot)
            elif self.mode == "full":
                for f, dep in quick_targets():            # most likely places first
                    self._walk(f, dep, nc(f) in self.hot)
                for drv in fixed_drives():
                    self._walk(drv, 64, False)
            else:
                for f in self.folders:
                    if os.path.isfile(f):
                        st = os.stat(f)
                        self._put(f, st.st_size, st.st_mtime, False, True)
                    elif os.path.isdir(f):
                        self._walk(f, 64, True)
        finally:
            self.stats["enum_done"] = True

    @staticmethod
    def _memory_targets():
        out = []
        try:
            import psutil
            for p in psutil.process_iter(["exe"]):
                e = p.info.get("exe")
                if e and not sysmon.in_windows_dir(e):
                    out.append(e)
        except Exception:
            pass
        try:
            for e in sysmon.list_autoruns():
                for t in (sysmon.exe_from_command(e["command"]), sysmon.payload_from_command(e["command"])):
                    if t and os.path.isfile(t) and not sysmon.in_windows_dir(t):
                        out.append(t)
        except Exception:
            pass
        return out

    # ---------------------------------------------------------------- main loop
    def run(self):
        th = threading.Thread(target=self._enumerate, daemon=True)
        th.start()
        suspects = []
        pool = None
        try:
            try:
                pool = ProcessPoolExecutor(self.workers, initializer=_init,
                                           initargs=(self.data_dir, engine.SELF['dirs'], engine.SELF['exes']))
            except Exception:
                pool = None
            if pool is None:
                _init(self.data_dir)
                pool = ThreadPoolExecutor(2)
            inflight = {}
            batch, bsz = [], 12
            while not self.stop:
                if self.paused:
                    time.sleep(0.2)
                    continue
                # fill batches from the queue
                try:
                    while len(batch) < bsz:
                        batch.append(self._q.get(timeout=0.05 if inflight else 0.25))
                except queue.Empty:
                    pass
                done_enum = self.stats["enum_done"] and self._q.empty()
                if batch and (len(batch) >= bsz or done_enum or len(inflight) < self.workers):
                    if len(inflight) < self.workers * 3:
                        items = [(p, m, h) for p, m, h, _, _ in batch]
                        try:
                            fut = pool.submit(_scan_batch, items)
                        except Exception:
                            pool = ThreadPoolExecutor(2)
                            _init(self.data_dir)
                            fut = pool.submit(_scan_batch, items)
                        inflight[fut] = batch
                        batch = []
                if inflight:
                    done, _ = wait(list(inflight), timeout=0.05, return_when=FIRST_COMPLETED)
                    for fut in done:
                        b = inflight.pop(fut)
                        sigs = {nc(p): (sig, size, h) for p, _, h, size, sig in b}
                        try:
                            res = fut.result()
                        except Exception as e:           # a worker crashed: redo this batch in-process
                            _init(self.data_dir)
                            res = _scan_batch([(p, m, h) for p, m, h, _, _ in b])
                        for path, score, d, err in res:
                            sig, size, hot = sigs.get(nc(path), ("", 0, False))
                            self.stats["scanned"] += 1
                            self.stats["current"] = path
                            if err:
                                self.stats["errors"] += 1
                                continue
                            if score >= 0:
                                self.stats["bytes"] += size
                            if score < 25:
                                self.new_cache[nc(path)] = sig
                            else:
                                d["hot"] = hot
                                suspects.append(d)
                                self.stats["suspects"] += 1
                elif done_enum and not batch:
                    break
            if pool:
                pool.shutdown(wait=not self.stop, cancel_futures=True)
                pool = None
            if not self.stop and suspects:
                self._verify(suspects)
        finally:
            self.cancelled = self.stop
            if pool:
                pool.shutdown(wait=False, cancel_futures=True)
            self.stop = True
            th.join(2)
            self._save_cache()
        self.stats["phase"] = "Done"
        return self.summary()

    def _verify(self, suspects):
        """Second opinion on suspects: signature + Defender + full engine with the user's settings."""
        self.stats["phase"] = "Verifying suspicious files"
        suspects.sort(key=lambda d: -d["score"])
        # 1. one batched Authenticode check: software signed by a trusted publisher is not reported
        #    unless something definitive (hash database, family signature, disguise) was found
        sigs = {}
        if self.settings.get("check_signature", True):
            pe = [d["target"] for d in suspects if d.get("meta", {}).get("type") == "PE" or os.path.splitext(d["target"])[1].lower() in SIGNABLE]
            try:
                sigs = sysmon.signatures(pe) if pe else {}
            except Exception:
                sigs = {}
        st = dict(self.settings)
        st.update(online_dns=False, follow_redirects=False, check_signature=False)
        fs = engine.FileScanner(st, self.data_dir, engine.LinkScanner(st, self.data_dir))
        deep, rest = [], []
        for d in suspects:
            status, signer = sigs.get(d["target"], ("", ""))
            definitive = any(f["category"] in DEFINITIVE for f in d["findings"])
            if status == "Valid" and not definitive:
                self._report(engine.ScanResult(d["kind"], d["target"], d["name"]), d.get("hot"))   # clean -> cached
                continue
            d["_sig"] = (status, signer)
            (deep if len(deep) < 150 else rest).append(d)

        # 2. Defender + full engine on what is left
        def one(d):
            if self.stop:
                return d, None
            try:
                r = fs.scan(d["target"])
            except Exception:
                return d, engine.ScanResult.from_dict(d)
            status, signer = d["_sig"]
            if status:
                r.meta["signature"] = f"{status}{' - ' + signer if signer else ''}"
                if status == "Valid":
                    r.bonus -= 30
                    r.add(engine.INFO, "Signature", "Valid digital signature", signer)
                elif status == "HashMismatch":
                    r.add(engine.CRIT, "Signature", "Digital signature TAMPERED (file modified after signing)", signer, 70)
                elif status == "NotSigned":
                    r.add(engine.LOW, "Signature", "Unsigned executable", "", 6)
            if os.path.basename(d["target"]).lower() in engine.SYSTEM_NAMES and sysmon.in_windows_dir(d["target"]):
                r.findings = [f for f in r.findings if "system process" not in f.title]
            bonus = r.bonus
            apply_policy(r, d.get("hot", False))
            if bonus < 0:                      # policy keeps only penalties; re-apply trust bonuses
                r.bonus = bonus
                r.finalize()
            return d, r

        self.stats["verify_total"] = len(deep)
        with ThreadPoolExecutor(4) as ex:
            for d, r in ex.map(one, deep):
                self.stats["verified"] += 1
                if r is None:
                    continue
                self.stats["current"] = d["target"]
                self._report(r, d.get("hot"))
        for d in rest:
            self._report(engine.ScanResult.from_dict(d))

    def _report(self, r, hot=False):
        r.meta["trigger"] = f"{self.mode} system scan"
        if r.score < 25:
            try:
                s = os.stat(r.target)
                self.new_cache[nc(r.target)] = f"{s.st_size}|{int(s.st_mtime)}" + ("|h" if hot else "")
            except OSError:
                pass
            return
        if r.verdict == "DANGEROUS":
            self.stats["threats"] += 1
        else:
            self.stats["suspicious"] += 1
        self.detections.append(r)
        if self.on_detect:
            self.on_detect(r)

    def summary(self):
        s = self.stats
        return {"mode": self.mode, "date": s["started"], "duration": time.time() - s["started"],
                "scanned": s["scanned"], "cached": s["cached"], "threats": s["threats"], "suspicious": s["suspicious"],
                "errors": s["errors"], "bytes": s["bytes"], "cancelled": getattr(self, "cancelled", False),
                "detections": [{"name": r.name, "target": r.target, "score": r.score, "verdict": r.verdict}
                               for r in self.detections]}


def load_log(data_dir):
    try:
        with open(os.path.join(data_dir, "scan_log.json"), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_log(data_dir, summary):
    log = load_log(data_dir)
    log.insert(0, summary)
    del log[50:]
    try:
        with open(os.path.join(data_dir, "scan_log.json"), "w", encoding="utf-8") as f:
            json.dump(log, f, ensure_ascii=False, indent=1)
    except Exception:
        pass
