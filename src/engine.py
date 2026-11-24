"""
ECLIPSE - analysis engine
Heuristic static analysis of files (RAT, stealer, malware) and links (phishing).
"""
from __future__ import annotations

import base64
import hashlib
import io
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import struct
import subprocess
import time
import unicodedata
import urllib.error
import urllib.request
import zipfile
from collections import Counter
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse, unquote, parse_qsl, urljoin

try:
    import pefile
except Exception:  # pragma: no cover
    pefile = None


# --------------------------------------------------------------------------- #
#  Self identity: Eclipse contains its own detection rules, so it would flag itself
# --------------------------------------------------------------------------- #
SELF = {"dirs": [], "exes": [], "prefixes": (), "hashes": None}


def path_forms(p):
    """The path as given plus its long and 8.3 short forms (Nuitka reports e.g. 112BA0~1.0 for '1.1.0')."""
    p = os.path.abspath(p)
    out = {p}
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(32768)
        for fn in (ctypes.windll.kernel32.GetLongPathNameW, ctypes.windll.kernel32.GetShortPathNameW):
            n = fn(p, buf, 32768)
            if 0 < n < 32768:
                out.add(buf.value)
    except Exception:
        pass
    return out


def set_self(dirs=(), exes=()):
    """Folders that belong to Eclipse and its executables (copies are recognised by hash)."""
    SELF["dirs"] = [os.path.abspath(d) for d in dirs if d]
    SELF["exes"] = [os.path.abspath(e) for e in exes if e]
    SELF["prefixes"] = tuple({os.path.normcase(f).rstrip("\\/") + os.sep
                              for d in SELF["dirs"] for f in path_forms(d)})
    SELF["hashes"] = None


def is_self_path(path):
    return bool(SELF["prefixes"]) and os.path.normcase(os.path.abspath(path)).startswith(SELF["prefixes"])


def self_hashes():
    if SELF["hashes"] is None:                       # lazy: no cost at startup
        hs = set()
        for e in SELF["exes"]:
            try:
                h = hashlib.sha256()
                with open(e, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                hs.add(h.hexdigest())
            except OSError:
                pass
        SELF["hashes"] = hs
    return SELF["hashes"]

INFO, LOW, MED, HIGH, CRIT = 0, 1, 2, 3, 4
SEV_NAME = {INFO: "INFO", LOW: "LOW", MED: "MEDIUM", HIGH: "HIGH", CRIT: "CRITICAL"}
SEV_SCORE = {INFO: 0, LOW: 5, MED: 15, HIGH: 30, CRIT: 60}
NO_WINDOW = 0x08000000
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0 Safari/537.36")


# --------------------------------------------------------------------------- #
#  Risultati
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    severity: int
    category: str
    title: str
    detail: str = ""
    score: int = 0


@dataclass
class ScanResult:
    kind: str                     # "file" | "link"
    target: str
    name: str
    score: int = 0
    verdict: str = "SAFE"
    findings: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    bonus: int = 0

    def add(self, severity, category, title, detail="", score=None):
        if score is None:
            score = SEV_SCORE[severity]
        for f in self.findings:            # niente duplicati
            if f.title == title and f.detail == detail[:400]:
                return
        self.findings.append(Finding(severity, category, title, str(detail)[:400], score))

    def top_severity(self):
        return max([f.severity for f in self.findings], default=INFO)

    def finalize(self):
        raw = sum(f.score for f in self.findings)
        top = self.top_severity()
        if top >= CRIT:
            raw = max(raw, 85)
        elif top >= HIGH:
            raw = max(raw, 45)
        raw += self.bonus
        self.score = int(max(0, min(100, raw)))
        if self.score >= 60:
            self.verdict = "DANGEROUS"
        elif self.score >= 25:
            self.verdict = "SUSPICIOUS"
        else:
            self.verdict = "SAFE"
        self.findings.sort(key=lambda f: (-f.severity, -f.score))
        return self

    def to_dict(self):
        d = asdict(self)
        return d

    @staticmethod
    def from_dict(d):
        r = ScanResult(d["kind"], d["target"], d["name"])
        r.score = d.get("score", 0)
        r.verdict = d.get("verdict", "SAFE")
        r.verdict = {"SICURO": "SAFE", "SOSPETTO": "SUSPICIOUS", "PERICOLOSO": "DANGEROUS"}.get(r.verdict, r.verdict)
        r.meta = d.get("meta", {})
        r.timestamp = d.get("timestamp", time.time())
        r.findings = [Finding(**f) for f in d.get("findings", [])]
        return r

    def report_text(self):
        lines = [
            "=" * 64,
            "  ECLIPSE THREAT REPORT",
            "=" * 64,
            f"Type       : {'File' if self.kind == 'file' else 'Link'}",
            f"Target     : {self.target}",
            f"Date       : {time.strftime('%d/%m/%Y %H:%M:%S', time.localtime(self.timestamp))}",
            f"Score      : {self.score}/100",
            f"Verdict    : {self.verdict}",
            "",
        ]
        if self.meta:
            lines.append("-- Details " + "-" * 53)
            for k, v in self.meta.items():
                if isinstance(v, (list, dict)):
                    v = json.dumps(v, ensure_ascii=False)
                lines.append(f"{k:<14}: {v}")
            lines.append("")
        lines.append("-- Findings " + "-" * 52)
        if not self.findings:
            lines.append("No indicators detected.")
        for f in self.findings:
            lines.append(f"[{SEV_NAME[f.severity]:<7}] ({f.category}) {f.title}")
            if f.detail:
                lines.append(f"           {f.detail}")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
#  Utility
# --------------------------------------------------------------------------- #
def entropy(data: bytes, sample: int = 1 << 20) -> float:
    if len(data) > sample:                       # head + middle + tail sample
        third = sample // 3
        mid = len(data) // 2
        data = data[:third] + data[mid:mid + third] + data[-third:]
    n = len(data)
    if not n:
        return 0.0
    ent = 0.0
    for c in Counter(data).values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def str_entropy(s: str) -> float:
    if not s:
        return 0.0
    ent = 0.0
    for ch in set(s):
        p = s.count(ch) / len(s)
        ent -= p * math.log2(p)
    return ent


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def human_size(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"


ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")


def extract_text(data: bytes) -> str:
    a = b"\n".join(ASCII_RE.findall(data)).decode("latin-1")
    u = "\n".join(m.decode("utf-16le", "ignore") for m in UTF16_RE.findall(data))
    return a + "\n" + u


def _http_get_json(url, headers, timeout=12):
    req = urllib.request.Request(url, headers={"User-Agent": "Eclipse-Scanner", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "ignore"))


# --------------------------------------------------------------------------- #
#  Firme e indicatori per i FILE
# --------------------------------------------------------------------------- #
MAGIC = [
    (b"MZ", "PE"), (b"PK\x03\x04", "ZIP"), (b"%PDF", "PDF"),
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "OLE"), (b"Rar!", "RAR"),
    (b"7z\xBC\xAF\x27\x1C", "7Z"), (b"\x4C\x00\x00\x00\x01\x14\x02\x00", "LNK"),
    (b"\x7fELF", "ELF"), (b"\xCA\xFE\xBA\xBE", "MACHO/CLASS"), (b"\x89PNG", "PNG"),
    (b"\xFF\xD8\xFF", "JPEG"), (b"GIF8", "GIF"), (b"\x1f\x8b", "GZIP"),
    (b"MSCF", "CAB"), (b"{\\rtf", "RTF"), (b"ID3", "MP3"),
]

DANGEROUS_EXT = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".msi", ".msp", ".jar", ".lnk", ".dll",
    ".cpl", ".reg", ".iso", ".img", ".vhd", ".vhdx", ".apk", ".sys", ".appx",
    ".msix", ".chm", ".inf", ".url", ".scf", ".xll", ".gadget", ".application", ".py",
    ".pyw", ".appref-ms", ".msc",
}
SCRIPT_EXT = {".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".ps1", ".psm1",
              ".hta", ".py", ".pyw", ".sh", ".reg", ".url", ".scf", ".inf"}
DECOY_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg",
             ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".avi", ".mkv", ".rtf", ".csv",
             ".odt", ".zip", ".rar", ".bmp", ".wav", ".mov", ".webp"}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam", ".xlsb"}
MEDIA_TYPES = {"PNG", "JPEG", "GIF", "MP3", "GZIP", "CAB", "RAR", "7Z"}

SYSTEM_NAMES = {"svchost.exe", "csrss.exe", "lsass.exe", "winlogon.exe", "explorer.exe",
                "services.exe", "smss.exe", "spoolsv.exe", "taskhost.exe", "taskhostw.exe",
                "dllhost.exe", "rundll32.exe", "conhost.exe", "wininit.exe", "lsm.exe",
                "runtimebroker.exe", "sihost.exe", "ctfmon.exe", "dwm.exe", "msmpeng.exe"}

PACKER_SECTIONS = {"upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".aspack": "ASPack",
                   ".adata": "ASPack", ".mpress1": "MPRESS", ".mpress2": "MPRESS",
                   ".themida": "Themida", ".winlice": "WinLicense", ".vmp0": "VMProtect",
                   ".vmp1": "VMProtect", ".enigma1": "Enigma", ".enigma2": "Enigma",
                   ".petite": "Petite", "nsp0": "NsPack", "nsp1": "NsPack",
                   ".packed": "Packer", "pec2": "PECompact", ".nsp0": "NsPack",
                   ".perplex": "Perplex", ".yp": "Y0da", "mew": "MEW", ".boom": "Boom"}

# (categoria, titolo, gravita', regex)
STRING_RULES = [
    # --- famiglie RAT note ---
    ("RAT", "AsyncRAT signature", CRIT, r"asyncrat|async_rat"),
    ("RAT", "QuasarRAT signature", CRIT, r"quasar\.client|quasarrat|quasar\.common"),
    ("RAT", "njRAT / Bladabindi signature", CRIT, r"njrat|bladabindi|\|'\|'\|"),
    ("RAT", "DarkComet signature", CRIT, r"darkcomet|dc_mutex-"),
    ("RAT", "Remcos signature", CRIT, r"remcos|breaking-security\.net"),
    ("RAT", "NanoCore signature", CRIT, r"nanocore"),
    ("RAT", "DCRat (DarkCrystal) signature", CRIT, r"\bdcrat\b|darkcrystal"),
    ("RAT", "XWorm signature", CRIT, r"xworm"),
    ("RAT", "VenomRAT signature", CRIT, r"venom\s?rat"),
    ("RAT", "Warzone / AveMaria signature", CRIT, r"ave_maria|warzone\s?rat"),
    ("RAT", "Orcus / LimeRAT / BitRAT signature", CRIT, r"orcus\.shared|\blimerat\b|\bbitrat\b"),
    ("RAT", "Gh0st / PlugX / NetWire signature", CRIT, r"gh0st|plugx|netwire"),
    ("Stealer", "Known infostealer signature", CRIT,
     r"redline\s?stealer|raccoon\s?stealer|\bvidar\b|lumma(?:c2)?\b|\bstealc\b|agent\.?tesla|"
     r"\bformbook\b|\bazorult\b|meta\s?stealer|\brisepro\b|blank\s?grabber|empyrean\s?grabber|luna\s?grabber|"
     r"\brhadamanthys\b|atomic\s?stealer|mystic\s?stealer"),
    # --- comportamenti stealer ---
    ("Stealer", "Accesses passwords saved in the browser", HIGH,
     r"\\login data|logins\.json|key4\.db|encrypted_key"),
    ("Stealer", "Accesses browser cookies", MED, r"\\network\\cookies|cookies\.sqlite"),
    ("Stealer", "Discord token theft", CRIT,
     r"dQw4w9WgXcQ:|discord\\local storage\\leveldb|discordcanary\\local storage|discordptb\\local storage"),
    ("Stealer", "Telegram session theft", HIGH, r"telegram desktop\\tdata"),
    ("Stealer", "Crypto wallet theft", HIGH,
     r"wallet\.dat|exodus\\exodus\.wallet|electrum\\wallets|nkbihfbeogaeaoehlefnkodbefgpgknn|atomic\\local storage"),
    # --- C2 / esfiltrazione ---
    ("C2", "Discord webhook (data exfiltration)", HIGH, r"discord(?:app)?\.com/api/webhooks/\d+/[\w-]+"),
    ("C2", "Telegram bot (C2/exfiltration channel)", HIGH, r"api\.telegram\.org/bot"),
    ("C2", "Payload hosted on paste services", MED,
     r"pastebin\.com/raw|paste\.ee/r/|hastebin\.com/raw|rentry\.co/\w+/raw"),
    ("C2", "ngrok tunnel / dynamic DNS (typical of RATs)", HIGH,
     r"\.ngrok(?:-free)?\.(?:io|app|dev)|tcp\.ngrok|duckdns\.org|\.ddns\.net|no-ip\.(?:org|biz|info)|"
     r"hopto\.org|zapto\.org|sytes\.net|serveo\.net|portmap\.(?:io|host)|playit\.gg"),
    ("C2", "Hardcoded IP:port address", MED,
     r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d):\d{2,5}\b"),
    # --- persistenza ---
    ("Persistence", "Autostart via registry (Run key)", MED,
     r"software\\microsoft\\windows\\currentversion\\run"),
    ("Persistence", "Creates a scheduled task", MED, r"schtasks(?:\.exe)?\s+/create"),
    ("Persistence", "Copies itself to the Startup folder", MED,
     r"\\start menu\\programs\\startup|shell:startup"),
    ("Persistence", "Modifies Winlogon / IFEO", HIGH, r"winlogon\\(?:shell|userinit)|image file execution options"),
    # --- evasione ---
    ("Evasion", "Disables/excludes Windows Defender", CRIT,
     r"add-mppreference\s+-exclusion|set-mppreference\s+-disable|disableantispyware|disablerealtimemonitoring"),
    ("Evasion", "Disables the firewall", HIGH, r"netsh\s+(?:adv)?firewall\s+(?:set|add)"),
    ("Ransomware", "Deletes shadow copies / backups", CRIT,
     r"vssadmin(?:\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|recoveryenabled\s+no|wbadmin\s+delete"),
    ("Evasion", "Clears system logs", HIGH, r"wevtutil(?:\.exe)?\s+cl\b"),
    ("Evasion", "VM / sandbox detection (anti-analysis)", MED,
     r"sbiedll\.dll|vboxservice|vmtoolsd|vboxhook|cuckoomon|wine_get_unix_file_name"),
    ("Evasion", "Checks for analysis tools", MED,
     r"wireshark|processhacker|x64dbg|ollydbg|dnspy|ida64\.exe"),
    ("Evasion", "Known .NET obfuscator", MED,
     r"confuserex|confused by|\.net reactor|smartassembly|babelobfuscator|eazfuscator"),
    ("Privileges", "Bypass UAC", HIGH,
     r"fodhelper|computerdefaults\.exe|ms-settings\\shell\\open\\command|sdclt\.exe"),
    # --- download & esecuzione ---
    ("Execution", "PowerShell with encoded command", HIGH,
     r"powershell[^\n]{0,80}\s-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{40,}"),
    ("Execution", "PowerShell in hidden window", HIGH, r"-w(?:indowstyle)?\s+hidden|-w\s+h\b"),
    ("Execution", "In-memory download and execution (IEX)", CRIT,
     r"\biex\s*\(|invoke-expression|downloadstring\(|\.downloaddata\("),
    ("Execution", "Downloads files from the Internet", MED,
     r"downloadfile\(|invoke-webrequest|start-bitstransfer|urldownloadtofile"),
    ("Execution", "LOLBin abuse (certutil / bitsadmin / mshta / regsvr32)", HIGH,
     r"certutil(?:\.exe)?\s+-urlcache|certutil(?:\.exe)?\s+-decode|bitsadmin(?:\.exe)?\s+/transfer|"
     r"mshta(?:\.exe)?\s+(?:https?|vbscript|javascript)|regsvr32(?:\.exe)?\s+/s\s+/n\s+/u\s+/i:|rundll32(?:\.exe)?\s+javascript:"),
    ("Execution", "Runtime Base64 decoding", LOW, r"frombase64string|\batob\(|base64_decode|b64decode"),
    ("Execution", "Scripting COM objects (WScript / Shell)", MED,
     r"wscript\.shell|shell\.application|adodb\.stream|msxml2\.xmlhttp|winhttp\.winhttprequest"),
    ("Execution", "Follina exploit (ms-msdt)", CRIT, r"ms-msdt:"),
    # --- spionaggio ---
    ("Spying", "Keylogger (keystroke logging)", HIGH,
     r"\[(?:enter|backspace|capslock|ctrl|bksp)\]|wh_keyboard_ll|keylogger|keyboard hook"),
    ("Spying", "Webcam capture", HIGH, r"capcreatecapturewindow|webcam\s?capture|avicap32"),
    ("Spying", "Screen capture", LOW, r"copyfromscreen|take_?screenshot"),
    ("Spying", "Microphone recording", MED, r"waveinopen|record\s+mic"),
    ("Remote", "Reverse remote shell", HIGH, r"reverse.?shell|/bin/sh -i|nc(?:\.exe)?\s+-e\s"),
    ("Remote", "Hidden remote desktop (HVNC)", CRIT, r"\bhvnc\b|hidden.?vnc"),
    # --- altro ---
    ("Ransomware", "Ransom note", CRIT,
     r"your (?:files|documents) (?:have been|are) encrypted|i tuoi file sono stati (?:crittografati|cifrati)|"
     r"how to recover your files|decrypt(?:ion)? key[^\n]{0,60}bitcoin"),
    ("Miner", "Cryptominer", HIGH, r"stratum\+(?:tcp|ssl)://|xmrig|cryptonight|nicehash|minexmr|moneroocean"),
    ("Test", "EICAR antivirus test file", CRIT, r"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"),
]
try:
    import re._parser as _srep
    import re._constants as _srec
except ImportError:  # pragma: no cover
    import sre_parse as _srep
    import sre_constants as _srec


def _needles(pattern):
    """Literal strings of which at least one must appear for `pattern` to match (None = no safe prefilter)."""
    def seq(items):
        cands, run = [], []

        def flush():
            if run:
                cands.append(["".join(run)])
                run.clear()
        for op, av in items:
            if op is _srec.LITERAL:
                run.append(chr(av))
                continue
            flush()
            if op is _srec.BRANCH:
                subs = [seq(list(b)) for b in av[1]]
                if all(subs):
                    cands.append([x for sub in subs for x in sub])
            elif op is _srec.SUBPATTERN:
                sub = seq(list(av[-1]))
                if sub:
                    cands.append(sub)
            elif op in (_srec.MAX_REPEAT, _srec.MIN_REPEAT) and av[0] >= 1:
                sub = seq(list(av[2]))
                if sub:
                    cands.append(sub)
        flush()
        good = [c for c in cands if min(len(x) for x in c) >= 2]
        return max(good, key=lambda c: min(len(x) for x in c)) if good else None
    try:
        return seq(list(_srep.parse(pattern)))
    except Exception:
        return None


# rules run on lower-cased text: patterns are lower-cased too (they contain no upper-case escapes)
STRING_RULES_C = [(c, t, s, re.compile(p.lower()), _needles(p.lower())) for c, t, s, p in STRING_RULES]

API_GROUPS = [
    ("Injection", "Code injection APIs (into other processes)",
     ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection",
      "ZwUnmapViewOfSection", "SetThreadContext", "QueueUserAPC", "RtlCreateUserThread",
      "NtWriteVirtualMemory", "NtCreateThreadEx"], 3),
    ("Spying", "Typical keylogger APIs",
     ["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyboardState", "MapVirtualKey", "GetKeyState"], 2),
    ("Evasion", "API anti-debug",
     ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugString"], 2),
]
API_RE = {name: re.compile(r"\b" + name) for _, _, names, _ in API_GROUPS for name in names}

KNOWN_BAD_SHA256 = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR test file",
}


# --------------------------------------------------------------------------- #
#  Decompressione macro VBA (MS-OVBA)
# --------------------------------------------------------------------------- #
def ovba_decompress(buf: bytes, start: int) -> bytes:
    out = bytearray()
    if start >= len(buf) or buf[start] != 1:
        return b""
    pos, n = start + 1, len(buf)
    try:
        while pos + 2 <= n and len(out) < 2_000_000:
            header = struct.unpack_from("<H", buf, pos)[0]
            pos += 2
            size = (header & 0x0FFF) + 3
            if (header >> 12) & 0x7 != 0b011:
                break
            chunk_end = min(pos + size - 2, n)
            dstart = len(out)
            if not (header >> 15) & 1:
                out += buf[pos:pos + 4096]
                pos += 4096
                continue
            while pos < chunk_end:
                flags = buf[pos]
                pos += 1
                for bit in range(8):
                    if pos >= chunk_end:
                        break
                    if not (flags >> bit) & 1:
                        out.append(buf[pos])
                        pos += 1
                    else:
                        if pos + 2 > chunk_end:
                            pos = chunk_end
                            break
                        tok = struct.unpack_from("<H", buf, pos)[0]
                        pos += 2
                        d = len(out) - dstart
                        if d < 1:
                            return bytes(out)
                        bc = max(4, (d - 1).bit_length())
                        length = (tok & (0xFFFF >> bc)) + 3
                        offset = (tok >> (16 - bc)) + 1
                        if offset > len(out):
                            return bytes(out)
                        for _ in range(length):
                            out.append(out[-offset])
            pos = chunk_end
    except Exception:
        pass
    return bytes(out)


def extract_vba(buf: bytes) -> str:
    sources = []
    for m in re.finditer(rb"\x00Attribut", buf):
        start = m.start() - 3
        if start >= 0 and buf[start] == 1:
            src = ovba_decompress(buf, start)
            if src:
                sources.append(src.decode("latin-1", "ignore"))
        if len(sources) > 40:
            break
    return "\n".join(sources)


# --------------------------------------------------------------------------- #
#  Integrazioni Windows
# --------------------------------------------------------------------------- #
def find_mpcmdrun():
    cands = []
    plat = r"C:\ProgramData\Microsoft\Windows Defender\Platform"
    if os.path.isdir(plat):
        for d in sorted(os.listdir(plat), reverse=True):
            p = os.path.join(plat, d, "MpCmdRun.exe")
            if os.path.isfile(p):
                cands.append(p)
    cands.append(os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                              "Windows Defender", "MpCmdRun.exe"))
    for c in cands:
        if os.path.isfile(c):
            return c
    return None


def defender_scan(path):
    exe = find_mpcmdrun()
    if not exe:
        return "missing", []
    path = os.path.normpath(os.path.abspath(path))
    try:
        r = subprocess.run([exe, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"],
                           capture_output=True, timeout=240, creationflags=NO_WINDOW)
    except subprocess.TimeoutExpired:
        return "error", ["timeout"]
    except Exception as e:
        return "error", [str(e)]
    out = (r.stdout or b"").decode("utf-8", "ignore") + (r.stderr or b"").decode("utf-8", "ignore")
    if not os.path.exists(path):
        # il file e' sparito durante la scansione: la protezione in tempo reale l'ha rimosso
        return "threat", ["removed by real-time protection"]
    threats = sorted(set(re.findall(r"\b[A-Za-z]+:[A-Za-z0-9]+/[\w.!\-]+", out)))
    threats = [t for t in threats if not t.lower().startswith(("http:", "https:", "file:"))]
    if threats:
        return "threat", threats
    hr = re.search(r"failed with hr\s*=\s*(0x[0-9a-f]+)", out, re.I)
    if hr:
        return "error", [f"MpCmdRun error {hr.group(1)}"]
    if r.returncode == 2:
        return "threat", []
    if r.returncode == 0:
        return "clean", []
    return "error", [out.strip()[-200:] or f"code {r.returncode}"]


def authenticode(path):
    p = path.replace("'", "''")
    cmd = ("$s=Get-AuthenticodeSignature -LiteralPath '%s'; "
           "$n=''; if($s.SignerCertificate){$n=$s.SignerCertificate.Subject}; "
           "Write-Output ($s.Status.ToString()+'|'+$n)") % p
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                           capture_output=True, timeout=25, creationflags=NO_WINDOW)
        out = r.stdout.decode("utf-8", "ignore").strip().splitlines()
        if not out:
            return None, ""
        status, _, subj = out[-1].partition("|")
        m = re.search(r"CN=([^,]+)", subj)
        return status.strip(), (m.group(1).strip('" ') if m else subj)
    except Exception:
        return None, ""


def zone_identifier(path):
    try:
        with open(path + ":Zone.Identifier", "r", encoding="utf-8", errors="ignore") as f:
            txt = f.read()
    except Exception:
        return None
    z = re.search(r"ZoneId=(\d)", txt)
    host = re.search(r"HostUrl=(.+)", txt)
    ref = re.search(r"ReferrerUrl=(.+)", txt)
    return {"zone": int(z.group(1)) if z else None,
            "host": host.group(1).strip() if host else "",
            "referrer": ref.group(1).strip() if ref else ""}


# --------------------------------------------------------------------------- #
#  SCANNER FILE
# --------------------------------------------------------------------------- #
MAX_READ = 48 * 1024 * 1024
MAX_STR = 24 * 1024 * 1024


class FileScanner:
    def __init__(self, settings=None, data_dir=None, link_scanner=None):
        self.s = settings or {}
        self.max_read = int(self.s.get("max_read", MAX_READ))
        self.max_str = int(self.s.get("max_str", MAX_STR))
        self.data_dir = data_dir
        self.links = link_scanner
        self.bad_hashes = dict(KNOWN_BAD_SHA256)
        if data_dir:
            hp = os.path.join(data_dir, "hash_blacklist.txt")
            if os.path.isfile(hp):
                with open(hp, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        h = line.strip().split()[0].lower() if line.strip() else ""
                        if re.fullmatch(r"[0-9a-f]{64}", h):
                            self.bad_hashes[h] = "local blacklist"

    # ---------------------------------------------------------------- main
    @staticmethod
    def _self_result(res):
        res.meta["signature"] = "Eclipse"
        res.meta["type"] = res.meta.get("type") or "Eclipse component"
        res.add(INFO, "Trusted", "Part of Eclipse itself", "its own detection rules are not a threat")
        return res.finalize()

    def scan(self, path, step=None):
        step = step or (lambda msg: None)
        name = os.path.basename(path)
        res = ScanResult("file", path, name)
        try:
            size = os.path.getsize(path)
        except OSError as e:
            res.add(MED, "Error", "Unable to read the file", str(e))
            return res.finalize()
        res.meta["size"] = human_size(size)
        if is_self_path(path):
            return self._self_result(res)

        step("Computing cryptographic hashes")
        md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
        data = bytearray()
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(1 << 20)
                    if not chunk:
                        break
                    md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
                    if len(data) < self.max_read:
                        data += chunk[:self.max_read - len(data)]
        except PermissionError as e:
            res.add(MED, "Error", "Access denied (file locked or already quarantined?)", str(e))
            return res.finalize()
        except OSError as e:
            res.add(MED, "Error", "Read failed", str(e))
            return res.finalize()
        data = bytes(data)
        res.meta["sha256"] = sha256.hexdigest()
        res.meta["sha1"] = sha1.hexdigest()
        res.meta["md5"] = md5.hexdigest()

        sh = res.meta["sha256"]
        if sh in self_hashes():                      # a copy of Eclipse.exe somewhere else
            return self._self_result(res)
        if sh in self.bad_hashes:
            res.add(CRIT, "Database", "Hash found in the threat database", self.bad_hashes[sh], 90)

        step("Analyzing file name")
        self._name_checks(name, res)

        z = zone_identifier(path)
        if z and z.get("zone") in (3, 4):
            res.meta["origin"] = z.get("host") or z.get("referrer") or "Internet"
            res.add(INFO, "Origin", "File downloaded from the Internet (Mark-of-the-Web)",
                    z.get("host") or z.get("referrer") or "")

        signed = False
        if data[:2] == b"MZ" and self.s.get("check_signature", True):
            step("Verifying digital signature")
            status, signer = authenticode(path)
            res.meta["signature"] = f"{status or 'n/d'}{' - ' + signer if signer else ''}"
            if status == "Valid":
                signed = True
                res.bonus -= 30
                res.add(INFO, "Signature", "Valid digital signature", signer)
            elif status == "HashMismatch":
                res.add(CRIT, "Signature", "Digital signature TAMPERED (file modified after signing)", signer, 70)
            elif status in ("NotTrusted", "UnknownError"):
                res.add(MED, "Signature", "Untrusted digital signature", f"{status} {signer}")
            elif status == "NotSigned":
                res.add(LOW, "Signature", "Unsigned executable", "", 6)

        step("Static content analysis")
        self._scan_bytes(data, name, res, 0, signed, path)

        if self.s.get("use_defender", True):
            step("Scanning with Windows Defender")
            st, info = defender_scan(path)
            if st == "threat":
                res.add(CRIT, "Defender", "Windows Defender detected a threat",
                        ", ".join(info) or "threat detected", 95)
                res.meta["defender"] = ", ".join(info) or "THREAT"
            elif st == "clean":
                res.meta["defender"] = "no threats"
                res.bonus -= 8
                res.add(INFO, "Defender", "Windows Defender: no threats")
            elif st == "missing":
                res.meta["defender"] = "not available"
            else:
                res.meta["defender"] = "error"
                res.add(INFO, "Defender", "Defender scan failed", ", ".join(info))

        key = (self.s.get("vt_key") or "").strip()
        if key:
            step("Querying VirusTotal")
            self._virustotal(sh, key, res)

        return res.finalize()

    # ---------------------------------------------------------------- nome
    def _name_checks(self, name, res):
        low = name.lower()
        if "\u202e" in name or "\u202d" in name:
            res.add(CRIT, "Deception", "RTLO character in name (spoofed extension)", repr(name), 70)
        parts = low.split(".")
        ext = "." + parts[-1] if len(parts) > 1 else ""
        if len(parts) >= 3 and ext in DANGEROUS_EXT and "." + parts[-2] in DECOY_EXT:
            res.add(HIGH, "Deception", "Deceptive double extension", name, 40)
        if re.search(r"\s{5,}\.\w+$", name):
            res.add(HIGH, "Deception", "Multiple spaces hiding the extension", name, 35)
        if ext in MACRO_EXT:
            res.add(MED, "Macro", "Macro-enabled Office document", ext)
        elif ext in DANGEROUS_EXT:
            res.add(LOW, "Type", "Potentially executable file type", ext, 6)
        if low in SYSTEM_NAMES:
            res.add(HIGH, "Deception", "Name identical to a Windows system process", name, 35)
        bait = re.search(r"(crack|keygen|cheat|hack|free.?robux|aimbot|loader|injector|spoofer|"
                         r"nitro.?gen|activator|kmspico|patch)", low)
        if bait:
            res.add(MED, "Bait", "Name typical of malware bait (crack/cheat/generator)", bait.group(1), 15)

    # ---------------------------------------------------------------- contenuto
    def _scan_bytes(self, data, name, res, depth, signed=False, path=None):
        ext = os.path.splitext(name.lower())[1]
        ftype = "UNKNOWN"
        for magic, t in MAGIC:
            if data.startswith(magic):
                ftype = t
                break
        if ftype == "UNKNOWN" and ext in SCRIPT_EXT:
            ftype = "SCRIPT"
        elif ftype == "UNKNOWN":
            try:
                data[:4096].decode("utf-8")
                ftype = "TEXT"
            except UnicodeDecodeError:
                pass
        if depth == 0:
            res.meta["type"] = ftype

        # estensione non coerente col contenuto
        if ftype == "PE" and ext not in {".exe", ".dll", ".scr", ".sys", ".cpl", ".com", ".ocx",
                                         ".drv", ".efi", ".mui", ".pyd", ".node", ".ax", ".tmp", ".bin", ".xll", ".winmd",
                                         ".mun", ".acm", ".tlb", ".tsp", ".api", ".lex", ".fae"}:
            res.add(CRIT, "Deception", "Executable disguised as another file type",
                    f"extension {ext or '(none)'} but PE/EXE content", 65)
        if ftype == "LNK" and ext != ".lnk":
            res.add(HIGH, "Deception", "Disguised LNK shortcut", ext)

        # PE incorporato in file non eseguibile
        if ftype not in ("PE",) and depth == 0:
            idx = data.find(b"This program cannot be run in DOS mode")
            if idx > 64:
                res.add(HIGH, "Payload", "Executable hidden inside the file",
                        f"offset {idx}", 40)

        is_code = ftype in ("PE", "SCRIPT", "TEXT", "LNK", "OLE", "ELF", "MACHO/CLASS", "UNKNOWN", "RTF")
        if ftype not in MEDIA_TYPES and ftype != "ZIP":
            text = extract_text(data[:self.max_str])
            self._string_rules(text, res, signed, is_code)
        else:
            text = ""

        if ftype == "PE":
            self._analyze_pe(data, res, name, signed, path)
        elif ftype == "ZIP":
            self._analyze_zip(data, name, res, depth)
        elif ftype == "OLE":
            self._analyze_ole(data, res)
        elif ftype == "PDF":
            self._analyze_pdf(data, res)
        elif ftype == "RTF":
            if re.search(rb"\\objdata|\\objupdate|\\objautlink", data[:MAX_STR], re.I):
                res.add(HIGH, "Exploit", "RTF with embedded OLE objects (exploit vector)", "", 35)
        elif ftype == "LNK":
            if re.search(r"powershell|cmd(?:\.exe)?\s*/c|mshta|wscript|cscript|rundll32|bitsadmin|certutil", text, re.I):
                res.add(HIGH, "Execution", "LNK shortcut that runs commands/scripts", "", 40)
        elif ftype in ("SCRIPT", "TEXT") or ext in SCRIPT_EXT:
            self._analyze_script(text, res, ext)
        elif ftype in ("RAR", "7Z", "CAB"):
            res.add(INFO, "Archive", f"{ftype} archive: contents cannot be inspected statically",
                    "Check delegated to Windows Defender")
        if ext in (".iso", ".img", ".vhd", ".vhdx"):
            res.add(MED, "Evasion", "Disk image (used to bypass Windows protections)", ext)

        if ftype in ("UNKNOWN",) and len(data) > 4096:
            e = entropy(data[:4 * 1024 * 1024])
            res.meta.setdefault("entropy", round(e, 2))
            if e > 7.6 and ext not in DECOY_EXT:
                res.add(LOW, "Obfuscation", "Unrecognized encrypted or compressed content", f"entropy {e:.2f}", 8)

    # ---------------------------------------------------------------- stringhe
    def _string_rules(self, text, res, signed, is_code):
        tl = text.lower()
        for cat, title, sev, rx, needles in STRING_RULES_C:
            if not is_code and cat in ("Evasion", "Spying", "Privileges"):
                continue
            if needles and not any(n in tl for n in needles):
                continue
            m = rx.search(tl)
            if m:
                sample = m.group(0).strip()[:90]
                if signed and sev >= HIGH and cat not in ("RAT", "Stealer", "Test", "Ransomware"):
                    sev = MED
                res.add(sev, cat, title, f'found: "{sample}"')
        if not is_code:
            return
        for cat, title, names, thr in API_GROUPS:
            hits = [n for n in names if n in text and API_RE[n].search(text)]
            if len(hits) >= thr:
                sev = HIGH if cat in ("Injection", "Spying") else LOW
                if signed:
                    sev = min(sev, LOW)
                res.add(sev, cat, title, ", ".join(hits))
            elif cat == "Injection" and len(hits) == 2 and not signed:
                res.add(LOW, cat, "Some APIs used for code injection", ", ".join(hits))

    # ---------------------------------------------------------------- PE
    def _analyze_pe(self, data, res, name, signed, path):
        if pefile is None:
            return
        try:
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
            ])
        except Exception as e:
            res.add(MED, "PE", "Malformed or corrupted PE structure", str(e)[:120])
            return
        try:
            is_dll = pe.is_dll()
            arch = "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86" if pe.FILE_HEADER.Machine == 0x14c else hex(pe.FILE_HEADER.Machine)
            dotnet = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0
            res.meta["format"] = f"{'DLL' if is_dll else 'EXE'} {arch}{' .NET' if dotnet else ''}"
            ts = pe.FILE_HEADER.TimeDateStamp
            if ts > time.time() + 86400 * 2:
                res.add(LOW, "PE", "Compile date in the future (forged)",
                        time.strftime("%Y-%m-%d", time.gmtime(ts)), 5)
            elif ts:
                res.meta["compiled"] = time.strftime("%Y-%m-%d", time.gmtime(ts))

            # sezioni
            packers, high_ent, wx = set(), [], []
            for s in pe.sections:
                sname = s.Name.rstrip(b"\x00").decode("latin-1", "ignore")
                if sname.lower() in PACKER_SECTIONS:
                    packers.add(PACKER_SECTIONS[sname.lower()])
                ent = entropy(s.get_data()[:262144], 262144) if s.SizeOfRawData else 0.0
                if ent > 7.2 and s.SizeOfRawData > 2048:
                    high_ent.append(f"{sname or '?'} ({ent:.2f})")
                ch = s.Characteristics
                if ch & 0x20000000 and ch & 0x80000000:
                    wx.append(sname or "?")
            if packers:
                res.add(MED if signed else HIGH, "Obfuscation", "Executable compressed/protected by a packer",
                        ", ".join(sorted(packers)), 20 if signed else 30)
            if high_ent:
                res.add(LOW if signed else MED, "Obfuscation", "High-entropy sections (encrypted code)",
                        ", ".join(high_ent[:4]))
            if wx:
                res.add(LOW if signed else MED, "PE", "Writable and executable sections (self-modifying)", ", ".join(wx[:4]))

            # import
            n_imp, dlls = 0, []
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
                dlls.append(entry.dll.decode("latin-1", "ignore").lower())
                n_imp += len(entry.imports)
            if not dotnet and n_imp < 8 and not is_dll and len(data) > 30_000:
                res.add(MED if not signed else LOW, "Obfuscation",
                        "Very few imported functions (typical of packed malware)", f"{n_imp} import")
            if "avicap32.dll" in dlls:
                res.add(HIGH, "Spying", "Imports webcam capture library (avicap32)", "", 30)

            # overlay
            ov = pe.get_overlay_data_start_offset()
            if ov and len(data) - ov > 512 * 1024:
                oe = entropy(data[ov:ov + 2 * 1024 * 1024])
                if oe > 7.5 and not signed:
                    res.add(LOW, "Payload", "Large encrypted data block appended to the executable",
                            f"{human_size(len(data) - ov)}, entropy {oe:.2f}", 8)

            # version info
            info = {}
            try:
                for fi in getattr(pe, "FileInfo", []) or []:
                    for entry in fi:
                        for st in getattr(entry, "StringTable", []) or []:
                            for k, v in st.entries.items():
                                info[k.decode("latin-1", "ignore")] = v.decode("latin-1", "ignore")
            except Exception:
                pass
            if info.get("CompanyName"):
                res.meta["company"] = info["CompanyName"][:60]
            if info.get("ProductName"):
                res.meta["product"] = info["ProductName"][:60]
            comp = info.get("CompanyName", "").lower()
            has_sig = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size > 0
            if not signed and not has_sig and any(b in comp for b in ("microsoft", "google", "adobe", "apple", "nvidia", "intel")):
                res.add(HIGH, "Deception", "Claims a well-known vendor but is not signed",
                        info.get("CompanyName", ""), 35)
            if path and name.lower() in SYSTEM_NAMES and not path.lower().startswith(r"c:\windows"):
                res.add(HIGH, "Deception", "System process outside the Windows folder", path, 35)
            if dotnet and not signed:
                res.add(INFO, "PE", "Unsigned .NET application (common language for RATs)")
        finally:
            del pe          # built from bytes: close() would only trigger a slow gc.collect()

    # ---------------------------------------------------------------- ZIP / OOXML
    def _analyze_zip(self, data, name, res, depth):
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            infos = zf.infolist()
        except Exception:
            res.add(LOW, "Archive", "Damaged or truncated ZIP archive")
            return
        names = [i.filename for i in infos]
        lnames = [n.lower() for n in names]

        # --- documenti Office OOXML ---
        if "[content_types].xml" in lnames:
            res.meta["document"] = "Office OOXML"
            if any(n.endswith("vbaproject.bin") for n in lnames):
                res.add(HIGH, "Macro", "The document contains VBA macros", "", 30)
                for i in infos:
                    if i.filename.lower().endswith("vbaproject.bin") and i.file_size < 30_000_000:
                        self._macro_checks(extract_vba(zf.read(i)), res)
            if any("macrosheets/" in n for n in lnames):
                res.add(HIGH, "Macro", "Excel 4.0 macro sheets (XLM)", "", 35)
            if any("activex" in n for n in lnames):
                res.add(MED, "Macro", "Embedded ActiveX controls")
            if any("embeddings/oleobject" in n for n in lnames):
                res.add(MED, "Payload", "OLE objects embedded in the document")
            for i in infos:
                ln = i.filename.lower()
                if ln.endswith(".rels") and i.file_size < 2_000_000:
                    x = zf.read(i).decode("utf-8", "ignore")
                    if re.search(r'TargetMode="External"', x) and re.search(r"attachedTemplate|oleObject|frame", x):
                        tgt = re.search(r'Target="(https?://[^"]+|\\\\[^"]+)"', x)
                        res.add(HIGH, "Exploit", "Remote template/object (template injection)",
                                tgt.group(1) if tgt else "", 40)
                    if "mhtml:" in x.lower() or "ms-msdt" in x.lower():
                        res.add(CRIT, "Exploit", "MHTML/MSDT reference (Follina)", "", 70)
                elif ln.endswith(".xml") and i.file_size < 20_000_000 and ("document" in ln or "sheet" in ln):
                    x = zf.read(i).decode("utf-8", "ignore")
                    if re.search(r"DDEAUTO|\bDDE\b", x):
                        res.add(HIGH, "Exploit", "DDE field with automatic execution", "", 40)
            return

        if "meta-inf/manifest.mf" in lnames and any(n.endswith(".class") for n in lnames):
            res.meta["document"] = "Java JAR"
        if "androidmanifest.xml" in lnames:
            res.meta["document"] = "Android APK"

        # --- archivio generico ---
        res.meta.setdefault("archive_files", len(infos))
        if any(i.flag_bits & 1 for i in infos):
            res.add(MED, "Evasion", "Password-protected archive (often used to evade antivirus)", "", 18)
        total = sum(i.file_size for i in infos)
        comp = sum(i.compress_size for i in infos) or 1
        if total > 1_000_000_000 and total / comp > 100:
            res.add(HIGH, "Archive", "Possible ZIP bomb", f"{human_size(total)} uncompressed", 30)
            return
        dang = [n for n in names if os.path.splitext(n.lower())[1] in DANGEROUS_EXT]
        for n in dang[:4]:
            res.add(MED, "Archive", "Executable/script inside the archive", n, 12)
        if len(dang) > 4:
            res.add(INFO, "Archive", f"{len(dang) - 4} more executable files in the archive")
        if depth >= 2:
            return
        scanned = 0
        for i in infos:
            if scanned >= 40 or i.is_dir() or i.flag_bits & 1 or i.file_size > 40_000_000:
                continue
            try:
                blob = zf.read(i)
            except Exception:
                continue
            scanned += 1
            child = ScanResult("file", i.filename, os.path.basename(i.filename))
            self._name_checks(os.path.basename(i.filename), child)
            self._scan_bytes(blob, os.path.basename(i.filename), child, depth + 1)
            for f in child.findings:
                if f.severity == INFO:
                    continue
                f.detail = f"[{i.filename}] {f.detail}".strip()
                res.findings.append(f)

    # ---------------------------------------------------------------- OLE legacy
    def _analyze_ole(self, data, res):
        res.meta["document"] = "Office legacy (OLE)"
        if "_VBA_PROJECT".encode("utf-16le") in data or b"_VBA_PROJECT" in data or b"Attribute VB_" in data:
            res.add(HIGH, "Macro", "The document contains VBA macros", "", 30)
            self._macro_checks(extract_vba(data), res)
        if re.search(rb"EXEC\(|CALL\(|REGISTER\(|\bAuto_Open\b", data):
            res.add(MED, "Macro", "Suspicious Excel 4.0 macro formulas")
        if b"Equation.3" in data or b"\x02\xce\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46" in data:
            res.add(HIGH, "Exploit", "Equation Editor object (CVE-2017-11882)", "", 40)

    def _macro_checks(self, src, res):
        if not src:
            return
        auto = re.findall(r"\b(AutoOpen|Auto_Open|Document_Open|Workbook_Open|AutoExec|AutoClose|"
                          r"Document_Close|Workbook_Activate|Auto_Close|Workbook_BeforeClose)\b", src, re.I)
        if auto:
            res.add(HIGH, "Macro", "Auto-executing macro", ", ".join(sorted(set(auto))), 30)
        sus = re.findall(r"\b(Shell|CreateObject|GetObject|URLDownloadToFile|XMLHTTP|ADODB\.Stream|"
                         r"Environ|CallByName|StrReverse|Powershell|WScript|ShellExecute|"
                         r"VirtualAlloc|RtlMoveMemory|CreateThread|Lib \"kernel32\")\b", src, re.I)
        if sus:
            uniq = sorted(set(s.lower() for s in sus))
            res.add(HIGH if len(uniq) >= 3 else MED, "Macro", "Dangerous instructions in the macro",
                    ", ".join(uniq[:10]), 15 + 5 * min(len(uniq), 6))
        if len(re.findall(r"Chr[W$]?\(", src, re.I)) > 25:
            res.add(MED, "Obfuscation", "Obfuscated macro (character concatenation)")
        self._string_rules(src, res, False, True)

    # ---------------------------------------------------------------- PDF
    def _analyze_pdf(self, data, res):
        d = data[:MAX_STR]
        cnt = lambda pat: len(re.findall(pat, d))
        js = cnt(rb"/JavaScript|/JS\b")
        auto = cnt(rb"/OpenAction|/AA\b")
        launch = cnt(rb"/Launch")
        emb = cnt(rb"/EmbeddedFile")
        res.meta["pdf"] = f"JS:{js} AutoAction:{auto} Launch:{launch} Embedded:{emb}"
        if js and auto:
            res.add(HIGH, "PDF", "JavaScript executed when the PDF opens", "", 40)
        elif js:
            res.add(MED, "PDF", "The PDF contains JavaScript")
        if launch:
            res.add(HIGH, "PDF", "/Launch action (runs programs)", "", 40)
        if emb:
            res.add(MED, "PDF", "Files embedded in the PDF", f"{emb}")
        if re.search(rb"/[A-Za-z]*#[0-9A-Fa-f]{2}", d):
            res.add(MED, "Obfuscation", "PDF names obfuscated with hex encoding")
        if cnt(rb"/XFA") and js:
            res.add(LOW, "PDF", "XFA form with scripts")
        if self.links:
            uris = re.findall(rb"/URI\s*\(([^)]{6,400})\)", d)
            seen = set()
            for u in uris[:12]:
                url = u.decode("latin-1", "ignore").strip()
                if url in seen or not re.match(r"https?://", url, re.I):
                    continue
                seen.add(url)
                lr = self.links.scan(url, offline_only=True)
                if lr.score >= 45:
                    res.add(HIGH, "Phishing", "Phishing link inside the PDF", url, 35)
                elif lr.score >= 25:
                    res.add(MED, "Phishing", "Suspicious link inside the PDF", url)

    # ---------------------------------------------------------------- script
    def _analyze_script(self, text, res, ext):
        if re.search(r"[A-Za-z0-9+/]{300,}={0,2}", text):
            res.add(MED, "Obfuscation", "Large embedded Base64 block (hidden payload)", "", 18)
        if len(re.findall(r"chr[w]?\s*\(\s*\d+", text, re.I)) > 25 or \
                len(re.findall(r"\[char\]\s*\d+", text, re.I)) > 15:
            res.add(MED, "Obfuscation", "Strings built character by character", "", 18)
        if re.search(r"string\.fromcharcode|\beval\s*\(|unescape\s*\(|execute(?:global)?\s*\(", text, re.I):
            res.add(MED, "Obfuscation", "Dynamic code execution (eval/Execute)")
        if ext in (".bat", ".cmd") and text.count("^") > 40:
            res.add(MED, "Obfuscation", "Batch file obfuscated with escape characters")
        if ext in (".bat", ".cmd") and re.search(r"%[a-z_]{1,8}:~\d+,\d+%", text, re.I):
            res.add(MED, "Obfuscation", "Batch file obfuscated with variable substrings")
        if re.search(r"exec\s*\(\s*(?:base64|zlib|marshal|codecs)\.|__import__\(['\"](?:base64|zlib|marshal)", text):
            res.add(HIGH, "Obfuscation", "Python running hidden code (exec + decode)", "", 35)
        if ext == ".reg" and re.search(r"currentversion\\run|winlogon|image file execution", text, re.I):
            res.add(HIGH, "Persistence", ".reg file that modifies startup keys", "", 35)
        if ext in (".url", ".scf") and re.search(r"(?:url|iconfile)\s*=\s*(?:file:|\\\\)", text, re.I):
            res.add(HIGH, "Exploit", "Shortcut pointing to a network resource (NTLM hash theft)", "", 35)
        if ext == ".hta":
            res.add(MED, "Execution", "Executable HTML application (HTA)")

    # ---------------------------------------------------------------- VT
    def _virustotal(self, sha256, key, res):
        try:
            j = _http_get_json(f"https://www.virustotal.com/api/v3/files/{sha256}", {"x-apikey": key})
            st = j["data"]["attributes"]["last_analysis_stats"]
            mal, sus = st.get("malicious", 0), st.get("suspicious", 0)
            tot = sum(st.values())
            label = j["data"]["attributes"].get("popular_threat_classification", {}).get("suggested_threat_label", "")
            res.meta["virustotal"] = f"{mal}/{tot}"
            if mal >= 3:
                res.add(CRIT, "VirusTotal", f"VirusTotal: {mal}/{tot} antivirus engines detect it", label, 90)
            elif mal or sus:
                res.add(HIGH, "VirusTotal", f"VirusTotal: {mal + sus}/{tot} detections", label, 35)
            else:
                res.bonus -= 10
                res.add(INFO, "VirusTotal", f"VirusTotal: 0/{tot} detections")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                res.meta["virustotal"] = "sconosciuto"
                res.add(INFO, "VirusTotal", "File never seen by VirusTotal")
            else:
                res.add(INFO, "VirusTotal", "VirusTotal error", f"HTTP {e.code}")
        except Exception as e:
            res.add(INFO, "VirusTotal", "VirusTotal unreachable", str(e)[:100])


# --------------------------------------------------------------------------- #
#  SCANNER LINK (phishing)
# --------------------------------------------------------------------------- #
BRANDS = {
    "PayPal": (["paypal"], ["paypal.com", "paypal.me", "paypal.it", "paypalobjects.com"]),
    "Google": (["google", "gmail", "youtube"], ["google.com", "google.it", "gmail.com", "youtube.com",
                                                 "youtu.be", "goo.gl", "googleusercontent.com", "gstatic.com",
                                                 "googleapis.com", "withgoogle.com", "blogger.com"]),
    "Apple": (["apple", "icloud", "appleid", "itunes"], ["apple.com", "icloud.com", "apple.co", "itunes.com"]),
    "Microsoft": (["microsoft", "office365", "outlook", "onedrive", "sharepoint", "hotmail", "xbox"],
                  ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com", "office365.com",
                   "bing.com", "xbox.com", "sharepoint.com", "onedrive.com", "hotmail.com", "msn.com",
                   "windows.net", "azure.com", "skype.com", "microsoft365.com", "live.net", "1drv.ms"]),
    "Amazon": (["amazon"], ["amazon.com", "amazon.it", "amazon.de", "amazon.fr", "amazon.es", "amazon.co.uk",
                            "amzn.to", "amzn.eu", "amazonaws.com", "primevideo.com", "a2z.com"]),
    "Facebook": (["facebook"], ["facebook.com", "fb.com", "fb.me", "messenger.com", "meta.com", "fbcdn.net"]),
    "Instagram": (["instagram"], ["instagram.com", "cdninstagram.com"]),
    "WhatsApp": (["whatsapp"], ["whatsapp.com", "wa.me", "whatsapp.net"]),
    "Netflix": (["netflix"], ["netflix.com", "nflxext.com"]),
    "Steam": (["steam", "steamcommunity", "steampowered"], ["steampowered.com", "steamcommunity.com",
                                                             "steamstatic.com", "steamgames.com", "s.team"]),
    "Discord": (["discord"], ["discord.com", "discord.gg", "discordapp.com", "discord.media",
                              "discordapp.net", "discord.new", "discord.gift", "discordstatus.com"]),
    "Roblox": (["roblox"], ["roblox.com", "rbxcdn.com"]),
    "Epic Games": (["epicgames", "fortnite"], ["epicgames.com", "fortnite.com", "unrealengine.com"]),
    "Binance": (["binance"], ["binance.com"]),
    "Coinbase": (["coinbase"], ["coinbase.com"]),
    "MetaMask": (["metamask"], ["metamask.io"]),
    "Poste Italiane": (["poste", "posteitaliane", "bancoposta", "postepay"],
                       ["poste.it", "posteitaliane.it", "postepay.it"]),
    "Intesa Sanpaolo": (["intesasanpaolo", "intesa"], ["intesasanpaolo.com", "intesasanpaolo.it"]),
    "UniCredit": (["unicredit"], ["unicredit.it", "unicredit.eu", "unicreditgroup.eu"]),
    "BNL": (["bnl"], ["bnl.it"]),
    "INPS": (["inps"], ["inps.it"]),
    "Agenzia Entrate": (["agenziaentrate"], ["agenziaentrate.gov.it", "agenziaentrateriscossione.gov.it"]),
    "DHL": (["dhl"], ["dhl.com", "dhl.it", "dhl.de"]),
    "UPS": (["ups"], ["ups.com"]),
    "FedEx": (["fedex"], ["fedex.com"]),
    "BRT": (["brt", "bartolini"], ["brt.it"]),
    "LinkedIn": (["linkedin"], ["linkedin.com", "lnkd.in"]),
    "Twitter/X": (["twitter"], ["twitter.com", "x.com", "t.co", "twimg.com"]),
    "TikTok": (["tiktok"], ["tiktok.com", "tiktokcdn.com"]),
    "Telegram": (["telegram"], ["telegram.org", "t.me", "telegram.me"]),
    "Spotify": (["spotify"], ["spotify.com", "spoti.fi"]),
    "eBay": (["ebay"], ["ebay.com", "ebay.it", "ebay.de", "ebay.co.uk"]),
    "Adobe": (["adobe"], ["adobe.com", "adobe.io"]),
    "Dropbox": (["dropbox"], ["dropbox.com", "db.tt"]),
    "DocuSign": (["docusign"], ["docusign.com", "docusign.net"]),
    "Revolut": (["revolut"], ["revolut.com", "revolut.me"]),
    "Nexi": (["nexi"], ["nexi.it", "nexigroup.com"]),
    "Satispay": (["satispay"], ["satispay.com"]),
    "GitHub": (["github"], ["github.com", "github.io", "githubusercontent.com"]),
    "Vodafone": (["vodafone"], ["vodafone.it", "vodafone.com"]),
    "Enel": (["enel"], ["enel.it", "enel.com"]),
    "Aruba": (["aruba"], ["aruba.it", "pec.it"]),
    "Chase": (["chase"], ["chase.com"]),
    "Wells Fargo": (["wellsfargo"], ["wellsfargo.com"]),
    "Bank of America": (["bankofamerica"], ["bankofamerica.com"]),
    "OpenAI": (["openai", "chatgpt"], ["openai.com", "chatgpt.com"]),
}
OFFICIAL = {d for _, (_, doms) in BRANDS.items() for d in doms}
TRUSTED_EXTRA = {"wikipedia.org", "stackoverflow.com", "reddit.com", "yahoo.com", "duckduckgo.com",
                 "mozilla.org", "python.org", "anthropic.com", "claude.ai", "cloudflare.com",
                 "gov.it", "governo.it", "repubblica.it", "corriere.it", "ansa.it", "twitch.tv",
                 "zoom.us", "wikimedia.org", "archive.org", "npmjs.com", "pypi.org"}
TYPO_EXCEPT = {"stream", "streams", "apply", "applet", "steak", "steal", "steel", "stem", "enel",
               "panel", "angel", "goggle", "goodle", "hotels", "outloo", "dhlx", "chaser", "chasse",
               "paypai"}

MULTI_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.br", "com.au", "net.au", "org.au", "co.jp",
    "co.in", "com.mx", "com.ar", "com.tr", "co.za", "com.cn", "com.tw", "co.kr", "co.nz", "com.sg",
    "com.hk", "com.ua", "com.pl", "com.ru", "com.es", "com.co", "co.id", "com.my", "com.ph", "gov.it",
    # hosting gratuiti: il sottodominio e' il vero proprietario
    "github.io", "blogspot.com", "herokuapp.com", "web.app", "firebaseapp.com", "pages.dev",
    "netlify.app", "vercel.app", "glitch.me", "000webhostapp.com", "azurewebsites.net", "repl.co",
    "workers.dev", "ngrok.io", "ngrok-free.app", "ngrok.app", "weebly.com", "wixsite.com",
    "godaddysites.com", "duckdns.org", "ddns.net", "r2.dev", "webflow.io", "framer.app",
    "replit.app", "onrender.com", "surge.sh", "sites.google.com", "ipfs.io", "trycloudflare.com",
    "square.site", "myshopify.com", "carrd.co", "mystrikingly.com", "jimdosite.com", "netlify.com",
    "firebasestorage.googleapis.com", "storage.googleapis.com", "s3.amazonaws.com", "translate.goog",
}
FREE_HOSTING = {s for s in MULTI_SUFFIX if "." in s and not re.fullmatch(r"(?:co|com|org|net|ac|gov|me)\.\w\w", s)}

SUSPICIOUS_TLD = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "kim",
                  "work", "rest", "icu", "cam", "buzz", "monster", "cyou", "sbs", "cfd", "live", "online",
                  "site", "website", "space", "fun", "club", "loan", "win", "bid", "date", "download",
                  "review", "stream", "racing", "party", "science", "trade", "accountant", "men", "gdn",
                  "support", "help", "lat", "bond", "quest", "shop", "best", "su", "ru", "cn", "pw", "cc"}
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy",
              "shorturl.at", "tiny.cc", "s.id", "rebrand.ly", "bl.ink", "t.ly", "v.gd", "qrco.de",
              "linktr.ee", "shorte.st", "adf.ly", "bit.do", "soo.gd", "clck.ru", "u.to", "tny.im",
              "short.io", "lnkd.in", "t.co", "x.gd", "urlz.fr", "2no.co", "iplogger.org", "grabify.link",
              "iplogger.com", "blasze.com", "ps3cfw.com", "yip.su"}
IP_LOGGERS = {"iplogger.org", "iplogger.com", "grabify.link", "blasze.com", "yip.su", "2no.co",
              "ps3cfw.com", "iplis.ru", "02ip.ru", "ezstat.ru"}
PHISH_WORDS = ["login", "log-in", "signin", "sign-in", "verify", "verification", "account", "update",
               "secure", "security", "banking", "confirm", "password", "wallet", "unlock", "suspend",
               "suspended", "billing", "invoice", "recover", "recovery", "webscr", "cmd=_login",
               "gift", "nitro", "airdrop", "claim", "bonus", "free", "reward", "prize", "authenticate",
               "validate", "reactivate", "limited", "restore", "accedi", "verifica", "conto", "sblocca",
               "aggiorna", "pagamento", "rimborso", "premio", "omaggio", "sicurezza", "credenziali",
               "giacenza", "spedizione", "pacco", "multa", "seed", "metamask", "2fa", "otp"]
DOWNLOAD_EXT = (".exe", ".scr", ".zip", ".rar", ".7z", ".apk", ".msi", ".bat", ".cmd", ".js", ".vbs",
                ".iso", ".img", ".lnk", ".hta", ".jar", ".ps1", ".dll")
CONFUSABLE = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ո": "n", "ս": "u", "ν": "v", "ο": "o", "α": "a", "ε": "e",
    "ι": "i", "κ": "k", "τ": "t", "ρ": "p", "ı": "i", "ł": "l", "ᴠ": "v", "ʏ": "y", "ɑ": "a", "ь": "b",
    "ԛ": "q", "ԝ": "w", "в": "b", "м": "m", "н": "h", "т": "t", "к": "k", "ℓ": "l", "ⅼ": "l", "ꞵ": "b",
}


def skeleton(s: str) -> str:
    s = "".join(CONFUSABLE.get(c, c) for c in s)
    s = unicodedata.normalize("NFKD", s)
    return "".join(c for c in s if not unicodedata.combining(c))


def deleet(s: str, one="l") -> str:
    return (s.replace("0", "o").replace("1", one).replace("3", "e").replace("4", "a")
             .replace("5", "s").replace("7", "t").replace("$", "s").replace("@", "a")
             .replace("rn", "m").replace("vv", "w"))


def split_domain(host: str):
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_SUFFIX:
        if len(parts) >= 4 and ".".join(parts[-3:]) in MULTI_SUFFIX:
            return ".".join(parts[-4:]), ".".join(parts[-3:])
        return ".".join(parts[-3:]), ".".join(parts[-2:])
    if len(parts) >= 4 and ".".join(parts[-3:]) in MULTI_SUFFIX:
        return ".".join(parts[-4:]), ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:]), parts[-1]
    return host, ""


URL_FIND_RE = re.compile(r"(?:(?:https?|hxxps?|ftp)://|www\.)[^\s<>\"'`]+", re.I)


def extract_urls(text: str):
    urls = [u.rstrip(").,;]>") for u in URL_FIND_RE.findall(text)]
    if not urls:
        urls = [l.strip() for l in re.split(r"[\s,;]+", text) if "." in l.strip()]
    seen, out = set(), []
    for u in urls:
        u = re.sub(r"^hxxp", "http", u, flags=re.I).replace("[.]", ".").replace("(.)", ".")
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out[:200]


class LinkScanner:
    def __init__(self, settings=None, data_dir=None):
        self.s = settings or {}
        self.data_dir = data_dir
        self.feed_urls, self.feed_hosts = set(), set()
        self.load_feed()

    # ---------------------------------------------------------------- feed
    def feed_path(self):
        return os.path.join(self.data_dir, "phishing_feed.txt") if self.data_dir else None

    def load_feed(self):
        p = self.feed_path()
        self.feed_urls, self.feed_hosts = set(), set()
        if p and os.path.isfile(p):
            with open(p, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    u = line.strip()
                    if not u or u.startswith("#"):
                        continue
                    self.feed_urls.add(u.rstrip("/").lower())
                    h = urlparse(u if "://" in u else "http://" + u).hostname
                    if h:
                        self.feed_hosts.add(h.lower())
        return len(self.feed_urls)

    def update_feed(self):
        p = self.feed_path()
        sources = ["https://openphish.com/feed.txt",
                   "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE-NOW.txt"]
        lines, ok = set(), []
        for src in sources:
            try:
                req = urllib.request.Request(src, headers={"User-Agent": "Eclipse-Scanner"})
                with urllib.request.urlopen(req, timeout=25) as r:
                    txt = r.read(30_000_000).decode("utf-8", "ignore")
                n0 = len(lines)
                lines.update(l.strip() for l in txt.splitlines() if l.strip() and not l.startswith("#"))
                ok.append(f"{src.split('/')[2]}: {len(lines) - n0}")
            except Exception as e:
                ok.append(f"{src.split('/')[2]}: error ({str(e)[:40]})")
        if lines and p:
            with open(p, "w", encoding="utf-8") as f:
                f.write(f"# updated {time.strftime('%Y-%m-%d %H:%M')}\n")
                f.write("\n".join(sorted(lines)))
        return self.load_feed(), ok

    # ---------------------------------------------------------------- scan
    def scan(self, raw, offline_only=False, _depth=0):
        raw = raw.strip()
        res = ScanResult("link", raw, raw[:90])
        url = re.sub(r"^hxxp", "http", raw, flags=re.I).replace("[.]", ".")
        low = url.lower()

        if re.match(r"(javascript|vbscript|data|file):", low):
            res.add(CRIT, "Scheme", "Dangerous URL scheme", low.split(":")[0] + ":", 80)
            return res.finalize()
        if not re.match(r"^[a-z][a-z0-9+.\-]*://", low):
            url = "http://" + url
        try:
            p = urlparse(url)
            host = (p.hostname or "").strip(".").lower()
        except ValueError as e:
            res.add(MED, "Format", "Invalid URL", str(e))
            return res.finalize()
        if not host:
            res.add(MED, "Format", "Unable to determine the domain")
            return res.finalize()
        res.meta["domain"] = host

        # ---------------- IDN / omoglifi
        display_host = host
        if host.startswith("xn--") or ".xn--" in host:
            try:
                display_host = host.encode("ascii").decode("idna")
            except Exception:
                pass
            res.add(MED, "Homoglyphs", "Internationalized domain (punycode)", f"{host} -> {display_host}", 18)
        if any(ord(c) > 127 for c in display_host):
            scripts = set()
            for c in display_host:
                if c.isalpha():
                    try:
                        scripts.add(unicodedata.name(c).split()[0])
                    except ValueError:
                        pass
            if len(scripts) > 1:
                res.add(HIGH, "Homoglyphs", "Mixes different alphabets (e.g. Cyrillic + Latin)",
                        ", ".join(sorted(scripts)), 40)
            else:
                res.add(LOW, "Homoglyphs", "Non-ASCII characters in the domain", display_host, 8)
        sk_host = skeleton(display_host)

        real_registered, _ = split_domain(host)          # dominio reale (ASCII/punycode)
        registered, suffix = split_domain(sk_host)       # versione "normalizzata" per i confronti
        res.meta["registered_domain"] = real_registered
        sld = registered[: -len(suffix) - 1] if suffix and registered.endswith("." + suffix) else registered.split(".")[0]
        sub = sk_host[: -len(registered)].rstrip(".") if sk_host.endswith(registered) else ""
        tld = host.rsplit(".", 1)[-1]

        official_brand = None
        for brand, (_, doms) in BRANDS.items():
            if any(real_registered == d or real_registered.endswith("." + d) for d in doms):
                official_brand = brand
        registered = real_registered if official_brand else registered
        trusted = official_brand is not None or real_registered in TRUSTED_EXTRA or tld == "gov" or \
            real_registered.endswith(".gov.it") or real_registered.endswith(".edu")

        # ---------------- feed phishing
        nurl = url.rstrip("/").lower()
        if nurl in self.feed_urls or raw.rstrip("/").lower() in self.feed_urls:
            res.add(CRIT, "Database", "URL listed in the active phishing database", "OpenPhish / Phishing.Database", 95)
        elif host in self.feed_hosts and not trusted:
            res.add(HIGH, "Database", "Domain listed in the phishing database", host, 45)

        # ---------------- struttura URL
        is_ip = False
        try:
            ipaddress.ip_address(host.strip("[]"))
            is_ip = True
        except ValueError:
            if re.fullmatch(r"\d{8,10}|0x[0-9a-f]{6,8}", host) or re.fullmatch(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){1,3}", host):
                is_ip = True
                res.add(HIGH, "Obfuscation", "Obfuscated IP address (decimal/hex)", host, 35)
        if is_ip:
            res.add(HIGH, "Structure", "Uses an IP address instead of a domain", host, 30)
        if p.username or "@" in p.netloc:
            res.add(HIGH, "Deception", "'@' symbol in the address (the real domain is after the @)", p.netloc, 45)
        if p.scheme == "http":
            res.add(LOW, "Encryption", "Unencrypted connection (HTTP)", "", 8)
        try:
            if p.port and p.port not in (80, 443, 8080, 8443):
                res.add(MED, "Structure", "Non-standard port", str(p.port), 12)
        except ValueError:
            res.add(MED, "Format", "Invalid port")
        if host in IP_LOGGERS or registered in IP_LOGGERS:
            res.add(HIGH, "Tracking", "IP-logger service (records your IP address)", host, 45)
        elif host in SHORTENERS or registered in SHORTENERS:
            res.add(MED, "Redirect", "Shortened link: the real destination is hidden", host, 15)
        if suffix in FREE_HOSTING:
            res.add(MED, "Hosting", "Site on free/temporary hosting", suffix, 15)
        if tld in SUSPICIOUS_TLD and not trusted:
            res.add(MED, "Domain", "Domain extension widely used for scams", "." + tld, 15)
        if not is_ip and sub.count(".") >= 3:
            res.add(MED, "Structure", "Excessive number of subdomains", sub, 15)
        if len(host) > 45:
            res.add(LOW, "Structure", "Very long domain name", f"{len(host)} characters", 6)
        if len(url) > 120:
            res.add(LOW, "Structure", "Very long URL", f"{len(url)} characters", 4)
        hy = sld.count("-")
        if hy >= 2 and not trusted:
            res.add(MED, "Domain", "Many hyphens in the domain", registered, 12)
        if not is_ip and not trusted and "-" not in sld and len(sld) >= 12 and (str_entropy(sld) > 3.7 or
                                                             sum(c.isdigit() for c in sld) / len(sld) > 0.3):
            res.add(MED, "Domain", "Random-looking domain (auto-generated)", sld, 15)

        path_q = unquote(unquote((p.path or "") + "?" + (p.query or "") + "#" + (p.fragment or ""))).lower()
        if p.path.lower().endswith(DOWNLOAD_EXT):
            res.add(HIGH, "Download", "The link directly downloads an executable/archive",
                    p.path.rsplit("/", 1)[-1], 35)
        for k, v in parse_qsl(p.query or "", keep_blank_values=True):
            if re.match(r"(?:https?:)?//|www\.", unquote(v), re.I):
                res.add(MED, "Redirect", "Redirect to another site in the parameters", f"{k}={v[:80]}", 15)
                break
        if (p.path or "").count("%") > 12:
            res.add(LOW, "Obfuscation", "Heavily encoded URL", "", 6)
        if "//" in (p.path or "")[1:]:
            res.add(LOW, "Structure", "Double slash in path (hidden redirect)", "", 5)

        # ---------------- parole esca
        if not trusted:
            words = sorted({w for w in PHISH_WORDS if w in (sk_host + " " + path_q)})
            if words:
                res.add(MED if len(words) >= 2 else LOW, "Bait", "Typical phishing words",
                        ", ".join(words[:8]), min(25, 6 * len(words)))

        # ---------------- imitazione marchi
        if not official_brand:
            host_tokens = [t for t in re.split(r"[.\-_]", sub + "." + sld) if t]
            path_tokens = [t for t in re.split(r"[^a-z0-9]", path_q) if t]
            done = set()
            for brand, (kws, _) in BRANDS.items():
                for kw in kws:
                    hit_host = any(t == kw or (len(kw) >= 5 and kw in t) for t in host_tokens)
                    if hit_host and brand not in done:
                        res.add(HIGH, "Impersonation",
                                f"The domain imitates {brand} but is NOT an official site", host, 55)
                        done.add(brand)
                    elif brand not in done and any(t == kw or (len(kw) >= 6 and kw in t) for t in path_tokens):
                        res.add(MED, "Impersonation",
                                f"Reference to {brand} on an unofficial domain", p.path[:80], 15)
                        done.add(brand)
            # typosquatting
            cands = {sld} | set(sld.split("-"))
            for c in cands:
                if len(c) < 4 or c in TYPO_EXCEPT:
                    continue
                for brand, (kws, _) in BRANDS.items():
                    if brand in done:
                        continue
                    for kw in kws:
                        if len(kw) < 5:
                            continue
                        norm = {deleet(c, "l"), deleet(c, "i")}
                        if c != kw and kw in norm:
                            res.add(HIGH, "Typosquatting",
                                    f"Letters swapped to imitate {brand}", f"{c} -> {kw}", 45)
                            done.add(brand)
                            break
                        dist = min(levenshtein(n, kw) for n in norm)
                        lim = 1 if len(kw) <= 6 else 2
                        if 0 < dist <= lim and abs(len(c) - len(kw)) <= 2:
                            res.add(HIGH, "Typosquatting", f"Domain almost identical to {brand}",
                                    f"{c} ~ {kw} (difference: {dist} characters)", 40)
                            done.add(brand)
                            break
            if sk_host != display_host and any(kw in sk_host for kws, _ in BRANDS.values() for kw in kws if len(kw) >= 5):
                res.add(CRIT, "Homoglyphs", "Uses deceptive characters to imitate a brand",
                        f"{display_host} looks like {sk_host}", 70)

        if trusted:
            res.bonus -= 25
            res.add(INFO, "Reputation",
                    f"Official {official_brand} domain" if official_brand else "Known trusted domain", registered)

        # ---------------- controlli online
        if not offline_only and _depth == 0:
            if self.s.get("online_dns", True) and not is_ip:
                try:
                    socket.setdefaulttimeout(6)
                    ips = sorted({a[4][0] for a in socket.getaddrinfo(host, None)})
                    res.meta["ip"] = ", ".join(ips[:3])
                    for ip in ips:
                        try:
                            ipo = ipaddress.ip_address(ip)
                            if ipo.is_private or ipo.is_loopback:
                                res.add(MED, "DNS", "The domain points to a private/local address", ip, 15)
                                break
                        except ValueError:
                            pass
                except socket.gaierror:
                    res.add(MED, "DNS", "The domain does not exist or has been taken down", host, 15)
                except Exception:
                    pass
            if self.s.get("follow_redirects", False):
                self._follow(url, host, registered, trusted, res)
            key = (self.s.get("vt_key") or "").strip()
            if key:
                self._virustotal(url, key, res)
        return res.finalize()

    # ---------------------------------------------------------------- redirect & pagina
    def _follow(self, url, host, registered, trusted, res):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        opener = urllib.request.build_opener(NoRedirect)
        chain, cur, body, status = [url], url, b"", None
        for _ in range(8):
            try:
                req = urllib.request.Request(cur, headers={"User-Agent": UA, "Accept": "text/html,*/*"})
                with opener.open(req, timeout=8) as r:
                    status = r.status
                    body = r.read(400_000)
                m = re.search(rb'http-equiv=["\']?refresh["\']?[^>]*url=([^"\'>\s]+)', body, re.I)
                if m and len(chain) < 8:
                    cur = urljoin(cur, m.group(1).decode("latin-1", "ignore"))
                    chain.append(cur)
                    continue
                break
            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308) and e.headers.get("Location"):
                    cur = urljoin(cur, e.headers["Location"])
                    chain.append(cur)
                    continue
                status = e.code
                break
            except urllib.error.URLError as e:
                reason = getattr(e, "reason", e)
                if isinstance(reason, ssl.SSLCertVerificationError) or "CERTIFICATE" in str(reason).upper():
                    res.add(HIGH, "Encryption", "Invalid or forged SSL certificate", str(reason)[:120], 35)
                else:
                    res.add(INFO, "Network", "Site unreachable", str(reason)[:120])
                break
            except Exception as e:
                res.add(INFO, "Network", "Connection error", str(e)[:120])
                break
        if status:
            res.meta["http"] = str(status)
        if len(chain) > 1:
            res.meta["redirect"] = " -> ".join(chain)[:500]
            final = chain[-1]
            fh = (urlparse(final).hostname or "").lower()
            if fh and fh != host:
                res.add(LOW if trusted else MED, "Redirect", "Redirects to a different domain",
                        f"{host} -> {fh}", 5 if trusted else 12)
                child = self.scan(final, _depth=1)
                for f in child.findings:
                    if f.severity >= LOW:
                        f.title = "[destination] " + f.title
                        res.findings.append(f)
                trusted = child.top_severity() < LOW and any(f.category == "Reputation" for f in child.findings)
        if body and not trusted:
            html = body.decode("utf-8", "ignore")
            title = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
            title = title.group(1).strip()[:100] if title else ""
            if title:
                res.meta["page_title"] = title
            has_pwd = re.search(r"<input[^>]+type=[\"']?password", html, re.I)
            brand_in_page = [b for b, (kws, _) in BRANDS.items() if any(k in title.lower() for k in kws if len(k) >= 4)]
            if has_pwd and brand_in_page:
                res.add(CRIT, "Phishing", f"Login page imitating {brand_in_page[0]}", title, 65)
            elif has_pwd:
                res.add(MED, "Phishing", "The page asks for a password on an unverified site", title, 15)
            if re.search(r"seed phrase|recovery phrase|12.word|frase di recupero|private key", html, re.I):
                res.add(HIGH, "Phishing", "The page asks for the wallet seed phrase / private key", "", 40)
            if re.search(r"<form[^>]+action=[\"']https?://(?!" + re.escape(host) + r")", html, re.I):
                res.add(MED, "Phishing", "The form sends data to another domain", "", 15)

    def _virustotal(self, url, key, res):
        try:
            uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            j = _http_get_json(f"https://www.virustotal.com/api/v3/urls/{uid}", {"x-apikey": key})
            st = j["data"]["attributes"]["last_analysis_stats"]
            mal, sus = st.get("malicious", 0), st.get("suspicious", 0)
            tot = sum(st.values())
            res.meta["virustotal"] = f"{mal}/{tot}"
            if mal >= 2:
                res.add(CRIT, "VirusTotal", f"VirusTotal: {mal}/{tot} engines flag it as malicious", "", 85)
            elif mal or sus:
                res.add(HIGH, "VirusTotal", f"VirusTotal: {mal + sus}/{tot} reports", "", 35)
            else:
                res.add(INFO, "VirusTotal", f"VirusTotal: 0/{tot} reports")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                res.add(INFO, "VirusTotal", "URL never analyzed by VirusTotal")
            else:
                res.add(INFO, "VirusTotal", "VirusTotal error", f"HTTP {e.code}")
        except Exception as e:
            res.add(INFO, "VirusTotal", "VirusTotal unreachable", str(e)[:100])
