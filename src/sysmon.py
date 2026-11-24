"""
ECLIPSE - system inspection
Running processes, autostart entries, network connections and the real-time folder watcher,
all scored with the same heuristic model used by the file scanner.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import winreg

import psutil

import engine
from engine import INFO, LOW, MED, HIGH, CRIT, ScanResult, NO_WINDOW

# --------------------------------------------------------------------------- #
#  Paths and constants
# --------------------------------------------------------------------------- #
nc = os.path.normcase
WINDIR = nc(os.environ.get("SystemRoot", r"C:\Windows"))
SYS32 = os.path.join(WINDIR, "system32")
WOW64 = os.path.join(WINDIR, "syswow64")
SYS_DIRS = (SYS32, WOW64, os.path.join(WINDIR, "winsxs"), os.path.join(WINDIR, "systemapps"),
            os.path.join(WINDIR, "immersivecontrolpanel"), os.path.join(WINDIR, "servicing"))
TEMP = nc(os.path.abspath(os.environ.get("TEMP", tempfile.gettempdir())))
LOCALAPPDATA = nc(os.environ.get("LOCALAPPDATA", ""))
PROGRAMFILES = [nc(p) for p in {os.environ.get("ProgramFiles", ""), os.environ.get("ProgramFiles(x86)", ""),
                                os.environ.get("ProgramW6432", "")} if p]

DATA_DIR = None          # set by init()
OWN_EXE = set()          # Eclipse's own executable(s): never flagged
LAUNCHER = None          # the exe users start (Nuitka onefile: not sys.executable)

LOLBINS = {"powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe",
           "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe",
           "forfiles.exe", "conhost.exe", "schtasks.exe", "wmic.exe", "curl.exe"}
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe",
          "onenote.exe", "acrord32.exe", "acrobat.exe", "visio.exe"}
SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
          "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}
CRITICAL_PROC = {"system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
                 "lsass.exe", "lsaiso.exe", "svchost.exe", "dwm.exe", "fontdrvhost.exe", "memory compression",
                 "secure system", "msmpeng.exe", "sgrmbroker.exe"}

RAT_PORTS = {
    4444: "Metasploit / generic RAT", 1337: "generic backdoor", 31337: "Back Orifice",
    5552: "njRAT", 1177: "njRAT", 1604: "DarkComet", 2404: "Remcos", 4782: "Quasar RAT",
    6606: "AsyncRAT", 7707: "AsyncRAT", 8808: "AsyncRAT", 8848: "DcRat", 54984: "NanoCore",
    12345: "NetBus", 6667: "IRC botnet", 6697: "IRC botnet",
}
REMOTE_TOOL_PORTS = {5938: "TeamViewer", 4899: "Radmin", 5900: "VNC", 5901: "VNC", 3389: "Remote Desktop",
                     7070: "AnyDesk"}
DYN_DNS = ("duckdns.org", "ddns.net", "hopto.org", "zapto.org", "sytes.net", "serveftp.com", "myftp.biz",
           "myftp.org", "no-ip.org", "no-ip.biz", "no-ip.info", "servehttp.com", "redirectme.net",
           "servegame.com", "myvnc.com", "bounceme.net", "gotdns.ch", "dynu.net", "mooo.com",
           "chickenkiller.com", "3utilities.com", "kozow.com", "ngrok.io", "ngrok-free.app", "ngrok.app",
           "portmap.io", "portmap.host", "serveo.net", "playit.gg", "ply.gg", "loca.lt",
           "trycloudflare.com", "localto.net", "tcp.ngrok.io", "pagekite.me", "linkpc.net", "freeddns.org")
EXFIL_HOSTS = {"api.telegram.org": "Telegram bot API (used by stealers to send stolen data)",
               "pastebin.com": "Pastebin (used to host payloads and configs)",
               "transfer.sh": "transfer.sh (anonymous file upload)",
               "anonfiles.com": "anonymous file host", "gofile.io": "anonymous file host"}
EXFIL_OWNERS = {"telegram.exe", "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe"}
SKIP_EXT = (".crdownload", ".part", ".partial", ".download", ".tmp", ".opdownload", ".!ut", ".aria2",
            ".!qb", ".ytdl", ".temp")


def init(data_dir, own_exe=None, launcher=None):
    global DATA_DIR, LAUNCHER
    DATA_DIR = data_dir
    LAUNCHER = launcher
    for e in ([own_exe] if isinstance(own_exe, str) else own_exe or []):
        OWN_EXE.update(nc(f) for f in engine.path_forms(e))


def run_ps(script, timeout=60):
    """Runs a PowerShell snippet and returns the parsed JSON it prints (or None)."""
    pre = "[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ProgressPreference='SilentlyContinue';"
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                            "-Command", pre + script], capture_output=True, timeout=timeout, creationflags=NO_WINDOW)
        out = r.stdout.decode("utf-8", "ignore").strip()
        return json.loads(out) if out else None
    except Exception:
        return None


def is_under(path, root):
    return bool(root) and (path == root or path.startswith(root.rstrip("\\") + "\\"))


def in_windows_dir(path):
    d = nc(os.path.dirname(path))
    return d == WINDIR or any(is_under(d, s) for s in SYS_DIRS)


def in_program_files(path):
    return any(is_under(nc(path), p) for p in PROGRAMFILES)


def downloads_dir():
    guid = "{374DE290-123F-4565-9164-39C4925E467B}"
    for sub in ("User Shell Folders", "Shell Folders"):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Explorer" + "\\" + sub) as k:
                p = os.path.expandvars(winreg.QueryValueEx(k, guid)[0])
                if os.path.isdir(p):
                    return p
        except OSError:
            pass
    return os.path.join(os.path.expanduser("~"), "Downloads")


# --------------------------------------------------------------------------- #
#  Digital signatures (batched through one PowerShell call, cached on disk)
# --------------------------------------------------------------------------- #
_SIG = None


def _sig_cache():
    global _SIG
    if _SIG is None:
        _SIG = {}
        if DATA_DIR:
            try:
                with open(os.path.join(DATA_DIR, "sigcache.json"), encoding="utf-8") as f:
                    _SIG = json.load(f)
            except Exception:
                _SIG = {}
    return _SIG


def _sig_key(p):
    try:
        st = os.stat(p)
        return f"{nc(p)}|{int(st.st_mtime)}|{st.st_size}"
    except OSError:
        return None


def signatures(paths):
    """Returns {path: (status, signer)} for every existing file."""
    cache = _sig_cache()
    out, todo = {}, []
    for p in set(x for x in paths if x):
        k = _sig_key(p)
        if not k:
            continue
        if k in cache:
            out[p] = tuple(cache[k])
        else:
            todo.append(p)
    if todo:
        tmp = os.path.join(tempfile.gettempdir(), f"eclipse_sig_{os.getpid()}.txt")
        with open(tmp, "w", encoding="utf-8-sig") as f:
            f.write("\n".join(todo))
        script = ("$r=foreach($p in (Get-Content -LiteralPath '%s' -Encoding UTF8)){if(-not $p){continue};"
                  "try{$s=Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop;$n='';"
                  "if($s.SignerCertificate){$n=$s.SignerCertificate.Subject};"
                  "[pscustomobject]@{p=[string]$p;s=[string]$s.Status;n=$n}}catch{[pscustomobject]@{p=[string]$p;s='Error';n=''}}};"
                  "ConvertTo-Json -InputObject @($r) -Compress") % tmp.replace("'", "''")
        res = run_ps(script, timeout=40 + len(todo)) or []
        try:
            os.remove(tmp)
        except OSError:
            pass
        if isinstance(res, dict):
            res = [res]
        for it in res:
            m = re.search(r'CN=("[^"]+"|[^,]+)', it.get("n") or "")
            signer = m.group(1).strip('" ') if m else ""
            val = (it.get("s") or "Error", signer)
            out[it["p"]] = val
            k = _sig_key(it["p"])
            if k and val[0] != "Error":
                cache[k] = list(val)
        if DATA_DIR:
            try:
                if len(cache) > 6000:
                    for k in list(cache)[:-4000]:
                        del cache[k]
                with open(os.path.join(DATA_DIR, "sigcache.json"), "w", encoding="utf-8") as f:
                    json.dump(cache, f)
            except Exception:
                pass
    return out


# --------------------------------------------------------------------------- #
#  Shared heuristics
# --------------------------------------------------------------------------- #
def path_findings(path, signed):
    """Location-based indicators. Returns (findings, user_writable)."""
    p = nc(path)
    f = []
    uw = False
    if "\\$recycle.bin\\" in p:
        f.append((CRIT, "Location", "Runs from the Recycle Bin", path)); uw = True
    elif is_under(p, TEMP) or "\\appdata\\local\\temp\\" in p or is_under(p, os.path.join(WINDIR, "temp")):
        f.append((MED if signed else HIGH, "Location", "Runs from a temporary folder", path)); uw = True
    elif "\\users\\public\\" in p:
        f.append((MED if signed else HIGH, "Location", "Runs from the Public user folder", path)); uw = True
    elif "\\downloads\\" in p:
        if not signed:
            f.append((MED, "Location", "Runs from the Downloads folder", path))
        uw = True
    elif re.search(r"\\appdata\\roaming\\[^\\]+$", p):
        if not signed:
            f.append((MED, "Location", "Executable placed directly in AppData\\Roaming", path))
        uw = True
    elif re.search(r"^[a-z]:\\programdata\\[^\\]+$", p):
        if not signed:
            f.append((MED, "Location", "Executable placed directly in ProgramData", path))
        uw = True
    elif "\\appdata\\" in p or "\\programdata\\" in p or re.match(r"^[a-z]:\\users\\", p):
        uw = True
    return f, uw


def name_findings(name, path):
    n = name.lower()
    f = []
    if path and n in engine.SYSTEM_NAMES and not in_windows_dir(path) and "windows defender" not in nc(path):
        f.append((CRIT, "Deception", f"Fake Windows process: {name} outside the Windows folder", path))
    elif len(n) >= 9 and n not in engine.SYSTEM_NAMES:
        for s in engine.SYSTEM_NAMES:
            swapped = len(n) == len(s) and any(n[:i] + n[i + 1] + n[i] + n[i + 2:] == s for i in range(len(n) - 1))
            if len(s) >= 9 and (engine.levenshtein(n, s) == 1 or swapped):
                f.append((HIGH, "Deception", f"Name imitates the Windows process {s}", name))
                break
    if re.search(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp3|mp4|zip|rar)\.(exe|scr|com|bat|cmd|pif)$", n):
        f.append((HIGH, "Deception", "Double extension to disguise an executable", name))
    return f


SIG_TEXT = {"NotSigned": "not signed", "HashMismatch": "BROKEN - file modified after signing",
            "NotTrusted": "not trusted", "UnknownError": "not trusted", "Error": "unknown"}


def sig_text(status, signer):
    if status == "Valid":
        return f"valid  ·  {signer}" if signer else "valid"
    return SIG_TEXT.get(status, status or "unknown")


def sig_findings(status, signer, user_writable, in_pf):
    if status == "Valid":
        return [(INFO, "Signature", f"Signed by {signer}" if signer else "Valid digital signature", "")]
    if status == "HashMismatch":
        return [(CRIT, "Signature", "Digital signature is broken: the file was modified after signing", signer)]
    if status == "NotSigned":
        if in_pf:
            return [(LOW, "Signature", "Not digitally signed", "")]
        return [(MED if user_writable else LOW, "Signature", "Not digitally signed", "")]
    if status in ("NotTrusted", "UnknownError", "Incompatible", "NotSupportedFileFormat"):
        return [(MED, "Signature", f"Signature not trusted ({status})", signer)]
    return []


ENC_RE = re.compile(r"\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+[A-Za-z0-9+/=]{16,}", re.I)
B64_RE = re.compile(r"[A-Za-z0-9+/]{180,}={0,2}")


def command_findings(cmd):
    """Indicators in a command line launched through a script host / LOLBin."""
    if not cmd:
        return []
    c = cmd.lower()
    host = os.path.basename(exe_from_command(cmd)).lower()
    f = []
    if host not in LOLBINS:
        return f
    if host in ("powershell.exe", "pwsh.exe"):
        if ENC_RE.search(" " + cmd):
            f.append((HIGH, "Obfuscation", "Encoded PowerShell command", short(cmd)))
        if re.search(r"-w(indowstyle)?\s+h(idden)?\b", c):
            f.append((MED, "Evasion", "PowerShell runs with a hidden window", short(cmd)))
        if re.search(r"downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|\biwr\b|"
                     r"start-bitstransfer|invoke-restmethod|\birm\b", c):
            f.append((HIGH, "Execution", "Downloads content from the internet", short(cmd)))
        if re.search(r"\biex\b|invoke-expression|\[scriptblock\]::create", c):
            f.append((HIGH, "Execution", "Runs dynamically generated code (Invoke-Expression)", short(cmd)))
        if re.search(r"-ep\s+bypass|-executionpolicy\s+bypass", c):
            f.append((LOW, "Evasion", "Bypasses the PowerShell execution policy", short(cmd)))
        hidden = any("hidden window" in x[2] for x in f)
        if hidden and any(x[2].startswith(("Encoded", "Downloads", "Runs dynamically")) for x in f):
            f.append((HIGH, "Evasion", "Hidden PowerShell running encoded or downloaded code", short(cmd)))
        if re.search(r"add-mppreference\s+-exclusion|set-mppreference\s+-disable", c):
            f.append((CRIT, "Evasion", "Tries to disable or blind Windows Defender", short(cmd)))
    if host == "mshta.exe" and re.search(r"https?:|javascript:|vbscript:", c):
        f.append((HIGH, "Execution", "mshta runs remote or inline script", short(cmd)))
    if host == "regsvr32.exe" and (re.search(r"/i:\s*https?:", c) or "scrobj.dll" in c):
        f.append((CRIT, "Execution", "regsvr32 loads a remote scriptlet (Squiblydoo)", short(cmd)))
    if host == "rundll32.exe":
        if "javascript:" in c or "mshtml,runhtmlapplication" in c:
            f.append((CRIT, "Execution", "rundll32 runs inline script", short(cmd)))
        else:
            m = re.search(r'"?([a-z]:\\[^",]+?\.(dll|cpl|ocx|dat|tmp|bin|png|jpg))"?\s*,', c)
            if m and (is_under(nc(m.group(1)), TEMP) or "\\appdata\\" in m.group(1) or "\\users\\public\\" in m.group(1)):
                f.append((HIGH, "Execution", "rundll32 loads a library from a user folder", m.group(1)))
    if host == "certutil.exe" and re.search(r"-urlcache|-decode|-decodehex", c):
        f.append((HIGH, "Execution", "certutil used to download or decode files", short(cmd)))
    if host == "bitsadmin.exe" and "/transfer" in c:
        f.append((MED, "Execution", "bitsadmin downloads a file", short(cmd)))
    if host in ("wscript.exe", "cscript.exe"):
        m = re.search(r'([a-z]:\\[^"]+?\.(vbs|vbe|js|jse|wsf|wsh))', c)
        if m and (is_under(nc(m.group(1)), TEMP) or "\\appdata\\" in m.group(1) or "\\users\\public\\" in m.group(1)
                  or "\\startup\\" in m.group(1)):
            f.append((HIGH, "Execution", "Script launched from a user folder", m.group(1)))
        elif m:
            f.append((LOW, "Execution", "Runs a Windows script file", m.group(1)))
    if host == "cmd.exe" and re.search(r"\b(curl|bitsadmin|certutil|powershell)\b.*https?://", c):
        f.append((HIGH, "Execution", "Command prompt chain downloads from the internet", short(cmd)))
    if re.search(r"https?://", c) and not any(x[1] == "Execution" for x in f):
        f.append((MED, "Network", "Command line contains an internet address", short(cmd)))
    if B64_RE.search(cmd) and not any("Encoded" in x[2] for x in f):
        f.append((MED, "Obfuscation", "Long Base64 blob in the command line", short(cmd)))
    return f


def short(s, n=240):
    s = str(s)
    return s if len(s) <= n else s[:n] + "…"


def exe_from_command(cmd):
    """Extracts the executable path from a command line."""
    if not cmd:
        return ""
    cmd = os.path.expandvars(cmd.strip())
    if cmd.startswith('"'):
        path = cmd[1:].split('"', 1)[0]
    else:
        parts = cmd.split(" ")
        path = parts[0]
        for i in range(len(parts), 0, -1):
            cand = " ".join(parts[:i])
            if os.path.isfile(cand):
                path = cand
                break
            if os.path.isfile(cand + ".exe"):
                path = cand + ".exe"
                break
    path = path.strip().rstrip(",")
    if path.lower().startswith("\\??\\"):
        path = path[4:]
    if path.lower().startswith("\\systemroot\\"):
        path = os.path.join(WINDIR, path[12:])
    if path.lower().startswith("system32\\"):
        path = os.path.join(WINDIR, path)
    if path and not os.path.isabs(path):
        w = shutil.which(path) or shutil.which(path + ".exe")
        if w:
            path = w
        else:
            for d in (SYS32, WINDIR):
                c = os.path.join(d, path if path.lower().endswith(".exe") else path + ".exe")
                if os.path.isfile(c):
                    path = c
                    break
    return path


def payload_from_command(cmd):
    """For script hosts (wscript, rundll32 ...) returns the script/library they load."""
    host = os.path.basename(exe_from_command(cmd)).lower()
    if host not in LOLBINS:
        return ""
    m = re.search(r'"?([a-zA-Z]:\\[^"]+?\.(dll|vbs|vbe|js|jse|wsf|hta|ps1|bat|cmd|exe|cpl|ocx))"?', cmd[len(host):] if
                  len(cmd) > len(host) else cmd)
    if m:
        p = m.group(1)
        if nc(p) != nc(exe_from_command(cmd)):
            return p
    return ""


def apply(r, items):
    for sev, cat, title, detail in items:
        r.add(sev, cat, title, detail)


# --------------------------------------------------------------------------- #
#  DNS cache: which names did this PC resolve to which IP
# --------------------------------------------------------------------------- #
_DNS = {"t": 0, "map": {}}


def dns_cache(max_age=20):
    if time.time() - _DNS["t"] < max_age:
        return _DNS["map"]
    res = run_ps("ConvertTo-Json -InputObject @(Get-DnsClientCache | Where-Object {$_.Type -in 1,28} | "
                 "Select-Object Entry,Data) -Compress", timeout=20) or []
    if isinstance(res, dict):
        res = [res]
    m = {}
    for it in res:
        ip, name = it.get("Data"), (it.get("Entry") or "").lower().rstrip(".")
        if ip and name:
            m.setdefault(ip, set()).add(name)
    _DNS.update(t=time.time(), map=m)
    return m


def domain_findings(domains, proc_name):
    f = []
    for d in domains:
        for s in DYN_DNS:
            if d == s or d.endswith("." + s):
                f.append((HIGH, "Network", f"Dynamic DNS / tunnel service often used as RAT server ({s})", d))
                break
        if d in EXFIL_HOSTS and proc_name.lower() not in EXFIL_OWNERS:
            f.append((MED, "Network", EXFIL_HOSTS[d], d))
    return f


def remote_port_findings(port):
    if port in RAT_PORTS:
        return [(HIGH, "Network", f"Remote port {port}: default for {RAT_PORTS[port]}", str(port))]
    if port in REMOTE_TOOL_PORTS:
        return [(LOW, "Network", f"Remote-control port {port} ({REMOTE_TOOL_PORTS[port]})", str(port))]
    return []


# --------------------------------------------------------------------------- #
#  Processes
# --------------------------------------------------------------------------- #
_PROFILE = {}


def _proc_infos():
    attrs = ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time", "memory_info"]
    out = []
    for p in psutil.process_iter(attrs):
        try:
            out.append(dict(p.info))
        except Exception:
            pass
    return out


def _conns_by_pid():
    d = {}
    try:
        for c in psutil.net_connections("inet"):
            d.setdefault(c.pid, []).append(c)
    except Exception:
        pass
    return d


def profile_process(info, sig, names, flagged):
    """Scores one process without its network activity."""
    pid, name = info["pid"], info.get("name") or "?"
    exe = info.get("exe") or ""
    cmd = info.get("cmdline") or []
    cmdline = " ".join(f'"{a}"' if " " in a else a for a in cmd) if isinstance(cmd, list) else str(cmd)
    r = ScanResult("process", exe or name, name)
    mem = info.get("memory_info")
    r.meta.update({
        "pid": pid, "parent": f"{names.get(info.get('ppid'), '?')} ({info.get('ppid')})",
        "path": exe, "user": (info.get("username") or "").split("\\")[-1],
        "memory": engine.human_size(mem.rss) if mem else "",
        "started": time.strftime("%d/%m %H:%M", time.localtime(info["create_time"])) if info.get("create_time") else "",
        "command": short(cmdline, 500),
    })
    if pid in (0, 4) or not exe:
        r.meta["signature"] = "protected system process" if pid in (0, 4) or name.lower() in CRITICAL_PROC else \
            "access denied (run as administrator for details)"
        return r.finalize()
    if nc(exe) in OWN_EXE:
        r.meta["signature"] = "Eclipse"
        return r.finalize()
    st, signer = sig.get(exe, (None, ""))
    signed = st == "Valid"
    r.meta["signature"] = sig_text(st, signer)
    pf, uw = path_findings(exe, signed)
    apply(r, pf)
    apply(r, name_findings(name, exe))
    if st:
        apply(r, sig_findings(st, signer, uw, in_program_files(exe)))
    apply(r, command_findings(cmdline))
    parent = names.get(info.get("ppid"), "").lower()
    if parent in OFFICE and name.lower() in SHELLS:
        r.add(HIGH, "Execution", f"{parent} launched {name}: typical of malicious documents", cmdline[:300])
    try:
        if os.stat(exe).st_file_attributes & 2:
            r.add(MED, "Evasion", "Executable file is hidden", exe)
    except (OSError, AttributeError):
        pass
    if nc(exe) in flagged:
        r.add(HIGH, "Reputation", f"Eclipse already flagged this file as {flagged[nc(exe)]}", exe)
    return r.finalize()


def scan_processes(flagged=None, step=None):
    flagged = flagged or {}
    if step:
        step("Listing processes")
    infos = _proc_infos()
    names = {i["pid"]: i.get("name") or "?" for i in infos}
    conns = _conns_by_pid()
    if step:
        step("Checking digital signatures")
    sig = signatures([i.get("exe") for i in infos])
    if step:
        step("Reading the DNS cache")
    dns = dns_cache()
    if step:
        step("Scoring")
    out = []
    for info in infos:
        r = profile_process(info, sig, names, flagged)
        _PROFILE[(info["pid"], info.get("create_time"))] = r
        cl = conns.get(info["pid"], [])
        remote = [c for c in cl if c.raddr]
        listen = [c for c in cl if c.status == psutil.CONN_LISTEN]
        r.meta["connections"] = f"{len(remote)} active, {len(listen)} listening" if cl else ""
        if remote or listen:
            signed = str(r.meta.get("signature", "")).startswith("valid")
            for c in remote:
                apply(r, remote_port_findings(c.raddr.port))
                apply(r, domain_findings(dns.get(c.raddr.ip, ()), r.name))
            if not signed and not in_windows_dir(r.meta.get("path") or ""):
                for c in listen:
                    if c.laddr.ip in ("0.0.0.0", "::") and c.laddr.port > 1024:
                        r.add(MED, "Network", f"Unsigned program accepts connections from the network (port {c.laddr.port})",
                              str(c.laddr.port))
                        break
            r.finalize()
        out.append(r)
    out.sort(key=lambda r: (-r.score, r.name.lower()))
    return out


def kill_process(pid):
    p = psutil.Process(pid)
    name = (p.name() or "").lower()
    if pid in (0, 4) or pid == os.getpid() or name in CRITICAL_PROC:
        raise PermissionError(f"{name} is a critical Windows process and cannot be terminated")
    for ch in p.children(recursive=True):
        try:
            ch.kill()
        except Exception:
            pass
    p.kill()
    p.wait(3)


# --------------------------------------------------------------------------- #
#  Network
# --------------------------------------------------------------------------- #
def ip_kind(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "?"
    if a.is_loopback:
        return "loopback"
    if a.is_private or a.is_link_local:
        return "lan"
    if a.is_multicast or a.is_unspecified:
        return "other"
    return "internet"


_DOMAIN_SCORE = {}
_PTR = {}


def reverse_dns(ips, budget=4.0):
    """Reverse lookups in parallel (cached): used when the DNS cache is empty, e.g. browsers with DoH."""
    import socket
    from concurrent.futures import ThreadPoolExecutor, wait
    todo = [ip for ip in set(ips) if ip not in _PTR]
    if todo:
        def look(ip):
            try:
                return ip, socket.gethostbyaddr(ip)[0].lower()
            except Exception:
                return ip, ""
        ex = ThreadPoolExecutor(16)
        futs = [ex.submit(look, ip) for ip in todo[:120]]
        done, _ = wait(futs, timeout=budget)
        for f in done:
            ip, name = f.result()
            _PTR[ip] = name
        ex.shutdown(wait=False, cancel_futures=True)
    return {ip: _PTR.get(ip, "") for ip in ips}


class _Names(dict):
    """pid -> process name, looked up lazily (only parents that are actually needed)."""
    def __missing__(self, pid):
        try:
            v = psutil.Process(pid).name()
        except Exception:
            v = "?"
        self[pid] = v
        return v

    def get(self, pid, default=None):
        return self[pid] if pid is not None else default


_LIGHT = {}


def _infos_for(pids):
    """Process details only for the given pids; full details only when the profile is not cached yet."""
    out = {}
    for pid in pids:
        try:
            p = psutil.Process(pid)
            ct = p.create_time()
            if (pid, ct) in _PROFILE and (pid, ct) in _LIGHT:
                out[pid] = _LIGHT[(pid, ct)]
                continue
            info = p.as_dict(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time", "memory_info"])
            _LIGHT[(pid, ct)] = info
            out[pid] = info
        except Exception:
            pass
    return out


def scan_network(link_scanner=None, include_listen=False, flagged=None):
    try:
        conns = psutil.net_connections("inet")
    except Exception:
        conns = []
    infos = _infos_for({c.pid for c in conns if c.pid})
    names = _Names({pid: i.get("name") or "?" for pid, i in infos.items()})
    dns = dns_cache()
    need = [infos[c.pid].get("exe") for c in conns if c.pid in infos]
    sig = signatures(need)
    ptr = reverse_dns([c.raddr.ip for c in conns if c.raddr and ip_kind(c.raddr.ip) == "internet"
                       and not dns.get(c.raddr.ip)])
    out, seen = [], {}
    for c in conns:
        listening = c.status == psutil.CONN_LISTEN
        if not c.raddr and not (include_listen and listening):
            continue
        if c.raddr and ip_kind(c.raddr.ip) == "loopback":
            continue
        dk = (c.pid, c.raddr.ip, c.raddr.port) if c.raddr else (c.pid, "listen", c.laddr.port, c.type)
        if dk in seen:
            seen[dk].meta["sockets"] += 1
            continue
        info = infos.get(c.pid, {"pid": c.pid, "name": "System" if c.pid in (0, 4) else "?"})
        key = (c.pid, info.get("create_time"))
        prof = _PROFILE.get(key)
        if prof is None:
            prof = profile_process(info, sig, names, flagged or {})
            _PROFILE[key] = prof
        pname = info.get("name") or "?"
        proto = "TCP" if c.type == 1 else "UDP"
        if c.raddr:
            rip, rport = c.raddr.ip, c.raddr.port
            doms = sorted(dns.get(rip, ()))
            rev = ptr.get(rip, "") if not doms else ""
            host = doms[0] if doms else (rev or rip)
            r = ScanResult("conn", f"{rip}:{rport}", f"{pname}  →  {host}:{rport}")
            kind = ip_kind(rip)
            r.meta.update({"process": f"{pname} ({c.pid})", "path": info.get("exe") or "", "remote": f"{rip}:{rport}",
                           "domain": ", ".join(doms[:4]), "reverse_dns": rev, "network": {"lan": "local network", "internet": "internet"}.get(kind, kind),
                           "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "", "state": c.status, "protocol": proto,
                           "signature": prof.meta.get("signature", "")})
            apply(r, remote_port_findings(rport))
            apply(r, domain_findings(doms + ([rev] if rev else []), pname))
            if link_scanner and doms:
                d = doms[0]
                if d not in _DOMAIN_SCORE:
                    try:
                        _DOMAIN_SCORE[d] = link_scanner.scan(d, offline_only=True).score
                    except Exception:
                        _DOMAIN_SCORE[d] = 0
                s = _DOMAIN_SCORE[d]
                if s >= 60:
                    r.add(HIGH, "Reputation", f"Domain looks malicious to the link scanner (score {s})", d)
        else:
            r = ScanResult("conn", f"{c.laddr.ip}:{c.laddr.port}", f"{pname}  ·  listening on {c.laddr.port}")
            r.meta.update({"process": f"{pname} ({c.pid})", "path": info.get("exe") or "",
                           "local": f"{c.laddr.ip}:{c.laddr.port}", "state": "LISTEN", "protocol": proto,
                           "signature": prof.meta.get("signature", "")})
            exposed = c.laddr.ip in ("0.0.0.0", "::")
            r.meta["network"] = "open to the network" if exposed else "this PC only"
            if exposed and c.laddr.port in RAT_PORTS:
                r.add(HIGH, "Network", f"Listening on port {c.laddr.port}, default for {RAT_PORTS[c.laddr.port]}", "")
        if prof.score >= 25:
            top = prof.findings[0] if prof.findings else None
            sev = min(HIGH, max(MED, prof.top_severity()))
            r.add(sev, "Process", f"The owning process is {prof.verdict.lower()} (score {prof.score})",
                  top.title if top else "")
        r.meta["pid"] = c.pid
        r.meta["sockets"] = 1
        r.finalize()
        seen[dk] = r
        out.append(r)
    out.sort(key=lambda r: (-r.score, r.name.lower()))
    return out


# --------------------------------------------------------------------------- #
#  Autostart entries
# --------------------------------------------------------------------------- #
HKCU, HKLM = winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE
HIVE_NAME = {HKCU: "HKCU", HKLM: "HKLM"}
CV = r"Software\Microsoft\Windows\CurrentVersion"
APPROVED = CV + r"\Explorer\StartupApproved"
RUN_KEYS = [
    (HKCU, CV + r"\Run", "Run", HKCU),
    (HKCU, CV + r"\RunOnce", None, None),
    (HKLM, CV + r"\Run", "Run", HKLM),
    (HKLM, CV + r"\RunOnce", None, None),
    (HKLM, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "Run32", HKLM),
    (HKLM, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", None, None),
    (HKCU, CV + r"\Policies\Explorer\Run", None, None),
    (HKLM, CV + r"\Policies\Explorer\Run", None, None),
]


def _values(hive, path):
    out = []
    try:
        with winreg.OpenKey(hive, path) as k:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumValue(k, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return out


def _approved(hive, sub, name):
    try:
        with winreg.OpenKey(hive, APPROVED + "\\" + sub) as k:
            v, _ = winreg.QueryValueEx(k, name)
            return not (isinstance(v, bytes) and v and v[0] & 1)
    except OSError:
        return True


def _set_approved(hive, sub, name, enabled):
    data = (bytes([2, 0, 0, 0]) + b"\0" * 8) if enabled else \
        (bytes([3, 0, 0, 0]) + struct.pack("<Q", int((time.time() + 11644473600) * 1e7)))
    with winreg.CreateKeyEx(hive, APPROVED + "\\" + sub, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, name, 0, winreg.REG_BINARY, data)


def startup_folders():
    user = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")
    common = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), r"Microsoft\Windows\Start Menu\Programs\Startup")
    return [(HKCU, user), (HKLM, common)]


def _lnk_targets(paths):
    if not paths:
        return {}
    arr = ",".join("'" + p.replace("'", "''") + "'" for p in paths)
    res = run_ps("$w=New-Object -ComObject WScript.Shell;$r=foreach($p in @(%s)){$s=$w.CreateShortcut($p);"
                 "[pscustomobject]@{p=[string]$p;t=$s.TargetPath;a=$s.Arguments}};ConvertTo-Json -InputObject @($r) -Compress"
                 % arr, timeout=30) or []
    if isinstance(res, dict):
        res = [res]
    return {it["p"]: ((it.get("t") or ""), (it.get("a") or "")) for it in res}


def _entry(source, location, name, command, kind, enabled=True, ref=None, can_toggle=False):
    return {"source": source, "location": location, "name": name, "command": command or "", "kind": kind,
            "enabled": enabled, "ref": ref or {}, "can_toggle": can_toggle}


def list_autoruns():
    items = []
    for hive, path, sub, ahive in RUN_KEYS:
        for name, val, _t in _values(hive, path):
            if not isinstance(val, str) or not name:
                continue
            en = _approved(ahive, sub, name) if sub else True
            items.append(_entry(f"Registry · {HIVE_NAME[hive]} {path.split(chr(92))[-1]}",
                                f"{HIVE_NAME[hive]}\\{path}", name, val, "reg", en,
                                {"hive": HIVE_NAME[ahive] if ahive else None, "sub": sub, "name": name}, bool(sub)))
    # startup folders
    lnks = []
    for hive, d in startup_folders():
        if not os.path.isdir(d):
            continue
        for fn in os.listdir(d):
            if fn.lower() == "desktop.ini":
                continue
            fp = os.path.join(d, fn)
            en = _approved(hive, "StartupFolder", fn)
            e = _entry("Startup folder" + (" (all users)" if hive == HKLM else ""), d, fn, fp, "folder", en,
                       {"hive": HIVE_NAME[hive], "sub": "StartupFolder", "name": fn}, True)
            items.append(e)
            if fn.lower().endswith(".lnk"):
                lnks.append(e)
    tg = _lnk_targets([e["command"] for e in lnks])
    for e in lnks:
        t, a = tg.get(e["command"], ("", ""))
        if t:
            e["lnk"] = e["command"]
            e["command"] = (f'"{t}" {a}' if " " in t else f"{t} {a}").strip()
    # Winlogon
    for hive in (HKLM, HKCU):
        for name, val, _t in _values(hive, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"):
            if name in ("Shell", "Userinit") and isinstance(val, str):
                items.append(_entry(f"Winlogon · {HIVE_NAME[hive]}", f"{HIVE_NAME[hive]}\\...\\Winlogon", name, val,
                                    "winlogon"))
    # IFEO debugger hijacks
    ifeo = r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    try:
        with winreg.OpenKey(HKLM, ifeo) as k:
            i = 0
            while True:
                try:
                    sk = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                for name, val, _t in _values(HKLM, ifeo + "\\" + sk):
                    if name == "Debugger" and isinstance(val, str) and val.strip():
                        items.append(_entry("Image hijack (IFEO)", f"HKLM\\...\\Image File Execution Options\\{sk}", sk,
                                            val, "ifeo"))
    except OSError:
        pass
    # AppInit DLLs
    for name, val, _t in _values(HKLM, r"Software\Microsoft\Windows NT\CurrentVersion\Windows"):
        if name == "AppInit_DLLs" and isinstance(val, str) and val.strip():
            items.append(_entry("AppInit DLLs", "HKLM\\...\\Windows", name, val, "appinit"))
    # scheduled tasks
    tasks = run_ps("$r=Get-ScheduledTask | ForEach-Object { $a=@($_.Actions | Where-Object {$_.Execute})[0];"
                   "if($a){[pscustomobject]@{n=$_.TaskName;p=$_.TaskPath;s=[string]$_.State;e=$a.Execute;g=$a.Arguments;"
                   "au=$_.Author;h=[bool]$_.Settings.Hidden}}}; ConvertTo-Json -InputObject @($r) -Compress",
                   timeout=60) or []
    if isinstance(tasks, dict):
        tasks = [tasks]
    for t in tasks:
        exe = os.path.expandvars((t.get("e") or "").strip('"'))
        cmd = (f'"{exe}" ' if " " in exe else exe + " ") + (t.get("g") or "")
        ms = (t.get("p") or "").lower().startswith("\\microsoft\\")
        if ms:
            ex = nc(exe_from_command(cmd))
            if in_windows_dir(ex) and not command_findings(cmd):
                continue
        items.append(_entry("Scheduled task" + (" (hidden)" if t.get("h") else ""), (t.get("p") or "") + (t.get("n") or ""),
                            t.get("n") or "?", cmd.strip(), "task", (t.get("s") or "") != "Disabled",
                            {"task": (t.get("p") or "\\") + (t.get("n") or ""), "hidden": t.get("h"),
                             "author": t.get("au") or ""}, True))
    # auto-start services outside the Windows folder
    svcs = run_ps("ConvertTo-Json -InputObject @(Get-CimInstance Win32_Service | Where-Object {$_.StartMode -eq 'Auto'} | "
                  "Select-Object Name,DisplayName,PathName,State) -Compress", timeout=60) or []
    if isinstance(svcs, dict):
        svcs = [svcs]
    for s in svcs:
        pn = s.get("PathName") or ""
        ex = exe_from_command(pn)
        if not pn or in_windows_dir(nc(ex)):
            continue
        items.append(_entry("Service", f"Service: {s.get('Name')}", s.get("DisplayName") or s.get("Name"), pn,
                            "service", True, {"service": s.get("Name"), "state": s.get("State")}))
    return items


def scan_autoruns(flagged=None, step=None):
    flagged = flagged or {}
    if step:
        step("Reading autostart locations")
    items = list_autoruns()
    for e in items:
        e["exe"] = exe_from_command(e["command"]) if e["kind"] not in ("appinit",) else e["command"].split(",")[0].strip()
        e["payload"] = payload_from_command(e["command"])
    if step:
        step("Checking digital signatures")
    sig = signatures([e["exe"] for e in items] + [e["payload"] for e in items if e["payload"]])
    out = []
    for e in items:
        r = ScanResult("autorun", e["exe"] or e["command"], e["name"])
        r.meta.update({"source": e["source"], "location": e["location"], "command": short(e["command"], 500),
                       "path": e["exe"], "status": "enabled" if e["enabled"] else "disabled"})
        if e.get("payload"):
            r.meta["loads"] = e["payload"]
        if e["ref"].get("author"):
            r.meta["author"] = e["ref"]["author"]
        r.meta["_entry"] = e
        exe = e["exe"]
        if exe and nc(exe) in OWN_EXE:
            r.meta["signature"] = "Eclipse"
            out.append(r.finalize())
            continue
        kind = e["kind"]
        if kind == "winlogon":
            v = e["command"].strip().lower().rstrip(",")
            ok = {"Shell": ("explorer.exe",), "Userinit": (os.path.join(SYS32, "userinit.exe"), "userinit.exe",
                                                           r"c:\windows\system32\userinit.exe")}[e["name"]]
            parts = [p.strip() for p in v.split(",") if p.strip()]
            if any(nc(p) not in ok for p in parts):
                r.add(CRIT, "Persistence", f"Winlogon {e['name']} was modified to launch an extra program", e["command"])
            out.append(r.finalize())
            continue
        if kind == "ifeo":
            r.add(CRIT if e["name"].lower() in ("sethc.exe", "utilman.exe", "osk.exe", "narrator.exe", "magnify.exe",
                                                "displayswitch.exe", "msmpeng.exe", "taskmgr.exe") else HIGH,
                  "Persistence", f"Launching {e['name']} silently starts another program (debugger hijack)", e["command"])
        if kind == "appinit":
            r.add(HIGH, "Persistence", "DLL injected into every program that loads user32.dll (AppInit_DLLs)", e["command"])
        targets = [t for t in (exe, e.get("payload")) if t]
        missing = exe and not os.path.exists(exe)
        if missing:
            r.add(LOW, "Integrity", "The program this entry points to no longer exists", exe)
        for t in targets:
            if not os.path.exists(t):
                continue
            st, signer = sig.get(t, (None, ""))
            signed = st == "Valid"
            if t == exe:
                r.meta["signature"] = sig_text(st, signer)
            if in_windows_dir(t) and signed:
                continue
            pf, uw = path_findings(t, signed)
            apply(r, pf)
            apply(r, name_findings(os.path.basename(t), t))
            if st:
                apply(r, sig_findings(st, signer, uw, in_program_files(t)))
            if nc(t) in flagged:
                r.add(HIGH, "Reputation", f"Eclipse already flagged this file as {flagged[nc(t)]}", t)
            ext = os.path.splitext(t)[1].lower()
            if ext in (".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".ps1", ".bat", ".cmd") and uw:
                r.add(MED, "Persistence", "A script in a user folder starts with Windows", t)
        apply(r, command_findings(e["command"]))
        if kind == "task" and e["ref"].get("hidden"):
            r.add(MED if r.findings and any(f.severity >= MED for f in r.findings) else LOW,
                  "Evasion", "Task is marked as hidden", "")
        if kind == "folder" and os.path.splitext(e["name"])[1].lower() in (".exe", ".scr", ".vbs", ".js", ".bat",
                                                                           ".cmd", ".ps1", ".hta", ".jse", ".vbe"):
            r.add(MED, "Persistence", "Program or script copied directly into the Startup folder", e["name"])
        out.append(r.finalize())
    out.sort(key=lambda r: (-r.score, not r.meta["_entry"]["enabled"], r.name.lower()))
    return out


def set_autorun_enabled(entry, enabled):
    """Enables/disables an entry the same way Task Manager does (reversible)."""
    ref = entry["ref"]
    if entry["kind"] in ("reg", "folder"):
        hive = HKCU if ref["hive"] == "HKCU" else HKLM
        try:
            _set_approved(hive, ref["sub"], ref["name"], enabled)
        except PermissionError:
            raise PermissionError("Administrator rights are required for this entry: restart Eclipse as administrator")
        return
    if entry["kind"] == "task":
        r = subprocess.run(["schtasks", "/Change", "/TN", ref["task"], "/ENABLE" if enabled else "/DISABLE"],
                           capture_output=True, timeout=30, creationflags=NO_WINDOW)
        if r.returncode != 0:
            msg = (r.stderr or r.stdout).decode("utf-8", "ignore").strip()
            raise PermissionError(msg or "Administrator rights are required: restart Eclipse as administrator")
        return
    raise ValueError("This entry cannot be disabled from Eclipse")


# --------------------------------------------------------------------------- #
#  Real-time watcher (polling: robust on OneDrive and network folders)
# --------------------------------------------------------------------------- #
class FolderWatcher:
    def __init__(self, folders, interval=1.5, depth=1):
        self.folders = [f for f in folders if os.path.isdir(f)]
        self.interval, self.depth = interval, depth
        self.known = {}
        self.pending = {}
        self.handles = []

    def _walk(self):
        out = {}
        stack = [(f, 0) for f in self.folders]
        while stack:
            d, lvl = stack.pop()
            try:
                it = os.scandir(d)
            except OSError:
                continue
            with it:
                for e in it:
                    n = e.name
                    try:
                        if e.is_dir(follow_symlinks=False):
                            if lvl + 1 <= self.depth and not n.startswith("."):
                                stack.append((e.path, lvl + 1))
                            continue
                        if n.startswith(("~$", ".")) or n.lower().endswith(SKIP_EXT) or n.lower() == "desktop.ini":
                            continue
                        st = e.stat(follow_symlinks=False)    # cached by scandir on Windows: no extra syscall
                    except OSError:
                        continue
                    out[e.path] = (st.st_size, st.st_mtime)
        return out

    def prime(self):
        self.known = self._walk()
        self._open_handles()

    # --- change notifications: the thread sleeps in the kernel instead of polling the disk
    def _open_handles(self):
        import ctypes
        k32 = ctypes.windll.kernel32
        k32.FindFirstChangeNotificationW.restype = ctypes.c_void_p
        flags = 0x1 | 0x2 | 0x8 | 0x10        # file name, dir name, size, last write
        for f in self.folders:
            h = k32.FindFirstChangeNotificationW(ctypes.c_wchar_p(f), self.depth > 0, flags)
            if h and h != ctypes.c_void_p(-1).value:
                self.handles.append(h)

    def wait(self, timeout):
        """Blocks until something changes in a watched folder (True) or the timeout expires (False)."""
        if not self.handles:
            time.sleep(timeout)
            return True
        import ctypes
        k32 = ctypes.windll.kernel32
        arr = (ctypes.c_void_p * len(self.handles))(*self.handles)
        r = k32.WaitForMultipleObjects(len(self.handles), arr, False, int(timeout * 1000))
        if 0 <= r < len(self.handles):
            k32.FindNextChangeNotification(ctypes.c_void_p(self.handles[r]))
            return True
        return False

    def close(self):
        import ctypes
        for h in self.handles:
            ctypes.windll.kernel32.FindCloseChangeNotification(ctypes.c_void_p(h))
        self.handles = []

    def poll(self):
        """Returns files that are new/changed and finished writing."""
        now = self._walk()
        ready = []
        for fp, sig in now.items():
            if self.known.get(fp) == sig:
                continue
            prev = self.pending.get(fp)
            if prev and prev[0] == sig:
                if time.time() - prev[1] >= self.interval and self._readable(fp):
                    ready.append(fp)
                    self.known[fp] = sig
                    del self.pending[fp]
            else:
                self.pending[fp] = (sig, time.time())
        for fp in list(self.known):
            if fp not in now:
                del self.known[fp]
        for fp in list(self.pending):
            if fp not in now:
                del self.pending[fp]
        return ready

    @staticmethod
    def _readable(fp):
        try:
            with open(fp, "rb") as f:
                f.read(1)
            return True
        except OSError:
            return False


# --------------------------------------------------------------------------- #
#  Launch at Windows startup (for Eclipse itself)
# --------------------------------------------------------------------------- #
def self_startup_command():
    if LAUNCHER:
        return f'"{LAUNCHER}" --tray'
    if getattr(sys, "frozen", False):
        return f'"{os.path.abspath(sys.executable)}" --tray'
    pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    return f'"{pyw if os.path.exists(pyw) else sys.executable}" "{os.path.abspath(sys.argv[0])}" --tray'


def set_self_startup(on):
    with winreg.CreateKeyEx(HKCU, CV + r"\Run", 0, winreg.KEY_SET_VALUE) as k:
        if on:
            winreg.SetValueEx(k, "Eclipse", 0, winreg.REG_SZ, self_startup_command())
        else:
            try:
                winreg.DeleteValue(k, "Eclipse")
            except OSError:
                pass


def get_self_startup():
    try:
        with winreg.OpenKey(HKCU, CV + r"\Run") as k:
            winreg.QueryValueEx(k, "Eclipse")
            return True
    except OSError:
        return False
