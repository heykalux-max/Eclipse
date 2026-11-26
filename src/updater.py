"""
Automatic updates for the single-file Eclipse.exe.

GitHub hosts release/latest.json next to release/Eclipse.exe. The manifest is signed with the same
Ed25519 key as the Plus licenses (the private half never leaves the publisher's PC), so a tampered
manifest or executable is refused even if the repository itself were compromised.

Install: the new exe is downloaded next to the running one (Eclipse.exe.new) and checked (size + SHA-256);
the running exe is renamed to Eclipse.exe.old (Windows allows renaming a running program) and the
new one takes its name. The new copy is started with --wait-pid so it waits for the old process to
exit; at its next start the leftovers are removed.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request

import plus

MANIFEST_URL = os.environ.get("ECLIPSE_UPDATE_URL") or \
    "https://raw.githubusercontent.com/heykalux-max/Eclipse/main/release/latest.json"
DOWNLOAD_URL = "https://github.com/heykalux-max/Eclipse/raw/main/release/Eclipse.exe"
UA = {"User-Agent": "Eclipse-Updater"}
MAX_SIZE = 200 * 1024 * 1024


class UpdateError(Exception):
    pass


def vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v))[:4]) or (0,)


def signed_text(m):
    return f"eclipse-update|{m['version']}|{m['sha256']}|{m['size']}|{m['url']}".encode()


def make_manifest(secret, version, exe_path, url=DOWNLOAD_URL, notes=""):
    """For the publisher (tools/license_tool.py release)."""
    h = hashlib.sha256()
    with open(exe_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    m = {"version": version, "url": url, "sha256": h.hexdigest(), "size": os.path.getsize(exe_path),
         "notes": notes, "date": time.strftime("%Y-%m-%d")}
    m["sig"] = plus.sign(secret, signed_text(m)).hex()
    return m


def verify_manifest(m):
    try:
        ok = plus.verify(bytes.fromhex(plus.PUBLIC_KEY), signed_text(m), bytes.fromhex(m["sig"]))
    except (KeyError, ValueError, TypeError):
        ok = False
    if not ok:
        raise UpdateError("The update information is not signed by the Eclipse publisher: ignored.")
    if not str(m["url"]).startswith("https://") and not os.environ.get("ECLIPSE_UPDATE_URL"):
        raise UpdateError("The update address is not secure: ignored.")
    if not (0 < int(m["size"]) <= MAX_SIZE):
        raise UpdateError("The update has an invalid size: ignored.")
    return m


def check(current, timeout=15):
    """-> verified manifest dict if a newer version exists, else None. Raises UpdateError / OSError."""
    req = urllib.request.Request(MANIFEST_URL + ("&" if "?" in MANIFEST_URL else "?") + f"t={int(time.time())}",
                                 headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read(64 * 1024)
    try:
        m = json.loads(raw.decode("utf-8"))
    except ValueError:
        raise UpdateError("The update information could not be read.")
    verify_manifest(m)
    return m if vtuple(m["version"]) > vtuple(current) else None


def download(m, launcher, progress=None, cancel=None):
    """Downloads next to the launcher and verifies it. -> path of the verified .new file."""
    dest = launcher + ".new"
    part = dest + ".part"
    h = hashlib.sha256()
    got = 0
    req = urllib.request.Request(m["url"], headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=30) as r, open(part, "wb") as f:
            while True:
                if cancel and cancel():
                    raise UpdateError("Download cancelled.")
                chunk = r.read(1 << 16)
                if not chunk:
                    break
                got += len(chunk)
                if got > int(m["size"]):
                    raise UpdateError("The download is larger than announced: discarded.")
                h.update(chunk)
                f.write(chunk)
                if progress:
                    progress(got, int(m["size"]))
        if got != int(m["size"]) or h.hexdigest() != m["sha256"]:
            raise UpdateError("The downloaded file does not match the signed update (it may still be "
                              "propagating on GitHub): discarded, try again in a few minutes.")
        os.replace(part, dest)
        return dest
    except BaseException:
        try:
            os.remove(part)
        except OSError:
            pass
        raise


def install(new_path, launcher):
    """Swaps the files. On failure the original exe is put back."""
    old = launcher + ".old"
    try:
        if os.path.exists(old):
            os.remove(old)
    except OSError:
        old = launcher + f".{int(time.time())}.old"
    os.replace(launcher, old)
    try:
        os.replace(new_path, launcher)
    except OSError:
        os.replace(old, launcher)
        raise
    return old


def restart(launcher, args=()):
    flags = 0x00000008 | 0x00000200          # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    subprocess.Popen([launcher, "--wait-pid", str(os.getpid()), *args], close_fds=True, creationflags=flags,
                     cwd=os.path.dirname(launcher))


def cleanup(launcher, version):
    """Removes files left by a previous update and the extraction caches of older versions."""
    if launcher:
        d, base = os.path.split(launcher)
        for _ in range(15):                   # the old launcher may still be closing for a moment
            left = 0
            for f in os.listdir(d):
                if f.lower().startswith(base.lower() + ".") and f.lower().endswith((".old", ".new", ".part")):
                    try:
                        os.remove(os.path.join(d, f))
                    except OSError:
                        left += 1
            if not left:
                break
            time.sleep(1)
    cache = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Eclipse")
    if not os.path.isdir(cache):
        return
    stale = [os.path.join(cache, f) for f in os.listdir(cache)   # only version-named folders: other apps
             if re.fullmatch(r"\d+\.\d+\.\d+", f) and f != version and os.path.isdir(os.path.join(cache, f))]
    if not stale:
        return
    in_use = set()                            # another copy of Eclipse (other version) may still be running
    try:
        import psutil
        for p in psutil.process_iter(["exe"]):
            exe = os.path.normcase(p.info.get("exe") or "")
            for s in stale:
                if exe.startswith(os.path.normcase(s) + os.sep):
                    in_use.add(s)
    except Exception:
        return
    for s in stale:
        if s not in in_use:
            shutil.rmtree(s, ignore_errors=True)


def wait_for_pid(pid, timeout=40):
    try:
        import psutil
        psutil.Process(int(pid)).wait(timeout)
    except Exception:
        pass


def writable(folder):
    try:
        probe = os.path.join(folder, f".eclipse-write-test-{os.getpid()}")
        with open(probe, "w"):
            pass
        os.remove(probe)
        return True
    except OSError:
        return False
