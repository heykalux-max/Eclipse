"""
Eclipse Plus licensing.

A license key is a small signed text: "ECL1-" + base64url(payload + Ed25519 signature).
The payload says who the key belongs to and until when it is valid. Eclipse only holds the
PUBLIC key, so it can check keys but not create them; keys are issued with tools/license_tool.py
and the private key that never leaves the seller's PC.

Payload (UTF-8, fields separated by "|"):  plus|<owner>|<expires YYYYMMDD or 0 = lifetime>|<issued YYYYMMDD>|<id>
"""
import base64
import hashlib
import json
import os
import time

PREFIX = "ECL1-"
# Public half of the signing key (hex). Replace it only together with a new private key: every key
# issued with the old one stops working.
PUBLIC_KEY = "8f5b0bff5eee08f69106a66877dc8da563d6d3b4c6eccb4be5a5d49b4d79e263"
PLUS_URL = "https://github.com/heykalux-max/Eclipse#eclipse-plus"
GRACE_DAYS = 3                 # a lapsed subscription keeps working this long, to cover renewal delays
PRICE = "€3.99 / month"
TRIAL_DAYS = 7
TRIAL_REG = r"Software\Eclipse ThreatScanner"
TRIAL_VALUE = "TrialStart" + os.environ.get("ECLIPSE_INSTANCE_TAG", "")   # test copies never use the real trial

FEATURES = [
    ("ransom_guard", "Ransomware shield", "Decoy files and burst detection: a program that starts encrypting "
                                          "your documents is frozen on the spot."),
    ("memory_scan", "Process memory scan", "Finds code injected into other programs, threads started from "
                                           "unbacked memory and process hollowing."),
    ("scheduled_scan", "Scheduled scans", "A quick system scan runs by itself every day or every week, "
                                          "even with Eclipse closed."),
]

# --------------------------------------------------------------------------- #
#  Ed25519 (RFC 8032), pure Python: verification for the app, signing for the tool
# --------------------------------------------------------------------------- #
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _inv(x):
    return pow(x, _P - 2, _P)


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _I % _P
    if (x * x - x2) % _P:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _add(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % _P
    B = (a[1] + a[0]) * (b[1] + b[0]) % _P
    C = 2 * a[3] * b[3] * _D % _P
    D = 2 * a[2] * b[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _mul(s, pt):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _add(q, pt)
        pt = _add(pt, pt)
        s >>= 1
    return q


def _eq(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _enc(pt):
    zi = _inv(pt[2])
    x, y = pt[0] * zi % _P, pt[1] * zi % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _dec(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _h(m):
    return int.from_bytes(hashlib.sha512(m).digest(), "little")


def _expand(secret):
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_from_secret(secret):
    a, _ = _expand(secret)
    return _enc(_mul(a, _G))


def sign(secret, msg):
    a, prefix = _expand(secret)
    A = _enc(_mul(a, _G))
    r = _h(prefix + msg) % _L
    R = _enc(_mul(r, _G))
    s = (r + _h(R + A + msg) * a) % _L
    return R + int.to_bytes(s, 32, "little")


def verify(public, msg, sig):
    if len(public) != 32 or len(sig) != 64:
        return False
    A = _dec(public)
    R = _dec(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    k = _h(sig[:32] + public + msg) % _L
    return _eq(_mul(s, _G), _add(R, _mul(k, A)))


# --------------------------------------------------------------------------- #
#  Keys
# --------------------------------------------------------------------------- #
def make_key(secret, owner, expires="0", issued=None, key_id=None):
    owner = owner.replace("|", " ").strip()[:80]
    issued = issued or time.strftime("%Y%m%d")
    key_id = key_id or os.urandom(4).hex()
    payload = f"plus|{owner}|{expires}|{issued}|{key_id}".encode("utf-8")
    blob = payload + sign(secret, payload)
    return PREFIX + base64.urlsafe_b64encode(blob).decode().rstrip("=")


def parse_key(key, public_hex=None):
    """-> dict(owner, expires 'YYYYMMDD'|'0', issued, id) or raises ValueError with a readable reason."""
    key = "".join(str(key).split())
    if not key.startswith(PREFIX):
        raise ValueError("This is not an Eclipse Plus key (it should start with ECL1-).")
    try:
        body = key[len(PREFIX):]
        blob = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except Exception:
        raise ValueError("The key is damaged: copy it again in full.")
    if len(blob) < 64 + 10:
        raise ValueError("The key is incomplete: copy it again in full.")
    payload, sig = blob[:-64], blob[-64:]
    try:
        pub = bytes.fromhex(public_hex or PUBLIC_KEY)
    except ValueError:
        raise ValueError("This build of Eclipse cannot check Plus keys.")
    if not verify(pub, payload, sig):
        raise ValueError("The key is not valid.")
    parts = payload.decode("utf-8", "replace").split("|")
    if len(parts) != 5 or parts[0] != "plus":
        raise ValueError("The key is not valid.")
    return {"owner": parts[1], "expires": parts[2], "issued": parts[3], "id": parts[4]}


def _day(yyyymmdd):
    return time.mktime(time.strptime(yyyymmdd, "%Y%m%d"))


class License:
    """Holds the activated key (data\\license.key) and answers 'is Plus active right now?'."""

    def __init__(self, data_dir):
        self.path = os.path.join(data_dir, "license.key")
        self.state_path = os.path.join(data_dir, "license.state")
        self.trial_path = os.path.join(data_dir, "license.trial")
        self.info = None          # parsed key
        self.error = ""           # why the stored key is not usable
        self.reload()

    def reload(self):
        self.info, self.error = None, ""
        try:
            with open(self.path, encoding="utf-8") as f:
                key = f.read().strip()
        except OSError:
            return
        try:
            self.info = parse_key(key)
        except ValueError as e:
            self.error = str(e)

    def _clock_ok(self):
        """Refuses a clock set far back in time to stretch an expired subscription."""
        now = time.time()
        seen = 0.0
        try:
            with open(self.state_path, encoding="utf-8") as f:
                seen = float(json.load(f).get("seen", 0))
        except Exception:
            pass
        if now > seen:
            try:
                with open(self.state_path, "w", encoding="utf-8") as f:
                    json.dump({"seen": now}, f)
            except OSError:
                pass
            return True
        return now > seen - 2 * 86400

    def expires_at(self):
        """Epoch seconds at the end of the last valid day (grace included), or None for lifetime."""
        if not self.info or self.info["expires"] in ("", "0"):
            return None
        return _day(self.info["expires"]) + (1 + GRACE_DAYS) * 86400

    def key_active(self):
        if not self.info:
            return False
        end = self.expires_at()
        if end is not None and (time.time() >= end or not self._clock_ok()):
            return False
        return True

    # ---- free trial: once per Windows user, recorded in the registry AND in data\ (deleting one is not enough)
    def _trial_start(self):
        starts = []
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, TRIAL_REG) as k:
                starts.append(float(winreg.QueryValueEx(k, TRIAL_VALUE)[0]))
        except (OSError, ValueError, ImportError):
            pass
        try:
            with open(self.trial_path, encoding="utf-8") as f:
                starts.append(float(f.read().strip()))
        except (OSError, ValueError):
            pass
        return min(starts) if starts else None

    def trial_end(self):
        st = self._trial_start()
        return None if st is None else st + TRIAL_DAYS * 86400

    def trial_used(self):
        return self._trial_start() is not None

    def trial_active(self):
        st = self._trial_start()
        if st is None:
            return False
        now = time.time()
        if st > now + 86400:                  # start date in the future: clock or registry tampering
            return False
        return now < st + TRIAL_DAYS * 86400 and self._clock_ok()

    def trial_ended(self):
        return self.trial_used() and not self.trial_active() and not self.key_active()

    def start_trial(self):
        if self.trial_used():
            raise ValueError("The free trial has already been used on this PC.")
        now = str(int(time.time()))
        try:
            import winreg
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, TRIAL_REG, 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, TRIAL_VALUE, 0, winreg.REG_SZ, now)
        except (OSError, ImportError):
            pass
        with open(self.trial_path, "w", encoding="utf-8") as f:
            f.write(now)
        self._clock_ok()

    # ---- overall state
    def active(self):
        return self.key_active() or self.trial_active()

    def kind(self):
        """'key', 'trial' or None: what is giving Plus right now."""
        return "key" if self.key_active() else "trial" if self.trial_active() else None

    def expired(self):
        """A subscription key is present but no longer valid."""
        return bool(self.info) and not self.key_active()

    def days_left(self):
        """Days until the paid period (or the trial) ends; grace days are not advertised. None = lifetime."""
        if self.key_active():
            if self.info["expires"] in ("", "0"):
                return None
            return max(0, int((_day(self.info["expires"]) + 86400 - time.time()) // 86400))
        if self.trial_active():
            return max(0, int(-(-(self.trial_end() - time.time()) // 86400)))
        return 0

    def describe(self):
        if self.key_active() or self.info:
            if self.info["expires"] in ("", "0"):
                return f"Lifetime license  ·  {self.info['owner']}"
            d = time.strftime("%d/%m/%Y", time.strptime(self.info["expires"], "%Y%m%d"))
            if self.key_active():
                return f"Active until {d}  ·  {self.info['owner']}"
            return f"Expired on {d}  ·  {self.info['owner']}"
        if self.trial_active():
            return "Free trial until " + time.strftime("%d/%m/%Y %H:%M", time.localtime(self.trial_end()))
        if self.trial_used():
            return "Your free trial has ended"
        return self.error or "Free version"

    def activate(self, key):
        info = parse_key(key)                       # raises ValueError with the reason
        if info["expires"] not in ("", "0") and time.time() >= _day(info["expires"]) + (1 + GRACE_DAYS) * 86400:
            raise ValueError("This key has already expired. Renew your subscription to get a new one.")
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("".join(str(key).split()))
        self.reload()
        return info

    def deactivate(self):
        try:
            os.remove(self.path)
        except OSError:
            pass
        self.reload()
