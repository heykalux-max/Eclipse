"""
ECLIPSE - script deobfuscation
Peels the layers malware uses to hide its real code (PowerShell -EncodedCommand, Base64, gzip/deflate,
[char] codes, Chr()/ChrW(), String.fromCharCode, string concatenation, reversed strings, backtick and
caret noise, %xx / \\xNN escapes) so the detection rules can run on the code that actually executes.

deobfuscate(text) -> list of Layer(technique, text, blob)
    text  decoded readable code (may be "")
    blob  decoded binary payload worth scanning as a file (PE, archive...), else None
"""
from __future__ import annotations

import base64
import binascii
import gzip
import re
import zlib
from dataclasses import dataclass

MAX_LAYERS = 4          # nested encodings followed (b64 -> gzip -> b64 -> ...)
MAX_BLOBS = 24          # Base64 candidates decoded per layer
MAX_TEXT = 4 * 1024 * 1024
MIN_B64 = 60            # shorter Base64 strings are usually ids/hashes, not code


@dataclass
class Layer:
    technique: str
    text: str = ""
    blob: bytes | None = None


# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #
_PRINTABLE = set(range(32, 127)) | {9, 10, 13}


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    sample = b[:4096]
    return sum(1 for c in sample if c in _PRINTABLE) / len(sample)


def _bytes_to_text(b: bytes) -> str | None:
    """Readable text from decoded bytes (UTF-16LE as PowerShell uses, or UTF-8/latin-1), else None."""
    if len(b) >= 4 and b[1:2] == b"\x00" and b[3:4] == b"\x00":
        try:
            t = b.decode("utf-16le", "ignore")
            if t and sum(1 for ch in t[:2000] if ch.isprintable() or ch in "\r\n\t") / len(t[:2000]) > 0.9:
                return t
        except Exception:
            pass
    if _printable_ratio(b) > 0.9:
        return b.decode("utf-8", "ignore")
    return None


def _decompress(b: bytes) -> bytes | None:
    if b[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(b)[:MAX_TEXT]
        except Exception:
            return None
    for wbits in (15, -15):                     # zlib stream, raw deflate (DeflateStream)
        try:
            d = zlib.decompressobj(wbits)
            out = d.decompress(b, MAX_TEXT)
            if out and len(out) > len(b) // 2:
                return out
        except Exception:
            continue
    return None


BINARY_MAGIC = (b"MZ", b"PK\x03\x04", b"\xd0\xcf\x11\xe0", b"%PDF", b"\x7fELF", b"Rar!", b"7z\xbc\xaf")


def _classify(raw: bytes, technique: str, out: list):
    """Adds the decoded bytes as text, decompressed text or binary payload."""
    if not raw:
        return
    if raw.startswith(BINARY_MAGIC):
        out.append(Layer(technique + " -> binary payload", "", raw[:MAX_TEXT]))
        return
    t = _bytes_to_text(raw)
    if t is not None:
        out.append(Layer(technique, t[:MAX_TEXT]))
        return
    d = _decompress(raw)
    if d:
        if d.startswith(BINARY_MAGIC):
            out.append(Layer(technique + " + compression -> binary payload", "", d))
            return
        t = _bytes_to_text(d)
        if t is not None:
            out.append(Layer(technique + " + compression", t))


def _b64(s: str) -> bytes | None:
    s = re.sub(r"\s+", "", s)
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


# --------------------------------------------------------------------------- #
#  Normalisers: cheap rewrites that undo noise without "decoding"
# --------------------------------------------------------------------------- #
_PS_TICK = re.compile(r"`(?=[^0abefnrtv\s`'\"$])")          # I`nv`oke-Ex`pression
_CARET = re.compile(r"\^(?=[A-Za-z0-9.\\/:\-])")             # p^o^w^e^r^s^h^e^l^l
# a whole chain of literals joined by + (PS/JS/Python), & (VBS) or .. (Lua): 'Inv'+'oke'+'-Exp'+'ression'
_LIT = r"""(?:'[^'\r\n]{0,400}'|"[^"\r\n]{0,400}")"""
_CHAIN = re.compile(_LIT + r"(?:[ \t]*(?:\+|&|\.\.)[ \t]*" + _LIT + ")+")
_LIT_PARTS = re.compile(r"""'([^'\r\n]*)'|"([^"\r\n]*)\"""")
# PowerShell: $v = 'literal'  ...  & ($v) / .($v) / $v
_PS_ASSIGN = re.compile(r"""\$(\w{1,40})\s*=\s*(['"])([^'"\r\n]{1,300})\2\s*(?=;|\r|\n|$)""")
_PS_CALL_STR = re.compile(r"""(&|\.)\s*\(\s*['"]([\w.-]{2,80})['"]\s*\)|&\s*['"]([\w.-]{2,80})['"]""")
_CHAR_PS = re.compile(r"\[char\]\s*(0x[0-9a-f]+|\d{1,6})", re.I)
_CHR_VB = re.compile(r"\bchrw?\$?\s*\(\s*(&h[0-9a-f]+|\d{1,6})\s*\)", re.I)
_FROMCC = re.compile(r"string\.fromcharcode\s*\(([\d\s,x]+)\)", re.I)
_HEX_ESC = re.compile(r"\\x([0-9a-fA-F]{2})")
_UNI_ESC = re.compile(r"\\u([0-9a-fA-F]{4})")
_PCT_ESC = re.compile(r"%([0-9a-fA-F]{2})")
_CHARARRAY = re.compile(r"\[char\[\]\]\s*\(\s*((?:\d{2,3}\s*,\s*){4,}\d{2,3})\s*\)", re.I)
_REVERSE_VB = re.compile(r"strreverse\s*\(\s*\"([^\"]{4,2000})\"\s*\)", re.I)
_REVERSE_PS = re.compile(r"""(['"])([^'"]{8,4000})\1\s*\[\s*-1\s*\.\.\s*-?\(?[\w.$]+\)?\s*\]""")
_REVERSE_PY = re.compile(r"""(['"])([^'"]{8,4000})\1\s*\[\s*::\s*-1\s*\]""")


def _num(tok: str) -> int:
    tok = tok.strip().lower()
    if tok.startswith("&h"):
        return int(tok[2:], 16)
    return int(tok, 16) if tok.startswith("0x") else int(tok)


def _chr(n: int) -> str:
    try:
        return chr(n) if 0 < n < 0x110000 else ""
    except ValueError:
        return ""


# which tricks make sense in which language: a backtick is PowerShell's escape but ordinary text in
# Python/Markdown, ^ is batch's escape but a regex anchor elsewhere, \xNN is normal in Python strings...
FEATURES = {
    "ps":  {"tick", "concat", "charps", "reverse_ps", "vars"},
    "bat": {"caret", "concat", "charps", "vars"},
    "cmd": {"tick", "caret", "concat", "charps", "vars"},        # LNK targets / command lines
    "vb":  {"concat", "chr", "reverse_vb"},
    "js":  {"concat", "fromcc", "escapes", "unescape"},
    "py":  {"reverse_py"},
    "any": {"concat", "charps", "chr", "fromcc", "unescape"},
}
LANG_BY_EXT = {".ps1": "ps", ".psm1": "ps", ".psd1": "ps", ".bat": "bat", ".cmd": "bat",
               ".vbs": "vb", ".vbe": "vb", ".wsf": "vb", ".wsh": "vb", ".vba": "vb",
               ".js": "js", ".jse": "js", ".mjs": "js", ".hta": "js", ".html": "js", ".htm": "js",
               ".py": "py", ".pyw": "py", ".lnk": "cmd"}


def lang_for(name: str) -> str:
    n = name.lower()
    return LANG_BY_EXT.get(n[n.rfind("."):] if "." in n else "", "any")


def normalise(text: str, lang: str = "any") -> tuple[str, list[str]]:
    """Returns (rewritten text, techniques applied)."""
    feat = FEATURES.get(lang, FEATURES["any"])
    used = []
    t = text

    if "tick" in feat and t.count("`") > 5:
        n = _PS_TICK.sub("", t)
        if len(t) - len(n) >= 3:
            used.append("PowerShell backtick obfuscation")
            t = n

    if "caret" in feat and t.count("^") > 15:
        n = _CARET.sub("", t)
        if n != t:
            used.append("caret escapes")
        t = n

    if "concat" in feat:
        n = _join_chains(t)
        if n != t:
            used.append("string concatenation")
        t = n

    def sub_count(key, rx, fn, label, minimum=4):
        nonlocal t
        if key not in feat:
            return
        hits = len(rx.findall(t))
        if hits >= minimum:
            t = rx.sub(fn, t)
            used.append(label)

    sub_count("charps", _CHARARRAY, lambda m: '"' + "".join(_chr(int(x)) for x in m.group(1).split(",")) + '"',
              "[char[]] array", 1)
    sub_count("charps", _CHAR_PS, lambda m: '"' + _chr(_num(m.group(1))) + '"', "[char] codes")
    sub_count("chr", _CHR_VB, lambda m: '"' + _chr(_num(m.group(1))) + '"', "Chr()/ChrW() codes")
    sub_count("fromcc", _FROMCC, lambda m: '"' + "".join(_chr(_num(x)) for x in m.group(1).split(",") if x.strip())
              + '"', "String.fromCharCode", 1)
    sub_count("escapes", _HEX_ESC, lambda m: chr(int(m.group(1), 16)), "\\x escapes", 12)
    sub_count("escapes", _UNI_ESC, lambda m: chr(int(m.group(1), 16)), "\\u escapes", 12)
    if re.search(r"unescape\s*\(|decodeuri", t, re.I):
        sub_count("unescape", _PCT_ESC, lambda m: chr(int(m.group(1), 16)), "%xx escapes (unescape)", 12)
    sub_count("reverse_vb", _REVERSE_VB, lambda m: '"' + m.group(1)[::-1] + '"', "StrReverse", 1)
    sub_count("reverse_ps", _REVERSE_PS, lambda m: '"' + m.group(2)[::-1] + '"', "reversed string", 1)
    sub_count("reverse_py", _REVERSE_PY, lambda m: '"' + m.group(2)[::-1] + '"', "reversed string", 1)

    if used and "concat" in feat:   # char codes become "a"+"b"+... pieces: join them too
        t = _join_chains(t)

    if "vars" not in feat:
        return t, used
    # PowerShell variables holding a literal: $c='IEX'; & ($c) $x  ->  IEX $x
    assigns = {m.group(1).lower(): m.group(3) for m in _PS_ASSIGN.finditer(t)} if "$" in t else {}
    if assigns and len(assigns) <= 200:
        def var_sub(m):
            v = assigns.get(m.group(1).lower())
            return f"'{v}'" if v is not None else m.group(0)
        body = _PS_ASSIGN.sub(lambda m: "", t)
        n = re.sub(r"\$(\w{1,40})\b", var_sub, body)
        if n != body:
            used.append("variable substitution")
            t = n
    n = _PS_CALL_STR.sub(lambda m: (m.group(2) or m.group(3)) if m.group(1) != "." else "." + m.group(2), t)
    if n != t:
        if "dynamic invocation" not in used:
            used.append("dynamic invocation")
        t = n
    return t, used


def _join_chains(t: str) -> str:
    def join(m):
        parts = _LIT_PARTS.findall(m.group(0))
        return '"' + "".join(a or b for a, b in parts) + '"'
    return _CHAIN.sub(join, t)


# --------------------------------------------------------------------------- #
#  Decoders: encodings that hide a whole new layer of code
# --------------------------------------------------------------------------- #
_ENC_CMD = re.compile(r"(?:^|\s)[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+['\"]?([A-Za-z0-9+/=]{16,})",
                      re.I)
_FROM_B64 = re.compile(r"frombase64string\s*\(\s*['\"]([A-Za-z0-9+/=\s]{16,})['\"]", re.I)
_B64_ANY = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{%d,}={0,2}(?![A-Za-z0-9+/])" % MIN_B64)
_SIG_BLOCK = re.compile(r"# SIG # Begin signature block.*?# SIG # End signature block", re.S | re.I)
_PEM = re.compile(r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", re.S)
_DATA_URI = re.compile(r"data:[\w/+.-]+;base64,[A-Za-z0-9+/=]+", re.I)


def _decode_layer(text: str) -> list[Layer]:
    out: list[Layer] = []
    seen = set()

    def add_b64(s, technique):
        key = s[:200]
        if key in seen:
            return
        seen.add(key)
        raw = _b64(s)
        if raw and len(raw) >= 12:
            _classify(raw, technique, out)

    for m in _ENC_CMD.finditer(text):
        raw = _b64(m.group(1))
        seen.add(m.group(1)[:200])
        if raw:
            t = raw.decode("utf-16le", "ignore") if b"\x00" in raw[:8] else raw.decode("utf-8", "ignore")
            if t.strip():
                out.append(Layer("PowerShell -EncodedCommand", t[:MAX_TEXT]))
    for m in _FROM_B64.finditer(text):
        add_b64(m.group(1), "FromBase64String")

    # generic Base64: skip blocks that are legitimately Base64 (signatures, certificates, inline images)
    scrub = _DATA_URI.sub(" ", _PEM.sub(" ", _SIG_BLOCK.sub(" ", text)))
    for n, m in enumerate(_B64_ANY.finditer(scrub)):
        if n >= MAX_BLOBS:
            break
        s = m.group(0)
        if len(set(s)) < 16:                      # "AAAAAAAA..." padding, separators
            continue
        add_b64(s, "Base64")
    return out


_HINTS = ("frombase64", "[char]", "chr(", "chrw(", "fromcharcode", "strreverse", "unescape(", "\\x", "\\u0",
          "[-1..", "[::-1]", "-enc", "-ec ", "-e ", "/enc", "gzipstream", "deflatestream", "b64decode",
          "atob(", "decompress")
_HAS_B64 = re.compile(r"[A-Za-z0-9+/]{%d}" % MIN_B64)


def worth_trying(text: str, lang: str = "any") -> bool:
    """Cheap pre-check so ordinary files skip the (much slower) deobfuscation pass."""
    if not text:
        return False
    head = text[:MAX_TEXT]
    low = head.lower()
    if any(h in low for h in _HINTS):
        return True
    feat = FEATURES.get(lang, FEATURES["any"])
    if ("tick" in feat and head.count("`") > 5) or ("caret" in feat and head.count("^") > 15):
        return True
    if low.count("'+'") + low.count('"+"') + low.count("' + '") + low.count('" + "') + low.count('" & "') > 2:
        return True
    return bool(_HAS_B64.search(head))


def deobfuscate(text: str, max_layers: int = MAX_LAYERS, lang: str = "any") -> list[Layer]:
    """All hidden layers found in text (normalised view first, then decoded ones, recursively).
    lang: "ps", "bat", "cmd", "vb", "js", "py" or "any" (see FEATURES / lang_for)."""
    if not text:
        return []
    text = text[:MAX_TEXT]
    layers: list[Layer] = []
    norm, used = normalise(text, lang)
    if used and norm != text:
        layers.append(Layer(" + ".join(used), norm))
    frontier = [(norm, "", lang)]
    for _ in range(max_layers):
        nxt = []
        for t, chain, cur in frontier:
            for lay in _decode_layer(t):
                # what PowerShell decodes is PowerShell; a generic Base64 layer keeps the parent language
                sub = "ps" if lay.technique.startswith(("PowerShell", "FromBase64")) else cur
                lay.technique = f"{chain} > {lay.technique}" if chain else lay.technique
                if lay.text:
                    n2, u2 = normalise(lay.text, sub)
                    if u2:
                        lay.text = n2
                        lay.technique += " + " + " + ".join(u2)
                    nxt.append((lay.text, lay.technique, sub))
                layers.append(lay)
                if len(layers) >= 40:
                    return layers
        if not nxt:
            break
        frontier = nxt
    return layers
