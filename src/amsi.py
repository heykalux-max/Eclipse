"""
ECLIPSE - AMSI (Antimalware Scan Interface)
Hands in-memory content (decoded scripts, files inside archives, macro source) to the antivirus engine
registered with Windows (normally Microsoft Defender) without writing anything to disk.

scan(data, name) -> (status, detail)
    status: "detected" | "blocked" | "clean" | "unavailable"
"""
from __future__ import annotations

import ctypes
import threading
from ctypes import wintypes

AMSI_RESULT_DETECTED = 32768
AMSI_RESULT_BLOCKED_BY_ADMIN_START = 0x4000
AMSI_RESULT_BLOCKED_BY_ADMIN_END = 0x4FFF
MAX_SCAN = 8 * 1024 * 1024      # AMSI providers cap what they inspect anyway

_lock = threading.Lock()
_state = {"ctx": None, "dll": None, "tried": False}


def _load():
    """Initialises AMSI once per process. Returns (dll, context) or (None, None)."""
    if _state["tried"]:
        return _state["dll"], _state["ctx"]
    _state["tried"] = True
    try:
        dll = ctypes.WinDLL("amsi.dll")
        dll.AmsiInitialize.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
        dll.AmsiInitialize.restype = ctypes.c_long
        dll.AmsiScanBuffer.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, wintypes.LPCWSTR,
                                       ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
        dll.AmsiScanBuffer.restype = ctypes.c_long
        dll.AmsiUninitialize.argtypes = [ctypes.c_void_p]
        ctx = ctypes.c_void_p()
        if dll.AmsiInitialize("Eclipse", ctypes.byref(ctx)) != 0 or not ctx.value:
            return None, None
        _state.update(dll=dll, ctx=ctx)
        return dll, ctx
    except (OSError, AttributeError):
        return None, None


def available() -> bool:
    with _lock:
        dll, ctx = _load()
    return dll is not None


def scan(data, name: str = "eclipse-buffer") -> tuple[str, str]:
    if isinstance(data, str):
        data = data.encode("utf-16le", "surrogatepass")   # what script hosts submit; providers expect it
    if not data:
        return "clean", ""
    data = bytes(data[:MAX_SCAN])
    with _lock:
        dll, ctx = _load()
        if dll is None:
            return "unavailable", "AMSI is not available on this system"
        buf = ctypes.create_string_buffer(data, len(data))
        result = ctypes.c_int(0)
        hr = dll.AmsiScanBuffer(ctx, buf, len(data), name[:200], None, ctypes.byref(result))
    if hr != 0:
        return "unavailable", f"AmsiScanBuffer error 0x{hr & 0xFFFFFFFF:08X}"
    r = result.value
    if r >= AMSI_RESULT_DETECTED:
        return "detected", "the Windows antivirus engine flags this content as malware"
    if AMSI_RESULT_BLOCKED_BY_ADMIN_START <= r <= AMSI_RESULT_BLOCKED_BY_ADMIN_END:
        return "blocked", "content blocked by administrator policy"
    return "clean", ""
