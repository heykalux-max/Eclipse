"""
ECLIPSE - Threat Scanner
Futuristic GUI for analyzing files (RAT / malware) and links (phishing).
"""
import multiprocessing
if __name__ == "__main__":
    multiprocessing.freeze_support()    # system-scan worker processes re-launch this exe
import json
import math
import os
import random
import re
import sys
import time
import traceback
import uuid

from PySide6.QtCore import (Qt, QTimer, QThread, Signal, QPropertyAnimation, QVariantAnimation,
                            QEasingCurve, Property, QPointF, QRectF, QRect, QSize, QUrl, QPoint)
from PySide6.QtGui import (QPainter, QColor, QPen, QBrush, QLinearGradient, QRadialGradient,
                           QConicalGradient, QFont, QPainterPath, QIcon, QPixmap, QDesktopServices,
                           QFontMetrics, QGuiApplication, QRegion, QAction)
from PySide6.QtWidgets import (QApplication, QWidget, QFrame, QLabel, QPushButton, QVBoxLayout,
                               QHBoxLayout, QGridLayout, QStackedWidget, QListWidget, QListWidgetItem,
                               QScrollArea, QPlainTextEdit, QLineEdit, QFileDialog, QProgressBar,
                               QCheckBox, QSizePolicy, QMessageBox, QGraphicsDropShadowEffect,
                               QAbstractItemView, QDialog, QGraphicsOpacityEffect, QStyledItemDelegate, QStyle,
                               QSystemTrayIcon, QMenu)

import engine
import sysmon
import fullscan

APP_NAME = "ECLIPSE"
VERSION = "1.1.0"

# --------------------------------------------------------------------------- #
#  Percorsi
# --------------------------------------------------------------------------- #
def app_identity():
    """(install folder, launcher exe, own executables, own folders) for source, PyInstaller and Nuitka builds."""
    if "__compiled__" in globals():                      # Nuitka (onefile: runs from an extracted copy)
        inner = os.path.abspath(sys.executable)
        launcher = (os.environ.get("NUITKA_ONEFILE_BINARY")
                    or getattr(__compiled__, "original_argv0", None) or sys.argv[0])  # noqa: F821
        launcher = os.path.abspath(launcher)
        if not os.path.isfile(launcher) and os.path.isfile(launcher + ".exe"):
            launcher += ".exe"
        if not os.path.isfile(launcher):
            launcher = inner
        base = os.path.dirname(launcher)
        return base, launcher, [launcher, inner], [base, os.path.dirname(inner)]
    if getattr(sys, "frozen", False):                    # PyInstaller
        exe = os.path.abspath(sys.executable)
        return os.path.dirname(exe), exe, [exe], [os.path.dirname(exe)]
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return base, None, [], [base]


BASE, LAUNCHER, OWN_EXES, OWN_DIRS = app_identity()
DATA = os.path.join(BASE, "data")
QUAR = os.path.join(BASE, "Quarantine")
REPORTS = os.path.join(BASE, "Reports")
# System-scan workers re-import this module but get their paths from the parent: they must not
# create folders (in a Nuitka onefile build they would see the extraction folder as BASE).
# parent_process() is still None while a spawned worker imports this module and Nuitka strips
# "--multiprocessing-fork" from sys.argv, so several signals are checked.
_IS_WORKER = (
    __name__ == "__mp_main__"
    or "--multiprocessing-fork" in sys.argv
    or "--multiprocessing-fork" in getattr(sys, "orig_argv", ())
    or multiprocessing.parent_process() is not None
    # Nuitka onefile: only workers resolve the launcher to the extracted inner exe
    or ("__compiled__" in globals() and getattr(__compiled__, "onefile", False)  # noqa: F821
        and os.path.normcase(LAUNCHER or "") == os.path.normcase(os.path.abspath(sys.executable)))
)
if not _IS_WORKER:
    # old Italian folder names from earlier versions
    for _old, _new in (("Quarantena", QUAR), ("Report", REPORTS)):
        _op = os.path.join(BASE, _old)
        if os.path.isdir(_op) and not os.path.exists(_new):
            try:
                os.rename(_op, _new)
            except OSError:
                pass
    for _d in (DATA, QUAR, REPORTS):
        os.makedirs(_d, exist_ok=True)
engine.set_self(OWN_DIRS, OWN_EXES)                     # Eclipse never flags its own files
sysmon.init(DATA, OWN_EXES, LAUNCHER)

# --------------------------------------------------------------------------- #
#  Tema
# --------------------------------------------------------------------------- #
C = {
    # nero profondo + viola
    "bg": "#030205", "bg2": "#08060d", "panel": "#0c0914", "panel2": "#130d20",
    "border": "#221934", "cyan": "#b388ff", "violet": "#7c3aed", "magenta": "#d946ef",
    "green": "#34d399", "amber": "#fbbf24", "orange": "#fb923c", "red": "#f43f5e",
    "text": "#eee8f8", "muted": "#8b80a6", "dim": "#4b4163",
}
VERDICT_COLOR = {"SAFE": C["green"], "SUSPICIOUS": C["amber"], "DANGEROUS": C["red"]}
SEV_COLOR = {0: C["muted"], 1: "#a78bfa", 2: C["amber"], 3: C["orange"], 4: C["red"]}
HEAD = "Segoe UI Variable Display"
BODY = "Segoe UI"
MONO = "Consolas"

IC = {
    "home": "", "file": "", "link": "", "history": "", "settings": "",
    "shield": "", "folder": "", "upload": "", "search": "", "delete": "",
    "lock": "", "warn": "", "ok": "", "copy": "", "save": "",
    "refresh": "", "close": "", "min": "", "max": "", "restore": "",
    "bug": "", "download": "", "paste": "", "stop": "", "globe": "",
    "quarantine": "", "undo": "", "key": "", "info": "", "radar": "",
    "cpu": "\uE9D9", "power": "\uE7E8", "net": "\uE968", "add": "\uE710", "remove": "\uE738",
    "flash": "\uE945", "drive": "\uEDA2", "play": "\uE768", "pause": "\uE769",
}


def qc(hexstr, a=255):
    c = QColor(hexstr)
    c.setAlpha(a)
    return c


def mkfont(size, weight=QFont.Weight.Normal, family=BODY):
    f = QFont(family)
    if family == HEAD:
        f.setFamilies([HEAD, "Segoe UI Semibold", "Segoe UI"])
        if size < 10:
            f.setLetterSpacing(QFont.SpacingType.PercentageSpacing, 108)
    f.setPointSizeF(size)
    f.setWeight(weight)
    return f


def icon_font(size):
    f = QFont()
    f.setFamilies(["Segoe Fluent Icons", "Segoe MDL2 Assets"])
    f.setPointSizeF(size)
    return f


def short(s, n=64):
    s = str(s)
    return s if len(s) <= n else s[: n // 2 - 1] + "…" + s[-(n // 2 - 1):]


def softwrap(s, n=40):
    return re.sub(r"(\S{%d})(?=\S)" % n, "\\1\u200b", str(s))


def score_color(s):
    return C["green"] if s < 25 else C["amber"] if s < 60 else C["red"]


def lbl(text="", size=10, color=None, weight=QFont.Weight.Normal, family=BODY, wrap=False, sel=False):
    w = QLabel(text)
    w.setFont(mkfont(size, weight, family))
    w.setStyleSheet(f"color:{color or C['text']}; background:transparent;")
    w.setWordWrap(wrap)
    if sel:
        w.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return w


def icon_lbl(glyph, size=14, color=None):
    w = QLabel(glyph)
    w.setFont(icon_font(size))
    w.setStyleSheet(f"color:{color or C['cyan']}; background:transparent;")
    return w


QSS = f"""
QWidget {{ color: {C['text']}; }}
QToolTip {{ background: {C['panel2']}; color: {C['text']}; border: 1px solid {C['cyan']}; padding: 6px; }}
QScrollArea {{ background: transparent; border: none; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}
QScrollBar:vertical {{ background: transparent; width: 8px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: #3b2a5c; border-radius: 3px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {C['cyan']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: none; }}
QScrollBar:horizontal {{ height: 0; }}
QLineEdit, QPlainTextEdit {{
    background: rgba(255,255,255,5); border: 1px solid rgba(255,255,255,14); border-radius: 12px;
    padding: 10px 12px; selection-background-color: {C['violet']}; color: {C['text']};
}}
QLineEdit:focus, QPlainTextEdit:focus {{ border: 1px solid {C['violet']}; background: rgba(124,58,237,14); }}
QListWidget {{ background: transparent; border: none; outline: 0; }}
QListWidget::item {{ border: 1px solid transparent; border-radius: 12px; margin: 2px 2px; }}
QListWidget::item:hover {{ background: rgba(255,255,255,6); }}
QListWidget::item:selected {{ background: rgba(124,58,237,30); border: 1px solid rgba(179,136,255,70); }}
QProgressBar {{ background: rgba(255,255,255,8); border: none; border-radius: 2px; max-height: 4px; }}
QProgressBar::chunk {{ border-radius: 2px;
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 {C['violet']}, stop:1 {C['magenta']}); }}
QMenu {{ background: {C['panel']}; border: 1px solid {C['border']}; border-radius: 8px; padding: 6px; }}
QMenu::item {{ padding: 7px 22px 7px 14px; border-radius: 6px; color: {C['text']}; }}
QMenu::item:selected {{ background: rgba(124,58,237,60); }}
QMenu::separator {{ height: 1px; background: {C['border']}; margin: 4px 6px; }}
QMessageBox {{ background: {C['panel']}; }}
QMessageBox QLabel {{ color: {C['text']}; }}
QMessageBox QPushButton {{ background: {C['panel2']}; border: 1px solid {C['cyan']}; border-radius: 6px;
    padding: 6px 18px; color: {C['text']}; min-width: 70px; }}
"""


# --------------------------------------------------------------------------- #
#  Persistenza
# --------------------------------------------------------------------------- #
class Store:
    DEFAULTS = {"use_defender": True, "check_signature": True, "online_dns": True,
                "follow_redirects": False, "vt_key": "", "realtime": True, "watch_folders": [],
                "auto_quarantine": False, "notify": True, "tray_on_close": True}

    def __init__(self):
        self.settings_path = os.path.join(DATA, "settings.json")
        self.history_path = os.path.join(DATA, "history.json")
        self.settings = dict(self.DEFAULTS)
        self.history = []
        try:
            with open(self.settings_path, encoding="utf-8") as f:
                self.settings.update(json.load(f))
        except Exception:
            pass
        try:
            with open(self.history_path, encoding="utf-8") as f:
                self.history = json.load(f)
        except Exception:
            self.history = []

    def save_settings(self):
        with open(self.settings_path, "w", encoding="utf-8") as f:
            json.dump(self.settings, f, indent=2)

    def add(self, res):
        self.history.insert(0, res.to_dict())
        del self.history[1500:]

    def save_history(self):
        try:
            with open(self.history_path, "w", encoding="utf-8") as f:
                json.dump(self.history, f, ensure_ascii=False)
        except Exception:
            pass

    def stats(self):
        s = {"file": 0, "link": 0, "danger": 0, "sus": 0}
        for h in self.history:
            s[h["kind"]] = s.get(h["kind"], 0) + 1
            if h.get("verdict") == "DANGEROUS":
                s["danger"] += 1
            elif h.get("verdict") == "SUSPICIOUS":
                s["sus"] += 1
        return s


# --------------------------------------------------------------------------- #
#  Quarantena (file cifrati XOR, non eseguibili)
# --------------------------------------------------------------------------- #
XOR_TABLE = bytes(i ^ 0xA5 for i in range(256))


def quarantine_file(res):
    path = res.target
    qid = time.strftime("%Y%m%d%H%M%S") + "_" + uuid.uuid4().hex[:6]
    with open(path, "rb") as f:
        data = f.read()
    with open(os.path.join(QUAR, qid + ".eclq"), "wb") as f:
        f.write(data.translate(XOR_TABLE))
    meta = {"id": qid, "path": path, "name": os.path.basename(path), "date": time.time(),
            "score": res.score, "verdict": res.verdict, "sha256": res.meta.get("sha256", ""),
            "reason": res.findings[0].title if res.findings else ""}
    with open(os.path.join(QUAR, qid + ".json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    try:
        os.remove(path)
    except Exception:
        os.remove(os.path.join(QUAR, qid + ".eclq"))
        os.remove(os.path.join(QUAR, qid + ".json"))
        raise
    return qid


def quarantine_list():
    out = []
    for n in os.listdir(QUAR):
        if n.endswith(".json"):
            try:
                with open(os.path.join(QUAR, n), encoding="utf-8") as f:
                    out.append(json.load(f))
            except Exception:
                pass
    return sorted(out, key=lambda m: -m.get("date", 0))


def quarantine_restore(meta):
    src = os.path.join(QUAR, meta["id"] + ".eclq")
    dst = meta["path"]
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.exists(dst):
        root, ext = os.path.splitext(dst)
        dst = f"{root}_restored{ext}"
    with open(src, "rb") as f:
        data = f.read().translate(XOR_TABLE)
    with open(dst, "wb") as f:
        f.write(data)
    os.remove(src)
    os.remove(os.path.join(QUAR, meta["id"] + ".json"))
    return dst


def quarantine_delete(meta):
    for ext in (".eclq", ".json"):
        p = os.path.join(QUAR, meta["id"] + ext)
        if os.path.exists(p):
            os.remove(p)


# --------------------------------------------------------------------------- #
#  Worker thread
# --------------------------------------------------------------------------- #
class FileWorker(QThread):
    step = Signal(str)
    progress = Signal(int, int, str)
    result = Signal(object)
    done = Signal(int)

    def __init__(self, paths, settings):
        super().__init__()
        self.paths, self.settings, self.stop = paths, dict(settings), False

    def run(self):
        files = []
        for p in self.paths:
            if os.path.isdir(p):
                for root, dirs, fs in os.walk(p):
                    dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "__pycache__")]
                    for f in fs:
                        files.append(os.path.join(root, f))
                        if len(files) >= 2000:
                            break
                    if len(files) >= 2000 or self.stop:
                        break
            elif os.path.isfile(p):
                files.append(p)
        ls = engine.LinkScanner(self.settings, DATA)
        fs = engine.FileScanner(self.settings, DATA, ls)
        n = len(files)
        for i, f in enumerate(files):
            if self.stop:
                break
            self.progress.emit(i, n, os.path.basename(f))
            try:
                r = fs.scan(f, step=self.step.emit)
            except Exception as e:
                r = engine.ScanResult("file", f, os.path.basename(f))
                r.add(engine.MED, "Error", "Error during analysis", str(e))
                r.finalize()
            self.result.emit(r)
        self.progress.emit(n, n, "")
        self.done.emit(n)


class LinkWorker(QThread):
    progress = Signal(int, int, str)
    result = Signal(object)
    done = Signal(int)

    def __init__(self, urls, settings):
        super().__init__()
        self.urls, self.settings, self.stop = urls, dict(settings), False

    def run(self):
        ls = engine.LinkScanner(self.settings, DATA)
        n = len(self.urls)
        for i, u in enumerate(self.urls):
            if self.stop:
                break
            self.progress.emit(i, n, u)
            try:
                r = ls.scan(u)
            except Exception as e:
                r = engine.ScanResult("link", u, u[:90])
                r.add(engine.MED, "Error", "Error during analysis", str(e))
                r.finalize()
            self.result.emit(r)
        self.progress.emit(n, n, "")
        self.done.emit(n)


class FeedWorker(QThread):
    done = Signal(int, list)

    def run(self):
        try:
            n, info = engine.LinkScanner({}, DATA).update_feed()
        except Exception as e:
            n, info = 0, [str(e)]
        self.done.emit(n, info)


# --------------------------------------------------------------------------- #
#  Widget grafici
# --------------------------------------------------------------------------- #
class Animated(QWidget):
    """Widget with a timer that runs only while visible, and slows down when the window is in the background."""
    def __init__(self, interval=33, parent=None):
        super().__init__(parent)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._step)
        self._interval = interval
        self._n = 0

    def showEvent(self, e):
        self._timer.start(self._interval)
        super().showEvent(e)

    def hideEvent(self, e):
        self._timer.stop()
        super().hideEvent(e)

    def _step(self):
        w = self.window()
        if w.isMinimized() or not w.isVisible():
            return
        if not w.isActiveWindow():
            self._n = (self._n + 1) % 4
            if self._n:
                return
        self.tick()

    def tick(self):
        self.update()


class EclipseLogo(Animated):
    def __init__(self, size=48, parent=None, speed=1.0, intensity=1.0):
        super().__init__(33, parent)
        self.setFixedSize(size, size)
        self.angle = random.random() * 360
        self.speed = speed
        self.intensity = intensity
        self.t = 0.0

    def tick(self):
        self.angle = (self.angle + self.speed * 2) % 360
        self.t += 0.08
        self.update()

    def paintEvent(self, e):
        paint_eclipse(self, self.width(), self.angle, self.t, self.intensity)


def paint_eclipse(device, w, angle, t=0.0, intensity=1.0):
    p = QPainter(device)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    c = QPointF(w / 2, w / 2)
    r = w * 0.29
    pulse = 0.85 + 0.15 * math.sin(t)
    g = QRadialGradient(c, w / 2)
    g.setColorAt(0.0, qc(C["violet"], int(110 * intensity * pulse)))
    g.setColorAt(0.5, qc(C["cyan"], int(45 * intensity * pulse)))
    g.setColorAt(1.0, qc("#000000", 0))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(g)
    p.drawEllipse(c, w / 2, w / 2)
    # anello esterno tratteggiato
    pen2 = QPen(qc(C["cyan"], int(110 * intensity)), max(1.0, w / 120))
    pen2.setDashPattern([2, 5])
    pen2.setDashOffset(-angle / 4)
    p.setPen(pen2)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawEllipse(c, r * 1.48, r * 1.48)
    # corona
    cg = QConicalGradient(c, -angle)
    cg.setColorAt(0.00, qc("#ffffff"))
    cg.setColorAt(0.06, qc(C["cyan"]))
    cg.setColorAt(0.35, qc(C["violet"], 220))
    cg.setColorAt(0.60, qc(C["magenta"], 120))
    cg.setColorAt(0.85, qc(C["cyan"], 40))
    cg.setColorAt(1.00, qc("#ffffff"))
    p.setPen(QPen(QBrush(cg), max(2.0, w * 0.055)))
    p.drawEllipse(c, r * 1.1, r * 1.1)
    # luna
    mg = QRadialGradient(c + QPointF(-r * 0.35, -r * 0.35), r * 1.5)
    mg.setColorAt(0, qc("#1b2140"))
    mg.setColorAt(1, qc("#010205"))
    p.setPen(QPen(qc("#ffffff", 25), 1))
    p.setBrush(mg)
    p.drawEllipse(c, r, r)
    # "anello di diamante"
    a = math.radians(angle)
    hp = c + QPointF(math.cos(a) * r * 1.1, math.sin(a) * r * 1.1)
    hg = QRadialGradient(hp, w * 0.11)
    hg.setColorAt(0, qc("#ffffff", int(230 * intensity)))
    hg.setColorAt(0.25, qc(C["cyan"], int(120 * intensity)))
    hg.setColorAt(1, qc(C["cyan"], 0))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(hg)
    p.drawEllipse(hp, w * 0.11, w * 0.11)
    p.end()


def paint_app_icon(device, s):
    """Icona dell'app: tessera neon con eclisse luminosa, leggibile anche a 16px."""
    p = QPainter(device)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    m = max(0.5, s * 0.03)
    tile = QRectF(m, m, s - 2 * m, s - 2 * m)
    rad = s * 0.22
    bg = QLinearGradient(tile.topLeft(), tile.bottomRight())
    bg.setColorAt(0, qc("#141a45"))
    bg.setColorAt(0.55, qc("#080b1f"))
    bg.setColorAt(1, qc("#14072a"))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(bg)
    p.drawRoundedRect(tile, rad, rad)
    c = QPointF(s / 2, s / 2)
    glow = QRadialGradient(c, s * 0.48)
    glow.setColorAt(0.0, qc(C["violet"], 150))
    glow.setColorAt(0.45, qc(C["cyan"], 70))
    glow.setColorAt(1.0, qc(C["cyan"], 0))
    path = QPainterPath()
    path.addRoundedRect(tile, rad, rad)
    p.fillPath(path, glow)
    bp = QLinearGradient(tile.topLeft(), tile.bottomRight())
    bp.setColorAt(0, qc(C["cyan"]))
    bp.setColorAt(1, qc(C["violet"]))
    p.setPen(QPen(QBrush(bp), max(1.0, s * 0.025)))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawRoundedRect(tile, rad, rad)
    r = s * 0.25
    # alone della corona
    p.setPen(QPen(qc(C["cyan"], 70), s * 0.13))
    p.drawEllipse(c, r * 1.12, r * 1.12)
    cg = QConicalGradient(c, 45)
    cg.setColorAt(0.00, qc("#ffffff"))
    cg.setColorAt(0.10, qc(C["cyan"]))
    cg.setColorAt(0.40, qc(C["violet"]))
    cg.setColorAt(0.70, qc(C["magenta"]))
    cg.setColorAt(0.90, qc(C["cyan"]))
    cg.setColorAt(1.00, qc("#ffffff"))
    p.setPen(QPen(QBrush(cg), max(1.6, s * 0.075)))
    p.drawEllipse(c, r * 1.12, r * 1.12)
    # luna
    mg = QRadialGradient(c + QPointF(-r * 0.3, r * 0.3), r * 1.4)
    mg.setColorAt(0, qc("#161b38"))
    mg.setColorAt(1, qc("#010205"))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(mg)
    p.drawEllipse(c, r, r)
    # anello di diamante
    hp = c + QPointF(math.cos(math.radians(-45)) * r * 1.12, math.sin(math.radians(-45)) * r * 1.12)
    hg = QRadialGradient(hp, s * 0.16)
    hg.setColorAt(0, qc("#ffffff"))
    hg.setColorAt(0.2, qc("#ffffff", 200))
    hg.setColorAt(0.45, qc(C["cyan"], 90))
    hg.setColorAt(1, qc(C["cyan"], 0))
    p.setBrush(hg)
    p.drawEllipse(hp, s * 0.16, s * 0.16)
    p.end()


def make_app_icon():
    icon = QIcon()
    for s in (16, 24, 32, 48, 64, 128, 256):
        pm = QPixmap(s, s)
        pm.fill(Qt.GlobalColor.transparent)
        paint_app_icon(pm, s)
        icon.addPixmap(pm)
    return icon


class Gauge(QWidget):
    def __init__(self, size=170, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self._v = 0.0
        self.verdict = ""
        self.anim = QPropertyAnimation(self, b"value", self)
        self.anim.setDuration(1100)
        self.anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    def getv(self):
        return self._v

    def setv(self, v):
        self._v = v
        self.update()

    value = Property(float, getv, setv)

    def set_score(self, score, verdict):
        self.verdict = verdict
        self.anim.stop()
        self.anim.setStartValue(0.0)
        self.anim.setEndValue(float(score))
        self.anim.start()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w = self.width()
        m = 14
        rect = QRectF(m, m, w - 2 * m, w - 2 * m)
        col = qc(score_color(self._v))
        # tacche
        p.save()
        p.translate(w / 2, w / 2)
        for i in range(41):
            ang = 225 - i * 270 / 40
            rad = math.radians(ang)
            active = i / 40 <= self._v / 100 + 1e-6
            p.setPen(QPen(col if active else qc(C["dim"], 120), 1.6 if i % 5 == 0 else 1))
            r1, r2 = w / 2 - 3, w / 2 - (9 if i % 5 == 0 else 6)
            p.drawLine(QPointF(math.cos(rad) * r1, -math.sin(rad) * r1),
                       QPointF(math.cos(rad) * r2, -math.sin(rad) * r2))
        p.restore()
        inner = rect.adjusted(8, 8, -8, -8)
        p.setPen(QPen(qc("#141c35"), 9, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawArc(inner, 225 * 16, -270 * 16)
        span = -270 * 16 * self._v / 100
        glow = QColor(col)
        glow.setAlpha(60)
        p.setPen(QPen(glow, 18, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawArc(inner, 225 * 16, int(span))
        p.setPen(QPen(col, 9, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawArc(inner, 225 * 16, int(span))
        # testo
        p.setPen(qc(C["text"]))
        p.setFont(mkfont(w * 0.17, QFont.Weight.Bold, HEAD))
        p.drawText(QRectF(0, w * 0.27, w, w * 0.3), Qt.AlignmentFlag.AlignCenter, f"{int(round(self._v))}")
        p.setPen(qc(C["muted"]))
        p.setFont(mkfont(w * 0.05, QFont.Weight.Normal, HEAD))
        p.drawText(QRectF(0, w * 0.53, w, w * 0.1), Qt.AlignmentFlag.AlignCenter, "THREAT SCORE")
        if self.verdict:
            p.setPen(col)
            p.setFont(mkfont(w * 0.054, QFont.Weight.Bold, HEAD))
            p.drawText(QRectF(0, w * 0.68, w, w * 0.12), Qt.AlignmentFlag.AlignCenter, self.verdict)
        p.end()


class Radar(Animated):
    def __init__(self, parent=None):
        super().__init__(16, parent)
        self.setMinimumSize(220, 220)
        self.angle = 0
        self.blips = []

    def tick(self):
        self.angle = (self.angle + 3.2) % 360
        if random.random() < 0.06:
            self.blips.append([random.uniform(0.15, 0.92), random.uniform(0, 360), 1.0])
        for b in self.blips:
            b[2] -= 0.012
        self.blips = [b for b in self.blips if b[2] > 0]
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        s = min(self.width(), self.height()) - 20
        c = QPointF(self.width() / 2, self.height() / 2)
        r = s / 2
        bg = QRadialGradient(c, r)
        bg.setColorAt(0, qc(C["cyan"], 25))
        bg.setColorAt(1, qc(C["cyan"], 5))
        p.setBrush(bg)
        p.setPen(QPen(qc(C["cyan"], 120), 1.4))
        p.drawEllipse(c, r, r)
        p.setBrush(Qt.BrushStyle.NoBrush)
        for k in (0.25, 0.5, 0.75):
            p.setPen(QPen(qc(C["cyan"], 45), 1))
            p.drawEllipse(c, r * k, r * k)
        p.drawLine(QPointF(c.x() - r, c.y()), QPointF(c.x() + r, c.y()))
        p.drawLine(QPointF(c.x(), c.y() - r), QPointF(c.x(), c.y() + r))
        # spazzata
        cg = QConicalGradient(c, -self.angle)
        cg.setColorAt(0.0, qc(C["cyan"], 170))
        cg.setColorAt(0.12, qc(C["cyan"], 30))
        cg.setColorAt(0.2, qc(C["cyan"], 0))
        cg.setColorAt(1.0, qc(C["cyan"], 0))
        path = QPainterPath()
        path.addEllipse(c, r, r)
        p.fillPath(path, QBrush(cg))
        a = math.radians(self.angle)
        p.setPen(QPen(qc("#ffffff", 200), 1.5))
        p.drawLine(c, c + QPointF(math.cos(a) * r, math.sin(a) * r))
        for d, ang, life in self.blips:
            ra = math.radians(ang)
            pt = c + QPointF(math.cos(ra) * r * d, math.sin(ra) * r * d)
            col = qc(C["magenta"] if d > 0.7 else C["green"], int(255 * life))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(col)
            p.drawEllipse(pt, 3.2, 3.2)
            p.setBrush(qc(col.name(), int(60 * life)))
            p.drawEllipse(pt, 8 * (1.6 - life), 8 * (1.6 - life))
        p.end()


class HudCard(QFrame):
    """Card minimal in vetro scuro: bordo sottile che si illumina al passaggio del mouse."""
    def __init__(self, parent=None, accent=None, pad=18):
        super().__init__(parent)
        self.accent = accent or C["cyan"]
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(pad, pad, pad, pad)
        self.lay.setSpacing(10)
        self._h = 0.0
        self._ha = QVariantAnimation(self)
        self._ha.setDuration(260)
        self._ha.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._ha.valueChanged.connect(self._seth)

    def _seth(self, v):
        self._h = v
        self.update()

    def _anim(self, to):
        self._ha.stop()
        self._ha.setStartValue(self._h)
        self._ha.setEndValue(to)
        self._ha.start()

    def enterEvent(self, e):
        self._anim(1.0)
        super().enterEvent(e)

    def leaveEvent(self, e):
        self._anim(0.0)
        super().leaveEvent(e)

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        g = QLinearGradient(r.topLeft(), r.bottomLeft())
        g.setColorAt(0, QColor(22, 14, 36, 165))
        g.setColorAt(1, QColor(10, 7, 17, 175))
        p.setBrush(g)
        bc = QColor(self.accent)
        bc.setAlpha(int(16 + 80 * self._h))
        p.setPen(QPen(bc if self._h > 0.01 else QColor(255, 255, 255, 14), 1))
        p.drawRoundedRect(r, 18, 18)
        # riflesso sul bordo superiore
        tg = QLinearGradient(r.left(), 0, r.right(), 0)
        tg.setColorAt(0.0, qc(self.accent, 0))
        tg.setColorAt(0.5, qc(self.accent, int(70 + 110 * self._h)))
        tg.setColorAt(1.0, qc(self.accent, 0))
        p.setPen(QPen(QBrush(tg), 1.2))
        p.drawLine(QPointF(r.left() + 30, r.top() + 0.6), QPointF(r.right() - 30, r.top() + 0.6))
        p.end()


class GlowButton(QPushButton):
    """Pulsante con bagliore, riflesso animato e effetto onda al clic."""
    def __init__(self, text, glyph=None, kind="primary", parent=None):
        super().__init__(parent)
        self.kind = kind
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(40)
        self.setStyleSheet("QPushButton { border: none; background: transparent; }")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12 if text else 0, 0, 12 if text else 0, 0)
        lay.setSpacing(8)
        lay.addStretch()
        self.base_col = "#ffffff" if kind == "primary" else (C["red"] if kind == "danger" else C["text"])
        if glyph:
            self.ic = icon_lbl(glyph, 11, self.base_col if kind != "ghost" else C["cyan"])
            self.ic.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            lay.addWidget(self.ic)
        self.tl = lbl(text, 9.5, self.base_col, QFont.Weight.DemiBold, HEAD)
        self.tl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        if text:
            lay.addWidget(self.tl)
        lay.addStretch()
        fm = QFontMetrics(self.tl.font())
        self.setMinimumWidth(fm.horizontalAdvance(text) + (54 if glyph else 34) if text else 44)
        self._h = 0.0
        self._shine = -1.0
        self.ripples = []
        self.ha = QVariantAnimation(self)
        self.ha.setDuration(240)
        self.ha.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.ha.valueChanged.connect(self._seth)
        self.sa = QVariantAnimation(self)
        self.sa.setDuration(750)
        self.sa.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self.sa.setStartValue(-0.3)
        self.sa.setEndValue(1.3)
        self.sa.valueChanged.connect(self._setshine)
        self.rt = QTimer(self)
        self.rt.timeout.connect(self._ripple_tick)
        if kind == "primary":
            self.fx = QGraphicsDropShadowEffect(self)
            self.fx.setOffset(0, 4)
            self.fx.setColor(qc(C["violet"], 160))
            self.fx.setBlurRadius(18)
            self.setGraphicsEffect(self.fx)

    def _seth(self, v):
        self._h = v
        if self.kind == "primary":
            self.fx.setBlurRadius(18 + 22 * v)
        self.update()

    def _setshine(self, v):
        self._shine = v
        self.update()

    def _ripple_tick(self):
        for r in self.ripples:
            r[1] += 0.045
        self.ripples = [r for r in self.ripples if r[1] < 1]
        if not self.ripples:
            self.rt.stop()
        self.update()

    def enterEvent(self, e):
        if self.isEnabled():
            self.ha.stop(); self.ha.setStartValue(self._h); self.ha.setEndValue(1.0); self.ha.start()
            if self.kind == "primary":
                self.sa.stop(); self.sa.start()
        super().enterEvent(e)

    def leaveEvent(self, e):
        self.ha.stop(); self.ha.setStartValue(self._h); self.ha.setEndValue(0.0); self.ha.start()
        super().leaveEvent(e)

    def mousePressEvent(self, e):
        if self.isEnabled():
            self.ripples.append([e.position(), 0.0])
            self.rt.start(16)
        super().mousePressEvent(e)

    def setEnabled(self, on):
        super().setEnabled(on)
        col = self.base_col if on else C["dim"]
        self.tl.setStyleSheet(f"color:{col}; background:transparent;")
        if hasattr(self, "ic"):
            ic = col if (self.kind != "ghost" or not on) else C["cyan"]
            self.ic.setStyleSheet(f"color:{ic}; background:transparent;")
        if not on:
            self._seth(0.0)

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        rad = 12
        path = QPainterPath()
        path.addRoundedRect(r, rad, rad)
        on = self.isEnabled()
        h = self._h
        if self.kind == "primary":
            g = QLinearGradient(r.topLeft(), r.topRight())
            if on:
                c1 = QColor(C["violet"]).lighter(100 + int(18 * h))
                c2 = QColor(C["magenta"]).lighter(100 + int(12 * h))
            else:
                c1 = c2 = QColor("#1a1328")
            g.setColorAt(0, c1)
            g.setColorAt(1, c2)
            p.fillPath(path, g)
            ig = QLinearGradient(r.topLeft(), r.bottomLeft())
            ig.setColorAt(0, QColor(255, 255, 255, 40 if on else 0))
            ig.setColorAt(0.5, QColor(255, 255, 255, 0))
            p.fillPath(path, ig)
            if -0.3 < self._shine < 1.3 and on:
                x = r.left() + self._shine * r.width()
                sg = QLinearGradient(x - 40, 0, x + 40, 0)
                sg.setColorAt(0, QColor(255, 255, 255, 0))
                sg.setColorAt(0.5, QColor(255, 255, 255, 70))
                sg.setColorAt(1, QColor(255, 255, 255, 0))
                p.save(); p.setClipPath(path); p.fillRect(r, sg); p.restore()
        else:
            acc = QColor(C["red"] if self.kind == "danger" else C["cyan"])
            fill = QColor(acc); fill.setAlpha(int(6 + 26 * h))
            p.fillPath(path, fill if on else QColor(255, 255, 255, 4))
            bc = QColor(acc); bc.setAlpha(int((70 if self.kind == "danger" else 22) + 120 * h))
            p.setPen(QPen(bc if on else QColor(255, 255, 255, 10), 1))
            p.drawPath(path)
        if self.ripples:
            p.save()
            p.setClipPath(path)
            p.setPen(Qt.PenStyle.NoPen)
            maxr = math.hypot(r.width(), r.height())
            for pos, t in self.ripples:
                p.setBrush(QColor(255, 255, 255, int(70 * (1 - t))))
                p.drawEllipse(pos, maxr * t, maxr * t)
            p.restore()
        p.end()


class Toggle(QCheckBox):
    def __init__(self, checked=False, parent=None):
        super().__init__(parent)
        self.setFixedSize(50, 26)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._pos = 1.0 if checked else 0.0
        self.setChecked(checked)
        self.anim = QPropertyAnimation(self, b"knob", self)
        self.anim.setDuration(180)
        self.anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.toggled.connect(self._go)

    def getk(self):
        return self._pos

    def setk(self, v):
        self._pos = v
        self.update()

    knob = Property(float, getk, setk)

    def _go(self, on):
        self.anim.stop()
        self.anim.setStartValue(self._pos)
        self.anim.setEndValue(1.0 if on else 0.0)
        self.anim.start()

    def hitButton(self, pos):
        return self.rect().contains(pos)

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(1, 1, self.width() - 2, self.height() - 2)
        on = self._pos
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(255, 255, 255, 18))
        p.drawRoundedRect(r, 12, 12)
        if on > 0:
            g = QLinearGradient(r.topLeft(), r.topRight())
            g.setColorAt(0, qc(C["violet"], int(255 * on)))
            g.setColorAt(1, qc(C["magenta"], int(255 * on)))
            p.setBrush(g)
            p.drawRoundedRect(r, 12, 12)
        x = 3 + on * (self.width() - 26)
        glow = QRadialGradient(QPointF(x + 10, 13), 16)
        glow.setColorAt(0, qc(C["magenta"], int(120 * on)))
        glow.setColorAt(1, qc(C["magenta"], 0))
        p.setBrush(glow)
        p.drawEllipse(QPointF(x + 10, 13), 16, 16)
        p.setBrush(qc("#ffffff"))
        p.drawEllipse(QRectF(x, 3, 20, 20))
        p.end()


class DropZone(Animated):
    dropped = Signal(list)
    clicked = Signal()

    def __init__(self, parent=None):
        super().__init__(40, parent)
        self.setAcceptDrops(True)
        self.setMinimumHeight(170)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.off = 0.0
        self.hover = False
        self.t = 0.0

    def tick(self):
        self.off = (self.off + (1.6 if self.hover else 0.5)) % 100
        self.t += 0.05
        self.update()

    def mousePressEvent(self, e):
        self.clicked.emit()

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
            self.hover = True

    def dragLeaveEvent(self, e):
        self.hover = False

    def dropEvent(self, e):
        self.hover = False
        paths = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
        if paths:
            self.dropped.emit(paths)

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        hv = 1.0 if self.hover or self.underMouse() else 0.0
        bg = QLinearGradient(r.topLeft(), r.bottomLeft())
        bg.setColorAt(0, qc(C["violet"], int(14 + 26 * hv)))
        bg.setColorAt(1, qc(C["violet"], int(4 + 10 * hv)))
        p.setBrush(bg)
        pen = QPen(qc(C["cyan"], int(55 + 150 * hv)), 1.2)
        pen.setDashPattern([5, 6])
        pen.setDashOffset(-self.off)
        p.setPen(pen)
        p.drawRoundedRect(r, 18, 18)
        cx, cy = r.center().x(), r.center().y() - 20
        # onde che si espandono attorno all'icona
        p.setBrush(Qt.BrushStyle.NoBrush)
        for k in range(3):
            ph = (self.t * 0.35 + k / 3) % 1.0
            p.setPen(QPen(qc(C["cyan"], int(110 * (1 - ph))), 1))
            p.drawEllipse(QPointF(cx, cy), 22 + 34 * ph, 22 + 34 * ph)
        g = QRadialGradient(QPointF(cx, cy), 26)
        g.setColorAt(0, qc(C["violet"], 200))
        g.setColorAt(1, qc(C["magenta"], 90))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(g)
        p.drawEllipse(QPointF(cx, cy), 24, 24)
        p.setFont(icon_font(17))
        p.setPen(qc("#ffffff"))
        p.drawText(QRectF(cx - 24, cy - 24 + 2 * math.sin(self.t * 1.6), 48, 48),
                   Qt.AlignmentFlag.AlignCenter, IC["upload"])
        p.setFont(mkfont(12, QFont.Weight.DemiBold, HEAD))
        p.setPen(qc(C["text"]))
        p.drawText(QRectF(r.left(), cy + 40, r.width(), 24), Qt.AlignmentFlag.AlignCenter,
                   "Drop files or folders here")
        p.setFont(mkfont(9))
        p.setPen(qc(C["muted"]))
        p.drawText(QRectF(r.left(), cy + 63, r.width(), 20), Qt.AlignmentFlag.AlignCenter,
                   "or click to browse")
        p.end()


class Chip(QLabel):
    def __init__(self, text, color, parent=None, size=8):
        super().__init__(text, parent)
        self.setFont(mkfont(size, QFont.Weight.Bold, HEAD))
        c = QColor(color)
        self.setStyleSheet(f"color:{color}; background: rgba({c.red()},{c.green()},{c.blue()},28);"
                           f"border: 1px solid rgba({c.red()},{c.green()},{c.blue()},60);"
                           f"border-radius: 9px; padding: 2px 9px;")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)


class ResultItem(QWidget):
    def __init__(self, res, parent=None):
        super().__init__(parent)
        self.res = res
        col = VERDICT_COLOR.get(res.verdict, C["muted"])
        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 8, 12, 8)
        lay.setSpacing(10)
        bar = QFrame()
        bar.setFixedSize(3, 30)
        bar.setStyleSheet(f"background:{col}; border-radius:1px;")
        lay.addWidget(bar)
        lay.addWidget(icon_lbl(IC["file"] if res.kind == "file" else IC["globe"], 13, col))
        v = QVBoxLayout()
        v.setSpacing(1)
        name = lbl("", 10, C["text"], QFont.Weight.DemiBold)
        fm = QFontMetrics(name.font())
        name.setText(fm.elidedText(res.name, Qt.TextElideMode.ElideMiddle, 260))
        name.setToolTip(res.target)
        if res.kind == "file":
            sub = f"{res.meta.get('type', '?')}  ·  {res.meta.get('size', '')}"
        else:
            sub = res.meta.get("domain", "")
        sub += "  ·  " + time.strftime("%b %d, %H:%M", time.localtime(res.timestamp))
        v.addWidget(name)
        v.addWidget(lbl(sub, 8, C["muted"]))
        lay.addLayout(v, 1)
        lay.addWidget(Chip(res.verdict, col))
        sc = lbl(str(res.score), 13, col, QFont.Weight.Bold, HEAD)
        sc.setFixedWidth(34)
        sc.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        lay.addWidget(sc)

    def fade_in(self, delay=0):
        """Comparsa morbida del risultato."""
        self.fx = QGraphicsOpacityEffect(self)
        self.fx.setOpacity(0.0)
        self.setGraphicsEffect(self.fx)
        self.fa = QPropertyAnimation(self.fx, b"opacity", self)
        self.fa.setDuration(450)
        self.fa.setStartValue(0.0)
        self.fa.setEndValue(1.0)
        self.fa.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.fa.finished.connect(lambda: self.setGraphicsEffect(None))
        QTimer.singleShot(delay, self.fa.start)


class RowSpec:
    """What a list row shows (painted by RowDelegate: no child widgets, so thousands of rows stay fast)."""
    __slots__ = ("g", "t", "s", "c", "n", "col", "ic", "sc", "born")

    def __init__(self, glyph, title, sub, chips, score, col, icon_col=None, score_col=None, fade=False):
        self.g, self.t, self.s, self.c, self.n = glyph, title, sub, list(chips), score
        self.col, self.ic, self.sc = col, icon_col or col, score_col or col
        self.born = time.time() if fade else 0.0


ROW_ROLE = Qt.ItemDataRole.UserRole + 1


class RowDelegate(QStyledItemDelegate):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.f_icon = icon_font(12)
        self.f_title = mkfont(9.5, QFont.Weight.DemiBold)
        self.f_sub = mkfont(8, family=MONO)
        self.f_chip = mkfont(7, QFont.Weight.Bold, HEAD)
        self.f_score = mkfont(12, QFont.Weight.Bold, HEAD)
        self.m_title, self.m_sub, self.m_chip = (QFontMetrics(f) for f in (self.f_title, self.f_sub, self.f_chip))
        self.c_text, self.c_muted = QColor(C["text"]), QColor(C["muted"])

    def paint(self, p, opt, idx):
        d = idx.data(ROW_ROLE)
        if d is None:
            return super().paint(p, opt, idx)
        p.save()
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        r = QRectF(opt.rect).adjusted(2, 2, -2, -2)
        if d.born:
            a = (time.time() - d.born) / 0.45
            if a < 1:
                p.setOpacity(max(0.0, a))
                r.translate(0, 6 * (1 - a))
            else:
                d.born = 0.0
        sel = bool(opt.state & QStyle.StateFlag.State_Selected)
        hov = bool(opt.state & QStyle.StateFlag.State_MouseOver)
        if sel:
            p.setBrush(QColor(124, 58, 237, 30))
            p.setPen(QPen(QColor(179, 136, 255, 70), 1))
            p.drawRoundedRect(r, 12, 12)
        elif hov:
            p.setBrush(QColor(255, 255, 255, 7))
            p.setPen(Qt.PenStyle.NoPen)
            p.drawRoundedRect(r, 12, 12)
        cy = r.center().y()
        x = r.left() + 10
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(d.col))
        p.drawRoundedRect(QRectF(x, cy - 14, 3, 28), 1.5, 1.5)
        x += 13
        p.setFont(self.f_icon)
        p.setPen(QColor(d.ic))
        p.drawText(QRectF(x, r.top(), 22, r.height()), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, d.g)
        x += 28
        right = r.right() - 12
        p.setFont(self.f_score)
        p.setPen(QColor(d.sc))
        p.drawText(QRectF(right - 36, r.top(), 36, r.height()), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight,
                   str(d.n))
        right -= 46
        p.setFont(self.f_chip)
        for text, cc in reversed(d.c):
            cw = self.m_chip.horizontalAdvance(text) + 18
            cr = QRectF(right - cw, cy - 10, cw, 20)
            c = QColor(cc)
            fill, bc = QColor(c), QColor(c)
            fill.setAlpha(28)
            bc.setAlpha(60)
            p.setPen(QPen(bc, 1))
            p.setBrush(fill)
            p.drawRoundedRect(cr, 9, 9)
            p.setPen(c)
            p.drawText(cr, Qt.AlignmentFlag.AlignCenter, text)
            right -= cw + 8
        tw = max(20, int(right - x))
        p.setFont(self.f_title)
        p.setPen(self.c_text)
        p.drawText(QRectF(x, cy - 18, tw, 18), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                   self.m_title.elidedText(d.t, Qt.TextElideMode.ElideMiddle, tw))
        p.setFont(self.f_sub)
        p.setPen(self.c_muted)
        p.drawText(QRectF(x, cy + 1, tw, 16), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                   self.m_sub.elidedText(d.s, Qt.TextElideMode.ElideMiddle, tw))
        p.restore()


class FastList(QListWidget):
    """QListWidget whose rows are painted by RowDelegate, with a cheap fade-in for new rows."""
    def __init__(self, parent=None, row_h=52):
        super().__init__(parent)
        self.row_h = row_h
        self.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setItemDelegate(RowDelegate(self))
        self.setUniformItemSizes(True)
        self.setMouseTracking(True)
        self.viewport().setAttribute(Qt.WidgetAttribute.WA_Hover)
        self._fade_until = 0.0
        self._ft = QTimer(self)
        self._ft.timeout.connect(self._fade_tick)

    def add_row(self, data, spec, top=False, tip=""):
        it = QListWidgetItem()
        it.setSizeHint(QSize(100, self.row_h))
        it.setData(Qt.ItemDataRole.UserRole, data)
        it.setData(ROW_ROLE, spec)
        if tip:
            it.setToolTip(tip)
        if top:
            self.insertItem(0, it)
        else:
            self.addItem(it)
        if spec.born:
            self._fade_until = time.time() + 0.5
            if not self._ft.isActive():
                self._ft.start(16)
        return it

    def _fade_tick(self):
        self.viewport().update()
        if time.time() > self._fade_until:
            self._ft.stop()


class FindingRow(QFrame):
    def __init__(self, f, parent=None):
        super().__init__(parent)
        col = SEV_COLOR[f.severity]
        c = QColor(col)
        self.setStyleSheet(f"QFrame {{ background: rgba({c.red()},{c.green()},{c.blue()},10);"
                           f"border-left: 2px solid {col}; border-radius: 10px; }}")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 7, 10, 7)
        lay.setSpacing(10)
        chip = Chip(engine.SEV_NAME[f.severity], col, size=7.5)
        chip.setFixedWidth(70)
        lay.addWidget(chip, 0, Qt.AlignmentFlag.AlignTop)
        v = QVBoxLayout()
        v.setSpacing(2)
        t = lbl(f.title, 9.5, C["text"], QFont.Weight.DemiBold, wrap=True)
        t.setStyleSheet(t.styleSheet() + "border:none;")
        v.addWidget(t)
        if f.detail:
            d = lbl(softwrap(f.detail), 8.5, C["muted"], family=MONO, wrap=True, sel=True)
            d.setStyleSheet(d.styleSheet() + "border:none;")
            v.addWidget(d)
        lay.addLayout(v, 1)
        cat = lbl(f.category.upper(), 7.5, C["dim"], QFont.Weight.Bold, HEAD)
        cat.setStyleSheet(cat.styleSheet() + "border:none;")
        lay.addWidget(cat, 0, Qt.AlignmentFlag.AlignTop)


class PageFade(QWidget):
    """Transizione tra pagine: dissolvenza incrociata con scivolamento verso l'alto."""
    def __init__(self, parent):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._p = 1.0
        self.old = self.new = None
        self.page = None
        self.hide()
        self.anim = QVariantAnimation(self)
        self.anim.setDuration(420)
        self.anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.anim.valueChanged.connect(self._set)
        self.anim.finished.connect(self._finish)

    def _set(self, v):
        self._p = v
        self.update()

    @staticmethod
    def snap(w):
        if w.layout():
            w.layout().activate()
        pm = QPixmap(w.size() * w.devicePixelRatioF())
        pm.setDevicePixelRatio(w.devicePixelRatioF())
        pm.fill(Qt.GlobalColor.transparent)
        w.render(pm, QPoint(), QRegion(), QWidget.RenderFlag.DrawChildren)
        return pm

    def run(self, stack, i):
        if self.anim.state() == QVariantAnimation.State.Running:
            self.anim.stop()
            self._finish()
        old_w = stack.currentWidget()
        self.old = self.snap(old_w) if old_w else None
        stack.setCurrentIndex(i)
        self.page = stack.currentWidget()
        self.new = self.snap(self.page)
        self.page.hide()
        self.setGeometry(stack.geometry())
        self.raise_()
        self.show()
        self.anim.setStartValue(0.0)
        self.anim.setEndValue(1.0)
        self.anim.start()

    def _finish(self):
        if self.page is not None:
            self.page.show()
        self.page = None
        self.old = self.new = None
        self.hide()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        t = self._p
        if self.old is not None:
            p.setOpacity(max(0.0, 1 - t * 1.6))
            p.drawPixmap(QPointF(0, -14 * t), self.old)
        if self.new is not None:
            p.setOpacity(t)
            p.drawPixmap(QPointF(0, 22 * (1 - t)), self.new)
        p.end()


class Toast(QFrame):
    def __init__(self, parent, title, msg, color):
        super().__init__(parent)
        c = QColor(color)
        self.setStyleSheet(f"QFrame#toast {{ background: rgba(14,9,24,245); border: 1px solid {color};"
                           f"border-radius: 12px; }}")
        self.setObjectName("toast")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 12, 18, 12)
        lay.addWidget(icon_lbl(IC["warn"] if color != C["green"] else IC["ok"], 16, color))
        v = QVBoxLayout()
        v.setSpacing(1)
        v.addWidget(lbl(title, 10, color, QFont.Weight.Bold, HEAD))
        m = lbl(msg, 9, C["text"], wrap=True)
        m.setMaximumWidth(320)
        v.addWidget(m)
        lay.addLayout(v)
        fx = QGraphicsDropShadowEffect(self)
        fx.setBlurRadius(30)
        fx.setOffset(0, 0)
        fx.setColor(qc(color, 140))
        self.setGraphicsEffect(fx)
        self.adjustSize()
        x = parent.width() - self.width() - 26
        self.move(x + 60, 64)
        self.show()
        self.raise_()
        self.a = QPropertyAnimation(self, b"pos", self)
        self.a.setDuration(320)
        self.a.setEasingCurve(QEasingCurve.Type.OutBack)
        self.a.setStartValue(QPoint(x + 60, 64))
        self.a.setEndValue(QPoint(x, 64))
        self.a.start()
        QTimer.singleShot(4200, self.close_anim)

    def close_anim(self):
        self.b = QPropertyAnimation(self, b"pos", self)
        self.b.setDuration(260)
        self.b.setStartValue(self.pos())
        self.b.setEndValue(self.pos() + QPoint(self.width() + 60, 0))
        self.b.finished.connect(self.deleteLater)
        self.b.start()


def section_title(text, glyph=None):
    w = QWidget()
    h = QHBoxLayout(w)
    h.setContentsMargins(0, 0, 0, 0)
    h.setSpacing(8)
    if glyph:
        h.addWidget(icon_lbl(glyph, 11, C["cyan"]))
    h.addWidget(lbl(text.upper(), 9.5, C["cyan"], QFont.Weight.Bold, HEAD))
    line = QFrame()
    line.setFixedHeight(1)
    line.setStyleSheet(f"background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 rgba(179,136,255,90), stop:1 transparent);")
    h.addWidget(line, 1)
    return w


# --------------------------------------------------------------------------- #
#  Pannello dettagli risultato
# --------------------------------------------------------------------------- #
class ResultDetail(HudCard):
    quarantined = Signal(object)

    def __init__(self, kind, parent=None):
        super().__init__(parent, accent=C["violet"])
        self.kind = kind
        self.res = None
        self.stack = QStackedWidget()
        self.lay.addWidget(self.stack)

        # vuoto
        empty = QWidget()
        ev = QVBoxLayout(empty)
        ev.addStretch()
        logo = EclipseLogo(130, speed=0.5, intensity=0.6)
        ev.addWidget(logo, 0, Qt.AlignmentFlag.AlignHCenter)
        t = lbl("WAITING FOR A SCAN", 12, C["muted"], QFont.Weight.Bold, HEAD)
        t.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ev.addWidget(t)
        s = lbl({"history": "Select a history item to see its details.",
                 "system": "Choose a scan type and press START. Detections will appear here."}.get(
                    kind, "Import a file or enter a link: results will appear here."), 9, C["dim"], wrap=True)
        s.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ev.addWidget(s)
        ev.addStretch()
        self.stack.addWidget(empty)

        # scansione in corso
        scan = QWidget()
        sv = QVBoxLayout(scan)
        sv.addStretch()
        self.radar = Radar()
        self.radar.setFixedSize(250, 250)
        sv.addWidget(self.radar, 0, Qt.AlignmentFlag.AlignHCenter)
        self.scan_title = lbl("SCANNING", 13, C["cyan"], QFont.Weight.Bold, HEAD)
        self.scan_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sv.addWidget(self.scan_title)
        self.scan_target = lbl("", 9.5, C["text"], family=MONO)
        self.scan_target.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sv.addWidget(self.scan_target)
        self.scan_step = lbl("", 9, C["muted"])
        self.scan_step.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sv.addWidget(self.scan_step)
        sv.addStretch()
        self.stack.addWidget(scan)

        # dettaglio
        det = QWidget()
        dv = QVBoxLayout(det)
        dv.setContentsMargins(0, 0, 0, 0)
        dv.setSpacing(12)
        top = QHBoxLayout()
        top.setSpacing(18)
        self.gauge = Gauge(170)
        top.addWidget(self.gauge, 0, Qt.AlignmentFlag.AlignTop)
        info = QVBoxLayout()
        info.setSpacing(4)
        self.v_label = lbl("", 20, C["green"], QFont.Weight.Bold, HEAD)
        info.addWidget(self.v_label)
        self.v_name = lbl("", 11, C["text"], QFont.Weight.DemiBold, sel=True)
        info.addWidget(self.v_name)
        self.v_target = lbl("", 8.5, C["muted"], family=MONO, sel=True)
        info.addWidget(self.v_target)
        self.meta_box = QGridLayout()
        self.meta_box.setHorizontalSpacing(12)
        self.meta_box.setVerticalSpacing(3)
        info.addSpacing(4)
        info.addLayout(self.meta_box)
        info.addStretch()
        top.addLayout(info, 1)
        dv.addLayout(top)
        self.f_title = section_title("Findings", IC["radar"])
        dv.addWidget(self.f_title)
        self.f_scroll = QScrollArea()
        self.f_scroll.setWidgetResizable(True)
        self.f_host = QWidget()
        self.f_lay = QVBoxLayout(self.f_host)
        self.f_lay.setContentsMargins(0, 0, 6, 0)
        self.f_lay.setSpacing(6)
        self.f_scroll.setWidget(self.f_host)
        dv.addWidget(self.f_scroll, 1)
        btns = QHBoxLayout()
        self.b_report = GlowButton("REPORT", IC["save"], "ghost")
        self.b_copy = GlowButton("COPY", IC["copy"], "ghost")
        self.b_copy.setToolTip("Copy SHA-256 (file) or URL (link)")
        self.b_folder = GlowButton("LOCATION", IC["folder"], "ghost")
        self.b_quar = GlowButton("QUARANTINE", IC["lock"], "danger")
        self.b_report.clicked.connect(self.export)
        self.b_copy.clicked.connect(self.copy)
        self.b_folder.clicked.connect(self.open_folder)
        self.b_quar.clicked.connect(self.quarantine)
        for b in (self.b_report, self.b_copy, self.b_folder):
            btns.addWidget(b)
        btns.addStretch()
        btns.addWidget(self.b_quar)
        dv.addLayout(btns)
        self.stack.addWidget(det)

    def scanning(self, target="", step=""):
        self.stack.setCurrentIndex(1)
        fm = QFontMetrics(self.scan_target.font())
        self.scan_target.setText(fm.elidedText(target, Qt.TextElideMode.ElideMiddle, 380))
        self.scan_step.setText(step)

    def set_step(self, s):
        self.scan_step.setText(s + "...")

    def clear(self):
        self.res = None
        self.stack.setCurrentIndex(0)

    def show_result(self, res):
        self.res = res
        self.stack.setCurrentIndex(2)
        col = VERDICT_COLOR.get(res.verdict, C["muted"])
        self.gauge.set_score(res.score, res.verdict)
        txt = {"SAFE": "NO THREATS FOUND", "SUSPICIOUS": "SUSPICIOUS ACTIVITY", "DANGEROUS": "THREAT DETECTED"}
        if res.kind == "link":
            txt = {"SAFE": "TRUSTED LINK", "SUSPICIOUS": "SUSPICIOUS LINK", "DANGEROUS": "LIKELY PHISHING"}
        self.v_label.setText(txt.get(res.verdict, res.verdict))
        self.v_label.setStyleSheet(f"color:{col}; background:transparent;")
        self.v_name.setText(short(res.name, 58))
        self.v_name.setToolTip(res.name)
        tgt = res.target if res.kind == "file" else res.meta.get("domain", "")
        self.v_target.setText(short(tgt, 66))
        self.v_target.setToolTip(tgt)
        while self.meta_box.count():
            it = self.meta_box.takeAt(0)
            if it.widget():
                it.widget().deleteLater()
        keys = ["type", "format", "size", "signature", "defender", "virustotal", "company", "origin",
                "document", "sha256", "registered_domain", "ip", "http", "page_title", "redirect", "pdf"]
        row = 0
        for k in keys:
            if k in res.meta and res.meta[k] not in ("", None):
                v = str(res.meta[k])
                self.meta_box.addWidget(lbl(k.replace("_", " ").upper(), 7.5, C["dim"], QFont.Weight.Bold, HEAD), row, 0,
                                        Qt.AlignmentFlag.AlignTop)
                vl = lbl(softwrap(short(v, 140), 44), 8.5, C["text"], family=MONO, wrap=True, sel=True)
                vl.setToolTip(v)
                self.meta_box.addWidget(vl, row, 1)
                row += 1
        self.meta_box.setColumnStretch(1, 1)
        while self.f_lay.count():
            it = self.f_lay.takeAt(0)
            if it.widget():
                it.widget().deleteLater()
        shown = [f for f in res.findings]
        self.f_title.findChildren(QLabel)[-1].setText(f"FINDINGS  ({len([f for f in shown if f.severity > 0])})")
        if not shown:
            ok = lbl("✓  No indicators of compromise found.", 10, C["green"])
            self.f_lay.addWidget(ok)
        for f in shown:
            self.f_lay.addWidget(FindingRow(f))
        self.f_lay.addStretch()
        is_file = res.kind == "file"
        self.b_folder.setVisible(is_file)
        self.b_quar.setVisible(is_file and os.path.exists(res.target))

    def export(self):
        if not self.res:
            return
        safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in self.res.name)[:60]
        path, _ = QFileDialog.getSaveFileName(self, "Export report",
                                              os.path.join(REPORTS, f"{safe}_report.txt"),
                                              "Text report (*.txt);;JSON (*.json)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            if path.lower().endswith(".json"):
                json.dump(self.res.to_dict(), f, ensure_ascii=False, indent=2)
            else:
                f.write(self.res.report_text())
        self.window().toast("REPORT SAVED", os.path.basename(path), C["green"])

    def copy(self):
        if not self.res:
            return
        txt = self.res.meta.get("sha256", self.res.target) if self.res.kind == "file" else self.res.target
        QGuiApplication.clipboard().setText(txt)
        self.window().toast("COPIED", txt[:64], C["cyan"])

    def open_folder(self):
        if self.res and self.res.kind == "file":
            d = os.path.dirname(self.res.target)
            if os.path.isdir(d):
                QDesktopServices.openUrl(QUrl.fromLocalFile(d))

    def quarantine(self):
        if not self.res or not os.path.exists(self.res.target):
            return
        mb = QMessageBox(self)
        mb.setWindowTitle("Quarantine")
        mb.setText(f"Move to quarantine?\n\n{self.res.target}\n\nThe file will be encrypted and removed from its "
                   f"original location. You can restore it from the Quarantine section.")
        mb.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if mb.exec() != QMessageBox.StandardButton.Yes:
            return
        try:
            quarantine_file(self.res)
            self.b_quar.setVisible(False)
            self.window().toast("FILE ISOLATED", f"{self.res.name} has been quarantined.", C["green"])
            self.quarantined.emit(self.res)
        except Exception as e:
            self.window().toast("QUARANTINE ERROR", str(e), C["red"])


# --------------------------------------------------------------------------- #
#  Pagine
# --------------------------------------------------------------------------- #
def page_header(title, subtitle):
    w = QWidget()
    v = QVBoxLayout(w)
    v.setContentsMargins(0, 0, 0, 4)
    v.setSpacing(2)
    v.addWidget(lbl(title, 24, C["text"], QFont.Weight.DemiBold, HEAD))
    v.addWidget(lbl(subtitle, 9.5, C["muted"]))
    return w


class ResultsList(FastList):
    picked = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent, row_h=56)
        self.currentItemChanged.connect(self._sel)

    def add_result(self, res, top=True, fade=None):
        col = VERDICT_COLOR.get(res.verdict, C["muted"])
        if res.kind == "file":
            sub = f"{res.meta.get('type', '?')}  ·  {res.meta.get('size', '')}"
        else:
            sub = res.meta.get("domain", "")
        sub += "  ·  " + time.strftime("%b %d, %H:%M", time.localtime(res.timestamp))
        if fade is None:
            fade = top or self.count() < 14
        spec = RowSpec(IC["file"] if res.kind == "file" else IC["globe"], res.name, sub, [(res.verdict, col)],
                       res.score, col, fade=fade)
        return self.add_row(res, spec, top, res.target)

    def _sel(self, cur, prev):
        if cur:
            self.picked.emit(cur.data(Qt.ItemDataRole.UserRole))


class ScanPage(QWidget):
    """Base comune per le pagine File e Link."""
    def __init__(self, main, kind):
        super().__init__()
        self.main, self.kind, self.worker = main, kind, None
        self.count = {"SAFE": 0, "SUSPICIOUS": 0, "DANGEROUS": 0}

    def build_progress(self, v):
        row = QHBoxLayout()
        self.p_label = lbl("Ready.", 8.5, C["muted"], family=MONO, wrap=True)
        row.addWidget(self.p_label, 1)
        self.stop_btn = GlowButton("CANCEL", IC["stop"], "ghost")
        self.stop_btn.setMinimumHeight(30)
        self.stop_btn.hide()
        self.stop_btn.clicked.connect(self.cancel)
        row.addWidget(self.stop_btn)
        v.addLayout(row)
        self.pbar = QProgressBar()
        self.pbar.setTextVisible(False)
        self.pbar.setRange(0, 1)
        self.pbar.setValue(0)
        v.addWidget(self.pbar)

    def cancel(self):
        if self.worker:
            self.worker.stop = True
            self.p_label.setText("Cancelling...")

    def on_progress(self, i, n, name):
        self.pbar.setRange(0, max(n, 1))
        self.pbar.setValue(i)
        if name:
            self.p_label.setText(f"[{i + 1}/{n}] {name[:70]}")
            self.detail.scanning(name, "Initializing")

    def on_result(self, res):
        self.main.store.add(res)
        it = self.list.add_result(res)
        self.count[res.verdict] = self.count.get(res.verdict, 0) + 1
        if res.verdict == "DANGEROUS":
            what = "Threat detected" if res.kind == "file" else "Likely phishing"
            self.main.toast(what.upper(), f"{res.name[:60]} - score {res.score}/100", C["red"])
        self._last = it

    def on_done(self, n):
        self.stop_btn.hide()
        self.set_busy(False)
        self.main.store.save_history()
        self.main.refresh_dashboard()
        c = self.count
        self.p_label.setText(f"Done: {n} scanned  ·  {c['DANGEROUS']} dangerous  ·  "
                             f"{c['SUSPICIOUS']} suspicious  ·  {c['SAFE']} safe")
        if getattr(self, "_last", None):
            self.list.setCurrentItem(None)
            self.list.setCurrentItem(self._last)
        else:
            self.detail.clear()
        self.worker = None

    def set_busy(self, busy):
        pass


class FilesPage(ScanPage):
    def __init__(self, main):
        super().__init__(main, "file")
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(18)
        left = QVBoxLayout()
        left.setSpacing(12)
        left.addWidget(page_header("File Scanner", "Detects RATs, stealers, trojans, macros and hidden payloads in imported files"))
        self.drop = DropZone()
        self.drop.dropped.connect(self.start)
        self.drop.clicked.connect(self.pick_files)
        left.addWidget(self.drop)
        br = QHBoxLayout()
        self.b_files = GlowButton("IMPORT FILES", IC["file"], "primary")
        self.b_dir = GlowButton("FOLDER", IC["folder"], "ghost")
        self.b_dl = GlowButton("DOWNLOAD", IC["download"], "ghost")
        self.b_dl.setToolTip("Scan the Downloads folder (where most malware arrives)")
        self.b_clear = GlowButton("", IC["delete"], "ghost")
        self.b_clear.setMinimumWidth(44)
        self.b_clear.setToolTip("Clear the results list")
        self.b_files.clicked.connect(self.pick_files)
        self.b_dir.clicked.connect(self.pick_dir)
        self.b_dl.clicked.connect(self.scan_downloads)
        self.b_clear.clicked.connect(self.clear_list)
        br.addWidget(self.b_files, 2)
        br.addWidget(self.b_dir, 1)
        br.addWidget(self.b_dl, 1)
        br.addWidget(self.b_clear)
        left.addLayout(br)
        self.build_progress(left)
        left.addWidget(section_title("Results", IC["shield"]))
        self.list = ResultsList()
        left.addWidget(self.list, 1)
        lw = QWidget()
        lw.setLayout(left)
        lw.setFixedWidth(480)
        root.addWidget(lw, 5)
        self.detail = ResultDetail("file")
        root.addWidget(self.detail, 6)
        self.list.picked.connect(self.detail.show_result)
        self.detail.quarantined.connect(lambda r: self.main.refresh_quarantine())

    def pick_files(self):
        if self.worker:
            return
        files, _ = QFileDialog.getOpenFileNames(self, "Select files to scan")
        if files:
            self.start(files)

    def pick_dir(self):
        if self.worker:
            return
        d = QFileDialog.getExistingDirectory(self, "Select a folder to scan")
        if d:
            self.start([d])

    def scan_downloads(self):
        d = sysmon.downloads_dir()
        if os.path.isdir(d):
            files = [os.path.join(d, f) for f in os.listdir(d) if os.path.isfile(os.path.join(d, f))]
            if files:
                self.start(files)
            else:
                self.main.toast("DOWNLOADS EMPTY", "No files to scan.", C["cyan"])

    def clear_list(self):
        if not self.worker:
            self.list.clear()
            self.detail.clear()
            self.p_label.setText("Ready.")

    def set_busy(self, busy):
        for b in (self.b_files, self.b_dir, self.b_dl, self.b_clear):
            b.setEnabled(not busy)
        self.drop.setEnabled(not busy)

    def start(self, paths):
        if self.worker:
            return
        self.count = {"SAFE": 0, "SUSPICIOUS": 0, "DANGEROUS": 0}
        self._last = None
        self.set_busy(True)
        self.stop_btn.show()
        self.detail.scanning("Preparing...", "Collecting files")
        self.worker = FileWorker(paths, self.main.store.settings)
        self.worker.progress.connect(self.on_progress)
        self.worker.step.connect(self.detail.set_step)
        self.worker.result.connect(self.on_result)
        self.worker.done.connect(self.on_done)
        self.worker.start()


class LinksPage(ScanPage):
    def __init__(self, main):
        super().__init__(main, "link")
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(18)
        left = QVBoxLayout()
        left.setSpacing(12)
        left.addWidget(page_header("Link Scanner", "Exposes phishing, typosquatting, homoglyphs, IP loggers and suspicious redirects"))
        card = HudCard(pad=14)
        card.lay.addWidget(lbl("ENTER ONE OR MORE LINKS", 8.5, C["cyan"], QFont.Weight.Bold, HEAD))
        self.input = QPlainTextEdit()
        self.input.setFont(mkfont(10, family=MONO))
        self.input.setPlaceholderText("https://example.com/login\n\nYou can also paste the full text of an email or a "
                                      "message: Eclipse will extract every link automatically.")
        self.input.setFixedHeight(130)
        card.lay.addWidget(self.input)
        br = QHBoxLayout()
        self.b_scan = GlowButton("SCAN", IC["search"], "primary")
        self.b_paste = GlowButton("PASTE", IC["paste"], "ghost")
        self.b_clear = GlowButton("", IC["delete"], "ghost")
        self.b_clear.setMinimumWidth(44)
        self.b_scan.clicked.connect(self.start)
        self.b_paste.clicked.connect(self.paste)
        self.b_clear.clicked.connect(self.clear_list)
        br.addWidget(self.b_scan, 2)
        br.addWidget(self.b_paste, 1)
        br.addWidget(self.b_clear)
        card.lay.addLayout(br)
        left.addWidget(card)
        self.mode = lbl("", 8.5, C["muted"], wrap=True)
        left.addWidget(self.mode)
        self.build_progress(left)
        left.addWidget(section_title("Results", IC["shield"]))
        self.list = ResultsList()
        left.addWidget(self.list, 1)
        lw = QWidget()
        lw.setLayout(left)
        lw.setFixedWidth(480)
        root.addWidget(lw, 5)
        self.detail = ResultDetail("link")
        root.addWidget(self.detail, 6)
        self.list.picked.connect(self.detail.show_result)
        self.update_mode()

    def update_mode(self):
        s = self.main.store.settings
        parts = ["heuristic analysis"]
        if s.get("online_dns"):
            parts.append("DNS")
        if s.get("follow_redirects"):
            parts.append("redirect + page")
        if s.get("vt_key"):
            parts.append("VirusTotal")
        n = len(engine.LinkScanner({}, DATA).feed_urls)
        parts.append(f"phishing database: {n:,} URLs" if n else "phishing database not downloaded")
        self.mode.setText("Mode: " + "  ·  ".join(parts))

    def paste(self):
        self.input.setPlainText(QGuiApplication.clipboard().text())

    def clear_list(self):
        if not self.worker:
            self.list.clear()
            self.detail.clear()
            self.input.clear()

    def set_busy(self, busy):
        for b in (self.b_scan, self.b_paste, self.b_clear):
            b.setEnabled(not busy)
        self.input.setReadOnly(busy)

    def start(self):
        if self.worker:
            return
        urls = engine.extract_urls(self.input.toPlainText())
        if not urls:
            self.main.toast("NO LINKS", "Enter at least one address to scan.", C["amber"])
            return
        self.count = {"SAFE": 0, "SUSPICIOUS": 0, "DANGEROUS": 0}
        self._last = None
        self.set_busy(True)
        self.stop_btn.show()
        self.detail.scanning(urls[0], "Analyzing domain")
        self.worker = LinkWorker(urls, self.main.store.settings)
        self.worker.progress.connect(self.on_progress)
        self.worker.progress.connect(lambda i, n, u: self.detail.set_step("Heuristics and reputation") if u else None)
        self.worker.result.connect(self.on_result)
        self.worker.done.connect(self.on_done)
        self.worker.start()


class PulseDot(Animated):
    def __init__(self, parent=None):
        super().__init__(50, parent)
        self.setFixedSize(12, 14)
        self.ok = True
        self.t = 0.0

    def tick(self):
        self.t += 0.1
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        c = QColor(C["green"] if self.ok else C["amber"])
        c.setAlpha(int(90 + 165 * (0.5 + 0.5 * math.sin(self.t))))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(c)
        p.drawEllipse(QPointF(5, 7), 3.5, 3.5)
        p.end()


class StatCard(HudCard):
    def __init__(self, title, glyph, color):
        super().__init__(accent=color, pad=16)
        top = QHBoxLayout()
        top.addWidget(lbl(title.upper(), 8.5, C["muted"], QFont.Weight.Bold, HEAD))
        top.addStretch()
        top.addWidget(icon_lbl(glyph, 14, color))
        self.lay.addLayout(top)
        self.num = lbl("0", 28, color, QFont.Weight.Bold, HEAD)
        self.lay.addWidget(self.num)
        self.anim = QVariantAnimation(self)
        self.anim.setDuration(900)
        self.anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.anim.valueChanged.connect(lambda v: self.num.setText(str(int(v))))
        self.val = 0

    def set_value(self, v):
        self.anim.stop()
        self.anim.setStartValue(self.val)
        self.anim.setEndValue(v)
        self.val = v
        self.anim.start()


class StatusLine(QWidget):
    def __init__(self, label):
        super().__init__()
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 2, 0, 2)
        self.dot = QLabel("●")
        self.dot.setFont(mkfont(9))
        h.addWidget(self.dot)
        h.addWidget(lbl(label, 9.5, C["muted"]))
        h.addStretch()
        self.val = lbl("", 9.5, C["text"], QFont.Weight.DemiBold, HEAD)
        h.addWidget(self.val)

    def set(self, text, ok=True, warn=False):
        col = C["green"] if ok else (C["amber"] if warn else C["red"])
        self.dot.setStyleSheet(f"color:{col}; background:transparent;")
        self.val.setText(text)
        self.val.setStyleSheet(f"color:{col}; background:transparent;")


_FEED = {"m": None, "n": 0}


def feed_count():
    p = os.path.join(DATA, "phishing_feed.txt")
    m = os.path.getmtime(p) if os.path.exists(p) else 0
    if _FEED["m"] != m:
        _FEED["m"], _FEED["n"] = m, len(engine.LinkScanner({}, DATA).feed_urls)
    return _FEED["n"]


class DashboardPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(16)
        v.addWidget(page_header("Control center", "Local threat intelligence  ·  RAT  ·  malware  ·  phishing"))

        hero = HudCard(pad=22)
        hl = QHBoxLayout()
        hl.setSpacing(28)
        logo_box = QVBoxLayout()
        self.logo = EclipseLogo(200, speed=0.8, intensity=1.1)
        logo_box.addWidget(self.logo, 0, Qt.AlignmentFlag.AlignCenter)
        hl.addLayout(logo_box)
        right = QVBoxLayout()
        right.setSpacing(6)
        t = lbl("ECLIPSE", 34, C["text"], QFont.Weight.Bold, HEAD)
        right.addWidget(t)
        self.state = lbl("SYSTEM ONLINE  ·  PROTECTION READY", 10, C["cyan"], QFont.Weight.Bold, HEAD)
        self.state.setMinimumWidth(10)
        right.addWidget(self.state)
        right.addSpacing(8)
        self.s_engine = StatusLine("Heuristic engine")
        self.s_def = StatusLine("Windows Defender")
        self.s_sig = StatusLine("Digital signature check")
        self.s_feed = StatusLine("Phishing database")
        self.s_vt = StatusLine("VirusTotal")
        self.s_net = StatusLine("Online link analysis")
        self.s_rt = StatusLine("Real-time protection")
        self.s_scan = StatusLine("Last system scan")
        for s in (self.s_rt, self.s_scan, self.s_engine, self.s_def, self.s_sig, self.s_feed, self.s_vt, self.s_net):
            right.addWidget(s)
        right.addStretch()
        qa = QHBoxLayout()
        b0 = GlowButton("QUICK SCAN", IC["flash"], "primary")
        b0.setToolTip("Scan running programs, startup items and the folders where malware hides")
        b1 = GlowButton("SCAN FILES", IC["file"], "ghost")
        b2 = GlowButton("SCAN LINKS", IC["link"], "ghost")
        b0.clicked.connect(lambda: self.main.quick_scan())
        b1.clicked.connect(lambda: self.main.go(self.main.stack.indexOf(self.main.files)))
        b2.clicked.connect(lambda: self.main.go(self.main.stack.indexOf(self.main.links)))
        qa.addWidget(b0)
        qa.addWidget(b1)
        qa.addWidget(b2)
        qa.addStretch()
        right.addLayout(qa)
        hl.addLayout(right, 1)
        hero.lay.addLayout(hl)
        v.addWidget(hero)

        stats = QHBoxLayout()
        stats.setSpacing(14)
        self.c_files = StatCard("Files scanned", IC["file"], C["cyan"])
        self.c_links = StatCard("Links scanned", IC["link"], C["violet"])
        self.c_danger = StatCard("Threats", IC["bug"], C["red"])
        self.c_sus = StatCard("Suspicious", IC["warn"], C["amber"])
        for c in (self.c_files, self.c_links, self.c_danger, self.c_sus):
            stats.addWidget(c)
        v.addLayout(stats)
        v.addWidget(section_title("Recent activity", IC["history"]))
        self.recent = ResultsList()
        self.recent.picked.connect(lambda r: self.main.open_history(r))
        v.addWidget(self.recent, 1)

    def refresh(self):
        st = self.main.store.stats()
        self.c_files.set_value(st.get("file", 0))
        self.c_links.set_value(st.get("link", 0))
        self.c_danger.set_value(st["danger"])
        self.c_sus.set_value(st["sus"])
        s = self.main.store.settings
        self.s_engine.set(f"ACTIVE  ·  {len(engine.STRING_RULES) + len(engine.API_GROUPS)} rules")
        if not hasattr(self, "_mp"):
            self._mp = bool(engine.find_mpcmdrun())
        if s.get("use_defender"):
            self.s_def.set("INTEGRATED" if self._mp else "NOT FOUND", self._mp)
        else:
            self.s_def.set("DISABLED", False, True)
        self.s_sig.set("ENABLED" if s.get("check_signature") else "DISABLED", s.get("check_signature"), True)
        n = feed_count()
        self.s_feed.set(f"{n:,} URLs" if n else "NOT DOWNLOADED (Settings)", bool(n), True)
        self.s_vt.set("CONFIGURED" if s.get("vt_key") else "NOT CONFIGURED", bool(s.get("vt_key")), True)
        net = []
        if s.get("online_dns"):
            net.append("DNS")
        if s.get("follow_redirects"):
            net.append("REDIRECT")
        self.s_net.set(" + ".join(net) if net else "OFFLINE ONLY", bool(net), True)
        if self.main.rt_worker is not None:
            n = len([f for f in self.main.prot.folders() if os.path.isdir(f)])
            self.s_rt.set(f"ACTIVE  ·  {n} folder{'s' if n != 1 else ''}")
        else:
            self.s_rt.set("OFF", False, True)
        sc = getattr(self.main, "sysscan", None)
        if sc is not None and sc.worker is not None:
            self.s_scan.set("RUNNING NOW", True)
        else:
            log = fullscan.load_log(DATA)
            if not log:
                self.s_scan.set("NEVER  ·  run a Quick scan", False, True)
            else:
                L = log[0]
                t, sus = L.get("threats", 0), L.get("suspicious", 0)
                txt = f"{L.get('mode', '').upper()}  ·  {fmt_ago(L.get('date', 0)).upper()}  ·  "
                if t:
                    self.s_scan.set(txt + f"{t} THREAT{'S' if t > 1 else ''}", False)
                elif sus:
                    self.s_scan.set(txt + f"{sus} SUSPICIOUS", False, True)
                elif L.get("cancelled"):
                    self.s_scan.set(txt + "STOPPED", False, True)
                else:
                    self.s_scan.set(txt + "CLEAN", time.time() - L.get("date", 0) < 14 * 86400, True)
        self.recent.blockSignals(True)
        self.recent.clear()
        for h in self.main.store.history[:12]:
            self.recent.add_result(engine.ScanResult.from_dict(h), top=False)
        self.recent.blockSignals(False)


class HistoryPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(18)
        left = QVBoxLayout()
        left.setSpacing(12)
        left.addWidget(page_header("History", "Every scan you have run, stored locally"))
        fl = QHBoxLayout()
        fl.setSpacing(6)
        self.filters = {}
        for key, text in (("all", "ALL"), ("file", "FILE"), ("link", "LINK"), ("bad", "THREATS")):
            b = QPushButton(text)
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setFont(mkfont(8.5, QFont.Weight.Bold, HEAD))
            b.setStyleSheet(f"""QPushButton {{ background: transparent; border: 1px solid {C['border']};
                border-radius: 8px; padding: 6px 12px; color: {C['muted']}; }}
                QPushButton:checked {{ border: 1px solid {C['cyan']}; color: {C['cyan']}; background: rgba(179,136,255,20); }}""")
            b.clicked.connect(lambda _=False, k=key: self.set_filter(k))
            self.filters[key] = b
            fl.addWidget(b)
        fl.addStretch()
        left.addLayout(fl)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search by name, domain or hash...")
        self.search.textChanged.connect(self.reload)
        left.addWidget(self.search)
        self.list = ResultsList()
        left.addWidget(self.list, 1)
        self.b_clear = GlowButton("CLEAR HISTORY", IC["delete"], "danger")
        self.b_clear.clicked.connect(self.clear_all)
        left.addWidget(self.b_clear)
        lw = QWidget()
        lw.setLayout(left)
        lw.setFixedWidth(480)
        root.addWidget(lw, 5)
        self.detail = ResultDetail("history")
        root.addWidget(self.detail, 6)
        self.list.picked.connect(self.detail.show_result)
        self.detail.quarantined.connect(lambda r: self.main.refresh_quarantine())
        self.flt = "all"
        self.filters["all"].setChecked(True)

    def set_filter(self, k):
        self.flt = k
        for key, b in self.filters.items():
            b.setChecked(key == k)
        self.reload()

    def reload(self):
        q = self.search.text().lower().strip()
        self.list.blockSignals(True)
        self.list.clear()
        n = 0
        for h in self.main.store.history:
            if self.flt == "file" and h["kind"] != "file":
                continue
            if self.flt == "link" and h["kind"] != "link":
                continue
            if self.flt == "bad" and h.get("verdict") == "SAFE":
                continue
            if q and q not in (h["name"] + h["target"] + json.dumps(h.get("meta", {}))).lower():
                continue
            self.list.add_result(engine.ScanResult.from_dict(h), top=False)
            n += 1
            if n >= 400:
                break
        self.list.blockSignals(False)

    def select_result(self, res):
        for i in range(self.list.count()):
            r = self.list.item(i).data(Qt.ItemDataRole.UserRole)
            if r.timestamp == res.timestamp and r.target == res.target:
                self.list.setCurrentRow(i)
                return
        self.detail.show_result(res)

    def clear_all(self):
        mb = QMessageBox(self)
        mb.setWindowTitle("History")
        mb.setText("Delete the entire scan history?")
        mb.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if mb.exec() == QMessageBox.StandardButton.Yes:
            self.main.store.history = []
            self.main.store.save_history()
            self.reload()
            self.detail.clear()
            self.main.refresh_dashboard()


class QuarantineItem(QWidget):
    def __init__(self, meta):
        super().__init__()
        self.meta = meta
        h = QHBoxLayout(self)
        h.setContentsMargins(12, 8, 12, 8)
        h.addWidget(icon_lbl(IC["lock"], 14, C["red"]))
        v = QVBoxLayout()
        v.setSpacing(1)
        v.addWidget(lbl(meta.get("name", "?"), 10, C["text"], QFont.Weight.DemiBold))
        v.addWidget(lbl(f"{meta.get('path', '')}", 8, C["muted"], family=MONO))
        v.addWidget(lbl(f"{time.strftime('%d/%m/%Y %H:%M', time.localtime(meta.get('date', 0)))}  ·  "
                        f"{meta.get('reason', '')}", 8, C["dim"]))
        h.addLayout(v, 1)
        col = VERDICT_COLOR.get(meta.get("verdict"), C["muted"])
        h.addWidget(Chip(f"{meta.get('verdict', '')} {meta.get('score', '')}", col))


class QuarantinePage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(14)
        v.addWidget(page_header("Quarantine", "Isolated, encrypted files: they cannot run while they stay here"))
        card = HudCard(accent=C["red"])
        self.list = QListWidget()
        self.list.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        card.lay.addWidget(self.list, 1)
        self.empty = lbl("No files in quarantine.", 10, C["muted"])
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card.lay.addWidget(self.empty)
        br = QHBoxLayout()
        b_restore = GlowButton("RESTORE", IC["undo"], "ghost")
        b_del = GlowButton("DELETE PERMANENTLY", IC["delete"], "danger")
        b_open = GlowButton("OPEN FOLDER", IC["folder"], "ghost")
        b_restore.clicked.connect(self.restore)
        b_del.clicked.connect(self.delete)
        b_open.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(QUAR)))
        br.addWidget(b_restore)
        br.addWidget(b_open)
        br.addStretch()
        br.addWidget(b_del)
        card.lay.addLayout(br)
        v.addWidget(card, 1)

    def reload(self):
        self.list.clear()
        items = quarantine_list()
        for m in items:
            it = QListWidgetItem()
            it.setSizeHint(QSize(100, 70))
            it.setData(Qt.ItemDataRole.UserRole, m)
            self.list.addItem(it)
            self.list.setItemWidget(it, QuarantineItem(m))
        self.empty.setVisible(not items)
        self.list.setVisible(bool(items))

    def _cur(self):
        it = self.list.currentItem()
        return it.data(Qt.ItemDataRole.UserRole) if it else None

    def restore(self):
        m = self._cur()
        if not m:
            return
        mb = QMessageBox(self)
        mb.setWindowTitle("Restore")
        mb.setText(f"Restore {m['name']}?\n\nThis file was classified as {m.get('verdict')} "
                   f"({m.get('score')}/100). Only restore it if you are sure it is safe.")
        mb.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if mb.exec() == QMessageBox.StandardButton.Yes:
            try:
                dst = quarantine_restore(m)
                self.main.toast("FILE RESTORED", dst, C["amber"])
            except Exception as e:
                self.main.toast("ERROR", str(e), C["red"])
            self.reload()

    def delete(self):
        m = self._cur()
        if not m:
            return
        mb = QMessageBox(self)
        mb.setWindowTitle("Delete")
        mb.setText(f"Permanently delete {m['name']}?\nThis cannot be undone.")
        mb.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if mb.exec() == QMessageBox.StandardButton.Yes:
            quarantine_delete(m)
            self.main.toast("DELETED", m["name"], C["green"])
            self.reload()


class SettingRow(QWidget):
    def __init__(self, title, desc, toggle):
        super().__init__()
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 6, 0, 6)
        v = QVBoxLayout()
        v.setSpacing(2)
        v.addWidget(lbl(title, 10.5, C["text"], QFont.Weight.DemiBold))
        d = lbl(desc, 8.5, C["muted"], wrap=True)
        v.addWidget(d)
        h.addLayout(v, 1)
        h.addSpacing(20)
        h.addWidget(toggle)


class SettingsPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        s = main.store.settings
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(page_header("Settings", "Configure scan engines, integrations and databases"))
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        host = QWidget()
        v = QVBoxLayout(host)
        v.setContentsMargins(0, 8, 8, 0)
        v.setSpacing(14)
        scroll.setWidget(host)
        outer.addWidget(scroll, 1)

        c1 = HudCard()
        c1.lay.addWidget(section_title("File analysis", IC["file"]))
        self.t_def = Toggle(s["use_defender"])
        self.t_sig = Toggle(s["check_signature"])
        c1.lay.addWidget(SettingRow("Windows Defender scan",
                                    "Uses the antivirus engine built into Windows (MpCmdRun) on top of Eclipse's heuristic analysis. "
                                    "Catches known threats with up-to-date signatures.", self.t_def))
        c1.lay.addWidget(SettingRow("Digital signature check",
                                    "Checks whether executables are signed by a trusted publisher or whether the signature was tampered with.",
                                    self.t_sig))
        v.addWidget(c1)

        c2 = HudCard(accent=C["violet"])
        c2.lay.addWidget(section_title("Link analysis", IC["link"]))
        self.t_dns = Toggle(s["online_dns"])
        self.t_red = Toggle(s["follow_redirects"])
        c2.lay.addWidget(SettingRow("DNS resolution",
                                    "Checks that the domain exists and which address it points to (does not visit the site).", self.t_dns))
        c2.lay.addWidget(SettingRow("Follow redirects and analyze the page",
                                    "Downloads the page WITHOUT running scripts to reveal where shortened links really go "
                                    "and to spot fake login pages. Note: the site may log the visit.", self.t_red))
        v.addWidget(c2)

        c3 = HudCard(accent=C["magenta"])
        c3.lay.addWidget(section_title("Threat intelligence", IC["globe"]))
        c3.lay.addWidget(lbl("Phishing database (OpenPhish + Phishing.Database)", 10.5, C["text"], QFont.Weight.DemiBold))
        c3.lay.addWidget(lbl("Downloads the latest list of active phishing sites for instant recognition.", 8.5,
                             C["muted"], wrap=True))
        fr = QHBoxLayout()
        self.feed_lbl = lbl("", 9, C["muted"], family=MONO)
        fr.addWidget(self.feed_lbl, 1)
        self.b_feed = GlowButton("UPDATE NOW", IC["refresh"], "primary")
        self.b_feed.clicked.connect(self.update_feed)
        fr.addWidget(self.b_feed)
        c3.lay.addLayout(fr)
        c3.lay.addSpacing(8)
        c3.lay.addWidget(lbl("VirusTotal API key (optional)", 10.5, C["text"], QFont.Weight.DemiBold))
        c3.lay.addWidget(lbl("With a free key Eclipse checks hashes and links against 70+ antivirus engines. "
                             "Only hashes and URLs are sent, never your files.", 8.5, C["muted"], wrap=True))
        kr = QHBoxLayout()
        self.vt = QLineEdit(s.get("vt_key", ""))
        self.vt.setEchoMode(QLineEdit.EchoMode.Password)
        self.vt.setPlaceholderText("Paste your API key here...")
        kr.addWidget(self.vt, 1)
        b_get = GlowButton("GET A KEY", IC["key"], "ghost")
        b_get.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://www.virustotal.com/gui/join-us")))
        kr.addWidget(b_get)
        c3.lay.addLayout(kr)
        v.addWidget(c3)

        c4 = HudCard(accent=C["green"])
        c4.lay.addWidget(section_title("Folders", IC["folder"]))
        c4.lay.addWidget(lbl(f"Install folder: {BASE}", 9, C["muted"], family=MONO, sel=True))
        pr = QHBoxLayout()
        for text, path in (("DATA", DATA), ("QUARANTINE", QUAR), ("REPORTS", REPORTS)):
            b = GlowButton(text, IC["folder"], "ghost")
            b.clicked.connect(lambda _=False, p=path: QDesktopServices.openUrl(QUrl.fromLocalFile(p)))
            pr.addWidget(b)
        pr.addStretch()
        c4.lay.addLayout(pr)
        c4.lay.addWidget(lbl("You can add custom SHA-256 hashes to data\\hash_blacklist.txt (one per line).",
                             8.5, C["dim"], wrap=True))
        c4.lay.addWidget(lbl(f"ECLIPSE v{VERSION}  ·  local static analysis. No tool guarantees 100% "
                             f"detection: when in doubt, do not open the file.", 8.5, C["dim"], wrap=True))
        v.addWidget(c4)
        v.addStretch()

        for t in (self.t_def, self.t_sig, self.t_dns, self.t_red):
            t.toggled.connect(self.save)
        self.vt.editingFinished.connect(self.save)
        self.refresh_feed()

    def save(self):
        s = self.main.store.settings
        s["use_defender"] = self.t_def.isChecked()
        s["check_signature"] = self.t_sig.isChecked()
        s["online_dns"] = self.t_dns.isChecked()
        s["follow_redirects"] = self.t_red.isChecked()
        s["vt_key"] = self.vt.text().strip()
        self.main.store.save_settings()
        self.main.refresh_dashboard()

    def refresh_feed(self):
        p = os.path.join(DATA, "phishing_feed.txt")
        n = len(engine.LinkScanner({}, DATA).feed_urls)
        if n and os.path.exists(p):
            self.feed_lbl.setText(f"{n:,} URLs  ·  updated {time.strftime('%d/%m/%Y %H:%M', time.localtime(os.path.getmtime(p)))}"
                                  )
        else:
            self.feed_lbl.setText("Not downloaded yet")

    def update_feed(self):
        self.b_feed.setEnabled(False)
        self.feed_lbl.setText("Downloading...")
        self.fw = FeedWorker()
        self.fw.done.connect(self._feed_done)
        self.fw.start()

    def _feed_done(self, n, info):
        self.b_feed.setEnabled(True)
        self.refresh_feed()
        self.main.refresh_dashboard()
        if n:
            self.main.toast("DATABASE UPDATED", f"{n:,} phishing sites loaded.", C["green"])
        else:
            self.main.toast("UPDATE FAILED", " / ".join(info)[:150], C["red"])


# --------------------------------------------------------------------------- #
#  System monitor: shared widgets
# --------------------------------------------------------------------------- #
class CallWorker(QThread):
    """Runs any function in the background."""
    done = Signal(object)
    failed = Signal(str)
    step = Signal(str)

    def __init__(self, fn, *a, with_step=False, **kw):
        super().__init__()
        self.fn, self.a, self.kw, self.with_step = fn, a, kw, with_step

    def run(self):
        try:
            if self.with_step:
                self.kw["step"] = self.step.emit
            self.done.emit(self.fn(*self.a, **self.kw))
        except Exception as e:
            self.failed.emit(f"{type(e).__name__}: {e}")


class RealtimeWorker(QThread):
    """Watches folders and scans every new file once it has finished downloading."""
    detected = Signal(object)
    scanning = Signal(str)

    def __init__(self, folders, settings):
        super().__init__()
        self.folders, self.settings, self.stop = list(folders), dict(settings), False

    def run(self):
        w = sysmon.FolderWatcher(self.folders)
        try:
            w.prime()
        except Exception:
            pass
        ls = engine.LinkScanner(self.settings, DATA)
        fs = engine.FileScanner(self.settings, DATA, ls)
        last = time.time()
        try:
            self._loop(w, fs, last)
        finally:
            w.close()

    def _loop(self, w, fs, last):
        while not self.stop:
            # sleep in the kernel until the folder changes (0% CPU when nothing happens)
            changed = w.wait(0.4)
            if self.stop:
                return
            if not (changed or w.pending or time.time() - last > 60):
                continue
            if w.pending and not changed:
                time.sleep(0.3)
            last = time.time()
            try:
                ready = w.poll()
            except Exception:
                continue
            for fp in ready:
                if self.stop:
                    return
                self.scanning.emit(fp)
                try:
                    r = fs.scan(fp)
                except Exception as e:
                    r = engine.ScanResult("file", fp, os.path.basename(fp))
                    r.add(engine.MED, "Error", "Error during analysis", str(e))
                    r.finalize()
                r.meta["trigger"] = "real-time protection"
                self.detected.emit(r)
            if ready:
                self.scanning.emit("")


class ElideLabel(QLabel):
    """Single-line label that elides its text to the available width."""
    def __init__(self, text="", size=10, color=None, weight=QFont.Weight.Normal, family=BODY,
                 mode=Qt.TextElideMode.ElideRight):
        super().__init__()
        self.full, self.col, self.mode = text, color or C["text"], mode
        self.setFont(mkfont(size, weight, family))
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.setFixedHeight(QFontMetrics(self.font()).height() + 2)
        self.setToolTip(text if len(text) > 40 else "")

    def setText(self, t):
        self.full = t
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setFont(self.font())
        p.setPen(QColor(self.col))
        p.drawText(self.rect(), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                   self.fontMetrics().elidedText(self.full, self.mode, self.width()))
        p.end()


def filter_btn(text):
    b = QPushButton(text)
    b.setCheckable(True)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    b.setFont(mkfont(8.5, QFont.Weight.Bold, HEAD))
    b.setStyleSheet(f"""QPushButton {{ background: transparent; border: 1px solid {C['border']};
        border-radius: 8px; padding: 6px 12px; color: {C['muted']}; }}
        QPushButton:hover {{ color: {C['text']}; }}
        QPushButton:checked {{ border: 1px solid {C['cyan']}; color: {C['cyan']}; background: rgba(179,136,255,20); }}""")
    return b


class SysRow(QWidget):
    def __init__(self, res, glyph, title, sub, chips=()):
        super().__init__()
        flagged = res.score >= 25
        col = VERDICT_COLOR.get(res.verdict, C["muted"]) if res.score >= 10 else C["dim"]
        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 6, 12, 6)
        lay.setSpacing(10)
        bar = QFrame()
        bar.setFixedSize(3, 28)
        bar.setStyleSheet(f"background:{col}; border-radius:1px;")
        lay.addWidget(bar)
        ic = icon_lbl(glyph, 12, col if flagged else C["cyan"])
        ic.setFixedWidth(18)
        lay.addWidget(ic)
        v = QVBoxLayout()
        v.setSpacing(0)
        v.addWidget(ElideLabel(title, 9.5, C["text"], QFont.Weight.DemiBold))
        v.addWidget(ElideLabel(sub, 8, C["muted"], family=MONO, mode=Qt.TextElideMode.ElideMiddle))
        lay.addLayout(v, 1)
        for text, ccol in chips:
            lay.addWidget(Chip(text, ccol, size=7))
        sc = lbl(str(res.score), 12, col if res.score else C["dim"], QFont.Weight.Bold, HEAD)
        sc.setFixedWidth(30)
        sc.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        lay.addWidget(sc)


class SysDetail(HudCard):
    """Right-hand panel with score, details and findings for a process / entry / connection."""
    def __init__(self, glyph, title, text):
        super().__init__(accent=C["violet"])
        self.stack = QStackedWidget()
        self.lay.addWidget(self.stack)
        empty = QWidget()
        ev = QVBoxLayout(empty)
        ev.addStretch()
        ic = icon_lbl(glyph, 46, C["violet"])
        ic.setAlignment(Qt.AlignmentFlag.AlignCenter)
        fx = QGraphicsDropShadowEffect(ic)
        fx.setBlurRadius(40)
        fx.setOffset(0, 0)
        fx.setColor(qc(C["magenta"], 200))
        ic.setGraphicsEffect(fx)
        ev.addWidget(ic)
        ev.addSpacing(14)
        t = lbl(title, 12, C["muted"], QFont.Weight.Bold, HEAD)
        t.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ev.addWidget(t)
        s = lbl(text, 9, C["dim"], wrap=True)
        s.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ev.addWidget(s)
        ev.addStretch()
        self.stack.addWidget(empty)

        det = QWidget()
        dv = QVBoxLayout(det)
        dv.setContentsMargins(0, 0, 0, 0)
        dv.setSpacing(10)
        top = QHBoxLayout()
        top.setSpacing(14)
        self.gauge = Gauge(124)
        top.addWidget(self.gauge, 0, Qt.AlignmentFlag.AlignTop)
        info = QVBoxLayout()
        info.setSpacing(3)
        self.v_label = lbl("", 15, C["green"], QFont.Weight.Bold, HEAD)
        info.addWidget(self.v_label)
        self.v_name = lbl("", 11, C["text"], QFont.Weight.DemiBold, wrap=True, sel=True)
        info.addWidget(self.v_name)
        self.v_sub = lbl("", 8.5, C["muted"], family=MONO, wrap=True, sel=True)
        info.addWidget(self.v_sub)
        info.addStretch()
        top.addLayout(info, 1)
        dv.addLayout(top)
        self.meta_box = QGridLayout()
        self.meta_box.setHorizontalSpacing(12)
        self.meta_box.setVerticalSpacing(3)
        dv.addLayout(self.meta_box)
        self.f_title = section_title("Findings", IC["radar"])
        dv.addWidget(self.f_title)
        sc = QScrollArea()
        sc.setWidgetResizable(True)
        host = QWidget()
        self.f_lay = QVBoxLayout(host)
        self.f_lay.setContentsMargins(0, 0, 6, 0)
        self.f_lay.setSpacing(6)
        sc.setWidget(host)
        dv.addWidget(sc, 1)
        self.btns = QHBoxLayout()
        self.btns.setSpacing(8)
        dv.addLayout(self.btns)
        self.stack.addWidget(det)
        self.res = None

    def clear(self):
        self.res = None
        self.stack.setCurrentIndex(0)

    def show_result(self, res, keys, label, sub):
        self.res = res
        self.stack.setCurrentIndex(1)
        col = VERDICT_COLOR.get(res.verdict, C["muted"])
        self.gauge.set_score(res.score, res.verdict)
        self.v_label.setText(label)
        self.v_label.setStyleSheet(f"color:{col}; background:transparent;")
        self.v_name.setText(softwrap(short(res.name, 90), 34))
        self.v_sub.setText(softwrap(short(sub, 120), 40))
        self.v_sub.setToolTip(sub)
        while self.meta_box.count():
            it = self.meta_box.takeAt(0)
            if it.widget():
                it.widget().deleteLater()
        row = 0
        for k in keys:
            v = res.meta.get(k)
            if v in ("", None, 0) and k != "pid":
                continue
            self.meta_box.addWidget(lbl(k.replace("_", " ").upper(), 7.5, C["dim"], QFont.Weight.Bold, HEAD), row, 0,
                                    Qt.AlignmentFlag.AlignTop)
            vl = lbl(softwrap(short(str(v), 160), 42), 8.5, C["text"], family=MONO, wrap=True, sel=True)
            vl.setToolTip(str(v))
            self.meta_box.addWidget(vl, row, 1)
            row += 1
        self.meta_box.setColumnStretch(1, 1)
        while self.f_lay.count():
            it = self.f_lay.takeAt(0)
            if it.widget():
                it.widget().deleteLater()
        real = [f for f in res.findings if f.severity > 0]
        self.f_title.findChildren(QLabel)[-1].setText(f"FINDINGS  ({len(real)})")
        if not real:
            self.f_lay.addWidget(lbl("✓  Nothing suspicious found.", 10, C["green"]))
        for f in res.findings:
            self.f_lay.addWidget(FindingRow(f))
        self.f_lay.addStretch()


class MonitorPage(QWidget):
    """Base for the Processes / Startup / Network pages: list on the left, details on the right."""
    TITLE, SUB, GLYPH = "", "", IC["radar"]
    EMPTY = ("", "")
    KEYS = []
    FILTERS = (("all", "ALL"), ("flag", "FLAGGED"))
    NOUN = "items"

    def __init__(self, main):
        super().__init__()
        self.main, self.worker, self.results, self.loaded = main, None, [], False
        self.loaded_once = False
        self.flt = "all"
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(18)
        left = QVBoxLayout()
        left.setSpacing(10)
        left.addWidget(page_header(self.TITLE, self.SUB))
        bar = QHBoxLayout()
        bar.setSpacing(6)
        self.fbtns = {}
        for k, t in self.FILTERS:
            b = filter_btn(t)
            b.clicked.connect(lambda _=False, key=k: self.set_filter(key))
            bar.addWidget(b)
            self.fbtns[k] = b
        self.fbtns["all"].setChecked(True)
        bar.addStretch()
        self.extra_bar(bar)
        self.b_scan = GlowButton("SCAN", IC["refresh"], "primary")
        self.b_scan.clicked.connect(self.refresh)
        bar.addWidget(self.b_scan)
        left.addLayout(bar)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter by name, path or address...")
        self.search.textChanged.connect(self.refill)
        left.addWidget(self.search)
        sr = QHBoxLayout()
        self.summary = lbl("Not scanned yet.", 8.5, C["muted"], family=MONO)
        sr.addWidget(self.summary, 1)
        left.addLayout(sr)
        self.pbar = QProgressBar()
        self.pbar.setTextVisible(False)
        self.pbar.setRange(0, 1)
        left.addWidget(self.pbar)
        self.list = FastList(row_h=50)
        self.list.currentItemChanged.connect(self._pick)
        left.addWidget(self.list, 1)
        lw = QWidget()
        lw.setLayout(left)
        root.addWidget(lw, 1)
        self.detail = SysDetail(self.GLYPH, *self.EMPTY)
        self.detail.setFixedWidth(430)
        root.addWidget(self.detail)
        self.build_buttons(self.detail.btns)

    # hooks for subclasses
    def extra_bar(self, bar):
        pass

    def build_buttons(self, lay):
        pass

    def job(self, step):
        return []

    def row(self, r):
        return IC["radar"], r.name, r.target, ()

    def key(self, r):
        return r.target

    def match(self, r, flt):
        return True

    def label(self, r):
        return r.verdict

    def selected(self, r):
        pass

    # common logic
    def on_show(self):
        if not self.loaded and not self.worker:
            self.refresh()

    def refresh(self, quiet=False):
        if self.worker:
            return
        self.quiet = quiet
        if not quiet:
            self.pbar.setRange(0, 0)
            self.b_scan.setEnabled(False)
            self.summary.setText("Scanning...")
        self.worker = CallWorker(self.job, with_step=True)
        self.worker.step.connect(lambda s: None if self.quiet else self.summary.setText(s + "..."))
        self.worker.done.connect(self._done)
        self.worker.failed.connect(self._failed)
        self.worker.start()

    def _finish(self):
        self.pbar.setRange(0, 1)
        self.b_scan.setEnabled(True)
        self.worker = None

    def _failed(self, msg):
        self._finish()
        self.summary.setText("Scan failed.")
        self.main.toast("SCAN FAILED", msg[:160], C["red"])

    def _done(self, results):
        self._finish()
        self.results = results or []
        self.loaded = True
        self.refill()

    def set_filter(self, k):
        self.flt = k
        for key, b in self.fbtns.items():
            b.setChecked(key == k)
        self.refill()

    def refill(self):
        q = self.search.text().lower().strip()
        cur = self.list.currentItem()
        cur_key = self.key(cur.data(Qt.ItemDataRole.UserRole)) if cur else None
        bar = self.list.verticalScrollBar().value()
        self.list.blockSignals(True)
        self.list.clear()
        sel = None
        shown = 0
        for r in self.results:
            if self.flt == "flag" and r.score < 25:
                continue
            if self.flt not in ("all", "flag") and not self.match(r, self.flt):
                continue
            if q and q not in (r.name + " " + r.target + " " + " ".join(str(v) for k, v in r.meta.items()
                                                                           if not k.startswith("_"))).lower():
                continue
            glyph, title, sub, chips = self.row(r)
            col = VERDICT_COLOR.get(r.verdict, C["muted"]) if r.score >= 10 else C["dim"]
            spec = RowSpec(glyph, title, sub, chips, r.score, col, col if r.score >= 25 else C["cyan"],
                           col if r.score else C["dim"], fade=not self.loaded_once and shown < 14)
            it = self.list.add_row(r, spec)
            if cur_key is not None and self.key(r) == cur_key:
                sel = it
            shown += 1
            if shown >= 3000:
                break
        self.loaded_once = True
        self.list.blockSignals(False)
        d = sum(1 for r in self.results if r.verdict == "DANGEROUS")
        s = sum(1 for r in self.results if r.verdict == "SUSPICIOUS")
        self.summary.setText(f"{len(self.results)} {self.NOUN}  ·  {d} dangerous  ·  {s} suspicious"
                             + (f"  ·  showing {shown}" if shown != len(self.results) else ""))
        self.summary.setStyleSheet(f"color:{C['red'] if d else C['amber'] if s else C['muted']}; background:transparent;")
        if sel is not None:
            self.list.blockSignals(True)
            self.list.setCurrentItem(sel)
            self.list.blockSignals(False)
            self._pick(sel, None)
        elif cur_key is not None:
            self.detail.clear()
        self.list.verticalScrollBar().setValue(bar)

    def _pick(self, cur, prev):
        if not cur:
            return
        r = cur.data(Qt.ItemDataRole.UserRole)
        glyph, title, sub, chips = self.row(r)
        self.detail.show_result(r, self.KEYS, self.label(r), sub)
        self.selected(r)

    def current(self):
        return self.detail.res

    def deep_scan(self, path):
        if not path or not os.path.isfile(path):
            self.main.toast("FILE NOT FOUND", path or "No file for this item", C["amber"])
            return
        if self.main.files.worker:
            self.main.toast("BUSY", "The file scanner is already running.", C["amber"])
            return
        self.main.go(self.main.stack.indexOf(self.main.files))
        self.main.files.start([path])

    def open_location(self, path):
        if path and os.path.exists(path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.dirname(path)))
        else:
            self.main.toast("NOT FOUND", path or "No location for this item", C["amber"])

    def confirm(self, title, text):
        mb = QMessageBox(self)
        mb.setWindowTitle(title)
        mb.setText(text)
        mb.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        return mb.exec() == QMessageBox.StandardButton.Yes

    def end_process(self, pid, name):
        if not self.confirm("End process", f"Terminate {name} (PID {pid}) and its child processes?\n\n"
                                           f"Unsaved work in that program will be lost."):
            return False
        try:
            sysmon.kill_process(pid)
            self.main.toast("PROCESS TERMINATED", f"{name} (PID {pid})", C["green"])
            return True
        except Exception as e:
            self.main.toast("COULD NOT TERMINATE", str(e)[:150], C["red"])
            return False


def sig_chip(r):
    s = str(r.meta.get("signature", ""))
    if s.startswith("valid") or s == "Eclipse":
        return ("SIGNED", C["green"])
    if s == "not signed":
        return ("UNSIGNED", C["amber"])
    if s.startswith("BROKEN"):
        return ("TAMPERED", C["red"])
    if s == "not trusted":
        return ("UNTRUSTED", C["amber"])
    return None


# --------------------------------------------------------------------------- #
#  Processes
# --------------------------------------------------------------------------- #
class ProcessesPage(MonitorPage):
    TITLE = "Processes"
    SUB = "Programs running right now: where a RAT that is already installed hides"
    GLYPH = IC["cpu"]
    EMPTY = ("SELECT A PROCESS", "Pick a process to see its location, signature, command line and network activity.")
    KEYS = ["pid", "path", "signature", "parent", "user", "started", "memory", "connections", "command"]
    FILTERS = (("all", "ALL"), ("flag", "FLAGGED"), ("unsigned", "UNSIGNED"), ("net", "ONLINE"))
    NOUN = "processes"

    def build_buttons(self, lay):
        self.b_deep = GlowButton("DEEP SCAN", IC["search"], "ghost")
        self.b_loc = GlowButton("LOCATION", IC["folder"], "ghost")
        self.b_kill = GlowButton("END", IC["stop"], "danger")
        self.b_kill.setToolTip("Terminate the process and its children")
        self.b_deep.clicked.connect(lambda: self.current() and self.deep_scan(self.current().meta.get("path")))
        self.b_loc.clicked.connect(lambda: self.current() and self.open_location(self.current().meta.get("path")))
        self.b_kill.clicked.connect(self.kill)
        lay.addWidget(self.b_deep)
        lay.addWidget(self.b_loc)
        lay.addStretch()
        lay.addWidget(self.b_kill)

    def job(self, step):
        return sysmon.scan_processes(self.main.flagged_paths(), step)

    def key(self, r):
        return r.meta.get("pid")

    def match(self, r, flt):
        if flt == "unsigned":
            s = str(r.meta.get("signature", ""))
            return s in ("not signed", "not trusted") or s.startswith("BROKEN")
        if flt == "net":
            return bool(r.meta.get("connections"))
        return True

    def row(self, r):
        chips = []
        sc = sig_chip(r)
        if sc and sc[0] != "SIGNED":
            chips.append(sc)
        if r.meta.get("connections"):
            chips.append(("NET", C["cyan"]))
        chips.append((f"PID {r.meta.get('pid')}", C["dim"]))
        return IC["cpu"], r.name, r.meta.get("path") or str(r.meta.get("signature", "")), chips

    def label(self, r):
        return {"SAFE": "LOOKS CLEAN", "SUSPICIOUS": "SUSPICIOUS PROCESS", "DANGEROUS": "LIKELY MALWARE"}[r.verdict]

    def selected(self, r):
        has = bool(r.meta.get("path"))
        self.b_deep.setEnabled(has)
        self.b_loc.setEnabled(has)
        self.b_kill.setEnabled(r.name.lower() not in sysmon.CRITICAL_PROC and r.meta.get("pid") not in (0, 4))

    def kill(self):
        r = self.current()
        if r and self.end_process(r.meta.get("pid"), r.name):
            self.results = [x for x in self.results if x is not r]
            self.detail.clear()
            self.refill()


# --------------------------------------------------------------------------- #
#  Startup entries
# --------------------------------------------------------------------------- #
KIND_GLYPH = {"reg": IC["key"], "folder": IC["folder"], "task": IC["history"], "service": IC["settings"],
              "ifeo": IC["warn"], "winlogon": IC["warn"], "appinit": IC["warn"]}
KIND_CHIP = {"reg": "RUN KEY", "folder": "STARTUP", "task": "TASK", "service": "SERVICE", "ifeo": "IFEO",
             "winlogon": "WINLOGON", "appinit": "APPINIT"}


class StartupPage(MonitorPage):
    TITLE = "Startup"
    SUB = "Everything that launches by itself with Windows: where malware makes itself permanent"
    GLYPH = IC["power"]
    EMPTY = ("SELECT AN ENTRY", "Pick an entry to see what it launches and why it may be risky.")
    KEYS = ["source", "status", "path", "loads", "signature", "author", "location", "command"]
    FILTERS = (("all", "ALL"), ("flag", "FLAGGED"), ("off", "DISABLED"))
    NOUN = "entries"

    def build_buttons(self, lay):
        self.b_deep = GlowButton("DEEP SCAN", IC["search"], "ghost")
        self.b_loc = GlowButton("LOCATION", IC["folder"], "ghost")
        self.b_off = GlowButton("DISABLE", IC["stop"], "danger")
        self.b_on = GlowButton("ENABLE", IC["undo"], "ghost")
        self.b_deep.clicked.connect(lambda: self.current() and self.deep_scan(self.target(self.current())))
        self.b_loc.clicked.connect(lambda: self.current() and self.open_location(self.target(self.current())))
        self.b_off.clicked.connect(lambda: self.toggle(False))
        self.b_on.clicked.connect(lambda: self.toggle(True))
        lay.addWidget(self.b_deep)
        lay.addWidget(self.b_loc)
        lay.addStretch()
        lay.addWidget(self.b_off)
        lay.addWidget(self.b_on)

    @staticmethod
    def target(r):
        e = r.meta.get("_entry", {})
        p = e.get("payload") or e.get("exe") or ""
        return p

    def job(self, step):
        return sysmon.scan_autoruns(self.main.flagged_paths(), step)

    def key(self, r):
        e = r.meta.get("_entry", {})
        return (e.get("location"), e.get("name"))

    def match(self, r, flt):
        if flt == "off":
            return not r.meta["_entry"]["enabled"]
        return True

    def row(self, r):
        e = r.meta["_entry"]
        chips = [(KIND_CHIP.get(e["kind"], "?"), C["violet"])]
        if not e["enabled"]:
            chips.insert(0, ("DISABLED", C["muted"]))
        return KIND_GLYPH.get(e["kind"], IC["power"]), r.name, e["command"] or e["location"], chips

    def label(self, r):
        return {"SAFE": "LOOKS LEGITIMATE", "SUSPICIOUS": "SUSPICIOUS ENTRY", "DANGEROUS": "MALICIOUS PERSISTENCE"}[r.verdict]

    def selected(self, r):
        e = r.meta["_entry"]
        has = bool(self.target(r)) and os.path.exists(self.target(r))
        self.b_deep.setEnabled(has)
        self.b_loc.setEnabled(has)
        self.b_off.setVisible(e["can_toggle"] and e["enabled"])
        self.b_on.setVisible(e["can_toggle"] and not e["enabled"])
        self.b_off.setEnabled(True)
        self.b_on.setEnabled(True)

    def toggle(self, on):
        r = self.current()
        if not r:
            return
        e = r.meta["_entry"]
        if not on and not self.confirm("Disable startup entry",
                                       f"Stop “{r.name}” from launching with Windows?\n\n{short(e['command'], 120)}\n\n"
                                       f"Nothing is deleted: Eclipse disables it the same way Task Manager does, "
                                       f"and you can enable it again here."):
            return
        try:
            sysmon.set_autorun_enabled(e, on)
        except Exception as ex:
            self.main.toast("NOT CHANGED", str(ex)[:160], C["red"])
            return
        e["enabled"] = on
        r.meta["status"] = "enabled" if on else "disabled"
        self.main.toast("ENTRY ENABLED" if on else "ENTRY DISABLED", r.name, C["green"])
        self.refill()


# --------------------------------------------------------------------------- #
#  Network
# --------------------------------------------------------------------------- #
class NetworkPage(MonitorPage):
    TITLE = "Network"
    SUB = "Which programs talk to the internet, and where: a RAT must connect to its server"
    GLYPH = IC["net"]
    EMPTY = ("SELECT A CONNECTION", "Pick a connection to see the program behind it and where it goes.")
    KEYS = ["process", "remote", "domain", "reverse_dns", "network", "state", "local", "protocol", "signature",
            "sockets", "path"]
    FILTERS = (("all", "ALL"), ("flag", "FLAGGED"), ("internet", "INTERNET"), ("listen", "LISTENING"))
    NOUN = "connections"

    def extra_bar(self, bar):
        self.t_live = Toggle(True)
        self.t_live.setToolTip("Refresh automatically every few seconds")
        bar.addWidget(lbl("LIVE", 8.5, C["muted"], QFont.Weight.Bold, HEAD))
        bar.addWidget(self.t_live)
        bar.addSpacing(6)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(5000)

    def _tick(self):
        if self.isVisible() and self.t_live.isChecked() and self.loaded and self.main.isVisible():
            self.refresh(quiet=True)

    def build_buttons(self, lay):
        self.b_dom = GlowButton("CHECK HOST", IC["link"], "ghost")
        self.b_dom.setToolTip("Analyze the remote host with the Link Scanner")
        self.b_copy = GlowButton("", IC["copy"], "ghost")
        self.b_copy.setToolTip("Copy the remote address")
        self.b_kill = GlowButton("END", IC["stop"], "danger")
        self.b_kill.setToolTip("Terminate the program that owns this connection")
        self.b_dom.clicked.connect(self.check_host)
        self.b_copy.clicked.connect(self.copy)
        self.b_kill.clicked.connect(self.kill)
        lay.addWidget(self.b_dom)
        lay.addWidget(self.b_copy)
        lay.addStretch()
        lay.addWidget(self.b_kill)

    def job(self, step):
        return sysmon.scan_network(engine.LinkScanner({}, DATA), include_listen=True,
                                   flagged=self.main.flagged_paths())

    def key(self, r):
        return (r.meta.get("pid"), r.target, r.meta.get("state"))

    def match(self, r, flt):
        if flt == "internet":
            return r.meta.get("network") == "internet"
        if flt == "listen":
            return r.meta.get("state") == "LISTEN"
        return True

    def refill(self):
        if self.flt == "all":
            keep = self.results
            self.results = [r for r in keep if r.meta.get("state") != "LISTEN" or r.score >= 25]
            super().refill()
            self.results = keep
        else:
            super().refill()

    def row(self, r):
        chips = []
        n = r.meta.get("sockets", 1)
        if n > 1:
            chips.append((f"×{n}", C["muted"]))
        if r.meta.get("state") == "LISTEN":
            chips.append(("LISTEN", C["violet"]))
        elif r.meta.get("network") == "local network":
            chips.append(("LAN", C["muted"]))
        if r.meta.get("state") == "LISTEN":
            sub = f"{r.meta.get('local', '')}  ·  {r.meta.get('network', '')}"
        else:
            host = r.meta.get("domain") or r.meta.get("reverse_dns") or ""
            sub = "  ·  ".join(x for x in (r.meta.get("state", "").lower(), r.meta.get("network", ""),
                                           r.meta.get("remote", "") if host else "", host) if x)
        return (IC["net"] if r.meta.get("state") == "LISTEN" else IC["globe"]), r.name, sub, chips

    def label(self, r):
        return {"SAFE": "NORMAL TRAFFIC", "SUSPICIOUS": "SUSPICIOUS CONNECTION", "DANGEROUS": "LIKELY C2 TRAFFIC"}[r.verdict]

    def selected(self, r):
        self.b_dom.setEnabled(bool(r.meta.get("remote")))
        self.b_copy.setEnabled(True)
        name = str(r.meta.get("process", "")).split(" (")[0].lower()
        self.b_kill.setEnabled(name not in sysmon.CRITICAL_PROC and r.meta.get("pid") not in (0, 4))

    def check_host(self):
        r = self.current()
        if not r:
            return
        host = (r.meta.get("domain") or "").split(",")[0].strip() or r.meta.get("remote", "").rsplit(":", 1)[0]
        if not host:
            return
        lp = self.main.links
        if lp.worker:
            self.main.toast("BUSY", "The link scanner is already running.", C["amber"])
            return
        self.main.go(self.main.stack.indexOf(lp))
        lp.input.setPlainText("http://" + (f"[{host}]" if ":" in host else host))
        lp.start()

    def copy(self):
        r = self.current()
        if r:
            t = r.meta.get("remote") or r.meta.get("local", "")
            QGuiApplication.clipboard().setText(t)
            self.main.toast("COPIED", t, C["cyan"])

    def kill(self):
        r = self.current()
        if r and self.end_process(r.meta.get("pid"), str(r.meta.get("process", "")).split(" (")[0]):
            self.detail.clear()
            self.refresh()


# --------------------------------------------------------------------------- #
#  Real-time protection
# --------------------------------------------------------------------------- #
class PulseShield(Animated):
    """Shield with expanding rings: green and alive when protection is on, grey when off."""
    def __init__(self, size=150, parent=None):
        super().__init__(33, parent)
        self.setFixedSize(size, size)
        self.t = 0.0
        self.on = True
        self.busy = False

    def tick(self):
        self.t += 0.033 * (2.2 if self.busy else 1.0)
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w = self.width()
        c = QPointF(w / 2, w / 2)
        col = QColor(C["green"] if self.on else C["dim"])
        acc = QColor(C["magenta"] if self.busy else (C["violet"] if self.on else C["dim"]))
        if self.on:
            for k in range(3):
                ph = (self.t * 0.45 + k / 3) % 1.0
                p.setPen(QPen(qc(acc.name(), int(150 * (1 - ph))), 1.4))
                p.setBrush(Qt.BrushStyle.NoBrush)
                r = w * 0.2 + w * 0.28 * ph
                p.drawEllipse(c, r, r)
            # rotating arc
            p.setPen(QPen(qc(C["cyan"], 140), 2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            rr = w * 0.44
            p.drawArc(QRectF(c.x() - rr, c.y() - rr, 2 * rr, 2 * rr), int(-self.t * 90 * 16) % (360 * 16), 70 * 16)
            p.drawArc(QRectF(c.x() - rr, c.y() - rr, 2 * rr, 2 * rr), int(-self.t * 90 * 16 + 180 * 16) % (360 * 16), 70 * 16)
        g = QRadialGradient(c, w * 0.24)
        g.setColorAt(0, qc(acc.name(), 230 if self.on else 90))
        g.setColorAt(1, qc(C["violet"] if self.on else C["dim"], 60))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(g)
        p.drawEllipse(c, w * 0.21, w * 0.21)
        p.setFont(icon_font(w * 0.13))
        p.setPen(qc("#ffffff") if self.on else qc(C["muted"]))
        p.drawText(QRectF(0, 0, w, w), Qt.AlignmentFlag.AlignCenter, IC["shield"])
        p.setBrush(col)
        p.drawEllipse(QPointF(c.x() + w * 0.15, c.y() + w * 0.15), w * 0.035, w * 0.035)
        p.end()


class ProtectionPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        s = main.store.settings
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(14)
        v.addWidget(page_header("Real-time protection", "Watches your folders and scans every new file the moment it lands"))

        hero = HudCard(pad=20)
        hl = QHBoxLayout()
        hl.setSpacing(22)
        self.shield = PulseShield(140)
        hl.addWidget(self.shield)
        mid = QVBoxLayout()
        mid.setSpacing(4)
        mid.addStretch()
        self.state = lbl("", 20, C["green"], QFont.Weight.Bold, HEAD)
        mid.addWidget(self.state)
        self.state_sub = lbl("", 9.5, C["muted"], wrap=True)
        mid.addWidget(self.state_sub)
        self.now = ElideLabel("", 8.5, C["cyan"], family=MONO, mode=Qt.TextElideMode.ElideMiddle)
        mid.addWidget(self.now)
        mid.addStretch()
        hl.addLayout(mid, 1)
        tv = QVBoxLayout()
        tv.addStretch()
        self.t_rt = Toggle(s.get("realtime", True))
        self.t_rt.setFixedSize(50, 26)
        tv.addWidget(self.t_rt, 0, Qt.AlignmentFlag.AlignHCenter)
        tv.addWidget(lbl("PROTECTION", 7.5, C["dim"], QFont.Weight.Bold, HEAD), 0, Qt.AlignmentFlag.AlignHCenter)
        tv.addStretch()
        hl.addLayout(tv)
        hero.lay.addLayout(hl)
        v.addWidget(hero)

        row = QHBoxLayout()
        row.setSpacing(14)
        fc = HudCard(accent=C["violet"])
        fc.lay.addWidget(section_title("Watched folders", IC["folder"]))
        self.flist = QListWidget()
        self.flist.setFixedHeight(104)
        self.flist.setFont(mkfont(9, family=MONO))
        fc.lay.addWidget(self.flist)
        fb = QHBoxLayout()
        b_add = GlowButton("ADD", IC["add"], "ghost")
        b_rem = GlowButton("REMOVE", IC["remove"], "ghost")
        b_add.clicked.connect(self.add_folder)
        b_rem.clicked.connect(self.remove_folder)
        fb.addWidget(b_add)
        fb.addWidget(b_rem)
        fb.addStretch()
        fc.lay.addLayout(fb)
        row.addWidget(fc, 1)
        oc = HudCard(accent=C["magenta"])
        oc.lay.setSpacing(0)
        oc.lay.addWidget(section_title("Options", IC["settings"]))
        self.t_aq = Toggle(s.get("auto_quarantine", False))
        self.t_nt = Toggle(s.get("notify", True))
        self.t_tray = Toggle(s.get("tray_on_close", True))
        self.t_boot = Toggle(sysmon.get_self_startup())
        for t, title, desc in ((self.t_aq, "Auto-quarantine threats", "Dangerous files are isolated immediately."),
                               (self.t_nt, "Desktop notifications", "Windows alert when something is found."),
                               (self.t_tray, "Keep running in the tray", "Closing the window keeps protection on."),
                               (self.t_boot, "Start with Windows", "Launch Eclipse silently in the tray at login.")):
            oc.lay.addWidget(SettingRow(title, desc, t))
        row.addWidget(oc, 1)
        v.addLayout(row)

        v.addWidget(section_title("Live activity", IC["radar"]))
        self.log = ResultsList()
        self.log.setMinimumHeight(110)
        self.log.picked.connect(lambda r: self.main.open_history(r))
        v.addWidget(self.log, 1)
        self.log_empty = lbl("No new files yet. Download something and it will show up here within seconds.",
                             9, C["dim"])
        self.log_empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        v.addWidget(self.log_empty)

        self.t_rt.toggled.connect(self.toggle_rt)
        for t in (self.t_aq, self.t_nt, self.t_tray):
            t.toggled.connect(self.save)
        self.t_boot.toggled.connect(self.toggle_boot)
        self.checked = 0
        self.blocked = 0
        self.reload_folders()
        for h in main.store.history:
            if h.get("meta", {}).get("trigger") == "real-time protection":
                self.log.add_result(engine.ScanResult.from_dict(h), top=False)
                if self.log.count() >= 30:
                    break
        self.log_empty.setVisible(self.log.count() == 0)
        self.update_state()

    def folders(self):
        return self.main.store.settings.get("watch_folders") or [sysmon.downloads_dir()]

    def reload_folders(self):
        self.flist.clear()
        for f in self.folders():
            it = QListWidgetItem(f if os.path.isdir(f) else f + "   (missing)")
            it.setData(Qt.ItemDataRole.UserRole, f)
            self.flist.addItem(it)

    def add_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Folder to watch")
        if d:
            d = os.path.normpath(d)
            fs = self.folders()
            if d not in fs:
                self.main.store.settings["watch_folders"] = fs + [d]
                self.main.store.save_settings()
                self.reload_folders()
                self.main.restart_realtime()

    def remove_folder(self):
        it = self.flist.currentItem()
        if not it:
            return
        fs = [f for f in self.folders() if f != it.data(Qt.ItemDataRole.UserRole)]
        self.main.store.settings["watch_folders"] = fs
        self.main.store.save_settings()
        self.reload_folders()
        self.main.restart_realtime()

    def save(self):
        s = self.main.store.settings
        s["auto_quarantine"] = self.t_aq.isChecked()
        s["notify"] = self.t_nt.isChecked()
        s["tray_on_close"] = self.t_tray.isChecked()
        self.main.store.save_settings()

    def toggle_rt(self, on):
        self.main.store.settings["realtime"] = on
        self.main.store.save_settings()
        if on:
            self.main.start_realtime()
        else:
            self.main.stop_realtime()

    def toggle_boot(self, on):
        try:
            sysmon.set_self_startup(on)
            self.main.toast("STARTUP UPDATED", "Eclipse will start with Windows." if on else
                            "Eclipse will no longer start with Windows.", C["green"])
        except Exception as e:
            self.main.toast("ERROR", str(e)[:150], C["red"])

    def set_scanning(self, path):
        self.shield.busy = bool(path)
        self.now.setText(f"Scanning  {path}" if path else "")

    def add_event(self, res):
        self.checked += 1
        if res.verdict != "SAFE":
            self.blocked += 1
        self.log.add_result(res)
        while self.log.count() > 60:
            self.log.takeItem(self.log.count() - 1)
        self.log_empty.hide()
        self.update_state()

    def update_state(self):
        on = self.main.rt_worker is not None
        self.shield.on = on
        n = len([f for f in self.folders() if os.path.isdir(f)])
        if on:
            self.state.setText("PROTECTION ACTIVE")
            self.state.setStyleSheet(f"color:{C['green']}; background:transparent;")
            self.state_sub.setText(f"Watching {n} folder{'s' if n != 1 else ''}  ·  {self.checked} new file"
                                   f"{'s' if self.checked != 1 else ''} checked this session  ·  "
                                   f"{self.blocked} flagged")
        else:
            self.state.setText("PROTECTION OFF")
            self.state.setStyleSheet(f"color:{C['amber']}; background:transparent;")
            self.state_sub.setText("New files are not being checked. Turn protection on to scan downloads automatically.")
        if self.t_rt.isChecked() != on:
            self.t_rt.blockSignals(True)
            self.t_rt.setChecked(on)
            self.t_rt.setk(1.0 if on else 0.0)
            self.t_rt.blockSignals(False)


# --------------------------------------------------------------------------- #
#  Finestra principale
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
#  System scan (Quick / Full / Custom)
# --------------------------------------------------------------------------- #
def fmt_dur(sec):
    sec = int(max(0, sec))
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m:02d}m"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def fmt_ago(ts):
    d = time.time() - ts
    if d < 90:
        return "just now"
    if d < 3600:
        return f"{int(d // 60)} min ago"
    if d < 86400:
        return f"{int(d // 3600)} h ago"
    if d < 7 * 86400:
        n = int(d // 86400)
        return f"{n} day{'s' if n > 1 else ''} ago"
    return time.strftime("%b %d", time.localtime(ts))


class SystemScanWorker(QThread):
    detected = Signal(object)
    finished_scan = Signal(object)

    def __init__(self, mode, settings, folders=None):
        super().__init__()
        self.scan = fullscan.SystemScan(mode, DATA, settings, folders)
        self.scan.on_detect = self.detected.emit       # called from the scan thread: queued to the GUI

    def run(self):
        try:
            summ = self.scan.run()
        except Exception:
            with open(os.path.join(DATA, "crash.log"), "a", encoding="utf-8") as f:
                f.write(time.strftime("%Y-%m-%d %H:%M:%S system scan\n") + traceback.format_exc() + "\n")
            self.scan.stop = True
            summ = self.scan.summary()
            summ["error"] = True
        self.finished_scan.emit(summ)


class ScanRing(Animated):
    """Progress ring: determinate arc, or a sweeping arc while the total is still unknown."""
    def __init__(self, size=118, parent=None):
        super().__init__(33, parent)
        self.setFixedSize(size, size)
        self.t = 0.0
        self.frac = 0.0
        self.target = 0.0
        self.indet = False
        self.active = False
        self.color = C["cyan"]
        self.big = "—"
        self.small = "READY"

    def set_state(self, frac=None, indet=None, active=None, color=None, big=None, small=None):
        if frac is not None:
            self.target = max(0.0, min(1.0, frac))
        for k, v in (("indet", indet), ("active", active), ("color", color), ("big", big), ("small", small)):
            if v is not None:
                setattr(self, k, v)
        self.update()

    def tick(self):
        if not self.active and abs(self.target - self.frac) < 0.002:
            if self.frac != self.target:
                self.frac = self.target
                self.update()
            return                                  # idle: no repaint at all
        self.t += 0.033
        self.frac += (self.target - self.frac) * 0.14
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w = self.width()
        c = QPointF(w / 2, w / 2)
        r = w / 2 - 11
        rect = QRectF(c.x() - r, c.y() - r, 2 * r, 2 * r)
        col = QColor(self.color)
        # faint ticks
        p.save()
        p.translate(c)
        for i in range(60):
            a = math.radians(i * 6)
            on = (not self.indet) and i / 60 < self.frac
            p.setPen(QPen(qc(self.color, 150) if on else qc(C["dim"], 70), 1))
            p.drawLine(QPointF(math.cos(a) * (r + 7), math.sin(a) * (r + 7)),
                       QPointF(math.cos(a) * (r + 10), math.sin(a) * (r + 10)))
        p.restore()
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(qc("#1a1230"), 8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawEllipse(rect)
        if self.indet:
            start = int((90 - self.t * 220) * 16) % (360 * 16)
            span = int((70 + 40 * math.sin(self.t * 2.2)) * 16)
            arcs = [(start, span)]
        else:
            arcs = [(90 * 16, int(-360 * 16 * self.frac))] if self.frac > 0.001 else []
        for st, sp in arcs:
            glow = QColor(col)
            glow.setAlpha(55)
            p.setPen(QPen(glow, 16, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            p.drawArc(rect, st, sp)
            g = QConicalGradient(c, 90)
            g.setColorAt(0.0, col)
            g.setColorAt(0.5, qc(C["magenta"]) if self.color == C["cyan"] else col)
            g.setColorAt(1.0, col)
            p.setPen(QPen(QBrush(g), 8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            p.drawArc(rect, st, sp)
        if self.active:                              # slow outer orbit = "alive"
            rr = r + 15
            p.setPen(QPen(qc(C["violet"], 120), 1.4, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            orb = QRectF(c.x() - rr, c.y() - rr, 2 * rr, 2 * rr)
            p.drawArc(orb, int(self.t * 60 * 16) % (360 * 16), 40 * 16)
            p.drawArc(orb, int((self.t * 60 + 180) * 16) % (360 * 16), 40 * 16)
        p.setPen(qc(C["text"]))
        p.setFont(mkfont(w * (0.15 if len(self.big) > 5 else 0.19), QFont.Weight.Bold, HEAD))
        p.drawText(QRectF(0, w * 0.30, w, w * 0.28), Qt.AlignmentFlag.AlignCenter, self.big)
        p.setPen(qc(self.color if self.small in ("THREATS", "SUSPICIOUS", "CLEAN", "STOPPED") else C["muted"]))
        p.setFont(mkfont(w * 0.062, QFont.Weight.Bold, HEAD))
        p.drawText(QRectF(0, w * 0.58, w, w * 0.12), Qt.AlignmentFlag.AlignCenter, self.small)
        p.end()


class ModeCard(HudCard):
    clicked = Signal()

    def __init__(self, glyph, title, desc, accent):
        super().__init__(accent=accent, pad=14)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.selected = False
        self.lay.setSpacing(3)
        top = QHBoxLayout()
        top.addWidget(icon_lbl(glyph, 15, accent))
        top.addStretch()
        self.check = icon_lbl(IC["ok"], 10, accent)
        self.check.setVisible(False)
        top.addWidget(self.check)
        self.lay.addLayout(top)
        self.lay.addWidget(lbl(title, 11, C["text"], QFont.Weight.DemiBold, HEAD))
        self.lay.addWidget(lbl(desc, 8, C["muted"], wrap=True))
        self.lay.addStretch()

    def set_selected(self, on):
        self.selected = on
        self.check.setVisible(on)
        self.update()

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton and self.isEnabled():
            self.clicked.emit()

    def paintEvent(self, e):
        super().paintEvent(e)
        if self.selected:
            p = QPainter(self)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            r = QRectF(self.rect()).adjusted(1, 1, -1, -1)
            g = QLinearGradient(r.topLeft(), r.bottomRight())
            g.setColorAt(0, qc(self.accent, 46))
            g.setColorAt(1, qc(self.accent, 6))
            p.setBrush(g)
            p.setPen(QPen(qc(self.accent, 210), 1.4))
            p.drawRoundedRect(r, 18, 18)
            p.end()


class SystemScanPage(QWidget):
    MODES = [("quick", "flash", "Quick", "Running programs, startup items and the folders malware targets.", "cyan"),
             ("full", "drive", "Full", "Every file on all fixed drives. Can take a while.", "magenta"),
             ("custom", "folder", "Custom", "Only the files and folders you choose.", "violet")]

    def __init__(self, main):
        super().__init__()
        self.main = main
        self.worker = None
        self.results = []
        self.last = None
        s = main.store.settings
        self.mode = s.get("sysscan_mode", "quick")
        self.custom = [f for f in s.get("sysscan_folders", []) if isinstance(f, str)]
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(18)
        left = QVBoxLayout()
        left.setSpacing(12)
        left.addWidget(page_header("System Scan", "Deep scan of running programs, startup entries and the files on your drives"))

        mr = QHBoxLayout()
        mr.setSpacing(10)
        self.cards = {}
        for key, g, title, desc, col in self.MODES:
            c = ModeCard(IC[g], title, desc, C[col])
            c.setFixedHeight(116)
            c.clicked.connect(lambda k=key: self.set_mode(k))
            self.cards[key] = c
            mr.addWidget(c, 1)
        left.addLayout(mr)

        self.cbox = QWidget()
        cv = QVBoxLayout(self.cbox)
        cv.setContentsMargins(0, 0, 0, 0)
        cv.setSpacing(6)
        self.flist = QListWidget()
        self.flist.setFixedHeight(76)
        self.flist.setFont(mkfont(9, family=MONO))
        cv.addWidget(self.flist)
        fb = QHBoxLayout()
        self.b_add = GlowButton("ADD FOLDER", IC["add"], "ghost")
        self.b_files = GlowButton("ADD FILES", IC["file"], "ghost")
        self.b_rem = GlowButton("", IC["remove"], "ghost")
        self.b_rem.setMinimumWidth(44)
        self.b_rem.setToolTip("Remove the selected item")
        for b in (self.b_add, self.b_files, self.b_rem):
            b.setMinimumHeight(32)
            fb.addWidget(b)
        fb.addStretch()
        cv.addLayout(fb)
        left.addWidget(self.cbox)

        br = QHBoxLayout()
        self.b_start = GlowButton("START SCAN", IC["play"], "primary")
        self.b_pause = GlowButton("PAUSE", IC["pause"], "ghost")
        self.b_stop = GlowButton("STOP", IC["stop"], "danger")
        br.addWidget(self.b_start, 2)
        br.addWidget(self.b_pause, 1)
        br.addWidget(self.b_stop, 1)
        left.addLayout(br)

        pc = HudCard(accent=C["violet"], pad=16)
        ph = QHBoxLayout()
        ph.setSpacing(16)
        self.ring = ScanRing(118)
        ph.addWidget(self.ring, 0, Qt.AlignmentFlag.AlignVCenter)
        pv = QVBoxLayout()
        pv.setSpacing(3)
        self.phase = ElideLabel("Ready", 12, C["text"], QFont.Weight.DemiBold, HEAD)
        self.cur = ElideLabel("", 8.5, C["cyan"], family=MONO, mode=Qt.TextElideMode.ElideMiddle)
        pv.addWidget(self.phase)
        pv.addWidget(self.cur)
        pv.addSpacing(6)
        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(0)
        self.st = {}
        for i, (k, cap, col) in enumerate((("scanned", "FILES CHECKED", C["text"]), ("threats", "THREATS", C["red"]),
                                           ("suspicious", "SUSPICIOUS", C["amber"]), ("elapsed", "ELAPSED", C["text"]),
                                           ("speed", "FILES / SEC", C["text"]), ("data", "DATA READ", C["text"]))):
            r, cc = divmod(i, 3)
            v = lbl("0", 13, col, QFont.Weight.Bold, HEAD)
            grid.addWidget(v, r * 2, cc)
            grid.addWidget(lbl(cap, 7, C["dim"], QFont.Weight.Bold, HEAD), r * 2 + 1, cc)
            self.st[k] = v
        pv.addLayout(grid)
        ph.addLayout(pv, 1)
        pc.lay.addLayout(ph)
        left.addWidget(pc)

        dh = QHBoxLayout()
        dh.setSpacing(8)
        dh.addWidget(section_title("Detections", IC["bug"]), 1)
        self.b_qall = GlowButton("QUARANTINE ALL", IC["lock"], "danger")
        self.b_qall.setToolTip("Move every dangerous file found by this scan to quarantine")
        self.b_export = GlowButton("", IC["save"], "ghost")
        self.b_export.setMinimumWidth(44)
        self.b_export.setToolTip("Export the scan report")
        for b in (self.b_qall, self.b_export):
            b.setMinimumHeight(30)
            dh.addWidget(b)
        left.addLayout(dh)
        self.list = ResultsList()
        self.list.setMinimumHeight(110)
        left.addWidget(self.list, 1)
        self.empty = lbl("", 9, C["dim"], wrap=True)
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        left.addWidget(self.empty)
        lw = QWidget()
        lw.setLayout(left)
        lw.setFixedWidth(500)
        root.addWidget(lw, 5)
        self.detail = ResultDetail("system")
        root.addWidget(self.detail, 6)

        self.list.picked.connect(self.detail.show_result)
        self.detail.quarantined.connect(lambda r: (self.main.refresh_quarantine(), self._update_buttons()))
        self.b_start.clicked.connect(self.start)
        self.b_pause.clicked.connect(self.toggle_pause)
        self.b_stop.clicked.connect(self.stop)
        self.b_add.clicked.connect(self.add_folder)
        self.b_files.clicked.connect(self.add_files)
        self.b_rem.clicked.connect(self.remove_item)
        self.b_qall.clicked.connect(self.quarantine_all)
        self.b_export.clicked.connect(self.export_report)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll)
        self._speed = []
        self.reload_folders()
        self.set_mode(self.mode if self.mode in self.cards else "quick", save=False)

    # ------------------------------------------------------------ mode / folders
    def set_mode(self, k, save=True):
        if self.worker:
            return
        self.mode = k
        for key, c in self.cards.items():
            c.set_selected(key == k)
        self.cbox.setVisible(k == "custom")
        if save:
            self.main.store.settings["sysscan_mode"] = k
            self.main.store.save_settings()
        self.idle_state()

    def reload_folders(self):
        self.flist.clear()
        for f in self.custom:
            it = QListWidgetItem(f if os.path.exists(f) else f + "   (missing)")
            it.setData(Qt.ItemDataRole.UserRole, f)
            self.flist.addItem(it)
        if not self.custom:
            it = QListWidgetItem("Add the folders or files to scan")
            it.setFlags(Qt.ItemFlag.NoItemFlags)
            self.flist.addItem(it)

    def _save_custom(self):
        self.main.store.settings["sysscan_folders"] = self.custom
        self.main.store.save_settings()
        self.reload_folders()
        self._update_buttons()

    def add_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Folder to scan")
        if d:
            d = os.path.normpath(d)
            if d not in self.custom:
                self.custom.append(d)
                self._save_custom()

    def add_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Files to scan")
        for f in files:
            f = os.path.normpath(f)
            if f not in self.custom:
                self.custom.append(f)
        if files:
            self._save_custom()

    def remove_item(self):
        it = self.flist.currentItem()
        f = it.data(Qt.ItemDataRole.UserRole) if it else None
        if f in self.custom:
            self.custom.remove(f)
            self._save_custom()

    # ------------------------------------------------------------ state
    def _update_buttons(self):
        busy = self.worker is not None
        for c in self.cards.values():
            c.setEnabled(not busy)
        for b in (self.b_add, self.b_files, self.b_rem):
            b.setEnabled(not busy)
        self.b_start.setEnabled(not busy and (self.mode != "custom" or bool(self.custom)))
        self.b_pause.setEnabled(busy)
        self.b_stop.setEnabled(busy)
        self.b_qall.setEnabled(not busy and any(r.verdict == "DANGEROUS" and os.path.exists(r.target)
                                                for r in self.results))
        self.b_export.setEnabled(not busy and self.last is not None)

    def _set_stats(self, scanned, threats, sus, elapsed, speed, data):
        self.st["scanned"].setText(f"{scanned:,}")
        self.st["threats"].setText(str(threats))
        self.st["suspicious"].setText(str(sus))
        self.st["elapsed"].setText(elapsed)
        self.st["speed"].setText(speed)
        self.st["data"].setText(data)

    def idle_state(self):
        if self.worker:
            return
        self._update_buttons()
        if self.last is None:
            log = fullscan.load_log(DATA)
            L = log[0] if log else None
        else:
            L = self.last
        if not L:
            self.ring.set_state(0, False, False, C["cyan"], "—", "READY")
            self.phase.setText("No system scan yet")
            self.cur.setText("Start with a Quick scan: it takes a couple of minutes.")
            self._set_stats(0, 0, 0, "—", "—", "—")
        else:
            t, sus = L.get("threats", 0), L.get("suspicious", 0)
            col = C["red"] if t else (C["amber"] if sus or L.get("cancelled") else C["green"])
            big, small = (str(t), "THREATS") if t else ((str(sus), "SUSPICIOUS") if sus else
                                                        ("0", "STOPPED" if L.get("cancelled") else "CLEAN"))
            self.ring.set_state(1.0, False, False, col, big, small)
            state = "stopped" if L.get("cancelled") else "completed"
            self.phase.setText(f"Last scan: {L.get('mode', '').capitalize()}  ·  {state} {fmt_ago(L.get('date', 0))}")
            total = L.get("scanned", 0) + L.get("cached", 0)
            self.cur.setText(f"{total:,} files checked in {fmt_dur(L.get('duration', 0))}"
                             + ("  ·  no threats found" if not t and not sus and not L.get("cancelled") else ""))
            dur = max(1.0, L.get("duration", 1))
            self._set_stats(total, t, sus, fmt_dur(dur), f"{L.get('scanned', 0) / dur:,.0f}",
                            engine.human_size(L.get("bytes", 0)))
        self.empty.setText("" if self.list.count() else
                           "Nothing found yet. Detections from the next scan will be listed here.")
        self.empty.setVisible(self.list.count() == 0)

    # ------------------------------------------------------------ scan
    def start(self):
        if self.worker:
            return
        if self.mode == "custom" and not self.custom:
            self.main.toast("NOTHING TO SCAN", "Add at least one folder or file.", C["amber"])
            return
        self.list.clear()
        self.detail.clear()
        self.results = []
        self.last = None
        self._speed = []
        self._toasted = False
        self.worker = SystemScanWorker(self.mode, self.main.store.settings,
                                       list(self.custom) if self.mode == "custom" else None)
        self.worker.detected.connect(self.on_detect)
        self.worker.finished_scan.connect(self.on_done)
        self.worker.start()
        self.b_pause.tl.setText("PAUSE")
        self._update_buttons()
        self.ring.set_state(0, True, True, C["cyan"], "0", "FILES")
        self.phase.setText("Preparing")
        self.cur.setText("")
        self._set_stats(0, 0, 0, "0s", "—", "0 B")
        self.empty.setText("No threats so far.")
        self.empty.setVisible(True)
        self.detail.scanning("Preparing...", "Collecting files")
        self.timer.start(150)

    def toggle_pause(self):
        if self.worker:
            sc = self.worker.scan
            sc.paused = not sc.paused
            self.b_pause.tl.setText("RESUME" if sc.paused else "PAUSE")
            self.b_pause.ic.setText(IC["play"] if sc.paused else IC["pause"])

    def stop(self):
        if self.worker:
            self.worker.scan.stop = True
            self.worker.scan.paused = False
            self.phase.setText("Stopping...")

    def poll(self):
        w = self.worker
        if not w:
            return
        s = w.scan.stats
        now = time.time()
        el = now - s["started"]
        checked = s["scanned"] + s["cached"]
        self._speed.append((now, s["scanned"]))
        while len(self._speed) > 2 and now - self._speed[0][0] > 4:
            self._speed.pop(0)
        t0, n0 = self._speed[0]
        speed = (s["scanned"] - n0) / (now - t0) if now - t0 > 0.5 else 0
        self._set_stats(checked, s["threats"], s["suspicious"], fmt_dur(el),
                        f"{speed:,.0f}" if speed else "—", engine.human_size(s["bytes"]))
        phase = s["phase"]
        if phase.startswith("Verifying"):
            tot = max(1, s.get("verify_total", 0))
            frac = 0.9 + 0.1 * min(1.0, s.get("verified", 0) / tot)
            self.ring.set_state(frac, False, True, C["magenta"], f"{int(frac * 100)}%", "VERIFYING")
        elif s["enum_done"]:
            frac = 0.9 * s["scanned"] / max(1, s["found"])
            self.ring.set_state(frac, False, True, C["cyan"], f"{int(frac * 100)}%", "SCANNING")
        else:
            self.ring.set_state(None, True, True, C["cyan"], f"{checked:,}", "FILES")
        if w.scan.paused:
            phase = "Paused"
        elif w.scan.stop:
            phase = "Stopping..."
        self.phase.setText(phase)
        self.cur.setText(s["current"])
        if self.detail.res is None:
            self.detail.scanning(s["current"] or "Preparing...", phase)

    def on_detect(self, res):
        self.main.store.add(res)
        self.results.append(res)
        self.list.add_result(res)
        self.empty.setVisible(False)
        if res.verdict == "DANGEROUS" and not self._toasted:
            self._toasted = True
            self.main.toast("THREAT DETECTED", f"{res.name[:60]}  ·  score {res.score}/100", C["red"])

    def on_done(self, summ):
        self.timer.stop()
        w, self.worker = self.worker, None
        if w:
            w.wait(3000)
            w.deleteLater()
        self.last = summ
        fullscan.save_log(DATA, summ)
        self.main.store.save_history()
        self.main.refresh_dashboard()
        t, sus = summ.get("threats", 0), summ.get("suspicious", 0)
        self.idle_state()
        if summ.get("cancelled"):
            self.phase.setText("Scan stopped")
        else:
            self.phase.setText(f"{summ.get('mode', '').capitalize()} scan complete")
        if self.results:
            self.list.blockSignals(True)
            self.list.clear()
            for r in sorted(self.results, key=lambda r: -r.score):
                self.list.add_result(r, top=False)
            self.list.blockSignals(False)
            self.list.setCurrentRow(0)
            self.detail.show_result(sorted(self.results, key=lambda r: -r.score)[0])
        else:
            self.detail.clear()
        if summ.get("error"):
            title, msg, col = "SCAN ERROR", "The scan stopped unexpectedly (details in data\\crash.log).", C["red"]
        elif summ.get("cancelled"):
            title, msg, col = "SCAN STOPPED", f"{t} threats, {sus} suspicious files so far.", C["amber"]
        elif t:
            title, msg, col = "THREATS FOUND", f"{t} dangerous and {sus} suspicious files. Quarantine them.", C["red"]
        elif sus:
            title, msg, col = "SCAN COMPLETE", f"No threats  ·  {sus} suspicious files to review.", C["amber"]
        else:
            title, msg, col = "SCAN COMPLETE", "No threats found. Your PC is clean.", C["green"]
        self.main.toast(title, msg, col)
        if not self.main.isVisible() or not self.main.isActiveWindow():
            self.main.notify(f"Eclipse: {title.capitalize()}", msg, bool(t))

    # ------------------------------------------------------------ actions
    def quarantine_all(self):
        todo = [r for r in self.results if r.verdict == "DANGEROUS" and os.path.exists(r.target)]
        if not todo:
            self.main.toast("NOTHING TO QUARANTINE", "No dangerous files left on disk.", C["cyan"])
            return
        mb = QMessageBox(self)
        mb.setWindowTitle("Quarantine")
        mb.setText(f"Move {len(todo)} dangerous file{'s' if len(todo) > 1 else ''} to quarantine?\n\n"
                   + "\n".join(short(r.target, 80) for r in todo[:8]) + ("\n..." if len(todo) > 8 else "")
                   + "\n\nThey will be encrypted and removed from their location. "
                     "You can restore them from the Quarantine section.")
        mb.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if mb.exec() != QMessageBox.StandardButton.Yes:
            return
        ok, failed = 0, 0
        for r in todo:
            try:
                quarantine_file(r)
                ok += 1
            except Exception:
                failed += 1
        self.main.refresh_quarantine()
        self._update_buttons()
        if self.detail.res is not None:
            self.detail.show_result(self.detail.res)
        self.main.toast("FILES ISOLATED" if ok else "QUARANTINE ERROR",
                        f"{ok} moved to quarantine" + (f", {failed} failed (in use?)" if failed else ""),
                        C["green"] if ok and not failed else C["amber"])

    def export_report(self):
        if not self.last:
            return
        L = self.last
        stamp = time.strftime("%Y%m%d_%H%M", time.localtime(L.get("date", time.time())))
        path, _ = QFileDialog.getSaveFileName(self, "Export scan report",
                                              os.path.join(REPORTS, f"system_scan_{L.get('mode', '')}_{stamp}.txt"),
                                              "Text report (*.txt);;JSON (*.json)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            if path.lower().endswith(".json"):
                json.dump({"summary": L, "detections": [r.to_dict() for r in self.results]}, f,
                          ensure_ascii=False, indent=2)
            else:
                f.write("ECLIPSE - SYSTEM SCAN REPORT\n" + "=" * 60 + "\n")
                f.write(f"Mode        : {L.get('mode', '').capitalize()}\n")
                f.write(f"Started     : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(L.get('date', 0)))}\n")
                f.write(f"Duration    : {fmt_dur(L.get('duration', 0))}{'  (stopped)' if L.get('cancelled') else ''}\n")
                f.write(f"Files       : {L.get('scanned', 0) + L.get('cached', 0):,} checked "
                        f"({L.get('cached', 0):,} unchanged since the last scan)\n")
                f.write(f"Threats     : {L.get('threats', 0)}\nSuspicious  : {L.get('suspicious', 0)}\n\n")
                for r in self.results:
                    f.write(r.report_text() + "\n\n" + "-" * 60 + "\n\n")
        self.main.toast("REPORT SAVED", os.path.basename(path), C["green"])


class NavButton(QPushButton):
    def __init__(self, glyph, text):
        super().__init__()
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(44)
        self.glyph, self.text_ = glyph, text
        self._h = 0.0
        self.anim = QPropertyAnimation(self, b"hl", self)
        self.anim.setDuration(220)
        self.setStyleSheet("QPushButton { border: none; background: transparent; }")

    def geth(self):
        return self._h

    def seth(self, v):
        self._h = v
        self.update()

    hl = Property(float, geth, seth)

    def enterEvent(self, e):
        self.anim.stop(); self.anim.setStartValue(self._h); self.anim.setEndValue(1.0); self.anim.start()

    def leaveEvent(self, e):
        self.anim.stop(); self.anim.setStartValue(self._h); self.anim.setEndValue(0.0); self.anim.start()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(self.rect()).adjusted(10, 2, -10, -2)
        on = self.isChecked()
        if not on and self._h > 0:
            p.setBrush(QColor(255, 255, 255, int(8 * self._h)))
            p.setPen(Qt.PenStyle.NoPen)
            p.drawRoundedRect(r, 12, 12)
        if on:
            col = qc("#ffffff")
        else:
            c0, c1 = QColor(C["muted"]), QColor(C["text"])
            t = self._h
            col = QColor(int(c0.red() + (c1.red() - c0.red()) * t), int(c0.green() + (c1.green() - c0.green()) * t),
                         int(c0.blue() + (c1.blue() - c0.blue()) * t))
        shift = 3 * self._h if not on else 0
        p.setPen(qc(C["cyan"]) if on else col)
        p.setFont(icon_font(12.5))
        p.drawText(QRectF(r.left() + 14 + shift, r.top(), 26, r.height()), Qt.AlignmentFlag.AlignVCenter, self.glyph)
        p.setPen(col)
        p.setFont(mkfont(10.5, QFont.Weight.DemiBold if on else QFont.Weight.Normal, HEAD))
        p.drawText(QRectF(r.left() + 46 + shift, r.top(), r.width() - 50, r.height()), Qt.AlignmentFlag.AlignVCenter,
                   self.text_)
        p.end()


class NavIndicator(QWidget):
    """Pillola luminosa che scivola sotto la voce di menu attiva."""
    def __init__(self, parent):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.anim = QPropertyAnimation(self, b"geometry", self)
        self.anim.setDuration(420)
        self.anim.setEasingCurve(QEasingCurve.Type.OutBack)

    def move_to(self, btn, animate=True):
        target = btn.geometry().adjusted(10, 2, -10, -2)
        if not animate or not self.isVisible():
            self.setGeometry(target)
            self.show()
            self.lower()
            return
        self.anim.stop()
        self.anim.setStartValue(self.geometry())
        self.anim.setEndValue(target)
        self.anim.start()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        g = QLinearGradient(r.topLeft(), r.topRight())
        g.setColorAt(0, qc(C["violet"], 120))
        g.setColorAt(1, qc(C["magenta"], 30))
        p.setBrush(g)
        p.setPen(QPen(qc(C["cyan"], 60), 1))
        p.drawRoundedRect(r, 12, 12)
        glow = QRadialGradient(QPointF(r.left() + 4, r.center().y()), r.height())
        glow.setColorAt(0, qc(C["magenta"], 90))
        glow.setColorAt(1, qc(C["magenta"], 0))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(glow)
        p.drawRoundedRect(r, 12, 12)
        p.end()


class TitleBar(QWidget):
    def __init__(self, win):
        super().__init__()
        self.win = win
        self.setFixedHeight(44)
        h = QHBoxLayout(self)
        h.setContentsMargins(16, 0, 6, 0)
        h.setSpacing(10)
        h.addWidget(EclipseLogo(26, speed=1.4))
        h.addWidget(lbl("Eclipse", 11.5, C["text"], QFont.Weight.DemiBold, HEAD))
        h.addWidget(lbl("threat scanner", 9.5, C["dim"]))
        h.addStretch()
        self.clock = lbl("", 9, C["muted"], family=MONO)
        h.addWidget(self.clock)
        h.addSpacing(12)
        for glyph, slot, hover in ((IC["min"], win.showMinimized, "rgba(255,255,255,20)"),
                                   (IC["max"], win.toggle_max, "rgba(255,255,255,20)"),
                                   (IC["close"], win.close, C["red"])):
            b = QPushButton(glyph)
            b.setFont(icon_font(9))
            b.setFixedSize(42, 32)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setStyleSheet(f"QPushButton {{ border:none; border-radius:8px; color:{C['muted']}; background:transparent; }}"
                            f"QPushButton:hover {{ background:{hover}; color:white; }}")
            b.clicked.connect(slot)
            h.addWidget(b)
            if glyph == IC["max"]:
                self.maxbtn = b
        t = QTimer(self)
        t.timeout.connect(self._clock)
        t.start(1000)
        self._clock()

    def _clock(self):
        self.clock.setText(time.strftime("%H:%M"))

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self.win.windowHandle().startSystemMove()

    def mouseDoubleClickEvent(self, e):
        self.win.toggle_max()


class Backdrop(QWidget):
    """Black background with a slow violet aurora and drifting particles.
    The whole frame is composed once per tick into a pixmap; paint events only blit the dirty area,
    so small animations elsewhere (logo, buttons) no longer re-render the aurora."""
    BLOBS = [  # colour, relative radius, speed, phase
        ("#7c3aed", 0.55, 0.11, 0.0),
        ("#c026d3", 0.42, 0.07, 2.1),
        ("#4c1d95", 0.60, 0.05, 4.0),
        ("#a855f7", 0.30, 0.13, 1.3),
    ]
    INTERVAL = 140

    def __init__(self, parent=None):
        super().__init__(parent)
        self.base = None
        self.frame = None
        self.radius = 18
        self.t = random.random() * 100
        rnd = random.Random(3)
        self.parts = [[rnd.random(), rnd.random(), rnd.uniform(0.0004, 0.0012), rnd.uniform(0.6, 1.8),
                       rnd.uniform(0, 6.28)] for _ in range(30)]
        self._n = 0
        tm = QTimer(self)
        tm.timeout.connect(self._tick)
        tm.start(self.INTERVAL)

    def resizeEvent(self, e):
        self.base = None
        self.frame = None
        super().resizeEvent(e)

    @property
    def cache(self):
        return self.base

    @cache.setter
    def cache(self, v):
        self.base = v
        self.frame = None

    def _tick(self):
        w = self.window()
        if w.isMinimized() or not w.isVisible():
            return
        if not w.isActiveWindow():          # in the background: ~1.5 fps is plenty
            self._n = (self._n + 1) % 5
            if self._n:
                return
            k = 5
        else:
            k = 1
        k *= self.INTERVAL / 80
        self.t += 0.08 * k
        for pt in self.parts:
            pt[1] -= pt[2] * k
            if pt[1] < -0.02:
                pt[1] = 1.02
                pt[0] = random.random()
        self.frame = None
        self.update()

    def _build_base(self):
        w, h = self.width(), self.height()
        dpr = self.devicePixelRatioF()
        pm = QPixmap(int(w * dpr), int(h * dpr))
        pm.setDevicePixelRatio(dpr)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        path = QPainterPath()
        path.addRoundedRect(QRectF(0, 0, w, h), self.radius, self.radius)
        p.setClipPath(path)
        g = QLinearGradient(0, 0, 0, h)
        g.setColorAt(0, qc("#060409"))
        g.setColorAt(1, qc(C["bg"]))
        p.fillRect(0, 0, w, h, g)
        p.end()
        self.base = pm
        self.clip = path
        # vignette, pre-rendered once
        vg_pm = QPixmap(int(w * dpr), int(h * dpr))
        vg_pm.setDevicePixelRatio(dpr)
        vg_pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(vg_pm)
        vg = QRadialGradient(QPointF(w / 2, h / 2), max(w, h) * 0.75)
        vg.setColorAt(0.55, QColor(0, 0, 0, 0))
        vg.setColorAt(1.0, QColor(0, 0, 0, 170))
        p.fillRect(QRectF(0, 0, w, h), vg)
        p.end()
        self.vignette = vg_pm

    def _aurora(self):
        sw, sh = max(8, self.width() // 12), max(8, self.height() // 12)
        img = QPixmap(sw, sh)
        img.fill(Qt.GlobalColor.transparent)
        p = QPainter(img)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setCompositionMode(QPainter.CompositionMode.CompositionMode_Plus)
        for col, rr, sp, ph in self.BLOBS:
            x = sw * (0.5 + 0.42 * math.sin(self.t * sp + ph))
            y = sh * (0.45 + 0.4 * math.cos(self.t * sp * 0.8 + ph * 1.7))
            rad = max(sw, sh) * rr
            rg = QRadialGradient(QPointF(x, y), rad)
            rg.setColorAt(0, qc(col, 70))
            rg.setColorAt(0.5, qc(col, 24))
            rg.setColorAt(1, qc(col, 0))
            p.setBrush(rg)
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QPointF(x, y), rad, rad)
        p.end()
        return img

    def _compose(self):
        if self.base is None or self.base.deviceIndependentSize().toSize() != self.size():
            self._build_base()
        w, h = self.width(), self.height()
        fr = QPixmap(self.base)
        p = QPainter(fr)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        p.setClipPath(self.clip)
        p.drawPixmap(QRectF(0, 0, w, h), self._aurora(), QRectF(0, 0, max(8, w // 12), max(8, h // 12)))
        p.drawPixmap(0, 0, self.vignette)
        p.setPen(Qt.PenStyle.NoPen)
        for x, y, _, sz, ph in self.parts:
            a = int(60 + 60 * math.sin(self.t * 2 + ph))
            p.setBrush(QColor(200, 170, 255, max(0, a)))
            p.drawEllipse(QPointF(x * w, y * h), sz, sz)
        p.setClipping(False)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(QColor(179, 136, 255, 40), 1))
        p.drawRoundedRect(QRectF(0.5, 0.5, w - 1, h - 1), self.radius, self.radius)
        p.end()
        self.frame = fr

    def paintEvent(self, e):
        if self.frame is None:
            self._compose()
        p = QPainter(self)
        p.setCompositionMode(QPainter.CompositionMode.CompositionMode_Source)
        p.setClipRegion(e.region())
        p.drawPixmap(0, 0, self.frame)
        p.end()


class MainWindow(QWidget):
    MARGIN = 6

    def __init__(self):
        super().__init__()
        self.store = Store()
        self.setWindowTitle("ECLIPSE - Threat Scanner")
        self.setWindowIcon(make_app_icon())
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setMouseTracking(True)
        self.resize(1360, 860)
        self.setMinimumSize(1120, 720)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(self.MARGIN, self.MARGIN, self.MARGIN, self.MARGIN)
        self.back = Backdrop()
        outer.addWidget(self.back)
        bl = QVBoxLayout(self.back)
        bl.setContentsMargins(1, 1, 1, 1)
        bl.setSpacing(0)
        self.title = TitleBar(self)
        bl.addWidget(self.title)
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        bl.addLayout(body, 1)

        # sidebar
        side = QWidget()
        side.setFixedWidth(220)
        side.setStyleSheet("background: transparent;")
        sv = QVBoxLayout(side)
        sv.setContentsMargins(10, 10, 6, 16)
        sv.setSpacing(2)
        sv.addSpacing(4)
        self.side = side
        self.indicator = NavIndicator(side)
        self.navs = []
        NAV = [("SCAN", None), (IC["home"], "Dashboard"), (IC["drive"], "System Scan"), (IC["file"], "File Scanner"),
               (IC["link"], "Link Scanner"),
               ("MONITOR", None), (IC["shield"], "Real-time"), (IC["cpu"], "Processes"), (IC["power"], "Startup"),
               (IC["net"], "Network"),
               ("DATA", None), (IC["history"], "History"), (IC["lock"], "Quarantine"), (IC["settings"], "Settings")]
        for g, t in NAV:
            if t is None:
                h = lbl(g, 7.5, C["dim"], QFont.Weight.Bold, HEAD)
                h.setContentsMargins(26, 10 if self.navs else 0, 0, 4)
                sv.addWidget(h)
                continue
            b = NavButton(g, t)
            b.setFixedHeight(40)
            b.clicked.connect(lambda _=False, k=len(self.navs): self.go(k))
            sv.addWidget(b)
            self.navs.append(b)
        sv.addStretch()
        status = QWidget()
        sh = QHBoxLayout(status)
        sh.setContentsMargins(22, 0, 0, 4)
        sh.setSpacing(8)
        self.pulse = PulseDot()
        sh.addWidget(self.pulse)
        self.pulse_lbl = lbl("Protection active", 9, C["muted"])
        sh.addWidget(self.pulse_lbl)
        sh.addStretch()
        sv.addWidget(status)
        ver = lbl(f"v{VERSION}", 8, C["dim"], family=MONO)
        ver.setContentsMargins(24, 0, 0, 0)
        sv.addWidget(ver)
        body.addWidget(side)
        sep = QFrame()
        sep.setFixedWidth(1)
        sep.setStyleSheet("background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 transparent, "
                          "stop:0.5 rgba(179,136,255,40), stop:1 transparent);")
        body.addWidget(sep)

        # pagine
        area = QWidget()
        av = QVBoxLayout(area)
        av.setContentsMargins(24, 14, 24, 20)
        self.stack = QStackedWidget()
        av.addWidget(self.stack)
        body.addWidget(area, 1)
        self.dash = DashboardPage(self)
        self.sysscan = SystemScanPage(self)
        self.files = FilesPage(self)
        self.links = LinksPage(self)
        self.hist = HistoryPage(self)
        self.quar = QuarantinePage(self)
        self.sett = SettingsPage(self)
        self.rt_worker = None
        self.rt_ignore = set()
        self._quitting = False
        self.prot = ProtectionPage(self)
        self.procs = ProcessesPage(self)
        self.autoruns = StartupPage(self)
        self.net = NetworkPage(self)
        for pg in (self.dash, self.sysscan, self.files, self.links, self.prot, self.procs, self.autoruns, self.net,
                   self.hist, self.quar, self.sett):
            self.stack.addWidget(pg)
        self.fade = PageFade(area)

        self._pt = 0.0
        pt = QTimer(self)
        pt.timeout.connect(self._pulse)
        pt.start(500)
        self.setup_tray()
        QApplication.instance().aboutToQuit.connect(self.shutdown)
        if self.store.settings.get("realtime", True):
            self.start_realtime()
        self.go(0, animate=False)
        self.refresh_dashboard()

    # ----------------------------------------------------------- navigazione
    def go(self, i, animate=True):
        for k, b in enumerate(self.navs):
            b.setChecked(k == i)
        if self.stack.currentIndex() == i and animate:
            return
        pg = self.stack.widget(i)
        if pg is self.hist:
            self.hist.reload()
        elif pg is self.quar:
            self.quar.reload()
        elif pg is self.dash:
            self.refresh_dashboard()
        elif pg is self.links:
            self.links.update_mode()
        if hasattr(pg, "on_show"):
            QTimer.singleShot(450 if animate else 0, pg.on_show)
        if animate and self.isVisible():
            self.fade.run(self.stack, i)
        else:
            self.stack.setCurrentIndex(i)
        self.indicator.move_to(self.navs[i], animate and self.isVisible())

    def showEvent(self, e):
        super().showEvent(e)
        QTimer.singleShot(0, lambda: self.indicator.move_to(self.navs[self.stack.currentIndex()], False))
        # comparsa della finestra in dissolvenza
        if not getattr(self, "_shown", False):
            self._shown = True
            self.setWindowOpacity(0.0)
            self._wa = QPropertyAnimation(self, b"windowOpacity", self)
            self._wa.setDuration(500)
            self._wa.setStartValue(0.0)
            self._wa.setEndValue(1.0)
            self._wa.setEasingCurve(QEasingCurve.Type.OutCubic)
            self._wa.start()

    def open_history(self, res):
        self.go(self.stack.indexOf(self.hist))
        self.hist.select_result(res)

    def refresh_dashboard(self):
        self.dash.refresh()

    def refresh_quarantine(self):
        self.quar.reload()

    def quick_scan(self):
        self.show_from_tray()
        self.go(self.stack.indexOf(self.sysscan))
        if self.sysscan.worker is None:
            self.sysscan.set_mode("quick")
            self.sysscan.start()

    def toast(self, title, msg, color):
        Toast(self.back, title, msg, color)

    def _pulse(self):
        self._pt += 0.12
        self.pulse.ok = self.rt_worker is not None

    # ----------------------------------------------------------- finestra
    def toggle_max(self):
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    def changeEvent(self, e):
        if e.type() == e.Type.WindowStateChange:
            m = 0 if self.isMaximized() else self.MARGIN
            self.layout().setContentsMargins(m, m, m, m)
            self.back.radius = 0 if self.isMaximized() else 18
            self.back.cache = None
            self.title.maxbtn.setText(IC["restore"] if self.isMaximized() else IC["max"])
        super().changeEvent(e)

    def paintEvent(self, e):
        # bordo quasi trasparente: permette il ridimensionamento con il mouse
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(0, 0, 0, 2))
        p.end()

    def _edges(self, pos):
        m = self.MARGIN + 2
        r = self.rect()
        e = Qt.Edge(0)
        if pos.x() <= m:
            e |= Qt.Edge.LeftEdge
        if pos.x() >= r.width() - m:
            e |= Qt.Edge.RightEdge
        if pos.y() <= m:
            e |= Qt.Edge.TopEdge
        if pos.y() >= r.height() - m:
            e |= Qt.Edge.BottomEdge
        return e

    def mouseMoveEvent(self, e):
        if self.isMaximized():
            return
        ed = self._edges(e.position().toPoint())
        L, R, T, B = Qt.Edge.LeftEdge, Qt.Edge.RightEdge, Qt.Edge.TopEdge, Qt.Edge.BottomEdge
        if ed in (L | T, R | B):
            self.setCursor(Qt.CursorShape.SizeFDiagCursor)
        elif ed in (R | T, L | B):
            self.setCursor(Qt.CursorShape.SizeBDiagCursor)
        elif ed in (L, R):
            self.setCursor(Qt.CursorShape.SizeHorCursor)
        elif ed in (T, B):
            self.setCursor(Qt.CursorShape.SizeVerCursor)
        else:
            self.unsetCursor()

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton and not self.isMaximized():
            ed = self._edges(e.position().toPoint())
            if ed != Qt.Edge(0):
                self.windowHandle().startSystemResize(ed)

    # ----------------------------------------------------------- tray + real-time
    def setup_tray(self):
        self.tray = QSystemTrayIcon(make_app_icon(), self)
        self.tray.setToolTip("Eclipse - Threat Scanner")
        m = QMenu()
        a_open = QAction("Open Eclipse", m)
        a_open.triggered.connect(self.show_from_tray)
        m.addAction(a_open)
        m.addSeparator()
        self.a_rt = QAction("Real-time protection", m)
        self.a_rt.setCheckable(True)
        self.a_rt.triggered.connect(lambda on: self.prot.t_rt.setChecked(on))
        m.addAction(self.a_rt)
        a_scan = QAction("Scan Downloads now", m)
        a_scan.triggered.connect(lambda: (self.show_from_tray(), self.go(self.stack.indexOf(self.files)),
                                          self.files.scan_downloads()))
        m.addAction(a_scan)
        a_qs = QAction("Run a Quick system scan", m)
        a_qs.triggered.connect(self.quick_scan)
        m.addAction(a_qs)
        m.addSeparator()
        a_quit = QAction("Quit Eclipse", m)
        a_quit.triggered.connect(self.quit_app)
        m.addAction(a_quit)
        self.tray_menu = m
        self.tray.setContextMenu(m)
        self.tray.activated.connect(lambda r: self.show_from_tray()
                                    if r in (QSystemTrayIcon.ActivationReason.Trigger,
                                             QSystemTrayIcon.ActivationReason.DoubleClick) else None)
        self.tray.messageClicked.connect(lambda: (self.show_from_tray(), self.go(self.stack.indexOf(self.prot))))
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray.show()

    def show_from_tray(self):
        if self.isMinimized():
            self.showNormal()
        self.show()
        self.raise_()
        self.activateWindow()

    def notify(self, title, msg, danger=False):
        if self.store.settings.get("notify", True) and self.tray.isVisible():
            icon = QSystemTrayIcon.MessageIcon.Warning if danger else QSystemTrayIcon.MessageIcon.Information
            self.tray.showMessage(title, msg, icon, 7000)

    def flagged_paths(self):
        out = {}
        for h in self.store.history:
            if h.get("kind") == "file" and h.get("verdict") in ("DANGEROUS", "SUSPICIOUS"):
                out.setdefault(os.path.normcase(h["target"]), h["verdict"].lower())
        return out

    def start_realtime(self):
        if self.rt_worker is not None:
            return
        self.rt_worker = RealtimeWorker(self.prot.folders(), self.store.settings)
        self.rt_worker.detected.connect(self.on_realtime)
        self.rt_worker.scanning.connect(self.prot.set_scanning)
        self.rt_worker.start()
        self._rt_changed()

    def stop_realtime(self):
        w, self.rt_worker = self.rt_worker, None
        if w is not None:
            w.stop = True
            w.wait(4000)
        self.prot.set_scanning("")
        self._rt_changed()

    def restart_realtime(self):
        if self.rt_worker is not None:
            self.stop_realtime()
            self.start_realtime()
        else:
            self.prot.update_state()

    def _rt_changed(self):
        on = self.rt_worker is not None
        self.prot.update_state()
        self.pulse_lbl.setText("Real-time protection on" if on else "Real-time protection off")
        if hasattr(self, "a_rt"):
            self.a_rt.setChecked(on)
        self.tray.setToolTip("Eclipse - " + ("protection active" if on else "protection off")) if hasattr(self, "tray") else None
        if self.stack.currentWidget() is self.dash:
            self.refresh_dashboard()

    def on_realtime(self, res):
        self.store.add(res)
        self.store.save_history()
        quarantined = False
        if (res.verdict == "DANGEROUS" and self.store.settings.get("auto_quarantine")
                and os.path.normcase(res.target) not in self.rt_ignore and os.path.exists(res.target)):
            try:
                quarantine_file(res)
                quarantined = True
                res.meta["action"] = "quarantined automatically"
                self.store.history[0] = res.to_dict()
                self.store.save_history()
                self.quar.reload()
            except Exception:
                pass
        self.prot.add_event(res)
        if res.verdict != "SAFE":
            col = C["red"] if res.verdict == "DANGEROUS" else C["amber"]
            title = ("THREAT QUARANTINED" if quarantined else "THREAT DETECTED") if res.verdict == "DANGEROUS" \
                else "SUSPICIOUS FILE"
            self.toast(title, f"{res.name[:60]}  ·  score {res.score}/100", col)
            self.notify(f"Eclipse: {title.capitalize()}",
                        f"{res.name}\nScore {res.score}/100" + ("  ·  moved to quarantine" if quarantined else
                                                                 "  ·  do not open it"), True)
        if self.stack.currentWidget() is self.dash:
            self.refresh_dashboard()

    def quit_app(self):
        self._quitting = True
        self.close()

    def shutdown(self):
        if getattr(self, "_down", False):
            return
        self._down = True
        w = self.sysscan.worker
        if w is not None:
            w.scan.stop = True
            w.wait(8000)
        for pg in (self.files, self.links):
            if pg.worker:
                pg.worker.stop = True
                pg.worker.wait(3000)
        for pg in (self.procs, self.autoruns, self.net):
            if pg.worker:
                pg.worker.wait(8000)
        self.stop_realtime()
        self.store.save_history()
        if hasattr(self, "tray"):
            self.tray.hide()

    def closeEvent(self, e):
        if (not self._quitting and self.rt_worker is not None and self.store.settings.get("tray_on_close", True)
                and self.tray.isVisible()):
            e.ignore()
            self.hide()
            if not self.store.settings.get("tray_hint_shown"):
                self.store.settings["tray_hint_shown"] = True
                self.store.save_settings()
                self.tray.showMessage("Eclipse is still protecting you",
                                      "Real-time protection keeps running in the background. "
                                      "Right-click the tray icon to quit.", QSystemTrayIcon.MessageIcon.Information, 6000)
            return
        self.shutdown()
        super().closeEvent(e)
        QApplication.instance().quit()


def main():
    sys.setswitchinterval(0.002)
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Eclipse.ThreatScanner")
    except Exception:
        pass
    tray_mode = "--tray" in sys.argv
    show_evt = None
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        tag = os.environ.get("ECLIPSE_INSTANCE_TAG", "")      # lets a test build run beside the real one
        k32.CreateMutexW(None, False, "Local\\Eclipse.ThreatScanner.Instance" + tag)
        if k32.GetLastError() == 183:          # already running: ask it to show itself
            h = k32.OpenEventW(0x0002, False, "Local\\Eclipse.ThreatScanner.Show" + tag)
            if h:
                k32.SetEvent(h)
            return
        show_evt = k32.CreateEventW(None, False, False, "Local\\Eclipse.ThreatScanner.Show" + tag)
    except Exception:
        pass
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setQuitOnLastWindowClosed(False)
    app.setFont(mkfont(10))
    app.setStyleSheet(QSS)
    app.setWindowIcon(make_app_icon())
    splash = None if tray_mode else Splash()
    if splash:
        splash.show()
    win = MainWindow()
    if show_evt:
        def poll_show():
            if ctypes.windll.kernel32.WaitForSingleObject(show_evt, 0) == 0:
                win.show_from_tray()
        pt = QTimer(win)
        pt.timeout.connect(poll_show)
        pt.start(400)

    def reveal():
        splash.close()
        win.show()
    if splash:
        QTimer.singleShot(650, reveal)
    if "--quick-scan" in sys.argv:              # e.g. from Task Scheduler
        QTimer.singleShot(1200, win.quick_scan)
    sys.exit(app.exec())


class Splash(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.SplashScreen |
                            Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(420, 420)
        scr = QGuiApplication.primaryScreen().geometry()
        self.move(scr.center() - self.rect().center())
        self.angle, self.t, self.p = 0.0, 0.0, 0.0
        tm = QTimer(self)
        tm.timeout.connect(self._tick)
        tm.start(16)

    def _tick(self):
        self.angle = (self.angle + 3) % 360
        self.t += 0.08
        self.p = min(1.0, self.p + 0.03)
        self.update()

    def paintEvent(self, e):
        pm = QPixmap(300, 300)
        pm.fill(Qt.GlobalColor.transparent)
        paint_eclipse(pm, 300, self.angle, self.t, 1.3)
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.drawPixmap(60, 10, pm)
        p.setPen(qc(C["text"]))
        p.setFont(mkfont(26, QFont.Weight.Bold, HEAD))
        p.drawText(QRectF(0, 300, 420, 40), Qt.AlignmentFlag.AlignCenter, "E C L I P S E")
        p.setPen(qc(C["muted"]))
        p.setFont(mkfont(9, QFont.Weight.Bold, HEAD))
        p.drawText(QRectF(0, 338, 420, 20), Qt.AlignmentFlag.AlignCenter, "INITIALIZING SCAN ENGINES")
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(qc(C["border"]))
        p.drawRoundedRect(QRectF(110, 372, 200, 4), 2, 2)
        g = QLinearGradient(110, 0, 310, 0)
        g.setColorAt(0, qc(C["cyan"]))
        g.setColorAt(1, qc(C["violet"]))
        p.setBrush(g)
        p.drawRoundedRect(QRectF(110, 372, 200 * self.p, 4), 2, 2)
        p.end()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        with open(os.path.join(DATA, "crash.log"), "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S\n") + traceback.format_exc() + "\n")
        raise
