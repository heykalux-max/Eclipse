"""Genera eclipse.ico (tutte le dimensioni) e eclipse.png per l'eseguibile."""
import io
import os
import sys

from PySide6.QtCore import Qt, QBuffer, QIODevice
from PySide6.QtGui import QGuiApplication, QPixmap

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
app = QGuiApplication(sys.argv)
from main import paint_app_icon  # noqa: E402
from PIL import Image  # noqa: E402


def render(s):
    pm = QPixmap(s, s)
    pm.fill(Qt.GlobalColor.transparent)
    paint_app_icon(pm, s)
    buf = QBuffer()
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    pm.save(buf, "PNG")
    return Image.open(io.BytesIO(bytes(buf.data()))).convert("RGBA")


sizes = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256]
imgs = [render(s) for s in sizes]
imgs[-1].save(os.path.join(HERE, "eclipse.png"))
imgs[-1].save(os.path.join(HERE, "eclipse.ico"), sizes=[(s, s) for s in sizes], append_images=imgs[:-1])
print("ok")
