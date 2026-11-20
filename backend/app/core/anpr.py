"""
anpr.py
-------
Automatic Number Plate Recognition for real footage.

Pipeline per vehicle crop
  1. Localise plate candidates three ways: OpenCV's plate Haar cascade,
     high-contrast rectangular contours with a plate-like aspect ratio, and
     the lower part of the vehicle as a last resort.
  2. Read each candidate with every available OCR engine:
       * EasyOCR, used only if its model files are already cached locally
         (it never downloads during a demo), and
       * Tesseract (always available), several binarisations, psm 7 and 8.
  3. Clean, positionally repair (state code = letters, last four = digits)
     and score each read. A read that matches the Indian HSRP / BH format
     scores far higher than one that does not.

OCR is slow next to detection (100 ms to 1 s), so `ANPRService` runs it on a
background thread with a bounded queue. The video pipeline submits a crop
and keeps going; the result is applied a few frames later. If the queue is
full the job is dropped and retried on a later frame.
"""

from __future__ import annotations

import logging
import os
import queue
import shutil
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

import cv2
import numpy as np

from app.config import ANPR_MODE
from app.core import plates as plate_utils

logger = logging.getLogger("ibvap.anpr")
LITE = ANPR_MODE == "lite"

try:
    import pytesseract
    _win_default = Path(r"C:\Program Files\Tesseract-OCR\tesseract.exe")
    if not shutil.which("tesseract") and _win_default.exists():
        pytesseract.pytesseract.tesseract_cmd = str(_win_default)
    _HAS_TESSERACT = bool(shutil.which("tesseract") or _win_default.exists())
except Exception:  # noqa: BLE001
    pytesseract = None  # type: ignore[assignment]
    _HAS_TESSERACT = False

_EASYOCR_DIR = Path(os.environ.get("EASYOCR_MODULE_PATH", Path.home() / ".EasyOCR")) / "model"
try:
    import importlib.util
    _HAS_EASYOCR = (importlib.util.find_spec("easyocr") is not None
                    and _EASYOCR_DIR.exists() and any(_EASYOCR_DIR.glob("*.pth")))
except Exception:  # noqa: BLE001
    _HAS_EASYOCR = False

_WHITELIST = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


@dataclass
class PlateRead:
    text: str
    confidence: float
    raw_ocr: str
    engine: str
    bbox: tuple = (0, 0, 0, 0)

    @property
    def format_valid(self) -> bool:
        return plate_utils.is_valid_format(self.text)


def engines() -> List[str]:
    out = []
    if _HAS_EASYOCR:
        out.append("EasyOCR")
    if _HAS_TESSERACT:
        out.append("Tesseract 5")
    return out


class PlateReader:
    def __init__(self):
        self.cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_russian_plate_number.xml")
        self._easy = None
        self._easy_failed = False

    # -- localisation ---------------------------------------------------
    def candidates(self, crop: np.ndarray) -> List[tuple]:
        h, w = crop.shape[:2]
        gray = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY)
        boxes: List[tuple] = []
        if not self.cascade.empty():
            for (x, y, bw, bh) in self.cascade.detectMultiScale(gray, 1.05, 3, minSize=(40, 12)):
                boxes.append((x, y, x + bw, y + bh))
        # bright rectangles with plate proportions (white/yellow HSRP plates)
        blur = cv2.bilateralFilter(gray, 7, 50, 50)
        edges = cv2.Canny(blur, 60, 180)
        edges = cv2.dilate(edges, np.ones((3, 3), np.uint8), iterations=1)
        cnts, _ = cv2.findContours(edges, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)
        for c in sorted(cnts, key=cv2.contourArea, reverse=True)[:40]:
            x, y, bw, bh = cv2.boundingRect(c)
            if bh < 10 or bw < 35:
                continue
            ar = bw / float(bh)
            if 1.8 <= ar <= 6.5 and bw < 0.9 * w and y > 0.25 * h:
                boxes.append((x, y, x + bw, y + bh))
        boxes.append((int(0.1 * w), int(0.55 * h), int(0.9 * w), h))  # lower body fallback
        out: List[tuple] = []
        for b in boxes:
            if all(_iou(b, o) < 0.6 for o in out):
                out.append(b)
        return out[:2] if LITE else out[:5]

    # -- OCR engines ----------------------------------------------------
    def _tesseract(self, plate: np.ndarray) -> List[tuple]:
        if not _HAS_TESSERACT:
            return []
        gray = cv2.cvtColor(plate, cv2.COLOR_BGR2GRAY) if plate.ndim == 3 else plate
        scale = max(1.0, 60.0 / max(1, gray.shape[0]))
        gray = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
        gray = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(4, 4)).apply(gray)
        _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        variants = [otsu] if LITE else [
            otsu, cv2.bitwise_not(otsu),
            cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 10)]
        reads = []
        for img in variants:
            img = cv2.copyMakeBorder(img, 10, 10, 10, 10, cv2.BORDER_CONSTANT, value=255)
            for psm in ((7,) if LITE else (7, 8)):
                try:
                    data = pytesseract.image_to_data(
                        img, config=f"--oem 3 --psm {psm} -c tessedit_char_whitelist={_WHITELIST}",
                        output_type=pytesseract.Output.DICT)
                except Exception:  # noqa: BLE001
                    return reads
                words = [(t, float(c)) for t, c in zip(data["text"], data["conf"]) if t.strip() and float(c) >= 0]
                if words:
                    text = "".join(t for t, _ in words)
                    conf = sum(c for _, c in words) / len(words) / 100.0
                    reads.append((text, conf, "Tesseract"))
        return reads

    def _easyocr(self, plate: np.ndarray) -> List[tuple]:
        if not _HAS_EASYOCR or self._easy_failed:
            return []
        if self._easy is None:
            try:
                import easyocr
                self._easy = easyocr.Reader(["en"], gpu=False, verbose=False,
                                            model_storage_directory=str(_EASYOCR_DIR), download_enabled=False)
            except Exception as e:  # noqa: BLE001
                logger.info("EasyOCR unavailable: %s", e)
                self._easy_failed = True
                return []
        try:
            res = self._easy.readtext(plate, allowlist=_WHITELIST, detail=1)
        except Exception:  # noqa: BLE001
            return []
        if not res:
            return []
        res = sorted(res, key=lambda r: min(p[0] for p in r[0]))
        text = "".join(r[1] for r in res)
        conf = sum(r[2] for r in res) / len(res)
        return [(text, conf, "EasyOCR")]

    # -- public ---------------------------------------------------------
    def read(self, crop: np.ndarray) -> Optional[PlateRead]:
        if crop is None or crop.size == 0 or crop.shape[0] < 20 or crop.shape[1] < 40:
            return None
        best: Optional[PlateRead] = None
        best_score = 0.0
        for (x1, y1, x2, y2) in self.candidates(crop):
            region = crop[max(0, y1):y2, max(0, x1):x2]
            if region.size == 0:
                continue
            for raw, conf, engine in self._easyocr(region) + self._tesseract(region):
                text = plate_utils.repair(plate_utils.clean(raw))
                if len(text) < 6 or len(text) > 11:
                    continue
                valid = plate_utils.is_valid_format(text)
                score = conf + (1.5 if valid else 0.0) + (0.2 if 9 <= len(text) <= 10 else 0.0)
                if score > best_score:
                    best_score = score
                    best = PlateRead(text, conf, raw, engine, (x1, y1, x2, y2))
            if best is not None and best.format_valid and best.confidence > 0.75:
                break
        return best


def _iou(a: tuple, b: tuple) -> float:
    ix1, iy1, ix2, iy2 = max(a[0], b[0]), max(a[1], b[1]), min(a[2], b[2]), min(a[3], b[3])
    inter = max(0, ix2 - ix1) * max(0, iy2 - iy1)
    if inter == 0:
        return 0.0
    area = (a[2] - a[0]) * (a[3] - a[1]) + (b[2] - b[0]) * (b[3] - b[1]) - inter
    return inter / max(1, area)


class ANPRService:
    """Single background OCR worker shared by every camera stream."""

    def __init__(self, maxsize: int = 24):
        self.reader = PlateReader()
        self._q: "queue.Queue[tuple]" = queue.Queue(maxsize=maxsize)
        self._thread: Optional[threading.Thread] = None
        self.processed = 0
        self.dropped = 0
        self.read_ok = 0

    def _ensure(self) -> None:
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(target=self._run, name="anpr-worker", daemon=True)
            self._thread.start()

    def submit(self, crop: np.ndarray, callback: Callable[[Optional[PlateRead]], None]) -> bool:
        if ANPR_MODE == "off":
            return False
        self._ensure()
        try:
            self._q.put_nowait((crop, callback))
            return True
        except queue.Full:
            self.dropped += 1
            return False

    def _run(self) -> None:
        while True:
            crop, cb = self._q.get()
            try:
                res = self.reader.read(crop)
                self.processed += 1
                if res is not None:
                    self.read_ok += 1
                cb(res)
            except Exception:  # noqa: BLE001
                logger.exception("ANPR job failed")

    def status(self) -> dict:
        return {"engines": engines(), "mode": ANPR_MODE, "queue": self._q.qsize(), "processed": self.processed,
                "reads": self.read_ok, "dropped": self.dropped}


anpr_service = ANPRService()
