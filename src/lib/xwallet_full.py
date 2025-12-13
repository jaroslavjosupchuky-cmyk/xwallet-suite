#!/usr/bin/env python3
# xwallet_full.py — All-in-one xWallet scanner (GUI + helper integration)
# Place in: /home/xx/wallet-installer/xwallet_full.py

from __future__ import annotations
import os
import re
import sys
import json
import threading
import subprocess
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Callable

# ---------- Heuristics & constants ----------

HOME = Path.home()
RESULTS_ROOT = HOME / "xwallet_scan_results"
EXPORT_ROOT = HOME / "xwallet_exported_masked"
RESULTS_ROOT.mkdir(parents=True, exist_ok=True)
EXPORT_ROOT.mkdir(parents=True, exist_ok=True)

MNEMONIC_RE = re.compile(r'\b([a-z]{3,})\b(?:\s+\b([a-z]{3,})\b){11,23}', re.IGNORECASE)
ETH_PRIV_RE = re.compile(r'0x[a-fA-F0-9]{64}')
HEX64_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')
WALLET_FILENAME_RE = re.compile(
    r'wallet|keystore|keystore-mnemonic|secret|seed|private[_ ]?key|keyfile',
    re.IGNORECASE,
)

def ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def ts_h() -> str:
    return datetime.now().strftime("%H:%M:%S")

def mask_text(s: str) -> str:
    if not s:
        return s
    s = ETH_PRIV_RE.sub("0x_PRIVKEY_MASKED", s)
    s = HEX64_RE.sub("HEX64_MASKED", s)
    s = MNEMONIC_RE.sub("MNEMONIC_MASKED", s)
    return s

def open_path(p: str) -> None:
    try:
        subprocess.Popen(["xdg-open", p])
    except Exception:
        pass

def get_linux_mounts() -> List[dict]:
    mounts = []
    try:
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0].startswith("/dev"):
                    mounts.append({"device": parts[0], "path": parts[1]})
    except Exception:
        # fallback: try psutil if available
        try:
            import psutil  # type: ignore
            for p in psutil.disk_partitions(all=False):
                mounts.append({"device": p.device, "path": p.mountpoint})
        except Exception:
            pass

    # dedupe by path
    out: List[dict] = []
    seen = set()
    for m in mounts:
        if m["path"] not in seen:
            out.append(m)
            seen.add(m["path"])
    return out

def ensure_result_dir(name: str) -> Path:
    safe = re.sub(r"[^0-9A-Za-z._-]+", "_", name)[:60]
    out = RESULTS_ROOT / f"{ts()}_{safe}"
    out.mkdir(parents=True, exist_ok=True)
    (out / "raw").mkdir(exist_ok=True)
    (out / "found").mkdir(exist_ok=True)
    return out

# ---------- SimpleScanner (non-GUI logic) ----------

class SimpleScanner:
    """
    Scans files and folders, plus can analyze text buffers.
    Logger: callable(str)
    """

    def __init__(self, outdir: Path, logger: Callable[[str], None] = print):
        self.outdir = Path(outdir)
        self.logger = logger
        self.stats = {
            "files_scanned": 0,
            "wallet_files": 0,
            "secrets_found": 0,
        }
        self.hits: List[dict] = []

    def log(self, msg: str) -> None:
        try:
            self.logger(f"[{ts_h()}] {msg}")
        except Exception:
            print(msg)

    def _scan_text_for_secrets(self, text: str, origin: str) -> None:
        found = False
        if MNEMONIC_RE.search(text):
            self.hits.append(
                {"type": "mnemonic", "origin": origin, "snippet": text[:200]}
            )
            self.stats["secrets_found"] += 1
            self.log(f"Mnemonic-like fragment in {origin}")
            found = True
        if ETH_PRIV_RE.search(text):
            self.hits.append(
                {"type": "eth_priv", "origin": origin, "snippet": text[:200]}
            )
            self.stats["secrets_found"] += 1
            self.log(f"Ethereum private-key-like fragment in {origin}")
            found = True
        if (not found) and HEX64_RE.search(text):
            self.hits.append(
                {"type": "hex64", "origin": origin, "snippet": text[:200]}
            )
            self.stats["secrets_found"] += 1
            self.log(f"Generic 64-hex fragment in {origin}")

    def scan_path(
        self,
        root: str,
        stop_event: Optional[threading.Event] = None,
        on_file: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        rootp = Path(root)
        if not rootp.exists():
            self.log(f"Path does not exist: {root}")
            return

        # Pre-count files for percentage
        total_files = 0
        for _dirpath, _dirnames, filenames in os.walk(root):
            total_files += len(filenames)
        if total_files == 0:
            total_files = 1

        self.log(f"Start file scan: {root} (approx {total_files} files)")
        scanned = 0

        for dirpath, dirnames, filenames in os.walk(root):
            if stop_event and stop_event.is_set():
                break
            for fn in filenames:
                if stop_event and stop_event.is_set():
                    break
                full = os.path.join(dirpath, fn)
                scanned += 1
                self.stats["files_scanned"] += 1

                # file-name heuristics
                if WALLET_FILENAME_RE.search(fn):
                    self.stats["wallet_files"] += 1
                    self.hits.append(
                        {"type": "wallet_file", "path": full, "hint": fn}
                    )
                    self.log(f"Wallet-like filename: {full}")

                # small text content scan
                try:
                    if os.path.getsize(full) <= 1024 * 1024:  # up to 1MB
                        with open(full, "r", encoding="utf-8", errors="ignore") as f:
                            txt = f.read()
                        self._scan_text_for_secrets(txt, origin=full)
                except Exception:
                    pass

                if on_file:
                    try:
                        on_file(scanned, total_files)
                    except Exception:
                        pass

        self.log("File scan finished")

    def scan_browsers(self, stop_event: Optional[threading.Event] = None) -> None:
        """
        Very simple browser folder scan — just collects interesting files.
        """
        candidates = [
            HOME / ".config" / "google-chrome" / "Default",
            HOME / ".config" / "chromium" / "Default",
            HOME / ".config" / "BraveSoftware" / "Brave-Browser" / "Default",
            HOME / ".mozilla" / "firefox",
        ]
        for base in candidates:
            if stop_event and stop_event.is_set():
                break
            if not base.exists():
                continue
            self.log(f"Inspecting browser folder: {base}")
            for p in base.rglob("*"):
                if stop_event and stop_event.is_set():
                    break
                if not p.is_file():
                    continue
                name_l = p.name.lower()
                if (
                    "wallet" in name_l
                    or "metamask" in name_l
                    or "keystore" in name_l
                    or "login data" in name_l
                    or "local state" in name_l
                ):
                    self.hits.append(
                        {"type": "browser_artifact", "path": str(p), "hint": name_l}
                    )
                    self.log(f"Browser artifact: {p}")

    def save_results(self) -> Path:
        """
        Saves hits & stats to outdir/found/results.ndjson and summary.json.
        Returns outdir path.
        """
        found_dir = self.outdir / "found"
        found_dir.mkdir(exist_ok=True)
        nd = found_dir / "results.ndjson"
        with nd.open("w", encoding="utf-8") as f:
            for h in self.hits:
                f.write(json.dumps(h, ensure_ascii=False) + "\n")
        meta = {
            "stats": self.stats,
            "created": datetime.now().isoformat(),
            "outdir": str(self.outdir),
        }
        with (found_dir / "summary.json").open("w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
        return self.outdir

# ---------- Qt GUI ----------

try:
    from PyQt5 import QtCore, QtGui, QtWidgets
    from PyQt5.QtWidgets import (
        QApplication,
        QMainWindow,
        QWidget,
        QListWidget,
        QPlainTextEdit,
        QProgressBar,
        QVBoxLayout,
        QHBoxLayout,
        QPushButton,
        QLabel,
        QMessageBox,
    )
except Exception:
    print("PyQt5 is required. Activate venv with PyQt5 or install system-wide.")
    raise

def qt_safe_append(box: QPlainTextEdit, text: str) -> None:
    def _a():
        box.appendPlainText(text)
        box.ensureCursorVisible()
    QtCore.QTimer.singleShot(0, _a)

def qt_safe_progress(bar: QProgressBar, value: int) -> None:
    def _a():
        bar.setValue(max(0, min(100, value)))
    QtCore.QTimer.singleShot(0, _a)

class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("xWallet Scanner (Full)")
        self.resize(1000, 650)

        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)

        # Top controls
        top = QHBoxLayout()
        root_layout.addLayout(top)

        self.refresh_btn = QPushButton("Refresh mounts")
        self.quick_btn = QPushButton("Quick scan selected path")
        self.auto_btn = QPushButton("One-click auto recovery")
        top.addWidget(self.refresh_btn)
        top.addWidget(self.quick_btn)
        top.addWidget(self.auto_btn)

        # Middle: mounts + log
        mid = QHBoxLayout()
        root_layout.addLayout(mid)

        left_v = QVBoxLayout()
        mid.addLayout(left_v, 1)
        left_v.addWidget(QLabel("Available mounts / paths:"))
        self.mounts_list = QListWidget()
        left_v.addWidget(self.mounts_list)

        right_v = QVBoxLayout()
        mid.addLayout(right_v, 2)
        right_v.addWidget(QLabel("Log / output"))
        self.log_box = QPlainTextEdit()
        self.log_box.setReadOnly(True)
        right_v.addWidget(self.log_box)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        right_v.addWidget(self.progress)

        # Bottom row
        bottom = QHBoxLayout()
        root_layout.addLayout(bottom)

        self.open_results_btn = QPushButton("Open results folder")
        self.pro_nvme_btn = QPushButton("Deep raw scan NVMe (helper)")
        self.pro_usb_btn = QPushButton("Deep raw scan USB (helper)")
        self.pro_full_btn = QPushButton("Full PRO auto recovery (helper)")
        bottom.addWidget(self.open_results_btn)
        bottom.addWidget(self.pro_nvme_btn)
        bottom.addWidget(self.pro_usb_btn)
        bottom.addWidget(self.pro_full_btn)

        # State
        self.scan_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()

        # Signals
        self.refresh_btn.clicked.connect(self.refresh_mounts)
        self.quick_btn.clicked.connect(self.start_quick_scan)
        self.auto_btn.clicked.connect(self.start_auto_recovery)
        self.open_results_btn.clicked.connect(self.open_results_folder)
        self.pro_nvme_btn.clicked.connect(lambda: self.run_helper_mode("nvme"))
        self.pro_usb_btn.clicked.connect(lambda: self.run_helper_mode("usb"))
        self.pro_full_btn.clicked.connect(lambda: self.run_helper_mode("full"))

        # Initial data
        self.refresh_mounts()

    # ----- logging -----
    def log(self, msg: str) -> None:
        qt_safe_append(self.log_box, f"[{ts_h()}] {msg}")
        print(msg)

    # ----- mounts -----
    def refresh_mounts(self) -> None:
        self.mounts_list.clear()
        mounts = get_linux_mounts()
        for m in mounts:
            self.mounts_list.addItem(f'{m["device"]}  →  {m["path"]}')
        self.mounts_list.addItem(f"HOME → {str(HOME)}")
        self.mounts_list.addItem(f"RESULTS → {str(RESULTS_ROOT)}")
        self.log("Devices refreshed")

    def _get_selected_path(self) -> Optional[str]:
        item = self.mounts_list.currentItem()
        if not item:
            return None
        text = item.text()
        if "→" in text:
            return text.split("→", 1)[1].strip()
        return text.strip()

    # ----- Quick scan -----
    def start_quick_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            QMessageBox.warning(self, "Scan", "Scan already running")
            return
        path = self._get_selected_path()
        if not path:
            QMessageBox.information(self, "Scan", "Select path to scan first")
            return
        self.stop_event.clear()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.log(f"Starting quick scan on: {path}")
        outdir = ensure_result_dir(Path(path).name or "scan")
        scanner = SimpleScanner(outdir=outdir, logger=self.log)

        def worker():
            def on_file(done: int, total: int) -> None:
                perc = int(done * 100 / max(1, total))
                qt_safe_progress(self.progress, perc)

            scanner.scan_path(path, stop_event=self.stop_event, on_file=on_file)
            scanner.scan_browsers(stop_event=self.stop_event)
            out = scanner.save_results()
            self.log(f"Quick scan finished. Results: {out}")
            qt_safe_progress(self.progress, 100)

        self.scan_thread = threading.Thread(target=worker, daemon=True)
        self.scan_thread.start()

    # ----- Auto recovery (GUI-only, non-root) -----
    def start_auto_recovery(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            QMessageBox.warning(self, "Scan", "Scan already running")
            return
        path = self._get_selected_path() or str(HOME)
        self.stop_event.clear()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.log(f"Starting AUTO recovery on: {path}")
        outdir = ensure_result_dir("auto")

        scanner = SimpleScanner(outdir=outdir, logger=self.log)

        def worker():
            def on_file(done: int, total: int) -> None:
                perc = int(done * 70 / max(1, total))  # 0–70% for FS
                qt_safe_progress(self.progress, perc)

            # Step 1: filesystem scan
            scanner.scan_path(path, stop_event=self.stop_event, on_file=on_file)

            # Step 2: browser artifacts (70–85%)
            self.log("AUTO: scanning browser artifacts")
            scanner.scan_browsers(stop_event=self.stop_event)
            qt_safe_progress(self.progress, 85)

            # TODO: RAM / VM / deleted files hooks (85–100%)
            self.log("AUTO: (placeholder) additional analysis steps")
            qt_safe_progress(self.progress, 95)

            out = scanner.save_results()
            self.log(f"AUTO recovery finished. Results: {out}")
            qt_safe_progress(self.progress, 100)

        self.scan_thread = threading.Thread(target=worker, daemon=True)
        self.scan_thread.start()

    # ----- Results / helper integration -----
    def open_results_folder(self) -> None:
        open_path(str(RESULTS_ROOT))

    def run_helper_mode(self, mode: str) -> None:
        """
        Runs root helper via pkexec and streams output into GUI log.
        Modes: nvme, usb, full
        """
        self.log(f"Starting PRO mode: {mode}")

        helper = "/usr/bin/xwallet-root-helper"
        if not os.path.exists(helper):
            QMessageBox.critical(self, "Error", f"Root helper not found:\n{helper}")
            return

        # Reset progress bar
        qt_safe_progress(self.progress, 0)

        # pkexec command
        cmd = [
            "pkexec",
            helper,
            f"--{mode}",
        ]

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        except Exception as e:
            self.log(f"Launch error: {e}")
            QMessageBox.critical(self, "Error", str(e))
            return

        # Thread to catch helper output
        def reader():
            for line in proc.stdout:
                line = line.rstrip()
                self.log(line)

                # Parse "Progress ...: XX%"
                if "Progress" in line and "%" in line:
                    try:
                        pct = int(line.split(":")[-1].replace("%", "").strip())
                        qt_safe_progress(self.progress, pct)
                    except:
                        pass

            proc.wait()
            qt_safe_progress(self.progress, 100)
            self.log("PRO scan complete")

            # Auto-open results directory
            QtCore.QTimer.singleShot(500, lambda: open_path(str(RESULTS_ROOT)))

        threading.Thread(target=reader, daemon=True).start()


# ---------- main ----------

def main(argv: List[str]) -> None:
    app = QApplication(argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main(sys.argv)
