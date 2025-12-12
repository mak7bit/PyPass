#!/usr/bin/env python3
"""
PyPass - GUI wordlist lookup and analyzer (PyQt6)
UI tweak: larger logo and creator credit placed next to the title.
"""

import sys
import os
import time
import json
import hashlib
from pathlib import Path
from typing import Optional
import re

# optional libraries - disabled by default to avoid import errors
psutil = None

try:
    from passlib.hash import sha256_crypt, sha512_crypt  # type: ignore
    PASSLIB_AVAILABLE = True
except Exception:
    PASSLIB_AVAILABLE = False

try:
    import bcrypt  # type: ignore
except Exception:
    bcrypt = None

try:
    import argon2  # type: ignore
    from argon2 import PasswordHasher as Argon2Hasher  # type: ignore
except Exception:
    argon2 = None
    Argon2Hasher = None

# PyQt6
try:
    from PyQt6.QtWidgets import (
        QApplication, QWidget, QLabel, QLineEdit, QPushButton, QFileDialog,
        QVBoxLayout, QHBoxLayout, QRadioButton, QButtonGroup, QMessageBox,
        QGroupBox, QListWidget, QListWidgetItem, QFrame, QMenu, QSplitter,
        QSpinBox, QCheckBox, QSizePolicy
    )
    from PyQt6.QtGui import QIcon, QAction, QPixmap, QDesktopServices
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QUrl
except Exception as e:
    print("ERROR: Failed to import PyQt6 modules.")
    print("Cause:", repr(e))
    print("Install with:\n    python -m pip install PyQt6")
    sys.exit(1)

APP_NAME = "PyPass"
HOME = Path.home()
APP_DIR = HOME / ".pypass"
APP_DIR.mkdir(exist_ok=True)
HISTORY_PATH = APP_DIR / "history.json"
RECENT_PATH = APP_DIR / "recent.json"
RESOURCES_DIR = Path(__file__).parent / "resources"

MAX_RESULTS = 200
MAX_HISTORY = 200
MAX_RECENT = 10

DEFAULT_MAX_ATTEMPTS = 1000
DEFAULT_JOB_TIMEOUT = 300
SUGGEST_STREAM_SIZE = 200 * 1024 * 1024  # 200 MB

# atomic write helpers
def atomic_write_json(path: Path, obj):
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)
    except Exception:
        try:
            if tmp.exists():
                tmp.unlink()
        except Exception:
            pass

def load_json(path: Path):
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return []

def save_json(path: Path, obj):
    atomic_write_json(path, obj)

# icon loader preference
def load_app_icon() -> Optional[QIcon]:
    if sys.platform.startswith("win"):
        candidates = ["icon.ico", "icon.png", "icon.svg"]
    else:
        candidates = ["icon.svg", "icon.png", "icon.ico"]
    for name in candidates:
        p = RESOURCES_DIR / name
        if p.exists():
            try:
                return QIcon(str(p))
            except Exception:
                continue
    return None

# Stats worker
class StatsWorker(QThread):
    finished = pyqtSignal(dict)
    def __init__(self, path: str):
        super().__init__()
        self.path = path
    def run(self):
        p = Path(self.path)
        stats = {"size_bytes": None, "lines": None, "mtime": None, "encoding": None, "read_time": None}
        try:
            stats["size_bytes"] = p.stat().st_size
            stats["mtime"] = p.stat().st_mtime
            start = time.time()
            count = 0
            with open(p, "rb") as f:
                for _ in f:
                    count += 1
            stats["lines"] = count
            stats["encoding"] = "utf-8"
            stats["read_time"] = time.time() - start
        except Exception as e:
            stats["error"] = str(e)
        self.finished.emit(stats)

# Search worker
class SearchWorker(QThread):
    finished = pyqtSignal(bool, dict)
    def __init__(self, wordlist_path: str, target: str, mode: Optional[str],
                 ignore_case: bool, stream_mode: bool,
                 slow_kdf_enabled: bool, slow_max_attempts: int, job_timeout: int, lower_priority: bool):
        super().__init__()
        self.wordlist_path = wordlist_path
        self.target = target
        self.mode = mode
        self.ignore_case = ignore_case
        self.stream_mode = stream_mode
        self._running = True
        self.slow_kdf_enabled = slow_kdf_enabled
        self.slow_max_attempts = slow_max_attempts
        self.job_timeout = job_timeout
        self.lower_priority = lower_priority

    def stop(self):
        self._running = False

    @staticmethod
    def _hash_candidate(candidate: str, algo: str) -> str:
        b = candidate.encode("utf-8", errors="ignore")
        if algo == "md5":
            return hashlib.md5(b).hexdigest()
        if algo == "sha1":
            return hashlib.sha1(b).hexdigest()
        if algo == "sha256":
            return hashlib.sha256(b).hexdigest()
        if algo == "sha384":
            return hashlib.sha384(b).hexdigest()
        if algo == "sha512":
            return hashlib.sha512(b).hexdigest()
        if algo == "sha3_256":
            return hashlib.sha3_256(b).hexdigest()
        if algo == "sha3_512":
            return hashlib.sha3_512(b).hexdigest()
        if algo == "ntlm":
            try:
                md4 = hashlib.new("md4", candidate.encode("utf-16-le"))
                return md4.hexdigest()
            except Exception:
                raise
        raise ValueError("unsupported hash type")

    def _apply_slow_verifier(self, candidate: str, mode: str, target_hash: str) -> bool:
        if mode == "bcrypt":
            if bcrypt is None:
                raise RuntimeError("bcrypt missing (pip install bcrypt)")
            try:
                return bcrypt.checkpw(candidate.encode("utf-8"), target_hash.encode("utf-8"))
            except Exception:
                return False
        if mode == "argon2":
            if Argon2Hasher is None:
                raise RuntimeError("argon2 missing (pip install argon2-cffi)")
            try:
                ph = Argon2Hasher()
                return ph.verify(target_hash, candidate)
            except Exception:
                return False
        if mode == "pbkdf2":
            if not PASSLIB_AVAILABLE:
                raise RuntimeError("passlib required for pbkdf2")
            try:
                from passlib.handlers.pbkdf2 import pbkdf2_sha256  # type: ignore
                return pbkdf2_sha256.verify(candidate, target_hash)
            except Exception:
                return False
        if mode in ("sha256_crypt", "sha512_crypt"):
            if not PASSLIB_AVAILABLE:
                raise RuntimeError("passlib required for unix-crypt")
            try:
                if mode == "sha256_crypt":
                    return sha256_crypt.verify(candidate, target_hash)
                if mode == "sha512_crypt":
                    return sha512_crypt.verify(candidate, target_hash)
            except Exception:
                return False
        return False

    def run(self):
        if self.lower_priority:
            try:
                if os.name == "posix":
                    try:
                        os.nice(10)
                    except Exception:
                        pass
                else:
                    # psutil disabled in this build; skip Windows priority change
                    pass
            except Exception:
                pass

        start = time.time()
        info = {"time": 0.0, "matches": [], "total_found": 0, "stopped_by_limit": False, "stopped_by_timeout": False}
        found = False
        path = Path(self.wordlist_path)
        deadline = start + self.job_timeout if self.job_timeout and self.job_timeout > 0 else None

        if self.mode is None:
            t = self.target.strip()
            if t.startswith("$2") or t.startswith("$2a$") or t.startswith("$2b$"):
                self.mode = "bcrypt"
            elif t.startswith("$argon2"):
                self.mode = "argon2"
            elif "$6$" in t:
                self.mode = "sha512_crypt"
            elif "$5$" in t:
                self.mode = "sha256_crypt"
            elif "pbkdf2" in t.lower():
                self.mode = "pbkdf2"

        try:
            fast_hashes = {"md5","sha1","sha256","sha384","sha512","sha3_256","sha3_512","ntlm"}
            slow_hashes = {"bcrypt","argon2","pbkdf2","sha256_crypt","sha512_crypt"}

            mode = self.mode

            if mode is None or mode == "plain":
                target_plain = self.target
                if self.ignore_case:
                    target_plain = target_plain.lower()
                if not self.stream_mode:
                    lines = []
                    with open(path, "r", errors="ignore") as f:
                        for line in f:
                            if not self._running:
                                break
                            lines.append(line.rstrip("\n\r"))
                    for lineno, cand in enumerate(lines, start=1):
                        if not self._running:
                            break
                        cmp_ = cand.lower() if self.ignore_case else cand
                        if target_plain in cmp_:
                            info["matches"].append({"line": lineno, "candidate": cand})
                            info["total_found"] += 1
                            if len(info["matches"]) >= MAX_RESULTS:
                                info["stopped_by_limit"] = True
                                break
                        if deadline and time.time() > deadline:
                            info["stopped_by_timeout"] = True
                            break
                else:
                    with open(path, "r", errors="ignore") as f:
                        for lineno, line in enumerate(f, start=1):
                            if not self._running:
                                break
                            cand = line.rstrip("\n\r")
                            cmp_ = cand.lower() if self.ignore_case else cand
                            if target_plain in cmp_:
                                info["total_found"] += 1
                                if len(info["matches"]) < MAX_RESULTS:
                                    info["matches"].append({"line": lineno, "candidate": cand})
                                else:
                                    info["stopped_by_limit"] = True
                            if deadline and time.time() > deadline:
                                info["stopped_by_timeout"] = True
                                break

            elif mode in fast_hashes:
                if not self.stream_mode:
                    lines = []
                    with open(path, "r", errors="ignore") as f:
                        for line in f:
                            if not self._running:
                                break
                            lines.append(line.rstrip("\n\r"))
                    for lineno, cand in enumerate(lines, start=1):
                        if not self._running:
                            break
                        try:
                            h = self._hash_candidate(cand, mode)
                        except Exception:
                            continue
                        if h.lower() == self.target.strip().lower():
                            info["matches"].append({"line": lineno, "candidate": cand})
                            info["total_found"] += 1
                            if len(info["matches"]) >= MAX_RESULTS:
                                info["stopped_by_limit"] = True
                                break
                        if deadline and time.time() > deadline:
                            info["stopped_by_timeout"] = True
                            break
                else:
                    with open(path, "r", errors="ignore") as f:
                        for lineno, line in enumerate(f, start=1):
                            if not self._running:
                                break
                            cand = line.rstrip("\n\r")
                            try:
                                h = self._hash_candidate(cand, mode)
                            except Exception:
                                continue
                            if h.lower() == self.target.strip().lower():
                                info["total_found"] += 1
                                if len(info["matches"]) < MAX_RESULTS:
                                    info["matches"].append({"line": lineno, "candidate": cand})
                                else:
                                    info["stopped_by_limit"] = True
                            if deadline and time.time() > deadline:
                                info["stopped_by_timeout"] = True
                                break

            elif mode in slow_hashes:
                if not self.slow_kdf_enabled:
                    info["error"] = "Slow KDF verification is disabled. Enable it to proceed."
                else:
                    attempts = 0
                    if not self.stream_mode:
                        lines = []
                        with open(path, "r", errors="ignore") as f:
                            for line in f:
                                if not self._running:
                                    break
                                lines.append(line.rstrip("\n\r"))
                        for lineno, cand in enumerate(lines, start=1):
                            if not self._running:
                                break
                            attempts += 1
                            try:
                                ok = self._apply_slow_verifier(cand, mode, self.target)
                            except RuntimeError as ex:
                                info["error"] = str(ex); ok = False
                            if ok:
                                info["matches"].append({"line": lineno, "candidate": cand})
                                info["total_found"] += 1
                            if attempts >= self.slow_max_attempts:
                                info["stopped_by_limit"] = True; break
                            if deadline and time.time() > deadline:
                                info["stopped_by_timeout"] = True; break
                    else:
                        with open(path, "r", errors="ignore") as f:
                            for lineno, line in enumerate(f, start=1):
                                if not self._running:
                                    break
                                cand = line.rstrip("\n\r")
                                attempts += 1
                                try:
                                    ok = self._apply_slow_verifier(cand, mode, self.target)
                                except RuntimeError as ex:
                                    info["error"] = str(ex); ok = False
                                if ok:
                                    info["total_found"] += 1
                                    if len(info["matches"]) < MAX_RESULTS:
                                        info["matches"].append({"line": lineno, "candidate": cand})
                                if attempts >= self.slow_max_attempts:
                                    info["stopped_by_limit"] = True; break
                                if deadline and time.time() > deadline:
                                    info["stopped_by_timeout"] = True; break
            else:
                target_plain = self.target
                if self.ignore_case:
                    target_plain = target_plain.lower()
                if not self.stream_mode:
                    lines = []
                    with open(path, "r", errors="ignore") as f:
                        for line in f:
                            if not self._running:
                                break
                            lines.append(line.rstrip("\n\r"))
                    for lineno, cand in enumerate(lines, start=1):
                        if not self._running:
                            break
                        cmp_ = cand.lower() if self.ignore_case else cand
                        if target_plain in cmp_:
                            info["matches"].append({"line": lineno, "candidate": cand})
                            info["total_found"] += 1
                            if len(info["matches"]) >= MAX_RESULTS:
                                info["stopped_by_limit"] = True; break
                        if deadline and time.time() > deadline:
                            info["stopped_by_timeout"] = True; break
                else:
                    with open(path, "r", errors="ignore") as f:
                        for lineno, line in enumerate(f, start=1):
                            if not self._running:
                                break
                            cand = line.rstrip("\n\r")
                            cmp_ = cand.lower() if self.ignore_case else cand
                            if target_plain in cmp_:
                                info["total_found"] += 1
                                if len(info["matches"]) < MAX_RESULTS:
                                    info["matches"].append({"line": lineno, "candidate": cand})
                                else:
                                    info["stopped_by_limit"] = True
                            if deadline and time.time() > deadline:
                                info["stopped_by_timeout"] = True; break

            found = info["total_found"] > 0
        except Exception as e:
            info["error"] = str(e)

        info["time"] = time.time() - start
        self.finished.emit(found, info)

# Main window
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PyPass Suite")
        icon = load_app_icon()
        if icon:
            try:
                self.setWindowIcon(icon)
            except Exception:
                pass
        try:
            if os.name == "posix" and os.geteuid() == 0:
                QMessageBox.warning(self, "Security", "Running PyPass as root is not recommended.")
        except Exception:
            pass

        self.resize(980, 600)
        self.wordlist_path: Optional[str] = None
        self._search_worker: Optional[SearchWorker] = None
        self._stats_worker: Optional[StatsWorker] = None

        # config
        self.config = {"slow_kdf_confirmed": False, "slow_kdf_enabled": False,
                       "slow_max_attempts": DEFAULT_MAX_ATTEMPTS,
                       "job_timeout": DEFAULT_JOB_TIMEOUT, "lower_priority": True}
        self._load_config()

        self._build_ui()
        self._load_history()
        self._load_recent()

    def _config_path(self):
        return APP_DIR / "config.json"

    def _load_config(self):
        p = self._config_path()
        try:
            if p.exists():
                self.config.update(json.loads(p.read_text(encoding="utf-8")))
        except Exception:
            pass

    def _save_config(self):
        p = self._config_path()
        atomic_write_json(p, self.config)

    def _build_ui(self):
        top_h = QHBoxLayout()

        # larger icon
        icon_label = QLabel()
        pix = None
        for ext in ("icon.svg", "icon.png", "icon.ico"):
            p = RESOURCES_DIR / ext
            if p.exists():
                try:
                    px = QPixmap(str(p))
                    if not px.isNull():
                        # scale larger
                        pix = px.scaled(80, 80, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                        break
                except Exception:
                    continue
        if pix:
            icon_label.setPixmap(pix)
        top_h.addWidget(icon_label)
        top_h.addSpacing(8)

        # title + credit next to each other
        title_credit_h = QHBoxLayout()
        title = QLabel(f"<b>{APP_NAME}</b>")
        title.setStyleSheet("font-size:30px;")
        title_credit_h.addWidget(title)

        # subtle creator credit placed next to title
        credit = QLabel("<i>- mak7bit</i>")
        credit.setStyleSheet("font-size:20px; color: #808080; font-weight: bold; font-style: italic; margin-left:0px; margin-top:10px")
        credit.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        title_credit_h.addWidget(credit)
        title_credit_h.addStretch()
        top_h.addLayout(title_credit_h)
        top_h.addStretch()


        disclaimer = QLabel(
        "This tool is made for educational use and authorized security testing only.\n"
        "Unauthorized password or hash cracking is illegal and strictly prohibited.\n"
        "Use this tool responsibly and respect the privacy and security of others.")
        disclaimer.setStyleSheet("font-size:13px; color: #808080; margin-left:10px;")
        disclaimer.setContentsMargins(200, 10, 10, 10)
        disclaimer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_credit_h.addWidget(disclaimer)

        # Identify hash button on the right
        id_btn = QPushButton("Identify hash")
        id_btn.setToolTip("Open hash identifier on hashes.com")
        id_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://hashes.com/en/tools/hash_identifier")))
        top_h.addWidget(id_btn)

        left_v = QVBoxLayout()
        wl_box = QGroupBox("Wordlist")
        wl_layout = QHBoxLayout()
        self.wl_label = QLabel("No file selected")
        self.wl_label.setFrameStyle(QFrame.Shape.Panel.value | QFrame.Shadow.Sunken.value)
        self.btn_select = QPushButton("Select .txt")
        self.btn_select.clicked.connect(self._select_wordlist)
        wl_layout.addWidget(self.wl_label, 1)
        wl_layout.addWidget(self.btn_select)
        wl_box.setLayout(wl_layout)
        left_v.addWidget(wl_box)

        stats_box = QGroupBox("Wordlist stats")
        stats_layout = QVBoxLayout()
        self.stats_text = QLabel("No file selected")
        self.stats_text.setWordWrap(True)
        stats_layout.addWidget(self.stats_text)
        stats_box.setLayout(stats_layout)
        left_v.addWidget(stats_box)

        recent_box = QGroupBox("Recent wordlists")
        recent_layout = QVBoxLayout()
        self.recent_list = QListWidget()
        self.recent_list.itemClicked.connect(self._on_recent_click)
        recent_layout.addWidget(self.recent_list)
        recent_box.setLayout(recent_layout)
        left_v.addWidget(recent_box)

        input_box = QGroupBox("Password / Hash")
        input_layout = QVBoxLayout()
        self.input_field = QLineEdit()
        self.input_field.setEchoMode(QLineEdit.EchoMode.Normal)
        self.input_field.setPlaceholderText("Enter password (search) or full hash string")
        self.input_field.returnPressed.connect(self.on_check)
        input_layout.addWidget(self.input_field)

        filters_h = QHBoxLayout()
        self.rb_contains = QRadioButton("Contains"); self.rb_contains.setChecked(True)
        self.rb_starts = QRadioButton("Starts with")
        self.rb_ends = QRadioButton("Ends with")
        self.rb_exact = QRadioButton("Exact")
        self.rb_regex = QRadioButton("Regex")
        self.filter_group = QButtonGroup()
        for idx, rb in enumerate([self.rb_contains, self.rb_starts, self.rb_ends, self.rb_exact, self.rb_regex]):
            self.filter_group.addButton(rb, id=idx)
            filters_h.addWidget(rb)
        input_layout.addLayout(filters_h)

        opts_h = QHBoxLayout()
        self.cb_case = QPushButton("Case-insensitive"); self.cb_case.setCheckable(True)
        self.cb_stream = QPushButton("Stream mode (low mem)"); self.cb_stream.setCheckable(True)
        opts_h.addWidget(self.cb_case); opts_h.addWidget(self.cb_stream)
        input_layout.addLayout(opts_h)

        # hash radios (no default selection)
        hash_box = QGroupBox("Hash type (optional)")
        hash_layout = QHBoxLayout()
        self.hash_group = QButtonGroup()
        self.rb_plain = QRadioButton("Plaintext")
        self.rb_md5 = QRadioButton("md5")
        self.rb_sha1 = QRadioButton("sha1")
        self.rb_sha256 = QRadioButton("sha256")
        self.rb_sha384 = QRadioButton("sha384")
        self.rb_sha512 = QRadioButton("sha512")
        self.rb_sha3_256 = QRadioButton("sha3-256")
        self.rb_sha3_512 = QRadioButton("sha3-512")
        self.rb_ntlm = QRadioButton("NTLM")
        self.rb_bcrypt = QRadioButton("bcrypt")
        self.rb_argon2 = QRadioButton("argon2")
        self.rb_scrypt = QRadioButton("scrypt")
        self.rb_pbkdf2 = QRadioButton("pbkdf2")
        radios = [self.rb_plain, self.rb_md5, self.rb_sha1, self.rb_sha256, self.rb_sha384, self.rb_sha512,
                  self.rb_sha3_256, self.rb_sha3_512, self.rb_ntlm, self.rb_bcrypt, self.rb_argon2, self.rb_scrypt, self.rb_pbkdf2]
        for i, r in enumerate(radios):
            self.hash_group.addButton(r, id=i)
            hash_layout.addWidget(r)
        hash_box.setLayout(hash_layout)
        input_layout.addWidget(hash_box)

        slow_box = QGroupBox("Slow KDFs (opt-in)")
        slow_layout = QHBoxLayout()
        self.cb_enable_slow = QCheckBox("Enable slow KDF verification")
        self.cb_enable_slow.setChecked(self.config.get("slow_kdf_enabled", False))
        self.cb_enable_slow.stateChanged.connect(self._on_toggle_slow_kdf)
        slow_layout.addWidget(self.cb_enable_slow)
        slow_layout.addWidget(QLabel("Max attempts:"))
        self.spin_max_attempts = QSpinBox(); self.spin_max_attempts.setRange(1, 10_000_000)
        self.spin_max_attempts.setValue(self.config.get("slow_max_attempts", DEFAULT_MAX_ATTEMPTS))
        slow_layout.addWidget(self.spin_max_attempts)
        slow_layout.addWidget(QLabel("Timeout(s):"))
        self.spin_timeout = QSpinBox(); self.spin_timeout.setRange(1, 86400)
        self.spin_timeout.setValue(self.config.get("job_timeout", DEFAULT_JOB_TIMEOUT))
        slow_layout.addWidget(self.spin_timeout)
        slow_box.setLayout(slow_layout)
        input_layout.addWidget(slow_box)

        input_box.setLayout(input_layout)
        left_v.addWidget(input_box)

        # actions
        btns_h = QHBoxLayout()
        self.btn_check = QPushButton("Check"); self.btn_check.clicked.connect(self.on_check)
        self.btn_cancel = QPushButton("Cancel"); self.btn_cancel.clicked.connect(self._on_cancel); self.btn_cancel.setEnabled(False)
        self.btn_clear = QPushButton("Clear"); self.btn_clear.clicked.connect(self.on_clear)
        self.btn_export = QPushButton("Export matches"); self.btn_export.clicked.connect(self._export_matches)
        btns_h.addWidget(self.btn_check); btns_h.addWidget(self.btn_cancel); btns_h.addWidget(self.btn_clear); btns_h.addWidget(self.btn_export)
        left_v.addLayout(btns_h)
        left_v.addStretch()

        # right: results bigger, history extended (bookmarks removed)
        right_v = QVBoxLayout()
        self.result_label = QLabel("No check performed"); self.result_label.setAlignment(Qt.AlignmentFlag.AlignCenter); self.result_label.setFixedHeight(36)
        right_v.addWidget(self.result_label)
        self.matches_list = QListWidget(); right_v.addWidget(self.matches_list, 2)
        self.matches_info = QLabel(""); self.matches_info.setWordWrap(True); right_v.addWidget(self.matches_info)

        # lower: expanded history (clear button present)
        lower_split = QSplitter(Qt.Orientation.Horizontal)
        hist_widget = QWidget(); hist_layout = QVBoxLayout(); hist_widget.setLayout(hist_layout)
        top_hist_row = QHBoxLayout()
        top_hist_row.addWidget(QLabel("History (click to repopulate)"))
        top_hist_row.addStretch()
        self.btn_clear_history = QPushButton("Clear history"); self.btn_clear_history.clicked.connect(self._on_clear_history_clicked)
        top_hist_row.addWidget(self.btn_clear_history)
        hist_layout.addLayout(top_hist_row)
        self.history_list = QListWidget()
        self.history_list.itemClicked.connect(self._on_history_click)
        self.history_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.history_list.customContextMenuRequested.connect(self._history_context_menu)
        hist_layout.addWidget(self.history_list)
        lower_split.addWidget(hist_widget)
        # keep the other side minimal (empty) so results remains dominant
        filler = QWidget(); lower_split.addWidget(filler)
        right_v.addWidget(lower_split, 1)

        main_h = QHBoxLayout(); main_h.addLayout(left_v, 1); main_h.addLayout(right_v, 2)
        root_v = QVBoxLayout(); root_v.addLayout(top_h); root_v.addSpacing(8); root_v.addLayout(main_h)
        self.setLayout(root_v)

        # shortcuts
        quit_action = QAction(self); quit_action.setShortcut("Ctrl+Q"); quit_action.triggered.connect(self.close); self.addAction(quit_action)
        open_action = QAction(self); open_action.setShortcut("Ctrl+O"); open_action.triggered.connect(self._select_wordlist); self.addAction(open_action)

        # minimal stylesheet so OS theme applies; tweak credit color via palette rule
        self.setStyleSheet("""
            QWidget { font-family: Segoe UI, Noto Sans, Arial; }
            QListWidget { background: palette(base); }
            QLabel { color: palette(text); }
        """)

    # wordlist selection
    def _select_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select wordlist (.txt)", str(HOME), "Text files (*.txt)")
        if not path: return
        if not path.lower().endswith(".txt"):
            QMessageBox.warning(self, "Invalid file", "Only .txt files are supported.")
            return
        self._set_wordlist(path)

    def _set_wordlist(self, path: str):
        self.wordlist_path = path
        self.wl_label.setText(os.path.basename(path))
        self._add_recent(path)
        self.stats_text.setText("Computing stats...")
        if self._stats_worker and self._stats_worker.isRunning():
            try: self._stats_worker.terminate()
            except Exception: pass
        self._stats_worker = StatsWorker(path)
        self._stats_worker.finished.connect(self._on_stats_finished)
        self._stats_worker.start()
        try:
            size = Path(path).stat().st_size
            if size >= SUGGEST_STREAM_SIZE:
                self.cb_stream.setChecked(True)
                QMessageBox.information(self, "Large wordlist", "This file is large. Stream mode has been suggested and enabled to avoid high memory usage.")
        except Exception:
            pass

    def _on_stats_finished(self, stats: dict):
        if "error" in stats:
            self.stats_text.setText(f"Error reading file: {stats['error']}"); return
        size = stats.get("size_bytes",0); lines = stats.get("lines",0); mtime = stats.get("mtime"); enc = stats.get("encoding","unknown"); rt = stats.get("read_time",0.0)
        mtime_s = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime)) if mtime else "?"
        self.stats_text.setText(f"Size: {size:,} bytes\nLines: {lines:,}\nEncoding guess: {enc}\nLast modified: {mtime_s}\nStats read time: {rt:.2f}s")

    # recent
    def _add_recent(self, path: str):
        arr = load_json(RECENT_PATH)
        arr = [x for x in arr if x != path]
        arr.insert(0, path); arr = arr[:MAX_RECENT]; save_json(RECENT_PATH, arr); self._load_recent()

    def _load_recent(self):
        self.recent_list.clear()
        arr = load_json(RECENT_PATH)
        for p in arr:
            item = QListWidgetItem(os.path.basename(p)); item.setData(Qt.ItemDataRole.UserRole, p); self.recent_list.addItem(item)

    def _on_recent_click(self, item: QListWidgetItem):
        p = item.data(Qt.ItemDataRole.UserRole)
        if p: self._set_wordlist(p)

    # determine selected hash mode
    def _get_selected_hash_mode(self) -> Optional[str]:
        radios = [self.rb_plain, self.rb_md5, self.rb_sha1, self.rb_sha256, self.rb_sha384, self.rb_sha512,
                  self.rb_sha3_256, self.rb_sha3_512, self.rb_ntlm, self.rb_bcrypt, self.rb_argon2, self.rb_scrypt, self.rb_pbkdf2]
        modes = [None, "md5","sha1","sha256","sha384","sha512","sha3_256","sha3_512","ntlm","bcrypt","argon2","scrypt","pbkdf2"]
        for r,m in zip(radios, modes):
            if r.isChecked(): return m
        return None

    def on_check(self):
        if not self.wordlist_path:
            QMessageBox.warning(self, "No wordlist", "Please select a .txt wordlist first."); return
        target = self.input_field.text().strip()
        if not target:
            QMessageBox.warning(self, "No input", "Enter a password or hash to check."); return

        hash_mode = self._get_selected_hash_mode()
        ignore_case = self.cb_case.isChecked()
        stream_mode = self.cb_stream.isChecked()
        slow_enabled = self.cb_enable_slow.isChecked()
        slow_max = int(self.spin_max_attempts.value())
        timeout = int(self.spin_timeout.value())
        lower_priority = self.config.get("lower_priority", True)

        if slow_enabled and not self.config.get("slow_kdf_confirmed", False):
            if not self._confirm_slow_kdf():
                self.cb_enable_slow.setChecked(False); slow_enabled = False
            else:
                self.config["slow_kdf_confirmed"] = True; self.config["slow_kdf_enabled"] = True; self._save_config()

        self._set_ui_enabled(False); self.btn_cancel.setEnabled(True); self.result_label.setText("Searching..."); self.matches_list.clear(); self.matches_info.setText("")

        if self._search_worker and self._search_worker.isRunning():
            try: self._search_worker.stop()
            except Exception: pass

        self._search_worker = SearchWorker(
            wordlist_path=self.wordlist_path, target=target, mode=hash_mode,
            ignore_case=ignore_case, stream_mode=stream_mode,
            slow_kdf_enabled=slow_enabled, slow_max_attempts=slow_max,
            job_timeout=timeout, lower_priority=lower_priority
        )
        self._search_worker.finished.connect(self._on_search_finished)
        self._search_worker.start()

    def _on_search_finished(self, found: bool, info: dict):
        self._set_ui_enabled(True); self.btn_cancel.setEnabled(False)
        if "error" in info:
            self.result_label.setText("ERROR"); self.matches_info.setText(f"Error: {info['error']}"); return

        matches = info.get("matches", []); total = info.get("total_found",0)
        self.matches_list.clear()
        if matches:
            self.result_label.setText("FOUND")
            for m in matches:
                li = QListWidgetItem(f"{m['line']}: {m['candidate']}"); li.setData(Qt.ItemDataRole.UserRole, m); self.matches_list.addItem(li)
            if total > len(matches):
                self.matches_info.setText(f"Showing {len(matches)} of {total} matches (truncated). Time: {info.get('time',0):.3f}s")
            else:
                self.matches_info.setText(f"Matches: {total}. Time: {info.get('time',0):.3f}s")
        else:
            self.result_label.setText("NOT FOUND"); self.matches_info.setText(f"Matches: 0. Time: {info.get('time',0):.3f}s")

        # save history
        try:
            arr = load_json(HISTORY_PATH); arr.insert(0, {"target": self.input_field.text(), "found": bool(matches), "time": info.get("time",0.0), "ts": time.time()})
            arr = arr[:MAX_HISTORY]; save_json(HISTORY_PATH, arr); self._load_history()
        except Exception:
            pass

    def _on_cancel(self):
        if self._search_worker and self._search_worker.isRunning():
            self._search_worker.stop(); self._set_ui_enabled(True); self.btn_cancel.setEnabled(False); self.result_label.setText("Cancelled"); self.matches_info.setText("Search cancelled by user.")

    def _export_matches(self):
        if self.matches_list.count() == 0:
            QMessageBox.information(self, "Export", "No matches to export."); return
        path, filt = QFileDialog.getSaveFileName(self, "Export matches", str(HOME / "matches.txt"), "Text files (*.txt);;CSV files (*.csv)")
        if not path: return
        try:
            ext = Path(path).suffix.lower()
            with open(path, "w", encoding="utf-8") as fh:
                if ext == ".csv":
                    fh.write("line,match\n")
                    for i in range(self.matches_list.count()):
                        item = self.matches_list.item(i); m = item.data(Qt.ItemDataRole.UserRole)
                        if m: fh.write(f"{m['line']},{m['candidate'].replace(',','')}\n")
                        else: fh.write(item.text()+"\n")
                else:
                    for i in range(self.matches_list.count()):
                        item = self.matches_list.item(i); m = item.data(Qt.ItemDataRole.UserRole)
                        if m: fh.write(f"{m['line']}: {m['candidate']}\n")
                        else: fh.write(item.text()+"\n")
            QMessageBox.information(self, "Export", f"Saved {self.matches_list.count()} matches to:\n{path}")
        except Exception as e:
            QMessageBox.warning(self, "Export error", f"Failed to export: {e}")

    # history functions
    def _load_history(self):
        self.history_list.clear()
        arr = load_json(HISTORY_PATH)
        for e in arr:
            t = e.get("target",""); found = e.get("found",False); tm = e.get("time",0.0); ts = e.get("ts",0)
            timestr = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else ""
            txt = f"{timestr} | {t} — {'FOUND' if found else 'NOT'} ({tm:.3f}s)"
            li = QListWidgetItem(txt); li.setData(Qt.ItemDataRole.UserRole, e); self.history_list.addItem(li)

    def _on_history_click(self, item: QListWidgetItem):
        e = item.data(Qt.ItemDataRole.UserRole)
        if not e: return
        self.input_field.setText(e.get("target","")); self.on_check()

    def _history_context_menu(self, pos):
        menu = QMenu(self)
        clear_act = menu.addAction("Clear history")
        export_act = menu.addAction("Export history")
        action = menu.exec(self.history_list.mapToGlobal(pos))
        if action == clear_act:
            self._on_clear_history_clicked()
        elif action == export_act:
            self._export_history()

    def _on_clear_history_clicked(self):
        resp = QMessageBox.question(self, "Clear history", "Are you sure you want to permanently clear the search history?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if resp != QMessageBox.StandardButton.Yes: return
        try:
            if HISTORY_PATH.exists(): HISTORY_PATH.unlink()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to clear history: {e}"); return
        self._load_history()

    def _export_history(self):
        arr = load_json(HISTORY_PATH)
        if not arr:
            QMessageBox.information(self, "Export history", "No history to export."); return
        path, _ = QFileDialog.getSaveFileName(self, "Export history", str(HOME / "pypass_history.txt"), "Text files (*.txt);;CSV files (*.csv)")
        if not path: return
        try:
            ext = Path(path).suffix.lower()
            with open(path, "w", encoding="utf-8") as fh:
                if ext == ".csv":
                    fh.write("timestamp,target,found,time\n")
                    for e in arr:
                        ts = e.get("ts",0); t = e.get("target",""); fnd = e.get("found",False); tm = e.get("time",0.0)
                        fh.write(f"{ts},{t.replace(',','')},{int(fnd)},{tm:.3f}\n")
                else:
                    for e in arr:
                        ts = e.get("ts",0); t = e.get("target",""); fnd = e.get("found",False); tm = e.get("time",0.0)
                        fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))} | {t} — {'FOUND' if fnd else 'NOT'} ({tm:.3f}s)\n")
            QMessageBox.information(self, "Export history", f"Exported {len(arr)} entries to:\n{path}")
        except Exception as e:
            QMessageBox.warning(self, "Export history", f"Failed: {e}")

    def _set_ui_enabled(self, enabled: bool):
        self.btn_select.setEnabled(enabled); self.input_field.setEnabled(enabled)
        self.btn_check.setEnabled(enabled); self.btn_clear.setEnabled(enabled); self.btn_export.setEnabled(enabled)
        self.btn_cancel.setEnabled(not enabled)
        self.cb_case.setEnabled(enabled); self.cb_stream.setEnabled(enabled)
        self.spin_max_attempts.setEnabled(enabled); self.spin_timeout.setEnabled(enabled)
        for r in [self.rb_plain, self.rb_md5, self.rb_sha1, self.rb_sha256, self.rb_sha384, self.rb_sha512,
                  self.rb_sha3_256, self.rb_sha3_512, self.rb_ntlm, self.rb_bcrypt, self.rb_argon2, self.rb_scrypt, self.rb_pbkdf2]:
            r.setEnabled(enabled)
        self.cb_enable_slow.setEnabled(enabled)
        self.btn_clear_history.setEnabled(enabled)

    def _confirm_slow_kdf(self) -> bool:
        dlg = QMessageBox(self); dlg.setWindowTitle("Enable slow KDFs"); dlg.setIcon(QMessageBox.Icon.Warning)
        dlg.setText("Enabling slow KDF verification can heavily load your CPU and take a long time.\nDefault max attempts: {}\nDefault timeout: {}s\nProceed?".format(self.spin_max_attempts.value(), self.spin_timeout.value()))
        dlg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        res = dlg.exec(); return res == QMessageBox.StandardButton.Yes

    def _on_toggle_slow_kdf(self, state):
        enabled = state == Qt.CheckState.Checked
        if enabled and not self.config.get("slow_kdf_confirmed", False):
            if not self._confirm_slow_kdf():
                self.cb_enable_slow.setChecked(False); return
            self.config["slow_kdf_confirmed"] = True
        self.config["slow_kdf_enabled"] = enabled
        self.config["slow_max_attempts"] = self.spin_max_attempts.value()
        self.config["job_timeout"] = self.spin_timeout.value()
        self._save_config()

    def on_clear(self):
        """Clear input and results, reset result label."""
        self.input_field.clear()
        self.matches_list.clear()
        self.matches_info.setText("")
        self.result_label.setText("No check performed")

# entry
def main():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
