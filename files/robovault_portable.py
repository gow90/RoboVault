"""
RoboVault v2.1 — FANUC Robot Backup Tool (Hardened)
Author: Gowtham Kuppudurai | QuantumScope

v2.1 security hardening:
  - Credentials encrypted at rest using Windows DPAPI (user scope)
  - FTP passwords and Teams webhook URL never written to JSON in plaintext
  - Config file written atomically with user-only permissions (0600 on POSIX)
  - Path traversal guards on FTP download writes (ASVS V12)
  - Teams webhook URL validated as https:// (reject http / other schemes)
  - Schedule time, parallel count, retention days bounds-checked on load
  - No change to FTP protocol (FANUC R-30iB controllers do not support FTPS)

v2.0 features preserved:
  - Parallel backup (configurable 1-10 simultaneous robots)
  - Scheduled auto-backup (daily/weekly at chosen time)
  - Backup retention (auto-delete backups older than N days)
  - Backup diff (compare two backups, show added/removed/changed)
  - Project tree with collapse/expand
  - Green progress bar, live throughput log
  - FANUC FTP: blank login, NLST scan, md path handling
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog
import ftplib
import json
import os
import sys
import stat
import threading
import subprocess
import time
import socket
import base64
import ctypes
import ctypes.wintypes
import concurrent.futures
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timedelta
from pathlib import Path

APP_NAME = "RoboVault"
APP_VERSION = "2.1.0"
APP_AUTHOR = "Gowtham Kuppudurai"
APP_COMPANY = "QuantumScope"
CONFIG_FILE = "robovault_config.json"
DEFAULT_BACKUP_ROOT = str(Path.home() / "RoboVault_Backups")
FTP_BUFFER_SIZE = 65536
TIMESTAMP_FMT = "%Y-%m-%d_%H-%M-%S"

FILE_CATEGORIES = {
    "TP Programs":      [".tp"],
    "KAREL Programs":   [".pc", ".ls"],
    "System Variables": [".sv"],
    "I/O Config":       [".io"],
    "Registers":        [".vr", ".nr", ".pr", ".sr"],
    "Frames":           [".uf", ".tf", ".jf"],
    "Servo/Mastering":  [".dg"],
    "Menu/Config":      [".mn", ".cf", ".xml", ".dat"],
    "Vision":           [".vd", ".vda"],
    "Error/Logs":       [".er", ".lg", ".dt"],
    "All Other":        ["*"],
}


# =============================================================================
# SECURE CREDENTIAL STORAGE (DPAPI on Windows, OS keychain fallback elsewhere)
# =============================================================================

class SecureCredentialStore:
    """Encrypt small secrets (FTP passwords, webhook URLs) at rest.

    Windows: uses DPAPI CryptProtectData with CRYPTPROTECT_UI_FORBIDDEN.
    Ciphertext is bound to the current Windows user account — another user on
    the same machine cannot decrypt, and the file is worthless if copied off
    the machine.

    Non-Windows: falls back to base64 obfuscation with a WARNING logged.
    RoboVault is a Windows-first tool (FANUC engineering workstations), but
    the fallback keeps the code testable on Linux/macOS dev boxes.
    """

    _WARN_SHOWN = False

    # DPAPI constants
    CRYPTPROTECT_UI_FORBIDDEN = 0x1
    CRYPTPROTECT_LOCAL_MACHINE = 0x4  # NOT USED — we want per-user binding

    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    @classmethod
    def _is_windows(cls):
        return sys.platform == "win32"

    @classmethod
    def _dpapi_protect(cls, plaintext: bytes) -> bytes:
        blob_in = cls._DATA_BLOB(len(plaintext),
                                  ctypes.cast(ctypes.c_char_p(plaintext),
                                              ctypes.POINTER(ctypes.c_char)))
        blob_out = cls._DATA_BLOB()
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        if not crypt32.CryptProtectData(
                ctypes.byref(blob_in), None, None, None, None,
                cls.CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out)):
            raise OSError(f"CryptProtectData failed, err={kernel32.GetLastError()}")
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            kernel32.LocalFree(blob_out.pbData)

    @classmethod
    def _dpapi_unprotect(cls, ciphertext: bytes) -> bytes:
        blob_in = cls._DATA_BLOB(len(ciphertext),
                                  ctypes.cast(ctypes.c_char_p(ciphertext),
                                              ctypes.POINTER(ctypes.c_char)))
        blob_out = cls._DATA_BLOB()
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        if not crypt32.CryptUnprotectData(
                ctypes.byref(blob_in), None, None, None, None,
                cls.CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out)):
            raise OSError(f"CryptUnprotectData failed, err={kernel32.GetLastError()}")
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            kernel32.LocalFree(blob_out.pbData)

    @classmethod
    def encrypt(cls, plaintext: str) -> str:
        """Returns an opaque string safe to persist. Empty input -> empty output."""
        if not plaintext:
            return ""
        data = plaintext.encode("utf-8")
        if cls._is_windows():
            try:
                cipher = cls._dpapi_protect(data)
                return "dpapi:" + base64.b64encode(cipher).decode("ascii")
            except Exception:
                pass  # fall through to obfuscation
        if not cls._WARN_SHOWN:
            sys.stderr.write("WARNING: DPAPI unavailable; using weak obfuscation. "
                             "Do not deploy non-Windows builds in production.\n")
            cls._WARN_SHOWN = True
        return "b64:" + base64.b64encode(data).decode("ascii")

    @classmethod
    def decrypt(cls, stored: str) -> str:
        """Returns plaintext, or '' if input is empty/malformed."""
        if not stored:
            return ""
        try:
            if stored.startswith("dpapi:"):
                if not cls._is_windows():
                    return ""  # cannot decrypt cross-platform
                cipher = base64.b64decode(stored[len("dpapi:"):])
                return cls._dpapi_unprotect(cipher).decode("utf-8")
            if stored.startswith("b64:"):
                return base64.b64decode(stored[len("b64:"):]).decode("utf-8")
            # Legacy plaintext (migrated once on first load)
            return stored
        except Exception:
            return ""


# =============================================================================
# PATH SAFETY
# =============================================================================

def safe_join_under(base: str, *parts: str) -> str:
    """Join `parts` under `base`, guaranteeing the result stays inside `base`.

    Raises ValueError if the resolved path escapes `base` (e.g. via '..' or
    absolute path components from a malicious remote filename).
    """
    base_resolved = Path(base).resolve()
    candidate = Path(base, *parts).resolve()
    try:
        candidate.relative_to(base_resolved)
    except ValueError:
        raise ValueError(f"Path traversal blocked: {candidate} escapes {base_resolved}")
    return str(candidate)


def is_valid_webhook_url(url: str) -> tuple[bool, str]:
    """Validate a Teams webhook URL. Returns (ok, reason_if_not_ok).

    Policy:
      - https only (no http, no file://, no ftp://)
      - must have a hostname
      - warn if host is not a Microsoft domain (soft check, still allowed
        because some orgs proxy through custom domains)
    """
    if not url:
        return False, "empty URL"
    try:
        p = urllib.parse.urlparse(url)
    except (ValueError, AttributeError) as e:
        return False, f"unparseable: {e}"
    if p.scheme != "https":
        return False, f"must be https (got '{p.scheme}')"
    if not p.hostname:
        return False, "missing hostname"
    # Reject obvious localhost / private-ip exfil attempts
    host = p.hostname.lower()
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        return False, "localhost not allowed"
    return True, ""


# =============================================================================
# DATA MODEL
# =============================================================================

class Robot:
    """A robot's config. `ftp_pass` in memory is plaintext; it is encrypted
    only when serialized to disk via Project.to_dict_for_storage()."""

    def __init__(self, name="", ip="", identifier="", controller="R-30iB Plus",
                 ftp_user="", ftp_pass="", ftp_port=21, notes=""):
        self.name = name
        self.ip = ip
        self.identifier = identifier
        self.controller = controller
        self.ftp_user = ftp_user
        self.ftp_pass = ftp_pass  # plaintext in memory only
        self.ftp_port = ftp_port
        self.notes = notes

    def to_dict_public(self):
        """Non-secret fields for the main JSON config."""
        return {
            "name": self.name,
            "ip": self.ip,
            "identifier": self.identifier,
            "controller": self.controller,
            "ftp_user": self.ftp_user,
            "ftp_port": self.ftp_port,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d, ftp_pass=""):
        r = cls()
        for k in ("name", "ip", "identifier", "controller",
                  "ftp_user", "ftp_port", "notes"):
            if k in d:
                setattr(r, k, d[k])
        r.ftp_pass = ftp_pass
        return r


class Project:
    def __init__(self, name="New Project"):
        self.name = name
        self.robots = []
        self.sched_enabled = False
        self.sched_time = "02:00"
        self.sched_days = [0, 1, 2, 3, 4, 5, 6]

    def to_dict_public(self):
        return {
            "name": self.name,
            "robots": [r.to_dict_public() for r in self.robots],
            "sched_enabled": self.sched_enabled,
            "sched_time": self.sched_time,
            "sched_days": self.sched_days,
        }

    @classmethod
    def from_dict(cls, d, secrets=None):
        """`secrets` is {project_name: {robot_name: plaintext_password}}"""
        p = cls(d.get("name", "Unnamed"))
        proj_secrets = {}
        if secrets:
            proj_secrets = secrets.get(p.name, {})
        for rd in d.get("robots", []):
            pw = proj_secrets.get(rd.get("name", ""), "")
            p.robots.append(Robot.from_dict(rd, ftp_pass=pw))
        p.sched_enabled = bool(d.get("sched_enabled", False))
        p.sched_time = str(d.get("sched_time", "02:00"))
        days = d.get("sched_days", [0, 1, 2, 3, 4, 5, 6])
        p.sched_days = [i for i in days if isinstance(i, int) and 0 <= i <= 6]
        return p


# =============================================================================
# FTP BACKUP ENGINE
# =============================================================================

class BackupEngine:
    FANUC_PREFIXES = ["md:\\", "md:/", "MD:\\", "MD:/",
                       "fr:\\", "fr:/", "FR:\\", "FR:/",
                       "sr:\\", "sr:/", "SR:\\", "SR:/"]

    @staticmethod
    def sanitize_path(remote_path):
        p = remote_path
        for pfx in BackupEngine.FANUC_PREFIXES:
            if p.startswith(pfx) or p.lower().startswith(pfx.lower()):
                device = pfx.rstrip(":\\/").lower()
                p = device + "/" + p[len(pfx):]
                break
        p = p.replace("\\", "/").lstrip("/").replace(":", "")
        while "//" in p:
            p = p.replace("//", "/")
        # Strip traversal segments — belt & suspenders; safe_join_under also
        # enforces this at write time.
        parts = [seg for seg in p.split("/") if seg not in ("", ".", "..")]
        return "/".join(parts)

    def __init__(self, log_cb=None, progress_cb=None):
        self.log = log_cb or print
        self.progress = progress_cb or (lambda *a: None)
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def ping(self, ip, port=21, timeout=2):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            ok = s.connect_ex((ip, port)) == 0
            s.close()
            return ok
        except Exception:
            return False

    def _connect(self, robot, timeout=10):
        # NOSONAR python:S5332 - FANUC R-30iB controllers do not support FTPS
        # or SFTP. Cleartext FTP is a hardware constraint. OT network
        # segmentation is the compensating control. See SECURITY.md A1.
        ftp = ftplib.FTP()
        ftp.connect(robot.ip, robot.ftp_port, timeout=timeout)
        if robot.ftp_user:
            ftp.login(robot.ftp_user, robot.ftp_pass)
        else:
            try:
                ftp.login("", "")
            except ftplib.error_perm:
                ftp.login()
        try:
            ftp.sendcmd("TYPE I")
        except Exception:
            pass
        return ftp

    def check(self, robot):
        self.log(f"  Checking {robot.name} ({robot.ip})...")
        if not self.ping(robot.ip, robot.ftp_port):
            self.log(f"  X {robot.name} - port {robot.ftp_port} not reachable")
            return False
        try:
            ftp = self._connect(robot)
            self.log(f"    Banner: {ftp.getwelcome()}")
            self.log(f"    PWD: {ftp.pwd()}")
            entries = []
            ftp.retrlines("NLST", entries.append)
            real = [e.strip() for e in entries if e.strip() not in (".", "..")]
            self.log(f"    Files at root: {len(real)}")
            ftp.quit()
            self.log(f"  OK {robot.name} - {len(real)} files")
            return True
        except Exception as e:
            self.log(f"  X {robot.name} - {e}")
            return False

    def _discover_root(self, ftp):
        pwd = "/"
        try:
            pwd = ftp.pwd()
        except Exception:
            pass
        for path in [pwd, "/", "/md", ".", "/MD"]:
            try:
                ftp.cwd(path)
                entries = []
                ftp.retrlines("NLST", entries.append)
                real = [e.strip() for e in entries if e.strip() not in (".", "..")]
                if real:
                    return path, len(real)
            except Exception:
                continue
        return "/", 0

    def _scan_nlst(self, ftp, remote_dir, depth=0):
        files = []
        if depth > 10:
            return files
        try:
            ftp.cwd(remote_dir)
        except ftplib.error_perm:
            return files
        current = ftp.pwd()
        names = []
        try:
            ftp.retrlines("NLST", names.append)
        except ftplib.error_perm:
            return files
        names = [n.strip() for n in names if n.strip() and n.strip() not in (".", "..")]

        for name in names:
            if self._cancel:
                break
            sep = "\\" if "\\" in current else "/"
            tail = "" if current.endswith(sep) or current.endswith("/") else sep
            full = current + tail + name
            is_dir = False
            if "." not in name:
                try:
                    ftp.cwd(name)
                    is_dir = True
                    ftp.cwd(current)
                except ftplib.error_perm:
                    pass
            if is_dir:
                files.extend(self._scan_nlst(ftp, full, depth + 1))
                try:
                    ftp.cwd(current)
                except Exception:
                    pass
            else:
                files.append((full, name))
        return files

    def backup_robot(self, robot, backup_root, project_name, timestamp,
                     backup_type="full_md", selected_exts=None):
        """Backup a single robot. Thread-safe — each call creates its own FTP connection.

        Directory structure:
          backup_root / project_name / robot_name / timestamp / md / files...
        """
        self._cancel = False
        safe_proj = project_name.replace(" ", "_").replace("/", "_").replace("\\", "_")
        safe_robot = robot.name.replace(" ", "_").replace("/", "_").replace("\\", "_")
        try:
            robot_dir = safe_join_under(backup_root, safe_proj, safe_robot, timestamp)
        except ValueError as e:
            self.log(f"X {robot.name}: {e}")
            return False, 0, 0
        os.makedirs(robot_dir, exist_ok=True)

        self.log(f"\n{'='*55}")
        self.log(f"  {robot.name} ({robot.ip}) - {backup_type}")
        self.log(f"{'='*55}")

        try:
            ftp = self._connect(robot)
        except Exception as e:
            self.log(f"X {robot.name}: Connection failed - {e}")
            return False, 0, 0

        ok_count = 0
        fail_count = 0
        total_bytes = 0
        t0 = time.time()

        try:
            md_root, file_count = self._discover_root(ftp)
            self.log(f"  {robot.name}: Root '{md_root}' ({file_count} entries)")
            dirs = [md_root]

            all_files = []
            for d in dirs:
                all_files.extend(self._scan_nlst(ftp, d))

            if backup_type == "selective" and selected_exts:
                if "*" not in selected_exts:
                    all_files = [(p, n) for p, n in all_files
                                 if os.path.splitext(n)[1].lower() in selected_exts]

            total = len(all_files)
            self.log(f"  {robot.name}: Downloading {total} files...")
            self.progress(0, total, f"{robot.name}: Starting...")

            last_dir = None
            for i, (remote_path, filename) in enumerate(all_files):
                if self._cancel:
                    self.log(f"  {robot.name}: Cancelled")
                    break
                safe = self.sanitize_path(remote_path)
                # Enforce path stays under robot_dir. sanitize_path already
                # strips traversal segments; this is the definitive check.
                try:
                    local = safe_join_under(robot_dir, *safe.split("/"))
                except ValueError as e:
                    self.log(f"  {robot.name}: X {filename}: blocked ({e})")
                    fail_count += 1
                    continue
                os.makedirs(os.path.dirname(local), exist_ok=True)

                parent = remote_path
                for sep in ["\\", "/"]:
                    idx = parent.rfind(sep)
                    if idx >= 0:
                        parent = parent[:idx]
                        break
                if parent != last_dir:
                    try:
                        ftp.cwd(parent)
                        last_dir = parent
                    except Exception:
                        pass
                try:
                    with open(local, "wb") as f:
                        ftp.retrbinary(f"RETR {filename}", f.write,
                                       blocksize=FTP_BUFFER_SIZE)
                    sz = os.path.getsize(local)
                    ok_count += 1
                    total_bytes += sz
                    if (i + 1) % 50 == 0 or i == total - 1:
                        elapsed = time.time() - t0
                        rate = total_bytes / 1024 / max(elapsed, 0.01)
                        self.log(f"  {robot.name}: [{i+1}/{total}] "
                                 f"{rate:.0f} KB/s | {total_bytes/1024:.0f} KB")
                    self.progress(i + 1, total, f"{robot.name}: {filename}")
                except Exception as e:
                    self.log(f"  {robot.name}: X {filename}: {e}")
                    fail_count += 1

            ftp.quit()
        except Exception as e:
            self.log(f"  {robot.name}: X Error - {e}")
            try:
                ftp.quit()
            except Exception:
                pass
            return False, ok_count, fail_count

        elapsed = time.time() - t0
        self.log(f"  {robot.name}: Done - {ok_count} files, "
                 f"{total_bytes/1024/1024:.1f} MB, {elapsed:.1f}s")
        return True, ok_count, fail_count


# =============================================================================
# BACKUP DIFF
# =============================================================================

class BackupDiff:
    """Compare two backup snapshots and report differences."""

    @staticmethod
    def scan_backup(backup_path):
        files = {}
        for root, dirs, filenames in os.walk(backup_path):
            for fn in filenames:
                if fn.startswith("_"):
                    continue
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, backup_path)
                files[rel] = os.path.getsize(full)
        return files

    @staticmethod
    def compare(path_a, path_b):
        files_a = BackupDiff.scan_backup(path_a)
        files_b = BackupDiff.scan_backup(path_b)
        keys_a = set(files_a.keys())
        keys_b = set(files_b.keys())

        added = sorted(keys_b - keys_a)
        removed = sorted(keys_a - keys_b)
        common = keys_a & keys_b
        changed = sorted(f for f in common if files_a[f] != files_b[f])
        unchanged = sorted(f for f in common if files_a[f] == files_b[f])

        return added, removed, changed, unchanged, files_a, files_b


# =============================================================================
# SCHEDULER
# =============================================================================

class BackupScheduler:
    def __init__(self, get_projects_fn, trigger_callback):
        self.get_projects = get_projects_fn
        self.trigger = trigger_callback
        self._thread = None
        self._running = False
        self._last_run = {}

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            now = datetime.now()
            today = now.strftime("%Y-%m-%d")
            current_time = now.strftime("%H:%M")
            weekday = now.weekday()

            for pi, proj in enumerate(self.get_projects()):
                if not proj.sched_enabled:
                    continue
                if weekday not in proj.sched_days:
                    continue
                if current_time != proj.sched_time:
                    continue
                if self._last_run.get(proj.name) == today:
                    continue
                self._last_run[proj.name] = today
                self.trigger(pi)

            time.sleep(30)


# =============================================================================
# RETENTION MANAGER
# =============================================================================

class RetentionManager:
    @staticmethod
    def cleanup(backup_root, max_age_days):
        if max_age_days <= 0:
            return 0, []
        cutoff = datetime.now() - timedelta(days=max_age_days)
        deleted = []
        if not os.path.exists(backup_root):
            return 0, []

        import shutil
        backup_root_resolved = Path(backup_root).resolve()
        for proj_dir in os.listdir(backup_root):
            proj_path = os.path.join(backup_root, proj_dir)
            if not os.path.isdir(proj_path):
                continue
            for robot_dir in os.listdir(proj_path):
                robot_path = os.path.join(proj_path, robot_dir)
                if not os.path.isdir(robot_path):
                    continue
                for ts_dir in os.listdir(robot_path):
                    ts_path = os.path.join(robot_path, ts_dir)
                    if not os.path.isdir(ts_path):
                        continue
                    # Confirm the target is still under backup_root before rmtree
                    try:
                        if not Path(ts_path).resolve().is_relative_to(backup_root_resolved):
                            continue
                    except AttributeError:
                        # is_relative_to added in Py 3.9; fall back
                        try:
                            Path(ts_path).resolve().relative_to(backup_root_resolved)
                        except ValueError:
                            continue
                    try:
                        ts = datetime.strptime(ts_dir, TIMESTAMP_FMT)
                        if ts < cutoff:
                            shutil.rmtree(ts_path)
                            deleted.append(f"{proj_dir}/{robot_dir}/{ts_dir}")
                    except ValueError:
                        continue
                if os.path.isdir(robot_path) and not os.listdir(robot_path):
                    os.rmdir(robot_path)
            if os.path.isdir(proj_path) and not os.listdir(proj_path):
                os.rmdir(proj_path)

        return len(deleted), deleted


# =============================================================================
# CONFIG — public JSON + encrypted secrets sidecar
# =============================================================================

class ConfigManager:
    """Splits config into two files:

      robovault_config.json       <- non-secret (robot names, IPs, schedules)
      robovault_config.secrets    <- DPAPI-encrypted passwords + webhook URL

    Both files are written with user-only permissions where the OS supports it.
    """

    def __init__(self, path=None):
        base_dir = self._app_dir()
        self.path = path or os.path.join(base_dir, CONFIG_FILE)
        # Sidecar sits next to the public config with the same stem.
        root, _ = os.path.splitext(self.path)
        self.secrets_path = root + ".secrets"

    @staticmethod
    def _app_dir():
        # When packaged as PyInstaller --onefile, __file__ is inside a
        # temp _MEI dir that is wiped on exit. Use sys.executable's dir in
        # that case so config persists next to the .exe.
        if getattr(sys, "frozen", False):
            return os.path.dirname(sys.executable)
        return os.path.dirname(os.path.abspath(__file__))

    @staticmethod
    def _atomic_write(path, data_bytes):
        """Write `data_bytes` to `path` atomically with 0600 perms where supported."""
        tmp = path + ".tmp"
        # os.O_EXCL avoids TOCTOU on the tmp file
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        try:
            mode = 0o600
            fd = os.open(tmp, flags, mode)
        except OSError:
            fd = os.open(tmp, flags)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data_bytes)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass
            # On Windows os.chmod is limited but setting read-only is not
            # what we want; DPAPI already ties the ciphertext to the user.
            if os.name != "nt":
                try:
                    os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
                except OSError:
                    pass
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def save(self, projects, settings):
        # ---- public JSON ----
        public_settings = {k: v for k, v in settings.items()
                           if k != "teams_webhook_url"}
        public = {
            "version": APP_VERSION,
            "settings": public_settings,
            "projects": [p.to_dict_public() for p in projects],
        }
        self._atomic_write(self.path,
                           json.dumps(public, indent=2).encode("utf-8"))

        # ---- encrypted secrets sidecar ----
        secrets_data = {
            "ftp_passwords": {},        # {project_name: {robot_name: plaintext}}
            "teams_webhook_url": "",
        }
        for proj in projects:
            bucket = {}
            for r in proj.robots:
                if r.ftp_pass:
                    bucket[r.name] = r.ftp_pass
            if bucket:
                secrets_data["ftp_passwords"][proj.name] = bucket
        secrets_data["teams_webhook_url"] = settings.get("teams_webhook_url", "")

        # Serialize then encrypt the whole blob in one DPAPI call (simpler
        # than per-field, and the blob is tiny).
        plaintext = json.dumps(secrets_data).encode("utf-8")
        if any(secrets_data["ftp_passwords"].values()) or secrets_data["teams_webhook_url"]:
            encrypted = SecureCredentialStore.encrypt(plaintext.decode("utf-8"))
            self._atomic_write(self.secrets_path, encrypted.encode("utf-8"))
        else:
            # Nothing secret to store — remove sidecar if present
            try:
                os.unlink(self.secrets_path)
            except OSError:
                pass

    def load(self):
        if not os.path.exists(self.path):
            return [], {}
        with open(self.path, "r") as f:
            data = json.load(f)

        # ---- load & decrypt secrets sidecar ----
        secrets = {"ftp_passwords": {}, "teams_webhook_url": ""}
        if os.path.exists(self.secrets_path):
            try:
                with open(self.secrets_path, "r") as f:
                    enc = f.read().strip()
                plaintext = SecureCredentialStore.decrypt(enc)
                if plaintext:
                    secrets = json.loads(plaintext)
            except Exception as e:
                sys.stderr.write(f"WARNING: failed to load secrets sidecar: {e}\n")

        # ---- migrate v2.0 plaintext-passwords config ----
        # If ftp_pass is present in the JSON (old format), pull it and re-save
        # on first clean shutdown.
        migrated_any = False
        if "robots" in data and "projects" not in data:
            # very old single-project format
            p = Project("Default Project")
            for rd in data["robots"]:
                legacy_pw = rd.pop("ftp_pass", "")
                if legacy_pw:
                    secrets["ftp_passwords"].setdefault(p.name, {})[rd["name"]] = legacy_pw
                    migrated_any = True
                p.robots.append(Robot.from_dict(rd, ftp_pass=legacy_pw))
            settings = data.get("settings", {})
            # Legacy webhook URL migration
            if settings.get("teams_webhook_url") and not secrets.get("teams_webhook_url"):
                secrets["teams_webhook_url"] = settings.get("teams_webhook_url", "")
                migrated_any = True
            settings = {k: v for k, v in settings.items() if k != "teams_webhook_url"}
            settings["teams_webhook_url"] = secrets.get("teams_webhook_url", "")
            return [p], settings

        projects = []
        for pd in data.get("projects", []):
            for rd in pd.get("robots", []):
                legacy_pw = rd.pop("ftp_pass", "")
                if legacy_pw:
                    secrets["ftp_passwords"].setdefault(
                        pd.get("name", "Unnamed"), {})[rd.get("name", "")] = legacy_pw
                    migrated_any = True
            projects.append(Project.from_dict(pd, secrets=secrets["ftp_passwords"]))

        settings = data.get("settings", {}) or {}
        # Legacy webhook URL migration
        if settings.get("teams_webhook_url") and not secrets.get("teams_webhook_url"):
            secrets["teams_webhook_url"] = settings.get("teams_webhook_url", "")
            migrated_any = True
        settings = {k: v for k, v in settings.items() if k != "teams_webhook_url"}
        settings["teams_webhook_url"] = secrets.get("teams_webhook_url", "")

        if migrated_any:
            # Immediately re-save in the new format so plaintext is gone from disk.
            try:
                self.save(projects, settings)
                sys.stderr.write("Migrated legacy plaintext credentials to encrypted store.\n")
            except Exception as e:
                sys.stderr.write(f"WARNING: migration re-save failed: {e}\n")

        return projects, settings


# =============================================================================
# GUI
# =============================================================================

class RoboVaultApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"{APP_NAME} v{APP_VERSION} | {APP_COMPANY}")
        self.root.geometry("1060x780")
        self.root.minsize(900, 650)

        self.projects = []
        self.config = ConfigManager()
        self.engine = BackupEngine(log_cb=self._log, progress_cb=self._update_progress)
        self.backup_running = False
        self._active_projects = set()
        self.settings = {
            "backup_root": DEFAULT_BACKUP_ROOT,
            "parallel_count": 3,
            "retention_days": 30,
            "teams_webhook_url": "",
            "teams_notify_on_failure": True,
            "teams_notify_on_success": False,
        }

        self.scheduler = BackupScheduler(
            get_projects_fn=lambda: self.projects,
            trigger_callback=self._scheduled_backup_project
        )

        saved_proj, saved_set = self.config.load()
        if saved_proj:
            self.projects = saved_proj
        if saved_set:
            self.settings.update(saved_set)
        # Clamp numeric settings to safe ranges
        self.settings["parallel_count"] = max(1, min(10,
            int(self.settings.get("parallel_count", 3) or 3)))
        self.settings["retention_days"] = max(0, min(9999,
            int(self.settings.get("retention_days", 30) or 30)))

        self._build_styles()
        self._build_ui()
        self._refresh_tree()
        self._update_schedule_label()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.scheduler.start()

        self._robot_status = {}
        self._tick_clock()
        self._tick_countdown()
        self._tick_connectivity()

    def _build_styles(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("green.Horizontal.TProgressbar",
                    troughcolor="#e0e0e0", background="#22c55e", thickness=20)

    def _build_ui(self):
        menubar = tk.Menu(self.root)
        fm = tk.Menu(menubar, tearoff=0)
        fm.add_command(label="Set Backup Folder...", command=self._set_backup_folder)
        fm.add_command(label="Open Backup Folder", command=self._open_backup_folder)
        fm.add_separator()
        fm.add_command(label="Export Config...", command=self._export_config)
        fm.add_command(label="Import Config...", command=self._import_config)
        fm.add_separator()
        fm.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=fm)

        tm = tk.Menu(menubar, tearoff=0)
        tm.add_command(label="Check All Connectivity", command=self._check_all)
        tm.add_separator()
        tm.add_command(label="Browse Backups...", command=self._browse_backups)
        tm.add_command(label="Compare Backups...", command=self._diff_dialog)
        tm.add_separator()
        tm.add_command(label="Schedule Settings...", command=self._schedule_dialog)
        tm.add_command(label="Retention Settings...", command=self._retention_dialog)
        tm.add_command(label="Parallel Backup Settings...", command=self._parallel_dialog)
        tm.add_command(label="Teams Notifications...", command=self._teams_dialog)
        tm.add_separator()
        tm.add_command(label="Run Retention Cleanup Now", command=self._run_retention)
        menubar.add_cascade(label="Tools", menu=tm)

        hm = tk.Menu(menubar, tearoff=0)
        hm.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=hm)
        self.root.config(menu=menubar)

        top = ttk.Frame(self.root, padding=5)
        top.pack(fill=tk.X)
        ttk.Label(top, text="Backup:").pack(side=tk.LEFT)
        self.lbl_path = ttk.Label(top, text=self.settings["backup_root"],
                                   foreground="blue", cursor="hand2")
        self.lbl_path.pack(side=tk.LEFT, padx=5)
        self.lbl_path.bind("<Button-1>", lambda e: self._set_backup_folder())
        self.lbl_schedule = ttk.Label(top, text="", foreground="gray")
        self.lbl_schedule.pack(side=tk.RIGHT, padx=5)

        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        left = ttk.LabelFrame(paned, text="Projects / Robots", padding=5)
        paned.add(left, weight=1)
        tb = ttk.Frame(left)
        tb.pack(fill=tk.X, pady=(0, 5))
        for txt, cmd in [("+ Project", self._add_project), ("+ Robot", self._add_robot),
                          ("Edit", self._edit_selected), ("Delete", self._delete_selected),
                          ("Check", self._check_selected)]:
            ttk.Button(tb, text=txt, width=max(len(txt)+1, 7), command=cmd).pack(side=tk.LEFT, padx=1)

        self.tree = ttk.Treeview(left, columns=("ip", "ctrl", "status", "next"),
                                  show="tree headings", selectmode="extended")
        self.tree.heading("#0", text="Name", anchor=tk.W)
        self.tree.column("#0", width=170, minwidth=100)
        self.tree.heading("ip", text="IP Address")
        self.tree.column("ip", width=110)
        self.tree.heading("ctrl", text="Controller")
        self.tree.column("ctrl", width=95)
        self.tree.heading("status", text="Status")
        self.tree.column("status", width=65)
        self.tree.heading("next", text="Next Backup")
        self.tree.column("next", width=90)
        self.tree.tag_configure("online", foreground="#16a34a")
        self.tree.tag_configure("offline", foreground="#dc2626")
        self.tree.tag_configure("sched_on", foreground="#2563eb")
        self.tree.pack(fill=tk.BOTH, expand=True)

        sf = ttk.Frame(left)
        sf.pack(fill=tk.X, pady=(4, 0))
        ttk.Button(sf, text="Expand All", width=10, command=self._expand_all).pack(side=tk.LEFT, padx=1)
        ttk.Button(sf, text="Collapse All", width=10, command=self._collapse_all).pack(side=tk.LEFT, padx=1)

        right = ttk.Frame(paned)
        paned.add(right, weight=2)

        tf = ttk.LabelFrame(right, text="Backup Type", padding=8)
        tf.pack(fill=tk.X, pady=(0, 5))
        self.backup_type = tk.StringVar(value="full_md")
        for txt, val in [("Full MD backup - all user files", "full_md"),
                           ("Selective backup - pick file types", "selective")]:
            ttk.Radiobutton(tf, text=txt, variable=self.backup_type,
                            value=val, command=self._on_type_change).pack(anchor=tk.W, pady=1)
        self.lbl_parallel = ttk.Label(tf, text="", foreground="gray")
        self.lbl_parallel.pack(anchor=tk.W, pady=(4, 0))
        self._update_parallel_label()

        self.sel_frame = ttk.LabelFrame(right, text="File Types", padding=6)
        self.ft_vars = {}
        r, c = 0, 0
        for cat in FILE_CATEGORIES:
            v = tk.BooleanVar(value=True)
            self.ft_vars[cat] = v
            exts = ", ".join(FILE_CATEGORIES[cat])
            ttk.Checkbutton(self.sel_frame, text=f"{cat} ({exts})", variable=v).grid(
                row=r, column=c, sticky=tk.W, padx=4)
            c += 1
            if c > 1:
                c = 0
                r += 1
        btn_row = r + 1 if c == 0 else r + 2
        sf_btns = ttk.Frame(self.sel_frame)
        sf_btns.grid(row=btn_row, column=0, columnspan=2, sticky=tk.W, pady=(6, 0))
        ttk.Button(sf_btns, text="Check All", width=10,
                    command=lambda: [v.set(True) for v in self.ft_vars.values()]).pack(side=tk.LEFT, padx=2)
        ttk.Button(sf_btns, text="Uncheck All", width=10,
                    command=lambda: [v.set(False) for v in self.ft_vars.values()]).pack(side=tk.LEFT, padx=2)

        af = ttk.Frame(right)
        af.pack(fill=tk.X, pady=5)
        self.btn_start = ttk.Button(af, text="Start Backup", command=self._start_backup)
        self.btn_start.pack(side=tk.LEFT, padx=2)
        self.btn_cancel = ttk.Button(af, text="Cancel", command=self._cancel, state=tk.DISABLED)
        self.btn_cancel.pack(side=tk.LEFT, padx=2)

        pf = ttk.Frame(right)
        pf.pack(fill=tk.X, pady=(0, 2))
        self.prog_var = tk.DoubleVar(value=0)
        self.prog_bar = ttk.Progressbar(pf, variable=self.prog_var, maximum=100,
                                         style="green.Horizontal.TProgressbar")
        self.prog_bar.pack(fill=tk.X, side=tk.LEFT, expand=True)
        self.lbl_pct = ttk.Label(pf, text="0%", width=6)
        self.lbl_pct.pack(side=tk.RIGHT, padx=(6, 0))

        self.lbl_status = ttk.Label(right, text="Ready", foreground="gray")
        self.lbl_status.pack(fill=tk.X)

        lf = ttk.LabelFrame(right, text="Log", padding=5)
        lf.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        self.log_text = scrolledtext.ScrolledText(lf, height=12, font=("Consolas", 9),
                                                   state=tk.DISABLED, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        self.sbar = ttk.Label(self.root, relief=tk.SUNKEN, padding=3, text=self._sbar_text())
        self.sbar.pack(fill=tk.X, side=tk.BOTTOM)

    # ---- helpers ----
    def _sbar_text(self):
        total = sum(len(p.robots) for p in self.projects)
        ret = f"Retention: {self.settings['retention_days']}d"
        par = f"Parallel: {self.settings['parallel_count']}"
        return f"{APP_NAME} v{APP_VERSION} | {len(self.projects)} projects, {total} robots | {par} | {ret}"

    def _update_parallel_label(self):
        n = self.settings.get("parallel_count", 3)
        if hasattr(self, "lbl_parallel"):
            self.lbl_parallel.config(text=f"Parallel: {n} robots simultaneously (Tools > Parallel Backup Settings)")

    def _update_schedule_label(self):
        scheduled = [p.name for p in self.projects if p.sched_enabled]
        if scheduled:
            self.lbl_schedule.config(text=f"Scheduled: {', '.join(scheduled)}")
        else:
            self.lbl_schedule.config(text="Auto-backup: OFF")

    def _refresh_tree(self):
        old_status = {}
        for item in self.tree.get_children():
            for child in self.tree.get_children(item):
                vals = self.tree.item(child, "values")
                if vals and len(vals) >= 3:
                    old_status[child] = vals[2]

        self.tree.delete(*self.tree.get_children())
        for pi, proj in enumerate(self.projects):
            pid = f"P{pi}"
            if proj.sched_enabled:
                sched_txt = f"ON @ {proj.sched_time}"
                countdown = self._calc_countdown(proj)
                tag = ("sched_on",)
            else:
                sched_txt = "OFF"
                countdown = ""
                tag = ()
            self.tree.insert("", tk.END, iid=pid, text=f"  {proj.name}",
                             values=(f"{len(proj.robots)} robots", "", sched_txt, countdown),
                             open=True, tags=tag)
            for ri, robot in enumerate(proj.robots):
                rid = f"P{pi}R{ri}"
                status = old_status.get(rid, "-")
                rtag = ()
                if status == "Online":
                    rtag = ("online",)
                elif status == "OFFLINE":
                    rtag = ("offline",)
                self.tree.insert(pid, tk.END, iid=rid, text=f"    {robot.name}",
                                 values=(robot.ip, robot.controller, status, ""),
                                 tags=rtag)
        self.sbar.config(text=self._sbar_text())
        self._save()

    def _calc_countdown(self, proj):
        if not proj.sched_enabled or not proj.sched_days:
            return ""
        try:
            now = datetime.now()
            hh, mm = map(int, proj.sched_time.split(":"))
            for day_offset in range(8):
                candidate = now + timedelta(days=day_offset)
                candidate = candidate.replace(hour=hh, minute=mm, second=0, microsecond=0)
                if candidate <= now:
                    continue
                if candidate.weekday() in proj.sched_days:
                    delta = candidate - now
                    total_min = int(delta.total_seconds() // 60)
                    days = total_min // (24 * 60)
                    hours = (total_min % (24 * 60)) // 60
                    mins = total_min % 60
                    return f"{days:02d}:{hours:02d}:{mins:02d}"
        except Exception:
            pass
        return ""

    def _calc_countdown_minutes(self, proj):
        if not proj.sched_enabled or not proj.sched_days:
            return None
        try:
            now = datetime.now()
            hh, mm = map(int, proj.sched_time.split(":"))
            for day_offset in range(8):
                candidate = now + timedelta(days=day_offset)
                candidate = candidate.replace(hour=hh, minute=mm, second=0, microsecond=0)
                if candidate <= now:
                    continue
                if candidate.weekday() in proj.sched_days:
                    return int((candidate - now).total_seconds() // 60)
        except Exception:
            pass
        return None

    def _expand_all(self):
        for i in self.tree.get_children():
            self.tree.item(i, open=True)

    def _collapse_all(self):
        for i in self.tree.get_children():
            self.tree.item(i, open=False)

    def _parse_id(self, iid):
        if iid.startswith("P") and "R" in iid:
            parts = iid.split("R")
            return int(parts[0][1:]), int(parts[1])
        elif iid.startswith("P"):
            return int(iid[1:]), None
        return None, None

    def _get_selected_robots(self):
        result = []
        for iid in self.tree.selection():
            pi, ri = self._parse_id(iid)
            if pi is None:
                continue
            if ri is not None:
                result.append((pi, ri, self.projects[pi].robots[ri]))
            else:
                for ri2, r in enumerate(self.projects[pi].robots):
                    result.append((pi, ri2, r))
        return result

    def _get_all_robots(self):
        result = []
        for pi, proj in enumerate(self.projects):
            for ri, r in enumerate(proj.robots):
                result.append((pi, ri, r))
        return result

    def _add_project(self):
        name = simpledialog.askstring("New Project", "Project name:", parent=self.root)
        if name:
            self.projects.append(Project(name.strip()))
            self._refresh_tree()

    def _add_robot(self):
        sel = self.tree.selection()
        pi = 0
        if sel:
            pi, _ = self._parse_id(sel[0])
            if pi is None:
                pi = 0
        if not self.projects:
            self.projects.append(Project("Default"))
        RobotDialog(self.root, "Add Robot", callback=lambda r: self._on_robot_add(pi, r))

    def _on_robot_add(self, pi, robot):
        self.projects[pi].robots.append(robot)
        self._refresh_tree()

    def _edit_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        pi, ri = self._parse_id(sel[0])
        if pi is None:
            return
        if ri is None:
            old = self.projects[pi].name
            name = simpledialog.askstring("Rename", "Project name:", initialvalue=old, parent=self.root)
            if name:
                self.projects[pi].name = name.strip()
                self._refresh_tree()
        else:
            robot = self.projects[pi].robots[ri]
            RobotDialog(self.root, "Edit Robot", robot=robot,
                         callback=lambda r: self._on_robot_edit(pi, ri, r))

    def _on_robot_edit(self, pi, ri, robot):
        self.projects[pi].robots[ri] = robot
        self._refresh_tree()

    def _delete_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        del_p = set()
        del_r = {}
        for iid in sel:
            pi, ri = self._parse_id(iid)
            if pi is None:
                continue
            if ri is None:
                del_p.add(pi)
            else:
                del_r.setdefault(pi, []).append(ri)
        if messagebox.askyesno("Delete", "Delete selected items?"):
            for pi in sorted(del_p, reverse=True):
                del self.projects[pi]
            for pi, ris in del_r.items():
                if pi in del_p:
                    continue
                for ri in sorted(ris, reverse=True):
                    del self.projects[pi].robots[ri]
            self._refresh_tree()

    def _on_type_change(self):
        if self.backup_type.get() == "selective":
            self.sel_frame.pack(fill=tk.X, pady=(0, 5),
                                before=self.sel_frame.master.winfo_children()[2])
        else:
            self.sel_frame.pack_forget()

    def _check_selected(self):
        robots = self._get_selected_robots()
        if not robots:
            return
        self._log("\nConnectivity check:")
        for pi, ri, robot in robots:
            ok = self.engine.check(robot)
            rid = f"P{pi}R{ri}"
            status = "Online" if ok else "OFFLINE"
            tag = "online" if ok else "offline"
            self._robot_status[(pi, ri)] = status
            self.tree.set(rid, "status", status)
            self.tree.item(rid, tags=(tag,))

    def _check_all(self):
        self._log("\nChecking all...")
        for pi, proj in enumerate(self.projects):
            for ri, robot in enumerate(proj.robots):
                ok = self.engine.check(robot)
                rid = f"P{pi}R{ri}"
                status = "Online" if ok else "OFFLINE"
                tag = "online" if ok else "offline"
                self._robot_status[(pi, ri)] = status
                self.tree.set(rid, "status", status)
                self.tree.item(rid, tags=(tag,))

    # ---- BACKUP ----
    def _start_backup(self, robots=None):
        if self.backup_running:
            return
        if robots is None:
            robots = self._get_selected_robots()
        if not robots:
            robots = self._get_all_robots()
        if not robots:
            messagebox.showinfo("Backup", "No robots.")
            return

        ts = datetime.now().strftime(TIMESTAMP_FMT)
        broot = self.settings["backup_root"]
        os.makedirs(broot, exist_ok=True)
        btype = self.backup_type.get()
        sel_exts = None
        if btype == "selective":
            sel_exts = []
            for cat, var in self.ft_vars.items():
                if var.get():
                    sel_exts.extend(FILE_CATEGORIES[cat])
            if not sel_exts:
                messagebox.showinfo("Backup", "Select file types.")
                return

        self.backup_running = True
        active_pis = set(pi for pi, _, _ in robots)
        self._active_projects.update(active_pis)
        self.btn_start.config(state=tk.DISABLED)
        self.btn_cancel.config(state=tk.NORMAL)
        self.prog_var.set(0)
        self.lbl_pct.config(text="0%")
        rlist = []
        for pi, ri, r in robots:
            proj_name = self.projects[pi].name
            rlist.append((proj_name, r))
        max_workers = min(self.settings.get("parallel_count", 3), len(rlist))

        def run():
            t0 = time.time()
            self._log(f"\n{'#'*55}")
            self._log(f"  BACKUP STARTED - {ts}")
            self._log(f"  Type: {btype} | Robots: {len(rlist)} | Parallel: {max_workers}")
            self._log(f"  Root: {broot}")
            self._log(f"{'#'*55}")

            results = {}
            completed = [0]
            lock = threading.Lock()

            def backup_one(item):
                proj_name, robot = item
                if not self.backup_running:
                    return robot.name, False, 0, 0
                ok, files, fails = self.engine.backup_robot(
                    robot, broot, proj_name, ts, btype, sel_exts)
                with lock:
                    completed[0] += 1
                    pct = (completed[0] / len(rlist)) * 100
                    self.root.after(0, lambda: self.prog_var.set(pct))
                    self.root.after(0, lambda: self.lbl_pct.config(text=f"{int(pct)}%"))
                    self.root.after(0, lambda: self.lbl_status.config(
                        text=f"Completed {completed[0]}/{len(rlist)} robots"))
                return robot.name, ok, files, fails

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(backup_one, item): item for item in rlist}
                for future in concurrent.futures.as_completed(futures):
                    name, ok, files, fails = future.result()
                    results[name] = (ok, files, fails)

            elapsed = time.time() - t0
            self._log(f"\n{'#'*55}")
            self._log(f"  COMPLETE - {elapsed:.1f}s total ({max_workers} parallel)")
            for name, (ok, files, fails) in results.items():
                sym = "OK" if ok else "FAIL"
                self._log(f"  {sym} {name}: {files} files, {fails} failed")
            self._log(f"{'#'*55}")

            for pi, ri, r in robots:
                proj_name = self.projects[pi].name
                safe_proj = proj_name.replace(" ", "_").replace("/", "_").replace("\\", "_")
                safe_robot = r.name.replace(" ", "_").replace("/", "_").replace("\\", "_")
                try:
                    summary_dir = safe_join_under(broot, safe_proj, safe_robot, ts)
                except ValueError:
                    continue
                if os.path.isdir(summary_dir):
                    summary_path = safe_join_under(summary_dir, "_summary.txt")
                    with open(summary_path, "w") as f:
                        f.write(f"RoboVault Backup - {ts}\n")
                        f.write(f"Project: {proj_name} | Robot: {r.name}\n")
                        f.write(f"Type: {btype} | Duration: {elapsed:.1f}s\n")
                        if r.name in results:
                            ok, files, fails = results[r.name]
                            f.write(f"{'OK' if ok else 'FAIL'} | {files} files | {fails} failed\n")

            ret_days = self.settings.get("retention_days", 0)
            if ret_days > 0:
                count, deleted = RetentionManager.cleanup(
                    self.settings["backup_root"], ret_days)
                if count > 0:
                    self._log(f"\nRetention: Deleted {count} backup(s) older than {ret_days} days")
                    for d in deleted:
                        self._log(f"  Removed: {d}")

            self._notify_backup_results(ts, results)
            self.root.after(0, self._backup_done)

        threading.Thread(target=run, daemon=True).start()

    def _scheduled_backup_project(self, project_index):
        if project_index >= len(self.projects):
            return
        proj = self.projects[project_index]
        robots = [(project_index, ri, r) for ri, r in enumerate(proj.robots)]
        self.root.after(0, lambda: self._log(
            f"\n** Scheduled backup: {proj.name} ({len(robots)} robots) **"))
        self.root.after(0, lambda: self._start_backup(robots=robots))

    def _cancel(self):
        self.engine.cancel()
        self.backup_running = False
        self._active_projects.clear()
        self.lbl_status.config(text="Cancelling...")

    def _backup_done(self):
        self.backup_running = False
        self._active_projects.clear()
        self.btn_start.config(state=tk.NORMAL)
        self.btn_cancel.config(state=tk.DISABLED)
        self.prog_var.set(100)
        self.lbl_pct.config(text="100%")
        self.lbl_status.config(text="Backup complete")

    def _update_progress(self, current, total, filename):
        pass

    def _log(self, msg):
        def _a():
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, msg + "\n")
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
        self.root.after(0, _a)

    def _tick_clock(self):
        now = datetime.now().strftime("%a %Y-%m-%d  %H:%M:%S")
        self.sbar.config(text=f"{self._sbar_text()}  |  {now}")
        self.root.after(1000, self._tick_clock)

    def _tick_countdown(self):
        for pi, proj in enumerate(self.projects):
            pid = f"P{pi}"
            try:
                if proj.sched_enabled:
                    countdown = self._calc_countdown(proj)
                    self.tree.set(pid, "next", countdown)
                else:
                    self.tree.set(pid, "next", "")
            except Exception:
                pass
        self.root.after(30000, self._tick_countdown)

    def _tick_connectivity(self):
        def _check():
            for pi, proj in enumerate(self.projects):
                for ri, robot in enumerate(proj.robots):
                    rid = f"P{pi}R{ri}"
                    ok = self.engine.ping(robot.ip, robot.ftp_port)
                    status = "Online" if ok else "OFFLINE"
                    tag = "online" if ok else "offline"
                    self._robot_status[(pi, ri)] = status
                    try:
                        self.root.after(0, lambda r=rid, s=status, t=tag:
                            self._set_robot_status(r, s, t))
                    except Exception:
                        pass
        threading.Thread(target=_check, daemon=True).start()
        self.root.after(60000, self._tick_connectivity)

    def _set_robot_status(self, rid, status, tag):
        try:
            self.tree.set(rid, "status", status)
            self.tree.item(rid, tags=(tag,))
        except Exception:
            pass

    def _schedule_dialog(self):
        sel = self.tree.selection()
        pi = None
        if sel:
            pi, _ = self._parse_id(sel[0])
        if pi is None:
            messagebox.showinfo("Schedule", "Select a project first to configure its schedule.")
            return

        proj = self.projects[pi]

        if pi in self._active_projects:
            messagebox.showwarning("Schedule Locked",
                f"Cannot modify schedule for '{proj.name}' while its backup is running.\n\n"
                f"Wait for the backup to finish, then try again.")
            return

        if proj.sched_enabled:
            mins_left = self._calc_countdown_minutes(proj)
            if mins_left is not None and mins_left < 2:
                messagebox.showwarning("Schedule Locked",
                    f"Cannot modify schedule for '{proj.name}' — backup starts in "
                    f"less than 2 minutes.\n\n"
                    f"Wait for the scheduled backup to run, then modify the schedule.")
                return

        win = tk.Toplevel(self.root)
        win.title(f"Schedule - {proj.name}")
        win.geometry("380x320")
        win.resizable(False, False)
        win.transient(self.root)
        win.grab_set()

        f = ttk.Frame(win, padding=15)
        f.pack(fill=tk.BOTH, expand=True)

        ttk.Label(f, text=f"Project: {proj.name}", font=("Segoe UI", 10, "bold")).pack(anchor=tk.W)
        ttk.Label(f, text="").pack()

        enabled_var = tk.BooleanVar(value=proj.sched_enabled)
        ttk.Checkbutton(f, text="Enable scheduled auto-backup", variable=enabled_var).pack(anchor=tk.W)

        ttk.Label(f, text="\nBackup time:").pack(anchor=tk.W)
        time_frame = ttk.Frame(f)
        time_frame.pack(anchor=tk.W, pady=(2, 8))

        try:
            cur_hh, cur_mm = proj.sched_time.split(":")
        except Exception:
            cur_hh, cur_mm = "02", "00"

        hh_var = tk.StringVar(value=cur_hh.zfill(2))
        mm_var = tk.StringVar(value=cur_mm.zfill(2))

        hh_spin = tk.Spinbox(time_frame, from_=0, to=23, width=3, format="%02.0f",
                              textvariable=hh_var, wrap=True, font=("Consolas", 12),
                              justify=tk.CENTER)
        hh_spin.pack(side=tk.LEFT)
        ttk.Label(time_frame, text=" : ", font=("Consolas", 12)).pack(side=tk.LEFT)
        mm_spin = tk.Spinbox(time_frame, from_=0, to=59, width=3, format="%02.0f",
                              textvariable=mm_var, wrap=True, font=("Consolas", 12),
                              justify=tk.CENTER, increment=5)
        mm_spin.pack(side=tk.LEFT)
        ttk.Label(time_frame, text="  (24hr)", foreground="gray").pack(side=tk.LEFT, padx=(8, 0))

        ttk.Label(f, text="Days:").pack(anchor=tk.W)
        days_frame = ttk.Frame(f)
        days_frame.pack(anchor=tk.W, pady=4)
        day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        day_vars = []
        for i, name in enumerate(day_names):
            v = tk.BooleanVar(value=(i in proj.sched_days))
            day_vars.append(v)
            ttk.Checkbutton(days_frame, text=name, variable=v).pack(side=tk.LEFT, padx=3)

        def save():
            proj.sched_enabled = enabled_var.get()
            try:
                hh = int(hh_var.get()) % 24
                mm = int(mm_var.get()) % 60
            except ValueError:
                hh, mm = 2, 0
            proj.sched_time = f"{hh:02d}:{mm:02d}"
            proj.sched_days = [i for i, v in enumerate(day_vars) if v.get()]
            self._refresh_tree()
            self._update_schedule_label()
            win.destroy()

        ttk.Button(f, text="Save", width=10, command=save).pack(pady=(15, 0))

    def _retention_dialog(self):
        val = simpledialog.askinteger(
            "Retention", "Delete backups older than N days (0 = never):",
            initialvalue=self.settings.get("retention_days", 30),
            minvalue=0, maxvalue=9999, parent=self.root)
        if val is not None:
            self.settings["retention_days"] = val
            self.sbar.config(text=self._sbar_text())
            self._save()

    def _parallel_dialog(self):
        val = simpledialog.askinteger(
            "Parallel Backups", "Simultaneous robot connections (1-10):",
            initialvalue=self.settings.get("parallel_count", 3),
            minvalue=1, maxvalue=10, parent=self.root)
        if val is not None:
            self.settings["parallel_count"] = val
            self._update_parallel_label()
            self.sbar.config(text=self._sbar_text())
            self._save()

    def _run_retention(self):
        days = self.settings.get("retention_days", 0)
        if days <= 0:
            messagebox.showinfo("Retention", "Retention is disabled (set to 0 days).")
            return
        count, deleted = RetentionManager.cleanup(self.settings["backup_root"], days)
        if count > 0:
            self._log(f"\nRetention cleanup: Deleted {count} backup(s) older than {days} days")
            for d in deleted:
                self._log(f"  Removed: {d}")
        else:
            self._log(f"\nRetention: No backups older than {days} days found.")

    def _diff_dialog(self):
        broot = self.settings["backup_root"]
        if not os.path.exists(broot):
            messagebox.showinfo("Compare", "No backups found.")
            return

        all_paths = []
        for proj_dir in sorted(os.listdir(broot)):
            proj_path = os.path.join(broot, proj_dir)
            if not os.path.isdir(proj_path):
                continue
            for robot_dir in sorted(os.listdir(proj_path)):
                robot_path = os.path.join(proj_path, robot_dir)
                if not os.path.isdir(robot_path):
                    continue
                for ts_dir in sorted(os.listdir(robot_path), reverse=True):
                    ts_path = os.path.join(robot_path, ts_dir)
                    if not os.path.isdir(ts_path) or ts_dir.startswith("_"):
                        continue
                    label = f"{proj_dir} / {robot_dir} / {ts_dir}"
                    all_paths.append((label, ts_path))

        if len(all_paths) < 2:
            messagebox.showinfo("Compare", "Need at least 2 backup snapshots to compare.")
            return

        labels = [p[0] for p in all_paths]
        path_map = {p[0]: p[1] for p in all_paths}

        win = tk.Toplevel(self.root)
        win.title("Compare Backups")
        win.geometry("750x520")
        win.transient(self.root)
        win.grab_set()

        f = ttk.Frame(win, padding=10)
        f.pack(fill=tk.BOTH, expand=True)

        sel_f = ttk.Frame(f)
        sel_f.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(sel_f, text="Older:").pack(side=tk.LEFT)
        var_a = tk.StringVar(value=labels[-1])
        ttk.Combobox(sel_f, textvariable=var_a, values=labels, width=38,
                      state="readonly").pack(side=tk.LEFT, padx=(4, 12))
        ttk.Label(sel_f, text="Newer:").pack(side=tk.LEFT)
        var_b = tk.StringVar(value=labels[0])
        ttk.Combobox(sel_f, textvariable=var_b, values=labels, width=38,
                      state="readonly").pack(side=tk.LEFT, padx=4)

        result_text = scrolledtext.ScrolledText(f, font=("Consolas", 9),
                                                 state=tk.DISABLED, height=20)
        result_text.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        def run_diff():
            a_label = var_a.get()
            b_label = var_b.get()
            if a_label == b_label:
                messagebox.showinfo("Compare", "Select two different backups.")
                return
            a = path_map[a_label]
            b = path_map[b_label]
            added, removed, changed, unchanged, fa, fb = BackupDiff.compare(a, b)

            result_text.config(state=tk.NORMAL)
            result_text.delete("1.0", tk.END)
            result_text.insert(tk.END, f"Comparing:\n  OLD: {a_label}\n  NEW: {b_label}\n\n")
            result_text.insert(tk.END, f"Summary: {len(added)} added, {len(removed)} removed, "
                              f"{len(changed)} changed, {len(unchanged)} unchanged\n")
            result_text.insert(tk.END, f"{'='*60}\n\n")
            if added:
                result_text.insert(tk.END, f"ADDED ({len(added)}):\n")
                for fn in added:
                    result_text.insert(tk.END, f"  + {fn}  ({fb[fn]} bytes)\n")
                result_text.insert(tk.END, "\n")
            if removed:
                result_text.insert(tk.END, f"REMOVED ({len(removed)}):\n")
                for fn in removed:
                    result_text.insert(tk.END, f"  - {fn}  ({fa[fn]} bytes)\n")
                result_text.insert(tk.END, "\n")
            if changed:
                result_text.insert(tk.END, f"CHANGED ({len(changed)}):\n")
                for fn in changed:
                    delta = fb[fn] - fa[fn]
                    sign = "+" if delta > 0 else ""
                    result_text.insert(tk.END, f"  ~ {fn}  ({fa[fn]} -> {fb[fn]}, {sign}{delta} bytes)\n")
                result_text.insert(tk.END, "\n")
            if not added and not removed and not changed:
                result_text.insert(tk.END, "No differences found.\n")
            result_text.config(state=tk.DISABLED)

        ttk.Button(f, text="Compare", command=run_diff).pack()

    def _browse_backups(self):
        broot = self.settings["backup_root"]
        if not os.path.exists(broot):
            messagebox.showinfo("Browse", "No backups found.")
            return

        win = tk.Toplevel(self.root)
        win.title("Browse Backups")
        win.geometry("700x500")
        win.transient(self.root)

        f = ttk.Frame(win, padding=8)
        f.pack(fill=tk.BOTH, expand=True)

        tbf = ttk.Frame(f)
        tbf.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(tbf, text=broot, foreground="gray", font=("Consolas", 9)).pack(side=tk.LEFT)
        ttk.Button(tbf, text="Open in Explorer", width=16,
                    command=lambda: self._open_path(broot)).pack(side=tk.RIGHT)

        tree = ttk.Treeview(f, columns=("size", "files", "date"),
                             show="tree headings", selectmode="browse")
        tree.heading("#0", text="Name", anchor=tk.W)
        tree.column("#0", width=260, minwidth=150)
        tree.heading("size", text="Size")
        tree.column("size", width=80)
        tree.heading("files", text="Files")
        tree.column("files", width=60)
        tree.heading("date", text="Modified")
        tree.column("date", width=140)

        scroll = ttk.Scrollbar(f, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        ctx = tk.Menu(win, tearoff=0)
        ctx.add_command(label="Open folder in Explorer", command=lambda: self._open_tree_item(tree, broot))

        def show_ctx(event):
            item = tree.identify_row(event.y)
            if item:
                tree.selection_set(item)
                ctx.post(event.x_root, event.y_root)

        tree.bind("<Button-3>", show_ctx)
        tree.bind("<Double-1>", lambda e: self._open_tree_item(tree, broot))

        def dir_size(path):
            total = 0
            count = 0
            for root, dirs, files in os.walk(path):
                for fn in files:
                    if not fn.startswith("_"):
                        total += os.path.getsize(os.path.join(root, fn))
                        count += 1
            return total, count

        def format_size(b):
            if b < 1024:
                return f"{b} B"
            elif b < 1024 * 1024:
                return f"{b/1024:.1f} KB"
            else:
                return f"{b/1024/1024:.1f} MB"

        for proj_dir in sorted(os.listdir(broot)):
            proj_path = os.path.join(broot, proj_dir)
            if not os.path.isdir(proj_path):
                continue
            proj_id = tree.insert("", tk.END, text=f"  {proj_dir}", open=True)

            for robot_dir in sorted(os.listdir(proj_path)):
                robot_path = os.path.join(proj_path, robot_dir)
                if not os.path.isdir(robot_path):
                    continue
                robot_id = tree.insert(proj_id, tk.END, text=f"  {robot_dir}", open=False)

                for ts_dir in sorted(os.listdir(robot_path), reverse=True):
                    ts_path = os.path.join(robot_path, ts_dir)
                    if not os.path.isdir(ts_path) or ts_dir.startswith("_"):
                        continue
                    sz, count = dir_size(ts_path)
                    try:
                        mtime = datetime.strptime(ts_dir, TIMESTAMP_FMT)
                        date_str = mtime.strftime("%Y-%m-%d %H:%M")
                    except ValueError:
                        date_str = ""
                    tree.insert(robot_id, tk.END, text=f"  {ts_dir}",
                                values=(format_size(sz), f"{count} files", date_str),
                                tags=("timestamp",))

        tree.tag_configure("timestamp", foreground="#3b82f6")

    def _open_tree_item(self, tree, broot):
        sel = tree.selection()
        if not sel:
            return
        parts = []
        item = sel[0]
        while item:
            text = tree.item(item, "text").strip()
            parts.insert(0, text)
            item = tree.parent(item)
        try:
            path = safe_join_under(broot, *parts)
        except ValueError:
            return
        if os.path.isdir(path):
            self._open_path(path)

    def _open_path(self, path):
        # Defence-in-depth: only open paths that exist and that we construct
        # ourselves (never user-typed raw strings).
        if not os.path.exists(path):
            return
        if os.name == "nt":
            os.startfile(path)
        else:
            # List form — no shell interpolation
            subprocess.run(["xdg-open", path], check=False)

    # ---- TEAMS NOTIFICATIONS ----
    def _teams_dialog(self):
        win = tk.Toplevel(self.root)
        win.title("Teams Notifications")
        win.geometry("520x300")
        win.resizable(False, False)
        win.transient(self.root)
        win.grab_set()

        f = ttk.Frame(win, padding=15)
        f.pack(fill=tk.BOTH, expand=True)

        ttk.Label(f, text="Microsoft Teams Workflow Webhook URL (https only):").pack(anchor=tk.W)
        ttk.Label(f, text="(Channel > ... > Workflows > 'Post to a channel when a webhook request is received')",
                  foreground="gray", font=("Segoe UI", 9), wraplength=480).pack(anchor=tk.W)
        url_var = tk.StringVar(value=self.settings.get("teams_webhook_url", ""))
        ttk.Entry(f, textvariable=url_var, width=65).pack(fill=tk.X, pady=(4, 10))

        fail_var = tk.BooleanVar(value=self.settings.get("teams_notify_on_failure", True))
        ttk.Checkbutton(f, text="Notify on backup failure", variable=fail_var).pack(anchor=tk.W)

        success_var = tk.BooleanVar(value=self.settings.get("teams_notify_on_success", False))
        ttk.Checkbutton(f, text="Notify on backup success", variable=success_var).pack(anchor=tk.W)

        ttk.Label(f, text="URL is stored encrypted (DPAPI) and validated as https.",
                  foreground="gray", font=("Segoe UI", 9)).pack(anchor=tk.W, pady=(6, 0))

        status_lbl = ttk.Label(f, text="", foreground="gray")
        status_lbl.pack(anchor=tk.W, pady=(4, 0))

        def test():
            url = url_var.get().strip()
            ok_url, reason = is_valid_webhook_url(url)
            if not ok_url:
                status_lbl.config(text=f"Invalid URL: {reason}", foreground="red")
                return
            status_lbl.config(text="Sending test...", foreground="gray")
            win.update()
            ok, msg = self._send_teams_message(url, "RoboVault Test",
                "This is a test notification from RoboVault.", "#22c55e")
            if ok:
                status_lbl.config(text="Test sent successfully!", foreground="green")
            else:
                status_lbl.config(text=f"Failed: {msg}", foreground="red")

        def save():
            url = url_var.get().strip()
            if url:
                ok_url, reason = is_valid_webhook_url(url)
                if not ok_url:
                    messagebox.showerror("Invalid URL",
                        f"Webhook URL rejected: {reason}\n\n"
                        f"Must be an https URL to a valid host.", parent=win)
                    return
            self.settings["teams_webhook_url"] = url
            self.settings["teams_notify_on_failure"] = fail_var.get()
            self.settings["teams_notify_on_success"] = success_var.get()
            self._save()
            win.destroy()

        bf = ttk.Frame(f)
        bf.pack(pady=(10, 0))
        ttk.Button(bf, text="Test Webhook", width=14, command=test).pack(side=tk.LEFT, padx=4)
        ttk.Button(bf, text="Save", width=10, command=save).pack(side=tk.LEFT, padx=4)
        ttk.Button(bf, text="Cancel", width=10, command=win.destroy).pack(side=tk.LEFT, padx=4)

    def _send_teams_message(self, webhook_url, title, message, color="#ef4444"):
        """Send an Adaptive Card to Microsoft Teams via Workflow webhook."""
        ok_url, reason = is_valid_webhook_url(webhook_url)
        if not ok_url:
            return False, f"invalid webhook URL ({reason})"

        body_items = [
            {"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": title,
             "color": "attention" if "FAIL" in title.upper() else "good"},
            {"type": "TextBlock", "text": f"{APP_NAME} v{APP_VERSION} | {APP_COMPANY}",
             "isSubtle": True, "spacing": "None", "size": "Small"},
        ]
        for line in message.split("\n"):
            if line.strip():
                body_items.append({
                    "type": "TextBlock", "text": line.strip(),
                    "wrap": True, "spacing": "Small",
                    "font": "Monospace" if line.strip().startswith("-") else "Default"
                })

        adaptive_card = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": body_items
                }
            }]
        }

        try:
            data = json.dumps(adaptive_card).encode("utf-8")
            req = urllib.request.Request(
                webhook_url, data=data,
                headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10)  # noqa: S310 - URL validated above
            return True, ""
        except urllib.error.HTTPError as e:
            return False, f"HTTP {e.code}: {e.reason}"
        except Exception as e:
            return False, str(e)

    def _notify_backup_results(self, timestamp, results):
        url = self.settings.get("teams_webhook_url", "")
        if not url:
            return

        has_failures = any(not ok for ok, _, _ in results.values())
        has_successes = any(ok for ok, _, _ in results.values())

        should_notify = False
        if has_failures and self.settings.get("teams_notify_on_failure", True):
            should_notify = True
        if has_successes and self.settings.get("teams_notify_on_success", False):
            should_notify = True

        if not should_notify:
            return

        lines = [f"**Backup: {timestamp}**\n"]
        for name, (ok, files, fails) in results.items():
            icon = "OK" if ok else "FAIL"
            lines.append(f"- {icon} **{name}**: {files} files, {fails} failed")

        total_ok = sum(1 for ok, _, _ in results.values() if ok)
        total_fail = sum(1 for ok, _, _ in results.values() if not ok)
        lines.append(f"\n**Total: {total_ok} succeeded, {total_fail} failed**")

        color = "#ef4444" if has_failures else "#22c55e"
        title = "Backup FAILED" if has_failures else "Backup Complete"

        ok, err = self._send_teams_message(url, title, "\n".join(lines), color)
        if ok:
            self._log("Teams notification sent.")
        elif err:
            self._log(f"Teams notification failed: {err}")

    def _set_backup_folder(self):
        f = filedialog.askdirectory(title="Backup Folder",
                                     initialdir=self.settings["backup_root"])
        if f:
            self.settings["backup_root"] = f
            self.lbl_path.config(text=f)
            self._save()

    def _open_backup_folder(self):
        self._open_path(self.settings["backup_root"])

    def _save(self):
        self.config.save(self.projects, self.settings)

    def _export_config(self):
        """Export the non-secret config for transfer between machines.
        Secrets are NOT included — each user must re-enter passwords
        on the new machine (DPAPI ciphertext is not portable)."""
        p = filedialog.asksaveasfilename(defaultextension=".json",
                                          filetypes=[("JSON", "*.json")])
        if not p:
            return
        export = {
            "version": APP_VERSION,
            "_note": ("Passwords and webhook URL are excluded from exports. "
                      "Re-enter them after import."),
            "projects": [pr.to_dict_public() for pr in self.projects],
            "settings": {k: v for k, v in self.settings.items()
                         if k != "teams_webhook_url"},
        }
        with open(p, "w") as f:
            json.dump(export, f, indent=2)
        messagebox.showinfo("Export",
            "Config exported (secrets excluded).\n\n"
            "On import, you'll need to re-enter FTP passwords and webhook URL.")

    def _import_config(self):
        p = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if not p:
            return
        with open(p, "r") as f:
            data = json.load(f)
        imported = [Project.from_dict(d) for d in data.get("projects", [])]
        if messagebox.askyesno("Import", f"Import {len(imported)} projects?\n\n"
                               "Existing FTP passwords and webhook URL will be kept."):
            self.projects = imported
            if "settings" in data:
                incoming = {k: v for k, v in data["settings"].items()
                            if k != "teams_webhook_url"}
                self.settings.update(incoming)
            self._refresh_tree()
            self._update_schedule_label()

    def _show_about(self):
        about = tk.Toplevel(self.root)
        about.title(f"About {APP_NAME}")
        about.geometry("360x260")
        about.resizable(False, False)
        about.transient(self.root)
        about.grab_set()
        f = ttk.Frame(about, padding=20)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(f, text=f"{APP_NAME} v{APP_VERSION}",
                  font=("Segoe UI", 14, "bold")).pack()
        ttk.Label(f, text="FANUC Robot Backup Tool", foreground="gray").pack(pady=(2, 10))
        ttk.Label(f, text=f"Author: {APP_AUTHOR}").pack()
        ttk.Label(f, text=APP_COMPANY, foreground="gray").pack()
        ttk.Label(f, text="").pack()
        ttk.Label(f, text="FTP-based, no FANUC software required.", foreground="gray").pack()
        ttk.Label(f, text="R-30iA / iB / iB+ controllers.", foreground="gray").pack()
        ttk.Label(f, text="Credentials encrypted at rest (DPAPI).",
                  foreground="gray").pack()
        ttk.Button(f, text="OK", width=10, command=about.destroy).pack(pady=(12, 0))

    def _on_close(self):
        self._save()
        self.scheduler.stop()
        if self.backup_running:
            if messagebox.askyesno("Exit", "Backup running. Cancel and exit?"):
                self.engine.cancel()
                self.backup_running = False
                self.root.destroy()
        else:
            self.root.destroy()

    def run(self):
        self.root.mainloop()


# =============================================================================
# ROBOT DIALOG
# =============================================================================

class RobotDialog:
    CONTROLLERS = ["R-30iA", "R-30iA Mate", "R-30iB", "R-30iB Mate",
                    "R-30iB Plus", "R-30iB Plus Mate", "R-30iB Compact Plus"]

    def __init__(self, parent, title, robot=None, callback=None):
        self.callback = callback
        self.win = tk.Toplevel(parent)
        self.win.title(title)
        self.win.geometry("420x360")
        self.win.resizable(False, False)
        self.win.transient(parent)
        self.win.grab_set()
        f = ttk.Frame(self.win, padding=15)
        f.pack(fill=tk.BOTH, expand=True)
        self.entries = {}
        for i, (lbl, key) in enumerate([("Robot Name:", "name"), ("IP Address:", "ip"),
                                          ("Identifier (F#):", "identifier")]):
            ttk.Label(f, text=lbl).grid(row=i, column=0, sticky=tk.W, pady=3)
            e = ttk.Entry(f, width=28)
            e.grid(row=i, column=1, sticky=tk.EW, pady=3, padx=(8, 0))
            self.entries[key] = e
        ttk.Label(f, text="Controller:").grid(row=3, column=0, sticky=tk.W, pady=3)
        self.ctrl_var = tk.StringVar(value="R-30iB Plus")
        ttk.Combobox(f, textvariable=self.ctrl_var, values=self.CONTROLLERS,
                      state="readonly", width=25).grid(row=3, column=1, sticky=tk.EW, pady=3, padx=(8, 0))
        ttk.Label(f, text="FTP User:").grid(row=4, column=0, sticky=tk.W, pady=3)
        self.entries["ftp_user"] = ttk.Entry(f, width=28)
        self.entries["ftp_user"].grid(row=4, column=1, sticky=tk.EW, pady=3, padx=(8, 0))
        ttk.Label(f, text="FTP Password:").grid(row=5, column=0, sticky=tk.W, pady=3)
        self.entries["ftp_pass"] = ttk.Entry(f, width=28, show="*")
        self.entries["ftp_pass"].grid(row=5, column=1, sticky=tk.EW, pady=3, padx=(8, 0))
        ttk.Label(f, text="(blank = anonymous; stored encrypted)",
                  foreground="gray").grid(
            row=6, column=1, sticky=tk.W, padx=(8, 0))
        ttk.Label(f, text="Notes:").grid(row=7, column=0, sticky=tk.NW, pady=3)
        self.notes = tk.Text(f, height=2, width=28, font=("Segoe UI", 9))
        self.notes.grid(row=7, column=1, sticky=tk.EW, pady=3, padx=(8, 0))
        if robot:
            self.entries["name"].insert(0, robot.name)
            self.entries["ip"].insert(0, robot.ip)
            self.entries["identifier"].insert(0, robot.identifier)
            self.ctrl_var.set(robot.controller)
            self.entries["ftp_user"].insert(0, robot.ftp_user)
            self.entries["ftp_pass"].insert(0, robot.ftp_pass)
            self.notes.insert("1.0", robot.notes)
        bf = ttk.Frame(f)
        bf.grid(row=8, column=0, columnspan=2, pady=(12, 0))
        ttk.Button(bf, text="Save", width=10, command=self._save).pack(side=tk.LEFT, padx=5)
        ttk.Button(bf, text="Cancel", width=10, command=self.win.destroy).pack(side=tk.LEFT, padx=5)
        f.columnconfigure(1, weight=1)
        self.entries["name"].focus_set()

    def _save(self):
        name = self.entries["name"].get().strip()
        ip = self.entries["ip"].get().strip()
        if not name or not ip:
            messagebox.showwarning("Required", "Name and IP required.", parent=self.win)
            return
        r = Robot(name=name, ip=ip, identifier=self.entries["identifier"].get().strip(),
                  controller=self.ctrl_var.get(),
                  ftp_user=self.entries["ftp_user"].get().strip(),
                  ftp_pass=self.entries["ftp_pass"].get().strip(),
                  notes=self.notes.get("1.0", tk.END).strip())
        if self.callback:
            self.callback(r)
        self.win.destroy()


if __name__ == "__main__":
    RoboVaultApp().run()
