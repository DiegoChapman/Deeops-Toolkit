
import json
import hashlib
import os
import re
import sys
import ipaddress
import socket
import subprocess
import threading
import time
import importlib.util
import html
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

APP_NAME = "DeeOps Toolkit"
APP_VERSION = "1.3"
APP_TAGLINE = "Personal cyber utilities in one place"
APP_TITLE = f"{APP_NAME} v{APP_VERSION}"
SCRIPT_DIR = Path(__file__).resolve().parent
CREDENTIALS_PATH = SCRIPT_DIR / "credentials.json"
CONFIG_PATH = SCRIPT_DIR / "config.json"
LEGACY_CONFIG_PATH = SCRIPT_DIR.parent / "config.json"
LEGACY_CREDENTIALS_PATH = SCRIPT_DIR.parent / "credentials.json"
VAULT_ROOT = SCRIPT_DIR / "Vault"
LOGS_DIR = SCRIPT_DIR / "logs"
RESULTS_DIR = SCRIPT_DIR / "results"
PLUGINS_DIR = SCRIPT_DIR / "plugins"
PROFILES_PATH = SCRIPT_DIR / "profiles.json"
PLUGIN_TRUST_PATH = SCRIPT_DIR / "plugin_trust.json"
CONFIG_VERSION = 2

FAILED_LIMIT = 5
LOCKOUT_SECONDS = 30
HOT_PINK_SELECT_BG = "#ff1493"
HOT_PINK_SELECT_FG = "#111111"

DEFAULT_CONFIG = {
    "config_version": CONFIG_VERSION,
    "theme_name": "RedBlack",
    "bg": "#0B0B0B",
    "panel": "#121212",
    "fg": "#F5F5F5",
    "accent": "#CE1141",
    "select_bg": "#8E0E2A",
    "font_size": 11,
    "font_family_mode": "default",
    "onboarding_seen": False,
    "favorite_tools": [],
    "recent_targets": [],
    "last_tool_state": {
        "tool_name": "Ping",
        "inputs": {
            "target": "127.0.0.1",
            "count": "4",
            "domain": "example.com",
            "port": "80",
            "port_range": "20-1024",
            "permission_confirmed": False,
        },
    },
    "tool_help_visible": True,
}

_DOMAIN_PATTERN = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9.-]+(?<!-)$")
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _hash_password(password: str, salt_bytes: bytes) -> str:
    return hashlib.sha256(salt_bytes + password.encode("utf-8")).hexdigest()


def _normalize_credentials(raw):
    if not isinstance(raw, dict) or not raw:
        return {"schema_version": 2, "users": [], "last_login_user": ""}

    # v1 single-user format migration
    if "users" not in raw:
        if raw.get("username") and raw.get("salt") and raw.get("password_hash"):
            user = {
                "username": str(raw.get("username", "")).strip(),
                "salt": str(raw.get("salt", "")),
                "password_hash": str(raw.get("password_hash", "")),
                "role": "analyst" if str(raw.get("role", "admin")).lower() == "analyst" else "admin",
                "created_at": raw.get("created_at", datetime.now().isoformat(timespec="seconds")),
            }
            return {"schema_version": 2, "users": [user], "last_login_user": user["username"]}
        return {"schema_version": 2, "users": [], "last_login_user": ""}

    users = []
    seen = set()
    for item in raw.get("users", []):
        if not isinstance(item, dict):
            continue
        uname = str(item.get("username", "")).strip()
        if not uname or uname.lower() in seen:
            continue
        seen.add(uname.lower())
        users.append(
            {
                "username": uname,
                "salt": str(item.get("salt", "")),
                "password_hash": str(item.get("password_hash", "")),
                "role": "analyst" if str(item.get("role", "admin")).lower() == "analyst" else "admin",
                "created_at": item.get("created_at", datetime.now().isoformat(timespec="seconds")),
            }
        )

    return {
        "schema_version": 2,
        "users": users,
        "last_login_user": str(raw.get("last_login_user", "")).strip(),
    }


def save_credentials(data):
    normalized = _normalize_credentials(data)
    with open(CREDENTIALS_PATH, "w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=2)


def load_credentials():
    candidate = CREDENTIALS_PATH if CREDENTIALS_PATH.exists() else LEGACY_CREDENTIALS_PATH
    if not candidate.exists():
        return {"schema_version": 2, "users": [], "last_login_user": ""}
    try:
        with open(candidate, "r", encoding="utf-8") as f:
            parsed = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"schema_version": 2, "users": [], "last_login_user": ""}
    normalized = _normalize_credentials(parsed)
    if candidate != CREDENTIALS_PATH:
        try:
            save_credentials(normalized)
        except Exception:
            pass
    return normalized


def list_users():
    data = load_credentials()
    return [u.get("username", "") for u in data.get("users", [])]


def resolve_username(username: str) -> str:
    target = (username or "").strip().lower()
    if not target:
        return ""
    data = load_credentials()
    for user in data.get("users", []):
        stored = str(user.get("username", "")).strip()
        if stored.lower() == target:
            return stored
    return ""


def create_user(username, password, role="admin"):
    if not username or not password:
        raise ValueError("Username and password are required.")
    username = username.strip()
    if not username:
        raise ValueError("Username cannot be blank.")
    data = load_credentials()
    if any(username.lower() == u.get("username", "").lower() for u in data.get("users", [])):
        raise ValueError("Username already exists.")

    salt = os.urandom(16)
    user_obj = {
        "username": username,
        "salt": salt.hex(),
        "password_hash": _hash_password(password, salt),
        "role": "analyst" if str(role).lower() == "analyst" else "admin",
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }
    data["users"].append(user_obj)
    if not data.get("last_login_user"):
        data["last_login_user"] = username
    save_credentials(data)


def verify_user(username, password) -> bool:
    username = (username or "").strip().lower()
    data = load_credentials()
    for user in data.get("users", []):
        stored = str(user.get("username", "")).strip()
        if username != stored.lower():
            continue
        try:
            salt = bytes.fromhex(user.get("salt", ""))
        except ValueError:
            return False
        return _hash_password(password, salt) == user.get("password_hash", "")
    return False


def get_user_role(username) -> str:
    username = (username or "").strip().lower()
    data = load_credentials()
    for user in data.get("users", []):
        stored = str(user.get("username", "")).strip()
        if username == stored.lower():
            role = str(user.get("role", "admin")).lower()
            return "analyst" if role == "analyst" else "admin"
    return "admin"


def save_user_role(username, role: str):
    username = (username or "").strip().lower()
    data = load_credentials()
    changed = False
    for user in data.get("users", []):
        stored = str(user.get("username", "")).strip()
        if username == stored.lower():
            user["role"] = "analyst" if str(role).lower() == "analyst" else "admin"
            changed = True
            break
    if changed:
        save_credentials(data)


def change_user_password(username, current_password, new_password):
    if not new_password:
        raise ValueError("New password cannot be blank.")
    username = (username or "").strip().lower()
    data = load_credentials()
    for user in data.get("users", []):
        stored = str(user.get("username", "")).strip()
        if username != stored.lower():
            continue
        try:
            salt = bytes.fromhex(user.get("salt", ""))
        except ValueError:
            raise ValueError("Stored credentials are invalid.")
        if _hash_password(current_password, salt) != user.get("password_hash", ""):
            raise ValueError("Current password is incorrect.")
        new_salt = os.urandom(16)
        user["salt"] = new_salt.hex()
        user["password_hash"] = _hash_password(new_password, new_salt)
        save_credentials(data)
        return
    raise ValueError("User not found.")


def is_valid_hex_color(value: str) -> bool:
    return bool(re.fullmatch(r"#[0-9a-fA-F]{6}", value or ""))


def is_valid_target_format(value: str) -> bool:
    candidate = (value or "").strip()
    if not candidate:
        return False
    if candidate.lower() == "localhost":
        return True
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        pass
    if ":" in candidate:
        return False
    if candidate.endswith("."):
        candidate = candidate[:-1]
    return bool(_DOMAIN_PATTERN.fullmatch(candidate))


def resolve_target_ips(target: str):
    target = (target or "").strip()
    if not target:
        return []
    if target.lower() == "localhost":
        return [ipaddress.ip_address("127.0.0.1")]
    try:
        return [ipaddress.ip_address(target)]
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(target, None)
    except socket.gaierror:
        return []

    ips = []
    seen = set()
    for info in infos:
        host = info[4][0]
        try:
            ip_obj = ipaddress.ip_address(host)
        except ValueError:
            continue
        if str(ip_obj) not in seen:
            seen.add(str(ip_obj))
            ips.append(ip_obj)
    return ips


def is_private_or_loopback(ip_obj):
    if ip_obj.is_loopback:
        return True
    if ip_obj.version == 4:
        return any(ip_obj in net for net in _PRIVATE_NETS)
    return ip_obj.is_link_local or ip_obj.is_private


def parse_port_value(value: str):
    try:
        port = int((value or "").strip())
    except ValueError:
        return None
    if 1 <= port <= 65535:
        return port
    return None


def parse_port_range(value: str):
    if not value:
        return None
    m = re.fullmatch(r"\s*(\d{1,5})\s*-\s*(\d{1,5})\s*", value)
    if not m:
        return None
    start = int(m.group(1))
    end = int(m.group(2))
    if start < 1 or end > 65535 or start > end:
        return None
    return start, end


class ToolBase:
    tool_id = "base"
    name = "Base Tool"
    description = "Reusable tool base"

    def validate_inputs(self, inputs):
        return True, ""

    def run(self, inputs, cancel_event=None):
        raise NotImplementedError


class PingTool(ToolBase):
    tool_id = "ping"
    name = "Ping"
    description = "Send ICMP echo requests"

    def validate_inputs(self, inputs):
        target = inputs.get("target", "").strip()
        count_raw = inputs.get("count", "4").strip()
        if not is_valid_target_format(target):
            return False, "Invalid target. Use a valid IP or domain."
        try:
            count = int(count_raw)
        except ValueError:
            return False, "Count must be a number."
        if count < 1 or count > 20:
            return False, "Count must be between 1 and 20."
        return True, ""

    def run(self, inputs, cancel_event=None):
        target = inputs.get("target", "").strip()
        count = int(inputs.get("count", "4").strip())
        cmd = ["ping", "-n", str(count), target] if sys.platform.startswith("win") else ["ping", "-c", str(count), target]
        if cancel_event and cancel_event.is_set():
            return "Canceled before execution."
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=20, check=False)
        return (completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else "")


class DnsLookupTool(ToolBase):
    tool_id = "dns_lookup"
    name = "DNS Lookup"
    description = "Resolve A and AAAA records"

    def validate_inputs(self, inputs):
        domain = inputs.get("domain", "").strip()
        if not domain or not _DOMAIN_PATTERN.fullmatch(domain):
            return False, "Invalid domain format."
        return True, ""

    def run(self, inputs, cancel_event=None):
        domain = inputs.get("domain", "").strip()
        if cancel_event and cancel_event.is_set():
            return "Canceled before execution."
        lines = [f"Domain: {domain}"]
        try:
            infos = socket.getaddrinfo(domain, None)
        except socket.gaierror as err:
            return f"DNS lookup failed: {err}"

        v4 = sorted({i[4][0] for i in infos if "." in i[4][0]})
        v6 = sorted({i[4][0] for i in infos if ":" in i[4][0]})

        lines.append("A Records:")
        if v4:
            lines.extend([f"  - {ip}" for ip in v4])
        else:
            lines.append("  - None")

        lines.append("AAAA Records:")
        if v6:
            lines.extend([f"  - {ip}" for ip in v6])
        else:
            lines.append("  - None")
        return "\n".join(lines)


class TracerouteTool(ToolBase):
    tool_id = "traceroute"
    name = "Traceroute"
    description = "Trace route to a target"

    def validate_inputs(self, inputs):
        target = inputs.get("target", "").strip()
        if not is_valid_target_format(target):
            return False, "Invalid target. Use a valid IP or domain."
        return True, ""

    def run(self, inputs, cancel_event=None):
        target = inputs.get("target", "").strip()
        cmd = ["tracert", "-d", target] if sys.platform.startswith("win") else ["traceroute", "-n", target]
        if cancel_event and cancel_event.is_set():
            return "Canceled before execution."
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
        return (completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else "")

class PortCheckTool(ToolBase):
    tool_id = "port_check"
    name = "Port Check"
    description = "Check if a single port is open"

    def validate_inputs(self, inputs):
        target = inputs.get("target", "").strip()
        port_raw = inputs.get("port", "").strip()
        if not is_valid_target_format(target):
            return False, "Invalid target. Use a valid IP or domain."
        if parse_port_value(port_raw) is None:
            return False, "Port must be between 1 and 65535."
        return True, ""

    def run(self, inputs, cancel_event=None):
        target = inputs.get("target", "").strip()
        port = parse_port_value(inputs.get("port", "").strip())
        timeout = 1.5
        start = time.perf_counter()
        try:
            with socket.create_connection((target, port), timeout=timeout):
                elapsed = (time.perf_counter() - start) * 1000
                return f"{target}:{port} -> OPEN ({elapsed:.1f} ms)"
        except (socket.timeout, OSError):
            elapsed = (time.perf_counter() - start) * 1000
            return f"{target}:{port} -> CLOSED ({elapsed:.1f} ms)"


class PortScannerTool(ToolBase):
    tool_id = "port_scanner"
    name = "Port Scanner"
    description = "Threaded port scan for local/authorized targets"

    def validate_inputs(self, inputs):
        target = inputs.get("target", "").strip()
        range_raw = inputs.get("port_range", "").strip()
        confirmed = bool(inputs.get("permission_confirmed"))

        if not is_valid_target_format(target):
            return False, "Invalid target. Use a valid IP or domain."

        port_range = parse_port_range(range_raw)
        if not port_range:
            return False, "Port range must look like 20-1024."

        start_port, end_port = port_range
        if not confirmed and end_port > 1024:
            return False, "Without permission confirmation, max scan port is 1024."

        total = end_port - start_port + 1
        if total > 2000 and not confirmed:
            return False, "Range too large. Confirm permission to run larger scans."

        return True, ""

    def run(self, inputs, cancel_event=None):
        target = inputs.get("target", "").strip()
        start_port, end_port = parse_port_range(inputs.get("port_range", "").strip())
        timeout = 0.45
        ports = list(range(start_port, end_port + 1))
        open_ports = []

        def check_one(port):
            if cancel_event and cancel_event.is_set():
                return None
            try:
                with socket.create_connection((target, port), timeout=timeout):
                    return port
            except (socket.timeout, OSError):
                return None

        worker_count = min(120, max(8, len(ports) // 4))
        scanned = 0
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [executor.submit(check_one, p) for p in ports]
            for fut in as_completed(futures):
                if cancel_event and cancel_event.is_set():
                    break
                scanned += 1
                p = fut.result()
                if p is not None:
                    open_ports.append(p)

        if cancel_event and cancel_event.is_set():
            return f"Scan canceled. Ports checked before cancel: {scanned}"

        open_ports.sort()
        lines = [
            f"Target: {target}",
            f"Range: {start_port}-{end_port}",
            f"Scanned: {len(ports)} ports",
            f"Open ports: {len(open_ports)}",
        ]
        for p in open_ports:
            lines.append(f"  - {p}")
        return "\n".join(lines)


class CyberToolkitApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1150x740")
        self.root.minsize(940, 600)

        cfg = self.load_config()
        self.color_bg = cfg["bg"]
        self.color_panel = cfg["panel"]
        self.color_fg = cfg["fg"]
        self.color_accent = cfg["accent"]
        self.color_select_bg = cfg["select_bg"]
        self.font_size = cfg["font_size"]
        self.font_family_mode = cfg["font_family_mode"]
        self.onboarding_seen = bool(cfg.get("onboarding_seen", False))
        self.favorite_tools = list(cfg.get("favorite_tools", []))
        self.recent_targets = list(cfg.get("recent_targets", []))
        self.last_tool_state = dict(cfg.get("last_tool_state", DEFAULT_CONFIG["last_tool_state"]))
        self.tool_help_visible = bool(cfg.get("tool_help_visible", True))

        self.logs = []
        self.failed_attempts = 0
        self.lockout_remaining = 0
        self.current_user = None
        self.current_role = "admin"
        self.current_panel_name = ""
        self.sidebar_buttons = {}
        self.sidebar_item_to_panel = {}
        self.sidebar_item_to_tool = {}
        self._sidebar_syncing_selection = False
        self.current_vault_path = VAULT_ROOT.resolve()
        self.plugin_status = {}
        self.plugin_trust = self._load_plugin_trust()
        self.saved_profiles = self._load_profiles()
        self.filtered_profile_names = []
        self.command_palette = None
        self.command_listbox = None
        self.toast_label = None
        self.splash_frame = None
        self.splash_canvas = None
        self.splash_logo_outer = None
        self.splash_logo_inner = None
        self.splash_logo_text = None
        self.splash_subtitle_text = None
        self.splash_embers = []
        self.splash_anim_step = 0

        LOGS_DIR.mkdir(exist_ok=True)
        RESULTS_DIR.mkdir(exist_ok=True)
        PLUGINS_DIR.mkdir(exist_ok=True)

        self.tools = {
            "Ping": PingTool(),
            "DNS Lookup": DnsLookupTool(),
            "Traceroute": TracerouteTool(),
            "Port Check": PortCheckTool(),
            "Port Scanner": PortScannerTool(),
        }
        self._load_plugin_tools()
        self.current_tool_worker = None
        self.current_tool_cancel_event = None
        self.current_tool_name = "Ping"
        self.current_tool_started_at = None
        self.tool_menu_display_to_name = {}
        self.status_badges = []

        self.root.configure(bg=self.color_bg)
        self.log("App start")
        self._show_startup_splash()

    def _show_startup_splash(self):
        self.splash_frame = tk.Frame(self.root, bg=self.color_bg)
        self.splash_frame.pack(fill="both", expand=True)
        self.splash_canvas = tk.Canvas(self.splash_frame, highlightthickness=0, bd=0, bg=self.color_bg)
        self.splash_canvas.pack(fill="both", expand=True)
        self.splash_canvas.bind("<Configure>", self._draw_splash_scene)
        self.root.after(40, self._animate_splash_step)

    def _draw_splash_scene(self, _event=None):
        if not self.splash_canvas or not self.splash_canvas.winfo_exists():
            return
        c = self.splash_canvas
        w = max(c.winfo_width(), 1)
        h = max(c.winfo_height(), 1)
        c.delete("all")

        # Dark base + subtle red glow bars for a lightweight "power-on" feel.
        c.create_rectangle(0, 0, w, h, fill=self.color_bg, outline="")
        c.create_rectangle(0, int(h * 0.62), w, h, fill="#13070a", outline="")
        c.create_rectangle(0, int(h * 0.78), w, h, fill="#1b080c", outline="")

        cx, cy = w // 2, int(h * 0.42)
        outer_r = 36 + min(self.splash_anim_step, 18)
        inner_r = max(12, outer_r - 10)
        self.splash_logo_outer = c.create_oval(cx - outer_r, cy - outer_r, cx + outer_r, cy + outer_r, fill=self.color_panel, outline=self.color_accent, width=3)
        self.splash_logo_inner = c.create_oval(cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r, fill=self.color_bg, outline="")
        self.splash_logo_text = c.create_text(cx, cy, text="D", fill=self.color_accent, font=("Segoe UI", max(16, self.font_size + 10), "bold"))
        c.create_text(cx, cy + 72, text=APP_NAME, fill=self.color_fg, font=("Segoe UI", max(14, self.font_size + 6), "bold"))
        self.splash_subtitle_text = c.create_text(cx, cy + 100, text=APP_TAGLINE, fill="#c9c9c9", font=("Segoe UI", max(9, self.font_size - 1), "normal"))

        # Ember dots
        self.splash_embers = []
        for i in range(10):
            ex = int((i + 1) * (w / 11))
            ey = int(h * 0.84 + ((i % 2) * 8))
            dot = c.create_oval(ex - 2, ey - 2, ex + 2, ey + 2, fill=self.color_accent, outline="")
            self.splash_embers.append(dot)

    def _animate_splash_step(self):
        if not self.splash_canvas or not self.splash_canvas.winfo_exists():
            return
        self.splash_anim_step += 1
        self._draw_splash_scene()
        # Pulse embers slightly.
        for idx, dot in enumerate(self.splash_embers):
            if not self.splash_canvas.winfo_exists():
                return
            shift = (self.splash_anim_step + idx) % 6
            self.splash_canvas.move(dot, 0, -0.6 if shift < 3 else 0.6)
        if self.splash_anim_step < 26:
            self.root.after(45, self._animate_splash_step)
        else:
            self.root.after(280, self._finish_startup_from_splash)

    def _finish_startup_from_splash(self):
        if self.splash_frame and self.splash_frame.winfo_exists():
            self.splash_frame.destroy()
        self._build_login_panel()
        self.apply_theme()
        self._show_login_view()

    def load_config(self):
        if not CONFIG_PATH.exists():
            if LEGACY_CONFIG_PATH.exists():
                try:
                    with open(LEGACY_CONFIG_PATH, "r", encoding="utf-8") as f:
                        legacy = json.load(f)
                    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                        json.dump(legacy, f, indent=2)
                except (json.JSONDecodeError, OSError):
                    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                        json.dump(DEFAULT_CONFIG, f, indent=2)
            else:
                with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                    json.dump(DEFAULT_CONFIG, f, indent=2)
            return self.load_config()
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                loaded = json.load(f)
        except (json.JSONDecodeError, OSError):
            loaded = {}
        merged = dict(DEFAULT_CONFIG)
        merged.update({k: v for k, v in loaded.items() if k in merged})
        for key in ("bg", "panel", "fg", "accent", "select_bg"):
            if not is_valid_hex_color(merged[key]):
                merged[key] = DEFAULT_CONFIG[key]
        try:
            merged["font_size"] = int(merged["font_size"])
        except (ValueError, TypeError):
            merged["font_size"] = DEFAULT_CONFIG["font_size"]
        if merged["font_size"] < 10 or merged["font_size"] > 18:
            merged["font_size"] = DEFAULT_CONFIG["font_size"]
        if merged["font_family_mode"] not in ("default", "mono"):
            merged["font_family_mode"] = "default"
        merged["theme_name"] = "RedBlack"
        return merged

    def save_config(self):
        payload = {
            "config_version": CONFIG_VERSION,
            "theme_name": "RedBlack",
            "bg": self.color_bg,
            "panel": self.color_panel,
            "fg": self.color_fg,
            "accent": self.color_accent,
            "select_bg": self.color_select_bg,
            "font_size": self.font_size,
            "font_family_mode": self.font_family_mode,
            "onboarding_seen": self.onboarding_seen,
            "favorite_tools": self.favorite_tools,
            "recent_targets": self.recent_targets,
            "last_tool_state": self.last_tool_state,
            "tool_help_visible": self.tool_help_visible,
        }
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    def _load_profiles(self):
        if not PROFILES_PATH.exists():
            return {}
        try:
            with open(PROFILES_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_profiles(self):
        with open(PROFILES_PATH, "w", encoding="utf-8") as f:
            json.dump(self.saved_profiles, f, indent=2)

    def _load_plugin_trust(self):
        if not PLUGIN_TRUST_PATH.exists():
            return {}
        try:
            with open(PLUGIN_TRUST_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_plugin_trust(self):
        with open(PLUGIN_TRUST_PATH, "w", encoding="utf-8") as f:
            json.dump(self.plugin_trust, f, indent=2)

    def _file_sha256(self, path: Path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def _font(self, offset=0, bold=False):
        family = "Consolas" if self.font_family_mode == "mono" else "Segoe UI"
        weight = "bold" if bold else "normal"
        return (family, self.font_size + offset, weight)

    def apply_theme(self):
        self.root.configure(bg=self.color_bg)
        try:
            self.root.tk_setPalette(
                background=self.color_bg,
                foreground=self.color_fg,
                activeBackground=self.color_accent,
                activeForeground=self.color_fg,
                selectBackground=self.color_select_bg,
                selectForeground=self.color_fg,
            )
        except tk.TclError:
            pass

        if hasattr(self, "theme_widgets"):
            for w in self.theme_widgets:
                self._style_widget(w)

        if hasattr(self, "sidebar_tree") and self.sidebar_tree.winfo_exists():
            self._style_sidebar_tree()
            self._sync_sidebar_selection()
        if hasattr(self, "sidebar_accent_line") and self.sidebar_accent_line.winfo_exists():
            self.sidebar_accent_line.configure(bg=self.color_accent)
        if hasattr(self, "brand_logo_canvas") and self.brand_logo_canvas.winfo_exists():
            self._draw_brand_logo()
        self._style_status_badges()

    def _style_widget(self, widget):
        if not widget or not widget.winfo_exists():
            return
        cls = widget.winfo_class()
        try:
            if cls in ("Frame", "Labelframe"):
                widget.configure(bg=self.color_panel)
            elif cls == "Label":
                parent_bg = self.color_bg
                try:
                    parent_bg = widget.master.cget("bg")
                except Exception:
                    pass
                widget.configure(bg=parent_bg, fg=self.color_fg, font=self._font())
            elif cls == "Button":
                widget.configure(
                    bg=self.color_panel,
                    fg=self.color_fg,
                    activebackground=self.color_accent,
                    activeforeground=self.color_fg,
                    relief="flat",
                    bd=1,
                    highlightthickness=1,
                    highlightbackground=self.color_accent,
                    highlightcolor=self.color_accent,
                    cursor="hand2",
                    font=self._font(),
                )
                widget.bind("<Enter>", lambda _e, w=widget: w.configure(bg=self.color_select_bg))
                widget.bind("<Leave>", lambda _e, w=widget: w.configure(bg=self.color_panel))
            elif cls == "Entry":
                widget.configure(
                    bg=self.color_panel,
                    fg=self.color_fg,
                    insertbackground=self.color_fg,
                    selectbackground=self.color_select_bg,
                    selectforeground=self.color_fg,
                    relief="flat",
                    bd=1,
                    highlightthickness=1,
                    highlightbackground=self.color_accent,
                    highlightcolor=self.color_accent,
                    font=self._font(),
                )
            elif cls == "Listbox":
                widget.configure(
                    bg=self.color_panel,
                    fg=self.color_fg,
                    selectbackground=self.color_select_bg,
                    selectforeground=self.color_fg,
                    relief="flat",
                    bd=1,
                    highlightthickness=1,
                    highlightbackground=self.color_accent,
                    highlightcolor=self.color_accent,
                    font=("Consolas", self.font_size),
                )
            elif cls == "Text":
                widget.configure(
                    bg=self.color_panel,
                    fg=self.color_fg,
                    insertbackground=self.color_fg,
                    selectbackground=self.color_select_bg,
                    selectforeground=self.color_fg,
                    relief="flat",
                    bd=1,
                    highlightthickness=1,
                    highlightbackground=self.color_accent,
                    highlightcolor=self.color_accent,
                    font=("Consolas", self.font_size),
                )
            elif cls == "Canvas":
                widget.configure(bg=self.color_panel, highlightthickness=0, bd=0)
            elif cls == "Scale":
                widget.configure(bg=self.color_bg, fg=self.color_fg, troughcolor=self.color_panel, activebackground=self.color_accent, highlightthickness=0, font=self._font())
            elif cls == "Radiobutton":
                widget.configure(bg=self.color_bg, fg=self.color_fg, selectcolor=self.color_panel, activebackground=self.color_bg, activeforeground=self.color_fg, font=self._font())
            elif cls == "Checkbutton":
                widget.configure(bg=self.color_bg, fg=self.color_fg, selectcolor=self.color_panel, activebackground=self.color_bg, activeforeground=self.color_fg, font=self._font())
            elif cls == "Menubutton":
                widget.configure(
                    bg=self.color_panel,
                    fg=self.color_fg,
                    activebackground=self.color_accent,
                    activeforeground=self.color_fg,
                    relief="flat",
                    bd=1,
                    highlightthickness=1,
                    highlightbackground=self.color_accent,
                    highlightcolor=self.color_accent,
                    cursor="hand2",
                    font=self._font(),
                )
        except tk.TclError:
            pass

    def _style_sidebar_tree(self):
        style = ttk.Style()
        style.configure(
            "CyberNav.Treeview",
            background=self.color_panel,
            fieldbackground=self.color_panel,
            foreground=self.color_fg,
            borderwidth=1,
            relief="solid",
            rowheight=max(24, self.font_size + 14),
            font=self._font(),
        )
        style.map(
            "CyberNav.Treeview",
            background=[("selected", self.color_select_bg)],
            foreground=[("selected", self.color_fg)],
        )
        style.configure("CyberNav.Treeview.Heading", font=self._font(0, True))
        self.sidebar_tree.configure(style="CyberNav.Treeview")

    def _style_status_badges(self):
        if not self.status_badges:
            return
        for badge in self.status_badges:
            if badge and badge.winfo_exists():
                badge.configure(
                    bg=self.color_panel,
                    fg=self.color_fg,
                    relief="solid",
                    bd=1,
                    highlightthickness=1,
                    highlightbackground=self.color_accent,
                    highlightcolor=self.color_accent,
                    padx=8,
                    pady=2,
                    font=self._font(0, True),
                )

    def log(self, message):
        line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}"
        self.logs.append(line)
        if hasattr(self, "logs_text") and self.logs_text.winfo_exists():
            self.logs_text.configure(state="normal")
            self.logs_text.insert("end", line + "\n")
            self.logs_text.see("end")
            self.logs_text.configure(state="disabled")

    def _ensure_toast_label(self):
        if self.toast_label and self.toast_label.winfo_exists():
            return
        self.toast_label = tk.Label(self.root, text="", padx=10, pady=6, bd=1, relief="solid")
        self.theme_widgets.append(self.toast_label)
        self.toast_label.place_forget()

    def _show_toast(self, text, is_error=False):
        self._ensure_toast_label()
        self.toast_label.config(
            text=text,
            bg="#3b0a14" if is_error else self.color_panel,
            fg="#ff8f8f" if is_error else self.color_fg,
            highlightthickness=1,
            highlightbackground=self.color_accent,
            highlightcolor=self.color_accent,
        )
        self.toast_label.place(relx=1.0, x=-16, y=14, anchor="ne")
        self.root.after(2200, lambda: self.toast_label.place_forget())

    def _open_command_palette(self, _event=None):
        if self.command_palette and self.command_palette.winfo_exists():
            self.command_palette.lift()
            return "break"
        self.command_palette = tk.Toplevel(self.root)
        self.command_palette.title("Command Palette")
        self.command_palette.transient(self.root)
        self.command_palette.geometry("420x320")
        self.command_palette.configure(bg=self.color_panel)
        self.command_palette.bind("<Escape>", lambda _e: self.command_palette.destroy())

        commands = [
            ("Go: Files", self._show_files_panel),
            ("Go: Network Tools", self._show_tools_panel),
            ("Go: Results", self._show_results_panel),
            ("Go: Plugins", self._show_plugins_panel),
            ("Go: Logs", self._show_logs_panel),
            ("Go: Settings", self._show_settings_panel),
            ("Quick Workflow: DNS -> Ping -> Traceroute", self._run_quick_workflow),
            ("Tools: Open Results Folder", self._open_results_folder),
        ]
        self.palette_commands = commands
        self.command_listbox = tk.Listbox(self.command_palette, activestyle="none")
        self.command_listbox.pack(fill="both", expand=True, padx=12, pady=12)
        for title, _fn in commands:
            self.command_listbox.insert("end", title)
        self._style_widget(self.command_listbox)
        self.command_listbox.bind("<Return>", self._run_command_palette_selection)
        self.command_listbox.bind("<Double-1>", self._run_command_palette_selection)
        self.command_listbox.selection_set(0)
        self.command_listbox.focus_set()
        return "break"

    def _run_command_palette_selection(self, _event=None):
        if not self.command_listbox or not self.command_listbox.curselection():
            return "break"
        idx = self.command_listbox.curselection()[0]
        if idx >= len(self.palette_commands):
            return "break"
        _title, fn = self.palette_commands[idx]
        if self.command_palette and self.command_palette.winfo_exists():
            self.command_palette.destroy()
        fn()
        return "break"

    def _run_quick_workflow(self):
        self._show_tools_panel(selected_tool="DNS Lookup")
        self._show_toast("Quick workflow: start with DNS Lookup, then Ping, then Traceroute.")

    def _mark_onboarding_seen(self):
        self.onboarding_seen = True
        try:
            self.save_config()
        except Exception:
            pass

    def _show_onboarding_popup(self):
        if hasattr(self, "onboarding_popup") and self.onboarding_popup and self.onboarding_popup.winfo_exists():
            self.onboarding_popup.lift()
            return
        self.onboarding_popup = tk.Toplevel(self.root)
        self.onboarding_popup.title(f"Welcome to {APP_NAME}")
        self.onboarding_popup.transient(self.root)
        self.onboarding_popup.grab_set()
        self.onboarding_popup.geometry("540x430")
        self.onboarding_popup.configure(bg=self.color_panel)
        self.onboarding_popup.protocol("WM_DELETE_WINDOW", self._close_onboarding_popup)

        wrap = tk.Frame(self.onboarding_popup, padx=14, pady=14)
        wrap.pack(fill="both", expand=True)
        self._style_widget(wrap)

        title = tk.Label(wrap, text="Quick Start (First Time)", font=self._font(2, True), anchor="w")
        title.pack(fill="x", pady=(0, 10))
        self._style_widget(title)

        body = tk.Text(wrap, height=16, wrap="word", relief="flat")
        body.pack(fill="both", expand=True)
        body.insert(
            "end",
            "1) Use sidebar to switch panels.\n"
            "2) Start in Network Tools.\n"
            "3) Pick tool, enter values, click Run.\n"
            "4) Check output + status line.\n"
            "5) Open Results to view saved runs.\n"
            "6) Use Profiles to save repeat tool setups.\n"
            "7) Open Plugins to trust/reload plugin tools.\n"
            "8) Open Settings for users, role, password, theme.\n\n"
            "Tips:\n"
            "- Press Ctrl+K for command palette.\n"
            "- Use only authorized targets.\n"
            "- README.md has full beginner guide.",
        )
        body.configure(state="disabled")
        self._style_widget(body)

        actions = tk.Frame(wrap)
        actions.pack(fill="x", pady=(10, 0))
        self._style_widget(actions)
        open_tools = tk.Button(actions, text="Open Network Tools", width=16, command=lambda: self._onboarding_jump("tools"))
        open_tools.pack(side="left", padx=(0, 8))
        open_readme = tk.Button(actions, text="Open README", width=12, command=lambda: self._onboarding_jump("readme"))
        open_readme.pack(side="left", padx=(0, 8))
        done = tk.Button(actions, text="Got It", width=10, command=self._close_onboarding_popup)
        done.pack(side="right")
        self._style_widget(open_tools)
        self._style_widget(open_readme)
        self._style_widget(done)

    def _onboarding_jump(self, action):
        if action == "tools":
            self._show_tools_panel()
        elif action == "readme":
            readme = SCRIPT_DIR / "README.md"
            try:
                if sys.platform.startswith("win"):
                    os.startfile(str(readme))
                elif sys.platform == "darwin":
                    subprocess.run(["open", str(readme)], check=False)
                else:
                    subprocess.run(["xdg-open", str(readme)], check=False)
            except Exception:
                pass
        self._close_onboarding_popup()

    def _close_onboarding_popup(self):
        self._mark_onboarding_seen()
        if hasattr(self, "onboarding_popup") and self.onboarding_popup and self.onboarding_popup.winfo_exists():
            self.onboarding_popup.destroy()

    def _load_plugin_tools(self):
        # Remove previously loaded plugin tools before reloading.
        builtins = {"Ping", "DNS Lookup", "Traceroute", "Port Check", "Port Scanner"}
        self.tools = {name: tool for name, tool in self.tools.items() if name in builtins}
        self.plugin_status = {}

        plugin_files = sorted(PLUGINS_DIR.glob("*.py"))
        if not plugin_files:
            return
        for plugin_file in plugin_files:
            plugin_key = plugin_file.name
            try:
                digest = self._file_sha256(plugin_file)
                trust_info = self.plugin_trust.get(plugin_key, {})
                trusted = bool(trust_info.get("trusted", False))
                if trust_info.get("sha256") != digest:
                    trusted = False
                if plugin_key not in self.plugin_trust:
                    # First discovery defaults to trusted for smoother UX.
                    trusted = True
                self.plugin_trust[plugin_key] = {"trusted": trusted, "sha256": digest}
                if not trusted:
                    self.plugin_status[plugin_key] = "blocked (untrusted)"
                    continue

                mod_name = f"mct_plugin_{plugin_file.stem}"
                spec = importlib.util.spec_from_file_location(mod_name, str(plugin_file))
                if spec is None or spec.loader is None:
                    self.plugin_status[plugin_key] = "invalid spec"
                    continue
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                if not hasattr(module, "register_tools"):
                    self.plugin_status[plugin_key] = "missing register_tools"
                    continue
                loaded = module.register_tools(ToolBase)
                candidates = loaded if isinstance(loaded, list) else [loaded]
                loaded_count = 0
                for tool in candidates:
                    if not isinstance(tool, ToolBase):
                        continue
                    name = str(getattr(tool, "name", "")).strip()
                    if not name:
                        continue
                    self.tools[name] = tool
                    loaded_count += 1
                self.plugin_status[plugin_key] = f"loaded ({loaded_count} tools)"
                self.log(f"Plugin loaded: {plugin_file.name}")
            except Exception as err:
                self.log(f"Plugin load failed: {plugin_file.name} ({err})")
                self.plugin_status[plugin_key] = f"error: {err}"
        self._save_plugin_trust()

    def _bind_login_keys(self):
        self.username_entry.bind("<Return>", self._on_login_enter)
        self.password_entry.bind("<Return>", self._on_login_enter)
        self.username_entry.bind("<KP_Enter>", self._on_login_enter)
        self.password_entry.bind("<KP_Enter>", self._on_login_enter)
        self.username_entry.bind("<Tab>", self._on_username_tab)

    def _unbind_login_keys(self):
        self.username_entry.unbind("<Return>")
        self.password_entry.unbind("<Return>")
        self.username_entry.unbind("<KP_Enter>")
        self.password_entry.unbind("<KP_Enter>")
        self.username_entry.unbind("<Tab>")

    def _on_username_tab(self, _event=None):
        self.password_entry.focus_set()
        return "break"

    def _on_login_enter(self, _event=None):
        self._handle_login()
        return "break"

    def _build_login_panel(self):
        self.login_frame = tk.Frame(self.root)
        self.login_frame.pack(fill="both", expand=True)
        self.login_card = tk.Frame(self.login_frame, padx=24, pady=24)
        self.login_card.place(relx=0.5, rely=0.5, anchor="center")

        self.login_title = tk.Label(self.login_card, text=APP_TITLE, font=self._font(7, True))
        self.login_title.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))
        self.login_header = tk.Label(self.login_card, text=">> AUTHENTICATION PANEL", font=self._font(0, True))
        self.login_header.grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 10))

        tk.Label(self.login_card, text="Username").grid(row=2, column=0, sticky="w")
        self.username_entry = tk.Entry(self.login_card, width=34)
        self.username_entry.grid(row=3, column=0, columnspan=2, sticky="we", pady=(4, 10))
        tk.Label(self.login_card, text="Password").grid(row=4, column=0, sticky="w")
        self.password_entry = tk.Entry(self.login_card, width=34, show="*")
        self.password_entry.grid(row=5, column=0, columnspan=2, sticky="we", pady=(4, 12))

        self.login_button = tk.Button(self.login_card, text="Login", command=self._handle_login, width=12)
        self.login_button.grid(row=6, column=0, sticky="w")
        self.create_admin_button = tk.Button(self.login_card, text="Create Admin", command=self._show_setup_view, width=14)
        self.create_admin_button.grid(row=6, column=1, sticky="e")

        self.status_label = tk.Label(self.login_card, text="")
        self.status_label.grid(row=7, column=0, columnspan=2, sticky="w", pady=(12, 0))
        self.setup_frame = tk.Frame(self.login_card)
        tk.Label(self.setup_frame, text=">> FIRST-TIME SETUP", font=self._font(0, True)).grid(row=0, column=0, columnspan=2, sticky="w", pady=(12, 8))
        tk.Label(self.setup_frame, text="New username").grid(row=1, column=0, sticky="w")
        self.setup_username_entry = tk.Entry(self.setup_frame)
        self.setup_username_entry.grid(row=2, column=0, columnspan=2, sticky="we", pady=(4, 8))
        tk.Label(self.setup_frame, text="New password").grid(row=3, column=0, sticky="w")
        self.setup_password_entry = tk.Entry(self.setup_frame, show="*")
        self.setup_password_entry.grid(row=4, column=0, columnspan=2, sticky="we", pady=(4, 8))
        tk.Label(self.setup_frame, text="Confirm password").grid(row=5, column=0, sticky="w")
        self.setup_confirm_entry = tk.Entry(self.setup_frame, show="*")
        self.setup_confirm_entry.grid(row=6, column=0, columnspan=2, sticky="we", pady=(4, 10))
        self.setup_create_button = tk.Button(self.setup_frame, text="Save Admin", command=self._create_admin, width=14)
        self.setup_create_button.grid(row=7, column=0, sticky="w")
        self.setup_cancel_button = tk.Button(self.setup_frame, text="Cancel", command=self._hide_setup_view, width=10)
        self.setup_cancel_button.grid(row=7, column=1, sticky="e")

        self._bind_login_keys()

        self.theme_widgets = list(self.login_card.winfo_children()) + [
            self.login_frame,
            self.login_card,
            self.setup_frame,
            self.login_title,
            self.login_header,
            self.status_label,
        ]

    def _show_login_view(self):
        if list_users():
            self._hide_setup_view()
            self.create_admin_button.config(state="normal")
            self.status_label.config(text="Enter your credentials.", fg=self.color_fg)
            self.username_entry.focus_set()
        else:
            self._show_setup_view(auto=True)
            self.create_admin_button.config(state="disabled")
            self.status_label.config(text="No admin found. Complete first-time setup.", fg="#ff8080")
        self.username_entry.delete(0, "end")
        self.password_entry.delete(0, "end")
        self._bind_login_keys()
        self.username_entry.focus_set()

    def _show_setup_view(self, auto=False):
        self.setup_frame.grid(row=8, column=0, columnspan=2, sticky="we", pady=(10, 0))
        self.setup_username_entry.delete(0, "end")
        self.setup_password_entry.delete(0, "end")
        self.setup_confirm_entry.delete(0, "end")
        self.setup_username_entry.insert(0, "Dee")
        self.setup_password_entry.insert(0, "0218")
        self.setup_confirm_entry.insert(0, "0218")
        self.setup_cancel_button.config(state="disabled" if auto else "normal")
        if auto:
            self.log("First-time setup panel displayed")

    def _hide_setup_view(self):
        self.setup_frame.grid_remove()

    def _create_admin(self):
        username = self.setup_username_entry.get().strip()
        password = self.setup_password_entry.get()
        confirm = self.setup_confirm_entry.get()
        if not username or not password:
            self.status_label.config(text="Username and password are required.", fg="#ff8080")
            return
        if password != confirm:
            self.status_label.config(text="Passwords do not match.", fg="#ff8080")
            return
        try:
            create_user(username, password)
            self.status_label.config(text="Admin created. You can login now.", fg="#7dff9b")
            self._hide_setup_view()
            self.create_admin_button.config(state="normal")
            self.log(f"Setup created for user '{username}'")
        except Exception as err:
            self.status_label.config(text=f"Setup failed: {err}", fg="#ff8080")

    def _handle_login(self):
        if self.lockout_remaining > 0:
            self.password_entry.focus_set()
            return
        username_input = self.username_entry.get().strip()
        password = self.password_entry.get()
        if verify_user(username_input, password):
            username = resolve_username(username_input) or username_input
            self.failed_attempts = 0
            self.current_user = username
            self.current_role = get_user_role(username)
            creds = load_credentials()
            creds["last_login_user"] = username
            save_credentials(creds)
            self.log(f"Login success for user '{username}'")
            self._unbind_login_keys()
            self._show_main_shell()
            return
        self.failed_attempts += 1
        left = max(FAILED_LIMIT - self.failed_attempts, 0)
        self.status_label.config(text=f"Invalid login. Attempts left: {left}", fg="#ff8080")
        self.log(f"Login failure for user '{username_input or '<blank>'}'")
        self.password_entry.focus_set()
        self.password_entry.selection_range(0, "end")
        if self.failed_attempts >= FAILED_LIMIT:
            self._start_lockout()

    def _start_lockout(self):
        self.lockout_remaining = LOCKOUT_SECONDS
        self.login_button.config(state="disabled")
        self.log("Lockout started")
        self._tick_lockout()

    def _tick_lockout(self):
        if self.lockout_remaining <= 0:
            self.failed_attempts = 0
            self.login_button.config(state="normal")
            self.status_label.config(text="Lockout ended. Try again.", fg="#7dff9b")
            self.log("Lockout ended")
            self.password_entry.focus_set()
            return
        self.status_label.config(text=f"Too many failed attempts. Try again in {self.lockout_remaining}s", fg="#ff8080")
        self.lockout_remaining -= 1
        self.root.after(1000, self._tick_lockout)

    def _show_main_shell(self):
        self.login_frame.pack_forget()
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(fill="both", expand=True)

        self.main_body = tk.Frame(self.main_frame)
        self.main_body.pack(fill="both", expand=True)

        self.sidebar = tk.Frame(self.main_body, width=200)
        self.sidebar.pack(side="left", fill="y")

        self.brand_header_wrap = tk.Frame(self.sidebar)
        self.brand_header_wrap.pack(fill="x", padx=12, pady=(14, 2))
        self.brand_logo_canvas = tk.Canvas(self.brand_header_wrap, width=22, height=22, highlightthickness=0, bd=0)
        self.brand_logo_canvas.pack(side="left", padx=(0, 8))
        brand_text_wrap = tk.Frame(self.brand_header_wrap)
        brand_text_wrap.pack(side="left", fill="x", expand=True)
        self.sidebar_header = tk.Label(brand_text_wrap, text="DeeOps Toolkit", anchor="w", font=self._font(1, True))
        self.sidebar_header.pack(fill="x")
        self.sidebar_subtitle = tk.Label(self.sidebar, text="Cyber Toolkit", anchor="w", font=self._font(0, False))
        self.sidebar_subtitle.pack(fill="x", padx=12, pady=(0, 4))
        self.sidebar_accent_line = tk.Frame(self.sidebar, height=1)
        self.sidebar_accent_line.pack(fill="x", padx=12, pady=(0, 8))
        self._draw_brand_logo()
        self.sidebar_user = tk.Label(self.sidebar, text=f"User: {self.current_user}", anchor="w")
        self.sidebar_user.pack(fill="x", padx=12, pady=(0, 12))

        self.sidebar_tree_wrap = tk.Frame(self.sidebar)
        self.sidebar_tree_wrap.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.sidebar_tree = ttk.Treeview(self.sidebar_tree_wrap, show="tree", selectmode="browse")
        self.sidebar_tree.pack(side="left", fill="both", expand=True)
        self.sidebar_tree_scroll = tk.Scrollbar(self.sidebar_tree_wrap, command=self.sidebar_tree.yview)
        self.sidebar_tree_scroll.pack(side="right", fill="y")
        self.sidebar_tree.configure(yscrollcommand=self.sidebar_tree_scroll.set)
        self._build_sidebar_tree()
        self.sidebar_tree.bind("<<TreeviewSelect>>", self._on_sidebar_select)
        self.sidebar_tree.bind("<Return>", self._on_sidebar_activate)
        self.sidebar_tree.bind("<Double-1>", self._on_sidebar_double_click)

        self.logout_button = tk.Button(self.sidebar, text="Logout", command=self._logout, relief="flat", anchor="w", padx=14, pady=8, bd=0)
        self.logout_button.pack(fill="x", padx=10, pady=(0, 12))

        self.content_host = tk.Frame(self.main_body)
        self.content_host.pack(side="left", fill="both", expand=True)

        self.files_panel = tk.Frame(self.content_host)
        self.tools_panel = tk.Frame(self.content_host)
        self.results_panel = tk.Frame(self.content_host)
        self.plugins_panel = tk.Frame(self.content_host)
        self.logs_panel = tk.Frame(self.content_host)
        self.settings_panel = tk.Frame(self.content_host)

        self._build_files_panel()
        self._build_tools_panel()
        self._build_results_panel()
        self._build_plugins_panel()
        self._build_logs_panel()
        self._build_settings_panel()
        self._build_status_bar()

        self.theme_widgets.extend([
            self.main_frame, self.main_body, self.sidebar, self.brand_header_wrap, self.brand_logo_canvas, self.sidebar_header, self.sidebar_subtitle, self.sidebar_accent_line, self.sidebar_user,
            self.sidebar_tree_wrap, self.sidebar_tree, self.logout_button,
            self.content_host, self.files_panel, self.tools_panel, self.results_panel, self.plugins_panel, self.logs_panel, self.settings_panel,
            self.status_bar, self.status_user_label, self.status_user_value,
            self.status_role_label, self.status_role_value,
            self.status_panel_label, self.status_panel_value,
            self.status_time_label, self.status_time_value,
        ])
        self.apply_theme()
        self._refresh_tool_dropdown()
        self.set_active_panel("Files")
        self._enforce_role_permissions()
        self.root.bind("<Control-k>", self._open_command_palette)
        self._bind_main_shortcuts()
        self._ensure_toast_label()
        self._tick_clock()
        if not self.onboarding_seen:
            self.root.after(350, self._show_onboarding_popup)

    def _draw_brand_logo(self):
        if not hasattr(self, "brand_logo_canvas") or not self.brand_logo_canvas.winfo_exists():
            return
        c = self.brand_logo_canvas
        c.delete("all")
        c.configure(bg=self.color_panel)
        # Simple mark: red ring + dark core + D glyph.
        c.create_oval(1, 1, 21, 21, outline=self.color_accent, width=2, fill=self.color_panel)
        c.create_oval(5, 5, 17, 17, outline="", fill=self.color_bg)
        c.create_text(11, 11, text="D", fill=self.color_accent, font=("Segoe UI", max(8, self.font_size - 1), "bold"))

    def _build_status_bar(self):
        self.status_bar = tk.Frame(self.main_frame)
        self.status_bar.pack(fill="x", side="bottom")
        self.status_user_label = tk.Label(self.status_bar, text="USER:", anchor="w", font=self._font(0, True))
        self.status_user_label.pack(side="left", padx=(10, 4))
        self.status_user_value = tk.Label(self.status_bar, text=self.current_user or "-", anchor="w")
        self.status_user_value.pack(side="left", padx=(0, 14))
        self.status_role_label = tk.Label(self.status_bar, text="ROLE:", anchor="w", font=self._font(0, True))
        self.status_role_label.pack(side="left", padx=(0, 4))
        self.status_role_value = tk.Label(self.status_bar, text=(self.current_role or "admin").upper(), anchor="w")
        self.status_role_value.pack(side="left", padx=(0, 14))
        self.status_panel_label = tk.Label(self.status_bar, text="PANEL:", anchor="w", font=self._font(0, True))
        self.status_panel_label.pack(side="left", padx=(0, 4))
        self.status_panel_value = tk.Label(self.status_bar, text="-", anchor="w")
        self.status_panel_value.pack(side="left", padx=(0, 14))
        self.status_time_label = tk.Label(self.status_bar, text="TIME:", anchor="w", font=self._font(0, True))
        self.status_time_label.pack(side="left", padx=(0, 4))
        self.status_time_value = tk.Label(self.status_bar, text="-", anchor="w")
        self.status_time_value.pack(side="left")
        self.status_badges = [self.status_user_value, self.status_role_value, self.status_panel_value, self.status_time_value]
        self._style_status_badges()

    def _bind_main_shortcuts(self):
        self.root.bind("<Control-r>", self._shortcut_run_tool)
        self.root.bind("<Control-l>", self._shortcut_clear_output)
        self.root.bind("<Control-Shift-C>", self._shortcut_copy_output)
        self.root.bind("<Control-Shift-c>", self._shortcut_copy_output)

    def _unbind_main_shortcuts(self):
        self.root.unbind("<Control-r>")
        self.root.unbind("<Control-l>")
        self.root.unbind("<Control-Shift-C>")
        self.root.unbind("<Control-Shift-c>")

    def _shortcut_run_tool(self, _event=None):
        if hasattr(self, "run_tool_button") and self.current_panel_name == "Network Tools":
            self._run_selected_tool()
            return "break"

    def _shortcut_clear_output(self, _event=None):
        if hasattr(self, "tool_output_text") and self.current_panel_name == "Network Tools":
            self._clear_tool_output()
            return "break"

    def _shortcut_copy_output(self, _event=None):
        if hasattr(self, "tool_output_text") and self.current_panel_name == "Network Tools":
            self._copy_tool_output()
            return "break"

    def _tick_clock(self):
        if hasattr(self, "status_time_value") and self.status_time_value.winfo_exists():
            self.status_time_value.config(text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            self.root.after(1000, self._tick_clock)

    def _build_sidebar_tree(self):
        self.sidebar_tree.delete(*self.sidebar_tree.get_children())
        self.sidebar_item_to_panel = {}
        self.sidebar_item_to_tool = {}

        files_id = self.sidebar_tree.insert("", "end", text="📁 Files", open=False)
        net_id = self.sidebar_tree.insert("", "end", text="🛰 Network Tools", open=True)
        results_id = self.sidebar_tree.insert("", "end", text="📊 Results", open=False)
        plugins_id = self.sidebar_tree.insert("", "end", text="🧩 Plugins", open=False)
        logs_id = self.sidebar_tree.insert("", "end", text="📝 Logs", open=False)
        settings_id = self.sidebar_tree.insert("", "end", text="⚙ Settings", open=False)
        about_id = self.sidebar_tree.insert("", "end", text="ℹ About", open=False)

        ping_id = self.sidebar_tree.insert(net_id, "end", text="📡 Ping")
        dns_id = self.sidebar_tree.insert(net_id, "end", text="🌐 DNS Lookup")
        trace_id = self.sidebar_tree.insert(net_id, "end", text="🧭 Traceroute")
        check_id = self.sidebar_tree.insert(net_id, "end", text="🔌 Port Check")
        scan_id = self.sidebar_tree.insert(net_id, "end", text="🧪 Port Scan")

        self.sidebar_item_to_panel = {
            files_id: "Files",
            net_id: "Network Tools",
            results_id: "Results",
            plugins_id: "Plugins",
            logs_id: "Logs",
            settings_id: "Settings",
            about_id: "About",
            ping_id: "Network Tools",
            dns_id: "Network Tools",
            trace_id: "Network Tools",
            check_id: "Network Tools",
            scan_id: "Network Tools",
        }
        self.sidebar_item_to_tool = {
            ping_id: "Ping",
            dns_id: "DNS Lookup",
            trace_id: "Traceroute",
            check_id: "Port Check",
            scan_id: "Port Scanner",
        }
        self.sidebar_network_parent_id = net_id

    def _on_sidebar_select(self, _event=None):
        if self._sidebar_syncing_selection:
            return
        sel = self.sidebar_tree.selection()
        if not sel:
            return
        item_id = sel[0]
        tool_name = self.sidebar_item_to_tool.get(item_id)
        if tool_name:
            if self.current_panel_name == "Network Tools" and self.current_tool_name == tool_name:
                return
            self._show_tools_panel(selected_tool=tool_name)
            return
        panel = self.sidebar_item_to_panel.get(item_id)
        if panel == self.current_panel_name:
            return
        if panel == "Files":
            self._show_files_panel()
        elif panel == "Network Tools":
            self._show_tools_panel()
        elif panel == "Results":
            self._show_results_panel()
        elif panel == "Plugins":
            self._show_plugins_panel()
        elif panel == "Logs":
            self._show_logs_panel()
        elif panel == "Settings":
            self._show_settings_panel()
        elif panel == "About":
            self._show_about_dialog()

    def _on_sidebar_activate(self, _event=None):
        self._on_sidebar_select()
        return "break"

    def _on_sidebar_double_click(self, _event=None):
        item_id = self.sidebar_tree.focus()
        if item_id == getattr(self, "sidebar_network_parent_id", None):
            self.sidebar_tree.item(item_id, open=not self.sidebar_tree.item(item_id, "open"))
            return "break"

    def _sync_sidebar_selection(self):
        if not hasattr(self, "sidebar_tree") or not self.sidebar_tree.winfo_exists():
            return
        target_id = None
        if self.current_panel_name == "Network Tools":
            for iid, tool_name in self.sidebar_item_to_tool.items():
                if tool_name == self.current_tool_name:
                    target_id = iid
                    break
            if target_id is None:
                target_id = getattr(self, "sidebar_network_parent_id", None)
                if target_id:
                    self.sidebar_tree.item(target_id, open=True)
        else:
            for iid, panel_name in self.sidebar_item_to_panel.items():
                if panel_name == self.current_panel_name and iid not in self.sidebar_item_to_tool:
                    target_id = iid
                    break
        if target_id:
            self._sidebar_syncing_selection = True
            try:
                self.sidebar_tree.selection_set(target_id)
                self.sidebar_tree.focus(target_id)
                self.sidebar_tree.see(target_id)
            finally:
                self._sidebar_syncing_selection = False

    def set_active_panel(self, name):
        for panel in (self.files_panel, self.tools_panel, self.results_panel, self.plugins_panel, self.logs_panel, self.settings_panel):
            panel.pack_forget()
        {
            "Files": self.files_panel,
            "Network Tools": self.tools_panel,
            "Results": self.results_panel,
            "Plugins": self.plugins_panel,
            "Logs": self.logs_panel,
            "Settings": self.settings_panel,
        }[name].pack(fill="both", expand=True)
        self.current_panel_name = name
        self.status_panel_value.config(text=name)
        self._sync_sidebar_selection()

    def _build_files_panel(self):
        VAULT_ROOT.mkdir(exist_ok=True)
        self.files_header = tk.Label(self.files_panel, text=">> VAULT FILES", anchor="w", font=self._font(2, True))
        self.files_header.pack(fill="x", padx=12, pady=(12, 8))

        top = tk.Frame(self.files_panel)
        top.pack(fill="x", padx=12, pady=(0, 8))
        self.back_button = tk.Button(top, text="Back", command=self._go_back, width=10)
        self.back_button.pack(side="left")
        self.path_label = tk.Label(top, text="", anchor="w")
        self.path_label.pack(side="left", padx=(12, 0), fill="x", expand=True)

        browser = tk.Frame(self.files_panel)
        browser.pack(fill="both", expand=True, padx=12, pady=(0, 10))
        self.file_listbox = tk.Listbox(browser, relief="flat", activestyle="none")
        self.file_listbox.pack(side="left", fill="both", expand=True)
        file_scroll = tk.Scrollbar(browser, command=self.file_listbox.yview)
        file_scroll.pack(side="right", fill="y")
        self.file_listbox.configure(yscrollcommand=file_scroll.set)
        self.file_listbox.bind("<Double-1>", self._on_file_double_click)
        self.file_listbox.bind("<<ListboxSelect>>", self._on_file_select)

        info = tk.Frame(self.files_panel, padx=10, pady=10)
        info.pack(fill="x", padx=12, pady=(0, 12))
        self.info_header = tk.Label(info, text=">> ITEM DETAILS", anchor="w", font=self._font(0, True))
        self.info_header.pack(anchor="w")
        self.info_label = tk.Label(info, text="No selection.", justify="left", anchor="w")
        self.info_label.pack(anchor="w", pady=(6, 0))

        self.theme_widgets.extend([self.files_header, top, self.back_button, self.path_label, browser, self.file_listbox, info, self.info_header, self.info_label])
        self._refresh_file_list()

    def _safe_resolve_in_vault(self, candidate: Path):
        try:
            resolved = candidate.resolve()
            resolved.relative_to(VAULT_ROOT.resolve())
            return resolved
        except Exception:
            return None

    def _refresh_file_list(self):
        safe = self._safe_resolve_in_vault(self.current_vault_path)
        if safe is None:
            self.current_vault_path = VAULT_ROOT.resolve()

        self.file_listbox.delete(0, "end")
        self.info_label.config(text="No selection.")

        try:
            items = sorted(self.current_vault_path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        except Exception as err:
            self.log(f"Navigation error: {err}")
            items = []

        for item in items:
            tag = "[DIR]" if item.is_dir() else "[FILE]"
            self.file_listbox.insert("end", f"{tag} {item.name}")

        rel = self.current_vault_path.relative_to(VAULT_ROOT.resolve())
        self.path_label.config(text="Vault" if str(rel) == "." else f"Vault\\{rel}")
        self.back_button.config(state="disabled" if self.current_vault_path == VAULT_ROOT.resolve() else "normal")

    def _selected_path(self):
        sel = self.file_listbox.curselection()
        if not sel:
            return None
        row = self.file_listbox.get(sel[0])
        name = row.split(" ", 1)[1] if " " in row else row
        return self._safe_resolve_in_vault(self.current_vault_path / name)

    def _on_file_select(self, _event=None):
        item = self._selected_path()
        if item is None or not item.exists():
            self.info_label.config(text="No selection.")
            return
        kind = "Folder" if item.is_dir() else "File"
        size = "-"
        if item.is_file():
            try:
                size = f"{item.stat().st_size} bytes"
            except OSError:
                size = "Unavailable"
        try:
            mod = datetime.fromtimestamp(item.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        except OSError:
            mod = "Unavailable"
        self.info_label.config(text=f"Name: {item.name}\nType: {kind}\nSize: {size}\nModified: {mod}")

    def _on_file_double_click(self, _event=None):
        item = self._selected_path()
        if item is None:
            return
        if item.is_dir():
            self.current_vault_path = item
            self._refresh_file_list()
            self.log(f"Navigation: entered {item}")
            return
        try:
            if sys.platform.startswith("win"):
                os.startfile(str(item))
            elif sys.platform == "darwin":
                subprocess.run(["open", str(item)], check=False)
            else:
                subprocess.run(["xdg-open", str(item)], check=False)
            self.log(f"File opened: {item}")
        except Exception as err:
            self.log(f"File open failed: {item} ({err})")
            messagebox.showerror("Open failed", f"Could not open file:\n{err}")

    def _go_back(self):
        if self.current_vault_path == VAULT_ROOT.resolve():
            return
        parent = self._safe_resolve_in_vault(self.current_vault_path.parent)
        self.current_vault_path = parent if parent else VAULT_ROOT.resolve()
        self._refresh_file_list()
        self.log(f"Navigation: back to {self.current_vault_path}")

    def _show_files_panel(self):
        self.set_active_panel("Files")
        self.log("Panel switched: Files")

    def _build_tools_panel(self):
        self.tools_header = tk.Label(self.tools_panel, text=">> NETWORK TOOLS", anchor="w", font=self._font(2, True))
        self.tools_header.pack(fill="x", padx=12, pady=(12, 8))

        selector = tk.Frame(self.tools_panel)
        selector.pack(fill="x", padx=12, pady=(0, 8))
        tk.Label(selector, text="Tool").pack(side="left")
        self.tool_choice_var = tk.StringVar(value=self.current_tool_name)
        self.tool_choice = tk.OptionMenu(selector, self.tool_choice_var, *self.tools.keys(), command=self._on_tool_change)
        self.tool_choice.pack(side="left", padx=(8, 12))
        self.favorite_tool_button = tk.Button(selector, text="☆ Favorite", width=10, command=self._toggle_current_tool_favorite)
        self.favorite_tool_button.pack(side="left", padx=(0, 8))
        self.tool_description_label = tk.Label(selector, text=self.tools[self.current_tool_name].description, anchor="w")
        self.tool_description_label.pack(side="left", fill="x", expand=True)

        recent_row = tk.Frame(self.tools_panel)
        recent_row.pack(fill="x", padx=12, pady=(0, 8))
        tk.Label(recent_row, text="Recent target").pack(side="left")
        self.recent_target_var = tk.StringVar()
        self.recent_target_combo = ttk.Combobox(recent_row, textvariable=self.recent_target_var, state="readonly", width=24)
        self.recent_target_combo.pack(side="left", padx=(8, 8))
        self.apply_recent_button = tk.Button(recent_row, text="Use", width=8, command=self._apply_recent_target)
        self.apply_recent_button.pack(side="left")

        profiles_row = tk.Frame(self.tools_panel)
        profiles_row.pack(fill="x", padx=12, pady=(0, 8))
        tk.Label(profiles_row, text="Profile").pack(side="left")
        self.profile_name_entry = tk.Entry(profiles_row, width=20)
        self.profile_name_entry.pack(side="left", padx=(6, 8))
        self.save_profile_button = tk.Button(profiles_row, text="Save Profile", width=12, command=self._save_current_profile)
        self.save_profile_button.pack(side="left", padx=(0, 8))
        self.run_profile_button = tk.Button(profiles_row, text="Run Profile", width=10, command=self._run_selected_profile)
        self.run_profile_button.pack(side="left")

        profile_list_row = tk.Frame(self.tools_panel)
        profile_list_row.pack(fill="x", padx=12, pady=(0, 8))
        self.profile_listbox = tk.Listbox(profile_list_row, height=4, activestyle="none")
        self.profile_listbox.pack(side="left", fill="x", expand=True)
        self.profile_listbox.bind("<<ListboxSelect>>", self._on_profile_pick)
        self.delete_profile_button = tk.Button(profile_list_row, text="Delete", width=10, command=self._delete_selected_profile)
        self.delete_profile_button.pack(side="left", padx=(8, 0))

        self.tool_input_area = tk.Frame(self.tools_panel)
        self.tool_input_area.pack(fill="x", padx=12, pady=(0, 8))

        self.tool_fields = {
            "target": self._make_input_row("Target", "127.0.0.1"),
            "count": self._make_input_row("Count", "4"),
            "domain": self._make_input_row("Domain", "example.com"),
            "port": self._make_input_row("Port", "80"),
            "port_range": self._make_input_row("Port Range", "20-1024"),
        }
        for _k, (_row, entry) in self.tool_fields.items():
            entry.bind("<FocusOut>", lambda _e: self._save_last_tool_state())

        self.tool_permission_var = tk.BooleanVar(value=False)
        self.permission_check = tk.Checkbutton(
            self.tool_input_area,
            text="I confirm I have permission to scan this target",
            variable=self.tool_permission_var,
            anchor="w",
            justify="left",
        )
        self.permission_check.pack(fill="x", pady=(2, 2))

        self.public_warning_label = tk.Label(
            self.tool_input_area,
            text="Public targets require permission confirmation.",
            fg="#ffb366",
            anchor="w",
        )
        self.public_warning_label.pack(fill="x", pady=(0, 2))

        self.scanner_warning_label = tk.Label(
            self.tool_input_area,
            text="For local/authorized testing only",
            fg="#ff8080",
            anchor="w",
        )
        self.scanner_warning_label.pack(fill="x", pady=(0, 2))

        controls = tk.Frame(self.tools_panel)
        controls.pack(fill="x", padx=12, pady=(0, 8))
        self.run_tool_button = tk.Button(controls, text="Run", command=self._run_selected_tool, width=12)
        self.run_tool_button.pack(side="left", padx=(0, 8))
        self.cancel_tool_button = tk.Button(controls, text="Cancel", command=self._cancel_current_tool, width=12, state="disabled")
        self.cancel_tool_button.pack(side="left", padx=(0, 8))
        self.open_results_button = tk.Button(controls, text="Open Results Folder", command=self._open_results_folder, width=18)
        self.open_results_button.pack(side="left")
        self.copy_output_button = tk.Button(controls, text="Copy Output", command=self._copy_tool_output, width=12)
        self.copy_output_button.pack(side="left", padx=(8, 8))
        self.clear_output_button = tk.Button(controls, text="Clear Output", command=self._clear_tool_output, width=12)
        self.clear_output_button.pack(side="left")

        hints_row = tk.Frame(self.tools_panel)
        hints_row.pack(fill="x", padx=12, pady=(0, 8))
        self.toggle_hint_button = tk.Button(hints_row, text="Hide Help", width=10, command=self._toggle_tool_help)
        self.toggle_hint_button.pack(side="left", padx=(0, 8))
        self.tool_hint_label = tk.Label(hints_row, text="", anchor="w", justify="left")
        self.tool_hint_label.pack(side="left", fill="x", expand=True)

        self.tool_status_row = tk.Frame(self.tools_panel)
        self.tool_status_row.pack(fill="x", padx=12, pady=(0, 8))
        self.tool_status_badge = tk.Label(self.tool_status_row, text="READY", width=10, anchor="center")
        self.tool_status_badge.pack(side="left", padx=(0, 8))
        self.tool_status_line = tk.Label(self.tool_status_row, text="Status: Ready", anchor="w")
        self.tool_status_line.pack(side="left", fill="x", expand=True)

        output_wrap = tk.Frame(self.tools_panel)
        output_wrap.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.tool_output_text = tk.Text(output_wrap, relief="flat", wrap="word")
        self.tool_output_text.pack(side="left", fill="both", expand=True)
        output_scroll = tk.Scrollbar(output_wrap, command=self.tool_output_text.yview)
        output_scroll.pack(side="right", fill="y")
        self.tool_output_text.configure(yscrollcommand=output_scroll.set)

        self.theme_widgets.extend([
            self.tools_header, selector, self.tool_choice, self.favorite_tool_button, self.tool_description_label,
            recent_row, self.recent_target_combo, self.apply_recent_button,
            profiles_row, self.profile_name_entry, self.save_profile_button, self.run_profile_button,
            profile_list_row, self.profile_listbox, self.delete_profile_button,
            self.tool_input_area, self.permission_check, self.public_warning_label, self.scanner_warning_label,
            controls, self.run_tool_button, self.cancel_tool_button, self.open_results_button, self.copy_output_button, self.clear_output_button,
            hints_row, self.toggle_hint_button, self.tool_hint_label,
            self.tool_status_row, self.tool_status_badge, self.tool_status_line, output_wrap, self.tool_output_text,
        ])
        self._refresh_recent_targets()
        self._refresh_profile_list()
        self._refresh_tool_dropdown()
        self._restore_last_tool_state()
        self._sync_tool_input_visibility()
        self._refresh_favorite_button()
        self._update_tool_hint_text()
        self._set_tool_status("Ready")

    def _make_input_row(self, label_text, default_value):
        row = tk.Frame(self.tool_input_area)
        tk.Label(row, text=label_text, width=12, anchor="w").pack(side="left")
        entry = tk.Entry(row)
        entry.insert(0, default_value)
        entry.pack(side="left", fill="x", expand=True)
        row.pack(fill="x", pady=2)
        self.theme_widgets.extend([row, entry])
        return row, entry

    def _on_tool_change(self, *_):
        selected = self.tool_choice_var.get().strip()
        tool_name = self.tool_menu_display_to_name.get(selected, selected.replace("★ ", "", 1))
        self._set_current_tool(tool_name)

    def _tool_display_name(self, tool_name):
        return f"★ {tool_name}" if tool_name in self.favorite_tools else tool_name

    def _set_current_tool(self, tool_name, persist=True):
        if tool_name not in self.tools:
            return
        self.current_tool_name = tool_name
        self.tool_choice_var.set(self._tool_display_name(tool_name))
        self.tool_description_label.config(text=self.tools[self.current_tool_name].description)
        self._sync_tool_input_visibility()
        self._refresh_favorite_button()
        self._update_tool_hint_text()
        if persist:
            self._save_last_tool_state()
        if self.current_panel_name == "Network Tools":
            self._sync_sidebar_selection()

    def _sync_tool_input_visibility(self):
        for row, _entry in self.tool_fields.values():
            row.pack_forget()

        show_map = {
            "Ping": ["target", "count"],
            "DNS Lookup": ["domain"],
            "Traceroute": ["target"],
            "Port Check": ["target", "port"],
            "Port Scanner": ["target", "port_range"],
        }
        visible_keys = show_map.get(self.current_tool_name, ["target"])
        for key in visible_keys:
            row, _entry = self.tool_fields[key]
            row.pack(fill="x", pady=2)

        show_permission = self.current_tool_name in ("Ping", "Traceroute", "Port Check", "Port Scanner")
        self.permission_check.pack_forget()
        self.public_warning_label.pack_forget()
        self.scanner_warning_label.pack_forget()

        if show_permission:
            self.permission_check.pack(fill="x", pady=(2, 2))
            self.public_warning_label.pack(fill="x", pady=(0, 2))
        if self.current_tool_name == "Port Scanner":
            self.scanner_warning_label.pack(fill="x", pady=(0, 2))

    def _collect_tool_inputs(self):
        inputs = {
            "target": self.tool_fields["target"][1].get().strip(),
            "count": self.tool_fields["count"][1].get().strip(),
            "domain": self.tool_fields["domain"][1].get().strip(),
            "port": self.tool_fields["port"][1].get().strip(),
            "port_range": self.tool_fields["port_range"][1].get().strip(),
            "permission_confirmed": self.tool_permission_var.get(),
        }
        return inputs

    def _save_last_tool_state(self):
        self.last_tool_state = {
            "tool_name": self.current_tool_name,
            "inputs": self._collect_tool_inputs(),
        }
        self.save_config()

    def _restore_last_tool_state(self):
        state = self.last_tool_state or {}
        tool_name = state.get("tool_name", "Ping")
        if tool_name in self.tools:
            self._set_current_tool(tool_name, persist=False)
        inputs = state.get("inputs", {})
        for key in ("target", "count", "domain", "port", "port_range"):
            if key in self.tool_fields:
                entry = self.tool_fields[key][1]
                entry.delete(0, "end")
                entry.insert(0, str(inputs.get(key, entry.get())))
        self.tool_permission_var.set(bool(inputs.get("permission_confirmed", False)))

    def _refresh_recent_targets(self):
        if not hasattr(self, "recent_target_combo"):
            return
        cleaned = []
        for t in self.recent_targets:
            val = str(t).strip()
            if val and val not in cleaned:
                cleaned.append(val)
        self.recent_targets = cleaned[:10]
        self.recent_target_combo["values"] = self.recent_targets
        if self.recent_targets and not self.recent_target_var.get():
            self.recent_target_var.set(self.recent_targets[0])

    def _push_recent_target(self, value):
        target = (value or "").strip()
        if not target:
            return
        existing = [t for t in self.recent_targets if t != target]
        self.recent_targets = [target] + existing
        self._refresh_recent_targets()
        self.save_config()

    def _apply_recent_target(self):
        target = self.recent_target_var.get().strip()
        if not target:
            return
        field_key = "domain" if self.current_tool_name == "DNS Lookup" else "target"
        entry = self.tool_fields[field_key][1]
        entry.delete(0, "end")
        entry.insert(0, target)
        self._save_last_tool_state()
        self._show_toast("Recent target applied.")

    def _toggle_current_tool_favorite(self):
        tool_name = self.current_tool_name
        if tool_name in self.favorite_tools:
            self.favorite_tools = [t for t in self.favorite_tools if t != tool_name]
        else:
            self.favorite_tools.append(tool_name)
        self.save_config()
        self._refresh_tool_dropdown()
        self.tool_choice_var.set(self._tool_display_name(self.current_tool_name))
        self._refresh_favorite_button()

    def _refresh_favorite_button(self):
        if not hasattr(self, "favorite_tool_button"):
            return
        if self.current_tool_name in self.favorite_tools:
            self.favorite_tool_button.config(text="★ Favorited")
        else:
            self.favorite_tool_button.config(text="☆ Favorite")

    def _toggle_tool_help(self):
        self.tool_help_visible = not self.tool_help_visible
        self.save_config()
        self._update_tool_hint_text()

    def _update_tool_hint_text(self):
        if not hasattr(self, "tool_hint_label"):
            return
        hints = {
            "Ping": "Sends echo requests to check if target responds.",
            "DNS Lookup": "Resolves domain names to IPv4/IPv6 addresses.",
            "Traceroute": "Shows hop path from your system to target.",
            "Port Check": "Checks one specific port and response time.",
            "Port Scanner": "Scans a range of ports and lists open ones.",
        }
        text = hints.get(self.current_tool_name, "Run the selected tool with validated inputs.")
        self.toggle_hint_button.config(text="Hide Help" if self.tool_help_visible else "Show Help")
        self.tool_hint_label.config(text=text if self.tool_help_visible else "Help hidden.")

    def _copy_tool_output(self):
        text = self.tool_output_text.get("1.0", "end").strip()
        if not text:
            self._show_toast("No output to copy.", is_error=True)
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._show_toast("Output copied.")

    def _clear_tool_output(self):
        self.tool_output_text.delete("1.0", "end")
        self._set_tool_status("Ready")
        self._show_toast("Output cleared.")

    def _refresh_tool_dropdown(self):
        if not hasattr(self, "tool_choice"):
            return
        menu = self.tool_choice["menu"]
        menu.delete(0, "end")
        favorite_set = {t for t in self.favorite_tools if t in self.tools}
        tool_names = sorted(self.tools.keys(), key=lambda name: (0 if name in favorite_set else 1, name.lower()))
        self.tool_menu_display_to_name = {}
        for name in tool_names:
            display = self._tool_display_name(name)
            self.tool_menu_display_to_name[display] = name
            menu.add_command(label=display, command=lambda v=name: self._set_current_tool(v))
        if self.current_tool_name not in tool_names:
            self.current_tool_name = tool_names[0]
        self.tool_choice_var.set(self._tool_display_name(self.current_tool_name))

    def _refresh_profile_list(self):
        if not hasattr(self, "profile_listbox"):
            return
        self.profile_listbox.delete(0, "end")
        self.filtered_profile_names = sorted(self.saved_profiles.keys())
        for name in self.filtered_profile_names:
            self.profile_listbox.insert("end", name)

    def _on_profile_pick(self, _event=None):
        if not self.profile_listbox.curselection():
            return
        idx = self.profile_listbox.curselection()[0]
        if idx >= len(self.filtered_profile_names):
            return
        profile_name = self.filtered_profile_names[idx]
        data = self.saved_profiles.get(profile_name, {})
        tool_name = data.get("tool_name", "Ping")
        if tool_name in self.tools:
            self.tool_choice_var.set(tool_name)
            self._on_tool_change()
        inputs = data.get("inputs", {})
        for key in ("target", "count", "domain", "port", "port_range"):
            if key in inputs:
                entry = self.tool_fields[key][1]
                entry.delete(0, "end")
                entry.insert(0, str(inputs[key]))
        self.tool_permission_var.set(bool(inputs.get("permission_confirmed", False)))
        self.profile_name_entry.delete(0, "end")
        self.profile_name_entry.insert(0, profile_name)

    def _save_current_profile(self):
        name = self.profile_name_entry.get().strip()
        if not name:
            self._show_toast("Enter profile name first.", is_error=True)
            return
        self.saved_profiles[name] = {
            "tool_name": self.current_tool_name,
            "inputs": self._collect_tool_inputs(),
            "updated_at": datetime.now().isoformat(timespec="seconds"),
        }
        self._save_profiles()
        self._refresh_profile_list()
        self.log(f"Profile saved: {name}")
        self._show_toast(f"Profile '{name}' saved.")

    def _delete_selected_profile(self):
        if not self.profile_listbox.curselection():
            return
        idx = self.profile_listbox.curselection()[0]
        if idx >= len(self.filtered_profile_names):
            return
        name = self.filtered_profile_names[idx]
        self.saved_profiles.pop(name, None)
        self._save_profiles()
        self._refresh_profile_list()
        self.log(f"Profile deleted: {name}")
        self._show_toast(f"Profile '{name}' deleted.")

    def _run_selected_profile(self):
        self._on_profile_pick()
        self._run_selected_tool()

    def _validate_allowed_target_policy(self, tool_name, inputs):
        network_target_tools = {"Ping", "Traceroute", "Port Check", "Port Scanner"}
        if tool_name == "DNS Lookup":
            return True, ""
        if tool_name not in network_target_tools:
            return True, ""

        target = (inputs.get("target") or "").strip()
        if not target:
            return False, "Target is required."

        if not is_valid_target_format(target):
            return False, "Target format is invalid."

        resolved = resolve_target_ips(target)
        if not resolved:
            return False, "Target could not be resolved."

        if self.current_role == "analyst":
            pass
        elif inputs.get("permission_confirmed"):
            return True, ""

        public_hits = [str(ip) for ip in resolved if not is_private_or_loopback(ip)]
        if public_hits:
            if self.current_role == "analyst":
                return False, "Analyst role allows only localhost/private targets."
            return False, "Public target blocked. Check permission confirmation to continue."

        return True, ""

    def _set_tool_status(self, state, detail=""):
        color_map = {
            "Ready": self.color_accent,
            "Running": self.color_accent,
            "Done": self.color_accent,
            "Error": "#ff8080",
            "Canceled": "#ff6a8d",
        }
        text = f"Status: {state}"
        if detail:
            text += f" | {detail}"
        self.tool_status_line.config(text=text, fg=color_map.get(state, self.color_fg))
        if hasattr(self, "tool_status_badge"):
            self.tool_status_badge.config(text=state.upper(), fg=color_map.get(state, self.color_fg))

    def _append_tool_output(self, text):
        self.tool_output_text.insert("end", text + "\n")
        self.tool_output_text.see("end")

    def _run_selected_tool(self):
        if self.current_tool_worker and self.current_tool_worker.is_alive():
            return

        selected = self.tool_choice_var.get().strip()
        tool_name = self.tool_menu_display_to_name.get(selected, selected.replace("★ ", "", 1))
        tool = self.tools[tool_name]
        inputs = self._collect_tool_inputs()
        self._save_last_tool_state()

        ok, msg = self._validate_allowed_target_policy(tool_name, inputs)
        if not ok:
            self._set_tool_status("Error", msg)
            self._append_tool_output(f"[Policy Block] {msg}")
            self.log(f"Tool blocked by policy: {tool.tool_id} ({msg})")
            return

        ok, msg = tool.validate_inputs(inputs)
        if not ok:
            self._set_tool_status("Error", msg)
            self._append_tool_output(f"[Validation Error] {msg}")
            self.log(f"Tool validation failed: {tool.tool_id} ({msg})")
            return

        recent_seed = inputs.get("domain", "") if tool_name == "DNS Lookup" else inputs.get("target", "")
        self._push_recent_target(recent_seed)

        self.current_tool_cancel_event = threading.Event()
        self.current_tool_started_at = time.time()
        self.run_tool_button.config(state="disabled")
        self.cancel_tool_button.config(state="normal")
        self._set_tool_status("Running", tool.name)
        self._append_tool_output(f"\n[{datetime.now().strftime('%H:%M:%S')}] Running {tool.name}...")
        self.log(f"Tool start: {tool.tool_id} inputs={inputs}")

        def worker():
            started = datetime.now()
            status = "Done"
            output_text = ""
            err_text = ""
            try:
                output_text = tool.run(inputs, cancel_event=self.current_tool_cancel_event)
                if self.current_tool_cancel_event.is_set():
                    status = "Canceled"
            except subprocess.TimeoutExpired:
                status = "Error"
                err_text = "Execution timed out."
            except Exception as err:
                status = "Error"
                err_text = str(err)

            finished = datetime.now()
            timestamp = finished.strftime("%Y%m%d_%H%M%S")
            base = f"{tool.tool_id}_{timestamp}"
            txt_path = RESULTS_DIR / f"{base}.txt"
            json_path = RESULTS_DIR / f"{base}.json"

            final_output = output_text if status != "Error" else err_text
            if not final_output:
                final_output = "No output."

            result_payload = {
                "tool_id": tool.tool_id,
                "tool_name": tool.name,
                "started_at": started.isoformat(timespec="seconds"),
                "finished_at": finished.isoformat(timespec="seconds"),
                "duration_seconds": round((finished - started).total_seconds(), 3),
                "status": status,
                "inputs": inputs,
                "output": final_output,
            }

            try:
                with open(txt_path, "w", encoding="utf-8") as f:
                    f.write(final_output + "\n")
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(result_payload, f, indent=2)
            except Exception as io_err:
                status = "Error"
                final_output = f"Result save failed: {io_err}\n\n{final_output}"

            duration = (finished - started).total_seconds()
            self.root.after(0, lambda: self._on_tool_run_complete(tool, status, final_output, txt_path, json_path, duration))

        self.current_tool_worker = threading.Thread(target=worker, daemon=True)
        self.current_tool_worker.start()

    def _on_tool_run_complete(self, tool, status, output_text, txt_path, json_path, duration_seconds):
        self.run_tool_button.config(state="normal")
        self.cancel_tool_button.config(state="disabled")
        duration_label = f"{duration_seconds:.2f}s"

        if status == "Done":
            self._set_tool_status("Done", f"{tool.name} ({duration_label})")
            self.log(f"Tool end: {tool.tool_id} (success)")
        elif status == "Canceled":
            self._set_tool_status("Canceled", f"{tool.name} ({duration_label})")
            self.log(f"Tool end: {tool.tool_id} (canceled)")
        else:
            self._set_tool_status("Error", f"{tool.name} ({duration_label})")
            self.log(f"Tool error: {tool.tool_id} ({output_text.splitlines()[0] if output_text else 'unknown error'})")

        self._append_tool_output(output_text)
        self._append_tool_output(f"Duration: {duration_label}")
        self._append_tool_output(f"Saved: {txt_path.name}, {json_path.name}")
        if hasattr(self, "results_listbox"):
            self._refresh_results_list()

        self.current_tool_worker = None
        self.current_tool_cancel_event = None
        self.current_tool_started_at = None

    def _cancel_current_tool(self):
        if self.current_tool_cancel_event:
            self.current_tool_cancel_event.set()
            self._set_tool_status("Running", "Cancel requested")
            self.log("Tool cancel requested")

    def _open_results_folder(self):
        try:
            RESULTS_DIR.mkdir(exist_ok=True)
            if sys.platform.startswith("win"):
                os.startfile(str(RESULTS_DIR))
            elif sys.platform == "darwin":
                subprocess.run(["open", str(RESULTS_DIR)], check=False)
            else:
                subprocess.run(["xdg-open", str(RESULTS_DIR)], check=False)
            self.log(f"Results folder opened: {RESULTS_DIR}")
        except Exception as err:
            self.log(f"Open results folder failed: {err}")
            messagebox.showerror("Open folder failed", f"Could not open results folder:\n{err}", parent=self.root)

    def _show_tools_panel(self, selected_tool=None):
        if selected_tool and selected_tool in self.tools:
            self._set_current_tool(selected_tool)
            self.log(f"Tool selected: {selected_tool}")
        self.set_active_panel("Network Tools")
        self.log("Panel switched: Network Tools")

    def _build_results_panel(self):
        self.results_header = tk.Label(self.results_panel, text=">> RESULTS EXPLORER", anchor="w", font=self._font(2, True))
        self.results_header.pack(fill="x", padx=12, pady=(12, 8))

        dash = tk.Frame(self.results_panel)
        dash.pack(fill="x", padx=12, pady=(0, 8))
        self.results_total_label = tk.Label(dash, text="Runs: 0", anchor="w")
        self.results_total_label.pack(side="left", padx=(0, 14))
        self.results_success_label = tk.Label(dash, text="Done: 0", anchor="w")
        self.results_success_label.pack(side="left", padx=(0, 14))
        self.results_error_label = tk.Label(dash, text="Errors: 0", anchor="w")
        self.results_error_label.pack(side="left", padx=(0, 14))
        self.results_top_tool_label = tk.Label(dash, text="Top Tool: -", anchor="w")
        self.results_top_tool_label.pack(side="left", padx=(0, 14))
        self.results_diff_button = tk.Button(dash, text="Show Diff", width=10, command=self._show_selected_result_diff)
        self.results_diff_button.pack(side="left", padx=(0, 8))
        self.results_export_html_button = tk.Button(dash, text="Export HTML Report", width=16, command=self._export_selected_html_report)
        self.results_export_html_button.pack(side="left")

        filters = tk.Frame(self.results_panel)
        filters.pack(fill="x", padx=12, pady=(0, 8))
        tk.Label(filters, text="Tool").pack(side="left")
        self.results_tool_filter_var = tk.StringVar(value="All")
        self.results_tool_filter = tk.OptionMenu(filters, self.results_tool_filter_var, "All")
        self.results_tool_filter.pack(side="left", padx=(6, 12))
        tk.Label(filters, text="Status").pack(side="left")
        self.results_status_filter_var = tk.StringVar(value="All")
        self.results_status_filter = tk.OptionMenu(filters, self.results_status_filter_var, "All", "Done", "Error", "Canceled")
        self.results_status_filter.pack(side="left", padx=(6, 12))
        tk.Label(filters, text="Find").pack(side="left")
        self.results_search_entry = tk.Entry(filters, width=24)
        self.results_search_entry.pack(side="left", padx=(6, 8))
        self.results_refresh_button = tk.Button(filters, text="Refresh", command=self._refresh_results_list, width=10)
        self.results_refresh_button.pack(side="left")

        body = tk.Frame(self.results_panel)
        body.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        left = tk.Frame(body)
        left.pack(side="left", fill="y")
        self.results_listbox = tk.Listbox(left, width=44, activestyle="none")
        self.results_listbox.pack(side="left", fill="y")
        results_scroll = tk.Scrollbar(left, command=self.results_listbox.yview)
        results_scroll.pack(side="right", fill="y")
        self.results_listbox.configure(yscrollcommand=results_scroll.set)
        self.results_listbox.bind("<<ListboxSelect>>", self._on_result_select)

        right = tk.Frame(body)
        right.pack(side="left", fill="both", expand=True, padx=(10, 0))
        top_right = tk.Frame(right)
        top_right.pack(fill="both", expand=True)
        tk.Label(top_right, text="JSON").pack(anchor="w")
        self.results_json_text = tk.Text(top_right, relief="flat", wrap="word", height=13)
        self.results_json_text.pack(fill="both", expand=True)
        bottom_right = tk.Frame(right)
        bottom_right.pack(fill="both", expand=True, pady=(8, 0))
        tk.Label(bottom_right, text="TEXT").pack(anchor="w")
        self.results_txt_text = tk.Text(bottom_right, relief="flat", wrap="word", height=13)
        self.results_txt_text.pack(fill="both", expand=True)

        self.results_items = []
        self.results_tool_filter_var.trace_add("write", lambda *_: self._refresh_results_list())
        self.results_status_filter_var.trace_add("write", lambda *_: self._refresh_results_list())
        self.results_search_entry.bind("<KeyRelease>", lambda _e: self._refresh_results_list())

        self.theme_widgets.extend([
            self.results_header, dash, self.results_total_label, self.results_success_label, self.results_error_label, self.results_top_tool_label,
            self.results_diff_button, self.results_export_html_button,
            filters, self.results_tool_filter, self.results_status_filter, self.results_search_entry, self.results_refresh_button,
            body, left, self.results_listbox, right, top_right, self.results_json_text, bottom_right, self.results_txt_text,
        ])
        self._refresh_results_filter_tools()
        self._refresh_results_list()

    def _refresh_results_filter_tools(self):
        if not hasattr(self, "results_tool_filter"):
            return
        options = ["All"]
        tool_ids = set()
        for jfile in RESULTS_DIR.glob("*.json"):
            try:
                with open(jfile, "r", encoding="utf-8") as f:
                    data = json.load(f)
                tid = str(data.get("tool_id", "")).strip()
                if tid:
                    tool_ids.add(tid)
            except Exception:
                continue
        options.extend(sorted(tool_ids))
        menu = self.results_tool_filter["menu"]
        menu.delete(0, "end")
        for opt in options:
            menu.add_command(label=opt, command=lambda v=opt: self.results_tool_filter_var.set(v))
        if self.results_tool_filter_var.get() not in options:
            self.results_tool_filter_var.set("All")

    def _refresh_results_list(self):
        if not hasattr(self, "results_listbox"):
            return
        self._refresh_results_filter_tools()
        self.results_listbox.delete(0, "end")
        self.results_items = []
        tool_hist = {}
        total = 0
        success = 0
        errors = 0

        tool_filter = self.results_tool_filter_var.get()
        status_filter = self.results_status_filter_var.get()
        search = self.results_search_entry.get().strip().lower()

        all_json = sorted(RESULTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for jpath in all_json:
            try:
                with open(jpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                continue
            total += 1
            tool_id = str(data.get("tool_id", ""))
            status = str(data.get("status", ""))
            tool_hist[tool_id] = tool_hist.get(tool_id, 0) + 1
            if status == "Done":
                success += 1
            elif status in ("Error", "Canceled"):
                errors += 1
            joined = json.dumps(data, ensure_ascii=False).lower()
            if tool_filter != "All" and tool_id != tool_filter:
                continue
            if status_filter != "All" and status != status_filter:
                continue
            if search and search not in joined:
                continue
            label = f"{jpath.stem} | {status}"
            self.results_listbox.insert("end", label)
            self.results_items.append((jpath, data))

        top_tool = "-"
        if tool_hist:
            top_tool = max(tool_hist.items(), key=lambda kv: kv[1])[0]
        self.results_total_label.config(text=f"Runs: {total}")
        self.results_success_label.config(text=f"Done: {success}")
        self.results_error_label.config(text=f"Errors: {errors}")
        self.results_top_tool_label.config(text=f"Top Tool: {top_tool or '-'}")

        if self.results_items:
            self.results_listbox.selection_set(0)
            self._on_result_select()
        else:
            self.results_json_text.delete("1.0", "end")
            self.results_txt_text.delete("1.0", "end")
            self.results_json_text.insert("end", "No matching results. Run tools or adjust filters.")
            self.results_txt_text.insert("end", "No text output to show.")

    def _on_result_select(self, _event=None):
        if not hasattr(self, "results_listbox"):
            return
        sel = self.results_listbox.curselection()
        if not sel or not self.results_items:
            return
        idx = sel[0]
        if idx >= len(self.results_items):
            return
        jpath, data = self.results_items[idx]
        txt_path = RESULTS_DIR / f"{jpath.stem}.txt"
        self.results_json_text.delete("1.0", "end")
        self.results_json_text.insert("end", json.dumps(data, indent=2))
        self.results_txt_text.delete("1.0", "end")
        try:
            with open(txt_path, "r", encoding="utf-8") as f:
                self.results_txt_text.insert("end", f.read())
        except Exception:
            self.results_txt_text.insert("end", "[No TXT output found]")

    def _find_previous_result(self, current_json_path, current_data):
        tool_id = str(current_data.get("tool_id", ""))
        target = str(current_data.get("inputs", {}).get("target", ""))
        candidates = sorted(RESULTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for jpath in candidates:
            if jpath == current_json_path:
                continue
            try:
                with open(jpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                continue
            if str(data.get("tool_id", "")) != tool_id:
                continue
            if str(data.get("inputs", {}).get("target", "")) != target:
                continue
            return jpath, data
        return None, None

    def _extract_open_ports_set(self, text_output):
        ports = set()
        for line in (text_output or "").splitlines():
            line = line.strip()
            if line.startswith("-"):
                line = line.lstrip("-").strip()
            if line.isdigit():
                ports.add(int(line))
        return ports

    def _show_selected_result_diff(self):
        if not self.results_listbox.curselection() or not self.results_items:
            return
        idx = self.results_listbox.curselection()[0]
        if idx >= len(self.results_items):
            return
        cur_path, cur_data = self.results_items[idx]
        prev_path, prev_data = self._find_previous_result(cur_path, cur_data)
        if prev_data is None:
            self.results_txt_text.delete("1.0", "end")
            self.results_txt_text.insert("end", "No previous result found for this tool+target.")
            return

        cur_txt = (RESULTS_DIR / f"{cur_path.stem}.txt")
        prev_txt = (RESULTS_DIR / f"{prev_path.stem}.txt")
        try:
            cur_out = cur_txt.read_text(encoding="utf-8")
        except Exception:
            cur_out = ""
        try:
            prev_out = prev_txt.read_text(encoding="utf-8")
        except Exception:
            prev_out = ""

        cur_ports = self._extract_open_ports_set(cur_out)
        prev_ports = self._extract_open_ports_set(prev_out)
        added = sorted(cur_ports - prev_ports)
        removed = sorted(prev_ports - cur_ports)

        lines = [
            f"Current: {cur_path.name}",
            f"Previous: {prev_path.name}",
            f"Tool: {cur_data.get('tool_id', '-')}",
            f"Target: {cur_data.get('inputs', {}).get('target', '-')}",
            "",
            f"Added open ports: {added if added else 'None'}",
            f"Removed open ports: {removed if removed else 'None'}",
        ]
        self.results_txt_text.delete("1.0", "end")
        self.results_txt_text.insert("end", "\n".join(lines))

    def _export_selected_html_report(self):
        if not self.results_listbox.curselection() or not self.results_items:
            return
        idx = self.results_listbox.curselection()[0]
        if idx >= len(self.results_items):
            return
        jpath, data = self.results_items[idx]
        txt_path = RESULTS_DIR / f"{jpath.stem}.txt"
        try:
            txt_data = txt_path.read_text(encoding="utf-8")
        except Exception:
            txt_data = "[No text output found]"

        out_path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export HTML Report",
            defaultextension=".html",
            initialfile=f"{jpath.stem}_report.html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
        )
        if not out_path:
            return
        html_report = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{html.escape(APP_NAME)} Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#0B0B0B;color:#F5F5F5;padding:20px}}
h1{{color:#CE1141}} pre{{background:#121212;padding:12px;border:1px solid #CE1141;white-space:pre-wrap}}
.meta{{margin-bottom:14px}}
</style></head><body>
<h1>{html.escape(APP_NAME)} Report</h1>
<div class="meta"><b>Generated:</b> {html.escape(datetime.now().isoformat(timespec='seconds'))}</div>
<div class="meta"><b>Tool:</b> {html.escape(str(data.get('tool_name','-')))} | <b>Status:</b> {html.escape(str(data.get('status','-')))}</div>
<div class="meta"><b>Inputs:</b> <pre>{html.escape(json.dumps(data.get('inputs',{}), indent=2))}</pre></div>
<h2>JSON Result</h2><pre>{html.escape(json.dumps(data, indent=2))}</pre>
<h2>Text Output</h2><pre>{html.escape(txt_data)}</pre>
</body></html>"""
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html_report)
        try:
            webbrowser.open_new_tab(Path(out_path).as_uri())
        except Exception:
            pass
        self._show_toast("HTML report exported.")
        self.log(f"Report exported: {out_path}")

    def _show_results_panel(self):
        self.set_active_panel("Results")
        self._refresh_results_list()
        self.log("Panel switched: Results")

    def _build_plugins_panel(self):
        self.plugins_header = tk.Label(self.plugins_panel, text=">> PLUGIN MANAGER", anchor="w", font=self._font(2, True))
        self.plugins_header.pack(fill="x", padx=12, pady=(12, 8))

        controls = tk.Frame(self.plugins_panel)
        controls.pack(fill="x", padx=12, pady=(0, 8))
        self.reload_plugins_button = tk.Button(controls, text="Reload Plugins", width=14, command=self._reload_plugins)
        self.reload_plugins_button.pack(side="left", padx=(0, 8))
        self.toggle_plugin_button = tk.Button(controls, text="Toggle Trust", width=12, command=self._toggle_selected_plugin_trust)
        self.toggle_plugin_button.pack(side="left", padx=(0, 8))
        self.open_plugins_folder_button = tk.Button(controls, text="Open Plugins Folder", width=18, command=self._open_plugins_folder)
        self.open_plugins_folder_button.pack(side="left")

        body = tk.Frame(self.plugins_panel)
        body.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.plugin_listbox = tk.Listbox(body, width=48, activestyle="none")
        self.plugin_listbox.pack(side="left", fill="y")
        self.plugin_listbox.bind("<<ListboxSelect>>", self._on_plugin_pick)
        plugin_scroll = tk.Scrollbar(body, command=self.plugin_listbox.yview)
        plugin_scroll.pack(side="left", fill="y")
        self.plugin_listbox.configure(yscrollcommand=plugin_scroll.set)

        right = tk.Frame(body)
        right.pack(side="left", fill="both", expand=True, padx=(10, 0))
        self.plugin_detail_label = tk.Label(right, text="Select a plugin to see details.", justify="left", anchor="nw")
        self.plugin_detail_label.pack(fill="x")
        self.plugin_help_text = tk.Text(right, relief="flat", wrap="word")
        self.plugin_help_text.pack(fill="both", expand=True, pady=(8, 0))
        self.plugin_help_text.insert(
            "end",
            "Plugin folder contract:\n"
            "1. Put .py files in plugins/.\n"
            "2. Expose register_tools(ToolBase).\n"
            "3. Return one tool instance or a list.\n\n"
            "Use Toggle Trust to allow/block plugin execution.",
        )
        self.plugin_help_text.configure(state="disabled")

        self.plugin_names = []
        self.theme_widgets.extend([
            self.plugins_header, controls, self.reload_plugins_button, self.toggle_plugin_button, self.open_plugins_folder_button,
            body, self.plugin_listbox, right, self.plugin_detail_label, self.plugin_help_text,
        ])
        self._refresh_plugins_list()

    def _refresh_plugins_list(self):
        if not hasattr(self, "plugin_listbox"):
            return
        self.plugin_listbox.delete(0, "end")
        self.plugin_names = [p.name for p in sorted(PLUGINS_DIR.glob("*.py"))]
        if not self.plugin_names:
            self.plugin_listbox.insert("end", "[No plugin files found]")
            return
        for name in self.plugin_names:
            status = self.plugin_status.get(name, "not loaded")
            trusted = self.plugin_trust.get(name, {}).get("trusted", False)
            tag = "trusted" if trusted else "blocked"
            self.plugin_listbox.insert("end", f"{name} | {tag} | {status}")

    def _on_plugin_pick(self, _event=None):
        if not self.plugin_listbox.curselection() or not self.plugin_names:
            return
        idx = self.plugin_listbox.curselection()[0]
        if idx >= len(self.plugin_names):
            return
        name = self.plugin_names[idx]
        info = self.plugin_trust.get(name, {})
        status = self.plugin_status.get(name, "not loaded")
        self.plugin_detail_label.config(
            text=f"File: {name}\nTrusted: {bool(info.get('trusted', False))}\nSHA256: {info.get('sha256', '-')}\nStatus: {status}"
        )

    def _toggle_selected_plugin_trust(self):
        if not self.plugin_listbox.curselection() or not self.plugin_names:
            return
        idx = self.plugin_listbox.curselection()[0]
        if idx >= len(self.plugin_names):
            return
        name = self.plugin_names[idx]
        current = bool(self.plugin_trust.get(name, {}).get("trusted", False))
        self.plugin_trust.setdefault(name, {})["trusted"] = not current
        self._save_plugin_trust()
        self._refresh_plugins_list()
        self._show_toast(f"{name} trust set to {not current}.")

    def _reload_plugins(self):
        self._load_plugin_tools()
        self._refresh_tool_dropdown()
        self._refresh_plugins_list()
        self._show_toast("Plugins reloaded.")
        self.log("Plugins reloaded")

    def _open_plugins_folder(self):
        try:
            PLUGINS_DIR.mkdir(exist_ok=True)
            if sys.platform.startswith("win"):
                os.startfile(str(PLUGINS_DIR))
            elif sys.platform == "darwin":
                subprocess.run(["open", str(PLUGINS_DIR)], check=False)
            else:
                subprocess.run(["xdg-open", str(PLUGINS_DIR)], check=False)
        except Exception as err:
            messagebox.showerror("Open folder failed", f"Could not open plugins folder:\n{err}", parent=self.root)

    def _show_plugins_panel(self):
        self.set_active_panel("Plugins")
        self._refresh_plugins_list()
        self.log("Panel switched: Plugins")

    def _build_logs_panel(self):
        self.logs_header = tk.Label(self.logs_panel, text=">> EVENT LOGS", anchor="w", font=self._font(2, True))
        self.logs_header.pack(fill="x", padx=12, pady=(12, 8))
        top = tk.Frame(self.logs_panel)
        top.pack(fill="x", padx=12, pady=(0, 8))
        self.export_logs_button = tk.Button(top, text="Export Logs", command=self._export_logs, width=14)
        self.export_logs_button.pack(side="left")

        text_wrap = tk.Frame(self.logs_panel)
        text_wrap.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.logs_text = tk.Text(text_wrap, relief="flat", wrap="word", state="disabled")
        self.logs_text.pack(side="left", fill="both", expand=True)
        logs_scroll = tk.Scrollbar(text_wrap, command=self.logs_text.yview)
        logs_scroll.pack(side="right", fill="y")
        self.logs_text.configure(yscrollcommand=logs_scroll.set)
        for line in self.logs:
            self.logs_text.configure(state="normal")
            self.logs_text.insert("end", line + "\n")
            self.logs_text.configure(state="disabled")

        self.theme_widgets.extend([self.logs_header, top, self.export_logs_button, text_wrap, self.logs_text])

    def _show_logs_panel(self):
        self.set_active_panel("Logs")
        self.log("Panel switched: Logs")

    def _export_logs(self):
        fname = f"cyber_toolkit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export Logs",
            defaultextension=".txt",
            initialfile=fname,
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(self.logs) + "\n")
            self.log(f"Logs exported: {path}")
            messagebox.showinfo("Export complete", "Logs exported successfully.", parent=self.root)
        except Exception as err:
            self.log(f"Log export failed: {err}")
            messagebox.showerror("Export failed", f"Could not export logs:\n{err}", parent=self.root)

    def _build_settings_panel(self):
        self.settings_header = tk.Label(self.settings_panel, text=">> THEME SETTINGS", anchor="w", font=self._font(2, True))
        self.settings_header.pack(fill="x", padx=12, pady=(12, 8))

        role_row = tk.Frame(self.settings_panel)
        role_row.pack(fill="x", padx=12, pady=(0, 8))
        tk.Label(role_row, text="Session role").pack(side="left")
        self.role_var = tk.StringVar(value=(self.current_role or "admin"))
        self.role_menu = tk.OptionMenu(role_row, self.role_var, "admin", "analyst")
        self.role_menu.pack(side="left", padx=(8, 8))
        self.role_apply_button = tk.Button(role_row, text="Apply Role", width=12, command=self._apply_role_change)
        self.role_apply_button.pack(side="left")

        users_row = tk.Frame(self.settings_panel)
        users_row.pack(fill="x", padx=12, pady=(0, 8))
        tk.Label(users_row, text="Manage users").pack(side="left")
        self.new_user_entry = tk.Entry(users_row, width=14)
        self.new_user_entry.pack(side="left", padx=(8, 6))
        self.new_user_pass_entry = tk.Entry(users_row, width=14, show="*")
        self.new_user_pass_entry.pack(side="left", padx=(0, 6))
        self.new_user_role_var = tk.StringVar(value="analyst")
        self.new_user_role_menu = tk.OptionMenu(users_row, self.new_user_role_var, "analyst", "admin")
        self.new_user_role_menu.pack(side="left", padx=(0, 6))
        self.add_user_button = tk.Button(users_row, text="Add User", width=10, command=self._add_user_from_settings)
        self.add_user_button.pack(side="left")

        pass_row = tk.Frame(self.settings_panel)
        pass_row.pack(fill="x", padx=12, pady=(0, 8))
        tk.Label(pass_row, text="Change my password").pack(side="left")
        self.current_pass_entry = tk.Entry(pass_row, width=14, show="*")
        self.current_pass_entry.pack(side="left", padx=(8, 6))
        self.new_pass_entry = tk.Entry(pass_row, width=14, show="*")
        self.new_pass_entry.pack(side="left", padx=(0, 6))
        self.change_pass_button = tk.Button(pass_row, text="Update", width=10, command=self._change_my_password)
        self.change_pass_button.pack(side="left")

        self.user_list_label = tk.Label(self.settings_panel, text="Users: -", anchor="w")
        self.user_list_label.pack(fill="x", padx=12, pady=(0, 8))

        form = tk.Frame(self.settings_panel)
        form.pack(fill="x", padx=12, pady=(0, 10))
        self.bg_entry = self._add_setting_row(form, 0, "BG color (#RRGGBB)", self.color_bg)
        self.panel_entry = self._add_setting_row(form, 1, "PANEL color (#RRGGBB)", self.color_panel)
        self.fg_entry = self._add_setting_row(form, 2, "FG color (#RRGGBB)", self.color_fg)
        self.accent_entry = self._add_setting_row(form, 3, "ACCENT color (#RRGGBB)", self.color_accent)
        self.select_bg_entry = self._add_setting_row(form, 4, "SELECT_BG color (#RRGGBB)", self.color_select_bg)

        font_row = tk.Frame(form)
        font_row.grid(row=5, column=0, columnspan=2, sticky="we", pady=(6, 8))
        tk.Label(font_row, text="Font size (10-18)").pack(anchor="w")
        self.font_size_scale = tk.Scale(font_row, from_=10, to=18, orient="horizontal")
        self.font_size_scale.set(self.font_size)
        self.font_size_scale.pack(fill="x", pady=(2, 0))

        family_row = tk.Frame(form)
        family_row.grid(row=6, column=0, columnspan=2, sticky="we", pady=(2, 10))
        tk.Label(family_row, text="Font family").pack(anchor="w")
        self.font_family_var = tk.StringVar(value=self.font_family_mode)
        self.font_default_radio = tk.Radiobutton(family_row, text="Default", value="default", variable=self.font_family_var)
        self.font_default_radio.pack(side="left", padx=(0, 12))
        self.font_mono_radio = tk.Radiobutton(family_row, text="Monospace (Consolas)", value="mono", variable=self.font_family_var)
        self.font_mono_radio.pack(side="left")

        actions = tk.Frame(self.settings_panel)
        actions.pack(fill="x", padx=12, pady=(0, 8))
        self.settings_apply_button = tk.Button(actions, text="Apply", width=12, command=self._apply_settings)
        self.settings_apply_button.pack(side="left", padx=(0, 8))
        self.settings_save_button = tk.Button(actions, text="Save", width=12, command=self._save_settings)
        self.settings_save_button.pack(side="left", padx=(0, 8))
        self.settings_reset_button = tk.Button(actions, text="Reset to Default", width=16, command=self._reset_settings)
        self.settings_reset_button.pack(side="left")
        self.settings_reset_layout_button = tk.Button(actions, text="Reset UI Layout", width=16, command=self._reset_ui_layout)
        self.settings_reset_layout_button.pack(side="left", padx=(8, 0))
        self.settings_self_test_button = tk.Button(actions, text="Run Self Test", width=14, command=self._run_self_test)
        self.settings_self_test_button.pack(side="left", padx=(8, 0))

        self.settings_status = tk.Label(self.settings_panel, text="", anchor="w")
        self.settings_status.pack(fill="x", padx=12, pady=(0, 12))

        self.theme_widgets.extend([
            self.settings_header, role_row, self.role_menu, self.role_apply_button,
            users_row, self.new_user_entry, self.new_user_pass_entry, self.new_user_role_menu, self.add_user_button,
            pass_row, self.current_pass_entry, self.new_pass_entry, self.change_pass_button,
            self.user_list_label,
            form, self.bg_entry, self.panel_entry, self.fg_entry,
            self.accent_entry, self.select_bg_entry, font_row, self.font_size_scale,
            family_row, self.font_default_radio, self.font_mono_radio,
            actions, self.settings_apply_button, self.settings_save_button,
            self.settings_reset_button, self.settings_reset_layout_button, self.settings_self_test_button, self.settings_status,
        ])
        self._refresh_user_list_label()

    def _add_setting_row(self, parent, row, label_text, initial):
        tk.Label(parent, text=label_text).grid(row=row, column=0, sticky="w", pady=4, padx=(0, 10))
        entry = tk.Entry(parent, width=20)
        entry.insert(0, initial)
        entry.grid(row=row, column=1, sticky="w", pady=4)
        self.theme_widgets.append(entry)
        return entry

    def _refresh_user_list_label(self):
        if not hasattr(self, "user_list_label"):
            return
        users = list_users()
        text = ", ".join(users) if users else "-"
        self.user_list_label.config(text=f"Users: {text}")

    def _add_user_from_settings(self):
        if self.current_role != "admin":
            self.settings_status.config(text="Only admin can add users.", fg="#ff8080")
            return
        username = self.new_user_entry.get().strip()
        password = self.new_user_pass_entry.get()
        role = self.new_user_role_var.get()
        try:
            create_user(username, password, role=role)
        except Exception as err:
            self.settings_status.config(text=f"Add user failed: {err}", fg="#ff8080")
            return
        self.new_user_entry.delete(0, "end")
        self.new_user_pass_entry.delete(0, "end")
        self._refresh_user_list_label()
        self.settings_status.config(text=f"User '{username}' added.", fg="#7dff9b")
        self.log(f"User added: {username} ({role})")

    def _change_my_password(self):
        current_pwd = self.current_pass_entry.get()
        new_pwd = self.new_pass_entry.get()
        try:
            change_user_password(self.current_user, current_pwd, new_pwd)
        except Exception as err:
            self.settings_status.config(text=f"Password change failed: {err}", fg="#ff8080")
            return
        self.current_pass_entry.delete(0, "end")
        self.new_pass_entry.delete(0, "end")
        self.settings_status.config(text="Password changed successfully.", fg="#7dff9b")
        self.log(f"Password changed for user '{self.current_user}'")

    def _run_self_test(self):
        checks = []
        checks.append(("target validation", is_valid_target_format("127.0.0.1") and not is_valid_target_format("")))
        checks.append(("port parse", parse_port_value("80") == 80 and parse_port_value("70000") is None))
        checks.append(("port range", parse_port_range("20-25") == (20, 25)))
        checks.append(("results dir", RESULTS_DIR.exists()))
        checks.append(("profiles type", isinstance(self.saved_profiles, dict)))
        passed = sum(1 for _n, ok in checks if ok)
        summary = f"Self-test: {passed}/{len(checks)} passed"
        self.settings_status.config(text=summary, fg="#7dff9b" if passed == len(checks) else "#ff8080")
        self.log(summary)

    def _apply_role_change(self):
        new_role = "analyst" if self.role_var.get() == "analyst" else "admin"
        self.current_role = new_role
        try:
            save_user_role(self.current_user, new_role)
        except Exception as err:
            self.settings_status.config(text=f"Role save failed: {err}", fg="#ff8080")
            return
        self.status_role_value.config(text=self.current_role.upper())
        self._enforce_role_permissions()
        self.settings_status.config(text=f"Session role set to {self.current_role.upper()}.", fg="#7dff9b")
        self.log(f"Role changed: {self.current_role}")

    def _enforce_role_permissions(self):
        is_admin = self.current_role == "admin"
        if hasattr(self, "role_var"):
            self.role_var.set(self.current_role)
        if hasattr(self, "role_menu"):
            self.role_menu.configure(state="normal")
        if hasattr(self, "role_apply_button"):
            self.role_apply_button.configure(state="normal")
        if hasattr(self, "add_user_button"):
            self.add_user_button.configure(state="normal" if is_admin else "disabled")
            self.new_user_entry.configure(state="normal" if is_admin else "disabled")
            self.new_user_pass_entry.configure(state="normal" if is_admin else "disabled")
            self.new_user_role_menu.configure(state="normal" if is_admin else "disabled")
        if hasattr(self, "settings_apply_button"):
            self.settings_apply_button.configure(state="normal")
            self.settings_save_button.configure(state="normal")
            self.settings_reset_button.configure(state="normal")
            self.settings_reset_layout_button.configure(state="normal")
            self.settings_self_test_button.configure(state="normal")
            for entry in (self.bg_entry, self.panel_entry, self.fg_entry, self.accent_entry, self.select_bg_entry):
                entry.configure(state="normal")
            self.font_size_scale.configure(state="normal")
            self.font_default_radio.configure(state="normal")
            self.font_mono_radio.configure(state="normal")
        if hasattr(self, "change_pass_button"):
            self.change_pass_button.configure(state="normal")
            self.current_pass_entry.configure(state="normal")
            self.new_pass_entry.configure(state="normal")
        if hasattr(self, "tool_permission_var"):
            if not is_admin:
                self.tool_permission_var.set(False)
            self.permission_check.configure(state="normal" if is_admin else "disabled")
            if not is_admin:
                self.public_warning_label.config(text="Analyst mode: only localhost/private targets allowed.")
            else:
                self.public_warning_label.config(text="Public targets require permission confirmation.")

    def _read_settings_inputs(self):
        values = {
            "bg": self.bg_entry.get().strip(),
            "panel": self.panel_entry.get().strip(),
            "fg": self.fg_entry.get().strip(),
            "accent": self.accent_entry.get().strip(),
            "select_bg": self.select_bg_entry.get().strip(),
            "font_size": int(self.font_size_scale.get()),
            "font_family_mode": self.font_family_var.get(),
        }
        for field in ("bg", "panel", "fg", "accent", "select_bg"):
            if not is_valid_hex_color(values[field]):
                raise ValueError(f"Invalid {field.upper()} color. Use format like #RRGGBB")
        if values["font_family_mode"] not in ("default", "mono"):
            raise ValueError("Invalid font family mode.")
        return values

    def _apply_settings(self):
        try:
            values = self._read_settings_inputs()
        except ValueError as err:
            self.settings_status.config(text=str(err), fg="#ff8080")
            return

        self.color_bg = values["bg"]
        self.color_panel = values["panel"]
        self.color_fg = values["fg"]
        self.color_accent = values["accent"]
        self.color_select_bg = values["select_bg"]
        self.font_size = values["font_size"]
        self.font_family_mode = values["font_family_mode"]

        self.apply_theme()
        self.settings_status.config(text="Theme applied.", fg="#7dff9b")
        self.log("Settings applied")

    def _save_settings(self):
        self._apply_settings()
        if self.settings_status.cget("text").startswith("Invalid"):
            return
        try:
            self.save_config()
            self.settings_status.config(text="Settings saved to config.json.", fg="#7dff9b")
            self.log("Settings saved")
        except Exception as err:
            self.settings_status.config(text=f"Save failed: {err}", fg="#ff8080")

    def _reset_settings(self):
        self.bg_entry.delete(0, "end")
        self.bg_entry.insert(0, DEFAULT_CONFIG["bg"])
        self.panel_entry.delete(0, "end")
        self.panel_entry.insert(0, DEFAULT_CONFIG["panel"])
        self.fg_entry.delete(0, "end")
        self.fg_entry.insert(0, DEFAULT_CONFIG["fg"])
        self.accent_entry.delete(0, "end")
        self.accent_entry.insert(0, DEFAULT_CONFIG["accent"])
        self.select_bg_entry.delete(0, "end")
        self.select_bg_entry.insert(0, DEFAULT_CONFIG["select_bg"])
        self.font_size_scale.set(DEFAULT_CONFIG["font_size"])
        self.font_family_var.set(DEFAULT_CONFIG["font_family_mode"])
        self._apply_settings()
        self.save_config()
        self.settings_status.config(text="Reset to RedBlack defaults.", fg="#7dff9b")
        self.log("Settings reset to default")

    def _reset_ui_layout(self):
        self.tool_help_visible = True
        if hasattr(self, "sidebar_network_parent_id"):
            self.sidebar_tree.item(self.sidebar_network_parent_id, open=True)
        self._set_current_tool("Ping")
        self._clear_tool_output()
        self._set_tool_status("Ready")
        self._update_tool_hint_text()
        self.set_active_panel("Files")
        self._save_last_tool_state()
        self.save_config()
        self.settings_status.config(text="UI layout reset.", fg="#7dff9b")
        self.log("UI layout reset")

    def _show_settings_panel(self):
        self.set_active_panel("Settings")
        self._refresh_user_list_label()
        self._enforce_role_permissions()
        self.log("Panel switched: Settings")

    def _show_about_dialog(self):
        text = (
            f"{APP_NAME}\n"
            f"Version: {APP_VERSION}\n\n"
            f"{APP_TAGLINE}"
        )
        messagebox.showinfo("About DeeOps Toolkit", text, parent=self.root)
        self.log("About dialog opened")
        self._sync_sidebar_selection()

    def _logout(self):
        self.log(f"Logout: user '{self.current_user}'")
        if self.current_tool_cancel_event:
            self.current_tool_cancel_event.set()
        self._unbind_main_shortcuts()
        self.root.unbind("<Control-k>")

        self.current_user = None
        self.current_role = "admin"
        self.current_panel_name = ""
        self.current_vault_path = VAULT_ROOT.resolve()

        if hasattr(self, "main_frame") and self.main_frame.winfo_exists():
            self.main_frame.destroy()

        self.sidebar_buttons = {}
        self.login_frame.pack(fill="both", expand=True)
        self.username_entry.delete(0, "end")
        self.password_entry.delete(0, "end")
        self.status_label.config(text="Logged out.", fg=self.color_fg)
        self.apply_theme()
        self._show_login_view()


def main():
    root = tk.Tk()
    CyberToolkitApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()


