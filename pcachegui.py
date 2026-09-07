import os
import re
import sys
import ctypes
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from io import StringIO

# Run from the project root so "config/settings.json" and the modules/
# package resolve exactly like they do for pcache.py.
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(PROJECT_ROOT)
sys.path.insert(0, PROJECT_ROOT)

from modules.pcache_arp_scan import ArpProcessor
from modules.pcache_passive_scan import PassiveScan
from modules.pcache_system_info import SystemInfo
from modules.pcache_vendor_scan import VendorLu
from modules.pcache_ping_scan import PingScan

try:
    from scapy.all import get_if_list
except Exception:
    get_if_list = None

ICON_PATH = os.path.join(PROJECT_ROOT, "assets", "pcachelogo.ico")

# Windows groups running windows in the taskbar - and picks the icon
# to show for that group - by the process's "App User Model ID",
# which defaults to python.exe/pythonw.exe's own icon (a generic
# Python icon) unless the app claims its own ID. This has to happen
# before any window is created, so it's done here at import time
# rather than inside the GUI class.
if sys.platform == "win32":
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Pcache.App")
    except Exception:
        pass



BG_DARK = "#2b2b2b"         
FG_TEXT = "#e0e0e0"          
FG_ACCENT = "#90EE90"        
PLACEHOLDER_FG = "#8a8a8a"  

OUTPUT_BG = "#1e1e1e"       
OUTPUT_SHADOW = "#141414"   
OUTPUT_FG = "#86efac"       
GRID_DOT = "#282828"         

ENTRY_BG = "#1c1c1c"

BTN_BG = "#2e2e2e"         
BTN_BG_HOVER = "#3a3a3a"
BTN_BORDER = "#454545"
BTN_FG = "#e0e0e0"

# Strips ANSI/SGR escape sequences (e.g. ESC[3;35m, ESC[0m) that some
# of the underlying modules print for terminal coloring - the Tk Text
# widget doesn't interpret them, so they'd otherwise show up as raw
# "[3;35m" / "[0m" clutter around IPs and MAC addresses.
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\[[0-9]+(?:;[0-9]+)*m")

# The underlying scan modules print IP / MAC / vendor columns padded
# with runs of spaces. Collapse those runs into a single tab so the
# three fields line up cleanly and are genuinely tab-separated.
COLUMN_GAP_RE = re.compile(r" {2,}")

# Used by _tabify_result_line below to pull the IP and MAC back out of
# an already-formatted result line, regardless of how the module
# itself spaced them, so the fields can be rejoined with guaranteed
# tabs instead of whatever spacing happened to survive.
_RESULT_IP_RE = re.compile(
    r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"
)
_RESULT_MAC_RE = re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b")

# The underlying scan modules print a plain column header ("IP    MAC
# Vendor") above their result rows. It's not data - just labels for a
# table layout the tab-separated output doesn't need - so it's
# dropped entirely rather than reformatted.
_RESULT_HEADER_RE = re.compile(r"^\s*ip\s+mac\s+vendor\s*$", re.I)


def _tabify_result_line(line):
    """Reformat an "<ip> ... <mac> ... <vendor>" result line so the
    IP, MAC, and vendor fields are separated by real tabs, regardless
    of how the underlying module spaced them. Lines that don't
    contain both an IP and a MAC (headers, status lines, ping rows,
    vendor-only lines, etc.) are returned unchanged."""
    ip_match = _RESULT_IP_RE.search(line)
    mac_match = _RESULT_MAC_RE.search(line)
    if not ip_match or not mac_match:
        return line
    ip = ip_match.group(0)
    mac = mac_match.group(0)
    vendor = line[mac_match.end():].strip(" \t|-:")
    return f"{ip}\t{mac}\t{vendor}" if vendor else f"{ip}\t{mac}"


def _tabify_result_text(text):
    """Apply _tabify_result_line across every line of a block of scan
    output, preserving the original line breaks, and drop the plain
    "IP MAC Vendor" column header line outright so the raw output is
    just the scanned rows."""
    lines = [
        _tabify_result_line(line)
        for line in text.split("\n")
        if not _RESULT_HEADER_RE.match(line)
    ]
    return "\n".join(lines)


def round_rect(canvas, x1, y1, x2, y2, r, **kwargs):
    """Draw a rounded rectangle on a Canvas and return its item id."""
    r = min(r, (x2 - x1) / 2, (y2 - y1) / 2)
    if r < 0:
        r = 0
    points = [
        x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
        x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
        x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
    ]
    return canvas.create_polygon(points, smooth=True, **kwargs)


class RoundedButton(tk.Canvas):
    """A flat, rounded-corner button drawn on a Canvas, since ttk
    buttons can't get a border radius. Behaves like a normal button:
    takes a command, shows a hover state, supports disabling. Plain
    grey fill with a visible outline - no gloss/sheen."""

    def __init__(self, parent, text, command=None, width=190, height=36,
                 radius=5, bg=BG_DARK, fill=BTN_BG, hover_fill=BTN_BG_HOVER,
                 border=BTN_BORDER, fg=BTN_FG, font=("Segoe UI", 10)):
        super().__init__(parent, width=width, height=height, bg=bg,
                          highlightthickness=0, bd=0, cursor="hand2")
        self.command = command
        self.width = width
        self.height = height
        self.radius = radius
        self.fill = fill
        self.hover_fill = hover_fill
        self.border = border
        self.fg = fg
        self.enabled = True

        self._shape_id = round_rect(
            self, 1, 1, width - 1, height - 1, radius,
            fill=fill, outline=border, width=1,
        )

        self._text_id = self.create_text(
            width / 2, height / 2, text=text, fill=fg, font=font
        )

        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)

    def _on_enter(self, event):
        if self.enabled:
            self.itemconfig(self._shape_id, fill=self.hover_fill)

    def _on_leave(self, event):
        self.itemconfig(self._shape_id, fill=self.fill)

    def _on_click(self, event):
        if self.enabled and self.command:
            self.command()

    def set_enabled(self, enabled):
        self.enabled = enabled
        self.configure(cursor="hand2" if enabled else "arrow")
        self.itemconfig(self._text_id, fill=self.fg if enabled else "#777777")

    def set_text(self, text):
        self.itemconfig(self._text_id, text=text)



class NetworkGraphPanel(tk.Frame):
    """Clean left-to-right animated network mind map.

    The interaction is intentionally staged:
      1. Scan -> only the target appears.
      2. Click target -> IP branches smoothly grow out.
      3. Hover an IP -> it gets a soft lift/glow effect.
      4. Click an IP -> ONLY that IP's detail branches animate in.
      5. Click the IP again / its close button -> its details collapse.
      6. Click the target again / its close button -> all IP branches collapse.

    Important: opening an IP never replays the target/IP entrance animation.
    """

    def __init__(self, parent, bg=BG_DARK, panel_bg=OUTPUT_BG, radius=10):
        super().__init__(parent, bg=bg)
        self.panel_bg = panel_bg
        self.nodes = {}
        self.target = ""
        self.selected_ip = None
        self.hover_ip = None
        self.expanded = False
        self.field_labels = ("MAC", "VENDOR")
        self.device_mode = False
        self.device_info = {"hostname": "", "ip": "", "mac": ""}
        self.single_mode = False
        self.zoom = 1.0

        self._animation_job = None
        self._animation_started = 0.0
        self._animation_duration = 520
        self._animation_kind = None
        self._animation_ip = None
        self._animation_finish = None
        self._animation_progress = 1.0

        self.canvas = tk.Canvas(
            self, bg=panel_bg, highlightthickness=0, bd=0, cursor="arrow"
        )
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<Configure>", lambda e: self.redraw())
        self.canvas.bind("<Button-1>", self._on_click)
        self.canvas.bind("<Motion>", self._on_motion)
        self.canvas.bind("<Leave>", self._on_leave)
        # Mouse wheel zoom: Windows/Mac report <MouseWheel> with a
        # signed delta; X11/Linux instead sends discrete Button-4/5
        # events, so both are bound to cover every platform.
        self.canvas.bind("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind("<Button-4>", self._on_mousewheel_linux)
        self.canvas.bind("<Button-5>", self._on_mousewheel_linux)

    def clear(self):
        self._cancel_animation()
        self.nodes.clear()
        self.target = ""
        self.selected_ip = None
        self.hover_ip = None
        self.expanded = False
        self.field_labels = ("MAC", "VENDOR")
        self.device_mode = False
        self.device_info = {"hostname": "", "ip": "", "mac": ""}
        self.single_mode = False
        self.redraw()

    def set_target(self, target):
        self._cancel_animation()
        self.target = target.strip()
        self.selected_ip = None
        self.hover_ip = None
        self.expanded = False
        self.field_labels = ("MAC", "VENDOR")
        self.device_mode = False
        self.device_info = {"hostname": "", "ip": "", "mac": ""}
        self.single_mode = False
        self._start_animation("target_in", duration=420)

    def set_single_target(self, target):
        """Single-node mode for tools that only ever look up one
        thing (Vendor Lookup): everything discovered gets folded into
        one node - keyed by the target itself - showing MAC/VENDOR,
        instead of a separate root + per-result branches."""
        self._cancel_animation()
        self.target = target.strip()
        self.selected_ip = None
        self.hover_ip = None
        self.expanded = False
        self.field_labels = ("MAC", "VENDOR")
        self.device_mode = False
        self.single_mode = True
        self.nodes = {
            self.target: {"ip": self.target, "mac": "", "vendor": "", "raw": ""}
        }
        self._start_animation("target_in", duration=420)

    def set_device_target(self, label="This device"):
        """Special single-node mode for the System Info tab: instead
        of building one node per IP/MAC found in the output (which is
        what every other scan does), show exactly one node - this
        device - that opens into a hostname/IP/MAC detail card."""
        self._cancel_animation()
        self.target = label.strip() or "This device"
        self.selected_ip = None
        self.hover_ip = None
        self.expanded = False
        self.device_mode = True
        self.single_mode = False
        self.device_info = {"hostname": "", "ip": "", "mac": ""}
        self.nodes = {
            self.target: {"ip": self.target, "mac": "", "vendor": "", "raw": ""}
        }
        self._start_animation("target_in", duration=420)

    def add_device_output(self, text):
        """Parse SystemInfo's output for hostname/IP/MAC lines and
        update the single 'this device' node. Unlike add_output, this
        never creates extra nodes - everything found just fills in
        the one device's detail card."""
        if not text:
            return

        ip_re = re.compile(
            r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)"
            r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"
        )
        mac_re = re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b")

        changed = False
        for raw in re.split(r"[\r\n]+", text):
            line = raw.strip()
            if not line or line.startswith("-"):
                continue
            lower = line.lower()

            if "hostname" in lower or "host name" in lower:
                # Some system-info output uses a dot-leader before the
                # value (e.g. "Host Name . . . . . . . : DESKTOP-ABC"),
                # so split on the first colon when there is one, and
                # always strip stray leading dots/dashes/space after.
                if ":" in line:
                    value = line.split(":", 1)[1]
                else:
                    parts = re.split(r"[.\-]{2,}", line, maxsplit=1)
                    value = parts[1] if len(parts) > 1 else ""
                value = value.strip(" \t.-:")
                if value and value != self.device_info.get("hostname"):
                    self.device_info["hostname"] = value
                    changed = True
                continue

            if re.search(r"\bmac\b", lower):
                m = mac_re.search(line)
                if m:
                    mac = m.group(0).upper()
                    if mac != self.device_info.get("mac"):
                        self.device_info["mac"] = mac
                        changed = True
                continue

            if re.search(r"\bip\b", lower):
                m = ip_re.search(line)
                if m:
                    ip = m.group(0)
                    if ip != self.device_info.get("ip"):
                        self.device_info["ip"] = ip
                        changed = True
                continue

        if changed:
            self.redraw()

    def add_output(self, text):
        """Parse scanner output into IP/MAC -> detail branches. Handles
        lines with an IP+MAC (ARP/passive discovery), an IP alone
        (ping replies), or a MAC alone (vendor lookup by MAC) - keyed
        by whichever identifier the line actually has."""
        if not text:
            return

        ip_re = re.compile(
            r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)"
            r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"
        )
        mac_re = re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b")

        changed = False
        for raw in re.split(r"[\r\n]+", text):
            line = raw.strip()
            if not line:
                continue

            # Lines like "-Initiating Pcache scan" / "-Pcache scan
            # report for <ip>" are cosmetic status text, not data -
            # skip them outright so they can't get mistaken for a
            # real result (they'd otherwise poison a node's detail
            # fields with junk like "-Pcache scan report for").
            if line.startswith("-"):
                continue

            # A header row such as "Ip Address  Status    Type"
            # means we're looking at ping-style output - switch the
            # detail card's labels to match and move on; it's a
            # header, not a result to turn into a node.
            if re.search(r"\bstatus\b", line, re.I) and re.search(r"\btype\b", line, re.I):
                self.field_labels = ("STATUS", "TYPE")
                continue

            ips = ip_re.findall(line)
            mac_match = mac_re.search(line)
            if not ips and not mac_match:
                continue

            # In ping mode the data row is "<ip>\t<status>\t<type>" -
            # parse it by column instead of the generic MAC/vendor
            # scraping below, so exactly one node is made per IP and
            # its two fields are the actual status and type.
            if self.field_labels == ("STATUS", "TYPE") and ips:
                ip = ips[0]
                columns = [c.strip() for c in line.split("\t")]
                status_val = columns[1] if len(columns) > 1 else ""
                type_val = columns[2] if len(columns) > 2 else ""
                node = self.nodes.setdefault(ip, {
                    "ip": ip, "mac": "", "vendor": "", "raw": ""
                })
                old = dict(node)
                node["raw"] = line
                if status_val:
                    node["mac"] = status_val
                if type_val:
                    node["vendor"] = type_val
                changed = changed or old != node
                continue

            mac = mac_match.group(0).upper() if mac_match else ""
            # Key by every IP found; if there's no IP at all (a plain
            # MAC-only vendor lookup line), key by the MAC instead so
            # the result still gets a node. In single_mode (Vendor
            # Lookup) everything folds into the one target node
            # instead, regardless of what identifier the line has.
            if self.single_mode:
                keys = [self.target]
            else:
                keys = ips if ips else [mac]

            for key in keys:
                node = self.nodes.setdefault(key, {
                    "ip": key, "mac": "", "vendor": "", "raw": ""
                })
                old = dict(node)
                node["raw"] = line
                if mac:
                    node["mac"] = mac
                if mac_match:
                    remainder = line[mac_match.end():].strip(" \t|-:")
                    if remainder:
                        node["vendor"] = remainder
                else:
                    pieces = [p for p in line.split() if p != key]
                    if pieces and not node["vendor"]:
                        node["vendor"] = " ".join(pieces)
                changed = changed or old != node

        if changed:
            self.redraw()

    @staticmethod
    def _ease_out(t):
        t = max(0.0, min(1.0, t))
        return 1.0 - (1.0 - t) ** 3

    @staticmethod
    def _ease_back(t):
        t = max(0.0, min(1.0, t))
        c1 = 1.70158
        c3 = c1 + 1
        return 1 + c3 * (t - 1) ** 3 + c1 * (t - 1) ** 2

    @staticmethod
    def _ease_in_out(t):
        t = max(0.0, min(1.0, t))
        return t * t * (3.0 - 2.0 * t)

    def _cancel_animation(self):
        if self._animation_job is not None:
            try:
                self.after_cancel(self._animation_job)
            except Exception:
                pass
        self._animation_job = None
        self._animation_kind = None
        self._animation_ip = None
        self._animation_finish = None
        self._animation_progress = 1.0

    def _start_animation(self, kind, ip=None, duration=520, finish=None):
        self._cancel_animation()
        self._animation_kind = kind
        self._animation_ip = ip
        self._animation_duration = duration
        self._animation_finish = finish
        self._animation_started = __import__("time").perf_counter()
        self._animation_progress = 0.0
        self.redraw(0.0)
        self._animation_job = self.after(16, self._animate)

    def _animate(self):
        import time
        elapsed = (time.perf_counter() - self._animation_started) * 1000.0
        progress = self._ease_out(elapsed / max(1, self._animation_duration))
        self._animation_progress = progress
        self.redraw(progress)

        if elapsed < self._animation_duration:
            self._animation_job = self.after(16, self._animate)
            return

        self._animation_job = None
        finish = self._animation_finish
        self._animation_kind = None
        self._animation_ip = None
        self._animation_finish = None
        self._animation_progress = 1.0
        if finish:
            finish()
        self.redraw(1.0)

    @staticmethod
    def _curve_points(x1, y1, x2, y2, bend=0.42, steps=16):
        """Cubic control points for a clean native Tkinter spline.
        Keeping the point count moderate avoids the tiny stepped/pixel look
        caused by feeding an already-sampled Bezier curve back through
        Canvas's spline interpolation.
        """
        dx = x2 - x1
        c1x = x1 + dx * bend
        c2x = x2 - dx * bend
        points = []
        for i in range(steps + 1):
            t = i / steps
            u = 1.0 - t
            x = (u**3 * x1 + 3*u*u*t*c1x +
                 3*u*t*t*c2x + t**3*x2)
            y = (u**3 * y1 + 3*u*u*t*y1 +
                 3*u*t*t*y2 + t**3*y2)
            points.extend((x, y))
        return points

    @property
    def _single_result(self):
        """True when there's exactly one discovered result and it's
        keyed by the target itself (a ping reply). In that case we
        show just that one clickable node instead of a separate
        root + branch - there's nothing else to expand into. The
        System Info tab's single "this device" node reuses the same
        single-node view, so device_mode counts too - as does
        single_mode, used by Vendor Lookup."""
        if self.device_mode or self.single_mode:
            return True
        return (
            self.field_labels == ("STATUS", "TYPE")
            and len(self.nodes) == 1
            and self.target in self.nodes
        )

    @staticmethod
    def _single_result_geometry(w, h):
        cx, cy = w * 0.28, h / 2
        detail_end_x = min(w - 260, cx + 160)
        return cx, cy, detail_end_x

    def _detail_rows(self, ip):
        """Label/value pairs for the open node's detail card. The
        'this device' view always shows hostname/IP/MAC; every other
        single-node or branch view shows its usual two fields."""
        if self.device_mode:
            info = self.device_info
            return [
                ("HOSTNAME", info.get("hostname") or "not detected"),
                ("IP", info.get("ip") or "not detected"),
                ("MAC", info.get("mac") or "not detected"),
            ]
        node = self.nodes.get(ip, {})
        label1, label2 = self.field_labels
        return [
            (label1, node.get("mac") or "not detected"),
            (label2, node.get("vendor") or "not detected"),
        ]

    @staticmethod
    def _row_offsets(count):
        """Vertical offsets for `count` detail-card rows, centered on
        the node's y position."""
        if count <= 1:
            return [0]
        if count == 2:
            return [-22, 22]
        step = 26
        start = -step * (count - 1) / 2
        return [start + i * step for i in range(count)]

    def _layout(self):
        w = max(self.canvas.winfo_width(), 760)
        h = max(self.canvas.winfo_height(), 360)
        ips = sorted(self.nodes)
        root_x = 112
        center_y = h / 2
        ip_x = max(300, min(370, w * 0.43))
        # Capped (not grown) by window width - keeps the node->detail-card
        # connector line short and compact instead of stretching further
        # the wider the window gets. Must stay comfortably above 138px
        # (the fixed 60px + 78px eaten up by the node/card edge margins
        # in the drawing code below), or the connector collapses to a
        # zero/negative-length, invisible line.
        detail_x = min(ip_x + 185, w - 260)

        positions = {}
        count = len(ips)
        if count:
            spacing = 98
            if count > 1:
                spacing = min(spacing, max(72, (h - 120) / (count - 1)))
            total = (count - 1) * spacing
            start_y = center_y - total / 2
            for i, ip in enumerate(ips):
                y = start_y + i * spacing
                positions[ip] = {
                    "ip": (ip_x, y),
                    "mac": (detail_x, y - 22),
                    "vendor": (detail_x, y + 22),
                }
        return positions, (root_x, center_y)

    def _rounded_node(self, x, y, text, width, height, *, selected=False,
                      hovered=False, root=False, tag=None, scale=1.0):
        scale = max(0.05, scale)
        width *= scale
        height *= scale

        # Soft two-layer hover treatment: a larger quiet outline behind the
        # node gives a clean "lift" without relying on blurry canvas effects.
        if hovered and not root:
            round_rect(
                self.canvas,
                x - width/2 - 4, y - height/2 - 4,
                x + width/2 + 4, y + height/2 + 4,
                (height + 8)/2,
                fill="#292929", outline="#58798a", width=1,
                tags=("hover_glow", tag),
            )

        outline = FG_ACCENT if (selected or hovered or root) else BTN_BORDER
        fill = "#353535" if hovered and not root else BTN_BG
        border_width = 2 if (selected or hovered or root) else 1

        round_rect(
            self.canvas, x - width/2, y - height/2,
            x + width/2, y + height/2, height/2,
            fill=fill, outline=outline, width=border_width, tags=tag,
        )
        self.canvas.create_text(
            x, y, text=text,
            fill=FG_ACCENT if root else ("#f1f5f9" if hovered else FG_TEXT),
            font=("Segoe UI", max(7, int(10 * scale)),
                  "bold" if (root or selected or hovered) else "normal"),
            width=max(40, width - 18), tags=tag,
        )

    def _draw_grid(self, w, h):
        """Faint dot-grid backdrop so the canvas reads as a mapping
        surface rather than empty space. Skipped while an animation
        is actively running - redrawing ~200+ individual dots on every
        16ms animation frame is what made transitions feel heavy."""
        step = 40
        r = 0.9
        for gy in range(step, int(h), step):
            for gx in range(step, int(w), step):
                self.canvas.create_oval(
                    gx - r, gy - r, gx + r, gy + r,
                    fill=GRID_DOT, outline="", tags="grid",
                )

    def _draw_status_dot(self, x, y, width, height, resolved, scale=1.0):
        """Small colored dot offset just outside the left edge of an IP node:
        teal once we have a MAC for it, dim grey while still just an address."""
        r = 4.5 * max(0.6, scale)
        gap = 10 * scale
        cx = x - width/2 - gap
        color = "#5fd0a0" if resolved else "#6b6b6b"
        self.canvas.create_oval(
            cx - r, y - r, cx + r, y + r,
            fill=color, outline="", tags="status_dot",
        )

    def _draw_badge(self, x, y, text):
        """Small pill badge (used for the discovered-device count)."""
        pad = 8
        approx_w = pad * 2 + len(text) * 6
        round_rect(
            self.canvas, x - approx_w/2, y - 11, x + approx_w/2, y + 11, 11,
            fill="#1e3a28", outline=FG_ACCENT, width=1, tags="badge",
        )
        self.canvas.create_text(
            x, y, text=text, fill=FG_ACCENT,
            font=("Segoe UI", 8, "bold"), tags="badge",
        )

    def _draw_connector(self, x1, y1, x2, y2, progress=1.0, width=1.8,
                        fill="#565656", glow=False):
        if progress <= 0:
            return
        progress = max(0.0, min(1.0, progress))
        ex = x1 + (x2 - x1) * progress
        ey = y1 + (y2 - y1) * progress
        pts = self._curve_points(x1, y1, ex, ey, steps=16)

        if glow:
            self.canvas.create_line(
                *pts, fill="#344650", width=width + 4,
                smooth=True, splinesteps=14, capstyle="round", joinstyle="round"
            )
        self.canvas.create_line(
            *pts, fill=fill, width=width,
            smooth=True, splinesteps=14, capstyle="round", joinstyle="round"
        )
        # Small terminal dots give the connector a "plugged in" feel
        # instead of a line just trailing off into nothing.
        dot_color = "#7fb8c9" if glow else fill
        for dx, dy in ((x1, y1), (ex, ey)):
            self.canvas.create_oval(
                dx - 2.4, dy - 2.4, dx + 2.4, dy + 2.4,
                fill=dot_color, outline="", tags="connector_dot",
            )

    def _ip_branch_progress(self, progress, index):
        """Only the target->IP animation uses this progress.
        Detail animations keep all existing IP branches at 100%."""
        kind = self._animation_kind
        if kind == "ips_in":
            delay = min(0.36, index * 0.07)
            if progress <= delay:
                return 0.0
            return self._ease_out((progress - delay) / max(0.001, 1.0 - delay))
        if kind == "target_close":
            delay = min(0.22, index * 0.04)
            if progress <= delay:
                return 1.0
            return 1.0 - self._ease_out((progress - delay) / max(0.001, 1.0 - delay))
        return 1.0

    def redraw(self, progress=1.0):
        """Draw everything at normal (unzoomed) scale, then scale the
        whole canvas around its center to the current zoom level. Runs
        on every frame, so it's always drawn fresh before scaling -
        zoom never compounds across redraws."""
        self._redraw_content(progress)
        if abs(self.zoom - 1.0) > 0.001:
            w = max(self.canvas.winfo_width(), 760)
            h = max(self.canvas.winfo_height(), 360)
            self.canvas.scale("all", w / 2, h / 2, self.zoom, self.zoom)

    def _current_progress(self):
        return self._animation_progress if self._animation_job is not None else 1.0

    def set_zoom(self, value):
        self.zoom = max(0.5, min(2.0, round(value, 2)))
        self.redraw(self._current_progress())

    def zoom_in(self):
        self.set_zoom(self.zoom + 0.15)

    def zoom_out(self):
        self.set_zoom(self.zoom - 0.15)

    def zoom_reset(self):
        self.set_zoom(1.0)

    def _on_mousewheel(self, event):
        delta = getattr(event, "delta", 0)
        if delta > 0:
            self.zoom_in()
        elif delta < 0:
            self.zoom_out()

    def _on_mousewheel_linux(self, event):
        if event.num == 4:
            self.zoom_in()
        elif event.num == 5:
            self.zoom_out()

    def _redraw_content(self, progress=1.0):
        self.canvas.delete("all")
        w = max(self.canvas.winfo_width(), 760)
        h = max(self.canvas.winfo_height(), 360)
        if self._animation_kind is None:
            self._draw_grid(w, h)
        positions, (root_x, root_y) = self._layout()

        if not self.target:
            cx, cy = w / 2, h / 2 - 10
            for rad in (26, 42, 58):
                self.canvas.create_oval(
                    cx - rad, cy - rad, cx + rad, cy + rad,
                    outline="#333333", width=1,
                )
            self.canvas.create_oval(
                cx - 4, cy - 4, cx + 4, cy + 4, fill="#444444", outline="",
            )
            self.canvas.create_text(
                cx, cy + 80,
                text="Run a scan to build the target mind map",
                fill=PLACEHOLDER_FG, font=("Segoe UI", 11),
            )
            return

        if self._single_result:
            self._draw_single_result(w, h, progress)
            return

        root_progress = progress if self._animation_kind == "target_in" else 1.0
        root_eased = self._ease_out(root_progress)
        root_scale = 0.86 + 0.14 * self._ease_back(root_eased)
        root_draw_x = root_x - 48 * (1 - root_eased)
        root_draw_y = root_y + 22 * (1 - root_eased)

        show_ips = self.expanded or self._animation_kind == "target_close"
        if show_ips:
            ips_sorted = list(positions.keys())
            for index, ip in enumerate(ips_sorted):
                pos = positions[ip]
                branch_progress = self._ip_branch_progress(progress, index)
                start_x, start_y = root_x + 75, root_y
                x, y = pos["ip"]
                # The node settles upward into its final spot rather than
                # arriving via a plain straight-line interpolation - the
                # connector tip is offset the same way so it stays glued
                # to the node as both rise into place together.
                rise = 16 * (1 - branch_progress)
                target_y = y + rise

                self._draw_connector(
                    start_x, start_y, x - 60, target_y,
                    branch_progress,
                    width=2.35,
                    fill="#62676c",
                    glow=(ip == self.hover_ip),
                )

                ix = start_x + (x - start_x) * branch_progress
                iy = start_y + (target_y - start_y) * branch_progress
                hovered = (ip == self.hover_ip)
                node_scale = (0.88 + 0.12 * branch_progress) * (1.045 if hovered else 1.0)
                self._rounded_node(
                    ix, iy, ip, width=120, height=42,
                    selected=(ip == self.selected_ip),
                    hovered=hovered,
                    tag=("ip_node", ip),
                    scale=node_scale,
                )
                if branch_progress > 0.6:
                    resolved = bool(self.nodes.get(ip, {}).get("mac"))
                    self._draw_status_dot(ix, iy, 120, 42, resolved, scale=node_scale)

            # Detail branches are completely independent of the IP entrance
            # animation. Clicking an IP therefore never makes the IP web replay.
            if self.selected_ip and self.selected_ip in positions:
                ip = self.selected_ip
                pos = positions[ip]
                if self._animation_kind == "details_in" and self._animation_ip == ip:
                    dprogress = progress
                elif self._animation_kind == "details_close" and self._animation_ip == ip:
                    dprogress = 1.0 - progress
                else:
                    dprogress = 1.0
                dprogress = self._ease_in_out(dprogress)

                x, y = pos["ip"]
                dx, _ = pos["mac"]
                detail_start_x = x + 60
                detail_end_x = dx - 78
                rise_detail = 12 * (1 - dprogress)

                for dy in (-22, 22):
                    self._draw_connector(
                        detail_start_x, y,
                        detail_end_x, y + dy + rise_detail,
                        dprogress,
                        width=2.05,
                        fill="#5c6268",
                    )

                if dprogress > 0.25:
                    round_rect(
                        self.canvas,
                        detail_end_x - 14, y - 40 + rise_detail,
                        detail_end_x + 214, y + 40 + rise_detail, 10,
                        fill="#242424", outline=BTN_BORDER, width=1,
                        tags=("detail_card", ip),
                    )

                mac = self.nodes[ip].get("mac") or "not detected"
                vendor = self.nodes[ip].get("vendor") or "not detected"
                label1, label2 = self.field_labels
                detail_rows = [
                    (label1, mac, y - 22),
                    (label2, vendor, y + 22),
                ]
                for label, value, yy in detail_rows:
                    target_yy = yy + rise_detail
                    ex = detail_start_x + (detail_end_x - detail_start_x) * dprogress
                    ey = y + (target_yy - y) * dprogress
                    self.canvas.create_rectangle(
                        ex, ey - 9, ex + 6, ey - 3,
                        fill=FG_ACCENT, outline="", tags=("detail_node", ip),
                    )
                    self.canvas.create_text(
                        ex + 12, ey - 6, text=label, anchor="w", fill=FG_ACCENT,
                        font=("Segoe UI", 7, "bold"), tags=("detail_node", ip),
                    )
                    self.canvas.create_text(
                        ex, ey + 8, text=value, anchor="w", fill=FG_TEXT,
                        font=("Segoe UI", 9), width=195,
                        tags=("detail_node", ip),
                    )

        # Root stays above branch lines.
        self._rounded_node(
            root_draw_x, root_draw_y,
            f"✦  {self.target}", width=150, height=48,
            root=True, tag="target_node", scale=root_scale,
        )
        if self.nodes and root_eased > 0.6:
            count = len(self.nodes)
            label = f"{count} device{'s' if count != 1 else ''}"
            self._draw_badge(root_draw_x, root_draw_y + 38 * root_scale, label)

        if not self.expanded and not self._animation_kind:
            self.canvas.create_text(
                root_x + 120, root_draw_y + 55,
                text="Click the target to explore",
                fill=PLACEHOLDER_FG, font=("Segoe UI", 9), anchor="w",
            )

    def _draw_single_result(self, w, h, progress):
        """Render the single-node view used for a ping-style result:
        one clickable node (no separate root), which opens straight
        into its Status/Type detail card."""
        ip = self.target
        cx, cy, detail_end_x = self._single_result_geometry(w, h)

        entrance = progress if self._animation_kind == "target_in" else 1.0
        eased = self._ease_out(entrance)
        scale = 0.86 + 0.14 * self._ease_back(eased)
        draw_x = cx - 40 * (1 - eased)
        draw_y = cy

        hovered = (self.hover_ip == ip)
        selected = (self.selected_ip == ip)
        self._rounded_node(
            draw_x, draw_y, ip, width=170, height=48,
            selected=selected, hovered=hovered, root=True,
            tag=("ip_node", ip), scale=scale,
        )
        resolved = bool(self.nodes.get(ip, {}).get("mac"))
        self._draw_status_dot(draw_x, draw_y, 170, 48, resolved, scale=scale)

        if self.selected_ip == ip:
            if self._animation_kind == "details_in":
                dprogress = progress
            elif self._animation_kind == "details_close":
                dprogress = 1.0 - progress
            else:
                dprogress = 1.0
            dprogress = self._ease_in_out(dprogress)

            detail_start_x = draw_x + 90
            rise_detail = 12 * (1 - dprogress)

            rows = self._detail_rows(ip)
            offsets = self._row_offsets(len(rows))
            card_half = abs(offsets[0]) + 18

            for dy in offsets:
                self._draw_connector(
                    detail_start_x, draw_y,
                    detail_end_x, draw_y + dy + rise_detail,
                    dprogress, width=2.05, fill="#5c6268",
                )

            if dprogress > 0.25:
                round_rect(
                    self.canvas,
                    detail_end_x - 14, draw_y - card_half + rise_detail,
                    detail_end_x + 214, draw_y + card_half + rise_detail, 10,
                    fill="#242424", outline=BTN_BORDER, width=1,
                    tags=("detail_card", ip),
                )

            detail_rows = [
                (label, value, draw_y + dy)
                for (label, value), dy in zip(rows, offsets)
            ]
            for label, value, yy in detail_rows:
                target_yy = yy + rise_detail
                ex = detail_start_x + (detail_end_x - detail_start_x) * dprogress
                ey = draw_y + (target_yy - draw_y) * dprogress
                self.canvas.create_rectangle(
                    ex, ey - 9, ex + 6, ey - 3,
                    fill=FG_ACCENT, outline="", tags=("detail_node", ip),
                )
                self.canvas.create_text(
                    ex + 12, ey - 6, text=label, anchor="w", fill=FG_ACCENT,
                    font=("Segoe UI", 7, "bold"), tags=("detail_node", ip),
                )
                self.canvas.create_text(
                    ex, ey + 8, text=value, anchor="w", fill=FG_TEXT,
                    font=("Segoe UI", 9), width=195,
                    tags=("detail_node", ip),
                )

        elif not self._animation_kind:
            hint = "Click to view info" if self.device_mode else "Click to view status"
            self.canvas.create_text(
                draw_x, draw_y + 55,
                text=hint,
                fill=PLACEHOLDER_FG, font=("Segoe UI", 9),
            )

    def _finish_target_close(self):
        self.selected_ip = None
        self.hover_ip = None
        self.expanded = False

    def _finish_details_close(self):
        self.selected_ip = None

    def _on_click(self, event):
        # Ignore clicks while a branch animation is actively running. This
        # prevents accidental clicks from restarting/reversing the animation.
        if self._animation_job is not None:
            return

        if self._single_result:
            ip = self.target
            w = max(self.canvas.winfo_width(), 760)
            h = max(self.canvas.winfo_height(), 360)
            cx, cy, _ = self._single_result_geometry(w, h)
            if abs(event.x - cx) <= 90 and abs(event.y - cy) <= 30:
                if self.selected_ip == ip:
                    self._start_animation(
                        "details_close", ip=ip, duration=260,
                        finish=self._finish_details_close,
                    )
                else:
                    self.selected_ip = ip
                    self._start_animation("details_in", ip=ip, duration=360)
            return

        positions, (root_x, root_y) = self._layout()

        if abs(event.x-root_x) <= 80 and abs(event.y-root_y) <= 32:
            if self.expanded:
                self._start_animation(
                    "target_close", duration=320,
                    finish=self._finish_target_close,
                )
            else:
                self.expanded = True
                self.selected_ip = None
                self._start_animation("ips_in", duration=480)
            return

        if not self.expanded:
            return

        for ip, pos in positions.items():
            x, y = pos["ip"]
            if abs(event.x-x) <= 68 and abs(event.y-y) <= 30:
                if self.selected_ip == ip:
                    self._start_animation(
                        "details_close", ip=ip, duration=260,
                        finish=self._finish_details_close,
                    )
                else:
                    self.selected_ip = ip
                    self._start_animation("details_in", ip=ip, duration=360)
                return

    def _on_motion(self, event):
        if self._single_result:
            w = max(self.canvas.winfo_width(), 760)
            h = max(self.canvas.winfo_height(), 360)
            cx, cy, detail_end_x = self._single_result_geometry(w, h)
            new_hover = self.target if (
                abs(event.x - cx) <= 90 and abs(event.y - cy) <= 30
            ) else None

            if new_hover != self.hover_ip:
                self.hover_ip = new_hover
                current = self._animation_progress if self._animation_job is not None else 1.0
                self.redraw(current)

            cursor = "hand2" if new_hover else "arrow"

            return

        positions, (root_x, root_y) = self._layout()
        new_hover = None

        if self.expanded:
            for ip, pos in positions.items():
                x, y = pos["ip"]
                if abs(event.x-x) <= 68 and abs(event.y-y) <= 30:
                    new_hover = ip
                    break

        if new_hover != self.hover_ip:
            self.hover_ip = new_hover
            # Preserve the currently running animation frame. Hover must not
            # restart the target/IP/detail animation.
            current = self._animation_progress if self._animation_job is not None else 1.0
            self.redraw(current)

        cursor = "hand2" if new_hover else "arrow"
        if abs(event.x-root_x) <= 82 and abs(event.y-root_y) <= 34:
            cursor = "hand2"
        self.canvas.configure(cursor=cursor)

    def _on_leave(self, event):
        if self.hover_ip is not None:
            self.hover_ip = None
            current = self._animation_progress if self._animation_job is not None else 1.0
            self.redraw(current)
        self.canvas.configure(cursor="arrow")


def add_placeholder(entry, placeholder):
    """Show grey example text inside an (otherwise empty) Entry, that
    clears on focus and comes back if the field is left empty."""
    entry._placeholder = placeholder
    entry._is_placeholder = True
    entry.insert(0, placeholder)
    entry.configure(foreground=PLACEHOLDER_FG)

    def on_focus_in(event):
        if entry._is_placeholder:
            entry.delete(0, tk.END)
            entry.configure(foreground=FG_TEXT)
            entry._is_placeholder = False

    def on_focus_out(event):
        if not entry.get():
            entry.insert(0, entry._placeholder)
            entry.configure(foreground=PLACEHOLDER_FG)
            entry._is_placeholder = True

    entry.bind("<FocusIn>", on_focus_in)
    entry.bind("<FocusOut>", on_focus_out)


def entry_value(entry):
    """Read an Entry's real value, treating a still-showing
    placeholder as empty."""
    if getattr(entry, "_is_placeholder", False):
        return ""
    return entry.get().strip()


class StreamToQueue:
    """File-like object that pushes writes into a queue instead of a
    real terminal, so output from a background thread can be safely
    drawn into the Tkinter Text widget on the main thread. Also strips
    ANSI color codes and turns column padding into real tabs between
    fields like IP / MAC / vendor."""

    def __init__(self, q):
        self.q = q

    def write(self, text):
        if text:
            cleaned = ANSI_ESCAPE_RE.sub("", text)
            cleaned = COLUMN_GAP_RE.sub("\t", cleaned)
            self.q.put(cleaned)

    def flush(self):
        pass

    def isatty(self):
        return False


def stop_thread(thread):
    """Best-effort forceful stop for a running thread by injecting a
    KeyboardInterrupt. Passive scan blocks inside Scapy's sniff() loop
    with no stop switch exposed, so this is the only way to interrupt
    it from the GUI without editing that module. Not 100% guaranteed,
    but works in practice - and closing the app always ends it too,
    since the scan thread is a daemon thread."""
    if not thread or not thread.is_alive():
        return
    tid = thread.ident
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
        ctypes.c_long(tid), ctypes.py_object(KeyboardInterrupt)
    )
    if res > 1:
        ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), None)


class OutputArea(tk.Frame):
    """Pairs the animated network mind map with a plain, always-
    reliable scrolling text log underneath. The map is nicer to look
    at for discovery-style scans, but not every module's output
    parses cleanly into IP/MAC nodes (System Info, some vendor
    lookups) - the raw log guarantees you can always see what a scan
    actually printed."""

    def __init__(self, parent, bg=BG_DARK, panel_bg=OUTPUT_BG):
        super().__init__(parent, bg=bg)

        self.graph = NetworkGraphPanel(self, bg=bg, panel_bg=panel_bg, radius=10)
        self.graph.pack(fill="both", expand=True)

        # Small zoom control overlaid in the corner of the mind map -
        # placed on top of the packed canvas via place(), created
        # after it so it stacks above.
        zoom_bar = tk.Frame(self.graph, bg=panel_bg)
        RoundedButton(
            zoom_bar, "-", command=self._zoom_out, width=28, height=26,
            radius=7, bg=panel_bg,
        ).pack(side="left", padx=(0, 4))
        self.zoom_label = tk.Label(
            zoom_bar, text="100%", bg=panel_bg, fg=FG_TEXT,
            font=("Segoe UI", 9), width=4,
        )
        self.zoom_label.pack(side="left", padx=(0, 4))
        RoundedButton(
            zoom_bar, "+", command=self._zoom_in, width=28, height=26,
            radius=7, bg=panel_bg,
        ).pack(side="left")
        zoom_bar.place(relx=1.0, rely=1.0, x=-14, y=-14, anchor="se")

        log_wrap = tk.Frame(self, bg=bg, height=130)
        log_wrap.pack(fill="x", side="bottom", pady=(10, 0))
        log_wrap.pack_propagate(False)

        self.log_text = tk.Text(
            log_wrap, wrap="word", bg=panel_bg, fg=OUTPUT_FG,
            insertbackground=OUTPUT_FG, borderwidth=0, highlightthickness=0,
            state="disabled",
        )
        log_scroll = ttk.Scrollbar(
            log_wrap, command=self.log_text.yview, style="Dark.Vertical.TScrollbar"
        )
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True, padx=(2, 4), pady=2)
        log_scroll.pack(side="right", fill="y", pady=2)

    def _zoom_in(self):
        self.graph.zoom_in()
        self._sync_zoom_label()

    def _zoom_out(self):
        self.graph.zoom_out()
        self._sync_zoom_label()

    def _sync_zoom_label(self):
        self.zoom_label.configure(text=f"{round(self.graph.zoom * 100)}%")

    def clear(self):
        self.graph.clear()
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state="disabled")

    def set_target(self, target):
        self.graph.set_target(target)

    def set_single_target(self, target):
        self.graph.set_single_target(target)

    def set_device_target(self, target):
        self.graph.set_device_target(target)

    def add_output(self, text):
        self.graph.add_output(text)
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, _tabify_result_text(text))
        self.log_text.see(tk.END)
        self.log_text.configure(state="disabled")

    def add_device_output(self, text):
        self.graph.add_device_output(text)
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, _tabify_result_text(text))
        self.log_text.see(tk.END)
        self.log_text.configure(state="disabled")

    def add_status(self, text):
        """Write a line straight to the text log only, skipping the
        mind-map parser. Used for an instant 'Pinging <ip>...' style
        message the moment a scan starts, before the module itself
        has printed anything - it shouldn't be mistaken for a real
        IP/MAC result line."""
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, text)
        self.log_text.see(tk.END)
        self.log_text.configure(state="disabled")


class PcacheGUI(tk.Tk):

    TOOLS = ["ARP Scan", "Passive Scan", "Ping", "Vendor Lookup", "System Info"]

    def __init__(self):
        super().__init__()
        self.title("Pcache")
        self.geometry("860x640")
        self.minsize(760, 560)
        self.configure(bg=BG_DARK)

        # App/window/taskbar icon. .ico is native on Windows (and
        # keeps every embedded resolution); elsewhere, fall back to
        # loading it through Pillow (which can read .ico directly) as
        # a plain PhotoImage. Kept as an instance attribute in the
        # PIL branch so the PhotoImage survives past this call.
        if not os.path.exists(ICON_PATH):
            print(f"[pcache] icon not found at {ICON_PATH} - skipping", file=sys.stderr)
        else:
            try:
                if sys.platform == "win32":
                    self.iconbitmap(default=ICON_PATH)
                else:
                    from PIL import Image, ImageTk
                    self._app_icon = ImageTk.PhotoImage(Image.open(ICON_PATH))
                    self.iconphoto(True, self._app_icon)
            except Exception as e:
                print(f"[pcache] couldn't set app icon: {e!r}", file=sys.stderr)

        # Match the Windows title bar to the app's dark theme. winfo_id()
        # returns the handle of Tk's inner drawing surface, not the real
        # top-level window that owns the title bar - DWM calls on that id
        # silently do nothing, which is why the bar stayed white. Walking
        # up to the actual top-level via GetParent() is required first.
        if sys.platform == "win32":
            try:
                self.update_idletasks()
                hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
                dwmapi = ctypes.windll.dwmapi

                def _colorref(hex_color):
                    value = int(hex_color[1:], 16)
                    r, g, b = value & 0xFF, (value >> 8) & 0xFF, (value >> 16) & 0xFF
                    return r | (g << 8) | (b << 16)

                def _set_attr(attr, value):
                    dwmapi.DwmSetWindowAttribute(
                        ctypes.c_void_p(hwnd), attr,
                        ctypes.byref(ctypes.c_int(value)), ctypes.sizeof(ctypes.c_int),
                    )

                # Dark title bar text/controls (Windows 10 2004+ and 11).
                # Harmless no-op on older builds - the call just fails and
                # is ignored, same as before.
                DWMWA_USE_IMMERSIVE_DARK_MODE = 20
                _set_attr(DWMWA_USE_IMMERSIVE_DARK_MODE, 1)

                # Custom caption background + text color matching the
                # app's own dark grey / light grey palette (Windows 11
                # 22000+ only; ignored below that).
                DWMWA_CAPTION_COLOR = 35
                DWMWA_TEXT_COLOR = 36
                _set_attr(DWMWA_CAPTION_COLOR, _colorref(BG_DARK))
                _set_attr(DWMWA_TEXT_COLOR, _colorref(FG_TEXT))
            except Exception:
                pass

        self.output_queue = queue.Queue()
        self.active_thread = None
        self.tool_frames = {}
        self.action_frames = {}

        self._build_style()
        self._build_widgets()
        self.after(80, self._poll_output)

    # ---------------- Styling ----------------

    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(".", background=BG_DARK, foreground=FG_TEXT)
        style.configure("TFrame", background=BG_DARK)

        style.configure(
            "Dark.Vertical.TScrollbar",
            background=BG_DARK,
            troughcolor=OUTPUT_BG,
            bordercolor=OUTPUT_BG,
            arrowcolor=FG_TEXT,
            relief="flat",
        )
        style.map(
            "Dark.Vertical.TScrollbar",
            background=[("active", BTN_BG_HOVER), ("pressed", BTN_BG_HOVER)],
        )
        style.configure("TLabel", background=BG_DARK, foreground=FG_TEXT)
        style.configure("TCheckbutton", background=BG_DARK, foreground=FG_TEXT)
        style.map("TCheckbutton", background=[("active", BG_DARK)])
        style.configure(
            "TEntry", fieldbackground=ENTRY_BG, background=ENTRY_BG, foreground=FG_TEXT,
            insertcolor=FG_TEXT, bordercolor=ENTRY_BG, lightcolor=ENTRY_BG,
            darkcolor=ENTRY_BG, borderwidth=1, relief="flat",
        )
        # The "clam" theme colors an entry's border blue while it's
        # focused (i.e. while you're clicked into it) unless that
        # state is overridden explicitly - map it to the app's accent
        # color instead.
        style.map(
            "TEntry",
            bordercolor=[("focus", FG_ACCENT)],
            lightcolor=[("focus", FG_ACCENT)],
            darkcolor=[("focus", FG_ACCENT)],
        )
        style.configure(
            "TCombobox", fieldbackground=ENTRY_BG, background=ENTRY_BG, foreground=FG_TEXT,
            arrowcolor=FG_TEXT, bordercolor=ENTRY_BG, lightcolor=ENTRY_BG,
            darkcolor=ENTRY_BG, borderwidth=1, relief="flat",
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", ENTRY_BG)],
            foreground=[("readonly", FG_TEXT)],
            bordercolor=[("focus", FG_ACCENT)],
            lightcolor=[("focus", FG_ACCENT)],
            darkcolor=[("focus", FG_ACCENT)],
        )
        self.option_add("*TCombobox*Listbox.background", ENTRY_BG)
        self.option_add("*TCombobox*Listbox.foreground", FG_TEXT)
        self.option_add("*TCombobox*Listbox.selectBackground", "#4a4a4a")
        self.option_add("*TCombobox*Listbox.selectForeground", FG_ACCENT)

    # ---------------- Layout ----------------

    def _build_widgets(self):
        # Header bar: dropdown menu icon + tool selector, with the
        # selected tool's inputs laid out inline beside it. Only a top
        # and bottom hairline (no left/right) mark it as a distinct
        # header - a plain frame's highlightthickness border would draw
        # all four sides, so two 1px frames are used instead.
        header_outline = tk.Frame(self, bg=BG_DARK)
        header_outline.pack(fill="x", padx=0, pady=(0, 20))

        tk.Frame(header_outline, bg=BTN_BORDER, height=1).pack(fill="x", side="top")

        header_bar = ttk.Frame(header_outline)
        header_bar.pack(fill="x", padx=12, pady=2)

        tk.Frame(header_outline, bg=BTN_BORDER, height=1).pack(fill="x", side="bottom")

        self.tool_var = tk.StringVar(value=self.TOOLS[0])
        self.tool_selector = ttk.Combobox(
            header_bar,
            textvariable=self.tool_var,
            values=self.TOOLS,
            state="readonly",
            width=16,
        )
        self.tool_selector.pack(side="left", padx=(0, 16))
        self.tool_selector.bind("<<ComboboxSelected>>", self._on_tool_switch)

        # Container that stacks every tool's input row; only the
        # selected one is raised to the top, so switching is instant.
        container = ttk.Frame(header_bar)
        container.pack(side="left", fill="x", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.tool_frames["ARP Scan"] = self._build_arp_tab(container)
        self.tool_frames["Passive Scan"] = self._build_passive_tab(container)
        self.tool_frames["Ping"] = self._build_ping_tab(container)
        self.tool_frames["Vendor Lookup"] = self._build_vendor_tab(container)
        self.tool_frames["System Info"] = self._build_info_tab(container)

        for name, frame in self.tool_frames.items():
            if name == self.tool_var.get():
                frame.grid(row=0, column=0, sticky="w")
            else:
                frame.grid(row=0, column=0, sticky="w")
                frame.grid_remove()

        # Action bar, directly above the output panel, grouped into
        # two pairs: the tool's Run action beside Clear Output (scan
        # controls), then a gap, then Save Results beside Load Results
        # (file controls). All four buttons share the same width so
        # the two pairs line up evenly.
        action_bar = ttk.Frame(self)
        action_bar.pack(fill="x", padx=16, pady=(4, 8))

        actions_stack = ttk.Frame(action_bar)
        actions_stack.pack(side="left")
        actions_stack.grid_rowconfigure(0, weight=1)
        actions_stack.grid_columnconfigure(0, weight=1)

        self.action_frames["ARP Scan"] = self._build_arp_actions(actions_stack)
        self.action_frames["Passive Scan"] = self._build_passive_actions(actions_stack)
        self.action_frames["Ping"] = self._build_ping_actions(actions_stack)
        self.action_frames["Vendor Lookup"] = self._build_vendor_actions(actions_stack)
        self.action_frames["System Info"] = self._build_info_actions(actions_stack)

        for name, frame in self.action_frames.items():
            if name == self.tool_var.get():
                frame.grid(row=0, column=0, sticky="w")
            else:
                frame.grid(row=0, column=0, sticky="w")
                frame.grid_remove()

        RoundedButton(action_bar, "Clear Output", command=self._clear_output, width=150, height=32).pack(
            side="left", padx=(10, 0)
        )

        # Thin vertical divider separating the scan controls (Run,
        # Clear Output) from the file controls (Save, Load) that
        # follow it.
        tk.Frame(action_bar, bg=BTN_BORDER, width=1, height=3).pack(
            side="left", padx=20
        )

        # Save Results and Load Results are both plain one-shot
        # actions on whatever's currently in the output panel - Save
        # writes it out to a .txt file right when you click it (no
        # "save mode" to remember to turn on beforehand), Load reads
        # one back in.
        RoundedButton(
            action_bar, "💾 Save Results", command=self._save_output,
            width=150, height=32,
        ).pack(side="left")

        RoundedButton(
            action_bar, "📂 Load Results", command=self._load_results_file,
            width=150, height=32,
        ).pack(side="left", padx=(10, 0))

        self.output_panel = OutputArea(self)
        self.output_panel.pack(fill="both", expand=True, padx=16, pady=(0, 14))
        self.output_text = None

    # ---------------- Shared tab helpers ----------------

    def _on_tool_switch(self, event=None):
        """Show only the newly selected tool's input panel and action
        button(s) - hide every other one outright so their widgets
        can't visually peek through or steal clicks - and wipe the
        output from whatever was run previously."""
        tool = self.tool_var.get()
        for name, frame in self.tool_frames.items():
            if name == tool:
                frame.grid()
            else:
                frame.grid_remove()
        for name, frame in self.action_frames.items():
            if name == tool:
                frame.grid()
            else:
                frame.grid_remove()
        self._clear_output()

    def _build_arp_tab(self, parent):
        tab = ttk.Frame(parent)

        self.arp_target = ttk.Entry(tab, width=22)
        add_placeholder(self.arp_target, "e.g. 192.168.1.0/24")
        self.arp_target.pack(side="left", padx=(0, 10))

        self.arp_speed = tk.StringVar(value="Default")
        speeds = [
            "Default", "~1 hour", "~20 minutes", "~10 minutes",
            "~5 minutes", "~25 seconds",
        ]
        speed_box = ttk.Combobox(
            tab, textvariable=self.arp_speed, values=speeds, state="readonly", width=14
        )
        speed_box.pack(side="left", padx=(0, 10))

        return tab

    def _build_arp_actions(self, parent):
        frame = ttk.Frame(parent)
        RoundedButton(frame, "Run ARP Scan", command=self._run_arp, width=150, height=32).pack(side="left")
        return frame

    def _build_passive_tab(self, parent):
        tab = ttk.Frame(parent)

        self.passive_target = ttk.Entry(tab, width=22)
        add_placeholder(self.passive_target, "e.g. 192.168.1.0/24")
        self.passive_target.pack(side="left", padx=(0, 10))

        self.passive_iface = ttk.Entry(tab, width=20)
        # Always start empty with a placeholder - never pre-filled
        # with an auto-detected interface - so the user has to type
        # the one they actually want.
        add_placeholder(self.passive_iface, "e.g. eth0")
        self.passive_iface.pack(side="left", padx=(0, 10))

        return tab

    def _build_passive_actions(self, parent):
        frame = ttk.Frame(parent)
        self.passive_running = False
        self.passive_btn = RoundedButton(
            frame, "Start Passive Scan", command=self._toggle_passive, width=150, height=32
        )
        self.passive_btn.pack(side="left")
        return frame

    def _build_ping_tab(self, parent):
        tab = ttk.Frame(parent)

        self.ping_target = ttk.Entry(tab, width=22)
        add_placeholder(self.ping_target, "e.g. 192.168.1.10")
        self.ping_target.pack(side="left", padx=(0, 10))

        return tab

    def _build_ping_actions(self, parent):
        frame = ttk.Frame(parent)
        RoundedButton(frame, "Ping", command=self._run_ping, width=150, height=32).pack(side="left")
        return frame

    def _build_vendor_tab(self, parent):
        tab = ttk.Frame(parent)

        self.vendor_target = ttk.Entry(tab, width=22)
        add_placeholder(self.vendor_target, "e.g. AA:BB:CC:DD:EE:FF")
        self.vendor_target.pack(side="left", padx=(0, 10))

        return tab

    def _build_vendor_actions(self, parent):
        frame = ttk.Frame(parent)
        RoundedButton(frame, "Lookup Vendor", command=self._run_vendor, width=150, height=32).pack(side="left")
        return frame

    def _build_info_tab(self, parent):
        tab = ttk.Frame(parent)
        return tab

    def _build_info_actions(self, parent):
        frame = ttk.Frame(parent)
        RoundedButton(frame, "Get System Info", command=self._run_info, width=150, height=32).pack(side="left")
        return frame

    # ---------------- Output handling ----------------

    def _clear_output(self):
        self.output_panel.clear()

    def _save_output(self):
        """Save whatever's currently shown in the output panel to a
        .txt file, right when you click the button - not a "save
        mode" you have to remember to turn on before running a scan."""
        text = self.output_panel.log_text.get("1.0", tk.END)
        if not text.strip():
            messagebox.showinfo("Nothing to save", "There's no output to save yet.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            title="Save results",
            initialfile="pcache_results.txt",
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        except OSError as e:
            messagebox.showerror("Save failed", f"Couldn't save that file:\n{e}")

    def _guess_target_from_results(self, text):
        """Best-effort guess at what a loaded results file was scanning,
        for the mind map's root node label. Looks for the module's own
        "...report for <target>" line first, then falls back to the
        first bare IP/CIDR the file mentions."""
        m = re.search(r"report for\s+(\S+)", text, re.I)
        if m:
            return m.group(1).strip()
        m = re.search(
            r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
            r"(?:/\d{1,2})?\b",
            text,
        )
        if m:
            return m.group(0)
        return None

    def _load_results_file(self):
        """Load a previously saved scan results .txt file and feed it
        through the same output parser a live scan uses, so the mind
        map gets rebuilt from the file exactly as it would have looked
        right after that scan finished."""
        if self._busy():
            return

        path = filedialog.askopenfilename(
            title="Load saved scan results",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError as e:
            messagebox.showerror("Load failed", f"Couldn't read that file:\n{e}")
            return

        if not text.strip():
            messagebox.showwarning("Empty file", "That file doesn't contain any results.")
            return

        text = ANSI_ESCAPE_RE.sub("", text)
        text = COLUMN_GAP_RE.sub("\t", text)

        target = (
            self._guess_target_from_results(text)
            or os.path.splitext(os.path.basename(path))[0]
        )

        self._clear_output()
        self.output_panel.set_target(target)
        self.output_panel.add_output(text)

    def _poll_output(self):
        info_tab = self.tool_var.get() == "System Info"
        try:
            while True:
                chunk = self.output_queue.get_nowait()
                if info_tab:
                    self.output_panel.add_device_output(chunk)
                else:
                    self.output_panel.add_output(chunk)
        except queue.Empty:
            pass

        # If the passive scan's thread ended on its own (rather than
        # via the Stop click), flip the button back to "Start".
        if getattr(self, "passive_running", False) and not (
            self.active_thread and self.active_thread.is_alive()
        ):
            self._reset_passive_button()

        self.after(80, self._poll_output)

    def _reset_passive_button(self):
        self.passive_running = False
        self.passive_btn.set_text("Start Passive Scan")

    # ---------------- Running module functions ----------------

    def _busy(self):
        if self.active_thread and self.active_thread.is_alive():
            messagebox.showwarning(
                "Busy", "Another scan is already running. Wait for it or stop it first."
            )
            return True
        return False

    def _run_in_thread(self, target_fn, *args, prefill_input=None):
        if self._busy():
            return False

        # Do not clear the graph here. The scan handlers set the target
        # immediately before starting the worker; clearing here would
        # erase that target and force the user to press Run again.
        def worker():
            old_stdout, old_stdin = sys.stdout, sys.stdin
            sys.stdout = StreamToQueue(self.output_queue)
            if prefill_input is not None:
                sys.stdin = StringIO(prefill_input + "\n")
            try:
                target_fn(*args)
            except Exception as e:
                self.output_queue.put(f"\n[GUI] Unhandled error: {e}\n")
            finally:
                sys.stdout, sys.stdin = old_stdout, old_stdin

        self.active_thread = threading.Thread(target=worker, daemon=True)
        self.active_thread.start()
        return True

    def _run_arp(self):
        target = entry_value(self.arp_target)
        if not target:
            messagebox.showerror("Missing target", "Enter a subnet, e.g. 192.168.1.0/24")
            return

        speed_map = {
            "Default": (False, False, False, False, False, False),
            "~1 hour": (True, False, False, False, False, False),
            "~20 minutes": (False, True, False, False, False, False),
            "~10 minutes": (False, False, True, False, False, False),
            "~5 minutes": (False, False, False, True, False, False),
            "~25 seconds": (False, False, False, False, True, False),
        }
        t00, t0, t1, t2, t3, t4 = speed_map[self.arp_speed.get()]

        self._clear_output()
        self.output_panel.set_target(target)
        self._run_in_thread(
            ArpProcessor, target, False, t00, t0, t1, t2, t3, t4
        )

    def _toggle_passive(self):
        """The single passive-scan button doubles as Start and Stop:
        it flips to "Stop" once a scan is running, and back to
        "Start Passive Scan" once stopped."""
        if self.passive_running:
            self._stop_passive()
        else:
            self._run_passive()

    def _run_passive(self):
        target = entry_value(self.passive_target)
        iface = entry_value(self.passive_iface)
        if not target or not iface:
            messagebox.showerror("Missing info", "Enter both a target subnet and an interface.")
            return

        self._clear_output()
        self.output_panel.set_target(target)
        started = self._run_in_thread(PassiveScan, target, iface, False)
        if started:
            self.passive_running = True
            self.passive_btn.set_text("Stop")

    def _stop_passive(self):
        if self.active_thread and self.active_thread.is_alive():
            stop_thread(self.active_thread)
            self.output_queue.put("\n[GUI] Stop requested.\n")
        self.passive_running = False
        self.passive_btn.set_text("Start Passive Scan")

    def _run_ping(self):
        target = entry_value(self.ping_target)
        if not target:
            messagebox.showerror("Missing target", "Enter a target IP address.")
            return

        self._clear_output()
        self.output_panel.set_target(target)
        self.output_panel.add_status(f"Pinging {target} ...\n")
        self._run_in_thread(PingScan, target, False)

    def _run_vendor(self):
        target = entry_value(self.vendor_target)
        if not target:
            messagebox.showerror("Missing target", "Enter a MAC or IP address.")
            return

        self._clear_output()
        self.output_panel.set_single_target(target)
        self._run_in_thread(VendorLu, target, False)

    def _run_info(self):
        self._clear_output()
        self.output_panel.set_device_target("This device")
        self._run_in_thread(SystemInfo)


if __name__ == "__main__":
    app = PcacheGUI()
    app.mainloop()