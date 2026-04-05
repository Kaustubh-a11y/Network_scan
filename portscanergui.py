import socket
import threading
import time
import queue
import sys
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import tkinter.font as tkfont

# -----------------------------
# Service Map (extend freely)
# -----------------------------
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    3306: 'MySQL', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt'
}

# ---------------------------
# Color Palette
# ---------------------------
BG_DARK    = "#0b0e14"
BG_PANEL   = "#111720"
BG_WIDGET  = "#141c27"
NEON_GREEN = "#00ff88"
NEON_CYAN  = "#00cfff"
NEON_RED   = "#ff4466"
NEON_AMBER = "#ffb347"
DIM_TEXT   = "#4a5568"
MID_TEXT   = "#8899aa"
BRIGHT     = "#e0eaf5"
BORDER     = "#1e2d40"

# ---------------------------
# Scanner Worker
# ---------------------------
class PortScanner:
    def __init__(self, target, start_port, end_port, timeout=0.5, max_workers=500):
        self.target      = target
        self.start_port  = start_port
        self.end_port    = end_port
        self.timeout     = timeout
        self.max_workers = max_workers
        self._stop_event = threading.Event()

        self.total_ports  = max(0, end_port - start_port + 1)
        self.scanned_count = 0
        self.open_ports   = []
        self._lock        = threading.Lock()
        self.result_queue = queue.Queue()

    def stop(self):
        self._stop_event.set()

    def _scan_port(self, port):
        if self._stop_event.is_set():
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.target, port))
            if result == 0:
                service = COMMON_PORTS.get(port, 'Unknown')
                with self._lock:
                    self.open_ports.append((port, service))
                self.result_queue.put(('open', port, service))
            s.close()
        except Exception as e:
            self.result_queue.put(('error', port, str(e)))
        finally:
            with self._lock:
                self.scanned_count += 1
            self.result_queue.put(('progress', self.scanned_count, self.total_ports))

    def resolve_target(self):
        return socket.gethostbyname(self.target)

    def run(self):
        sem     = threading.Semaphore(self.max_workers)
        threads = []
        for port in range(self.start_port, self.end_port + 1):
            if self._stop_event.is_set():
                break
            sem.acquire()
            t = threading.Thread(target=self._worker_wrapper, args=(sem, port), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        self.result_queue.put(('done', None, None))

    def _worker_wrapper(self, sem, port):
        try:
            self._scan_port(port)
        finally:
            sem.release()


# ---------------------------
# Custom Canvas Progress Bar
# ---------------------------
class NeonProgressBar(tk.Canvas):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, height=14, bg=BG_PANEL,
                         highlightthickness=0, bd=0, **kwargs)
        self._value   = 0
        self._maximum = 100
        self.bind("<Configure>", lambda e: self._draw())
        self._draw()

    def configure_bar(self, value=None, maximum=None):
        if maximum is not None:
            self._maximum = max(maximum, 1)
        if value is not None:
            self._value = value
        self._draw()

    def _draw(self):
        self.delete("all")
        w = self.winfo_width() or 400
        h = self.winfo_height() or 14
        r = 5

        # Track
        self.create_rounded_rect(2, 2, w - 2, h - 2, r, fill=BG_WIDGET, outline=BORDER, width=1)

        # Fill
        ratio = min(self._value / self._maximum, 1.0) if self._maximum else 0
        fill_w = int((w - 4) * ratio)
        if fill_w > 4:
            self.create_rounded_rect(2, 2, 2 + fill_w, h - 2, r, fill=NEON_GREEN, outline="")
            # Shimmer highlight
            self.create_rounded_rect(2, 2, 2 + fill_w, 2 + (h - 4) // 2, r,
                                     fill="#aaffd0", outline="", stipple="gray50")

        # Percentage label
        pct = int(ratio * 100)
        self.create_text(w // 2, h // 2 + 1, text=f"{pct}%",
                         fill=BRIGHT if pct > 0 else DIM_TEXT,
                         font=("Consolas", 8, "bold"))

    def create_rounded_rect(self, x1, y1, x2, y2, r, **kwargs):
        points = [
            x1 + r, y1,  x2 - r, y1,
            x2, y1,      x2, y1 + r,
            x2, y2 - r,  x2, y2,
            x2 - r, y2,  x1 + r, y2,
            x1, y2,      x1, y2 - r,
            x1, y1 + r,  x1, y1,
        ]
        return self.create_polygon(points, smooth=True, **kwargs)


# ---------------------------
# Blinking Cursor Label
# ---------------------------
class BlinkLabel(tk.Label):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self._blink_on = True
        self._blink_job = None

    def start_blink(self):
        self._blink()

    def stop_blink(self):
        if self._blink_job:
            self.after_cancel(self._blink_job)
        self.configure(fg=NEON_GREEN)

    def _blink(self):
        color = NEON_GREEN if self._blink_on else BG_PANEL
        self.configure(fg=color)
        self._blink_on = not self._blink_on
        self._blink_job = self.after(500, self._blink)


# ---------------------------
# Main GUI
# ---------------------------
class ScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NetProbe // Port Scanner")
        self.geometry("820x640")
        self.minsize(760, 560)
        self.configure(bg=BG_DARK)

        self.scanner        = None
        self.scanner_thread = None
        self.start_time     = None
        self.poll_after_ms  = 40

        self._apply_styles()
        self._build_ui()

    # --------------------------------------------------
    def _apply_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        base = dict(background=BG_PANEL, foreground=BRIGHT,
                    bordercolor=BORDER, darkcolor=BG_PANEL,
                    lightcolor=BG_PANEL, troughcolor=BG_DARK,
                    relief="flat")

        style.configure(".", font=("Consolas", 10), **base)
        style.configure("TFrame",      background=BG_DARK)
        style.configure("Card.TFrame", background=BG_PANEL)

        style.configure("TLabel", background=BG_PANEL, foreground=MID_TEXT,
                        font=("Consolas", 9))
        style.configure("Title.TLabel", background=BG_DARK, foreground=NEON_GREEN,
                        font=("Consolas", 22, "bold"))
        style.configure("Sub.TLabel", background=BG_DARK, foreground=DIM_TEXT,
                        font=("Consolas", 9))
        style.configure("Stat.TLabel", background=BG_PANEL, foreground=NEON_CYAN,
                        font=("Consolas", 10, "bold"))
        style.configure("Dim.TLabel",  background=BG_PANEL, foreground=DIM_TEXT,
                        font=("Consolas", 8))

        # Entry
        style.configure("TEntry", fieldbackground=BG_WIDGET, foreground=NEON_GREEN,
                        insertcolor=NEON_GREEN, bordercolor=BORDER,
                        font=("Consolas", 10))
        style.map("TEntry", bordercolor=[("focus", NEON_GREEN)])

        # Buttons
        style.configure("Accent.TButton", background=NEON_GREEN, foreground=BG_DARK,
                        font=("Consolas", 10, "bold"), padding=(14, 6), relief="flat",
                        borderwidth=0)
        style.map("Accent.TButton",
                  background=[("active", "#00cc66"), ("disabled", DIM_TEXT)],
                  foreground=[("disabled", BG_PANEL)])

        style.configure("Stop.TButton", background=NEON_RED, foreground=BRIGHT,
                        font=("Consolas", 10, "bold"), padding=(14, 6), relief="flat")
        style.map("Stop.TButton",
                  background=[("active", "#cc2244"), ("disabled", BG_WIDGET)])

        style.configure("Dim.TButton", background=BG_WIDGET, foreground=MID_TEXT,
                        font=("Consolas", 9), padding=(10, 5), relief="flat")
        style.map("Dim.TButton", background=[("active", BORDER)])

    # --------------------------------------------------
    def _build_ui(self):
        # ---- Header ----
        hdr = tk.Frame(self, bg=BG_DARK)
        hdr.pack(fill="x", padx=20, pady=(18, 6))

        tk.Label(hdr, text="NETPROBE", font=("Consolas", 26, "bold"),
                 bg=BG_DARK, fg=NEON_GREEN).pack(side="left")
        tk.Label(hdr, text=" // Port Intelligence Scanner",
                 font=("Consolas", 11), bg=BG_DARK, fg=DIM_TEXT).pack(side="left", padx=4, pady=6)

        # version tag
        tk.Label(hdr, text="v2.0", font=("Consolas", 8),
                 bg=BG_DARK, fg=DIM_TEXT).pack(side="right", pady=10)

        # divider
        tk.Frame(self, bg=NEON_GREEN, height=1).pack(fill="x", padx=20, pady=(0, 12))

        # ---- Scan Settings Card ----
        card = tk.Frame(self, bg=BG_PANEL, bd=0, relief="flat",
                        highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="x", padx=20, pady=(0, 10))

        tk.Label(card, text="TARGET CONFIGURATION",
                 font=("Consolas", 8, "bold"), bg=BG_PANEL, fg=DIM_TEXT
                 ).grid(row=0, column=0, columnspan=7, sticky="w", padx=14, pady=(10, 2))

        # Field: Target
        self._field_label(card, "HOST / IP", 1, 0)
        self.ent_target = self._entry(card, 36, 1, 1)

        # Field: Ports
        self._field_label(card, "START PORT", 1, 2)
        self.ent_start = self._entry(card, 8, 1, 3)
        self.ent_start.insert(0, "1")

        self._field_label(card, "END PORT", 1, 4)
        self.ent_end = self._entry(card, 8, 1, 5)
        self.ent_end.insert(0, "1024")

        # Buttons
        btn_frame = tk.Frame(card, bg=BG_PANEL)
        btn_frame.grid(row=1, column=6, padx=14, pady=10, sticky="e")

        self.btn_start = ttk.Button(btn_frame, text="▶  SCAN",
                                    style="Accent.TButton", command=self.start_scan)
        self.btn_start.pack(side="left", padx=(0, 6))

        self.btn_stop = ttk.Button(btn_frame, text="■  STOP",
                                   style="Stop.TButton", command=self.stop_scan,
                                   state="disabled")
        self.btn_stop.pack(side="left")

        for i in range(7):
            card.grid_columnconfigure(i, weight=1 if i in (1,) else 0)
        card.grid_columnconfigure(1, weight=1)

        # ---- Status Bar ----
        status_card = tk.Frame(self, bg=BG_PANEL, bd=0,
                               highlightbackground=BORDER, highlightthickness=1)
        status_card.pack(fill="x", padx=20, pady=(0, 10))

        left = tk.Frame(status_card, bg=BG_PANEL)
        left.pack(side="left", fill="x", expand=True, padx=14, pady=10)

        top_row = tk.Frame(left, bg=BG_PANEL)
        top_row.pack(fill="x")

        self.lbl_state_dot = tk.Label(top_row, text="●", font=("Consolas", 10),
                                      bg=BG_PANEL, fg=DIM_TEXT)
        self.lbl_state_dot.pack(side="left", padx=(0, 6))

        self.var_status = tk.StringVar(value="IDLE")
        tk.Label(top_row, textvariable=self.var_status,
                 font=("Consolas", 10, "bold"), bg=BG_PANEL, fg=BRIGHT
                 ).pack(side="left")

        self.var_elapsed = tk.StringVar(value="00:00.00")
        tk.Label(status_card, textvariable=self.var_elapsed,
                 font=("Consolas", 16, "bold"), bg=BG_PANEL, fg=NEON_CYAN
                 ).pack(side="right", padx=16)
        tk.Label(status_card, text="elapsed", font=("Consolas", 7),
                 bg=BG_PANEL, fg=DIM_TEXT).pack(side="right")

        # Progress
        prog_row = tk.Frame(left, bg=BG_PANEL)
        prog_row.pack(fill="x", pady=(6, 0))

        self.progress = NeonProgressBar(prog_row)
        self.progress.pack(fill="x", expand=True)

        self.var_ports_scanned = tk.StringVar(value="0 / 0 ports")
        tk.Label(prog_row, textvariable=self.var_ports_scanned,
                 font=("Consolas", 7), bg=BG_PANEL, fg=DIM_TEXT
                 ).pack(side="right", padx=(8, 0))

        # ---- Stats row ----
        stats = tk.Frame(self, bg=BG_DARK)
        stats.pack(fill="x", padx=20, pady=(0, 10))

        self._stat_box(stats, "OPEN PORTS", "0",   "open_count")
        self._stat_box(stats, "SCANNED",    "0",   "scan_count")
        self._stat_box(stats, "THREADS",    "500", "thread_count")
        self._stat_box(stats, "TIMEOUT",    "0.5s","timeout_val")

        # ---- Terminal Output ----
        term_card = tk.Frame(self, bg=BG_PANEL, bd=0,
                             highlightbackground=BORDER, highlightthickness=1)
        term_card.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        term_header = tk.Frame(term_card, bg=BORDER)
        term_header.pack(fill="x")

        # Traffic-light dots
        for col in (NEON_RED, NEON_AMBER, NEON_GREEN):
            tk.Label(term_header, text="●", font=("Consolas", 9),
                     bg=BORDER, fg=col).pack(side="left", padx=4, pady=4)

        tk.Label(term_header, text="output.log",
                 font=("Consolas", 8), bg=BORDER, fg=DIM_TEXT
                 ).pack(side="left", padx=6)

        self.txt_results = tk.Text(
            term_card, bg=BG_DARK, fg=NEON_GREEN,
            font=("Consolas", 10), insertbackground=NEON_GREEN,
            wrap="none", relief="flat", bd=0,
            selectbackground=BORDER, selectforeground=NEON_GREEN,
            padx=12, pady=10
        )
        self.txt_results.pack(fill="both", expand=True, side="left")

        # Tags for coloring
        self.txt_results.tag_configure("open",  foreground=NEON_GREEN)
        self.txt_results.tag_configure("info",  foreground=NEON_CYAN)
        self.txt_results.tag_configure("dim",   foreground=DIM_TEXT)
        self.txt_results.tag_configure("error", foreground=NEON_RED)
        self.txt_results.tag_configure("done",  foreground=NEON_AMBER)

        yscroll = tk.Scrollbar(term_card, orient="vertical",
                               command=self.txt_results.yview,
                               bg=BG_PANEL, troughcolor=BG_DARK,
                               activebackground=DIM_TEXT, width=8)
        yscroll.pack(side="right", fill="y")
        self.txt_results.configure(yscrollcommand=yscroll.set)

        xscroll = tk.Scrollbar(self, orient="horizontal",
                               command=self.txt_results.xview,
                               bg=BG_PANEL, troughcolor=BG_DARK, width=8)
        xscroll.pack(fill="x", padx=20, pady=(0, 6))
        self.txt_results.configure(xscrollcommand=xscroll.set)

        # ---- Bottom Toolbar ----
        toolbar = tk.Frame(self, bg=BG_DARK)
        toolbar.pack(fill="x", padx=20, pady=(0, 16))

        self.btn_clear = ttk.Button(toolbar, text="✕  CLEAR",
                                    style="Dim.TButton", command=self.clear_results)
        self.btn_clear.pack(side="left", padx=(0, 6))

        self.btn_save = ttk.Button(toolbar, text="↓  SAVE RESULTS",
                                   style="Dim.TButton", command=self.save_results,
                                   state="disabled")
        self.btn_save.pack(side="right")

        tk.Label(toolbar, text="Scan only targets you own or have explicit permission to test.",
                 font=("Consolas", 7), bg=BG_DARK, fg=DIM_TEXT
                 ).pack(side="left", padx=10)

        # Initial prompt
        self._print("NETPROBE Port Scanner ready.\n", "info")
        self._print("Enter a target and port range above, then press SCAN.\n", "dim")

    # --------------------------------------------------
    def _field_label(self, parent, text, row, col):
        tk.Label(parent, text=text, font=("Consolas", 7, "bold"),
                 bg=BG_PANEL, fg=DIM_TEXT
                 ).grid(row=row-1 if row > 0 else 0, column=col,
                        sticky="w", padx=(14 if col == 0 else 8, 2), pady=(2, 0))
        # re-place as subrow
        tk.Label(parent, text=text, font=("Consolas", 7, "bold"),
                 bg=BG_PANEL, fg=DIM_TEXT).grid_forget()
        # Just show inline
        tk.Label(parent, text=text, font=("Consolas", 7),
                 bg=BG_PANEL, fg=DIM_TEXT
                 ).grid(row=row, column=col, sticky="sw",
                        padx=(14 if col == 0 else 8, 2), pady=(0, 2))

    def _entry(self, parent, width, row, col):
        e = ttk.Entry(parent, width=width, style="TEntry")
        e.grid(row=row + 1, column=col, padx=(14 if col == 0 else 8, 2),
               pady=(0, 12), sticky="w")
        return e

    def _stat_box(self, parent, label, value, attr):
        box = tk.Frame(parent, bg=BG_PANEL, bd=0,
                       highlightbackground=BORDER, highlightthickness=1)
        box.pack(side="left", fill="x", expand=True, padx=(0, 8))
        box.pack_configure(padx=(0, 8))

        tk.Label(box, text=label, font=("Consolas", 7),
                 bg=BG_PANEL, fg=DIM_TEXT).pack(anchor="w", padx=10, pady=(6, 0))

        var = tk.StringVar(value=value)
        setattr(self, f"var_{attr}", var)
        tk.Label(box, textvariable=var, font=("Consolas", 18, "bold"),
                 bg=BG_PANEL, fg=NEON_CYAN).pack(anchor="w", padx=10, pady=(0, 8))

    # --------------------------------------------------
    def _print(self, text, tag=""):
        self.txt_results.insert(tk.END, text, tag)
        self.txt_results.see(tk.END)

    def _set_dot(self, color):
        self.lbl_state_dot.configure(fg=color)

    # --------------------------------------------------
    # Control Handlers
    # --------------------------------------------------
    def start_scan(self):
        if self.scanner_thread and self.scanner_thread.is_alive():
            messagebox.showinfo("NetProbe", "A scan is already running.")
            return

        target = self.ent_target.get().strip()
        if not target:
            messagebox.showerror("Input Error", "Please enter a target IP or hostname.")
            return

        try:
            start_port = int(self.ent_start.get().strip())
            end_port   = int(self.ent_end.get().strip())
        except ValueError:
            messagebox.showerror("Input Error", "Ports must be integers.")
            return

        if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535 and start_port <= end_port):
            messagebox.showerror("Input Error", "Port range: 0–65535 and start ≤ end.")
            return

        self.scanner = PortScanner(target, start_port, end_port, timeout=0.5, max_workers=500)

        try:
            resolved_ip = self.scanner.resolve_target()
        except Exception as e:
            messagebox.showerror("DNS Error", f"Cannot resolve '{target}'.\n{e}")
            self.scanner = None
            return

        self._print("\n" + "─" * 60 + "\n", "dim")
        self._print(f"  TARGET   {target} ({resolved_ip})\n", "info")
        self._print(f"  PORTS    {start_port} → {end_port}  ({end_port - start_port + 1} total)\n", "info")
        self._print(f"  THREADS  500   TIMEOUT  0.5s\n", "dim")
        self._print("─" * 60 + "\n\n", "dim")

        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.btn_save.configure(state="disabled")

        self.progress.configure_bar(value=0, maximum=max(end_port - start_port + 1, 1))
        self.var_status.set("SCANNING")
        self._set_dot(NEON_GREEN)

        self.var_open_count.set("0")
        self.var_scan_count.set("0")

        self.start_time = time.time()
        self._update_elapsed()

        self.scanner_thread = threading.Thread(target=self.scanner.run, daemon=True)
        self.scanner_thread.start()
        self.after(self.poll_after_ms, self._poll)

    def stop_scan(self):
        if self.scanner:
            self.scanner.stop()
            self.var_status.set("STOPPING")
            self._set_dot(NEON_AMBER)

    def clear_results(self):
        self.txt_results.delete("1.0", tk.END)
        self.progress.configure_bar(value=0, maximum=1)
        self.var_status.set("IDLE")
        self.var_elapsed.set("00:00.00")
        self.var_open_count.set("0")
        self.var_scan_count.set("0")
        self.var_ports_scanned.set("0 / 0 ports")
        self.btn_save.configure(state="disabled")
        self._set_dot(DIM_TEXT)
        self._print("Terminal cleared.\n", "dim")

    def save_results(self):
        if not self.scanner or not self.scanner.open_ports:
            messagebox.showinfo("Save", "No open ports to save.")
            return

        fname = f"netprobe_{self.scanner.target}_{int(time.time())}.txt"
        path  = filedialog.asksaveasfilename(
            title="Save Scan Results",
            defaultextension=".txt",
            initialfile=fname,
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"# NETPROBE Scan Report\n")
                f.write(f"# Target : {self.scanner.target}\n")
                f.write(f"# Range  : {self.scanner.start_port}-{self.scanner.end_port}\n")
                f.write(f"# Time   : {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"{'PORT':<10}{'SERVICE':<16}STATUS\n")
                f.write("-" * 36 + "\n")
                for port, svc in sorted(self.scanner.open_ports, key=lambda x: x[0]):
                    f.write(f"{port:<10}{svc:<16}OPEN\n")
            messagebox.showinfo("Saved", f"Results saved:\n{path}")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))

    # --------------------------------------------------
    # UI Polling / Timers
    # --------------------------------------------------
    def _update_elapsed(self):
        if self.start_time and self.var_status.get() in ("SCANNING", "STOPPING"):
            t   = time.time() - self.start_time
            m   = int(t) // 60
            s   = int(t) % 60
            ms  = int((t - int(t)) * 100)
            self.var_elapsed.set(f"{m:02d}:{s:02d}.{ms:02d}")
            self.after(100, self._update_elapsed)

    def _poll(self):
        if not self.scanner:
            return
        try:
            while True:
                kind, a, b = self.scanner.result_queue.get_nowait()
                if kind == 'open':
                    port, svc = a, b
                    self._print(f"  [OPEN]  ", "open")
                    self._print(f"port {port:<6}", "open")
                    self._print(f"  {svc}\n", "info")
                    self.var_open_count.set(str(len(self.scanner.open_ports)))
                elif kind == 'progress':
                    scanned, total = a, b
                    self.progress.configure_bar(value=scanned, maximum=total)
                    self.var_scan_count.set(str(scanned))
                    self.var_ports_scanned.set(f"{scanned} / {total} ports")
                elif kind == 'done':
                    n = len(self.scanner.open_ports)
                    elapsed = time.time() - self.start_time if self.start_time else 0
                    self._print("\n" + "─" * 60 + "\n", "dim")
                    self._print(f"  SCAN COMPLETE  ", "done")
                    self._print(f"{n} open port(s) found in {elapsed:.2f}s\n", "done")
                    self._print("─" * 60 + "\n", "dim")
                    self.var_status.set("COMPLETE")
                    self._set_dot(NEON_CYAN)
                    self.btn_start.configure(state="normal")
                    self.btn_stop.configure(state="disabled")
                    self.btn_save.configure(state="normal" if n else "disabled")
                    self.start_time = None
        except queue.Empty:
            pass

        if self.scanner_thread and self.scanner_thread.is_alive():
            self.after(self.poll_after_ms, self._poll)
        else:
            if self.var_status.get() in ("SCANNING", "STOPPING"):
                self.var_status.set("COMPLETE")
                self._set_dot(NEON_CYAN)
            self.btn_start.configure(state="normal")
            self.btn_stop.configure(state="disabled")
            if self.scanner and self.scanner.open_ports:
                self.btn_save.configure(state="normal")


# ---------------------------
# Entry Point
# ---------------------------
def main():
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-10), 7)
        except Exception:
            pass

    app = ScannerGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
