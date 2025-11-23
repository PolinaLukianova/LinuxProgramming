import tkinter as tk
from threading import Thread, Event, Lock
from collections import defaultdict
import time
import sys
import subprocess
import shlex

SCAPY = None

WINDOW_SECONDS = 5
DEFAULT_MAX_PACKET_SIZE = 1500
DEFAULT_PORT_THRESHOLD = 20
DEFAULT_REPEAT_THRESHOLD = 5

# отправляет ismp type 3 на указанный ip
def send_icmp_unreachable(ip):
    global SCAPY
# проверяем была ли библиотека импортирована
    if SCAPY is None:
        try:
            import scapy.all as scapy_all
            SCAPY = scapy_all
        except Exception as e:
            print("Scapy import error:", e)
            return False
# пытаемся создать icmp-пакет и отправить
    try:
        pkt = SCAPY.IP(dst=ip) / SCAPY.ICMP(type=3, code=1)
        SCAPY.send(pkt, verbose=False)
        print(f"[ICMP] Sent Destination Unreachable to {ip}")
        return True
    except Exception as e:
        print(f"[ICMP] Send error for {ip}: {e}")
        return False

def block_ip_iptables(ip):
    try:
        # Добавляем правило в INPUT, блокируем пакеты с источником ip
        subprocess.run(["/sbin/iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        print(f"[IPTABLES] BLOCKED {ip}")
        return True
    except Exception as e:
        print(f"[IPTABLES] Failed to block {ip}: {e}")
        return False

def unblock_ip_iptables(ip):
    try:
        # Удаляем правило
        subprocess.run(["/sbin/iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        print(f"[IPTABLES] UNBLOCKED {ip}")
        return True
    except Exception as e:
        print(f"[IPTABLES] Failed to unblock {ip}: {e}")
        return False

class TrafficScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Traffic Scanner")
        self.geometry("795x520")

        # GUI-переменные
        self.iface_var = tk.StringVar(value="")
        self.max_size_var = tk.IntVar(value=DEFAULT_MAX_PACKET_SIZE)
        self.port_thresh_var = tk.IntVar(value=DEFAULT_PORT_THRESHOLD)
        self.repeat_thresh_var = tk.IntVar(value=DEFAULT_REPEAT_THRESHOLD)
        self.size_check = tk.IntVar(value=1)
        self.port_check = tk.IntVar(value=1)
        self.repeat_check = tk.IntVar(value=1)

        # данные и потоки
        self.lock = Lock()
        self.ports_seen = defaultdict(dict)
        self.times = defaultdict(list)
        self.suspicious_ips = {}
        self.ip_vars = {}
        self.all_ips = set()       
        self.all_ip_vars = {}     
        self.blocked_ips = {}
        self.blocked_ip_vars = {}

        self.sniff_thread = None
        self.stop_event = Event()

        self.build_ui()
        self.after(300, self._refresh_results)

    def build_ui(self):
        frm = tk.Frame(self)
        frm.pack(fill="both", expand=True, padx=8, pady=8)

        tk.Label(frm, text="Interface").grid(row=0, column=0, sticky="w")
        tk.Entry(frm, textvariable=self.iface_var, width=18).grid(row=0, column=1, sticky="w")

        tk.Checkbutton(frm, text="Detect large packets", variable=self.size_check).grid(row=1, column=0, sticky="w")
        tk.Label(frm, text="Max size:").grid(row=1, column=1, sticky="w")
        tk.Entry(frm, textvariable=self.max_size_var, width=10).grid(row=1, column=2, sticky="w")

        tk.Checkbutton(frm, text="Detect port scans", variable=self.port_check).grid(row=2, column=0, sticky="w")
        tk.Label(frm, text="Port threshold:").grid(row=2, column=1, sticky="w")
        tk.Entry(frm, textvariable=self.port_thresh_var, width=10).grid(row=2, column=2, sticky="w")

        tk.Checkbutton(frm, text="Detect repeated requests", variable=self.repeat_check).grid(row=3, column=0, sticky="w")
        tk.Label(frm, text="Repeat threshold:").grid(row=3, column=1, sticky="w")
        tk.Entry(frm, textvariable=self.repeat_thresh_var, width=10).grid(row=3, column=2, sticky="w")

        tk.Button(frm, text="Start", command=self.start_sniffing).grid(row=4, column=0, pady=8)
        tk.Button(frm, text="Stop", command=self.stop_sniffing).grid(row=4, column=1, pady=8)
        tk.Button(frm, text="Clear", command=self.clear_results).grid(row=4, column=2, pady=8)

        sep = tk.Frame(frm, height=2, bd=1, relief="sunken")
        sep.grid(row=5, column=0, columnspan=6, sticky="we", pady=6)

        tk.Label(frm, text="All IPs:").grid(row=6, column=0, sticky="w")
        tk.Label(frm, text="Suspicious IPs:").grid(row=6, column=1, sticky="w")
        tk.Label(frm, text="Blocked IPs:").grid(row=6, column=2, sticky="w")

        self.all_canvas = tk.Canvas(frm, height=320, width=265)
        self.all_frame = tk.Frame(self.all_canvas)
        self.all_scroll = tk.Scrollbar(frm, orient="vertical", command=self.all_canvas.yview)
        self.all_canvas.configure(yscrollcommand=self.all_scroll.set)
        self.all_canvas.create_window((0, 0), window=self.all_frame, anchor="nw")
        self.all_frame.bind("<Configure>", lambda e: self.all_canvas.configure(
            scrollregion=self.all_canvas.bbox("all")
        ))

        self.all_canvas.grid(row=7, column=0, sticky="nsew")
        self.all_scroll.grid(row=7, column=0, sticky="nse")

        self.results_canvas = tk.Canvas(frm, height=320, width=265)
        self.results_frame = tk.Frame(self.results_canvas)
        self.results_scroll = tk.Scrollbar(frm, orient="vertical", command=self.results_canvas.yview)
        self.results_canvas.configure(yscrollcommand=self.results_scroll.set)
        self.results_canvas.create_window((0, 0), window=self.results_frame, anchor="nw")
        self.results_frame.bind("<Configure>", lambda e: self.results_canvas.configure(
            scrollregion=self.results_canvas.bbox("all")
        ))

        self.results_canvas.grid(row=7, column=1, sticky="nsew")
        self.results_scroll.grid(row=7, column=1, sticky="nse")

        self.blocked_canvas = tk.Canvas(frm, height=320, width=265)
        self.blocked_frame = tk.Frame(self.blocked_canvas)
        self.blocked_scroll = tk.Scrollbar(frm, orient="vertical", command=self.blocked_canvas.yview)
        self.blocked_canvas.configure(yscrollcommand=self.blocked_scroll.set)
        self.blocked_canvas.create_window((0, 0), window=self.blocked_frame, anchor="nw")
        self.blocked_frame.bind("<Configure>", lambda e: self.blocked_canvas.configure(
            scrollregion=self.blocked_canvas.bbox("all")
        ))

        self.blocked_canvas.grid(row=7, column=2, sticky="nsew")
        self.blocked_scroll.grid(row=7, column=2, sticky="nse")

        tk.Button(frm, text="Block selected (iptables)", command=self.block_selected).grid(row=8, column=0, pady=8, sticky="w")
        tk.Button(frm, text="Unblock selected", command=self.unblock_selected).grid(row=8, column=1, pady=8, sticky="w")
        tk.Button(frm, text="Exit", command=self._on_exit).grid(row=8, column=2, pady=8, sticky="e")

        frm.rowconfigure(7, weight=1)
        frm.columnconfigure(1, weight=1)


# начинаем захват пакетов в отдельном потоке
    def start_sniffing(self):
        global SCAPY
        if SCAPY is None:
            try:
                import scapy.all as scapy_all
                SCAPY = scapy_all
            except Exception as e:
                
                print("Ошибка импорта scapy:", e)
                return

        if self.sniff_thread and self.sniff_thread.is_alive():
            print("Сниффер уже запущен")
            return

        iface = self.iface_var.get().strip() or None
        self.clear_results()
        self.stop_event.clear()
        self.sniff_thread = Thread(target=self._sniff_loop, args=(iface,), daemon=True)
        self.sniff_thread.start()
        print(f"Started sniffing on: {iface or 'default'}")

# останавливаем пототок сниффера
    def stop_sniffing(self):
        if not (self.sniff_thread and self.sniff_thread.is_alive()):
            print("Сниффер не запущен")
            return
        self.stop_event.set()
        self.sniff_thread.join(timeout=2)
        print("Sniffing stopped")

# обертка вокруг scapy.sniff, использует stop_filter для остановки
    def _sniff_loop(self, iface):
        def stop_filter(pkt):
            return self.stop_event.is_set()

        try:
            SCAPY.sniff(iface=iface, prn=self.record_packet, store=False, stop_filter=stop_filter)
        except Exception as e:
            print("Sniff error:", e)

# проверяем каждый пакет сразу при получении
    def record_packet(self, pkt):
        if not pkt.haslayer(SCAPY.IP):
            return
        src = pkt[SCAPY.IP].src
        now = time.time()

        cfg = {
            "size_check": bool(self.size_check.get()),
            "max_size": int(self.max_size_var.get()),
            "port_check": bool(self.port_check.get()),
            "port_thresh": int(self.port_thresh_var.get()),
            "repeat_check": bool(self.repeat_check.get()),
            "repeat_thresh": int(self.repeat_thresh_var.get()),
        }

        with self.lock:
            self.all_ips.add(src)

            if cfg["size_check"] and len(pkt) > cfg["max_size"]:
                self.suspicious_ips[src] = f"Large packet ({len(pkt)} > {cfg['max_size']})"

            if cfg["port_check"] and (pkt.haslayer(SCAPY.TCP) or pkt.haslayer(SCAPY.UDP)):
                dport = pkt[SCAPY.TCP].dport if pkt.haslayer(SCAPY.TCP) else pkt[SCAPY.UDP].dport
                self.ports_seen[src][dport] = now
                self.ports_seen[src] = {p: t for p, t in self.ports_seen[src].items() if now - t <= WINDOW_SECONDS}
                if len(self.ports_seen[src]) >= cfg["port_thresh"]:
                    self.suspicious_ips[src] = f"Port scan (>= {cfg['port_thresh']})"

            if cfg["repeat_check"]:
                self.times[src].append(now)
                self.times[src] = [t for t in self.times[src] if now - t <= WINDOW_SECONDS]
                if len(self.times[src]) >= cfg["repeat_thresh"]:
                    self.suspicious_ips[src] = f"Repeated ({len(self.times[src])} >= {cfg['repeat_thresh']})"

# демонстрация текущих подозрительных ип и всех и заблокированных
    def _refresh_results(self):
        existing_susp = {ip: var.get() for ip, var in self.ip_vars.items()}
        existing_all  = {ip: var.get() for ip, var in self.all_ip_vars.items()}
        existing_blocked = {ip: var.get() for ip, var in self.blocked_ip_vars.items()}

        with self.lock:
            suspicious_items = list(self.suspicious_ips.items())
            all_items = sorted(self.all_ips)
            blocked_items = sorted(self.blocked_ips.items())

        for child in self.all_frame.winfo_children():
            child.destroy()
        self.all_ip_vars.clear()
        for ip in all_items:
            var = tk.IntVar(value=existing_all.get(ip,0))
            cb = tk.Checkbutton(self.all_frame, text=f"{ip}", variable=var, anchor="w", justify="left", wraplength=220)
            cb.pack(fill="x", anchor="w", pady=2)
            self.all_ip_vars[ip] = var

        for child in self.results_frame.winfo_children():
            child.destroy()
        self.ip_vars.clear()
        for ip, reason in sorted(suspicious_items):
            var = tk.IntVar(value=existing_susp.get(ip,0))
            cb = tk.Checkbutton(self.results_frame, text=f"{ip} — {reason}", variable=var, anchor="w", justify="left", wraplength=300)
            cb.pack(fill="x", anchor="w", pady=2)
            self.ip_vars[ip] = var

        for child in self.blocked_frame.winfo_children():
            child.destroy()
        self.blocked_ip_vars.clear()
        for ip, info in blocked_items:
            var = tk.IntVar(value=existing_blocked.get(ip,0))
            cb = tk.Checkbutton(self.blocked_frame, text=f"{ip} — {info}", variable=var, anchor="w", justify="left", wraplength=220)
            cb.pack(fill="x", anchor="w", pady=2)
            self.blocked_ip_vars[ip] = var

        self.after(300, self._refresh_results)

# реагируем на пользоввательский ввод
    def block_selected(self):
        selected_suspicious = [ip for ip, var in self.ip_vars.items() if var.get() == 1]
        selected_all = [ip for ip, var in self.all_ip_vars.items() if var.get() == 1]
        selected = set(selected_suspicious) | set(selected_all)
        if not selected:
            print("No IP selected for blocking.")
            return

        for ip in selected:
            ok = block_ip_iptables(ip)
            if ok:
                with self.lock:
                    # помечаем как заблокированный 
                    reason = self.suspicious_ips.get(ip, "manual block")
                    self.blocked_ips[ip] = reason

                    if ip in self.suspicious_ips:
                        del self.suspicious_ips[ip]
        print("Blocking done.")

# реагируем на пользовательский ввод: разблокировка выделенных IP
    def unblock_selected(self):
        selected_blocked = [ip for ip, var in self.blocked_ip_vars.items() if var.get() == 1]
        if not selected_blocked:
            print("No IP selected for unblocking.")
            return

        for ip in selected_blocked:
            ok = unblock_ip_iptables(ip)
            if ok:
                with self.lock:
                    # удаляем из списка заблокированных
                    if ip in self.blocked_ips:
                        del self.blocked_ips[ip]
        print("Unblocking done.")

# сбрасываем накопленные данные
    def clear_results(self):
        with self.lock:
            self.suspicious_ips.clear()
            self.ports_seen.clear()
            self.times.clear()
            self.all_ips.clear()
        print("Cleared results")

# корректно завершаем процесс
    def _on_exit(self):
        self.stop_event.set()
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=1)
        self.destroy()


if __name__ == "__main__":
    if not sys.platform.startswith("linux"):
        print("Script intended for Linux systems.")
        sys.exit(1)
    app = TrafficScannerApp()
    app.mainloop()

