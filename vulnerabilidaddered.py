import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
import threading
import subprocess
import nmap
import sys
from datetime import datetime

# --------- Ocultar cualquier ventana de consola que abra subprocess (incluido nmap) ----------
if sys.platform.startswith("win"):
    CREATE_NO_WINDOW = 0x08000000
    _orig_popen = subprocess.Popen
    def _popen_no_console(*args, **kwargs):
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | CREATE_NO_WINDOW
        return _orig_popen(*args, **kwargs)
    subprocess.Popen = _popen_no_console
# ---------------------------------------------------------------------------------------------

APP_NAME = "Vulnerabilidad de Red"

# Puertos/servicios que marcaremos como potencialmente peligrosos (firma simple)
VULN_SIGNATURES = {
    21:  "FTP sin cifrado (credenciales en claro)",
    22:  "SSH expuesto (fuerza bruta si no hay hardening)",
    23:  "Telnet inseguro (sin cifrado)",
    80:  "HTTP sin cifrado (considera HTTPS)",
    139: "NetBIOS expuesto (puede filtrar información)",
    445: "SMB expuesto (históricamente explotado)",
    3389:"RDP expuesto (objetivo frecuente de ataques)",
}

DEFAULT_PORTS = "21,22,23,80,139,443,445,3389"


class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("850x600")
        self.root.configure(bg="black")
        self.root.resizable(False, False)

        # Header
        tk.Label(
            root, text=APP_NAME, bg="black", fg="white",
            font=("Segoe UI", 16, "bold")
        ).pack(pady=8)

        # Inputs
        frm = tk.Frame(root, bg="black")
        frm.pack(pady=5, fill="x", padx=10)

        tk.Label(frm, text="Rango/IP:", bg="black", fg="white").grid(row=0, column=0, sticky="w")
        self.entry_target = tk.Entry(frm, width=40)
        self.entry_target.grid(row=0, column=1, sticky="w", padx=5)
        self.entry_target.insert(0, "192.168.1.0/24")

        tk.Label(frm, text="Puertos (coma):", bg="black", fg="white").grid(row=1, column=0, sticky="w")
        self.entry_ports = tk.Entry(frm, width=40)
        self.entry_ports.grid(row=1, column=1, sticky="w", padx=5)
        self.entry_ports.insert(0, DEFAULT_PORTS)

        # Buttons
        btn_frame = tk.Frame(root, bg="black")
        btn_frame.pack(pady=10)

        self.btn_scan = tk.Button(
            btn_frame, text="Iniciar escaneo", bg="#1f6feb", fg="white",
            font=("Segoe UI", 10, "bold"), command=self.start_scan
        )
        self.btn_scan.grid(row=0, column=0, padx=5)

        self.btn_save = tk.Button(
            btn_frame, text="Guardar reporte", bg="#6c757d", fg="white",
            font=("Segoe UI", 10, "bold"), state="disabled", command=self.save_report
        )
        self.btn_save.grid(row=0, column=1, padx=5)

        # Output area
        self.text = ScrolledText(
            root, width=100, height=25, font=("Consolas", 10),
            bg="#0f0f0f", fg="#f0f0f0", insertbackground="white"
        )
        self.text.pack(padx=10, pady=5)

        # Color tags
        self.text.tag_config("ok", foreground="#00FF00")       # verde
        self.text.tag_config("warn", foreground="#FFD700")     # amarillo
        self.text.tag_config("bad", foreground="#FF4444")      # rojo
        self.text.tag_config("info", foreground="#00BFFF")     # azul
        self.text.tag_config("default", foreground="#f0f0f0")  # blanco gris

        self.report_buffer = []
        self.is_scanning = False

    def log(self, msg, tag="default"):
        self.text.insert(tk.END, msg + "\n", tag)
        self.text.see(tk.END)
        self.report_buffer.append(msg)

    def start_scan(self):
        if self.is_scanning:
            return

        target = self.entry_target.get().strip()
        ports = self.entry_ports.get().strip()
        if not target:
            messagebox.showwarning("Falta objetivo", "Ingresa un rango o IP objetivo.")
            return
        if not ports:
            ports = DEFAULT_PORTS

        self.text.delete(1.0, tk.END)
        self.report_buffer = []
        self.btn_scan.config(state="disabled")
        self.btn_save.config(state="disabled")
        self.is_scanning = True

        threading.Thread(target=self.scan, args=(target, ports), daemon=True).start()

    def scan(self, target, ports):
        self.log(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Iniciando escaneo en: {target}", "info")
        self.log(f"Puertos: {ports}", "info")
        self.log("-" * 80, "default")

        try:
            nm = nmap.PortScanner()

            # Descubrir hosts activos
            self.log("[*] Descubriendo hosts activos...", "info")
            nm.scan(hosts=target, arguments="-sn")
            hosts = nm.all_hosts()
            if not hosts:
                self.log("No se encontraron hosts activos.", "bad")
                self.finish_scan()
                return

            self.log(f"Hosts activos: {len(hosts)}", "info")
            self.log("-" * 80, "default")

            for host in hosts:
                self.log(f"\n🔍 Host: {host} ({nm[host].hostname()})", "warn")
                try:
                    # nm.scan(hosts=host, arguments=f"-sS -p {ports}") # MACOS pide sudo
                    nm.scan(hosts=host, arguments=f"-sT -p {ports}")
                except nmap.PortScannerError as e:
                    self.log(f"   Error escaneando {host}: {e}", "bad")
                    continue

                if host not in nm.all_hosts():
                    continue

                protocols = nm[host].all_protocols()
                if not protocols:
                    self.log("   No se encontraron puertos abiertos.", "ok")
                    continue

                any_vuln = False
                for proto in protocols:
                    for port, pdata in nm[host][proto].items():
                        state = pdata.get("state", "unknown")
                        if state == "open":
                            desc = VULN_SIGNATURES.get(port)
                            if desc:
                                self.log(f"  🔴 {port}/{proto} ABIERTO -> {desc}", "bad")
                                any_vuln = True
                            else:
                                self.log(f"  ⚠️ {port}/{proto} ABIERTO", "warn")
                        else:
                            self.log(f"  ✅ {port}/{proto} {state.upper()}", "ok")

                if not any_vuln:
                    self.log("   No se detectaron vulnerabilidades por firmas simples.", "ok")

        except Exception as e:
            self.log(f"ERROR: {e}", "bad")

        self.finish_scan()

    def finish_scan(self):
        self.is_scanning = False
        self.btn_scan.config(state="normal")
        self.btn_save.config(state="normal" if self.report_buffer else "disabled")
        self.log("\n✅ Escaneo finalizado.", "ok")

    def save_report(self):
        fname = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Archivo de texto", "*.txt")],
            initialfile=f"reporte_albswarti_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        if not fname:
            return
        try:
            with open(fname, "w", encoding="utf-8") as f:
                for line in self.report_buffer:
                    f.write(line + "\n")
            messagebox.showinfo("Guardado", f"Reporte guardado en:\n{fname}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo guardar el reporte: {e}")


def main():
    root = tk.Tk()
    app = ScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
