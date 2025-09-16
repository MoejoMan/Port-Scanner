import socket
import sys
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from tabulate import tabulate
from colorama import init, Fore

init(autoreset=True)

WEB_PORTS = {80: "HTTP", 443: "HTTPS", 8080: "HTTP-alt"}
DB_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL"}
EMAIL_PORTS = {25: "SMTP", 110: "POP3", 143: "IMAP"}
ADMIN_PORTS = {22: "SSH", 3389: "RDP", 5900: "VNC"}

print("Select port category to scan:")
print("1 - Web ports")
print("2 - Database ports")
print("3 - Email ports")
print("4 - Admin/Other ports")

choice = input("Enter choice (1-4): ")

if choice == "1":
    ports_to_scan = WEB_PORTS.keys()
elif choice == "2":
    ports_to_scan = DB_PORTS.keys()
elif choice == "3":
    ports_to_scan = EMAIL_PORTS.keys()
elif choice == "4":
    ports_to_scan = ADMIN_PORTS.keys()
else:
    print("Invalid choice, defaulting to custom range")
    START_PORT = int(input("Start port: "))
    END_PORT = int(input("End port: "))
    ports_to_scan = range(START_PORT, END_PORT + 1)

TARGET = sys.argv[1] if len(sys.argv) > 1 else input("Target (ip or hostname): ")
ports = ports_to_scan

TIMEOUT = 0.6
THREADS = 200
OUTPUT_DIR = Path("scans")
OUTPUT_DIR.mkdir(exist_ok=True)

def scan_port(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        res = s.connect_ex((host, port))
        s.close()
        if res == 0:
            return {"port": port, "status": "open"}
        else:
            return {"port": port, "status": "closed"}
    except Exception:
        return {"port": port, "status": "filtered"}

def grab_banner(host, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((host, port))
        banner = s.recv(1024).decode().strip()
        s.close()
        return banner
    except:
        return None

def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def compress_ranges(ports_list):
    """Compress consecutive ports with same status into ranges"""
    if not ports_list:
        return []
    ports_list = sorted(ports_list, key=lambda x: x["port"])
    compressed = []
    start = prev = ports_list[0]["port"]
    for p in ports_list[1:]:
        if p["port"] == prev + 1:
            prev = p["port"]
        else:
            compressed.append(f"{start}-{prev}" if start != prev else str(start))
            start = prev = p["port"]
    compressed.append(f"{start}-{prev}" if start != prev else str(start))
    return compressed

def write_output(target, ip, open_ports, closed_ports, filtered_ports, duration):
    now = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    summary = {
        "target": target,
        "ip": ip,
        "timestamp_utc": now,
        "duration_s": duration,
        "open_ports": sorted(open_ports, key=lambda x: x["port"]),
        "closed_ports": sorted(closed_ports, key=lambda x: x["port"]),
        "filtered_ports": sorted(filtered_ports, key=lambda x: x["port"])
    }
    out_file = OUTPUT_DIR / f"scan_{target.replace('/','_')}_{now}.json"
    with open(out_file, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Saved results -> {out_file}")

def main():
    ip = resolve_host(TARGET)
    if not ip:
        print(f"Could not resolve {TARGET}")
        return

    print(f"Scanning {TARGET} ({ip}) ports {min(ports)}-{max(ports)}")
    start = datetime.utcnow()

    open_ports, closed_ports, filtered_ports = [], [], []
    total_ports = len(ports)
    scanned_count = 0

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = {ex.submit(scan_port, ip, p): p for p in ports}

        for fut in as_completed(futures):
            scanned_count += 1
            if scanned_count % 50 == 0 or scanned_count == total_ports:
                print(f"Scanned {scanned_count}/{total_ports} ports...")

            try:
                res = fut.result()
            except Exception:
                res = None

            if res:
                status = res["status"]
                if status == "open":
                    port_num = res["port"]
                    banner = grab_banner(ip, port_num)
                    open_ports.append({"port": port_num, "status": status, "banner": banner})

                elif status == "closed":
                    closed_ports.append(res)
                else:
                    filtered_ports.append(res)

    duration = (datetime.utcnow() - start).total_seconds()
    print(f"\nScan complete in {duration:.2f}s\n")

    summary_table = []

    for category, ports_list in [("Open", open_ports), ("Closed", closed_ports), ("Filtered", filtered_ports)]:
        color = Fore.GREEN if category == "Open" else Fore.RED if category == "Closed" else Fore.YELLOW
        
        if category == "Open":
            for p in ports_list:
                banner = p.get("banner")
                display = f"{p['port']} ({banner})" if banner else str(p["port"])
                summary_table.append([color + display, color + category])
        else:
            compressed = compress_ranges(ports_list)
            for entry in compressed:
                summary_table.append([color + entry, color + category])


    print("Scan Summary:")
    print(tabulate(summary_table, headers=["Ports", "Status"], tablefmt="fancy_grid"))
    print(f"\nTotals: Open={len(open_ports)}, Closed={len(closed_ports)}, Filtered={len(filtered_ports)}")

    write_output(TARGET, ip, open_ports, closed_ports, filtered_ports, duration)

if __name__ == "__main__":
    main()
