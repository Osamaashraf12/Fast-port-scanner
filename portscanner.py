import socket
import threading
import argparse
from datetime import datetime
import time
import platform
import subprocess
from tqdm import tqdm

class PortScanner:
    def __init__(self, target, start_port, end_port):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.open_ports = []
        self.lock = threading.Lock()
        self.max_threads = self.get_max_threads()

    def get_max_threads(self):
        os_type = platform.system()
        if os_type != "Linux":
            print("Please run on a Linux system.")
            exit(1)
        result = subprocess.run(["cat", "/proc/sys/kernel/threads-max"], capture_output=True, text=True)
        return int(result.stdout.strip())

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                service = self.get_service(port)
                with self.lock:
                    self.open_ports.append((port, service))
            sock.close()
        except:
            pass

    def get_service(self, port):
        common_services = {
            21: "FTP",
            22: "SSH",
            25: "SMTP",
            80: "HTTP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            8080: "HTTP-Proxy"
        }
        return common_services.get(port, "Unknown")

    def run_scan(self):
        print(f"Scanning {self.target} from port {self.start_port} to {self.end_port}.")
        threads = []
        ports = list(range(self.start_port, self.end_port + 1))
        chunk_size = max(1, len(ports) // self.max_threads)
        progress_bar = tqdm(total=len(ports), desc="Scanning ports", unit="port")

        def scan_port_range(start, end):
            for port in range(start, end):
                self.scan_port(port)
            with self.lock:
                progress_bar.update(end - start)

        for i in range(0, len(ports), chunk_size):
            start = ports[i]
            end = min(start + chunk_size, self.end_port + 1)
            thread = threading.Thread(target=scan_port_range, args=(start, end))
            threads.append(thread)
            thread.start()
            if len(threads) >= self.max_threads:
                for thread in threads:
                    thread.join()
                threads = []

        for thread in threads:
            thread.join()
        progress_bar.close()

    def generate_report(self, duration):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report = f"Port Scan Report for {self.target} ({timestamp})\n"
        report += f"Scan Duration: {duration:.2f} seconds\n"
        report += "=" * 50 + "\n"
        if self.open_ports:
            for port, service in self.open_ports:
                report += f"Port {port}: Open ({service})\n"
        else:
            report += "No open ports found.\n"

        print(report)

def parse_ports(port_str):
    if port_str == "-":
        return 1, 65535
    if "-" in port_str:
        start, end = map(int, port_str.split("-"))
        return start, end
    return int(port_str), int(port_str)

def is_valid_ip(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True
    except ValueError:
        return False

def main():
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("target", help="Target IP (e.g., 127.0.0.1)")
    parser.add_argument(
        "-p", "--ports",
        default="1-65535",
        help="Ports to scan: single port (e.g., 80), range (e.g., 1-1000), or all ports (e.g., - or 1-65535)"
    )
    args = parser.parse_args()

    try:
        if not is_valid_ip(args.target):
            raise ValueError("Invalid IP address")
        start_port, end_port = parse_ports(args.ports)
        scanner = PortScanner(args.target, start_port, end_port)
        start_time = time.time()
        scanner.run_scan()
        duration = time.time() - start_time
        scanner.generate_report(duration)
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
