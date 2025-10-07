from http.server import BaseHTTPRequestHandler
import json
import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import paramiko
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ---------- CONFIG ----------
PROBE_WORKERS = 25

ADMIN_USER = "admin"
ADMIN_PASS = "spt_admin"

PORTS_TO_CHECK = [22, 80]

CONNECT_TIMEOUT = 1.0
SSH_TIMEOUT = 4.0
HTTP_TIMEOUT = 3.0

SPIRENT_INDICATORS = ("spirent", "testcenter", "stc", "spirenttestcenter")
# ----------------------------

def parse_subnet(user_input):
    """Parse subnet or gateway/mask and return list of usable IPs."""
    user_input = user_input.strip()
    if "/" in user_input:
        network = ipaddress.IPv4Network(user_input, strict=False)
    else:
        parts = user_input.split()
        if len(parts) != 2:
            raise ValueError("Invalid input format.")
        ip, mask = parts
        network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    return [str(ip) for ip in network.hosts()]

def port_is_open(ip, port, timeout=CONNECT_TIMEOUT):
    """Check if a TCP port is open."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

def try_ssh_probe(ip, username, password):
    """Attempt SSH login and run basic commands."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, username=username, password=password,
                       timeout=SSH_TIMEOUT, allow_agent=False, look_for_keys=False)
    except Exception:
        return None

    output = []
    try:
        for cmd in ("show version", "uname -a", "cat /etc/issue"):
            try:
                stdin, stdout, stderr = client.exec_command(cmd, timeout=SSH_TIMEOUT)
                text = stdout.read().decode("utf-8", errors="ignore").strip()
                if text:
                    output.append(text)
            except Exception:
                pass
    finally:
        client.close()
    return "\n".join(output) if output else None

def try_http_probe(ip, username, password):
    """Try HTTP port 80 and look for Spirent indicators."""
    url = f"http://{ip}/"
    headers = {"User-Agent": "spirent-probe/1.0"}
    try:
        r = requests.get(url, timeout=HTTP_TIMEOUT, headers=headers, auth=(username, password))
        txt = r.text.lower() if r.text else ""
        if any(ind in txt for ind in SPIRENT_INDICATORS):
            return True
    except Exception:
        pass
    return False

def probe_host(ip):
    """Check SSH and HTTP for Spirent indicators."""
    info = {"ip": ip, "ports": [], "likely_spirent": False}
    open_ports = [p for p in PORTS_TO_CHECK if port_is_open(ip, p)]
    info["ports"] = open_ports

    # SSH check
    if 22 in open_ports:
        ssh_text = try_ssh_probe(ip, ADMIN_USER, ADMIN_PASS)
        if ssh_text and any(ind in ssh_text.lower() for ind in SPIRENT_INDICATORS):
            info["likely_spirent"] = True

    # HTTP check
    if 80 in open_ports:
        if try_http_probe(ip, ADMIN_USER, ADMIN_PASS):
            info["likely_spirent"] = True

    return info

def scan_network(subnet):
    """Main scanning function."""
    start_time = time.time()
    
    try:
        hosts = parse_subnet(subnet)
    except Exception as e:
        return {
            "error": str(e),
            "spirent_devices": [],
            "logs": []
        }
    
    logs = []
    logs.append(f"[+] Probing {len(hosts)} hosts for Spirent devices (SSH:22 / HTTP:80)...")
    
    results = []
    detected_count = 0
    
    with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as ex:
        futures = {ex.submit(probe_host, ip): ip for ip in hosts}
        for fut in as_completed(futures):
            try:
                r = fut.result()
                results.append(r)
                if r["likely_spirent"]:
                    detected_count += 1
                    logs.append(f"> Spirent detected: {r['ip']} (ports: {r['ports']})")
            except Exception:
                pass

    spirent_list = [r for r in results if r.get("likely_spirent")]
    
    logs.append("\nSummary - Likely Spirent devices:")
    if spirent_list:
        for s in spirent_list:
            logs.append(f" - {s['ip']} (ports: {s['ports']})")
    else:
        logs.append(" (none detected)")
    
    scan_time = time.time() - start_time
    logs.append(f"\nTotal time taken: {scan_time:.1f} seconds")
    
    return {
        "spirent_devices": spirent_list,
        "scan_time": f"{scan_time:.1f} seconds",
        "total_hosts": len(hosts),
        "logs": logs
    }

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            data = json.loads(post_data.decode('utf-8'))
            subnet = data.get('subnet', '')
            
            if not subnet:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Subnet is required"}).encode())
                return
            
            result = scan_network(subnet)
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
            
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            error_data = {"error": str(e), "type": "server_error"}
            self.wfile.write(json.dumps(error_data).encode())
    
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        response = {"status": "API is running", "endpoint": "/api/scan", "method": "POST"}
        self.wfile.write(json.dumps(response).encode())
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()