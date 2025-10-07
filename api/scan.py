import os
import json
import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import paramiko
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_DEPENDENCIES = True
except ImportError:
    HAS_DEPENDENCIES = False

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
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

def try_ssh_probe(ip, username, password):
    if not HAS_DEPENDENCIES:
        return None
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
    if not HAS_DEPENDENCIES:
        return False
    url = f"http://{ip}/"
    headers = {"User-Agent": "spirent-probe/1.0"}
    try:
        r = requests.get(url, timeout=HTTP_TIMEOUT, headers=headers, auth=(username, password))
        txt = r.text.lower() if r.text else ""
        return any(ind in txt for ind in SPIRENT_INDICATORS)
    except Exception:
        return False

def probe_host(ip):
    info = {"ip": ip, "ports": [], "likely_spirent": False}
    open_ports = [p for p in PORTS_TO_CHECK if port_is_open(ip, p)]
    info["ports"] = open_ports
    if 22 in open_ports and try_ssh_probe(ip, ADMIN_USER, ADMIN_PASS):
        info["likely_spirent"] = True
    if 80 in open_ports and try_http_probe(ip, ADMIN_USER, ADMIN_PASS):
        info["likely_spirent"] = True
    return info

def scan_network(subnet):
    if os.environ.get("VERCEL") and not HAS_DEPENDENCIES:
        return {
            "spirent_devices": [],
            "scan_time": "0.0 seconds",
            "total_hosts": 0,
            "logs": ["Stub scan: real scanning disabled in serverless environment"]
        }
    start_time = time.time()
    try:
        hosts = parse_subnet(subnet)
    except Exception as e:
        return {"error": str(e), "spirent_devices": [], "logs": []}

    logs = [f"[+] Probing {len(hosts)} hosts..."]
    results = []
    with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as ex:
        futures = {ex.submit(probe_host, ip): ip for ip in hosts}
        for fut in as_completed(futures):
            try:
                r = fut.result()
                results.append(r)
                if r["likely_spirent"]:
                    logs.append(f"> Spirent detected: {r['ip']} (ports: {r['ports']})")
            except Exception:
                pass
    spirent_list = [r for r in results if r.get("likely_spirent")]
    logs.append("\nSummary:")
    if spirent_list:
        for s in spirent_list:
            logs.append(f" - {s['ip']} (ports: {s['ports']})")
    else:
        logs.append(" (none detected)")
    scan_time = time.time() - start_time
    logs.append(f"Total time: {scan_time:.1f} seconds")
    return {
        "spirent_devices": spirent_list,
        "scan_time": f"{scan_time:.1f} seconds",
        "total_hosts": len(hosts),
        "logs": logs
    }

def handler(request):
    try:
        method = request.method.upper()
        if method == "GET":
            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
                "body": json.dumps({"status": "API is running", "endpoint": "/api/scan", "method": "POST"})
            }
        if method == "OPTIONS":
            return {
                "statusCode": 200,
                "headers": {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type"
                },
                "body": ""
            }
        if method == "POST":
            data = json.loads(request.body or "{}")
            subnet = data.get("subnet", "")
            if not subnet:
                return {
                    "statusCode": 400,
                    "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
                    "body": json.dumps({"error": "Subnet is required"})
                }
            result = scan_network(subnet)
            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
                "body": json.dumps(result)
            }
        return {
            "statusCode": 405,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"error": "Method not allowed"})
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"error": str(e), "type": "server_error"})
        }
