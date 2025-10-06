
import ipaddress
import platform
import subprocess
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import paramiko
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ---------- CONFIG ----------
PING_WORKERS = 100
PROBE_WORKERS = 25

ADMIN_USER = "admin"
ADMIN_PASS = "spt_admin"

PORTS_TO_CHECK = [22, 80]

CONNECT_TIMEOUT = 1.0
SSH_TIMEOUT = 4.0
HTTP_TIMEOUT = 3.0

SPIRENT_INDICATORS = ("spirent", "testcenter", "stc", "spirenttestcenter")
# ----------------------------

def ping_ip(ip: str, ping_timeout_seconds: int = 1) -> bool:
    """Ping a single IP, return True if reachable."""
    system = platform.system().lower()
    try:
        if system == "linux":
            cmd = ["ping", "-c", "1", "-W", str(int(ping_timeout_seconds)), ip]
        elif system == "darwin":
            cmd = ["ping", "-c", "1", "-W", str(int(ping_timeout_seconds * 1000)), ip]
        else:
            cmd = ["ping", "-n", "1", "-w", str(int(ping_timeout_seconds * 1000)), ip]
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

def generate_hosts_from_user_input():
    """Ask user for subnet or gateway/mask and return list of usable IPs."""
    user_input = input("Enter subnet (CIDR, e.g., 172.26.196.0/24) or gateway + mask (e.g., 172.26.196.1 255.255.255.0): ").strip()
    if "/" in user_input:
        network = ipaddress.IPv4Network(user_input, strict=False)
    else:
        parts = user_input.split()
        if len(parts) != 2:
            print("Invalid input format.")
            exit(1)
        ip, mask = parts
        network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    return [str(ip) for ip in network.hosts()]

def port_is_open(ip: str, port: int, timeout: float = CONNECT_TIMEOUT) -> bool:
    """Check if a TCP port is open."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

def try_ssh_probe(ip: str, username: str, password: str):
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

def try_http_probe(ip: str, username: str, password: str):
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

def probe_host(ip: str):
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

def main():
    start_time = time.time()
    hosts = generate_hosts_from_user_input()
    print(f"[+] Probing {len(hosts)} hosts for Spirent devices (SSH:22 / HTTP:80)...")

    results = []
    with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as ex:
        futures = {ex.submit(probe_host, ip): ip for ip in hosts}
        for fut in as_completed(futures):
            try:
                r = fut.result()
                results.append(r)
                if r["likely_spirent"]:
                    print(f"> Spirent detected: {r['ip']} (ports: {r['ports']})")
            except Exception:
                pass

    spirent_list = [r for r in results if r.get("likely_spirent")]
    print("\nSummary - Likely Spirent devices:")
    if spirent_list:
        for s in spirent_list:
            print(f" - {s['ip']} (ports: {s['ports']})")
    else:
        print(" (none detected)")

    print("\nTotal time taken: {:.1f} seconds".format(time.time() - start_time))

if __name__ == "__main__":
    main()
