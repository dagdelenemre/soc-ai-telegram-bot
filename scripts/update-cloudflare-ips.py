#!/usr/bin/env python3
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    # IDE and local repository execution
    from core.soc_resilience import http_get_text
except ImportError:
    # Production flattened execution (/usr/local/bin)
    from soc_resilience import http_get_text  # type: ignore

CONF_FILE = "/etc/nginx/conf.d/cloudflare-real-ip.conf"

def fetch_ips():
    ips = []
    try:
        # Transient network errors are retried with backoff before giving up
        ips.extend(http_get_text("https://www.cloudflare.com/ips-v4").strip().split('\n'))

        ips.extend(http_get_text("https://www.cloudflare.com/ips-v6").strip().split('\n'))
    except Exception as e:
        print(f"Error fetching Cloudflare IPs: {e}")
        sys.exit(1)
    return ips

def main():
    ips = fetch_ips()
    content = "# Cloudflare IP ranges - restore real visitor IP\n"
    for ip in ips:
        content += f"set_real_ip_from {ip};\n"
    
    content += "real_ip_header CF-Connecting-IP;\n"
    content += "real_ip_recursive on;\n"
    
    # Check if there are changes
    current_content = ""
    try:
        with open(CONF_FILE, "r") as f:
            current_content = f.read()
    except FileNotFoundError:
        pass

    if content != current_content:
        try:
            with open(CONF_FILE, "w") as f:
                f.write(content)
                
            nginx_test = subprocess.run(["nginx", "-t"], capture_output=True)
            if nginx_test.returncode == 0:
                subprocess.run(["systemctl", "reload", "nginx"])
                print("Cloudflare IPs updated and NGINX reloaded.")
            else:
                print("ERROR: NGINX config invalid, reload cancelled.")
        except PermissionError:
            print(f"Permission denied to write {CONF_FILE}. Please run as root.")
    else:
        print("No changes in Cloudflare IPs.")

if __name__ == "__main__":
    main()
