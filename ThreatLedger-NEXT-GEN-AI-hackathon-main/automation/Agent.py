import time
import subprocess
import requests

# Pointing directly to the backend's pre-filtered verified status query parameter
API_URL = "http://localhost:8080/api/threats?status=VERIFIED"

# Track IPs we already blocked so we don't repeat system work
blocked_ips = set()

# Path to the local file where Snort looks for custom signatures
SNORT_RULES_FILE = "local.rules"

def get_verified_threats():
    """Fetches the pre-filtered list of verified threat objects from the Java API."""
    try:
        print("[*] Checking backend for new verified threats...")
        response = requests.get(API_URL, timeout=5)
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"[!] Server error code: {response.status_code}")
            return []
    except Exception as e:
        print(f"[!] Failed to connect to backend: {e}")
        return []

def block_in_firewall(ip_address):
    """Executes a system command to drop traffic from the IP using UFW."""
    try:
        print(f"[+] Injecting firewall drop rule for: {ip_address}")
        command = ["sudo", "ufw", "deny", "from", ip_address, "to", "any"]
        subprocess.run(command, capture_output=True, text=True, check=True)
        print(f"[✓] Firewall successfully blocked {ip_address}")
        return True
    except Exception as e:
        print(f"[✗] Failed to execute firewall command for {ip_address}: {e}")
        return False

def add_to_snort_rules(ip_address, threat_id):
    """Appends a custom signature rule for Snort IDS so it flags traffic."""
    try:
        # Standard Snort rules syntax mapping directly to backend data indices
        snort_rule = f'drop ip {ip_address} any -> any any (msg:"ThreatLedger Blocked Traffic"; sid:{2000000 + threat_id}; rev:1;)\n'
        
        with open(SNORT_RULES_FILE, "a") as file:
            file.write(snort_rule)
            
        print(f"[✓] Appended custom signature to Snort config for {ip_address}")
        return True
    except Exception as e:
        print(f"[✗] Failed to write Snort rule entry: {e}")
        return False

def main_loop():
    print("==================================================")
    print(" ThreatLedger Client-Side Automation Agent Running ")
    print("==================================================")
    
    while True:
        # Backend returns ONLY verified threats, removing local status checks
        threat_list = get_verified_threats()
        
        for item in threat_list:
            ip = item.get("indicatorValue")
            data_type = item.get("indicatorType")
            threat_id = item.get("indicatorId", 0)
            
            # Target IP vectors that have not been registered in current session
            if data_type == "IP" and ip and ip not in blocked_ips:
                fw_success = block_in_firewall(ip)
                snort_success = add_to_snort_rules(ip, threat_id)
                
                if fw_success and snort_success:
                    blocked_ips.add(ip)
        
        print("[*] Sleeping for 10 seconds before next polling cycle...\n")
        time.sleep(10)

if __name__ == "__main__":
    main_loop()
