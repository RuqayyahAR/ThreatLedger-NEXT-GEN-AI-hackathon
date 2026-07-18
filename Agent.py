import time
import subprocess
import requests

# The URL of our team's Java Spring Boot backend server
API_URL = "http://localhost:8080/api/threats"

# Keep track of IPs we already blocked so we don't repeat work
blocked_ips = set()

# Path to the local file where Snort looks for custom rules
SNORT_RULES_FILE = "local.rules"

def get_verified_threats():
    """Fetches the list of verified threat IPs from the Java API."""
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
    """Executes a system command to block the IP using UFW (Linux firewall)."""
    try:
        print(f"[+] Block list update: {ip_address}")
        command = ["sudo", "ufw", "deny", "from", ip_address, "to", "any"]
        subprocess.run(command, capture_output=True, text=True, check=True)
        print(f"[✓] Firewall successfully blocked {ip_address}")
        return True
    except Exception as e:
        print(f"[✗] Failed to run firewall command for {ip_address}: {e}")
        return False

def add_to_snort_rules(ip_address, threat_id):
    """Appends a custom block rule for Snort IDS so it flags traffic from this IP."""
    try:
        # Create a standard Snort rule format
        # drop ip <malicious_ip> any -> any any (msg:"ThreatLedger Blocked IP"; sid:<unique_id>; rev:1;)
        snort_rule = f'drop ip {ip_address} any -> any any (msg:"ThreatLedger Blocked Traffic"; sid:{2000000 + threat_id}; rev:1;)\n'
        
        # Open our local rules file and append the new rule text
        with open(SNORT_RULES_FILE, "a") as file:
            file.write(snort_rule)
            
        print(f"[✓] Added rule to Snort config for {ip_address}")
        return True
    except Exception as e:
        print(f"[✗] Failed to write Snort rule: {e}")
        return False

def main_loop():
    print("==================================================")
    print(" ThreatLedger Client-Side Automation Agent Running ")
    print("==================================================")
    
    while True:
        threat_list = get_verified_threats()
        
        for item in threat_list:
            status = item.get("consensusStatus")
            ip = item.get("indicatorValue")
            data_type = item.get("indicatorType")
            threat_id = item.get("indicatorId", 0)
            
            # Check for verified IPs we haven't handled yet
            if status == "VERIFIED" and data_type == "IP" and ip not in blocked_ips:
                # Run firewall block
                fw_success = block_in_firewall(ip)
                
                # Run Snort block
                snort_success = add_to_snort_rules(ip, threat_id)
                
                # If both work, mark it as done so we don't repeat it
                if fw_success and snort_success:
                    blocked_ips.add(ip)
        
        print("[*] Sleeping for 10 seconds...\n")
        time.sleep(10)

if __name__ == "__main__":
    main_loop()
