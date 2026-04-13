import sys
import json
from server.agents.executer.recon.tools.server.linux_privesc_audit import linux_privesc_audit

if len(sys.argv) < 3:
    print("Usage: python test_htb.py <username> <password>")
    sys.exit(1)

username = sys.argv[1]
password = sys.argv[2]
target="10.129.22.137"

print(f"[*] Testing {target} via SSH paramiko with user {username}...")

result = linux_privesc_audit(
    tool="manual",
    mode="manual_suid",
    target=target,
    username=username,
    password=password,
    timeout=60
)

print("\n" + "="*60)
print("RESULTS:")
print("="*60)
print(json.dumps(result, indent=2))
