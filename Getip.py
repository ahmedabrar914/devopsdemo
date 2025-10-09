#!/usr/bin/env python3
import ipaddress
import subprocess
import sys
import os

# ========== CONFIG ==========
HOST_PROJECT = "your-host-project-id"
DEV_PROJECT = "your-dev-project-id"
SUBNET_NAME = "your-subnet-name"
REGION = "asia-south1"
VALIDATE_COUNT = 5  # Number of candidate IPs to try reserving to validate availability
# ============================

def run_cmd(cmd):
    """Run shell command and return stdout"""
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, universal_newlines=True)
    if result.returncode != 0:
        print(f"❌ Command failed: {cmd}")
        print(result.stderr.strip())
        sys.exit(1)
    return result.stdout.strip()

def get_subnet_cidr():
    """Get subnet CIDR from host project"""
    cmd = (
        f"gcloud compute networks subnets describe {SUBNET_NAME} "
        f"--region={REGION} --project={HOST_PROJECT} --format='value(ipCidrRange)'"
    )
    cidr = run_cmd(cmd)
    if not cidr:
        print("❌ Could not retrieve subnet CIDR.")
        sys.exit(1)
    print(f"✅ Subnet CIDR: {cidr}")
    return cidr

def get_used_ips(project_id):
    """Get static reserved IPs from a project"""
    cmd = (
        f"gcloud compute addresses list "
        f"--project={project_id} "
        f"--filter='subnetwork:{SUBNET_NAME}' "
        f"--format='value(address)'"
    )
    output = run_cmd(cmd)
    used = set(ip.strip() for ip in output.splitlines() if ip.strip())
    print(f"   - Found {len(used)} static IPs in {project_id}")
    return used

def generate_all_ips(cidr):
    """Generate all usable IP addresses from the subnet CIDR"""
    net = ipaddress.ip_network(cidr)
    all_ips = set(str(ip) for ip in net.hosts())  # excludes network & broadcast
    print(f"✅ Total usable IPs in CIDR: {len(all_ips)}")
    return all_ips

def validate_ip_availability(ip):
    """Try to reserve an IP in host project to verify if it's truly available"""
    cmd = (
        f"gcloud compute addresses create test-ip-{ip.replace('.', '-')}-temp "
        f"--region={REGION} "
        f"--subnet={SUBNET_NAME} "
        f"--addresses={ip} "
        f"--project={HOST_PROJECT}"
    )
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, universal_newlines=True)
    if result.returncode == 0:
        # Cleanup immediately
        subprocess.run(
            f"gcloud compute addresses delete test-ip-{ip.replace('.', '-')}-temp "
            f"--region={REGION} --project={HOST_PROJECT} --quiet",
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        return True
    else:
        return False

def main():
    print("🔎 Checking IP usage across Host + Dev projects (Shared VPC)\n")

    # 1. Get CIDR
    cidr = get_subnet_cidr()

    # 2. Get used IPs from host and dev
    print("📡 Collecting used static IPs...")
    host_used = get_used_ips(HOST_PROJECT)
    dev_used = get_used_ips(DEV_PROJECT)
    all_used_static = host_used.union(dev_used)
    print(f"✅ Total static used/reserved IPs (Host+Dev): {len(all_used_static)}")

    # 3. Generate all usable IPs
    all_ips = generate_all_ips(cidr)

    # 4. Subtract static used from full list
    candidate_free_ips = sorted(all_ips - all_used_static)
    print(f"✅ Candidate free IPs (before validation): {len(candidate_free_ips)}")

    # Save candidate list
    with open("candidate_free_ips.txt", "w") as f:
        for ip in candidate_free_ips:
            f.write(ip + "\n")

    # 5. Optional validation of a few IPs
    print(f"\n🧪 Validating first {VALIDATE_COUNT} candidate IPs by attempting temporary reservation...")
    truly_free = []
    for ip in candidate_free_ips[:VALIDATE_COUNT]:
        if validate_ip_availability(ip):
            truly_free.append(ip)

    if truly_free:
        print(f"✅ Truly available IPs (based on reservation test): {', '.join(truly_free)}")
    else:
        print("⚠️ No candidate IPs succeeded in reservation test — possible full usage or GKE allocations.")

    print("\n📄 Candidate free IPs saved to: candidate_free_ips.txt")

if __name__ == "__main__":
    main()
