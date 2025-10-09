#!/usr/bin/env python3
# find_free_ips_shared_vpc.py
# Works on Python 3.6+ (RHEL default). No external libs required.

import ipaddress
import json
import subprocess
import sys

# ========= CONFIGURE =========
HOST_PROJECT = "your-host-project-id"   # where the VPC/subnet lives
SERVICE_PROJECTS = ["your-dev-project-id"]  # list; can add more service projects
SUBNET_NAME = "your-subnet-name"
REGION = "asia-south1"
VALIDATE_N = 0   # >0 to try reserving first N candidates to double-check availability
# =============================

def run(cmd):
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, universal_newlines=True)
    if res.returncode != 0:
        print("❌ CMD failed:", cmd)
        print(res.stderr.strip())
        sys.exit(1)
    return res.stdout

def get_subnet_info():
    # CIDR
    cidr = run(
        "gcloud compute networks subnets describe {sn} "
        "--region={rg} --project={hp} --format='value(ipCidrRange)'"
        .format(sn=SUBNET_NAME, rg=REGION, hp=HOST_PROJECT)
    ).strip()
    # selfLink (used to filter instances / fwd rules precisely)
    self_link = run(
        "gcloud compute networks subnets describe {sn} "
        "--region={rg} --project={hp} --format='value(selfLink)'"
        .format(sn=SUBNET_NAME, rg=REGION, hp=HOST_PROJECT)
    ).strip()
    print("✅ Subnet CIDR:", cidr)
    print("✅ Subnet selfLink:", self_link)
    return cidr, self_link

def used_static_ips(project_id, subnet_self_link):
    # internal static addresses (reserved or in-use)
    out = run(
        "gcloud compute addresses list --project={p} "
        "--filter='subnetwork:{sub}' --format=json"
        .format(p=project_id, sub=subnet_self_link)
    )
    data = json.loads(out or "[]")
    ips = {a.get("address","").strip() for a in data if a.get("address")}
    return ips

def used_instance_ips(project_id, subnet_self_link, cidr):
    # all VM NIC IPs attached to this subnet (primary NIC IPs)
    out = run(
        "gcloud compute instances list --project={p} --format=json"
        .format(p=project_id)
    )
    data = json.loads(out or "[]")
    net = ipaddress.ip_network(cidr)
    ips = set()
    for inst in data:
        for nic in inst.get("networkInterfaces", []):
            if nic.get("subnetwork") == subnet_self_link:
                ip = (nic.get("networkIP") or "").strip()
                if ip:
                    # keep only if inside CIDR (paranoia / dual-NIC safety)
                    try:
                        if ipaddress.ip_address(ip) in net:
                            ips.add(ip)
                    except ValueError:
                        pass
    return ips

def used_forwarding_rule_ips(project_id, subnet_self_link, cidr):
    # internal L3/4 ILB (regional)
    reg = run(
        "gcloud compute forwarding-rules list --project={p} "
        "--regions={r} --format=json"
        .format(p=project_id, r=REGION)
    )
    # internal HTTP(S) ILB (global)
    glob = run(
        "gcloud compute forwarding-rules list --project={p} "
        "--global --format=json"
        .format(p=project_id)
    )
    net = ipaddress.ip_network(cidr)
    ips = set()

    def collect(arr):
        for fr in arr:
            ip = (fr.get("IPAddress") or "").strip()
            if not ip:
                continue
            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                continue
            # prefer exact subnetwork match if present; otherwise fall back to CIDR containment
            if fr.get("subnetwork") == subnet_self_link or ip_obj in net:
                # consider only INTERNAL LBs
                if fr.get("loadBalancingScheme") == "INTERNAL":
                    ips.add(ip)

    collect(json.loads(reg or "[]"))
    collect(json.loads(glob or "[]"))
    return ips

def generate_all_hosts(cidr):
    # hosts() excludes network & broadcast; we will also remove .1 (default GW) below
    net = ipaddress.ip_network(cidr)
    return [str(ip) for ip in net.hosts()]

def try_reserve_in_host(ip):
    # attempt a temporary reservation in the host project to prove availability
    name = "tmp-check-" + ip.replace(".", "-")
    create = subprocess.run(
        "gcloud compute addresses create {n} --project={p} --region={r} "
        "--subnet={sn} --addresses={ip} --quiet"
        .format(n=name, p=HOST_PROJECT, r=REGION, sn=SUBNET_NAME, ip=ip),
        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True
    )
    ok = (create.returncode == 0)
    # cleanup if created
    if ok:
        subprocess.run(
            "gcloud compute addresses delete {n} --project={p} --region={r} --quiet"
            .format(n=name, p=HOST_PROJECT, r=REGION),
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True
        )
    return ok

def main():
    print("🔎 Shared VPC free-IP detector (Host + Service projects)\n")
    cidr, self_link = get_subnet_info()

    # Build project set (host + all services)
    projects = [HOST_PROJECT] + SERVICE_PROJECTS

    # 1) static reservations
    static_used = set()
    for prj in projects:
        s = used_static_ips(prj, self_link)
        print("• Static in {}: {}".format(prj, len(s)))
        static_used |= s

    # 2) VM NIC IPs
    vm_used = set()
    for prj in projects:
        s = used_instance_ips(prj, self_link, cidr)
        print("• VM NICs in {}: {}".format(prj, len(s)))
        vm_used |= s

    # 3) ILB forwarding-rule IPs
    fr_used = set()
    for prj in projects:
        s = used_forwarding_rule_ips(prj, self_link, cidr)
        print("• ILB FRs in {}: {}".format(prj, len(s)))
        fr_used |= s

    # Combine all used
    used_all = {ip.strip() for ip in (static_used | vm_used | fr_used) if ip.strip()}

    # 4) generate all hosts and remove GCP-reserved .1 gateway
    all_hosts = generate_all_hosts(cidr)
    # GCP reserves the default gateway (first host); drop it if present
    if all_hosts:
        gw = all_hosts[0]
        all_hosts = [ip for ip in all_hosts if ip != gw]

    # 5) candidates
    candidates = sorted(set(all_hosts) - used_all)

    # Write audit files
    with open("used_static_ips.txt", "w") as f: f.write("\n".join(sorted(static_used)) + "\n")
    with open("used_vm_nic_ips.txt", "w") as f: f.write("\n".join(sorted(vm_used)) + "\n")
    with open("used_forwarding_rule_ips.txt", "w") as f: f.write("\n".join(sorted(fr_used)) + "\n")
    with open("candidate_free_ips.txt", "w") as f: f.write("\n".join(candidates) + "\n")

    print("\n📊 Summary")
    print("  CIDR             :", cidr)
    print("  Used (static)    :", len(static_used))
    print("  Used (VM NICs)   :", len(vm_used))
    print("  Used (ILB FRs)   :", len(fr_used))
    print("  Candidates (free):", len(candidates))
    if candidates:
        print("  Sample candidates:", ", ".join(candidates[:10]))

    # Optional: on-the-fly validation (catches any dynamic/edge cases)
    if VALIDATE_N > 0 and candidates:
        print("\n🧪 Validating first {} candidates via temp reservation in host project…"
              .format(VALIDATE_N))
        ok = []
        for ip in candidates[:VALIDATE_N]:
            if try_reserve_in_host(ip):
                ok.append(ip)
        if ok:
            print("  ✅ Truly free:", ", ".join(ok))
        else:
            print("  ⚠️ None of the tested candidates could be reserved — subnet may be busy.")

if __name__ == "__main__":
    main()
