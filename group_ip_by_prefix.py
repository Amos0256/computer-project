import os
import sys
import subprocess
import get_diff_malicious_ip
from utils.DefaultValue import *
from utils import Generator, CTI

SAME_PREFIX_BYTE = 3

if len(sys.argv) > 1:
    SAME_PREFIX_BYTE = int(sys.argv[1])
    if SAME_PREFIX_BYTE > 4 or SAME_PREFIX_BYTE < 0:
        print("same prefix bytes should between 0 and 4")
        exit()


def group_ips_by_prefix(ip_list):
    ip_groups = {}
    for ip in ip_list:
        prefix_bytes = ip.split(".")[0:SAME_PREFIX_BYTE]
        ip_prefix = ".".join(prefix_bytes)
        if ip_prefix in ip_groups:
            ip_groups[ip_prefix].append(ip)
        else:
            ip_groups[ip_prefix] = [ip]
    return ip_groups


input_dir = f"{BASE_PATH}distinct_malicious_IPs"

# generate different malicious ips
print("Generate different malicious ips...")
get_diff_malicious_ip.main()
print("Done!\n")


input_file = os.path.join(input_dir, "distinct_malicious_IPs.txt")

# Read the input IP addresses from the file
with open(input_file, "r") as f:
    ip_list = [line.strip() for line in f.readlines()]

# Group the IP addresses by their first three bytes
ip_groups = group_ips_by_prefix(ip_list)

# Output each group to a separate file

scan_file = "../malicious_IPs_netflow_20230101_to_20230228"
if not os.path.isdir(scan_file):
    print("\033[91m" + "Can't not find ../malicious_IPs_netflow_20230101_to_20230228")
    print("Please run python3 parallel_malicious_flow.py first" + "\033[0m")
    exit()


for ip_prefix, ips in ip_groups.items():
    if len(ips) == 1:  # only one ip has this prefix, drop it
        continue

    output_dir = f"../same_prefix_ip_{SAME_PREFIX_BYTE}/{ip_prefix}"
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    print(f"Group {ip_prefix}")

    # with open(output_file, "w") as f:
    for ip in ips:
        output_file = f"{output_dir}/{ip}.txt"
        with open(output_file, "w") as f:
            cmd = (
                f'find {scan_file} -iname "*{ip}.txt" -exec cat {{}} \\; -exec echo \\;'
            )
            print(f"\t{cmd}")
            subprocess.run(cmd, shell=True, stdout=f)
