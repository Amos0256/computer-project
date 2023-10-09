import os
import sys
import subprocess
from utils.DefaultValue import *
from utils import Generator, CTI
import return_malicious_IP_set

SAME_PREFIX_BYTE = 3

# if len(sys.argv) > 1:
#     SAME_PREFIX_BYTE = int(sys.argv[1])
#     if SAME_PREFIX_BYTE > 4 or SAME_PREFIX_BYTE < 0:
#         print("same prefix bytes should between 0 and 4")
#         exit();


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


def main(ip_dict, ip_set):
    # change malicious_ip set to list
    # ip_list = list(return_malicious_IP_set.main("20230101", "20230609"))
    # Group the IP addresses by their first three bytes
    ip_list = list(ip_set)
    ip_groups = group_ips_by_prefix(ip_list)

    output_file = "./ip_prefix_with_tag.txt"
    with open(output_file, "w") as f:
        for key, values in ip_groups.items():
            if len(values) > 1:
                print(f"{key}", file=f)
                for ip in values:
                    print(f"{ip}:{ip_dict[ip]}", file=f)
