import os
import sys
import subprocess
from utils.DefaultValue import *
from utils import Generator, CTI
import return_malicious_IP_set
from collections import OrderedDict, defaultdict
from dataclasses import dataclass

SAME_PREFIX_BYTE = 3


@dataclass
class DHCP_data:
    ip_prefix: str
    tag_list: list
    max_fit_count: int


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
    ip_list = list(ip_set)
    ip_prefix_group = group_ips_by_prefix(ip_list)

    prefix_with_tag_dict = defaultdict(dict)
    prefix_tag_combination = defaultdict(DHCP_data)
    # prefix: {tag: num}
    for prefix, IPs in ip_prefix_group.items():
        if len(IPs) == 1:
            continue

        check_flag = 0
        for ip in IPs:
            #             if 'tor' in ip_dict[ip] or 'cloud' in ip_dict[ip] or 'search_engine' in ip_dict[ip]:
            #                 check_flag = 1
            #                 break

            for tag in ip_dict[ip]:
                if tag not in prefix_with_tag_dict[prefix]:
                    prefix_with_tag_dict[prefix][tag] = 0
                prefix_with_tag_dict[prefix][tag] += 1

        #         if check_flag == 1:
        #             continue

        tag_total_num_dict = OrderedDict(
            sorted(
                prefix_with_tag_dict[prefix].items(),
                key=lambda item: item[1],
                reverse=True,
            )
        )

        # print(f'{prefix}: {tag_total_num_dict}')

        i = 0  # index for iterate tag list
        i_limit = len(tag_total_num_dict) / 2
        max_fit_count = 0
        tmp = []
        for tag, count in tag_total_num_dict.items():
            if count < i_limit:
                break
            if i != 0:
                if max_fit_count - count > i_limit:
                    break
            # record tag combination
            max_fit_count = count
            tmp.insert(-1, tag)

            if i == i_limit:
                break
            i += 1
        tmp.sort()
        prefix_tag_combination[prefix] = DHCP_data(prefix, tmp, max_fit_count)
        # differ < n/2 and current_index >= n/2

    # print(prefix_with_tag_dict)

    output_file = "./DHCP_detection.txt"
    with open(output_file, "w") as f:
        for prefix, DHCP_d in prefix_tag_combination.items():
            if DHCP_d.max_fit_count >= 2:
                print(f"{prefix}: tag{DHCP_d.tag_list}", file=f)
                for ip in ip_prefix_group[prefix]:
                    if set(DHCP_d.tag_list).issubset(ip_dict[ip]):
                        print(f"\t{ip}", file=f)
                print(file=f)
                # print(f'{prefix}: {DHCP_d.max_fit_count} IPs \n\ttag:{DHCP_d.tag_list}', file=f)
