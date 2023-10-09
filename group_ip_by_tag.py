import subprocess

# from utils.DefaultValue import *
# from utils import Generator, CTI
# import return_malicious_IP_set
import os
import sys
import logging
import argparse
import multiprocessing
from datetime import datetime, timedelta
import pandas as pd
from collections import defaultdict

from utils.DefaultValue import *
from utils.Plot import plot_upset

tag_list = [
    "botnets",
    "malware",
    "phishing",
    "ip_scanning",
    "port_scanning",
    "spam",
    "cloud",
    "tor",
    "search_engine",
    "cryptomining",
    "exploits",
]


def main(ip_dict, tag_list):
    tag_with_ip_dict = defaultdict(list)
    # tag_with_ip_dict = {"tag":{"ip_1", "ip_2",...}}
    for ip, tags in ip_dict.items():
        tag_with_ip_dict[tuple(tags)].insert(-1, ip)

    #     for tags, IPs in tag_with_ip_dict.items():
    #         print(f'{tags}: {IPs}')
    print(f"The total combination of tags: {len(tag_with_ip_dict.keys())}", end="")
    # print(tag_with_ip_dict)


if __name__ == "__main__":
    # for test
    ip_dict = {
        "1.2.3.4": ["botnet", "malware"],
        "2.3.4.5": ["botnet", "ip_scanning", "spam"],
        "3.4.5.6": ["tor", "exploits"],
    }
    main(ip_dict, tag_list)
