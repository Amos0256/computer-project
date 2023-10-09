#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import shutil
from concurrent.futures import ThreadPoolExecutor

# from multiprocessing import Queue
from utils.DefaultValue import *

# Usage: Pass an argument as YYYYMMDD
# Example: python3 dump_netflow_month_by_day.py 20221201
# Dump the NetFlow logs of each hour in 20221201 to csv.


def dump_netflow_logs(netflow_path, dump_path, input_file, date):
    fmt = "fmt:%ts,%te,%td,%pr,%sa,%sp,%da,%dp,%flg,%pkt,%byt,%stos"

    # print(f"date: {date}")
    with open(input_file) as f:
        for ip in f:
            ip = ip.strip()
            out_path = f"{dump_path}/dump_{date}_{ip}.txt"
            in_path = f"{netflow_path}/nfcapd.{date}0000:nfcapd.{date}2355"

            cmd = ["nfdump", "-R", f"{in_path}", f"src or dst ip {ip}", "-o", "long"]
            # subprocess.run(command, check=True)
            with open(out_path, "a") as out:
                subprocess.run(cmd, stdout=out, check=True)
            size = os.path.getsize(out_path)
            if size == 0:
                os.remove(out_path)


def get_hourly_minutes():
    minutes = []
    for minute in range(0, 60, 5):
        minutes.append(str(minute).zfill(2))
    return minutes


def main(date, start_date, end_date):
    START_DATE_STRING = start_date
    END_DATE_STRING = end_date
    netflow_path = f"{BASE_PATH}NetFlow_log/{date}"
    dump_dir = f"{BASE_PATH}netflow_txt/"
    dump_path = f"{dump_dir}{date}"
    input_dir = f"{BASE_PATH}malicious_IPs_{START_DATE_STRING}_to_{END_DATE_STRING}"
    input_file = os.path.join(input_dir, f"malicious_IPs_{date}.txt")
    # if len(sys.argv) < 2 or len(sys.argv[1]) != 8:
    #    print("Please pass an argument with YYYYMMDD")
    #    sys.exit(1)

    # date = sys.argv[1]
    # year = date[:4]
    # month = date[4:6]
    # day = date[6:8]

    if not os.path.exists(netflow_path):
        print(f"{netflow_path} not found.")
        sys.exit(1)

    if not os.path.exists(dump_dir):
        os.mkdir(dump_dir)

    # remove existing directory
    if os.path.exists(dump_path):
        shutil.rmtree(dump_path)
    os.mkdir(dump_path)

    dump_netflow_logs(netflow_path, dump_path, input_file, date)


if __name__ == "__main__":
    main()
