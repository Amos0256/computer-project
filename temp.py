#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import shutil
from concurrent.futures import ThreadPoolExecutor

# from multiprocessing import Queue
from utils.DefaultValue import *
import get_malicious_IP

# Usage: Pass an argument as YYYYMMDD
# Example: python3 dump_netflow_month_by_day.py 20221201
# Dump the NetFlow logs of each hour in 20221201 to csv.

START_DATE_STRING = "20230101"
END_DATE_STRING = "20230228"

netflow_path = f"{BASE_PATH}NetFlow_log/{year}{month}{day}"
dump_dir = f"{BASE_PATH}netflow_csv3/"
dump_path = f"{dump_dir}{year}{month}{day}"
input_dir = (
    input_dir
) = f"{BASE_PATH}malicious_IPs_{START_DATE_STRING}_to_{END_DATE_STRING}"


def dump_netflow_logs(date):
    fmt = "fmt:%ts,%te,%td,%pr,%sa,%sp,%da,%dp,%flg,%pkt,%byt,%stos"

    input_file = os.path.join(input_dir, f"malicious_IPs_{date}.txt")

    print(f"date: {date}")
    with open(input_file) as f:
        for ip in f:
            ip = ip.strip()
            for hour in range(0, 24):
                for minute in get_hourly_minutes():
                    minute_str = minute.zfill(2)
                    file_path = (
                        f"{dump_path}/dump_{date}{str(hour).zfill(2)}{minute_str}.csv"
                    )
                    command = [
                        "nfdump",
                        "-M",
                        netflow_path,
                        "-R",
                        f"nfcapd.{date}{str(hour).zfill(2)}{minute_str}",
                        f"src or dst ip {ip}",
                        "-N",
                        "-q",
                        "-o",
                        fmt,
                        ">",
                        file_path,
                    ]
                    subprocess.run(command, shell=True)


def get_hourly_minutes():
    minutes = []
    for minute in range(0, 60, 5):
        minutes.append(str(minute).zfill(2))
    return minutes


def main(date):
    if len(sys.argv) < 2 or len(sys.argv[1]) != 8:
        print("Please pass an argument with YYYYMMDD")
        sys.exit(1)

    # date = sys.argv[1]
    # year = date[:4]
    # month = date[4:6]
    # day = date[6:8]
    thread_count = 12

    if not os.path.exists(netflow_path):
        print(f"{netflow_path} not found.")
        sys.exit(1)

    if not os.path.exists(dump_dir):
        os.mkdir(dump_dir)

    # remove existing directory
    if os.path.exists(dump_path):
        shutil.rmtree(dump_path)
    os.mkdir(dump_path)

    # remove existing directory
    if os.path.exists(input_dir):
        shutil.rmtree(input_dir)
    get_malicious_IP.main()

    wait_time = 3
    print(f"Going to dump NetFlow log to {dump_dir} in {wait_time} seconds...")
    time.sleep(wait_time)

    start_time = time.time()

    dump_netflow_logs(date)

    spend_time = int(time.time() - start_time)
    print(f"'{dump_path}' finished. Spend {spend_time} second(s)")


if __name__ == "__main__":
    main()
