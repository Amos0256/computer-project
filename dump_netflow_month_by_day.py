#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import shutil
from concurrent.futures import ThreadPoolExecutor

# from multiprocessing import Queue
from utils.DefaultValue import *
from pathlib import Path

# Usage: Pass an argument as YYYYMMDD
# Example: python3 dump_netflow_month_by_day.py 20221201
# Dump the NetFlow logs of each hour in 20221201 to csv.


def dump_netflow_logs(netflow_path, dump_path, input_file, date):
    fmt = "fmt:%ts,%te,%td,%pr,%sa,%sp,%da,%dp,%flg,%pkt,%byt,%stos"

    # print(f"date: {date}")
    with open(input_file) as f:
        for ip in f:
            ip = ip.strip()
            for hour in range(0, 24):
                for minute in get_hourly_minutes():
                    minute_str = minute.zfill(2)
                    out_path = (
                        f"{dump_path}/dump_{date}{str(hour).zfill(2)}{minute_str}.csv"
                    )
                    in_path = (
                        f"{netflow_path}/nfcapd.{date}{str(hour).zfill(2)}{minute_str}"
                    )

                    if not os.path.isfile(in_path):
                        continue

                    command = [
                        "nfdump",
                        "-r",
                        f"{in_path}",
                        f"src or dst ip {ip}",
                        "-N",
                        "-q",
                        "-o",
                        fmt,
                    ]
                    # subprocess.run(command, check=True)
                    with open(out_path, "a") as out:
                        subprocess.run(command, stdout=out, check=True)
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

    # TODO change
    # no_tag_dump_dir = f"{BASE_PATH}FOR_NO_TAG/netflow_csv/"
    # no_tag_dump_path = f"{BASE_PATH}FOR_NO_TAG/netflow_csv/{date}"
    # Path(no_tag_dump_dir).mkdir(exist_ok=True)
    # TODO change end
    dump_dir = f"{BASE_PATH}netflow_csv/"
    dump_path = f"{dump_dir}{date}"
    input_dir = f"{BASE_PATH}malicious_IPs_{START_DATE_STRING}_to_{END_DATE_STRING}"

    # TODO change
    # no_tag_input_file = f'{BASE_PATH}FOR_NO_TAG/NO_TAG_IPs.txt'
    # TODO change end
    input_file = os.path.join(input_dir, f"malicious_IPs_{date}.txt")

    if not os.path.exists(netflow_path):
        print(f"{netflow_path} not found.")
        sys.exit(1)

    if not os.path.exists(dump_dir):
        os.mkdir(dump_dir)

    # remove existing directory
    if os.path.exists(dump_path):
        shutil.rmtree(dump_path)
    os.mkdir(dump_path)

    # TODO change

    ## remove existing directory
    # if os.path.exists(no_tag_dump_path):
    #    shutil.rmtree(no_tag_dump_path)
    # os.mkdir(no_tag_dump_path)
    # TODO change end

    # TODO change
    # dump_netflow_logs(netflow_path, no_tag_dump_path, no_tag_input_file, date)
    # TODO change end
    dump_netflow_logs(netflow_path, dump_path, input_file, date)


if __name__ == "__main__":
    main()
