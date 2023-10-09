#!/usr/bin/env python3
import os
import sys
import subprocess
import datetime
import time
import dump_netflow_to_txt
import shutil
from utils.DefaultValue import *
from multiprocessing import Pool
import get_malicious_IP
from utils import Generator, CTI
from itertools import repeat


# Usage: Pass an argument as YYYYMM
# Example: python3 dump_netflow_month_by_day_loop.py 202212
# Dump the NetFlow logs of each day in December to csv.
# Requires dump_netflow_month_by_day.py in the same directory.


def dump_netflow(args):
    # cmd = ["python3", "./dump_netflow_month_by_day.py", date]
    # subprocess.run(cmd, check=True)
    date, start, end = args
    print(f"date: {date}")
    dump_netflow_to_txt.main(date, start, end)


def main(start, end):
    START_DATE_STRING = start
    END_DATE_STRING = end

    input_dir = f"{BASE_PATH}malicious_IPs_{START_DATE_STRING}_to_{END_DATE_STRING}"
    # remove existing directory
    if os.path.exists(input_dir):
        shutil.rmtree(input_dir)
    get_malicious_IP.main(START_DATE_STRING, END_DATE_STRING)

    PROCESS_NUMBER = 20

    # if len(sys.argv) < 3 or len(sys.argv[1]) != 6:
    #    print("Please pass an argument with YYYYMMDD YYYYMMDD")
    #    sys.exit(1)

    # yyyymm = sys.argv[1]
    # year = yyyymm[:4]
    # month = yyyymm[4:6]

    start_date = datetime.datetime.strptime(START_DATE_STRING, "%Y%m%d")
    end_date = datetime.datetime.strptime(
        END_DATE_STRING, "%Y%m%d"
    ) + datetime.timedelta(days=1)
    dates = [
        datetime.datetime.strftime(i, "%Y%m%d")
        for i in Generator.date_range(start_date, end_date)
    ]

    print(f"Ready to dump NetFlow log...")
    # parallel processing

    start_time = time.time()
    with Pool(
        processes=PROCESS_NUMBER
    ) as pool:  # specify the number of worker processes here
        args = zip(dates, repeat(start), repeat(end))
        pool.map(dump_netflow, args)

    spend_time = int(time.time() - start_time)
    print(f"Dump netflow finished. Spend {spend_time} second(s)")


if __name__ == "__main__":
    start = "20230428"
    end = "20230430"
    main(start, end)
