import os
import datetime
from tqdm import tqdm
from utils.DefaultValue import *
from utils import Generator, CTI


def main(start_date, end_date):
    START_DATE_STRING = start_date
    END_DATE_STRING = end_date
    out_dir = f"{BASE_PATH}malicious_IPs_{START_DATE_STRING}_to_{END_DATE_STRING}/"
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    out_path = f"{out_dir}/"

    start_date = datetime.datetime.strptime(START_DATE_STRING, "%Y%m%d")
    end_date = datetime.datetime.strptime(
        END_DATE_STRING, "%Y%m%d"
    ) + datetime.timedelta(days=1)

    malicious_IP_from_CTI = set()
    print("Getting malicious IPs...")
    for date in Generator.date_range(start_date, end_date):
        file_path = (
            f"{BASE_PATH}{THREATWALL_LOG_PATH}"
            f'140.123.103.62_{datetime.datetime.strftime(date,"%Y-%m-%d")}.log'
        )
        if os.path.isfile(file_path):
            print(file_path)

        date_string = datetime.datetime.strftime(date, "%Y%m%d")
        out_file_name = f"{out_path}malicious_IPs_{date_string}.txt"
        with open(out_file_name, "w") as out:
            for i in CTI.get_log_ip(file_path):
                print(i, file=out)

        # malicious_IP_from_CTI.update(CTI.get_log_IP(file_path)) #original
        # print(f'miliciout_IPs_{datetime.datetime.strftime(date, "%m%d")}')

    # print(f'Find {len(malicious_IP_from_CTI)} malicious IPs.')
    # print(malicious_IP_from_CTI)
    print("Done getting malicious ip!")


if __name__ == "__main__":
    main()
