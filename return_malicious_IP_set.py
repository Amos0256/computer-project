import os
import datetime
from tqdm import tqdm
from utils.DefaultValue import *
from utils import Generator, CTI


def main(start_date_string, end_date_string):
    START_DATE_STRING = start_date_string
    END_DATE_STRING = end_date_string

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

        malicious_IP_from_CTI.update(CTI.get_log_ip(file_path))  # original
        # print(f'miliciout_IPs_{datetime.datetime.strftime(date, "%m%d")}')

    # print(f'Find {len(malicious_IP_from_CTI)} malicious IPs.')
    # print(malicious_IP_from_CTI)
    print("Done getting malicious IPs")

    return malicious_IP_from_CTI


if __name__ == "__main__":
    main()
