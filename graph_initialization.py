import os
import re
import sys
import shutil
import logging
import argparse
import multiprocessing
from datetime import datetime, timedelta
from itertools import repeat

from utils.DefaultValue import *
from utils import Generator, Graph, CTI


def main(args):
    """
    process day by day
    main function to execute
    """
    logging.basicConfig(format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT, level=args.verbose)
    logging.debug("ArgumentParser: %s", args)

    start_date = datetime.strptime(args.start_date, "%Y%m%d")
    end_date = datetime.strptime(args.end_date, "%Y%m%d") + timedelta(days=1)
    # print("start: ", start_date)
    # print("end: ", end_date)
    if not os.path.exists(BASE_PATH):
        logging.warning("'%s' not found!", BASE_PATH)
        sys.exit(1)

    if not os.path.exists(f"{BASE_PATH}{GRAPH_INITIAL_PATH}"):
        logging.info("Create directory '%s'", BASE_PATH + GRAPH_INITIAL_PATH)
        os.makedirs(f"{BASE_PATH}{GRAPH_INITIAL_PATH}")

    date_time_all = Generator.date_string_range(start_date, end_date)
    netflow_path_all = Generator.netflow_log_path(start_date, end_date)
    initial_path_all = Generator.graph_initial_path(start_date, end_date)
    # print(initial_path_all)

    for date in date_time_all:
        date_path = f"{BASE_PATH}{GRAPH_INITIAL_PATH}{date}"
        if not os.path.exists(date_path):
            os.makedirs(date_path)
            logging.info("Create directory '%s'", date_path)

    malicious_ip = set()
    for date in Generator.date_range(start_date, end_date):
        file_path = (
            f"{BASE_PATH}{CTI_LOG_PATH}"
            f'140.123.103.62_{datetime.strftime(date,"%Y-%m-%d")}.log'
        )
        malicious_ip.update(CTI.get_log_ip(file_path))

    with multiprocessing.Pool(processes=args.core) as pool:
        # Only pick up the malicious flow labeled by CTI.
        pool_result = pool.starmap(
            Graph.create_graph,
            # TODO 改netflow_path_all成read all file
            zip(netflow_path_all, initial_path_all, repeat(malicious_ip)),
        )
        # result = pool.starmap(
        #     Graph.create_graph,
        #     zip(netflow_path_all, initial_path_all)
        # )

    logging.debug("length: %s", len(pool_result))
    logging.debug(pool_result)
    logging.info("Create graph finished.")
    logging.info("%s task(s) successful.", pool_result.count(True))
    logging.info("%s task(s) failed.", pool_result.count(False))

    if pool_result.count(False) == 0 and args.delete_csv:
        logging.info("Delete NetFlow csv file...")
        pattern = args.start_date[:6] + "*"
        ls = os.listdir(f"{BASE_PATH}{NETFLOW_CSV_PATH}")
        for d in ls:
            if re.search(pattern, d):
                shutil.rmtree(f"{BASE_PATH}{NETFLOW_CSV_PATH}{d}")


if __name__ == "__main__":
    os.chdir(os.path.dirname(__file__))

    parser = argparse.ArgumentParser()
    parser.add_argument("start_date", type=str, help="YYYYMMDD")
    parser.add_argument("end_date", type=str, help="YYYYMMDD")
    parser.add_argument(
        "--core", type=int, help="Number of cores used for multi-processing"
    )
    parser.add_argument(
        "-d",
        action="store_true",
        help="Delete NetFlow csv file after graph generation",
        dest="delete_csv",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_const",
        const=logging.DEBUG,
        help="Print more info for debug",
        dest="verbose",
    )

    main(parser.parse_args())
