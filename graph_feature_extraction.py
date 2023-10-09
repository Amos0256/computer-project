import os
import sys
import logging
import argparse
import multiprocessing
from datetime import datetime, timedelta

from utils.DefaultValue import *
from utils import Generator, Graph


def main(args):
    """
    process day by day
    main function to execute
    """
    logging.basicConfig(format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT, level=args.verbose)
    logging.debug("ArgumentParser: %s", args)

    start_date = datetime.strptime(args.start_date, "%Y%m%d")
    end_date = datetime.strptime(args.end_date, "%Y%m%d") + timedelta(days=1)

    if not os.path.exists(BASE_PATH):
        logging.warning("'%s' not found!", BASE_PATH)
        sys.exit(1)

    if not os.path.exists(f"{BASE_PATH}{GRAPH_FEATURE_PATH}"):
        logging.info("Create directory '%s'", BASE_PATH + GRAPH_FEATURE_PATH)
        os.makedirs(f"{BASE_PATH}{GRAPH_FEATURE_PATH}")

    date_time_all = Generator.date_string_range(start_date, end_date)
    initial_path_all = Generator.graph_initial_path(start_date, end_date)
    feature_path_all = Generator.graph_feature_path(start_date, end_date)

    for date in date_time_all:
        date_path = f"{BASE_PATH}{GRAPH_FEATURE_PATH}{date}"
        if not os.path.exists(date_path):
            os.makedirs(date_path)
            logging.info("Create directory '%s'", date_path)

    with multiprocessing.Pool(processes=args.core) as pool:
        pool_result = pool.starmap(
            Graph.feature_extract, zip(initial_path_all, feature_path_all)
        )

    logging.debug("length: %s", len(pool_result))
    logging.debug(pool_result)
    logging.info("Create graph finished.")
    logging.info("%s task(s) successful.", pool_result.count(True))
    logging.info("%s task(s) failed.", pool_result.count(False))


if __name__ == "__main__":
    os.chdir(os.path.dirname(__file__))

    parser = argparse.ArgumentParser()
    parser.add_argument("start_date", type=str, help="YYYYMMDD")
    parser.add_argument("end_date", type=str, help="YYYYMMDD")
    parser.add_argument("--core", type=int, help="The cores used for multi-processing")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_const",
        const=logging.DEBUG,
        help="Print more info for debug",
        dest="verbose",
    )

    main(parser.parse_args())
