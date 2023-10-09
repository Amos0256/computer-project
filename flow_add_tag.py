import os
import sys
import logging
import argparse
import multiprocessing
from datetime import datetime, timedelta
import pandas as pd

from utils.DefaultValue import *
from utils.Plot import plot_upset
from utils import Generator, NetFlow, CTI


def main(args):
    """
    process month by month. -> can only handle one month at a time
    main function to execute
    """
    logging.basicConfig(format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT, level=args.verbose)
    logging.debug(args)

    start_date = datetime.strptime(args.start_date, "%Y%m%d")
    end_date = datetime.strptime(args.end_date, "%Y%m%d") + timedelta(days=1)

    if not os.path.exists(BASE_PATH):
        logging.warning("'%s' not found!", BASE_PATH)
        sys.exit(1)

    tags = CTI.get_report(f"{args.start_date}_{args.end_date}")

    df_tags = pd.DataFrame.from_dict(tags).T.drop("severity", axis=1)

    logging.debug("Save an UpSet plot of IP addresses.")
    plot_upset(
        MALICIOUS_TAG,
        df_tags,
        f"upset_ip_{start_date.strftime('%Y%m')}.png",
    )

    file_path_list = Generator.graph_feature_path(start_date, end_date)

    with multiprocessing.Pool(processes=args.core) as pool:
        pool_result = pool.starmap(NetFlow.get_feature, zip(file_path_list))

    df_flow = pd.concat([i for i in pool_result], join="outer")
    df_flow.reset_index(inplace=True)
    df_flow.drop("index", axis=1, inplace=True)

    for ip, tag in tags.items():
        df = df_flow[df_flow.Src_IP == ip]
        for tag_name in MALICIOUS_TAG:
            df_flow.loc[df.index, tag_name] = tag[tag_name]

        df = df_flow[df_flow.Dst_IP == ip]
        for tag_name in MALICIOUS_TAG:
            df_flow.loc[df.index, tag_name] = tag[tag_name]

    logging.debug("Save an UpSet plot of NetFlow.")
    plot_upset(
        MALICIOUS_TAG,
        df_flow,
        f"upset_flow_{start_date.strftime('%Y%m')}.png",
    )

    # Save dataframe as pickle object
    dataframe_path = f"{BASE_PATH}{DATAFRAME_PATH}/"
    if not os.path.exists(dataframe_path):
        os.mkdir(dataframe_path)

    save_path = f"{BASE_PATH}{DATAFRAME_PATH}/tag_{args.start_date}_{args.end_date}"
    df_flow.to_pickle(f"{save_path}.pkl")

    with open(save_path + ".log", mode="w", encoding="utf-8") as f:
        f.write(f"Start date: {start_date.strftime('%Y-%m-%d')}\r\n")
        f.write(f"End date: {(end_date - timedelta(days=1)).strftime('%Y-%m-%d')}\r\n")
        f.write(f"Number of samples: {df_flow.shape[0]}\r\n")
        f.write("Description: Malicious flow without the impact of benign flow.\r\n")
        f.write("Number of NaN:\r\n")
        f.write("----------------------------------\r\n")
        f.write(f"{df_flow.isna().sum()}\r\n")
        f.write("----------------------------------\r\n")
        # f.write(f":{}\r\n")

    logging.info("%s.pkl", save_path)
    logging.info("%s.log", save_path)


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
