from utils.DefaultValue import *
import os
from pathlib import Path
import pandas as pd
from tqdm import tqdm
from collections import defaultdict


def find_line(file_path, target_line):
    with open(file_path, "r") as file:
        for line in file:
            if target_line in line:
                value = line.split(": ")[1]  # get string after ': '
                value = value.replace("\n", "")
                return value
    return None  # Line not found


def main():
    # Load data
    df_flow1 = pd.read_pickle("../dataframe/tag_20230101_20230131.pkl")
    df_flow2 = pd.read_pickle("../dataframe/tag_20230201_20230228.pkl")
    df_flow = pd.concat([df_flow1, df_flow2])

    # Calculate different IP
    tos_dict = defaultdict(set)
    isp_dict = defaultdict(set)

    in_folder = f"{BASE_PATH}MALICIOUS_IP_INFO/"
    for _, row in tqdm(df_flow.iterrows(), total=len(df_flow), desc="Processing data"):
        ip = row["Src_IP"]
        tos = row["STos"]
        prefix = ".".join(ip.split(".")[:2])
        if prefix == "140.123":
            continue

        # TODO: get asn_reg, asn_num
        in_file = f"{in_folder}{ip}.txt"
        asn_desc = find_line(in_file, "asn_desc")

        tos_dict[tos].add(f"{asn_desc}")
        isp_dict[asn_desc].add(tos)

    # output
    out_folder = f"{BASE_PATH}TOS_ISP/"
    Path(out_folder).mkdir(exist_ok=True)

    for tos, asn_set in tqdm(tos_dict.items(), desc="Outputting tos...", unit="IP"):
        out_file = f"{out_folder}tos_{tos}.txt"
        with open(out_file, "w") as out:
            sorted_set = sorted(asn_set)
            print(f"isp count: {len(sorted_set)}\n", file=out)
            for asn in sorted_set:
                print(f"{asn}: ", file=out, end="")
                sorted_isp_dict = sorted(isp_dict[asn])
                for tos_value in sorted_isp_dict:
                    print(f"{tos_value} ", file=out, end="")
                print("", file=out)


if __name__ == "__main__":
    main()
