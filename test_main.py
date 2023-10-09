import os
from pathlib import Path
from tqdm import tqdm
from collections import defaultdict
import multiprocessing
from multiprocessing import Process
import glob
import pandas as pd
from itertools import repeat
import shutil
import time
import subprocess

from utils.DefaultValue import *

from pyecharts import options as opts
from pyecharts.charts import Pie

from rules import (
    ip_scanning,
    port_scanning,
    get_tor_list,
    get_cloud_list,
    get_search_engine_list,
    botnet,
    malware,
    phishing,
    spam,
    mining,
    exploit,
)
import return_malicious_IP_set, my_whois, get_no_tag_ip, group_ip_by_prefix_with_tag, count_tag, group_ip_by_tag, DHCP_Detection

from plot import (
    count_cloud_occur,
    show_tag_count,
    plot_ip_by_tag,
    count_tag_flow_size,
    whois_total_flow_analysis,
    count_tag_flow_count,
    show_school_exploit_count,
    show_school_exploit_size,
    show_match_rate,
)

from side_func import get_total_flow_of_ip, count_total_flow_of_ip

month_list = [
    ("01", "31"),
    ("02", "28"),
    ("03", "31"),
    ("04", "30"),
    ("05", "31"),
    ("06", "30"),
    ("07", "31"),
    ("08", "31"),
    ("09", "30"),
    ("10", "31"),
    ("11", "30"),
    ("12", "31"),
]

tag_list = [
    "botnets",
    "malware",
    "phishing",
    "ip_scanning",
    "port_scanning",
    "spam",
    "cloud",
    "tor",
    "search_engine",
    "cryptomining",
    "exploits",
]

# get cloud list
cloud_list = get_cloud_list.main()
search_engine_list = get_search_engine_list.main()


def process_ip(ip_and_args):
    ip = ip_and_args[0]
    ip_dict = ip_and_args[1]

    # ---------------------------------------------------
    # ///////////////FOLDER SETTING//////////////////////
    # ---------------------------------------------------
    # set up output
    out_folder = f"{BASE_PATH}MALICIOUS_IP_INFO/"
    # remove if exist
    #     if os.path.exists(out_folder):
    #         shutil.rmtree(out_folder)
    # create folder
    Path(out_folder).mkdir(exist_ok=True)
    # ///////////////////////////////////////////

    whois_result = my_whois.whois(ip)
    out_file = f"{out_folder}{ip}.txt"
    # check cloud
    for key, value in whois_result.items():
        # string compare
        ## compare every cloud name with whois value
        return_value = -1
        for name in cloud_list:
            return_value = str(value).lower().find(name)
            if return_value != -1:
                ip_dict[ip].append("cloud")
                break
        if return_value != -1:
            break

    # check search engine
    for key, value in whois_result.items():
        # string compare
        ## compare every cloud name with whois value
        return_value = -1
        for name in search_engine_list:
            return_value = str(value).lower().find(name)
            if return_value != -1:
                ip_dict[ip].append("search_engine")
                break
        if return_value != -1:
            break

    with open(out_file, "w") as out:
        print(f"tag: {ip_dict[ip]}\n", file=out)

        print("WHOIS result:", file=out)
        for key, value in whois_result.items():
            print(f"\t{key}: {value}", file=out)


def check_tag(line, tag):
    return_value = line.find(tag)
    if return_value != -1:
        return 1
    return 0


def execute_and_print(function_and_args):
    # extract func and args
    func = function_and_args[0]
    df_flow = function_and_args[1]

    if len(function_and_args) == 3:
        malicious_ip = function_and_args[2]
        func(df_flow, malicious_ip)
    else:
        func(df_flow)

    # Call the function

    # func(df_flow)
    # Print an empty line after each function is executed
    print()


def plot_analysis_result(ip_dict, tag_list, tag_count, malicious_ip, df_flow):
    # ---------------------------------------------------
    # ///////////////FOLDER SETTING//////////////////////
    # ---------------------------------------------------
    input_folder = f"{BASE_PATH}MALICIOUS_IP_INFO"
    # create folder for picture output
    picture_out_folder = f"{BASE_PATH}picture_output"
    if os.path.exists(picture_out_folder):
        shutil.rmtree(picture_out_folder)
    # create folder
    Path(picture_out_folder).mkdir(exist_ok=True)
    # ///////////////////////////////////////////

    # ---------------------------------------------------
    # ////////////START PROCESS PLOTTING/////////////////
    # ---------------------------------------------------

    # name_list, count_list = count_cloud_occur.main(input_folder)  # cloud_count is a list [(,), (,), ...]
    print("Output cloud_count.png...", end="")
    count_cloud_occur.main(
        input_folder, picture_out_folder
    )  # cloud_count is a list [(,), (,), ...]
    print("\t done!")

    # plot each tags combination correspond to total number of IPs
    print("Output ip_by_tag.png...", end="")
    plot_ip_by_tag.main(ip_dict, tag_list, picture_out_folder)
    print("\t done!")

    # show tag_count firgure
    # count each tag number
    malicious_ip_len = len(malicious_ip)
    print("Output tag_count.png...", end="")
    show_tag_count.main(tag_count, malicious_ip_len, picture_out_folder)
    print("\t done!")

    # SHOW EACHO WHOIS GROUP FLOW SIZE
    # print("Output ")
    ip_total_flow_size, ip_total_flow_count = whois_total_flow_analysis.main(
        input_folder, picture_out_folder, df_flow, ip_dict
    )

    # get flow_size and flow_count
    flow_size, flow_count = get_total_flow_of_ip.main(df_flow, malicious_ip)
    # SHOW EACH TAG SIZE
    print("Output tag_total_size.png...", end="")
    count_tag_flow_size.main(tag_list, ip_dict, flow_size, picture_out_folder)
    print("\t done!")

    # SHOW EACH TAG number
    print("Output tag_total_count.png...", end="")
    count_tag_flow_count.main(tag_list, ip_dict, flow_count, picture_out_folder)
    print("\t done!")

    # SHOW SCHOOL EXPLOIT
    print("Output school_ip_exploit_count.png...", end="")
    show_school_exploit_count.main(picture_out_folder)
    print("\t done!")

    # SHOW SCHOOL EXPLOIT
    print("Output school_ip_exploit_size.png...", end="")
    show_school_exploit_size.main(picture_out_folder)
    print("\t done!")

    # MATCH RATE BETWEEN CTI TAGS AND OUR TAGS
    print("Calculate matching rate...", end="")
    show_match_rate.main(df_flow, ip_dict, malicious_ip, picture_out_folder)
    print("\t done!")
    # ////////////////////////////////////////


def main():
    # set date
    start_date = "20230101"
    end_date = "20230609"
    ip_dict = defaultdict(list)

    # count month included
    start_month = int(start_date[4:6])
    end_month = int(end_date[4:6])
    month_cnt = end_month - start_month
    process_month = list()
    for month in range(start_month, start_month + month_cnt + 1):
        process_month.append(month_list[month - 1])

    # ---------------------------------------------------
    # ////////////INITIAL LOAD FLOW'S DATAFRAME///////////////
    # ---------------------------------------------------

    dataframe_path = f"{BASE_PATH}/dataframe"
    df_flow = pd.read_pickle(
        f"{dataframe_path}/tag_2023{process_month[0][0]}01_2023{process_month[0][0]}{process_month[0][1]}.pkl"
    )
    del process_month[0]
    for month in process_month:
        temp_flow = pd.read_pickle(
            f"{dataframe_path}/tag_2023{month[0]}01_2023{month[0]}{month[1]}.pkl"
        )
        df_flow = pd.concat([df_flow, temp_flow])

    # ///////////////////////////////////////////////////

    # ---------------------------------------------------
    # ////////////PROCESS MALICIOUS INFO/////////////////
    # ---------------------------------------------------

    malicious_ip = return_malicious_IP_set.main(
        start_date, end_date
    )  # the return value is a set of malicious IP
    functions_to_execute = [
        ip_scanning.main,
        port_scanning.main,
        botnet.main,
        malware.main,
        mining.main,
        phishing.main,
        spam.main,
        exploit.main,
    ]
    function_and_args = [(func, df_flow) for func in functions_to_execute]
    # add this to execution list
    function_and_args.append((count_total_flow_of_ip.main, df_flow, malicious_ip))
    with multiprocessing.Pool() as pool:
        # Use tqdm to show progress bar during parallel execution
        list(
            tqdm(
                pool.imap(execute_and_print, function_and_args),
                total=len(functions_to_execute),
                desc="Running ",
            )
        )
    input_folder = f"{BASE_PATH}SCANNING_CLUSTER/"

    # print a new line
    print()

    # get tag
    input_folder = f"{BASE_PATH}"
    tor_list = get_tor_list.main()
    for ip in malicious_ip:
        ip_dict[ip] = []
        is_port_scanning = f"{input_folder}SCANNING_CLUSTER/PORT_SCANNING/{ip}.txt"
        is_ip_scanning = f"{input_folder}SCANNING_CLUSTER/IP_SCANNING/{ip}.txt"
        is_botnet = f"{input_folder}BOTNET/{ip}.txt"
        is_crypto_mining = f"{input_folder}CRYPTO_MINING/{ip}.txt"
        is_malware = f"{input_folder}MALWARE/{ip}.txt"
        is_phishing = f"{input_folder}PHISHING/{ip}.txt"
        is_spam = f"{input_folder}SPAM/{ip}.txt"
        is_exploit = f"{input_folder}EXPLOIT/{ip}.txt"
        if os.path.exists(is_port_scanning):
            ip_dict[ip].append("port_scanning")
        if os.path.exists(is_ip_scanning):
            ip_dict[ip].append("ip_scanning")
        if ip in tor_list:
            ip_dict[ip].append("tor")
        if os.path.exists(is_botnet):
            ip_dict[ip].append("botnets")
        if os.path.exists(is_crypto_mining):
            ip_dict[ip].append("cryptomining")
        if os.path.exists(is_malware):
            ip_dict[ip].append("malware")
        if os.path.exists(is_phishing):
            ip_dict[ip].append("phishing")
        if os.path.exists(is_spam):
            ip_dict[ip].append("spam")
        if os.path.exists(is_exploit):
            ip_dict[ip].append("exploits")

    # Parallel processing
    ip_and_args = [(ip, ip_dict) for ip in malicious_ip]
    with multiprocessing.Pool() as pool:
        list(
            tqdm(
                pool.imap(process_ip, ip_and_args),
                total=len(malicious_ip),
                desc="Getting WHOIS result and outputting...",
            )
        )

    # append tag 'cloud', 'search_engine' to ip_dict
    in_folder = f"{BASE_PATH}MALICIOUS_IP_INFO"
    for ip in malicious_ip:
        ## cloud
        in_file = f"{in_folder}/{ip}.txt"
        check_list = ["cloud", "search_engine"]
        with open(in_file, "r") as f:
            first_line = f.readline()
            for tag in check_list:
                if check_tag(first_line, tag) == 1:
                    ip_dict[ip].append(tag)

    # ///////////////////////////////////////////////////
    # GET MALICIOUS INFO, END

    # ---------------------------------------------------
    # ///////////// RESULT ANALYSIS /////////////////////
    # ---------------------------------------------------

    # COUNT TAG
    tag_count = count_tag.main(malicious_ip)
    # /////////

    # GET IP WITHOUT TAG
    no_tag_ip = get_no_tag_ip.main(ip_dict, malicious_ip)
    no_tag_ip_len = len(no_tag_ip)
    ## set up output folder
    no_tag_ip_out_folder = f"{BASE_PATH}NO_TAG_IP/"
    ### remove if exist
    if os.path.exists(no_tag_ip_out_folder):
        shutil.rmtree(no_tag_ip_out_folder)
    ### create folder
    Path(no_tag_ip_out_folder).mkdir(exist_ok=True)
    ## output no_tag_ip
    netflow_txt_path = f"{BASE_PATH}netflow_txt/"
    # TODO change
    no_tag_dir = f"{BASE_PATH}FOR_NO_TAG"
    no_tag_file = f"{no_tag_dir}/NO_TAG_IPs.txt"
    Path(no_tag_dir).mkdir(exist_ok=True)
    # TODO change end
    ###output all no_tag_ip to a file
    print("Outing flow of no tag ip...", end="")
    with open(no_tag_file, "w") as no_tag_out:
        for ip in tqdm(
            no_tag_ip, total=len(no_tag_ip), desc="Find out all the no tag ip..."
        ):
            print(ip, file=no_tag_out)
            no_tag_ip_out_file = f"{no_tag_ip_out_folder}{ip}.txt"
            # command = [
            #    "find",
            #    f"{netflow_txt_path}",
            #    "-iname",
            #    f"\"*{ip}*\"",
            #    "-exec cat {}",
            #    "\\;",
            #    "-exec",
            #    "echo",
            #    "\\;"
            # ]
            with open(no_tag_ip_out_file, "w") as out:
                # subprocess.run(command, stdout=out, check=True)
                print("hello", file=out)
            os.system(
                f'find {netflow_txt_path} -iname "*{ip}*" -exec cat {{}} \\; -exec echo \\; > {no_tag_ip_out_file}'
            )
    print("done!")
    # /////////////////
    # GET IP WITHOUT TAG, END

    print("Group ip by tag...", end="")
    group_ip_by_tag.main(ip_dict, tag_list)
    print("\t done!")
    # ///////////////

    DHCP_Detection.main(ip_dict, malicious_ip)
    # /////////////////////
    # RESULT ANALYSIS, END

    # change
    group_ip_by_prefix_with_tag.main(ip_dict, malicious_ip)

    # ---------------------------------------------------
    # ////////////////// PLOTTING ///////////////////////
    # ---------------------------------------------------

    plot_analysis_result(ip_dict, tag_list, tag_count, malicious_ip, df_flow)

    # ////////////////////////////////////////


if __name__ == "__main__":
    main()
