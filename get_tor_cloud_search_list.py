from utils.DefaultValue import *
from collections import defaultdict
import os
from rules import get_cloud_list


def zero():  # initialize  dictionary
    return 0


# def main(input_folder, out_folder):
def main(ip_dict):
    tor_list = list()
    cloud_list = list()
    search_engine_list = list()

    for ip in ip_dict:
        if "cloud" in ip_dict[ip]:
            cloud_list.append(ip)
        if "tor" in ip_dict[ip]:
            tor_list.append(ip)
        if "search_engine" in ip_dict[ip]:
            search_engine_list.append(ip)

    return tor_list, cloud_list, search_engine_list


if __name__ == "__main__":
    main()
