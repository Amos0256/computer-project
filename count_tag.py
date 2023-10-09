from utils.DefaultValue import *
import os


def check_tag(line, tag):
    return_value = line.find(tag)
    if return_value != -1:
        return 1
    return 0


def main(malicious_ip):
    tag_count = dict()
    tag_count = {
        "botnets": 0,
        "malware": 0,
        "phishing": 0,
        "ip_scanning": 0,
        "port_scanning": 0,
        "spam": 0,
        "cloud": 0,
        "tor": 0,
        "search_engine": 0,
        "cryptomining": 0,
        "exploits": 0,
    }
    directory = f"{BASE_PATH}MALICIOUS_IP_INFO"
    ok_count = 0
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
    for file_name in os.listdir(directory):
        f = os.path.join(directory, file_name)

        # check if it is cloud
        with open(f, "r") as target:
            is_ok = 0
            first_line = target.readline()
            for tag in tag_list:
                return_value = check_tag(first_line, tag)
                if return_value == 1:
                    is_ok = 1
                tag_count[tag] += return_value

            ok_count += is_ok

    # kmalicious_ip = return_malicious_IP_set.main(start_date, end_date)
    malicious_ip_count = len(malicious_ip)
    percentage = round((ok_count / malicious_ip_count) * 100, 2)
    print(f"ip 總數: {malicious_ip_count}")
    print(f"有 tag 的 ip: {ok_count} ({percentage}%)")
    # print('===============')
    # for key, value in tag_count.items():
    #    percentage = round((value/malicious_ip_count)*100, 2)
    #    print(f'{key}: {value} ({percentage}%)')

    return tag_count


if __name__ == "__main__":
    main()
