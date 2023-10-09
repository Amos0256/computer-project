def main(ip_dict, malicious_ip):
    no_tag_ip = set()
    # TODO test
    malicious_ip_len = len(malicious_ip)

    # iterate malicious_ip
    for ip in malicious_ip:
        # if ip not in ip_dict, it have no tag.
        if len(ip_dict[ip]) == 0:
            no_tag_ip.add(ip)

    tag_ip_len = malicious_ip_len - len(no_tag_ip)
    return no_tag_ip


if __name__ == "__main__":
    main()
