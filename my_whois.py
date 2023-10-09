from ipwhois import IPWhois


def whois(malicious_ip) -> set:
    ip = malicious_ip
    obj = IPWhois(ip)
    res = obj.lookup_whois()
    # print(res)
    # print(res['nets'][0]['name'])
    # read whois result
    # ans registry, ans, nets name, nets description
    # asn_reg = res['asn_registry']
    # asn_num = res['asn']
    net_name = ""
    net_desc = ""
    asn_desc = res["asn_description"]

    if res["nets"]:
        net_name = res["nets"][0]["name"]

    if res["nets"]:
        net_desc = res["nets"][0]["description"]

    # whois output
    # whois_out = {'asn_reg': asn_reg, 'asn_num': asn_num, 'asn_desc': asn_desc, 'net_name': net_name, 'net_desc': net_desc}
    whois_out = {"asn_desc": asn_desc, "net_name": net_name, "net_desc": net_desc}
    whois_out2 = res
    return whois_out


def main():
    res = whois("1.179.185.50")
    print(res)
    # for key, value in res.items():
    #    print(key + ":" + value)


if __name__ == "__main__":
    main()
