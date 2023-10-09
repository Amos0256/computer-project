from sortedcontainers import SortedDict

out_dir = f"cluster/"
if not os.path.isdir(out_dir):
    os.makedirs(out_dir)
dict_df_flow = df_flow.to_dict("split")

cluster_dict = {}
for idx, label in enumerate(db_labels):
    if label not in cluster_dict:
        cluster_dict[label] = []
    cluster_dict[label].append(dict_df_flow["data"][idx])

# result_1 = pd.DataFrame([cluster_dict[-1]])
# result_2 = pd.DataFrame([cluster_dict[0]])
index = False

# create output_folder
out_folder = f"{BASE_PATH}same_ip_diff_behavior"
if not os.path.isdir(out_folder):
    os.mkdir(out_folder)


## outer dicr, key is distinct ip
ip_dict = SortedDict()

for i in cluster_dict:  # i is dictionary number
    # malicious_ip = set()
    index = False
    df = pd.DataFrame(
        cluster_dict[i],
        columns=[
            "packets_sent",
            "bytes_sent",
            "packets_recv",
            "bytes_recv",
            "packets_sent_to_target",
            "bytes_sent_to_target",
            "avg_packets_sent_size",
            "packets_recv_from_target",
            "bytes_recv_from_target",
            "avg_packets_recv_size",
            "packets_sent_to_port",
            "bytes_sent_to_port",
            "packets_recv_from_port",
            "bytes_recv_from_port",
            "distinct_to",
            "distinct_ports",
            "n_entries_to_target",
            "distinct_ports_to_target",
            "n_entries_to_port",
            "Src_IP",
            "Dst_IP",
            "Src_Port",
            "Dst_Port",
            "Protocol",
            "Duration",
            "First_Seen",
            "Last_Seen",
            "botnets",
            "exploits",
            "tor",
            "phishing",
            "ransomware",
            "malware",
            "spam",
            "cryptomining",
            "scanner",
        ],
    )
    df.drop(
        [
            "botnets",
            "exploits",
            "tor",
            "phishing",
            "ransomware",
            "malware",
            "spam",
            "cryptomining",
            "scanner",
        ],
        axis=1,
        inplace=True,
    )
    df.to_csv(f"cluster/cluster{i}.csv", encoding="utf-8")

    # build dict for distinct ip
    # print(df[["Src_IP", "First_Seen"]])
    dict_num = i
    # columns_of_interest = ['First_Seen']
    for index, row in df.iterrows():
        ip = row["Src_IP"]
        time = row["First_Seen"]
        # print(row['Src_IP'], row['First_Seen'])
        prefix = ip.split(".")
        prefix = ".".join(prefix[:2])
        if prefix == "140.123":
            continue

        if not ip_dict.__contains__(ip):
            ip_dict[ip] = SortedDict()
            ip_dict[ip].update({time: dict_num})
        else:
            ip_dict[ip].update({time: dict_num})

    # columns_of_interest = ['First_Seen']
    for index, row in df[["Dst_IP", "First_Seen"]].iterrows():
        ip = row["Dst_IP"]
        time = row["First_Seen"]
        prefix = ip.split(".")
        prefix = ".".join(prefix[:2])
        if prefix == "140.123":
            continue

        if not ip_dict.__contains__(ip):
            ip_dict[ip] = SortedDict()
            ip_dict[ip].update({time: dict_num})
        else:
            ip_dict[ip].update({time: dict_num})


# write out
for ip, cluster_dict in ip_dict.items():
    with open(f"{out_folder}/{ip}.txt", "w") as out_file:
        diff_value_map = {}
        for time, cluster_id in cluster_dict.items():
            if cluster_id not in diff_value_map.__contains__(cluster_id):
                diff_value_map[cluster_id] = 1
        if diff_value_map.len() == 1:
            break

        for time, cluster_id in cluster_dict.items():
            print(f"{time}: {cluster_id}", file=out_file)

del ip_dict
