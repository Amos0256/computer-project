#!/usr/bin/env python
# coding: utf-8

# - DBSCAN、HDBSCAN等方法將資料分群
# - 觀察分群參數及結果
# - 進一步的資料標記

# In[1]:


import gc
import os
import sys
import datetime
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

import joblib
from sklearn.metrics import euclidean_distances
from sklearn.cluster import DBSCAN
from sklearn.manifold import TSNE
import hdbscan
from sortedcontainers import SortedDict

from upsetplot import UpSet, from_indicators

from utils.DefaultValue import *

pd.set_option("display.max_columns", None)


# ## Load Data

# ### Load from Pickle Object

# In[2]:


df_flow1 = pd.read_pickle("../dataframe/tag_20230101_20230131.pkl")
df_flow2 = pd.read_pickle("../dataframe/tag_20230201_20230228.pkl")
df_flow = pd.concat([df_flow1, df_flow2])

df_flow


# In[3]:


for tag in MALICIOUS_TAG:
    print(tag, df_flow[tag].sum())


# ### Sample

# In[4]:


# tag_name = 'exploits'

# df_flow = df_flow[df_flow[tag_name] == 1].dropna()

if df_flow.shape[0] > 70000:
    df_flow = df_flow.sample(70000, random_state=42)
else:
    df_flow = df_flow

df_flow


# ## DBSCAN

# ### DBSCAN Setting

# In[5]:


db = DBSCAN(
    eps=2862,
    min_samples=max(30, int(df_flow.shape[0] * 0.004)),
    metric="precomputed",
    algorithm="brute",
    leaf_size=30,
    n_jobs=10,
)


# In[6]:


db.get_params()


# ### Fit

# In[7]:

print("Calculate euclidean_distances...")
D = euclidean_distances(
    df_flow[FEATURE_LIST].to_numpy(), df_flow[FEATURE_LIST].to_numpy()
)
# print(df_flow[NEW_FEATURE_LIST])
print(FEATURE_LIST)
# print(D.shape)


# In[8]:


print("dbscan predicting...")
db_labels = db.fit_predict(D)
print(db_labels)
# -1 代表outlier


# ### Analysis

# #### Cluster數量、大小

# In[ ]:


print(f"Number of labels: {max(db_labels) + 1}")
print(f"Outlier: {list(db_labels).count(-1) / len(db_labels) * 100:.02f}%")
for i in range(0, max(db_labels) + 1):
    print(f"Cluster {i}: {len(db_labels[db_labels==i]) / len(db_labels) * 100:.02f}%")


# ### Label分類

# In[ ]:


# out_dir = f'cluster/'
# if not os.path.isdir(out_dir):
#     os.makedirs(out_dir)
# dict_df_flow = df_flow.to_dict('split')

# cluster_dict = {}
# for idx, label in enumerate(db_labels):
#     if label not in cluster_dict:
#         cluster_dict[label] = []
#     cluster_dict[label].append(dict_df_flow['data'][idx])

# result_1 = pd.DataFrame([cluster_dict[-1]])
# result_2 = pd.DataFrame([cluster_dict[0]])

# for i in cluster_dict:
#     df = pd.DataFrame(cluster_dict[i], columns = ['packets_sent', 'bytes_sent', 'packets_recv', 'bytes_recv', 'packets_sent_to_target', 'bytes_sent_to_target', 'avg_packets_sent_size',
#                                      'packets_recv_from_target', 'bytes_recv_from_target', 'avg_packets_recv_size', 'packets_sent_to_port', 'bytes_sent_to_port',
#                                      'packets_recv_from_port', 'bytes_recv_from_port', 'distinct_to', 'distinct_ports', 'n_entries_to_target', 'distinct_ports_to_target',
#                                      'n_entries_to_port', 'Src_IP', 'Dst_IP', 'Src_Port', 'Dst_Port', 'Protocol', 'Duration', 'First_Seen', 'Last_Seen',
#                                      'botnets', 'exploits',	'tor', 'phishing', 'ransomware', 'malware', 'spam', 'cryptomining', 'scanner'])
#     df.drop(['botnets', 'exploits', 'tor', 'phishing', 'ransomware', 'malware', 'spam', 'cryptomining', 'scanner'], axis=1, inplace = True)
#     df.to_csv(f"{out_dir}/cluster{i}.csv", encoding='utf-8', index=False)


# In[ ]:

out_dir = f"cluster2/"
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
out_folder = f"{BASE_PATH}same_ip_diff_behavior2"
if not os.path.isdir(out_folder):
    os.mkdir(out_folder)


## outer dicr, key is distinct ip
ip_dict = SortedDict()

csv_out_folder = f"{BASE_PATH}cluster2"
if not os.path.isdir(csv_out_folder):
    os.mkdir(csv_out_folder)
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
    # transform pandas to .csv and store it.
    df.to_csv(f"{csv_out_folder}/cluster{i}.csv", encoding="utf-8")

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
    diff_value_map = {}
    for time, cluster_id in cluster_dict.items():
        if cluster_id not in diff_value_map:
            diff_value_map[cluster_id] = 1
    if len(diff_value_map) == 1:
        continue
    with open(f"{out_folder}/{ip}.txt", "w") as out_file:
        for time, cluster_id in cluster_dict.items():
            print(f"{time}: {cluster_id}", file=out_file)

del ip_dict


# #### 每個cluster的tag狀況

# In[ ]:


db_tags = dict()
for tag in MALICIOUS_TAG:
    db_tags[tag] = list()

for i in range(0, max(db_labels) + 1):
    df = df_flow[db_labels == i]

    for tag in MALICIOUS_TAG:
        db_tags[tag].append(df[tag].sum())

    print(f"Cluster {i} total: {df[MALICIOUS_TAG].shape[0]}")
    print(df[MALICIOUS_TAG].sum())
    print()


# #### 每個tag的資料，曾經出現在哪幾個cluster

# In[ ]:


for tag in MALICIOUS_TAG:
    print(f"{tag}: {[index for index, value in enumerate(db_tags[tag]) if value > 0]}")


# #### outlier狀況

# In[ ]:


for tag in MALICIOUS_TAG:
    print(f"Tag {tag} total: {df_flow[tag].sum()}")
    print(df_flow[db_labels == -1][tag].sum())
    print((df_flow[db_labels == -1][tag].sum() / df_flow[tag].sum()) * 100)


# #### 出現哪些IP

# In[ ]:


df_flow[(db_labels == 1)].Src_IP.unique()


# #### Cluster採樣

# In[ ]:


df_flow[
    (db_labels == 2)
    & (df_flow.malware == 1)
    & (df_flow.phishing == 1)
    & (df_flow.scanner == 1)
]


# In[ ]:


# sample = X_train[(~X_train.Src_Port.isin(p)) & (~X_train.Dst_Port.isin(p)) & (db_labels==4)]
# sample = X_train[~((X_train.Dst_IP=='151.139.128.11') | (X_train.Src_IP=='151.139.128.11'))]
sample = df_flow[(db_labels == 2)]
sample
