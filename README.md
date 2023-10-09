# black_list_analysis
## code
### malicious_IP.py
- generate malicious IP
- genereate directory malicious_IPs_{date1}_to_{date2}/malicious_IPs_{date}

### maliciousIP_with_tag.py
```=shell
python3 maliciousIP_with_tag 20230101_20230228
```
- genereate malicous IP with CTI tag
- it might not contain all the malicious IPs
- genereate directory malicious_IPs_with_tag_{date}/

### parallel_malicious_flow.py
- `nfdump -R flowfile 'src or dst ip {ip}' -o line`
- advanced version of malicous_flow.py
- execute with multiple thread
- default is 4
- you can customize your thread with following command
  ```=shell
  python3 parallel_malicious_flow.py {thread_num}
  ```
- genereate directory malicious_IPs_netflow_{date1}_to_{date2}/
- if the malicious IPs not exist, go execute malicious_IP.main

### parallel_cluster.py
- `nfdump -R flowfile 'net ip netmask' -o line`
- cluster first two bytes, using 255.255.0.0
- you can customize the netmask(with thread number necessary)
  ```=shell
  python3 parallel_cluster.py 4 255.0.0.0
  ```
### To group ip by same prefix
1. go to `code` folder
2. type `python3 group_ip_by_prefix.py [SAME_PREFIX_NUMBER]`
  - You can specify how many bytes you would like to match by adding SAME_PREFIX_NUMBER
    - The default value is 3
3. The above command will generate a folder name "same_prefix_ip_[SAME_PREFIX_NUMBER]" in the upper folder
 
