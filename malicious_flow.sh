#!/bin/bash

# variable
start_date="20230101"
end_date="20230110"
input_dir="malicious_IPs_date"
output_dir="malicious_IPs_netflow"
netflow_dir="NetFlow_log"

# check if the output directory exists, and creates it if not
if [ ! -d "$output_dir" ]; then
  mkdir -p "$output_dir"
fi

# date loop
for (( date=${start_date}; date<=${end_date}; date++))
do
  # set file path
  input_file="${input_dir}/malicious_IPs_${date}.txt"
  output_subdir="${output_dir}/${date}/"
  netflow_subdir="${netflow_dir}/${date}/";

  # check if the output directory exists, and creates it if not
  if [ ! -d "$output_subdir" ]; then
    mkdir -p "$output_subdir"
  fi

  # loop get IPs
  while read ip;
  do
    echo "$ip"
    # excute nfdump instruction
    nfdump -R "./${netflow_subdir}nfcapd.${date}0000:nfcapd.${date}2355" "src or dst ip ${ip}" -o line > "${output_subdir}${date}_${ip}.txt"
  done < "$input_file"
done
