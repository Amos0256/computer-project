#!/bin/bash
#
# Usage: Pass an argument as YYYYMM
# Example: ./dump_netflow_month_by_day_loop.sh 202212
# Dump the NetFlow logs of each day in the December to csv.
# Require dump_netflow_month_by_day.sh in a same directory.

if [ -z ${1} ] || [ ${#1} -ne 6 ]
then
	echo "Please pass an argument with YYYYMM"
	exit 1
fi

year=${1:0:4}
month=${1:4:2}

for day in $(seq -f "%02g" 1 31)
do
	./dump_netflow_month_by_day.sh ${year}${month}${day}
done
