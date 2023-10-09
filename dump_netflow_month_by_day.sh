#!/bin/bash
#
# Usage: Pass an argument as YYYYMMDD
# Example: ./dump_netflow_month_by_day.sh 20221201
# Dump the NetFlow logs of each hour in 20221201 to csv.

if [ -z ${1} ] || [ ${#1} -ne 8 ]
then
	echo "Please pass an argument with YYYYMMDD"
	exit 1
fi

year=${1:0:4}
month=${1:4:2}
day=${1:6:2}
netflow_path="../NetFlow_log/"${year}${month}${day}
dump_="../netflow_csv2/"
dump_path=${dump_}${year}${month}${day}
thread=6

if [ ! -d ${netflow_path} ]
then
	echo "${netflow_path} not found."
	exit 1
fi

if [ -d ${dump_} ]
then
	skip
else
	mkdir ${dump_}
fi

if [ -d ${dump_path} ]
then
	wait_time=3
	echo "${dump_path}"
	echo "Directory exists. Continue to dump NetFlow log in ${wait_time} seconds..."
	sleep ${wait_time}
else
	mkdir ${dump_path}
fi

# multi-thread initialization
temp_fifo="./temp.fifo"
mkfifo ${temp_fifo}
exec 6<>$temp_fifo
rm ${temp_fifo}

# create thread
for t in $(seq 0 $(($thread-1)))
do
	echo
done >&6

start_time=$(date +%s)
for hour in $(seq -f "%02g" 0 23)
do
	echo hour
	for ((minute=0; minute<=55; minute+=5))
	do
		minute_str=$(printf "%02d" $minute)
		file_path=${dump_path}/dump_${1}${hour}${minute_str}.csv
		fmt="fmt:%ts,%te,%td,%pr,%sa,%sp,%da,%dp,%flg,%pkt,%byt,%stos"

		read -u6
		{
			# file_size=($(find ${netflow_path}/*${1}${hour}* -type f -exec du -ch "{}" + | grep "total"))

			# hour_start_time=$(date +%s)
			nfdump -M ${netflow_path} -R nfcapd.${1}${hour}${minute_str} -N -q -o "${fmt}" > ${file_path}
			# hour_spend_time=$(($(date +%s) - $hour_start_time))

			# echo -e "${1}${hour}\t${hour_spend_time}\t${file_size[0]}" >> "nfdump_${1}.log"

			if [ -f ${file_path} ] && [ ! -s ${file_path} ]
			then
				echo "Remove '${file_path}' with empty."
				rm ${file_path}
			fi

			echo >&6
		} &
	done
done

wait
exec 6>&-

spend_time=$(($(date +%s) - $start_time))
echo "'${dump_path}' finished. Spend $spend_time second(s)"
