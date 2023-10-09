#!/bin/bash
#
# Usage: Pass an argument as YYYYMM for specific month,
#		 otherwise previous month as default.
# 		 Spend long time for first execution every month.
# Example: ./run.sh 202212
#

start_date=$(date -d "`date +%Y%m01` -1 month" +%Y%m%d)
end_date=$(date -d "`date +%Y%m01` -1 day" +%Y%m%d)

if [ -n ${1} ]
then
	if [ ${#1} -ne 6 ]
	then
		echo "Please pass an argument with YYYYMM"
		exit 1
	else
		start_date=$(date -d "${1}01" +%Y%m%d)
		end_date=$(date -d "${1}01 +1 month -1 day" +%Y%m%d)
	fi
fi

core=16
config_file=./.job_config
job_list=(
	"./dump_netflow_month_by_day_loop.sh ${start_date:0:6}" \
	"python3 code/graph_initialization.py $start_date $end_date --core $core -v" \
	"python3 code/graph_feature_extraction.py $start_date $end_date --core $core -v" \
	"python3 code/flow_add_tag.py $start_date $end_date --core $core -v" \
	"python3 code/flow_ml_dbscan.py $start_date $end_date -m 30000 -v" \
	"python3 code/flow_ml_dbscan.py ${1} -v" \
	"python3 code/flow_ml_semi.py ${start_date}_${end_date}" \
)

if [[ -e $config_file ]]; then
	last_job=$(head -n 1 $config_file)
else
	last_job=0
fi

for (( i=$last_job; i<3; i++ ))
do
	# update current job config
	echo $i > $config_file
	case $i in
		0)
			echo ${job_list[0]}
			${job_list[0]}
			;;
		1)
			echo ${job_list[1]}
			${job_list[1]}
			;;
		2)
			echo ${job_list[2]}
			${job_list[2]}
			;;
		3)
			echo ${job_list[3]}
			${job_list[3]}
			;;
		4)
			echo ${job_list[4]}
			${job_list[4]}
			;;
		# 5)
		# 	echo ${job_list[5]}
		# 	${job_list[5]}
		# 	;;
		*)
			echo "error job number $i"
			exit 1
			;;
	esac
	if [ $? -ne 0 ]
	then
		echo "execution finished with error"
		exit 1
	fi

done

# reset job config after all job finished
echo 0 > $config_file
