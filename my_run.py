import subprocess
import time
import dump_netflow_month_by_day_loop, graph_initialization, graph_feature_extraction, flow_add_tag
from datetime import datetime, timedelta

###The key points:
###Gets the full netflow data upfront for entire range
###Processes initial graph steps on full range
###Then loops month-by-month to add tags for each month's subset of flows

start_date = "20230101"
end_date = "20230328"

month_list = [
    ("01", "31"),
    ("02", "28"),
    ("03", "31"),
    ("04", "30"),
    ("05", "31"),
    ("06", "30"),
    ("07", "31"),
    ("08", "31"),
    ("09", "30"),
    ("10", "31"),
    ("11", "30"),
    ("12", "31"),
]

# +++Gets the full netflow data upfront for entire range
dump_netflow_month_by_day_loop.main(start_date, end_date)
# ---

# +++Processes initial graph steps on full range
print("Start initializing graph")
start_time = time.time()

command2 = ["python3", "graph_initialization.py", f"{start_date}", f"{end_date}"]
subprocess.run(command2, check=True)

spend_time = int(time.time() - start_time)
print(f"Done initializing graph. Spend {spend_time} second(s)\n")
# ---

# +Then loops month-by-month to add tags for each month's subset of flows
print("Start extracting feature from graph")
start_time = time.time()

command3 = ["python3", "graph_feature_extraction.py", f"{start_date}", f"{end_date}"]
subprocess.run(command3, check=True)

spend_time = int(time.time() - start_time)
print(f"Done extracting feature from graph. Spend {spend_time} second(s)\n")
# ---

# +++ processing flow_add_tag
start_month = datetime.strptime(start_date, "%Y%m%d").month
end_month = datetime.strptime(end_date, "%Y%m%d").month

current_month = start_month
process_month = []

while current_month <= end_month:
    process_month.append(month_list[current_month - 1])
    current_month += 1

year = datetime.strptime(start_date, "%Y%m%d").year

print("Start adding tag to flow")
start_time = time.time()

for month in process_month:
    command = [
        "python3",
        "flow_add_tag.py",
        f"{year}{month[0]}01",
        f"{year}{month[0]}{month[1]}",
    ]  # the first is the start day of the month, the second is the end day of the month
    subprocess.run(command, check=True)
spend_time = int(time.time() - start_time)
print(f"Done add tag to flow. Spend {spend_time} second(s)\n")
# end of flow_add_tag
