import subprocess
import dump_netflow_month_by_day_loop, graph_initialization, graph_feature_extraction, flow_add_tag

start_date = "20230301"
end_date = "20230310"

dump_netflow_month_by_day_loop.main(start_date, end_date)

# graph_initialization.main(start_date, end_date)
# graph_feature_extraction.main(start_date, end_date)
# flow_add_tag.main(start_date, end_date)
# command1 = ['python3', 'dump_netflow_month_by_day_loop.py', f'{start_date}', f'{end_date}']
command2 = ["python3", "graph_initialization.py", f"{start_date}", f"{end_date}"]
command3 = ["python3", "graph_feature_extraction.py", f"{start_date}", f"{end_date}"]
command4 = ["python3", "flow_add_tag.py", f"{start_date}", f"{end_date}"]

# subprocess.run(command1, check=True)
subprocess.run(command2, check=True)
subprocess.run(command3, check=True)
subprocess.run(command4, check=True)
