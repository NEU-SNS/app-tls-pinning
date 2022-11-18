#!/usr/bin/env python3
import os
import json
import multiprocessing
import socket
import sys
sys.path.append("../utils")
import task_variables
sys.path.append("../networkSecurityConfig")
import find_network_security_configs
sys.path.append("../stringSearch")
import app_string_search


CONFIGURATION_FILE = "../task_config.json"

def main():
    tasks_to_process = get_machine_tasks()
    worker_pool = multiprocessing.Pool()
    # Handle NSC Job, need to write the same logic for other jobs
    if task_variables.NSC_JOB in tasks_to_process:
        nsc_jobs = tasks_to_process[task_variables.NSC_JOB]
        print("Processing NSC_JOBS...", len(nsc_jobs))
        results = worker_pool.map_async(
                    find_network_security_configs.process_task,
                    nsc_jobs )
        total_nsc = 0
        for result in results.get():
            total_nsc += result
        print("Total Network Security configs found:", total_nsc)
    elif task_variables.STRING_SEARCH_JOB in tasks_to_process:
        string_search_jobs = tasks_to_process[task_variables.STRING_SEARCH_JOB]
        print("Processing STRING_SEARCH_JOBS...", len(string_search_jobs))
        results = worker_pool.map_async(
                    app_string_search.process_task,
                    string_search_jobs )
        total_string_search = 0
        for result in results.get():
            total_string_search += result
        print("Total String Search certs and pins found:", total_string_search)
    else:
        print("No jobs for this machine...")
    worker_pool.close()
    worker_pool.join()

def get_machine_tasks():
    machine_name = socket.gethostname()
    with open(CONFIGURATION_FILE) as inf:
        configuration = json.load(inf)
        try:
            return configuration[machine_name]
        except KeyError:
            print("No tasks for this machine...")
            return {}

# Boilerplate
if __name__ == "__main__":
    main()
