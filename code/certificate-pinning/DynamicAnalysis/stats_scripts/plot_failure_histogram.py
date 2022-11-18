#!/usr/bin/env python3
import os
import sys
import json
from collections import defaultdict
import matplotlib.pyplot as plt

def main():
    if len(sys.argv) < 2:
        print("Please provide at least 1 path to process .result files from.")
        return
    else:
        failure_paths = sys.argv[1:]

    failure_files = set()
    for path in failure_paths:
        failure_files.update(get_files_from_path(path + '/logs/', ".result"))

    alerts_seen_map = defaultdict(int)

    for failure_file in failure_files:
        with open(failure_file, "r") as inf:
            result = json.load(inf)
        if "failed_handshakes" in result and \
                "ALERT_FAILS" in result["failed_handshakes"]:
            alerts_seen_map[result["failed_handshakes"]["ALERT_FAILS"]] += 1
    write_CDF(alerts_seen_map, "failures_cdf.pdf", \
        "Number of TLS Alerts observed")

def get_files_from_path(path, extension):
    retset = set()
    for f in os.listdir(path):
        if f.endswith(extension):
            retset.add(path + "/" + f) # Need to track path as well
    return retset

def write_CDF(cdf_data, out_file, xlabel="Default x label."):
    cdf_total = 0
    print("CDF data:", cdf_data)
    for k, v in cdf_data.items():
        cdf_total += v
    moving_sum = 0
    cdf_x = [0]
    cdf_y = [0]
    max_datapoint = max(cdf_data.keys()) + 1
    for i in range(0, max_datapoint + 1):
        moving_sum += cdf_data[i - 1]
        cdf_x.append(i) # We have the x axis to plot.
        cdf_y.append(moving_sum / cdf_total) # We have the y axis point.
    plot_setup()
    plt.step(cdf_x, cdf_y)
    plt.grid(linestyle=":")
    # plt.xticks(range(0, max_datapoint))
    plt.yticks([0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
    plt.xlim(left=-0.1, right=max_datapoint)
    plt.ylim(bottom=0.0, top=1.1)
    plt.ylabel("CDF: " + str(cdf_total) + " Apps")
    plt.xlabel(xlabel)
    plt.savefig(out_file, dpi=2000)
    plt.close()
    print("CDF(x, y)", cdf_x, cdf_y)
    print("Total CDF data:", cdf_total)

def plot_setup():
    plt.rcParams['axes.labelsize'] = '7'
    plt.rcParams['axes.titlesize'] = '7'
    plt.rcParams['lines.linewidth'] = '1'
    plt.rcParams['xtick.labelsize'] = '7'
    plt.rcParams['ytick.labelsize'] = '7'
    plt.rcParams['grid.color'] = 'gray'
    plt.rcParams['grid.linestyle'] = ':'
    plt.rcParams['grid.linewidth'] = 0.75
    plt.rcParams['patch.force_edgecolor'] = True
    plt.rcParams['patch.facecolor'] = 'b'
    # plt.rcParams['xtick.direction'] = 'in'
    # plt.rcParams['ytick.direction'] = 'in'
    plt.rcParams['xtick.major.size'] = '3'
    plt.rcParams['ytick.major.size'] = '3'
    plt.rcParams['xtick.major.width'] = '0.5'
    plt.rcParams['ytick.major.width'] = '0.5'
    fig = plt.figure(figsize=(3.12561, 1.6))
    fig.set_tight_layout({"pad": 0, "rect": [0, 0, 1, 1]})
    ax = fig.add_subplot(111)
    # Plot stuff
    plt.tight_layout()

if __name__ == "__main__":
    main()
