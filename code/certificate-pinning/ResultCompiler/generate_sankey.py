#!/usr/bin/env python3
import sys
import plotly.graph_objects as go
import plotly.io as pio

SANKEY_DIAG = "common_600_sankey.pdf"

PIN_ANY_ONE = 69
PIN_BOTH = 27
PIN_ANDROID_ONLY = 20
PIN_IOS_ONLY = 22

# Consistency and inconsistency counts
PIN_BOTH_CONSISTENT = 15
PIN_BOTH_INCONSISTENT = 6
PIN_BOTH_INCONCLUSIVE = 6
# Android only apps' counts
ANDROID_CONSISTENT = 0
ANDROID_INCONSISTENT = 10
ANDROID_INCONCLUSIVE = 10
# iOS only apps' counts
IOS_CONSISTENT = 0
IOS_INCONSISTENT = 7
IOS_INCONCLUSIVE = 15

CONSISTENT_TOTAL = PIN_BOTH_CONSISTENT + ANDROID_CONSISTENT + IOS_CONSISTENT
INCONSISTENT_TOTAL = PIN_BOTH_INCONSISTENT + ANDROID_INCONSISTENT + IOS_INCONSISTENT
INCONCLUSIVE_TOTAL = PIN_BOTH_INCONCLUSIVE + ANDROID_INCONCLUSIVE + IOS_INCONCLUSIVE

def main():
    NODES = dict(
    label = [
        "Pinning in Common Dataset <br> (" +str(PIN_ANY_ONE)+")", # 0
        "Android & iOS <br>(" +str(PIN_BOTH)+")" , # 1
        "Android <br> (" +str(PIN_ANDROID_ONLY)+")", # 2
        "iOS <br> (" +str(PIN_IOS_ONLY)+")", # 3
        "Consistent Pinning  <br> (" +str(CONSISTENT_TOTAL)+")", # 4
        "Inconsistent Pinning <br> (" +str(INCONSISTENT_TOTAL)+")", # 5
        "Inconclusive <br> (" +str(INCONCLUSIVE_TOTAL)+")" # 6
        ],
    color = ["teal", "teal", "seagreen", "mediumblue", "white", "white", "white"],)
    LINKS = dict(
    source = [  0,  0,  0, 1, 1, 1, 2, 2, 2, 3, 3, 3], # The origin or the source nodes of the link
    target = [  1,  2,  3, 4, 5, 6, 4, 5, 6, 4, 5, 6], # The destination or the target nodes of the link
    value =  [ PIN_BOTH, PIN_ANDROID_ONLY, PIN_IOS_ONLY,
                PIN_BOTH_CONSISTENT, PIN_BOTH_INCONSISTENT, PIN_BOTH_INCONCLUSIVE,
                ANDROID_CONSISTENT, ANDROID_INCONSISTENT, ANDROID_INCONCLUSIVE,
                IOS_CONSISTENT, IOS_INCONSISTENT, IOS_INCONCLUSIVE], # The width (quantity) of the links
    # Color of the links
    color =     [ "turquoise",   "lawngreen",   "lightskyblue",
                "turquoise", "turquoise", "turquoise",
                "lawngreen", "lawngreen", "lawngreen",
                "lightskyblue", "lightskyblue", "lightskyblue"
    ])    # Source Node: 0 - United States of America
    data = go.Sankey(node = NODES, link = LINKS)
    fig = go.Figure(data)
    pio.full_figure_for_development(fig, warn=False)
    fig.write_image(SANKEY_DIAG, engine="kaleido", format="pdf")
    # fig.show()

if __name__ == "__main__":
    main()
