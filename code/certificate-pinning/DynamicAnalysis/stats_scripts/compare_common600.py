import sys
import matplotlib.pyplot as plt
from functools import cmp_to_key
from matplotlib_venn import venn2


app_mappings_android = {}
app_mappings_ios = {}
app_mappings_generic = {}

with open('compare_common600_mappings.txt', 'r') as mP:
    for line in mP.readlines():
        items = line.split("%%%")
        generic_name = items[0].strip().split(".ipa")[0]
        ios_name = items[1].strip()
        android_name = items[2].strip()

        app_mappings_generic[ios_name] = generic_name
        app_mappings_generic[android_name] = generic_name

        if ios_name not in app_mappings_ios:
            app_mappings_ios[ios_name] = set()
        app_mappings_ios[ios_name].add(android_name)

        if android_name not in app_mappings_android:
            app_mappings_android[android_name] = set()
        app_mappings_android[android_name].add(ios_name)

assert len(app_mappings_android) == len(app_mappings_ios)

for item in app_mappings_ios:
    assert len(app_mappings_ios[item]) == 1

for item in app_mappings_android:
    assert len(app_mappings_android[item]) == 1


def process_results_file(path):
    apps_that_pin = {}
    with open(path) as pF:
        for l in pF.readlines():
            items = l.split(" ")
            app_name = items[0].rsplit("/", 1)[1].rsplit("-", 1)[0].strip()

            if int(items[1]) > 0:
                apps_that_pin[app_name] = items[2]

    return apps_that_pin


android_results = process_results_file(sys.argv[1])
ios_results = process_results_file(sys.argv[2])
android_results_generic = set()
for x in android_results:
    android_results_generic.add(app_mappings_generic[x])

ios_results_generic = set()
for x in ios_results:
    ios_results_generic.add(app_mappings_generic[x])

table_data = []
for app in app_mappings_ios:
    if app in ios_results or list(app_mappings_ios[app])[0] in android_results:
        table_data.append([app_mappings_generic[app], u'\u2713' if app in ios_results else "", u'\u2713' if list(app_mappings_ios[app])[0] in android_results else "", app + ";" + list(app_mappings_ios[app])[0]])

def custom_cmp(a, b):
    if a[1] == u'\u2713' and a[2] == u'\u2713':
        return 1

    elif b[1] == u'\u2713' and b[2] == u'\u2713':
        return -1

    elif a[1] == u'\u2713':
        return 1

    else:
        return -1


custom_cmp_key = cmp_to_key(custom_cmp)
table_data.sort(key=custom_cmp_key, reverse=True)

venn2(subsets = (android_results_generic, ios_results_generic), set_labels = ('Android', 'iOS'))
plt.savefig("venn.png", dpi=300)
print("__________________________________________________________________")
print('{:30s} {:10s} {:10s} {:150s} '.format("Application | ", "iOS PINNED | ", "Android PINNED | ", "Package names (ios;android)"))
print("__________________________________________________________________")
for elem in table_data:
    print('{:30s} {:10s} {:10s} {:150s} '.format(elem[0], elem[1], elem[2], elem[3]))
print("__________________________________________________________________")
exit(0)


fig, ax = plt.subplots(1, 1)
column_labels = ["App names", "iOS pinned", "Android pinned"]
ax.axis('off')
tbl = ax.table(cellText=table_data, colLabels=column_labels, colWidths=[.1]*3, loc="center")
tbl.set_fontsize(24)
tbl.scale(3, 1)  # may help

plt.savefig("table.png", dpi=300)
