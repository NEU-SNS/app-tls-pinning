import json
import subprocess
import time

from ppadb.client import Client as AdbClient

"""
** place APKs in test_apks folder
Dependency:
    pip install pure-python-adb
"""

with open('dynamic_config.json') as f:
    data = json.load(f)

client = AdbClient(host="127.0.0.1", port=5037)

device = client.devices()[0]

for apk in data:
    try:
        apk_hash, apk_package_name = apk['app_hash'], apk['package_name']
        print("Working with: {}.apk".format(apk_hash))

        f = open("mitm_results/{}.txt".format(apk_hash), "w")
        p = subprocess.Popen(['mitmdump', '--ssl-insecure'], shell=True, stdout=f)

        device.install("test_apks/{}.apk".format(apk_hash))

        if len(apk['target_intents']) != 0:
            action, activity = apk['target_intents'][0]['action'][0], apk['target_intents'][0]['activity']
            device.shell("am start -a {} -n {}/{}".format(action, apk_package_name, activity))
        else:
            device.shell("monkey -p {} -c android.intent.category.LAUNCHER 1".format(apk_package_name))

        time.sleep(10)
        device.uninstall(apk_package_name)

        p.kill()
        f.close()

    except Exception as e:
        # TODO log
        pass



