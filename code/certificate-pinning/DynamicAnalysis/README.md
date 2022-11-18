# dynamic-tripwire

## Requirements

1. `iptables`
2. `mitmproxy`
3. `adb`
4. `nodejs`
5. `python3`
6. `adb-sync`

## Network setup

In order for transparent proxying to work, we require two network interfaces on the machine running the tests.

One interface connected to the internet (wired or wireless); the other, configured as a WiFi hotspot to which the test android device is connected.

This second interface is configured as the `MITM_INTERFACE` variable in the `mitmproxy-ctrl` script.

### android-flow.js

The android-flow script (Run with `node android-flow.js`) is the main driver script in charge of running tests.

It parses the ./apk_scripts/apks.json (contains mappings of package names and hashes) file, for each apk in that file it does the following:

- Clears the logcat for the connected device
- Starts fsmon (file system monitor tool) on the device
- Starts mitmproxy via the mitmproxy-ctrl script
- Installs the app (path must follow format: ./apks/package_name-package_hash.apk) on the connected android device
- Finds the mainActivity and mainAction and launched it with an Intent sent via ADB
- Sleeps for 10 seconds
- Stops the app and uninstalls it
- Saves all logs, Android logcat, mitmproxy and fsmon
- Moves on to the next apk

### mitmproxy-ctrl

This script manages `mitmdump` and `iptables` to allow transparent proxy capabilities on a selected network interface.

Follow these steps to configure the script.
1. Edit the `MITM_INTERFACE` variable in the script to the interface of your choice.
2. Run the script `./mitmproxy-ctrl start test test`, to create the default directories (mitm-conf and mitm-logs) and to make sure you don't run into errors.

Following these steps should make sure that all network requests coming in on the configured interface pass through mitm proxy, which can be verified by going through the log files.

## Installation
### For Mitmproxy and extension
1. Install aforementioned requirements.
2. Setup mobile device to use the base machine's hotspot, which is mitm'd.
3. `git clone https://git.homezone-project.com/feal94/mobile-browsers-scripts.git`
4. `pip install -r requirements`

## Usage
### For flow
1. `npm install`
2. `./get-apks.sh`
3. `node android-flow.js`
4. `wait for a wile`

the android-flow.js file is the entrypoint and mastermind of the process. Spawning mitmproxy and other necessary resources to be used during experminetation

## Steps to launch tests

A general guideline to launch a test.

- Factory reset the device
- Enable USB Debugging
- Enable Stay awake
- Install MITM certificate
- Disable Play Protect
- Disable selinux `setenforce 0`
- Connect to the Wifi
- Install fsmon to `/data/local/tmp/`
- Set up VPN for the base machine (Optional)
- Launch tests, `node android-flow.js`
