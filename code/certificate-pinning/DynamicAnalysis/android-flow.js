'use strict';

// Types of tests flags
const DEBUG = true;
const IOS_TEST = true;

const ENABLE_MITM = true;
const ENABLE_FRIDA = false;
const ENABLE_UI_AUTOMATOR = false;

// Logging related variables
const DATE = new Date();
const RESULTS_BASE_DIR = `/Volumes/paracha.m/iOSDynamicTesting`;
const RESULTS_DIR = `${RESULTS_BASE_DIR}/${DATE.toISOString().split('T')[0].replace(/-/g, "") + DATE.toTimeString().split(' ')[0].replace(/:/g, "")}`;
const LOGS_DIR = `${RESULTS_DIR}/logs/`;
const SCREENSHOTS_DIR = `${RESULTS_DIR}/screenshots/`;

// Helper related variables
const APKS_JSON = './dynamic_config.json';
const APKS_BASE_DIR = '../apks/';
// const IPAS_JSON = './todo.json';
const IPAS_DIR = '/Volumes/paracha.m/iTunes-iOSResearch/Mobile Applications';

const MITM_CTRL = `./mitm/mitmproxy-ctrl`;
const SIGNALING_PORT = 4590;
const FSMON = "/data/local/tmp/fsmon";
const FSMON_LOG = "/data/local/tmp/runlog";

const FRIDA_STARTER = "frida";
const FRIDA_SCRIPT = "./frida/bypass_all_pinning.js";

// UI AUTOMATOR CONFIGURATIONS
const APPIUM_CTRL = `./ui_automator/appium-ctrl`;
const UI_AUTOMATOR_SCRIPT = `./ui_automator/main.py`;
const ANDROID_VERSION = 29;
const UI_AUTOMATOR_STEPS = 15;

// Modules
const sleep = ms => new Promise( resolve => setTimeout( resolve, ms ) );
const fs = require('fs');
const exec = require('shelljs').exec;
const net = require('net');
const readline = require('readline');
const util = require('util');
const pexec = util.promisify( exec );
const cp = require('child_process');
const sha256File = require('sha256-file');
const crypto = require('crypto');
const glob = require('glob');

( async() => {

  // Setup all required folders
  let folders = [
    RESULTS_BASE_DIR,
    RESULTS_DIR,
    LOGS_DIR,
    SCREENSHOTS_DIR
  ];
  for(let f of folders) {
    if ( !fs.existsSync(f) ) {
      fs.mkdirSync(f);
    }
  }

  if (IOS_TEST) {
    await performIOSTests();
  } else {
    await performAndroidTests();
  }

})();

function getChecksum(path) {
  return new Promise(function (resolve, reject) {
    const hash = crypto.createHash('sha256');
    const input = fs.createReadStream(path);

    input.on('error', reject);

    input.on('data', function (chunk) {
      hash.update(chunk);
    });

    input.on('close', function () {
      resolve(hash.digest('hex'));
    });
  });
}

async function performIOSTests() {
  const resumeIndex = 0; // ONLY MODIFY LOCALLY FOR RESTARTS
  var ipaCounter = 0;
  var ipasPathsToTest = [];
  const openTimeout = 30000 // milliseconds to wait after app opening
  const springboardTimeout = 10000 // milliseconds to wait after restarting springboard

  fs.readdirSync(IPAS_DIR).forEach(ipa => {
    let ipaPath = IPAS_DIR + '/' + ipa;
    ipasPathsToTest.push(ipaPath);
  })

  for (let j=0; j < ipasPathsToTest.length; j++) {
    let ipaPath = ipasPathsToTest[j]

    // Skip forward tested IPAs if necessary.
    if(ipaCounter < resumeIndex) {
      ipaCounter += 1;
      consoleDebug(`Skipping ${ipaPath}`);
      continue;
    }

    consoleDebug(`Starting test for IPA  ` + ipaPath);
    ipaCounter += 1;

    // START MITM
    // await startMitm(`${ipaPath}`);

    // INSTALL IPA
    let installFail = true;
    let appId = ''
    var installLines = exec(`ideviceinstaller -i \'${ipaPath}\'`, {silent:true}).stdout.split('\n');
    for (let i = 0; i < installLines.length; i++) {
      if (installLines[i].includes('Install: Complete')) {
        installFail = false;
      }

      if (installLines[i].includes('Installing \'')) {
        appId = installLines[i].split(' ')[1].replace('\'', '').replace('\'', '');
      }
    }

    if (installFail) {
      console.error(`Install failed: ${installLines}`);
    } else {
      // OPEN IPA
      let processingFail = false

      let appHash = ''
      await getChecksum(`${ipaPath}`)
      .then((data) => {
            appHash = data
      })
      .catch((error) => {
        console.error(`SHA256 failed: ${error}`);
        processingFail = true;
      });

      // try {
      //   appHash = sha256File(`${ipaPath}`)
      // } catch (err) {
      //   console.error(`SHA256 failed: ${error}`);
      // }

      // RECORD TRAFFIC; timeouts a bit more than openTimeout
      const tcpdump = cp.spawn(`timeout 30 tcpdump -i bridge100 host 192.168.2.18 -w \'${LOGS_DIR}/${appId}-${appHash}.pcap\'`, {
        shell: true
      });

      // // RECORD LOGS; timeouts a bit more than openTimeout
      // const netstatOutput = cp.spawn(`ssh -p 2222 root@localhost \'timeout 10 ~/netstatOutput\'`, {
      //   shell: true
      // });

      // OPEN IPA (via Objection - SSL pinning bypassed)
      // const openViaObjectionBypassPinning = cp.spawn(`timeout 30 objection --gadget ${appId} explore -s "ios sslpinning disable"`, {
      //   shell: true
      // });

      // OPEN IPA (via Objection - Normally)
      const openViaObjection = cp.spawn(`timeout 30 objection --gadget ${appId} explore`, {
        shell: true
      });

      // OPEN IPA (normally)
      //await pexec(`ssh -p 2222 root@localhost \'open ${appId}\'`).catch((error) => {
      //  console.error(`Open failed: ${error}`);
      //  processingFail = true;
      //});

      // Wait a specified amount of time after opening the app; should be less than tcpdump timeout
      await new Promise(resolve => setTimeout(resolve, openTimeout));

      // Restart springboard
      await pexec(`ssh -p 2222 root@localhost \'launchctl reboot userspace\'`).catch((error) => {
        console.error(`Killall failed: ${error}`);
        processingFail = true;
      });

      // Wait a specified amount of time after restarting springboard
      await new Promise(resolve => setTimeout(resolve, springboardTimeout));

      // TRANFER LOGS
      // await pexec(`scp -P 2222 -r root@localhost:~/netstatOutput.log ${LOGS_DIR}/${appId}-${appHash}-netstatOutput.log`).catch((error) => {
      //   console.error(`Open failed: ${error}`);
      //   processingFail = true;
      // });

      // await pexec(`scp -P 2222 -r root@localhost:~/psOutput.log ${LOGS_DIR}/${appId}-${appHash}-psOutput.log`).catch((error) => {
      //   console.error(`Open failed: ${error}`);
      //   processingFail = true;
      // });


      // UNINSTALL IPA
      let uninstallFail = true;
      var uninstallLines = exec(`ideviceinstaller -U \'${appId}\'`, {silent:true}).stdout.split('\n');
      for (let i = 0; i < uninstallLines.length; i++) {
        if (uninstallLines[i].includes('Uninstall: Complete')) {
          uninstallFail = false;
        }
      }

      // Check for success
      if (!uninstallFail && !processingFail) {
        consoleDebug(`Successfully tested IPA ${ipaPath}`)
      }
    }

    // STOP MITM
    // await stopMitm();
  }
}

async function performAndroidTests() {
  // Interfaces needed for Android
  const adb             = require('adbkit')
  const client          = adb.createClient();
  const devices = await client.listDevices(); // Moving to working with just one device
  const device = devices[0];

  // Load apps to test
  const apks = JSON.parse( fs.readFileSync(APKS_JSON).toString() );
  apks.sort();

  const resumeIndex = 0; // ONLY MODIFY LOCALLY FOR RESTARTS
  const apksToTest = apks;
  var apkCounter = 0;

  var slackMessenger = setInterval(function() {
    sendMessage(`${DATE}: Done with ${apkCounter} of ${apksToTest.length}`);
  }, 10 * 60 * 1000);

  // Start Appium before testing the apps.
  await startAppium();

  console.log(`Testing ${apksToTest.length} apk(s)`);
  for (let {app_hash, package_name, target_intents} of apksToTest) {

    // Skip forward tested apks if necessary.
    if(apkCounter < resumeIndex) {
      apkCounter += 1;
      consoleDebug(`Skipping ${apkCounter}, ${package_name} / ${app_hash}`);
      continue;
    }

    apkCounter += 1;

    // Restart adb every few iterations.
    if(apkCounter % 1 == 0) {
      consoleDebug("Killing adb...");
      await pexec("adb kill-server");
      await sleep(5000);
      consoleDebug("Done killing...");
    }
    console.log(`Testing ${apkCounter} of ${apksToTest.length}`);

    const apkPaths = getApkPaths(package_name, app_hash);
    if (apkPaths == null) {
      consoleDebug(`Apk splits not found for ${package_name} ${app_hash}`);
      continue;
    }
    // Device ready, setup services needed
    consoleDebug(`Device: ${device.id}`);
    await clearLogcat();
    const fsmon = startFsmon();
    await startMitm(`${package_name}-${app_hash}`);

    consoleDebug(`Installing ${apkPaths}`);
    let installFail = false;
    await pexec(`adb -s ${device.id} install-multiple -g ${apkPaths}`).catch((error) => {
      console.error(`Installation failed: ${error}`);
      installFail = true;
    });
    if(installFail) {
      // Need to stop services since installation failed...
      await stopMitm();
      await stopFsmon(fsmon, `${package_name}-${app_hash}-failed`);
      continue;
    }

    var frida_child = null;
    // Launch the app after extracting the right activity.
    if (!ENABLE_FRIDA && !ENABLE_UI_AUTOMATOR) {
      // This logic to launch app if we don't let frida do it
      var activity = '';
      var action = '';
      // Launch app and wait for 10 seconds...
      const [mainActivity, mainAction] = await extractMain(client, device.id, package_name);
      if (target_intents && target_intents.length > 0) {
        activity = `${package_name}/${target_intents[0]['activity']}`;
        action = target_intents[0]['action'];
      } else {
        activity = mainActivity;
        action = mainAction;
      }
      consoleDebug(`Launching activity: ${activity}, with action ${action}`);
      await client.shell(device.id, `am start -a ${action} -n ${activity}`).catch(async () => {
        console.log("am start activity failed :/");
      });

      // Basic test heuristic, launch app and wait 30s
      await sleep(30000);
    } else if (ENABLE_UI_AUTOMATOR) {

      // Start UI automator with some info: seed, device id,
      var seed = `${package_name}-${app_hash}`;
      await runUIAutomator(seed, device.id, `${LOGS_DIR}/${package_name}-${app_hash}-uiautomator`, getBaseAPK(apkPaths));
    }
    else if (ENABLE_FRIDA) {
      // Assumes frida server is running on the device
      frida_child = startFrida(package_name, app_hash);

      // Basic test heuristic, launch app and wait 30s
      await sleep(30000);

      // Write quit, kill later
      if (frida_child.stdin.writeable) {
        frida_child.stdin.write('quit');
      }
    }

    // Stop mitm before killing the app so we don't see tcp resets from the kill
    await stopMitm();

    // Close app and uninstall it
    await client.shell(device.id, `am force-stop ${package_name}` );

    if (ENABLE_FRIDA && frida_child != null) frida_child.kill();

    consoleDebug(`Done testing ${package_name}...`);
    consoleDebug('Uninstalling...');
    await client.uninstall( device.id, package_name );

    // Stop services/logging
    saveLogcat(`${package_name}-${app_hash}`, false);
    // Stop fsmon after uninstall.
    await stopFsmon(fsmon, `${package_name}-${app_hash}`);

    // Cooldown from tests
    await sleep(5000);
  }

  await stopAppium();
  // Done running all apk tests.
  // Stop status update messenger.
  clearInterval(slackMessenger);
  sendMessage('Done with all tests!');
}

function consoleDebug(m) {
  if(DEBUG) {
    console.log(m);
  }
}

function getBaseAPK(apkPaths) {
  var splitPaths = apkPaths.split(' ');
  // Probably the first entry, but lets be sure
  if (splitPaths.length == 1) {
    return splitPaths[0];
  } else {
    for (let i = 0; i < splitPaths.length; i++) {
      if (splitPaths[i].endsWith("-0.apk")) {
        return splitPaths[i];
      }
    }
  }
}

function getApkPaths(package_name, app_hash) {
  let apkSplits = glob.sync(`${APKS_BASE_DIR}/${package_name}-${app_hash.toLowerCase()}-*`);
  if (apkSplits.length == 0) {
    return null;
  } else {
    return apkSplits.join(" ");
  }
}

async function extractMain(client, id, package_name) {
  return new Promise((resolve, reject) => {
    let result = Buffer.from('');
    client.shell(id, `pm dump ${package_name}`, (err, output) => {
      output.on('data',  (buf) => result = Buffer.concat([result, buf]));
      output.on('error', reject);
      output.on('end',   () => {
        const str = result.toString();
        const mainActRegex = new RegExp(`MAIN:\n.* (${package_name}.*) filter.*\n.*Action: "(.*)"`);
        const results = str.match(mainActRegex);
        if(results) resolve([results[1], results[2]]);
        resolve(['', '']);
      });
    });
  });
}

async function extractTarget(client, id, package_name, intents) {
  return new Promise((resolve, reject) => {
    let result = Buffer.from('');
    client.shell(id, `pm dump ${package_name}`, (err, output) => {
      output.on('data',  (buf) => result = Buffer.concat([result, buf]));
      output.on('error', reject);
      output.on('end',   () => {
        const str = result.toString();
        const targetRegex = new RegExp(`.* (${package_name}.*) filter.*\n.*Action: "(.*)"`);
        const results = str.match(targetRegex)
        consoleDebug(results);
        if(results) resolve([results[1], results[2]]);
        resolve(['', '']);
      });
    });
  });
}

function writeScreenshot(c, d, s) {
  consoleDebug(`Writing screenshot`);
  return c.screencap(d).then(function(stream) {
    stream.pipe(fs.createWriteStream(s));
  });
}

async function startMitm(logname){
  // For skip MITM tests.
  if (!ENABLE_MITM) return;

  consoleDebug(`Starting MITM Proxy via control script...`);
  return exec(`${MITM_CTRL} start ${RESULTS_DIR} ${logname}`);
}

function stopMitm(){
  // For skip MITM tests.
  if (!ENABLE_MITM) return;

  consoleDebug('Stopping MITM Proxy via control script');
  return exec(`${MITM_CTRL} stop`);
}

function startAppium(){
  // For tests without UI Automator.
  if (!ENABLE_UI_AUTOMATOR) return;

  consoleDebug(`Starting Appium via control script...`);
  return exec(`${APPIUM_CTRL} start ${RESULTS_DIR}`);
}

function stopAppium(){
  // For tests without UI Automator.
  if (!ENABLE_UI_AUTOMATOR) return;

  consoleDebug('Stopping Appium via control script');
  return exec(`${APPIUM_CTRL} stop`);
}

async function runUIAutomator(seed, deviceId, logPath, apkPath) {
  console.log(`Running UI automator with ${seed}, ${deviceId}, ${apkPath}, ${logPath}`);
  await pexec(`${UI_AUTOMATOR_SCRIPT} --android-version ${ANDROID_VERSION} --adb-udid ${deviceId} --steps ${UI_AUTOMATOR_STEPS} --random-seed ${seed} --out-dir ${logPath} ${apkPath}`).catch((error) => {
    console.error(`UI Automator execution failed :/`);
  });
}

function startFrida(package_name, app_hash) {
  // Double checking that this flag is set.
  if (!ENABLE_FRIDA) return;

  const { spawn } = require('child_process');

  consoleDebug(`Starting frida...`);
  const frida = spawn('frida', ['--no-pause', '-U', '-l', FRIDA_SCRIPT, '-f', package_name]);
  var logStream = fs.createWriteStream(
    `${LOGS_DIR}/${package_name}-${app_hash}.frida`,
    {flags: 'a'}
  );

  frida.stdout.on('data', (data) => {
    // Use to see if start frida is messing up writing to file for some reason
    // consoleDebug(`stdout: ${data}`);
    logStream.write(data);
  });

  frida.stderr.on('data', (data) => {
    consoleDebug(`stderr: ${data}`);
    logStream.write(`FRIDA_ERROR: ${data}`)
  });

  frida.on('close', (code) => {
    consoleDebug(`Frida child exited with code: ${code}`);
    logStream.write(`Frida child exited with code: ${code}`);
  });

  return frida;
}

function clearLogcat(){
  consoleDebug('Clearing all logcat logs');
  return exec('adb logcat -b all -c');
}

function saveLogcat(f, baseline){
  consoleDebug('Saving all logcat logs');
  if (baseline === true) {
    return exec(`adb logcat -d > ./${BASELINE_DIR}/${f}.logcat`);
  } else {
    return exec(`adb logcat -d > ./${LOGS_DIR}/${f}.logcat`);
  }
}

function startFsmon(){
  consoleDebug("Starting fsmon to log file changes.");
  return cp.exec(`adb shell "${FSMON} -J /sdcard/ > ${FSMON_LOG}"`);
}

function stopFsmon(fsmon, outfile){
  consoleDebug("Stopping fsom.");
  fsmon.kill();
  // Also exfil this and save it somewhere.
  exec(`adb pull ${FSMON_LOG} ./${LOGS_DIR}/${outfile}.fsmon`);
}

async function sendSlack(m){
  const { IncomingWebhook } = require('@slack/webhook');
  var url;
  try {
    url = fs.readFileSync('.slackHook').toString();
    const wh = new IncomingWebhook(url);
    consoleDebug('Sending slack message');
    await wh.send({text: `${m}`});

  } catch (err) {
    if(err.code == 'ENOENT') {
      consoleDebug('No slack hook file found. Configure for slack messages!');
    }
    else console.log(err.toString());
  }
}

async function sendMessage(m) {
  const https = require('https');

  try {
    let options = JSON.parse(fs.readFileSync('.messageOptions'));
    let payload = JSON.stringify({
      message: m
    });
    const req = https.request(options, res => {
      consoleDebug(`sendMessage Status code: ${res.statusCode}`);
      res.on("data", d => {
        consoleDebug(`sendMessage data: ${d}`);
      });
    });
    req.on('error', error => {
      consoleDebug(`sendMessage error: ${error}`);
    });
    req.write(payload);
    req.end();

  } catch (err) {
    if (err.code == 'ENOENT') {
      consoleDebug("No message config file found, set .messageOptions!")
    } else console.log(err.toString());
  }


}
