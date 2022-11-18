# Network Security Configuration analysis scripts

## `find_network_security_configs.py`

This script goes through all APKs in the `../../apks/` directory and pulls out the NSCs.
Each APK produces its own `.json` result file in the  `./nsc_results` dir.

### Requires
* `../task_config.json`: contains mappings from machines to APKs to process.

## `compile_nsc_results.py`

Once the find script is done, use this script to compile all the NSC results
