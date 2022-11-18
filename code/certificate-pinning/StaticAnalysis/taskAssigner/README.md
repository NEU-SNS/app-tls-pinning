# Task Assigner scripts

## `task_config_generator.py`

Writes the `../task_config.json` file, which contains the necessary information for the `find_network_security_configs.py` and `mcg_trust_manager_finder.py` scripts.

### Format
```
{
  "ACHTUNG #": {
    "apk_target_map": {
      "apk_filename (without .apk)": [
        list of classes to look for...
      ]
    }
  }
}
```
