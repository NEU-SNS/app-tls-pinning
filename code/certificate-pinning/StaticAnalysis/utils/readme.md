## Summary
The scripts in this directory are meant to facilitate the task of analyst using the outputs generated by other static analysis approaches.

## Descriptions
There are currently two scripts that each is described below. 

### Library analysis
This script analyzes the paths to the pinning methods, and extract some library names. The input should be the found pins containing a column that has the path value.
The script lets you set the column name. After processing, it produces two files. The name_freq.csv file contains the names, their frequencies and all paths containing that name.
See [Library names frequencies](https://drive.google.com/file/d/1y5hc637OCvKNUMvkoJKXtb4nGuDfUOZ7/view?usp=sharing) for an output example. To execute, type

    python3  paths_analysis.py [path\to\static\analysis\script\outputs].csv -col_name caller


### Standard output generator

**Screenshots**
