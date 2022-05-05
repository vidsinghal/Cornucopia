## Usage 

- you will need to have `angr` & `r2pipe` installed
- build Ghidra from source: [instructions](https://github.com/NationalSecurityAgency/ghidra), edit the `GHIDRA_PATH` in `models/runner.py`
- you will also need a licensed copy of IDA Pro, edit `IDA_PATH` in `models/runner.py` to reflect.
- make sure to have unstripped versions of binaries in a folder called `unstripped` 
- you can change tools to test in `run.py`
- hardcoded timeout for all tools is in `models/runner.py`

```
python3 run.py <directory_with_stripped_binaries>
```

## Output

- logs can be found in the `progress.log`, please note that this file is also used to save progress when resuming.
- In cases were differences were found output will be found in the `diff_fails` directory
- dumps of stdout and stderr can be found in the in the `crashes` directory 
