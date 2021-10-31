# mvt-ioc
MVT (Mobile Verification Toolkit) - Indicators of Compromise for Jailbroken device (checkra1n with Cydia)

## How to use
Edit the `filenames.txt` or `processes.txt` file with your desired indicators

Run `python3 stix2-jailbreak.py`

Copy or use the generated `jailbreak.stix2`

When using MVT with the provided STIX2 file, if something is found you should notice a WARNING in the output and a new file *\_detected. 

## Warning. For educational purposes only.
The processes found in `processes.txt` where those that I found after running the MVT process on a jailbroken checkra1n device and uses Cydia. 

The `filenames.txt` is a list of known file paths of processes and files found on a jailbroken device (not using MVT). The last three lines of `filenames.txt` is from indicators I found on a jailbroken checkra1n device and uses Cydia.
