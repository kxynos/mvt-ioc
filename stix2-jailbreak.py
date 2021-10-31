#!/usr/bin/env python3
# Code based off of https://github.com/mvt-project/mvt 

import sys
import os
from stix2.v21 import (Indicator, Malware, Relationship, Bundle, DomainName)

if __name__ == "__main__":
    if os.path.isfile("jailbreak.stix2"):
        os.remove("jailbreak.stix2")

    with open("filenames.txt") as f:
        filenames = list(set([a.strip() for a in f.read().split()]))
    with open("processes.txt") as f:
        processes = list(set([a.strip() for a in f.read().split()]))

    res = []
    malware = Malware(name="jailbreak", is_family=False, description="IOCs for checkra1n jailbreak")
    res.append(malware)
    for f in filenames:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[file:name='{}']".format(f), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    for p in processes:
        i = Indicator(indicator_types=["malicious-activity"], pattern="[process:name='{}']".format(p), pattern_type="stix")
        res.append(i)
        res.append(Relationship(i, 'indicates', malware))

    bundle = Bundle(objects=res)
    with open("jailbreak.stix2", "w+") as f:
        f.write(str(bundle))
    print("jailbreak.stix2 file created")