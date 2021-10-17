#!/usr/bin/python

import argparse
import subprocess
import os
from shodan import shodan
import config

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", required=True)
args = parser.parse_args()
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


#Converting CIDR to IPs and storing in ips.txt
f = open("ips.txt", "w")
cidr2ip = subprocess.run(["cidr2ip", "-f", args.file], stdout=f)

