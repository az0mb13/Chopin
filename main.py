#!/usr/bin/python

import argparse
import subprocess
import os
from shodan import Shodan
from config import shodan_key
import json

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", required=True)
parser.add_argument("-p", "--project", required=True)
args = parser.parse_args()
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

#Converting CIDR to IPs and storing in ips.txt
f = open("ips.txt", "w")
cidr2ip = subprocess.run(["cidr2ip", "-f", args.file], stdout=f)


#Adding CIDRs and IPs to Shodan Monitor
shodan_api = Shodan(shodan_key) 
with open(args.file) as sh:
    lines = sh.read().splitlines()
    #Creating alert
    # create_alert = shodan_api.create_alert(name=args.project, ip=lines, expires=0)
    # alert_id = create_alert["id"]
    # #Enabling triggers
    # shodan_api.enable_alert_trigger(aid=alert_id, trigger='industrial_control_system,internet_scanner,iot,malware,new_service,open_database,ssl_expired,uncommon,uncommon_plus,vulnerable,vulnerable_unverified')
    # #Enabling Slack Webhook for triggers
    # shodan_api.add_alert_notifier(aid=alert_id, nid='yUCrcHttQhRVuexc')

    query_string = "net:"+(",".join(lines))
    query_out = shodan_api.search(query=query_string, page=1)
    hostnames = []
    for i, j in query_out.items():
        for k in j:
            if k["hostnames"]:
                hostnames.append("".join(k["hostnames"]))
        break

    hostfile = open("hostnames.txt", "w")
    for element in list(set(hostnames)):
        hostfile.write(element + "\n")
    hostfile.close()