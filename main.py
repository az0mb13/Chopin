#!/usr/bin/python

import argparse
import subprocess
import os
from shodan import Shodan
from config import shodan_key,slackid
import json

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", required=True)
parser.add_argument("-p", "--project", required=True)
args = parser.parse_args()
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

#Converting CIDR to IPs and storing in ips.txt
cidr2ip = open("ips.txt", "w")
subprocess.run(["cidr2ip", "-f", args.file], stdout=cidr2ip)
cidr2ip.close()

#Adding CIDRs and IPs to Shodan Monitor
shodan_api = Shodan(shodan_key) 
with open(args.file) as sh:
    lines = sh.read().splitlines()
    #Creating alert
    create_alert = shodan_api.create_alert(name=args.project, ip=lines, expires=0)
    alert_id = create_alert["id"]
    #Enabling triggers
    shodan_api.enable_alert_trigger(aid=alert_id, trigger='industrial_control_system,internet_scanner,iot,malware,new_service,open_database,ssl_expired,uncommon,uncommon_plus,vulnerable,vulnerable_unverified')
    #Enabling Slack Webhook for triggers
    shodan_api.add_alert_notifier(aid=alert_id, nid=slackid)

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

# Fetching certs from SSL
cero = open("ssl_hosts_temp.txt", "w")
cero_in = open(args.file, "r")
subprocess.run(["cero"], stdout=cero, stdin=cero_in)

with open("ssl_hosts_temp.txt") as ss:
    f = open("ssl_hosts.txt", "w")
    sslines= ss.read().splitlines()
    for sse in list(set(sslines)):
        f.write(sse + "\n")
    f.close()
os.remove("ssl_hosts_temp.txt")

#Reverse DNS lookup
hakrev_in = open("ips.txt", "r")
hakrev_out = open("revdns_temp.txt", "w")
subprocess.run(["hakrevdns", "-d"], stdout=hakrev_out, stdin=hakrev_in)

with open("revdns_temp.txt") as hr:
    f = open("revdns.txt", "w")
    hrlines= hr.read().splitlines()
    for hre in list(set(hrlines)):
        if "in-addr.arpa" not in hre:
            f.write(hre + "\n")
    f.close()
os.remove("revdns_temp.txt")

#Unique all hosts
h1 = open("ssl_hosts.txt", "r")
h1Content = h1.read()
h2 = open("revdns.txt", "r")
h2Content = h2.read()
h3 = open("hostnames.txt", "r")
h3Content = h3.read()
h1List = h1Content.splitlines()
h2List = h2Content.splitlines()
h3List = h3Content.splitlines()
h1.close()
h2.close()
h3.close()
hosts_final = list(set(h1List+h2List+h3List))
h_final = open("hosts_final.txt", "w")
for item in hosts_final: 
    h_final.write(item + "\n")
h_final.close()

#Port scan using masscan
