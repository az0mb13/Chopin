# Chopin [NOT MAINTAINED]

External Network Pentest Automation using Shodan API and other tools. 

## Workflow
1. Input a file containing CIDR ranges.
2. Converts CIDR ranges to individual IP addresses.
3. Adds all the IPs to Shodan's Monitor and enables all the triggers along with Notification over Slack Webhook.
4. Extracts hostnames from Shodan query for the CIDR ranges
5. Fetches domains and subdomains from SSL certificates
6. Extracts domains and subdomains from Reverse DNS Lookup
7. Combines all the extracted domains into a single file
8. Port scan using masscan on all the hosts
9. Output of masscan + domains/subdomains is fed into httpx to resolve.
10. httpx output is sent to Nuclei.

## To be added 
* Nessus Scans using API
