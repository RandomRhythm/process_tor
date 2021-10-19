# process_tor
Process a CSV of tor detections against the www.dan.me.uk/tornodes list to confirm if the IP and port are listed.

Often security tools will generate detections entirely on the IP address being listed as a tor node. Many tor nodes host other services such as NTP that will generate false-detections. The IP address and the port contacted both need to be validated to determine if traffic may have been related to tor. 
