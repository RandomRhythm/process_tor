import csv
import os
import io
import operator
import itertools

from collections import defaultdict

strinputFile = "g:\\test\\tor_detections.csv" #Input file to process
strTorPath = "g:\\test\\Tor_list.txt" # copy of www.dan.me.uk/tornodes list
strOutPath = "g:\\test\\tor_assess.csv" #output file
outputEncoding = "utf-8"
boolTruncateAtChar = True #truncate key at first strTruncateChar
strTruncateChar = "\t"
boolIncludeCount = True
boolQuoteOutput = True #add quotes around each field
listIpColumns = [0,2] #IP address column location(s). If you have only one IP address column at column location 2 then use [2]. Column location count starts at zero
listPortColumns = [1,3] #Port column(s). First column location is zero and increases with next column 
boolDistinctPairs = True #Default=True. Set to True to check the IP and the port are at the same location in the www.dan.me.uk/tornodes list. False will check each IP's port against all ports in the https://www.dan.me.uk/tornodes list.
dictRouter = dict()
dictDirectory = dict()

def writeCSV(fHandle, rowOut):
  if boolQuoteOutput == True:
    fHandle.write("\"" + rowOut.replace("|", "\",\"") + "\"\n")
  else:
    fHandle.write(rowOut.replace("|", ",") + "\n")

intRowCount = 0;
with open(strTorPath, "rt", encoding="utf-8") as csvfile: #Open tor listing   #, encoding="utf-16"
    reader = csv.reader(csvfile, delimiter='|')
    for row in reader:
      strTmpIP = row[0]
      strTmpRouter = row[2]
      strTmpDirectory = row[3]
      dictRouter[strTmpIP + "|" + strTmpRouter] = strTmpDirectory #build dict of IP|port pairs for tor router
      dictDirectory[strTmpIP + "|" + strTmpDirectory] = strTmpRouter #build dict of IP|port pairs for tor directory

    #<ip>|<name>|<router-port>|<directory-port>|<flags>|<uptime>|<version>|<contactinfo>

with io.open(strOutPath, "w", encoding=outputEncoding) as f:
  intRowCount = 0;
  with open(strinputFile, "rt", encoding="utf-8") as csvfile: #, encoding="utf-16"
      reader = csv.reader(csvfile, delimiter=',', quotechar='\"')
      for row in reader:
        if len(listIpColumns) == len(listPortColumns) and boolDistinctPairs == True:
          intPairCount = 0
          for ipaddrloc in listIpColumns:
           if row[ipaddrloc] + "|" +  row[listPortColumns[intPairCount]] in dictRouter: #check if IP|port pair in tor router dict
             writeCSV(f, row[ipaddrloc] + "|" + row[listPortColumns[intPairCount]] + "|Router port match")
           if row[ipaddrloc] + "|" +  row[listPortColumns[intPairCount]] in dictDirectory: #check if IP|port pair in tor directory dict
             writeCSV(f, row[ipaddrloc] + "|" + row[listPortColumns[intPairCount]] + "|Directory port match")
           intPairCount +=1
        else:
          for ipaddrloc in listIpColumns:
            for portloc in listPortColumns:
             if row[ipaddrloc] + "|" + row[portloc] in dictRouter:
               writeCSV(f, row[ipaddrloc] + "|" + row[portloc] + "|Router port match")
             if row[ipaddrloc] + "|" + row[portloc] in dictDirectory:
               writeCSV(f, row[ipaddrloc] + "|" + row[portloc] + "|Directory port match")