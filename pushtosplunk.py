""" script:   pushtosplunk.py
    purpose:  pulls latest intel from Soltra Edge Mongo database
                and pushes them to an open port listening on Splunk

              This pulls the latest indicators from the Soltra Edge database (mongo)
                and writes them to a log file (/var/log/soltrasplunk.log)
              A Splunk light forwarder is also on the Soltra host, which pushes any 
                log file appends to a heavy forwarder/indexer

    dependencies:  pymongo

    created:  07 Aug 2015, Don Franke
    updated:  03 Dec 2015, Don Franke
    updated:  22 Dec 2015, Don Franke
    updated:  10 Jun 2016, Don Franke
"""
import re
from pymongo import MongoClient
import socket
import pycurl
from StringIO import StringIO
import sys
import time
from datetime import datetime, timedelta

# constants
SPLUNK_HOST="127.0.0.1"
SPLUNK_PORT=9997
NUM_HOURS_OF_INTEL=1
CERT_PATH="/etc/pki/tls/certs/ca-bundle.crt"

# replacement for native netcat
def netcat(hostname, port, content):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, port))
    s.sendall(content)
    s.shutdown(socket.SHUT_WR)
    while 1:
        data = s.recv(1024)
        if data == "":
            break
        print "Received:", repr(data)
    s.close()

class Ob:
    oID=""
    oValue=""
    oType=""
    iCreatedDate=""
    oCreatedBy=""

# get today's date
todaystring = str(datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"))

oList = []
aList = []

today = datetime.utcnow()-timedelta(hours=NUM_HOURS_OF_INTEL)
todaydt = datetime(today.year,today.month,today.day,today.hour,0,0)
print "Getting intel created since: ", todaydt

# clear out intel from Splunk
client = MongoClient('mongodb://localhost:27017/')
db = client.inbox
collection = db.stix
content = ""

# get new indicators from mongo database
ipv4regex = "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
ipv4cidrregex = "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))"
domainregex="(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})"
result = collection.find({"$or":[{"data.summary.type":"DomainNameObjectType"},{"data.summary.type":"AddressObjectType"}],"created_on":{"$gte":todaydt}},{"data.summary.value":1,"created_on":1,"data.summary.type":1,"data.idns":1})

i = 0
for d in result:
  oid = d["_id"]
  value = d["data"]["summary"]["value"]     
  #print "VALUE: " + value
  type = d["data"]["summary"]["type"]
  cd = d["created_on"]
  cd2 = cd.strftime("%Y-%m-%dT%H:%M:%S") 
  createdby = d["data"]["idns"]

  x = Ob()

  # deal with ip addresses
  # sometimes this field is used for URLS
  if type=="AddressObjectType":
    j = value.find(":")
    jj = value.find("http")
    if j>-1 and jj==-1:
      value = value[:j]
    else:
      j=value.find("@")
      domainmatch = re.match(domainregex,value)
      if(domainmatch and j==-1):
        type="domain"
      else:
        type="email_address"

    ipv4match = re.match(ipv4regex,value)
    if(ipv4match):
      iptype="ipv4"
      type="ip_address"

    ipv4cidrmatch = re.match(ipv4cidrregex,value)
    if(ipv4cidrmatch):
      iptype="ipv4cidr"
      type="ip_address"
    
  if type=="DomainNameObjectType":
    domainmatch = re.match(domainregex,value)
    if(domainmatch):
      type="domain"

  # remove trailing whitespace
  value = value.strip()

  x.oID=oid
  x.oValue=value
  x.oType=type
  x.oCreatedDate=cd2
  x.oCreatedBy=createdby
  oList.append(x)
  i = i + 1
  if i > 100:
    break

# get matching activities (if any)
collection=db.activity.log

for y in oList:
  oid = y.oID[18:]
  result = collection.find({"stix_id":"fsisac:observable-" + oid})
  for e in result:
    stixid = e["stix_id"]
    action = e["action"]
    aList.append(stixid)

# if indicator is in deprecated list, ignore
i=0
for z in oList:
  if z.oID in aList: 
    print z.oID,"is DEPRECATED"
  else:
    content = content + todaystring + ",Soltra Edge," + z.oCreatedDate + "," + z.oType + "," + z.oValue + "," + z.oCreatedBy + "," + z.oID + "\n"
  i=i+1

#print content

# write to log file that will be picked up by splunk
with open("/var/log/pushtosplunk.log", "a") as myfile:
    myfile.write(content)
    myfile.close()

