""" purpose:  pulls latest intel from Soltra Edge Mongo database
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
    updated:  16 Jun 2016, Don Franke - added validate function to filter out RFC 1918/1122 IPs
    updated:  10 Aug 2016, Don Franke - cleaned up domain regex, broke out domain and ip collection
                                          into separate routines for support/readability
"""
import re
from pymongo import MongoClient
import socket
import pycurl
from StringIO import StringIO
import sys
import time
from datetime import datetime, timedelta
from netaddr import *

# constants
NUM_HOURS_OF_INTEL=(7*24)
DATA_LIMIT = 50000

# global variables
oList = []
aList = []

def validate(itype, ivalue):
  isValid=True
  if(itype=="ip_address"):
    try:
      ip = IPAddress(ivalue)

      ipset = IPSet(['10.0.0.0/8']) # RFC 1918
      isValid = not (ip in ipset)

      ipset = IPSet(['172.16.0.0/12']) # RFC 1918
      isValid = not (ip in ipset)

      ipset = IPSet(['192.168.0.0/16']) # RFC 1918
      isValid = not (ip in ipset)

      ipset = IPSet(['127.0.0.1/32']) # RFC 1122
      isValid = not (ip in ipset)

    except:
        isValid = False

  return isValid

class Ob:
    oID=""
    oValue=""
    oType=""
    iCreatedDate=""
    oCreatedBy=""

# get today's date
todaystring = str(datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"))
validate("ipaddress","192.168.100.200")

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
domainregex="^([a-zA-Z0-9-_]{1,61})(\.[a-zA-Z0-9-_]{1,61}){1,5}?$"

# ============ get ip addresses =============
# query mongo db
result = collection.find({"data.summary.type":"AddressObjectType","created_on":{"$gte":todaydt}},{"data.summary.value":1,"created_on":1,"data.summary.type":1,"data.idns":1}).limit(DATA_LIMIT)

# iterate ip addresses
for d in result:
  oid = d["_id"]
  value = d["data"]["summary"]["value"]     
  type = d["data"]["summary"]["type"]
  value = value.strip()
  cd = d["created_on"]
  cd2 = cd.strftime("%Y-%m-%dT%H:%M:%S") 
  createdby = d["data"]["idns"]
  x = Ob()

  ipv4match = re.match(ipv4regex,value)
  if(ipv4match):
    iptype="ipv4"
    type="ip_address"

  ipv4cidrmatch = re.match(ipv4cidrregex,value)
  if(ipv4cidrmatch):
    iptype="ipv4cidr"
    type="ip_address"
    
  x.oID=oid
  x.oValue=value
  x.oType=type
  x.oCreatedDate=cd2
  x.oCreatedBy=createdby
  oList.append(x)

# ============ get domains =============
result = collection.find({"data.summary.type":"DomainNameObjectType","created_on":{"$gte":todaydt}},{"data.summary.value":1,"created_on":1,"data.summary.type":1,"data.idns":1}).limit(DATA_LIMIT)

# iterate domains
for d in result:
  oid = d["_id"]
  value = d["data"]["summary"]["value"]
  value = value.strip()
  value = value.lower()
  type = d["data"]["summary"]["type"]
  cd = d["created_on"]
  cd2 = cd.strftime("%Y-%m-%dT%H:%M:%S")
  createdby = d["data"]["idns"]
  x = Ob()

  domainmatch = re.match(domainregex,value)
  if(domainmatch):
    type="domain"
  else:
    print "REGEX MATCH FAILED for",value
  x.oID=oid
  x.oValue=value
  x.oType=type
  x.oCreatedDate=cd2
  x.oCreatedBy=createdby
  oList.append(x)

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
for z in oList:
  if (z.oID in aList): 
    pass
  else:
    if z.oType=="ip_address" or z.oType=="domain":
      if(z.oValue.find("/")==-1 and z.oValue.count(".")==3 and validate(z.oType,z.oValue)):
        content = content + todaystring + ",Soltra Edge," + z.oCreatedDate + "," + z.oType + "," + z.oValue + "," + z.oCreatedBy + "," + z.oID + "\n"
      else:
        pass

  # print content
  
# write to log file that will be picked up by splunk
with open("/var/log/pushtosplunk.log", "a") as myfile:
    myfile.write(content)
    myfile.close()


