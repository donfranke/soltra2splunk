# Soltra2Splunk
This is a python script that runs on a Soltra Edge node. It should be scheduled to run at a regular interval. It pulls the latest indicators (ip addresses, domains, and email addresses) from the intel databse and writes them to a log file. This log file can then be monitored by a Splunk light fowarder so that they are sent to an indexer, providing your Splunk instance with fresh FS-ISAC intel!

Soltra Edge is an intelligence sharing platform used by FS-ISAC. More information: http://www.dtcc.com/news/2014/december/03/soltra

# Usage
```
python soltra2splunk.py
```

# Requirements
* Python 2.6+ (not guaranteed to work with Python 3)
* pycurl
* pymongo
# netaddr
* Soltra Edge

# Notes
To get this script running on Soltra Edge, I had to reinstall the pymongo library using these steps:
* git clone git://github.com/mongodb/mongo-python-driver.git pymongo
* cd pymongo
* python setup.py install