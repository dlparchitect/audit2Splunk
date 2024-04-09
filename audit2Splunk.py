"""
audit2Splunk.py

PROVIDED AS-IS
The code is a) an example and b) provided as-is, we do not know your computing environment so you need to assess the script’s function and performance before implementing it.

Prerequisites
- Symantec DLP 16 RU1
- A Symantec DLP user with API and Administrative privileges 
- audit2Splunk.py is written in Python 3.8
- Python 3.8 Modules: json, requests, logging, datetime, timedelta 
- Splunk with HEC 

Modules: json, requests, logging, datetime, timedelta 

API Reference:
https://apidocs.securitycloud.symantec.com/#/doc?id=auditlog
"""

import json
import requests
from requests.auth import HTTPBasicAuth
from requests.structures import CaseInsensitiveDict
from requests.packages import urllib3
import logging
import logging.handlers
from datetime import datetime, timedelta


#Symantec DLP parameters
dlpEnforceURLBase = "https://EnforceHostName/ProtectManager/webservices/v2/auditlog"

# dlpEnforcePageSize controls the number of incidents to display
dlpEnforcePageSize = 10000

dlpheaders = CaseInsensitiveDict()
dlpheaders["Content-Type"] = "application/json"
#TODO Authorization Encoded DLP key follows the format [OptionalDLPRole]\[DLPUserName]:[DLPDomain]:[Password]
dlpheaders["Authorization"] = "Basic Encoded[OptionalDLPRole]\[DLPUserName]:[DLPDomain]:[Password]"


#Splunk Parameters
splunkURL = 'https://SplunkHostName:SplunkPort/services/collector'
splunkToken = 'SplunkToken-Goes-Here'
splunkHeaders =  {'Authorization': 'Splunk '+splunkToken}
splunkIndex = 'SplunkIndexNameGoesHere'
bolSplunkIt = True

#bolValidateSSL Validate HTTPS certificates
bolValidateSSL = False
#bolLoggingtoFile Log Results to a File
bolLoggingtoFile = True
loggingFile='audit2Splunk.log'

#Disable SSL warnings. DO NOT DO THIS IN PRODUCTION.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# File to store the last processed timestamp
LAST_PROCESSED_TIMESTAMP_FILE = 'audit2Splunk_last_processed_timestamp.txt'


if bolLoggingtoFile:
    logging.basicConfig(filename=loggingFile, level=logging.DEBUG)


def getAuditLogBatchLastProcessed():
    last_processed = get_last_processed_timestamp()
    
    queryAuditLogBatch = '''
    {
    "filter": {
        "filters": [            
            {
                "filterType": "localDateTime",
                "operandOne": {"name": "time"},
                "operator": "GTE",
                "operandTwoValues": ["'''+last_processed+'''"]
            }
        ],
        "filterType": "booleanLogic"
    },
    "orderBy": [
        {
            "field": {
                "name": "time"
            },
            "order": "ASC"
        }
    ],
    "page": {
        "type": "offset",
        "pageNumber": 1,
        "pageSize": '''+str(dlpEnforcePageSize)+'''
    }
    }
    '''
    #Call DLP Rest API to get a batch of Audit events. 
    print(queryAuditLogBatch)
    return requests.post(dlpEnforceURLBase, headers=dlpheaders, data=queryAuditLogBatch, verify=bolValidateSSL)


def indexSplunkIt(splunkevents):
    if bolSplunkIt:
        # Send the batch to Splunk
        # Concatenate the events into one payload, separated by newlines
        payload = '\n'.join(json.dumps(event) for event in splunkevents)
        
        response = requests.post(splunkURL, headers=splunkHeaders, data=payload, verify=bolValidateSSL)
        if response.status_code != 200:
            print(f"Failed to send batch: {response.text}")
            logging.debug(f"Failed to send batch: {response.text}")
        else:
            print("Batch sent successfully.")
            logging.debug("Batch sent successfully.")
            


def get_last_processed_timestamp():
    try:
        with open(LAST_PROCESSED_TIMESTAMP_FILE, 'r') as file:
            return file.read().strip()
    except FileNotFoundError:
        return "1970-01-01T00:00:00"  # Default to epoch if file does not exist

def update_last_processed_timestamp(timestamp):
    with open(LAST_PROCESSED_TIMESTAMP_FILE, 'w') as file:
        file.write(timestamp)
    logging.debug('Last audit log datetime is ' + str(timestamp))
    
def process_events(json_data):
    last_processed = get_last_processed_timestamp()
    new_events = []

    for event in json_data["auditLogs"]:
        if event["time"] > last_processed:
            new_events.append({"event": event})
    
    if new_events:
        indexSplunkIt(new_events)
        # Update the last processed timestamp with the time of the last event in this batch
        update_last_processed_timestamp(new_events[-1]["event"]["time"])
    else:
        print("No new events to process.")

if __name__ == "__main__":
    dlpAuditLogs = json.loads(getAuditLogBatchLastProcessed().content)
    process_events(dlpAuditLogs)