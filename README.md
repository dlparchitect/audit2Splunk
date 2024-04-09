# audit2Splunk
Example of sending the Symantec DLP Audit trail events to Splunk for consolidation, reporting, correlation, long-term archival, and other relevant use cases.

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
