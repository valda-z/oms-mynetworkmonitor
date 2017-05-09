#!/usr/bin/python
import pyping
import json
import requests
import datetime
import hashlib
import hmac
import base64
import uuid
import os

ping_rtt = 0.0
ping_ok = False
headers = {
}
uri = ""
datadir = "pingdata/"

try:
    response = pyping.ping('speed1.jmnet.cz')
    if response.ret_code == 0:
        ping_ok = True
        ping_rtt = (float(response.avg_rtt) / 2.0)
    else:
        ping_ok = False
except:
    ping_ok = False

print "PING: ", ping_rtt

tm_created = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

# Update the customer ID to your Operations Management Suite workspace ID
customer_id = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

# For the shared key, use either the primary or the secondary Connected Sources client authentication key   
shared_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=="

# The log type is the name of the event that is being submitted
log_type = 'NetworkLatencyMonitor'

# An example JSON web monitor object
json_data = {
    "MyLocality": "DOMA",
    "PingSuccess": ping_ok,
    "PingRTT": ping_rtt,
    "TimeCaptured": tm_created
}
body = json.dumps(json_data)

#####################
######Functions######  
#####################

# Build the API signature
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash).encode('utf-8')  
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest())
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization

# Build and send a request to the POST API
def post_data(customer_id, shared_key, body, log_type):
    global headers
    global uri
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date,
        'time-generated-field': 'TimeCaptured'
    }

    response = requests.post(uri,data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        print 'Accepted'
    else:
        print "Response code: {}".format(response.status_code)
        raise Exception("Response code: {}".format(response.status_code))

####### try to send data to OMS
try:
    post_data(customer_id, shared_key, body, log_type)
except Exception as error:
    print "ERROR: " + repr(error)
    fname = datadir + str(uuid.uuid4()) + ".json"
    post_data = {
        "body": body
    }
    wfile = open(fname, "w")
    wfile.write(json.dumps(post_data))
    wfile.close()

####### try to send not send requests
for file in os.listdir(datadir):
    if(file.endswith(".json")):
        print "... SENDING ... " + file
        rfile = open(datadir + file, "r")
	tosend = json.loads(rfile.read())
        rfile.close()
        post_data(customer_id, shared_key, tosend["body"], log_type)
        os.remove(datadir + file)

