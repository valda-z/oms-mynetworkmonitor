#!/usr/bin/python
import pyspeedtest
import json
import requests
import datetime
import hashlib
import hmac
import base64
import uuid
import os

headers = {
}
uri = ""
datadir = "speeddata/"

speed_ok = False
speed_ping = 0
speed_down = 0
speed_up = 0

try:
    st = pyspeedtest.SpeedTest()
    st.host = 'speed1.jmnet.cz'
    st.runs = 1
    speed_ping = st.ping()
    speed_down = st.download()
    speed_up = st.upload()
    speed_ok = True
    print ">> SPEED: ", speed_ping, speed_down, speed_up
except:
    speed_ok = False

tm_created = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

# Update the customer ID to your Operations Management Suite workspace ID
customer_id = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

# For the shared key, use either the primary or the secondary Connected Sources client authentication key   
shared_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=="

# The log type is the name of the event that is being submitted
log_type = 'NetworkBandwithMonitor'

# An example JSON web monitor object
json_data = {
    "MyLocality": "DOMA",
    "SpeedSuccess": speed_ok,
    "SpeedPing": speed_ping,
    "SpeedDownload": speed_down,
    "SpeedUpload": speed_up,
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

