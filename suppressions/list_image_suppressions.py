import time
import requests
import hashlib
import json
import hmac
from dotenv import load_dotenv
import os
#pip3 install pyjwt
import jwt

load_dotenv()

API_KEY = os.getenv("API_KEY")
API_SECRET=os.getenv("API_SECRET")
HOST=os.getenv("HOST")

if not API_KEY or not API_SECRET:
    raise RuntimeError(
        "API_KEY, API_SECRET and HOST must be set in the environment or .env file"
    )

def get_acks(image,token):
    endpoint = "https://" + HOST + "/api/v2/risks/acknowledge?skip_count=true&text_search="+image
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token
    }
    
    response = requests.get(endpoint, headers=headers)
    data = response.json()
    #print(data)
    field_list = data['result']
    for fields in field_list:
        print(
        f"{fields['issue_name']} "
        f"Resource: {fields['resource_cpe']} "
        f"Suppression Rule: {fields.get('suppression_rule_name', 'N/A')} "
        f"Author: {fields['author']} "
        f"Reason: {fields['comment']} "
        f"Created: {fields['date']} "
        f"Expiration Days: {fields['expiration_days']} "
        f"Days Until Exp: {fields['days_until_expiration']}"
    )
        
def get_token():
    endpoint='https://api.cloudsploit.com'
    path='/v2/tokens'
    url=endpoint + path
    timestamp=str(int(time.time() * 1000))
    method='POST'
    json_data = {
                "allowed_endpoints": [
                    "DELETE",
                    "GET",
                    "HEAD",
                    "OPTIONS",
                    "PATCH",
                    "POST",
                    "PUT",
                    "ANY"
                ],
                "validity": 240,
                "csp_roles":["jasonRole"]
            }

    body=json.dumps(json_data,separators=(',', ':'))

    string = timestamp + method + path + body

    sig = hmac.new(API_SECRET.encode('utf-8'), msg=string.encode('utf-8'), digestmod=hashlib.sha256).hexdigest()

    headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-API-Key": API_KEY,
            "X-Signature": sig,
            'X-Timestamp': timestamp}
    r = requests.post(url,data=body,headers=headers)
    data = r.json()
    #print(data)
    return data['data']

token = get_token()
get_acks('ubi8/toolbox',token)