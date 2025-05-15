import json

import requests

url = "https://www.virustotal.com/api/v3/files"

files = {
    "file": ("9.eml", open(r"C:\Users\Daemon\Downloads\public_phishing\phishing3\9.eml", "rb"), "message/rfc822")
}
"""payload = {
    "password": "123456"
}"""
headers = {
    "accept": "application/json",
    "x-apikey": "your_virustotal_api_key"
}

#response = requests.post(url, data=payload, files=files, headers=headers)

response = requests.post(url, files=files, headers=headers)


print(response.text)

datafile = json.loads(response.text)
url = "https://www.virustotal.com/api/v3/analyses/"+datafile['data']['id']

headers = {
    "accept": "application/json",
    "x-apikey": "your_virustotal_api_key"
}

response = requests.get(url, headers=headers)

print(response.text)