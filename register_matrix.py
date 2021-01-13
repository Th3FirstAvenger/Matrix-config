# Author : Marc Hortelano
# Date : 13/01/2021
'''
## GETTING ACCESS_TOCKEN
curl -XGET "https://my.matrix.host:8448/_matrix/client/r0/login"

```output
{
    "flows": [
        {
            "type": "m.login.password"
        }
    ]
}
```
curl -XPOST -d \
    '{"type":"m.login.password", "user":"myadminuser", "password":"mypassword"}' \
    "https://my.matrix.host:8448/_matrix/client/r0/login"
```output
{
    "access_token": "{ACCESS_TOKEN}",
    "device_id": "DDKBZUMSNV",
    "home_server": "my.matrix.host",
    "user_id": "@myadminuser:my.matrix.host",
    "well_known": {
        "m.homeserver": {
            "base_url": "https://my.matrix.host/"
        }
    }
}
```

## LIST USERS

curl --header "Authorization: Bearer {ACCESS_TOKEN}" -XGET \
    https://my.matrix.host:8448/_synapse/admin/v2/users?from=0&limit=10&guests=false

## QUERY USER

curl --header "Authorization: Bearer {ACCESS_TOKEN}" -XGET \
    https://my.matrix.host:8448/_synapse/admin/v2/users/@test:my.matrix.host

## MODIFY OR CREATE A USER

curl --header "Authorization: Bearer {ACCESS_TOKEN}" -XPUT -d \
    '{"displayname":"Display Name", "password": "password", "threepids": [{"medium": "email", "address":"useremail@example.com"}] }' \
    https://my.matrix.host:8448/_synapse/admin/v2/users/@newuser:my.matrix.host
'''

#/usr/bin/python3

import requests, threading, os, time
from pwn import *

url_domain = ''
port = ''
proxy = {"http":"http://172.0.0.1:8080"}

url = "http://{}:{}".format(url_domain,port)

user = ""
password = ""



def get_token(url):
    
    url_login = "{}/_matrix/client/r0/login".format(url)
    headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
            }
    
    payload = {"type":"m.login.password", "user":"admin", "password":"1234QWer*1234*"}
    
    p1 = log.progress("Login")
    p1.status("Introduciendo creds...")

    r = requests.post(url_login, headers=headers, json=payload, verify=False)

    if r.status_code == 200: 
        data = r.json()
        token = data['access_token']

        p1.success("Token Obtenido")
    
    else: 
        p1.failure("Error al login")
        sys.exit(1)

    return token

print(get_token(url))

