#!/usr/bin/python3

# Author : Marc Hortelano
# Date : 13/01/2021
# Descripcion: Te permite hacer una creación masiva de usuarios en matrix

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


import requests, sys, time, json, getopt
from pwn import *

## Variables que hay que modificar
url_domain = 'matrix.domain.tld' # Modificar
port = '443' # Modificar
user = "admin" # Modificar
password = "1234" # Modificar

## Variables Globales 
url = "https://{}:{}".format(url_domain,port)
# proxy = {"http":"http://172.0.0.1:8080"}  # Burp Suite


def get_token(url): # es necessario obtener el token de un usuario administrador para gestionar el servidor
    
    url_login = "{}/_matrix/client/r0/login".format(url)
    headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
            }
    # Parametros 
    payload = {
            "type":"m.login.password", 
            "user":user, 
            "password":password
            }
    
    p1 = log.progress("Login")
    p1.status("Introduciendo creds...")

    r = requests.post(url_login, headers=headers, json=payload, verify=False) # petición post 
    
    # Comporvación
    if r.status_code == 200: 
        data = r.json()
        token = data['access_token']
        print(r.status_code)
        p1.success("Token Obtenido")
    
    else: 
        p1.failure("Error al login")
        sys.exit(1)

    return token

def create_users(token,fichero): # Creación de usuarios a partir de un fichero separado por comas
    
    p1 = log.progress("Creación usuario")

    header= { 
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization' : 'Bearer {}'.format(token) 
            }
    ## Fichero: 
    # Nombre y apellido, email
    ## ejemplo: el fichero users.txt
    
    with open(fichero) as usuarios:
        for info in usuarios:
            full_name = re.findall(r'^(.+),',info) ## Extraer el nombre del usuario 
            email = re.findall(r', ([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)',info) ## Extraer el email
            pswd = '{0}!2021'.format(re.sub("[ ]", "_",full_name[0].lower())) ## generar passwd a apartir del nombre y apellido
            username = full_name[0].lower().replace(" ", "")

            p1.status("Generando usuario {}".format(full_name[0]))
            
            url_reg = '{0}/_synapse/admin/v2/users/@{1}:{2}'.format(url,username,url_domain)
            users = """
            {
                "displayname":"%s", 
                "password": "%s", 
                "threepids": [
                    {
                        "medium": "email", 
                        "address":"{%s}"
                    }
                ]
            }""" % (full_name[0],pswd,email) 
            
            r = requests.put(url_reg, data=users, headers=header, verify=False)
            time.sleep(1) ## Ponemos tiempo de 2s para que las req se hagan correctamente
    p1.success("Usuarios creados")

def list_users(rmin,rmax,tocken):
    
    p1 = log.progress("Lista de usuarios")

    url_list = '{0}/_synapse/admin/v2/users?from={1}&limit={2}&guests=false'.format(url,rmin,rmax)
    
    header= { 
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization' : 'Bearer {}'.format(token) 
            }
    
    p1.status("Buscando usuarios")
    time.sleep(3)
    
    r = requests.get(url_list, headers=header, verify=False)
    content = json.dumps(json.loads(r.content.decode()),indent=4)
    print(content)

def main(argv,token):
    path = ''
    try:
        opts, args = getopt.getopt(argv,"hlf:",["list","file="])
    except getopt.GetoptError:
        print ('{} [-l --list (listar usuarios)] / [ -f --file= /path/users-list.txt (añadir usuarios)]'.format(sys.argv[0]))
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('{} [-l --list (listar usuarios)] / [ -f --file= /path/users-list.txt (añadir usuarios)]'.format(sys.argv[0]))
            sys.exit(0)
        elif opt in ("-l", "--list"):
            rmin = input("Introduce rango inicial: [0] ")
            rmax = input("Introduce rango final: ")

            list_users(str(rmin),str(rmax),token)

        elif opt in ("-f", "--file"):
             path = arg

             create_users(token,path)

if __name__ == "__main__":

    token = get_token(url) # Funcion para obtener el token

    main(sys.argv[1:],token)
