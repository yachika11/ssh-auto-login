# ssh-auto-login

1. prerequisite
- make sure you have installed python 2.7.12 or above

- With Virtual ENV: create virtual env & install requirements to run the script using below steps:
Linux platform:

```
cd ssh-auto-login && virtualenv auth_tunnel
source auth_tunnel/bin/activate
pip install -r requirements.txt
cd ..
```

- Without Virtual ENV : install requirements to run the script using below steps:
Linux platform:
```
pip install -r requirements.txt
cd ..
```

- generate ssh private and public key using using 'ssh keygen' command.
- fill up ./app/templates/host_info.json file with hostname/hostips, username, password and public key in the format like below.

```
{
  "host_IP1": {
    "username": "<username>",
    "password": "<password>",
    "ssh_public_key": "<ssh_public_key path>"
    "keys_dir": "keys",
    "ssh_key": "id_rsa.pub"
  }
}

OR

{
  "host_IP2": {
    "username": "<username>",
    "private_key": "my-key.pem",
    "ssh_public_key": "<ssh_public_key path>"
    "keys_dir": "keys",
    "ssh_key": "id_rsa.pub"
  }
}
```

2. To grant the SSH access to the current client of list of server instances use below command:
  
```
cd ssh_auto_login && python app/login.py -l "<IP>" "<IP>" -A "<grant>"
```
eg: ./login.py -l "1.2.3.4" "1.2.3.5" "1.2.3.6" -A "grant"

3. To revoke the access of list of server instances or any one server instance from the current client, use below command:

```
cd ssh_auto_login && python app/login.py -l "<IP>" "<IP>" -A "<revoke>"
```
eg: ./login.py -l "1.2.3.4" "1.2.3.5" "1.2.3.6" -A "revoke"

```
NOTE: you just need to fill the IP address of server instances in host_info.json and it's username and password 

and then run the code by upper mentioned command
```