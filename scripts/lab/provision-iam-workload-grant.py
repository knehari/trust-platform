#!/usr/bin/env python3
"""Grant the actual Keycloak service-account subject one disposable lab CA."""
import os
import re
import subprocess

import requests

BASE = 'http://127.0.0.1:8180'
ISSUER = BASE + '/realms/trust-lab'
CA = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'

response = requests.post(BASE + '/realms/master/protocol/openid-connect/token', data={
    'client_id': 'admin-cli', 'grant_type': 'password', 'username': 'trust-lab-admin',
    'password': os.environ['TRUST_IAM_ADMIN_PASSWORD'],
}, timeout=15)
response.raise_for_status()
headers = {'Authorization': 'Bearer ' + response.json()['access_token']}
response = requests.get(BASE + '/admin/realms/trust-lab/clients',
                        params={'clientId': 'trust-workload-iam'}, headers=headers, timeout=15)
response.raise_for_status()
clients = [client for client in response.json() if client['clientId'] == 'trust-workload-iam']
if len(clients) != 1:
    raise RuntimeError('expected exactly one workload client')
response = requests.get(BASE + '/admin/realms/trust-lab/clients/' + clients[0]['id'] + '/service-account-user',
                        headers=headers, timeout=15)
response.raise_for_status()
subject = response.json()['id']
if not re.fullmatch(r'[0-9a-fA-F-]{36}', subject):
    raise RuntimeError('unexpected service-account subject')
sql = ("INSERT INTO management_reader_grant (issuer,subject,ca_id) VALUES "
       f"('{ISSUER}','{subject}','{CA}') ON CONFLICT DO NOTHING;\n")
subprocess.run(['docker', 'compose', '--env-file', '.env.iam.lab', '-f', 'compose.iam.lab.yaml',
                'exec', '-T', 'db', 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'trust_iam', '-d', 'trust_iam'],
               input=sql, text=True, check=True)
print('Provisioned one CA reader grant for the verified Keycloak workload subject.')
