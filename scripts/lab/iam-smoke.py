#!/usr/bin/env python3
"""Exercise actual Keycloak authorization-code PKCE and client-credentials flows."""
import base64
import hashlib
from html.parser import HTMLParser
import json
import os
import secrets
import sys
from urllib.parse import parse_qs, urlparse

import requests

ISSUER = 'http://127.0.0.1:8180/realms/trust-lab'
API = 'http://127.0.0.1:8181/v1'
CA = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
HIDDEN = 'ffffffff-ffff-4fff-8fff-ffffffffffff'
CALLBACK = 'http://127.0.0.1:5273/auth/callback'


class LoginForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form' and attrs.get('id') == 'kc-form-login':
            self.action = attrs.get('action')


def check(condition, message):
    if not condition:
        raise RuntimeError(message)
    print('PASS', message)


def claims(token):
    header, payload, _ = token.split('.')
    def part(value):
        return json.loads(base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)))
    return part(header), part(payload)


def human_token(username, password):
    session = requests.Session()
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    response = session.get(ISSUER + '/protocol/openid-connect/auth', params={
        'client_id': 'trust-console-iam', 'response_type': 'code', 'scope': 'openid profile',
        'redirect_uri': CALLBACK, 'state': secrets.token_urlsafe(16),
        'code_challenge': challenge, 'code_challenge_method': 'S256',
    }, timeout=15)
    check(response.status_code == 200, f'{username} authorization page')
    form = LoginForm()
    form.feed(response.text)
    check(form.action is not None, f'{username} login form')
    # Requests enforces Secure over HTTPS; browsers permit loopback secure contexts.
    # The lab intentionally exposes only loopback HTTP, so mirror that exception.
    for cookie in session.cookies:
        cookie.secure = False
    response = session.post(form.action, data={'username': username, 'password': password},
                            allow_redirects=False, timeout=15)
    if response.status_code not in (302, 303):
        print('Login response:', response.status_code,
              'invalid credentials' if 'Invalid username or password' in response.text else 'other login page',
              'title:', response.text.split('<title>')[1].split('</title>')[0] if '<title>' in response.text else 'none',
              'form URL:', urlparse(form.action).path,
              'error:', response.text.split('kc-feedback-text')[1][:300] if 'kc-feedback-text' in response.text else 'none')
    check(response.status_code in (302, 303), f'{username} authenticated redirect')
    location = response.headers.get('Location', '')
    if not location.startswith(CALLBACK):
        print('Redirect destination:', urlparse(location).path)
    check(location.startswith(CALLBACK), f'{username} exact callback')
    code = parse_qs(urlparse(location).query).get('code', [None])[0]
    check(code is not None, f'{username} authorization code')
    response = session.post(ISSUER + '/protocol/openid-connect/token', data={
        'grant_type': 'authorization_code', 'client_id': 'trust-console-iam',
        'code': code, 'redirect_uri': CALLBACK, 'code_verifier': verifier,
    }, timeout=15)
    check(response.ok, f'{username} PKCE token exchange')
    return response.json()['access_token'], response.json().get('id_token')


def status(token, path):
    return requests.get(API + path, headers={'Authorization': 'Bearer ' + token}, timeout=15)


def main():
    check(requests.get(API + '/ready', timeout=15).ok, 'API ready')
    check(requests.get(API + '/cas', timeout=15).status_code == 401, 'anonymous read denied')
    identities = []
    for username, role in [('maker', 'trust-profile-maker'), ('checker', 'trust-profile-checker')]:
        token, id_token = human_token(username, os.environ[f'TRUST_IAM_{username.upper()}_PASSWORD'])
        header, body = claims(token)
        check(header['typ'] == 'at+jwt' and body['azp'] == 'trust-console-iam', f'{username} access token type/client')
        check('trust-api' in body['aud'] and role in body['roles'] and 'trust-ca-reader' in body['roles'], f'{username} audience/roles')
        other_role = 'trust-profile-checker' if username == 'maker' else 'trust-profile-maker'
        check(other_role not in body['roles'], f'{username} cannot carry the other approval role')
        check(body['ca_ids'] == [CA], f'{username} CA scope')
        check(status(token, '/cas/' + CA).status_code == 200, f'{username} granted CA read')
        check(status(token, '/cas/' + HIDDEN).status_code == 403, f'{username} unrelated CA denied')
        check(id_token is not None and status(id_token, '/cas').status_code == 401, f'{username} ID token denied')
        identities.append(body['sub'])
    check(identities[0] != identities[1], 'maker/checker have distinct authenticated subjects')
    response = requests.post(ISSUER + '/protocol/openid-connect/token', data={
        'grant_type': 'client_credentials', 'client_id': 'trust-workload-iam',
        'client_secret': os.environ['TRUST_IAM_WORKLOAD_SECRET'],
    }, timeout=15)
    check(response.ok, 'workload client credentials exchange')
    token = response.json()['access_token']
    header, body = claims(token)
    check(header['typ'] == 'at+jwt' and body['azp'] == 'trust-workload-iam', 'workload access token type/client')
    check(body['roles'] == ['trust-ca-workload-reader'] and body['ca_ids'] == [CA], 'workload least-privilege role/scope')
    response = status(token, '/cas')
    if '--workload-granted' in sys.argv:
        check(response.status_code == 200 and len(response.json()) == 1,
              'granted workload sees exactly one CA')
        check(status(token, '/cas/' + CA).status_code == 200,
              'granted workload CA detail readable')
    else:
        check(response.status_code == 200 and response.json() == [], 'ungranted workload sees no CA')
        check(status(token, '/cas/' + CA).status_code == 403, 'ungranted workload CA detail denied')
    check(status(token, '/cas/' + HIDDEN).status_code == 403, 'workload unrelated CA denied')
    print('IAM smoke passed. Workload subject:', body['sub'])


if __name__ == '__main__':
    main()
