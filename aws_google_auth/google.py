#!/usr/bin/env python
# -*- coding: utf8 -*-
from . import _version

import sys
import requests
import json
import base64
from bs4 import BeautifulSoup

# In Python3, the library 'urlparse' was renamed to 'urllib.parse'. For this to
# maintain compatibility with both Python 2 and Python 3, the import must be
# dynamically chosen based on the version detected.
if sys.version_info >= (3, 0):
    import urllib.parse as urlparse
else:
    import urlparse


# The U2F USB Library is optional, if it's there, include it.
try:
    from . import u2f
except ImportError:
    print("Failed to import U2F libraries, U2F login unavailable. Other "
          "methods can still continue.")


class Google:
    def __init__(self, config):
        """The Google object holds authentication state
        for a given session. You need to supply:

        username: FQDN Google username, eg first.last@example.com
        password: obvious
        idp_id: Google's assigned IdP identifier for your G-suite account
        sp_id: Google's assigned SP identifier for your AWS SAML app

        Optionally, you can supply:
        duration_seconds: number of seconds for the session to be active (max 3600)
        """

        self.version = _version.__version__
        self.config = config

    @property
    def login_url(self):
        return "https://accounts.google.com/o/saml2/initsso?idpid={}&spid={}&forceauthn=false".format(
            self.config.idp_id, self.config.sp_id)

    def do_login(self):
        self.session = requests.Session()
        self.session.headers['User-Agent'] = "AWS Sign-in/{} (Cevo aws-google-auth)".format(self.version)
        sess = self.session.get(self.login_url)
        sess.raise_for_status()

        # Collect information from the page source
        first_page = BeautifulSoup(sess.text, 'html.parser')
        gxf = first_page.find('input', {'name': 'gxf'}).get('value')
        self.cont = first_page.find('input', {'name': 'continue'}).get('value')
        page = first_page.find('input', {'name': 'Page'}).get('value')
        sign_in = first_page.find('input', {'name': 'signIn'}).get('value')
        account_login_url = first_page.find('form', {'id': 'gaia_loginform'}).get('action')

        payload = {
            'bgresponse': 'js_disabled',
            'checkConnection': '',
            'checkedDomains': 'youtube',
            'continue': self.cont,
            'Email': self.config.username,
            'gxf': gxf,
            'identifier-captcha-input': '',
            'identifiertoken': '',
            'identifiertoken_audio': '',
            'ltmpl': 'popup',
            'oauth': 1,
            'Page': page,
            'Passwd': '',
            'PersistentCookie': 'yes',
            'ProfileInformation': '',
            'pstMsg': 0,
            'sarp': 1,
            'scc': 1,
            'SessionState': '',
            'signIn': sign_in,
            '_utf8': '?',
        }

        # GALX is sometimes not there
        try:
            galx = first_page.find('input', {'name': 'GALX'}).get('value')
            payload['GALX'] = galx
        except:
            pass

        # POST to account login info page, to collect profile and session info
        sess = self.session.post(account_login_url, data=payload)
        sess.raise_for_status()
        self.session.headers['Referer'] = sess.url

        # Collect ProfileInformation, SessionState, signIn, and Password Challenge URL
        challenge_page = BeautifulSoup(sess.text, 'html.parser')

        profile_information = challenge_page.find('input', {'name': 'ProfileInformation'}).get('value')
        session_state = challenge_page.find('input', {'name': 'SessionState'}).get('value')
        sign_in = challenge_page.find('input', {'name': 'signIn'}).get('value')
        passwd_challenge_url = challenge_page.find('form', {'id': 'gaia_loginform'}).get('action')

        # Update the payload
        payload['SessionState'] = session_state
        payload['ProfileInformation'] = profile_information
        payload['signIn'] = sign_in
        payload['Passwd'] = self.config.password

        # POST to Authenticate Password
        sess = self.session.post(passwd_challenge_url, data=payload)
        sess.raise_for_status()
        response_page = BeautifulSoup(sess.text, 'html.parser')
        error = response_page.find(class_='error-msg')
        cap = response_page.find('input', {'name': 'logincaptcha'})

        # Were there any errors logging in? Could be invalid username or password
        # There could also sometimes be a Captcha, which means Google thinks you,
        # or someone using the same outbound IP address as you, is a bot.
        if error is not None:
            raise ValueError('Invalid username or password')

        self.check_extra_step(response_page)

        if cap is not None:
            raise ValueError('Captcha Required. Manually Login to remove this.')

        self.session.headers['Referer'] = sess.url

        if "selectchallenge/" in sess.url:
            sess = self.handle_selectchallenge(sess)

        # Was there an MFA challenge?
        if "challenge/totp/" in sess.url:
            sess = self.handle_totp(sess)
        elif "challenge/ipp/" in sess.url:
            sess = self.handle_sms(sess)
        elif "challenge/az/" in sess.url:
            sess = self.handle_prompt(sess)
        elif "challenge/sk/" in sess.url:
            sess = self.handle_sk(sess)
        elif "challenge/iap/" in sess.url:
            sess = self.handle_iap(sess)

        # ... there are different URLs for backup codes (printed)
        # and security keys (eg yubikey) as well
        # save for later
        self.session_state = sess

    @staticmethod
    def check_extra_step(response):
        extra_step = response.find(text='This extra step shows that it’s really you trying to sign in')
        if extra_step:
            print(extra_step)
            msg = response.find(id='contactAdminMessage')
            if msg:
                raise ValueError(msg.text)
            else:
                raise ValueError(response)

    def parse_saml(self):
        if self.session_state is None:
            raise RuntimeError('You must use do_login() before calling parse_saml()')

        parsed = BeautifulSoup(self.session_state.text, 'html.parser')
        try:
            saml_element = parsed.find('input', {'name': 'SAMLResponse'}).get('value')
        except:
            raise RuntimeError('Could not find SAML response, check your credentials')

        return base64.b64decode(saml_element)

    def handle_sk(self, sess):
        response_page = BeautifulSoup(sess.text, 'html.parser')
        challenge_url = sess.url.split("?")[0]

        challenges_txt = response_page.find('input', {'name': "id-challenge"}).get('value')
        challenges = json.loads(challenges_txt)

        facet_url = urlparse.urlparse(challenge_url)
        facet = facet_url.scheme + "://" + facet_url.netloc
        app_id = challenges["appId"]
        u2f_challenges = []
        for c in challenges["challenges"]:
            c["appId"] = app_id
            u2f_challenges.append(c)

        # Prompt the user up to attempts_remaining times to insert their U2F device.
        attempts_remaining = 5
        auth_response = None
        while True:
            try:
                auth_response = json.dumps(u2f.u2f_auth(u2f_challenges, facet))
                break
            except RuntimeWarning:
                print("No U2F device found. {} attempts remaining.".format(attempts_remaining))
                if attempts_remaining <= 0:
                    break
                else:
                    input("Insert your U2F device and press enter to try again...")
                    attempts_remaining -= 1

        # If we exceed the number of attempts, raise an error and let the program exit.
        if auth_response is None:
            raise RuntimeError("No U2F device found. Please check your setup.")

        payload = {
            'challengeId': response_page.find('input', {'name': 'challengeId'}).get('value'),
            'challengeType': response_page.find('input', {'name': 'challengeType'}).get('value'),
            'continue': response_page.find('input', {'name': 'continue'}).get('value'),
            'scc': response_page.find('input', {'name': 'scc'}).get('value'),
            'sarp': response_page.find('input', {'name': 'sarp'}).get('value'),
            'checkedDomains': response_page.find('input', {'name': 'checkedDomains'}).get('value'),
            'pstMsg': response_page.find('input', {'name': 'pstMsg'}).get('value'),
            'TL': response_page.find('input', {'name': 'TL'}).get('value'),
            'gxf': response_page.find('input', {'name': 'gxf'}).get('value'),
            'id-challenge': challenges_txt,
            'id-assertion': auth_response,
            'TrustDevice': 'on',
        }

        sess = self.session.post(challenge_url, data=payload)
        sess.raise_for_status()

        return sess

    def handle_sms(self, sess):
        response_page = BeautifulSoup(sess.text, 'html.parser')
        challenge_url = sess.url.split("?")[0]

        try:
            sms_token = raw_input("Enter SMS token: G-") or None
        except NameError:
            sms_token = input("Enter SMS token: G-") or None

        payload = {
            'challengeId': response_page.find('input', {'name': 'challengeId'}).get('value'),
            'challengeType': response_page.find('input', {'name': 'challengeType'}).get('value'),
            'continue': response_page.find('input', {'name': 'continue'}).get('value'),
            'scc': response_page.find('input', {'name': 'scc'}).get('value'),
            'sarp': response_page.find('input', {'name': 'sarp'}).get('value'),
            'checkedDomains': response_page.find('input', {'name': 'checkedDomains'}).get('value'),
            'pstMsg': response_page.find('input', {'name': 'pstMsg'}).get('value'),
            'TL': response_page.find('input', {'name': 'TL'}).get('value'),
            'gxf': response_page.find('input', {'name': 'gxf'}).get('value'),
            'Pin': sms_token,
            'TrustDevice': 'on',
        }

        # Submit IPP (SMS code)
        sess = self.session.post(challenge_url, data=payload)
        sess.raise_for_status()

        return sess

    def handle_prompt(self, sess):
        response_page = BeautifulSoup(sess.text, 'html.parser')
        challenge_url = sess.url.split("?")[0]

        data_key = response_page.find('div', {'data-api-key': True}).get('data-api-key')
        data_tx_id = response_page.find('div', {'data-tx-id': True}).get('data-tx-id')

        # Need to post this to the verification/pause endpoint
        await_url = "https://content.googleapis.com/cryptauth/v1/authzen/awaittx?alt=json&key=%s" % data_key
        await_body = {'txId': data_tx_id}

        print("Open the Google App, and tap 'Yes' on the prompt to sign in ...")

        self.session.headers['Referer'] = sess.url
        response = self.session.post(await_url, json=await_body)
        parsed = json.loads(response.text)

        payload = {
            'challengeId': response_page.find('input', {'name': 'challengeId'}).get('value'),
            'challengeType': response_page.find('input', {'name': 'challengeType'}).get('value'),
            'continue': response_page.find('input', {'name': 'continue'}).get('value'),
            'scc': response_page.find('input', {'name': 'scc'}).get('value'),
            'sarp': response_page.find('input', {'name': 'sarp'}).get('value'),
            'checkedDomains': response_page.find('input', {'name': 'checkedDomains'}).get('value'),
            'checkConnection': 'youtube:1295:1',
            'pstMsg': response_page.find('input', {'name': 'pstMsg'}).get('value'),
            'TL': response_page.find('input', {'name': 'TL'}).get('value'),
            'gxf': response_page.find('input', {'name': 'gxf'}).get('value'),
            'token': parsed['txToken'],
            'action': response_page.find('input', {'name': 'action'}).get('value'),
            'TrustDevice': 'on',
        }

        sess = self.session.post(challenge_url, data=payload)
        sess.raise_for_status()

        return sess

    def handle_totp(self, sess):
        response_page = BeautifulSoup(sess.text, 'html.parser')
        tl = response_page.find('input', {'name': 'TL'}).get('value')
        gxf = response_page.find('input', {'name': 'gxf'}).get('value')
        challenge_url = sess.url.split("?")[0]
        challenge_id = challenge_url.split("totp/")[1]

        try:
            mfa_token = raw_input("MFA token: ") or None
        except NameError:
            mfa_token = input("MFA token: ") or None

        if not mfa_token:
            raise ValueError("MFA token required for {} but none supplied.".format(self.config.username))

        payload = {
            'challengeId': challenge_id,
            'challengeType': 6,
            'continue': self.cont,
            'scc': 1,
            'sarp': 1,
            'checkedDomains': 'youtube',
            'pstMsg': 0,
            'TL': tl,
            'gxf': gxf,
            'Pin': mfa_token,
            'TrustDevice': 'on',
        }

        # Submit TOTP
        sess = self.session.post(challenge_url, data=payload)
        sess.raise_for_status()

        return sess

    def handle_iap(self, sess):
        response_page = BeautifulSoup(sess.text, 'html.parser')
        challenge_url = sess.url.split("?")[0]
        try:
            phone_number = raw_input('Enter your phone number:') or None
        except NameError:
            phone_number = input('Enter your phone number:') or None

        while True:
            try:
                choice = int(input('Type 1 to receive a code by SMS or 2 for a voice call:'))
            except ValueError:
                print("Not an integer! Try again.")
                continue
            else:
                if choice == 1:
                    send_method = 'SMS'
                elif choice == 2:
                    send_method = 'VOICE'
                else:
                    continue
                break

        payload = {
            'challengeId': response_page.find('input', {'name': 'challengeId'}).get('value'),
            'challengeType': response_page.find('input', {'name': 'challengeType'}).get('value'),
            'continue': self.cont,
            'scc': response_page.find('input', {'name': 'scc'}).get('value'),
            'sarp': response_page.find('input', {'name': 'sarp'}).get('value'),
            'checkedDomains': response_page.find('input', {'name': 'checkedDomains'}).get('value'),
            'pstMsg': response_page.find('input', {'name': 'pstMsg'}).get('value'),
            'TL': response_page.find('input', {'name': 'TL'}).get('value'),
            'gxf': response_page.find('input', {'name': 'gxf'}).get('value'),
            'phoneNumber': phone_number,
            'sendMethod': send_method,
        }

        # Submit phone number and desired method (SMS or voice call)
        sess = self.session.post(challenge_url, data=payload)
        sess.raise_for_status()

        response_page = BeautifulSoup(sess.text, 'html.parser')
        challenge_url = sess.url.split("?")[0]

        try:
            token = raw_input("Enter " + send_method + " token: G-") or None
        except NameError:
            token = input("Enter " + send_method + " token: G-") or None

        payload = {
            'challengeId': response_page.find('input', {'name': 'challengeId'}).get('value'),
            'challengeType': response_page.find('input', {'name': 'challengeType'}).get('value'),
            'continue': response_page.find('input', {'name': 'continue'}).get('value'),
            'scc': response_page.find('input', {'name': 'scc'}).get('value'),
            'sarp': response_page.find('input', {'name': 'sarp'}).get('value'),
            'checkedDomains': response_page.find('input', {'name': 'checkedDomains'}).get('value'),
            'pstMsg': response_page.find('input', {'name': 'pstMsg'}).get('value'),
            'TL': response_page.find('input', {'name': 'TL'}).get('value'),
            'gxf': response_page.find('input', {'name': 'gxf'}).get('value'),
            'pin': token,
        }

        # Submit SMS/VOICE token
        sess = self.session.post(challenge_url, data=payload)
        sess.raise_for_status()

        return sess

    def handle_selectchallenge(self, sess):
        response_page = BeautifulSoup(sess.text, 'html.parser')
        challenge_id = response_page.find('input', {'name': 'challengeId'}).get('value')

        payload = {
            'challengeId': challenge_id,
            'challengeType': response_page.find('input', {'name': 'challengeType'}).get('value'),
            'continue': response_page.find('input', {'name': 'continue'}).get('value'),
            'scc': response_page.find('input', {'name': 'scc'}).get('value'),
            'sarp': response_page.find('input', {'name': 'sarp'}).get('value'),
            'checkedDomains': response_page.find('input', {'name': 'checkedDomains'}).get('value'),
            'pstMsg': response_page.find('input', {'name': 'pstMsg'}).get('value'),
            'TL': response_page.find('input', {'name': 'TL'}).get('value'),
            'gxf': response_page.find('input', {'name': 'gxf'}).get('value'),
            'subAction': 'selectChallenge',
            'SendMethod': 'SMS',
        }

        # Choose SMS challenge
        sess = self.session.post('https://accounts.google.com/signin/challenge/ipp/' + str(challenge_id), data=payload)
        sess.raise_for_status()

        return sess
