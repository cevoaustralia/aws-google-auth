#!/usr/bin/env python
# -*- coding: utf8 -*-
from __future__ import print_function

import base64
import io
import json
import logging
import os
import re
import sys

import requests
from PIL import Image
from distutils.spawn import find_executable
from bs4 import BeautifulSoup
from requests import HTTPError
from six import print_ as print
from six.moves import urllib_parse, input

from aws_google_auth import _version

# The U2F USB Library is optional, if it's there, include it.
try:
    from aws_google_auth import u2f
except ImportError:
    logging.info("Failed to import U2F libraries, U2F login unavailable. "
                 "Other methods can still continue.")


class ExpectedGoogleException(Exception):
    def __init__(self, *args):
        super(ExpectedGoogleException, self).__init__(*args)


class Google:
    def __init__(self, config, save_failure):
        """The Google object holds authentication state
        for a given session. You need to supply:

        username: FQDN Google username, eg first.last@example.com
        password: obvious
        idp_id: Google's assigned IdP identifier for your G-suite account
        sp_id: Google's assigned SP identifier for your AWS SAML app

        Optionally, you can supply:
        duration_seconds: number of seconds for the session to be active (max 43200)
        """

        self.version = _version.__version__
        self.config = config
        self.base_url = 'https://accounts.google.com'
        self.save_failure = save_failure
        self.session_state = None

    @property
    def login_url(self):
        return self.base_url + "/o/saml2/initsso?idpid={}&spid={}&forceauthn=false".format(
            self.config.idp_id, self.config.sp_id)

    def check_for_failure(self, sess):

        if isinstance(sess.reason, bytes):
            # We attempt to decode utf-8 first because some servers
            # choose to localize their reason strings. If the string
            # isn't utf-8, we fall back to iso-8859-1 for all other
            # encodings. (See PR #3538)
            try:
                reason = sess.reason.decode('utf-8')
            except UnicodeDecodeError:
                reason = sess.reason.decode('iso-8859-1')
        else:
            reason = sess.reason

        if sess.status_code == 403:
            raise ExpectedGoogleException(u'{} accessing {}'.format(
                reason, sess.url))

        try:
            sess.raise_for_status()
        except HTTPError as ex:

            if self.save_failure:
                logging.exception("Saving failure trace in 'failure.html'", ex)
                with open("failure.html", 'w') as out:
                    out.write(sess.text)

            raise ex

        return sess

    def post(self, url, data=None, json=None):
        try:
            response = self.check_for_failure(self.session.post(url, data=data, json=json))
        except requests.exceptions.ConnectionError as e:
            logging.exception(
                'There was a connection error, check your network settings.', e)
            sys.exit(1)
        except requests.exceptions.Timeout as e:
            logging.exception('The connection timed out, please try again.', e)
            sys.exit(1)
        except requests.exceptions.TooManyRedirects as e:
            logging.exception('The number of redirects exceeded the maximum '
                              'allowed.', e)
            sys.exit(1)

        return response

    def get(self, url):
        try:
            response = self.check_for_failure(self.session.get(url))
        except requests.exceptions.ConnectionError as e:
            logging.exception(
                'There was a connection error, check your network settings.', e)
            sys.exit(1)
        except requests.exceptions.Timeout as e:
            logging.exception('The connection timed out, please try again.', e)
            sys.exit(1)
        except requests.exceptions.TooManyRedirects as e:
            logging.exception('The number of redirects exceeded the maximum '
                              'allowed.', e)
            sys.exit(1)

        return response

    @staticmethod
    def parse_error_message(sess):
        response_page = BeautifulSoup(sess.text, 'html.parser')
        error = response_page.find('span', {'id': 'errorMsg'})

        if error is None:
            return None
        else:
            return error.text

    @staticmethod
    def find_key_handles(input, challengeTxt):
        keyHandles = []
        typeOfInput = type(input)
        if typeOfInput == dict:  # parse down a dict
            for item in input:
                keyHandles.extend(Google.find_key_handles(input[item], challengeTxt))

        elif typeOfInput == list:  # looks like we've hit an array - iterate it
            array = list(filter(None, input))  # remove any None type objects from the array
            for item in array:
                typeValue = type(item)
                if typeValue == list:  # another array - recursive call
                    keyHandles.extend(Google.find_key_handles(item, challengeTxt))
                elif typeValue == int or typeValue == bool:  # ints bools etc we don't care
                    continue
                else:  # we went a string or unicode here (python 3.x lost unicode global)
                    try:  # keyHandle string will be base64 encoded -
                        # if its not an exception is thrown and we continue as its not the string we're after
                        base64UrlEncoded = base64.urlsafe_b64encode(base64.b64decode(item))
                        if base64UrlEncoded != challengeTxt:  # make sure its not the challengeTxt - if it not return it
                            keyHandles.append(base64UrlEncoded)
                    except:
                        pass
        return keyHandles

    @staticmethod
    def find_app_id(inputString):
        try:
            searchResult = re.search('"appid":"[a-z://.-_]+"', inputString).group()
            searchObject = json.loads('{' + searchResult + '}')
            return str(searchObject['appid'])
        except:
            logging.exception('Was unable to find appid value in googles SAML page')
            sys.exit(1)

    def do_login(self):
        self.session = requests.Session()
        self.session.headers['User-Agent'] = "AWS Sign-in/{} (Cevo aws-google-auth)".format(self.version)
        sess = self.get(self.login_url)

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

        if self.config.bg_response:
            payload['bgresponse'] = self.config.bg_response

        # GALX is sometimes not there
        try:
            galx = first_page.find('input', {'name': 'GALX'}).get('value')
            payload['GALX'] = galx
        except:
            pass

        # POST to account login info page, to collect profile and session info
        sess = self.post(account_login_url, data=payload)

        self.session.headers['Referer'] = sess.url

        # Collect ProfileInformation, SessionState, signIn, and Password Challenge URL
        challenge_page = BeautifulSoup(sess.text, 'html.parser')

        # Handle the "old-style" page
        if challenge_page.find('form', {'id': 'gaia_loginform'}):
            form = challenge_page.find('form', {'id': 'gaia_loginform'})
            passwd_challenge_url = form.get('action')
        else:
            # sometimes they serve up a different page
            logging.info("Handling new-style login page")
            form = challenge_page.find('form', {'id': 'challenge'})
            passwd_challenge_url = 'https://accounts.google.com' + form.get('action')

        for tag in form.find_all('input'):
            if tag.get('name') is None:
                continue

            payload[tag.get('name')] = tag.get('value')

        # Update the payload
        payload['Passwd'] = self.config.password

        # POST to Authenticate Password
        sess = self.post(passwd_challenge_url, data=payload)

        response_page = BeautifulSoup(sess.text, 'html.parser')
        error = response_page.find(class_='error-msg')
        cap = response_page.find('input', {'name': 'logincaptcha'})

        # Were there any errors logging in? Could be invalid username or password
        # There could also sometimes be a Captcha, which means Google thinks you,
        # or someone using the same outbound IP address as you, is a bot.
        if error is not None:
            raise ExpectedGoogleException('Invalid username or password')

        if "signin/rejected" in sess.url:
            raise ExpectedGoogleException(u'''Default value of parameter `bgresponse` has not accepted.
                Please visit login URL {}, open the web inspector and execute document.bg.invoke() in the console.
                Then, set --bg-response to the function output.'''.format(self.login_url))

        self.check_extra_step(response_page)

        # Process Google CAPTCHA verification request if present
        if cap is not None:
            self.session.headers['Referer'] = sess.url

            sess = self.handle_captcha(sess, payload)

            response_page = BeautifulSoup(sess.text, 'html.parser')
            error = response_page.find(class_='error-msg')
            cap = response_page.find('input', {'name': 'logincaptcha'})

            # Were there any errors logging in? Could be invalid username or password
            # There could also sometimes be a Captcha, which means Google thinks you,
            # or someone using the same outbound IP address as you, is a bot.
            if error is not None:
                raise ExpectedGoogleException('Invalid username or password')

            self.check_extra_step(response_page)

            if cap is not None:
                raise ExpectedGoogleException(
                    'Invalid captcha')

        self.session.headers['Referer'] = sess.url

        if "selectchallenge/" in sess.url:
            sess = self.handle_selectchallenge(sess)

        # Was there an MFA challenge?
        if "challenge/totp/" in sess.url:
            error_msg = ""
            while error_msg is not None:
                sess = self.handle_totp(sess)
                error_msg = self.parse_error_message(sess)
                if error_msg is not None:
                    logging.error(error_msg)
        elif "challenge/ipp/" in sess.url:
            sess = self.handle_sms(sess)
        elif "challenge/az/" in sess.url:
            sess = self.handle_prompt(sess)
        elif "challenge/sk/" in sess.url:
            sess = self.handle_sk(sess)
        elif "challenge/iap/" in sess.url:
            sess = self.handle_iap(sess)
        elif "challenge/ootp/5" in sess.url:
            raise NotImplementedError(
                'Offline Google App OOTP not implemented')

        # ... there are different URLs for backup codes (printed)
        # and security keys (eg yubikey) as well
        # save for later
        self.session_state = sess

    @staticmethod
    def check_extra_step(response):
        extra_step = response.find(text='This extra step shows that it’s really you trying to sign in')
        if extra_step:
            if response.find(id='contactAdminMessage'):
                raise ValueError(response.find(id='contactAdminMessage').text)

    def parse_saml(self):
        if self.session_state is None:
            raise RuntimeError('You must use do_login() before calling parse_saml()')

        parsed = BeautifulSoup(self.session_state.text, 'html.parser')
        try:
            saml_element = parsed.find('input', {'name': 'SAMLResponse'}).get('value')
        except:

            if self.save_failure:
                logging.error("SAML lookup failed, storing failure page to "
                              "'saml.html' to assist with debugging.")
                with open("saml.html", 'w') as out:
                    out.write(str(self.session_state.text.encode('utf-8')))

            raise ExpectedGoogleException('Something went wrong - Could not find SAML response, check your credentials or use --save-failure-html to debug.')

        return base64.b64decode(saml_element)

    def handle_captcha(self, sess, payload):
        response_page = BeautifulSoup(sess.text, 'html.parser')

        # Collect ProfileInformation, SessionState, signIn, and Password Challenge URL
        profile_information = response_page.find('input', {
            'name': 'ProfileInformation'
        }).get('value')
        session_state = response_page.find('input', {
            'name': 'SessionState'
        }).get('value')
        sign_in = response_page.find('input', {'name': 'signIn'}).get('value')
        passwd_challenge_url = response_page.find('form', {
            'id': 'gaia_loginform'
        }).get('action')

        # Update the payload
        payload['SessionState'] = session_state
        payload['ProfileInformation'] = profile_information
        payload['signIn'] = sign_in
        payload['Passwd'] = self.config.password

        # Get all captcha challenge tokens and urls
        captcha_container = response_page.find('div', {'class': 'captcha-container'})
        captcha_logintoken = captcha_container.find('input', {'name': 'logintoken'}).get('value')
        captcha_url = captcha_container.find('input', {'name': 'url'}).get('value')
        captcha_logintoken_audio = captcha_container.find('input', {'name': 'logintoken_audio'}).get('value')
        captcha_url_audio = captcha_container.find('input', {'name': 'url_audio'}).get('value')

        open_image = True

        # Check if there is a display utility installed as Image.open(f).show() do not raise any exception if not
        # if neither xv or display are available just display the URL for the user to visit.
        if os.name == 'posix' and sys.platform != 'darwin':
            if find_executable('xv') is None and find_executable('display') is None:
                open_image = False

        print("Please visit the following URL to view your CAPTCHA: {}".format(captcha_url))

        if open_image:
            try:
                with requests.get(captcha_url) as url:
                    with io.BytesIO(url.content) as f:
                        Image.open(f).show()
            except Exception:
                pass

        try:
            captcha_input = raw_input("Captcha (case insensitive): ") or None
        except NameError:
            captcha_input = input("Captcha (case insensitive): ") or None

        # Update the payload
        payload['logincaptcha'] = captcha_input
        payload['logintoken'] = captcha_logintoken
        payload['url'] = captcha_url
        payload['logintoken_audio'] = captcha_logintoken_audio
        payload['url_audio'] = captcha_url_audio

        return self.post(passwd_challenge_url, data=payload)

    def handle_sk(self, sess):
        response_page = BeautifulSoup(sess.text, 'html.parser')
        challenge_url = sess.url.split("?")[0]
        challenges_txt = response_page.find('input', {
            'name': "id-challenge"
        }).get('value')

        facet_url = urllib_parse.urlparse(challenge_url)
        facet = facet_url.scheme + "://" + facet_url.netloc

        keyHandleJSField = response_page.find('div', {'jsname': 'C0oDBd'}).get('data-challenge-ui')
        startJSONPosition = keyHandleJSField.find('{')
        endJSONPosition = keyHandleJSField.rfind('}')
        keyHandleJsonPayload = json.loads(keyHandleJSField[startJSONPosition:endJSONPosition + 1])

        keyHandles = self.find_key_handles(keyHandleJsonPayload, base64.urlsafe_b64encode(base64.b64decode(challenges_txt)))
        appId = self.find_app_id(str(keyHandleJsonPayload))

        # txt sent for signing needs to be base64 url encode
        # we also have to remove any base64 padding because including including it will prevent google accepting the auth response
        challenges_txt_encode_pad_removed = base64.urlsafe_b64encode(base64.b64decode(challenges_txt)).strip('='.encode())

        u2f_challenges = [{'version': 'U2F_V2', 'challenge': challenges_txt_encode_pad_removed.decode(), 'appId': appId, 'keyHandle': keyHandle.decode()} for keyHandle in keyHandles]

        # Prompt the user up to attempts_remaining times to insert their U2F device.
        attempts_remaining = 5
        auth_response = None
        while True:
            try:
                auth_response_dict = u2f.u2f_auth(u2f_challenges, facet)
                auth_response = json.dumps(auth_response_dict)
                break
            except RuntimeWarning:
                logging.error("No U2F device found. %d attempts remaining",
                              attempts_remaining)
                if attempts_remaining <= 0:
                    break
                else:
                    input(
                        "Insert your U2F device and press enter to try again..."
                    )
                    attempts_remaining -= 1

        # If we exceed the number of attempts, raise an error and let the program exit.
        if auth_response is None:
            raise ExpectedGoogleException(
                "No U2F device found. Please check your setup.")

        payload = {
            'challengeId':
            response_page.find('input', {
                'name': 'challengeId'
            }).get('value'),
            'challengeType':
            response_page.find('input', {
                'name': 'challengeType'
            }).get('value'),
            'continue': response_page.find('input', {
                'name': 'continue'
            }).get('value'),
            'scc':
            response_page.find('input', {
                'name': 'scc'
            }).get('value'),
            'sarp':
            response_page.find('input', {
                'name': 'sarp'
            }).get('value'),
            'checkedDomains':
            response_page.find('input', {
                'name': 'checkedDomains'
            }).get('value'),
            'pstMsg': '1',
            'TL':
            response_page.find('input', {
                'name': 'TL'
            }).get('value'),
            'gxf':
            response_page.find('input', {
                'name': 'gxf'
            }).get('value'),
            'id-challenge':
            challenges_txt,
            'id-assertion':
            auth_response,
            'TrustDevice':
            'on',
        }
        return self.post(challenge_url, data=payload)

    def handle_sms(self, sess):
        response_page = BeautifulSoup(sess.text, 'html.parser')
        challenge_url = sess.url.split("?")[0]

        sms_token = input("Enter SMS token: G-") or None

        payload = {
            'challengeId':
            response_page.find('input', {
                'name': 'challengeId'
            }).get('value'),
            'challengeType':
            response_page.find('input', {
                'name': 'challengeType'
            }).get('value'),
            'continue':
            response_page.find('input', {
                'name': 'continue'
            }).get('value'),
            'scc':
            response_page.find('input', {
                'name': 'scc'
            }).get('value'),
            'sarp':
            response_page.find('input', {
                'name': 'sarp'
            }).get('value'),
            'checkedDomains':
            response_page.find('input', {
                'name': 'checkedDomains'
            }).get('value'),
            'pstMsg':
            response_page.find('input', {
                'name': 'pstMsg'
            }).get('value'),
            'TL':
            response_page.find('input', {
                'name': 'TL'
            }).get('value'),
            'gxf':
            response_page.find('input', {
                'name': 'gxf'
            }).get('value'),
            'Pin':
            sms_token,
            'TrustDevice':
            'on',
        }

        # Submit IPP (SMS code)
        return self.post(challenge_url, data=payload)

    def handle_prompt(self, sess):
        response_page = BeautifulSoup(sess.text, 'html.parser')
        challenge_url = sess.url.split("?")[0]

        data_key = response_page.find('div', {
            'data-api-key': True
        }).get('data-api-key')
        data_tx_id = response_page.find('div', {
            'data-tx-id': True
        }).get('data-tx-id')

        # Need to post this to the verification/pause endpoint
        await_url = "https://content.googleapis.com/cryptauth/v1/authzen/awaittx?alt=json&key={}".format(
            data_key)
        await_body = {'txId': data_tx_id}

        self.check_prompt_code(response_page)

        print("Open the Google App, and tap 'Yes' on the prompt to sign in ...")

        self.session.headers['Referer'] = sess.url

        retry = True
        response = None
        while retry:
            try:
                response = self.post(await_url, json=await_body)
                retry = False
            except requests.exceptions.HTTPError as ex:

                if not ex.response.status_code == 500:
                    raise ex

        parsed_response = json.loads(response.text)

        payload = {
            'challengeId':
            response_page.find('input', {
                'name': 'challengeId'
            }).get('value'),
            'challengeType':
            response_page.find('input', {
                'name': 'challengeType'
            }).get('value'),
            'continue':
            response_page.find('input', {
                'name': 'continue'
            }).get('value'),
            'scc':
            response_page.find('input', {
                'name': 'scc'
            }).get('value'),
            'sarp':
            response_page.find('input', {
                'name': 'sarp'
            }).get('value'),
            'checkedDomains':
            response_page.find('input', {
                'name': 'checkedDomains'
            }).get('value'),
            'checkConnection':
            'youtube:1295:1',
            'pstMsg':
            response_page.find('input', {
                'name': 'pstMsg'
            }).get('value'),
            'TL':
            response_page.find('input', {
                'name': 'TL'
            }).get('value'),
            'gxf':
            response_page.find('input', {
                'name': 'gxf'
            }).get('value'),
            'token':
            parsed_response['txToken'],
            'action':
            response_page.find('input', {
                'name': 'action'
            }).get('value'),
            'TrustDevice':
            'on',
        }

        return self.post(challenge_url, data=payload)

    @staticmethod
    def check_prompt_code(response):
        """
        Sometimes there is an additional numerical code on the response page that needs to be selected
        on the prompt from a list of multiple choice. Print it if it's there.
        """
        num_code = response.find("div", {"jsname": "EKvSSd"})
        if num_code:
            print("numerical code for prompt: {}".format(num_code.string))

    def handle_totp(self, sess):
        response_page = BeautifulSoup(sess.text, 'html.parser')
        tl = response_page.find('input', {'name': 'TL'}).get('value')
        gxf = response_page.find('input', {'name': 'gxf'}).get('value')
        challenge_url = sess.url.split("?")[0]
        challenge_id = challenge_url.split("totp/")[1]

        mfa_token = input("MFA token: ") or None

        if not mfa_token:
            raise ValueError(
                "MFA token required for {} but none supplied.".format(
                    self.config.username))

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
        return self.post(challenge_url, data=payload)

    def handle_iap(self, sess):
        response_page = BeautifulSoup(sess.text, 'html.parser')
        challenge_url = sess.url.split("?")[0]
        phone_number = input('Enter your phone number:') or None

        while True:
            try:
                choice = int(
                    input(
                        'Type 1 to receive a code by SMS or 2 for a voice call:'
                    ))
                if choice not in [1, 2]:
                    raise ValueError
            except ValueError:
                logging.error("Not a valid (integer) option, try again")
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
            'challengeId':
            response_page.find('input', {
                'name': 'challengeId'
            }).get('value'),
            'challengeType':
            response_page.find('input', {
                'name': 'challengeType'
            }).get('value'),
            'continue':
            self.cont,
            'scc':
            response_page.find('input', {
                'name': 'scc'
            }).get('value'),
            'sarp':
            response_page.find('input', {
                'name': 'sarp'
            }).get('value'),
            'checkedDomains':
            response_page.find('input', {
                'name': 'checkedDomains'
            }).get('value'),
            'pstMsg':
            response_page.find('input', {
                'name': 'pstMsg'
            }).get('value'),
            'TL':
            response_page.find('input', {
                'name': 'TL'
            }).get('value'),
            'gxf':
            response_page.find('input', {
                'name': 'gxf'
            }).get('value'),
            'phoneNumber':
            phone_number,
            'sendMethod':
            send_method,
        }

        # Submit phone number and desired method (SMS or voice call)
        sess = self.post(challenge_url, data=payload)

        response_page = BeautifulSoup(sess.text, 'html.parser')
        challenge_url = sess.url.split("?")[0]

        token = input("Enter " + send_method + " token: G-") or None

        payload = {
            'challengeId':
            response_page.find('input', {
                'name': 'challengeId'
            }).get('value'),
            'challengeType':
            response_page.find('input', {
                'name': 'challengeType'
            }).get('value'),
            'continue':
            response_page.find('input', {
                'name': 'continue'
            }).get('value'),
            'scc':
            response_page.find('input', {
                'name': 'scc'
            }).get('value'),
            'sarp':
            response_page.find('input', {
                'name': 'sarp'
            }).get('value'),
            'checkedDomains':
            response_page.find('input', {
                'name': 'checkedDomains'
            }).get('value'),
            'pstMsg':
            response_page.find('input', {
                'name': 'pstMsg'
            }).get('value'),
            'TL':
            response_page.find('input', {
                'name': 'TL'
            }).get('value'),
            'gxf':
            response_page.find('input', {
                'name': 'gxf'
            }).get('value'),
            'pin':
            token,
        }

        # Submit SMS/VOICE token
        return self.post(challenge_url, data=payload)

    def handle_selectchallenge(self, sess):
        response_page = BeautifulSoup(sess.text, 'html.parser')
        # Known mfa methods, 5 is disabled till its implemented
        auth_methods = {
            2: 'TOTP (Google Authenticator)',
            3: 'SMS',
            4: 'OOTP (Google Prompt)'
            # 5: 'OOTP (Google App Offline Security Code)'
        }

        unavailable_challenge_ids = [
            int(i.attrs.get('data-unavailable'))
            for i in response_page.find_all(
                lambda tag: tag.name == 'form' and 'data-unavailable' in tag.attrs
            )
        ]

        # ootp via google app offline code isn't implemented. make sure its not valid.
        unavailable_challenge_ids.append(5)

        challenge_ids = [
            int(i.get('value'))
            for i in response_page.find_all('input', {'name': 'challengeId'})
            if int(i.get('value')) not in unavailable_challenge_ids
        ]

        challenge_ids.sort()

        auth_methods = {
            k: auth_methods[k]
            for k in challenge_ids
            if k in auth_methods and k not in unavailable_challenge_ids
        }

        print('Choose MFA method from available:')
        print('\n'.join(
            '{}: {}'.format(*i) for i in list(auth_methods.items())))

        selected_challenge = input("Enter MFA choice number ({}): ".format(
            challenge_ids[-1:][0])) or None

        if selected_challenge is not None and int(selected_challenge) in challenge_ids:
            challenge_id = int(selected_challenge)
        else:
            # use the highest index as that will default to prompt, then sms, then totp, etc.
            challenge_id = challenge_ids[-1:][0]

        print("MFA Type Chosen: {}".format(auth_methods[challenge_id]))

        # We need the specific form of the challenge chosen
        challenge_form = response_page.find(
            'form', {'data-challengeentry': challenge_id})

        payload = {
            'challengeId':
            challenge_id,
            'challengeType':
            challenge_form.find('input', {
                'name': 'challengeType'
            }).get('value'),
            'continue':
            challenge_form.find('input', {
                'name': 'continue'
            }).get('value'),
            'scc':
            challenge_form.find('input', {
                'name': 'scc'
            }).get('value'),
            'sarp':
            challenge_form.find('input', {
                'name': 'sarp'
            }).get('value'),
            'checkedDomains':
            challenge_form.find('input', {
                'name': 'checkedDomains'
            }).get('value'),
            'pstMsg':
            challenge_form.find('input', {
                'name': 'pstMsg'
            }).get('value'),
            'TL':
            challenge_form.find('input', {
                'name': 'TL'
            }).get('value'),
            'gxf':
            challenge_form.find('input', {
                'name': 'gxf'
            }).get('value'),
            'subAction':
            challenge_form.find('input', {
                'name': 'subAction'
            }).get('value'),
        }
        if challenge_form.find('input', {'name': 'SendMethod'}) is not None:
            payload['SendMethod'] = challenge_form.find(
                'input', {
                    'name': 'SendMethod'
                }).get('value')

        # POST to google with the chosen challenge
        return self.post(
            self.base_url + challenge_form.get('action'), data=payload)
