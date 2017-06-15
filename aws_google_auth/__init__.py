#!/usr/bin/env python

import argparse
import getpass
import base64
import boto3
import os
import sys
import requests
from bs4 import BeautifulSoup
from lxml import etree

VERSION = "0.1"

REGION = os.getenv("AWS_DEFAULT_REGION") or "ap-southeast-2"
IDP_ID = os.getenv("GOOGLE_IDP_ID")
SP_ID = os.getenv("GOOGLE_SP_ID")
USERNAME = os.getenv("GOOGLE_USERNAME")
DURATION = os.getenv("DURATION")

class GoogleAuth:
    def __init__(self, **kwargs):
        """The GoogleAuth object holds authentication state
        for a given session. You need to supply:

        username: FQDN Google username, eg first.last@example.com
        password: obvious
        idp_id: Google's assigned IdP identifier for your G-suite account
        sp_id: Google's assigned SP identifier for your AWS SAML app

        Optionally, you can supply:
        duration_seconds: number of seconds for the session to be active (max 3600)
        """

        self.version = VERSION

        self.username = kwargs.pop('username')
        self.password = kwargs.pop('password')
        self.idp_id = kwargs.pop('idp_id')
        self.sp_id = kwargs.pop('sp_id')
        if kwargs.get('duration_seconds'):
            try:
                self.duration_seconds = int(kwargs.pop('duration_seconds'))
            except ValueError as e:
                raise ValueError('GoogleAuth: duration_seconds must be an integer')

            if self.duration_seconds > 3600:
                print "WARNING: Clamping duration_seconds to 3600"
                self.duration_seconds = 3600

        self.login_url = "https://accounts.google.com/o/saml2/initsso?idpid=%s&spid=%s&forceauthn=false" % (self.idp_id, self.sp_id)

    def do_login(self):
        session = requests.Session()
        session.headers['User-Agent'] = "Cevo aws-google-auth %s" % self.version
        sess = session.get(self.login_url)
        sess.raise_for_status()

        # Collect information from the page source
        first_page = BeautifulSoup(sess.text, 'html.parser')
        gxf = first_page.find('input', {'name': 'gxf'}).get('value')
        cont = first_page.find('input', {'name': 'continue'}).get('value')
        page = first_page.find('input', {'name': 'Page'}).get('value')
        sign_in = first_page.find('input', {'name': 'signIn'}).get('value')
        account_login_url = first_page.find('form', {'id': 'gaia_loginform'}).get('action')

        payload = {
            'bgresponse': 'js_disabled',
            'checkConnection': '',
            'checkedDomains': 'youtube',
            'continue': cont,
            'Email': self.username,
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
        sess = session.post(account_login_url, data=payload)
        sess.raise_for_status()
        session.headers['Referrer'] = sess.url

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
        payload['Passwd'] = self.password

        # POST to Authenticate Password
        sess = session.post(passwd_challenge_url, data=payload)
        sess.raise_for_status()
        response_page = BeautifulSoup(sess.text, 'html.parser')
        error = response_page.find(class_='error-msg')
        cap = response_page.find('input', {'name':'logincaptcha'})

        # Were there any errors logging in? Could be invalid username or password
        # There could also sometimes be a Captcha, which means Google thinks you,
        # or someone using the same outbound IP address as you, is a bot.
        if error is not None:
            raise ValueError('Invalid username or password')

        if cap is not None:
            raise ValueError('Captcha Required. Manually Login to remove this.')

        session.headers['Referrer'] = sess.url

        # Was there an MFA challenge?
        if sess.url.find("totp/"):
            tl = response_page.find('input', {'name': 'TL'}).get('value')
            gxf = response_page.find('input', {'name': 'gxf'}).get('value')
            challenge_url = sess.url.split("?")[0]
            challenge_id = challenge_url.split("totp/")[1]

            mfa_token  = raw_input("MFA token: ") or None

            if not mfa_token:
                raise ValueError("MFA token required for % but none supplied" % self.username)

            payload = {
                'challengeId': challenge_id,
                'challengeType': 6,
                'continue': cont,
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
            sess = session.post(challenge_url, data=payload)
            sess.raise_for_status()

        # save for later
        self.session = sess

    def parse_saml(self):
        if self.session is None:
            raise StandardError('You must use do_login() before calling parse_saml()')

        parsed = BeautifulSoup(self.session.text, 'html.parser')
        try:
            saml_element = parsed.find('input', {'name':'SAMLResponse'}).get('value')
        except:
            raise StandardError('Could not find SAML response, check your credentials')

        return saml_element

def pick_one(roles):
    while True:
        for i, role in enumerate(roles):
            print "[{:d}] {}".format(i, role)
        choice = raw_input("Choose role to assume: ")
        try:
            num = int(choice)
            return roles.items()[num]
        except:
            print "Invalid choice, try again"

def cli():
    parser = argparse.ArgumentParser(description="Acquire temporary AWS credentials via Google SSO")
    parser.add_argument('-u', '--username', default=USERNAME, help='Google Apps username ($GOOGLE_USERNAME)')
    parser.add_argument('-I', '--idp-id', default=IDP_ID, help='Google SSO IDP identifier ($GOOGLE_IDP_ID)')
    parser.add_argument('-S', '--sp-id', default=SP_ID, help='Google SSO SP identifier ($GOOGLE_SP_ID)')
    parser.add_argument('-R', '--region', default=REGION, help='AWS region endpoint ($AWS_DEFAULT_REGION)')
    parser.add_argument('-d', '--duration', default=DURATION, help='Credential duration ($DURATION)')

    args = parser.parse_args()

    if args.username is None:
        args.username = raw_input("Google username: ")

    if args.idp_id is None or args.sp_id is None:
        print "Must set both GOOGLE_IDP_ID and GOOGLE_SP_ID"
        parser.print_help()
        sys.exit(1)

    if args.duration is None:
        print "Setting duration to 3600 seconds"
        args.duration = 3600

    if args.duration > 3600:
        print "Duration must be less than or equal to 3600"
        duration = 3600

    passwd = getpass.getpass()

    google = GoogleAuth(
        username=args.username,
        password=passwd,
        idp_id=args.idp_id,
        sp_id=args.sp_id
    )

    google.do_login()
    encoded_saml = google.parse_saml()

    # Parse out the roles from the SAML so we can offer them as a choice
    doc = etree.fromstring(base64.b64decode(encoded_saml))
    roles = dict([x.split(',') for x in doc.xpath('//*[@Name = "https://aws.amazon.com/SAML/Attributes/Role"]//text()')])

    role, provider = pick_one(roles)

    print "Assuming " + role

    sts = boto3.client('sts', region_name=REGION)
    token = sts.assume_role_with_saml(
                RoleArn=role,
                PrincipalArn=provider,
                SAMLAssertion=encoded_saml,
                DurationSeconds=args.duration)

    print "export AWS_ACCESS_KEY_ID='{}'".format(token['Credentials']['AccessKeyId'])
    print "export AWS_SECRET_ACCESS_KEY='{}'".format(token['Credentials']['SecretAccessKey'])
    print "export AWS_SESSION_TOKEN='{}'".format(token['Credentials']['SessionToken'])
    print "export AWS_SESSION_EXPIRATION='{}'".format(token['Credentials']['Expiration'])
