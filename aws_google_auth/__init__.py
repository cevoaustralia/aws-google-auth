#!/usr/bin/env python

from . import _version
from . import prepare

import argparse
import base64
import boto3
import configparser
import getpass
import json
import logging
import os
import requests
import sys
from bs4 import BeautifulSoup
from lxml import etree
from tzlocal import get_localzone

# Set up the Logger.
logging.basicConfig(level=logging.WARN)
logger = logging.getLogger(__name__)

# In Python3, the library 'urlparse' was renamed to 'urllib.parse'. For this to
# maintain compatibility with both Python 2 and Python 3, the import must be
# dynamically chosen based on the version detected.
if sys.version_info >= (3, 0):
    import urllib.parse as urlparse
    logger.debug("Detected Python 3, using urllib.parse.")
else:
    import urlparse
    logger.debug("Detected Python 2, using urllib.")

REGION = os.getenv("AWS_DEFAULT_REGION") or "ap-southeast-2"
IDP_ID = os.getenv("GOOGLE_IDP_ID")
SP_ID = os.getenv("GOOGLE_SP_ID")
USERNAME = os.getenv("GOOGLE_USERNAME")
MAX_DURATION = 3600
DURATION = int(os.getenv("DURATION") or MAX_DURATION)
PROFILE = os.getenv("AWS_PROFILE")
ASK_ROLE = os.getenv("AWS_ASK_ROLE") or False
U2F_DISABLED = os.getenv("U2F_DISABLED") or False


if U2F_DISABLED:
    logger.info("User has disabled U2F support.")
else:
    try:
        from . import u2f
        logger.debug("Successfully imported u2f module.")
    except ImportError:
        logger.warn("Failed to import U2F libraries, U2F login unavailable."
                    " Other methods can still continue.")


class GoogleAuth:
    def __init__(self, **kwargs):
        """The GoogleAuth object holds authentication state
        for a given session. You need to supply:

        username: FQDN Google username, eg first.last@example.com
        password: obvious
        idp_id: Google's assigned IdP identifier for your G-suite account
        sp_id: Google's assigned SP identifier for your AWS SAML app

        Optionally, you can supply:
        duration_seconds: number of seconds for the session to be active
        (max 3600)
        """

        self.version = _version.__version__

        self.username = kwargs.pop('username')
        self.password = kwargs.pop('password')
        self.idp_id = kwargs.pop('idp_id')
        self.sp_id = kwargs.pop('sp_id')
        if kwargs.get('duration_seconds'):
            try:
                self.duration_seconds = int(kwargs.pop('duration_seconds'))
            except ValueError as e:
                logger.error("Value Error: duration_seconds must be an integer.")
                raise ValueError('GoogleAuth: duration_seconds must be an integer')

            if self.duration_seconds > MAX_DURATION:
                logger.warn("Clamping duration_seconds to {}.".format(MAX_DURATION))
                self.duration_seconds = MAX_DURATION

        self.login_url = "https://accounts.google.com/o/saml2/initsso?idpid=%s&spid=%s&forceauthn=false" % (self.idp_id, self.sp_id)

    def do_login(self):
        self.session = requests.Session()
        self.session.headers['User-Agent'] = "AWS Sign-in/%s (Cevo aws-google-auth)" % self.version
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
        payload['Passwd'] = self.password

        # POST to Authenticate Password
        sess = self.session.post(passwd_challenge_url, data=payload)
        sess.raise_for_status()
        response_page = BeautifulSoup(sess.text, 'html.parser')
        error = response_page.find(class_='error-msg')
        cap = response_page.find('input', {'name': 'logincaptcha'})

        # Were there any errors logging in? Could be invalid username or
        # password. There could also sometimes be a Captcha, which means
        # Google thinks you (or someone using the same outbound IP address
        # as you) is a bot.
        if error is not None:
            logger.error("Google returned an error: {}".format(error))
            raise ValueError('Invalid username or password')

        if cap is not None:
            logger.error("User has a CAPTCHA on their account. This requires"
                         "them to log into a web browser to remove it.")
            raise ValueError('Captcha Required. Manually Login to remove this.')

        self.session.headers['Referer'] = sess.url

        # Was there an MFA challenge?
        if "challenge/totp/" in sess.url:
            logger.info("Google has requested we use a TOTP challenge."
                        " Moving forward with that method.")
            sess = self.handle_totp(sess)
        elif "challenge/ipp/" in sess.url:
            logger.info("Google has requested we use a SMS challenge."
                        " Moving forward with that method.")
            sess = self.handle_sms(sess)
        elif "challenge/az/" in sess.url:
            logger.info("Google has requested we use a Prompt challenge."
                        " Moving forward with that method.")
            sess = self.handle_prompt(sess)
        elif "challenge/sk/" in sess.url:
            logger.info("Google has requested we use a Security Key challenge."
                        " Moving forward with that method.")
            sess = self.handle_sk(sess)

        # ... there are different URLs for backup codes (printed)
        # and security keys (eg yubikey) as well
        # save for later
        self.session_state = sess

    def parse_saml(self):
        if self.session_state is None:
            raise StandardError('You must use do_login() before calling parse_saml()')

        parsed = BeautifulSoup(self.session_state.text, 'html.parser')
        try:
            saml_element = parsed.find('input', {'name': 'SAMLResponse'}).get('value')
        except:
            raise StandardError('Could not find SAML response, check your credentials')

        return saml_element

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

        auth_response = json.dumps(u2f.u2f_auth(u2f_challenges, facet))

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
            raise ValueError("MFA token required for % but none supplied" % self.username)

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


def pick_one(roles):
    while True:
        for i, role in enumerate(roles):
            print("[{:>3d}] {}".format(i+1, role))

        prompt = 'Type the number (1 - {:d}) of the role to assume: '.format(len(roles))
        choice = get_user_input(prompt)

        try:
            num = int(choice)
            return list(roles.items())[num - 1]
        except:
            print("Invalid choice, try again")


def parse_roles(doc):
    roles = {}
    for x in doc.xpath('//*[@Name = "https://aws.amazon.com/SAML/Attributes/Role"]//text()'):
        if "arn:aws:iam:" not in x:
            continue

        res = x.split(',')
        roles[res[0]] = res[1]

    return roles


def parse_args(args):
    parser = argparse.ArgumentParser(
        prog="aws-google-auth",
        description="Acquire temporary AWS credentials via Google SSO",
    )

    parser.add_argument('-u', '--username', default=USERNAME,
                        help='Google Apps username ($GOOGLE_USERNAME)')
    parser.add_argument('-I', '--idp-id', default=IDP_ID,
                        help='Google SSO IDP identifier ($GOOGLE_IDP_ID)')
    parser.add_argument('-S', '--sp-id', default=SP_ID,
                        help='Google SSO SP identifier ($GOOGLE_SP_ID)')
    parser.add_argument('-R', '--region', default=REGION,
                        help='AWS region endpoint ($AWS_DEFAULT_REGION)')
    parser.add_argument('-d', '--duration', type=int, default=DURATION,
                        help='Credential duration ($DURATION)')
    parser.add_argument('-p', '--profile', default=PROFILE,
                        help='AWS profile ($AWS_PROFILE)')
    parser.add_argument('-a', '--ask-role', default=ASK_ROLE,
                        action='store_true', help='Set true to always pick the role')
    parser.add_argument('-V', '--version', action='version',
                        version='%(prog)s {version}'.format(version=_version.__version__))

    return parser.parse_args(args)


# A Python 2 and Python 3 compatible input wrapper
def get_user_input(prompt):
    try:
        user_input = raw_input(prompt)
        logger.debug("User replied with '{}'".format(user_input))
        return user_input
    except NameError:
        user_input = input(prompt)
        logger.debug("User replied with '{}'".format(user_input))
        return user_input


def main():
    try:
        cli(sys.argv[1:])
    except KeyboardInterrupt:
        pass


def cli(cli_args):

    args = parse_args(args=cli_args)

    if args.duration > MAX_DURATION:
        logger.warn("Duration must be less than or equal to {}, setting to "
                    "{}.".format(MAX_DURATION, MAX_DURATION))
        args.duration = MAX_DURATION

    config = prepare.get_prepared_config(
        args.profile,
        args.region,
        args.username,
        args.idp_id,
        args.sp_id,
        args.duration,
        args.ask_role
    )

    if config.google_username is None:
        config.google_username = get_user_input("Google Username: ")
    else:
        print("Google username: " + config.google_username)

    if config.google_idp_id is None:
        config.google_idp_id = get_user_input("Google IDP: ")

    if config.google_sp_id is None:
        config.google_sp_id = get_user_input("Google SP: ")

    passwd = getpass.getpass("Google Password: ")

    google = GoogleAuth(
        username=config.google_username,
        password=passwd,
        idp_id=config.google_idp_id,
        sp_id=config.google_sp_id
    )

    # ------------------ #
    # GET SAML ASSERTION #
    # ------------------ #

    google.do_login()
    encoded_saml = google.parse_saml()
    base64_decoded_saml = base64.b64decode(encoded_saml)
    logger.info("Obtained SAML Assertion from Google.")
    logger.debug("SAML Assertion: {}".format(base64_decoded_saml))

    # Parse out the roles from the SAML so we can offer them as a choice
    doc = etree.fromstring(base64_decoded_saml)
    roles = parse_roles(doc)

    # ----------------------------------- #
    # ASSUME AWS ROLE, GET AWS STS TOKENS #
    # ----------------------------------- #

    if config.role_arn not in roles:
        logger.warn("The Role ARN specified is not in the list of available roles.")
        config.role_arn, config.provider = pick_one(roles)
    elif config.ask_role:
        logger.debug("ASK_ROLE detected, forcing prompt.")
        config.role_arn, config.provider = pick_one(roles)
    else:
        logger.info("Do not need to prompt user, going forward with role "
                    "having ARN '{}'".format(config.role_arn))

    sts = boto3.client('sts', region_name=config.region)
    token = sts.assume_role_with_saml(
                RoleArn=config.role_arn,
                PrincipalArn=config.provider,
                SAMLAssertion=encoded_saml,
                DurationSeconds=config.duration)
    logger.debug("Token acquired: {}".format(token))
    logger.info("Obtained STS Tokens from AWS.")

    print("Credentials Expiration: " + format(token['Credentials']['Expiration'].astimezone(get_localzone())))

    # --------------------------------------------------------- #
    # WRITE CREDENTIALS TO ~/.AWS/CREDENTIALS AND ~/.AWS/CONFIG #
    # --------------------------------------------------------- #

    if config.profile is None:
        print_exports(token)

    _store(config, token)


def print_exports(token):
    export_template = "export AWS_ACCESS_KEY_ID='{}' AWS_SECRET_ACCESS_KEY='{}' AWS_SESSION_TOKEN='{}' AWS_SESSION_EXPIRATION='{}'"

    formatted = export_template.format(
        token['Credentials']['AccessKeyId'],
        token['Credentials']['SecretAccessKey'],
        token['Credentials']['SessionToken'],
        token['Credentials']['Expiration'].strftime('%Y-%m-%dT%H:%M:%S%z')
    )

    print(formatted)


def _store(config, aws_session_token):

    def store_config(profile, config_location, storer):
        config_file = configparser.RawConfigParser()
        config_file.read(config_location)

        if not config_file.has_section(profile):
            config_file.add_section(profile)

        storer(config_file, profile)

        with open(config_location, 'w+') as f:
            try:
                config_file.write(f)
            finally:
                f.close()

    def credentials_storer(config_file, profile):
        config_file.set(profile, 'aws_access_key_id', aws_session_token['Credentials']['AccessKeyId'])
        config_file.set(profile, 'aws_secret_access_key', aws_session_token['Credentials']['SecretAccessKey'])
        config_file.set(profile, 'aws_session_token', aws_session_token['Credentials']['SessionToken'])
        config_file.set(profile, 'aws_security_token', aws_session_token['Credentials']['SessionToken'])
        config_file.set(profile, 'aws_session_expiration', aws_session_token['Credentials']['Expiration'].strftime('%Y-%m-%dT%H:%M:%S%z'))

    def config_storer(config_file, profile):
        config_file.set(profile, 'region', config.region)
        config_file.set(profile, 'output', config.output_format)
        config_file.set(profile, 'google_config.role_arn', config.role_arn)
        config_file.set(profile, 'google_config.provider', config.provider)
        config_file.set(profile, 'google_config.google_idp_id', config.google_idp_id)
        config_file.set(profile, 'google_config.google_sp_id', config.google_sp_id)
        config_file.set(profile, 'google_config.google_username', config.google_username)
        config_file.set(profile, 'google_config.duration', config.duration)

    store_config(config.profile, config.aws_credentials_location, credentials_storer)
    if config.profile == 'default':
        store_config(config.profile, config.aws_config_location, config_storer)
    else:
        store_config('profile {}'.format(config.profile), config.aws_config_location, config_storer)


if __name__ == '__main__':
    main()
