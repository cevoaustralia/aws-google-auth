#!/usr/bin/env python

import os
import json
from datetime import datetime

import botocore.session
import filelock

try:
    from backports import configparser
except ImportError:
    import configparser

from aws_google_auth import util
from aws_google_auth import amazon


class Configuration(object):

    def __init__(self, **kwargs):
        self.options = {}
        self.__boto_session = botocore.session.Session()

        # Set up some defaults. These can be overridden as fit.
        self.ask_role = False
        self.keyring = False
        self.duration = self.max_duration
        self.auto_duration = False
        self.idp_id = None
        self.password = None
        self.profile = "sts"
        self.region = None
        self.role_arn = None
        self.__saml_cache = None
        self.__google_cookies = None
        self.sp_id = None
        self.u2f_disabled = False
        self.resolve_aliases = False
        self.username = None
        self.print_creds = False
        self.quiet = False
        self.bg_response = None
        self.account = ""

    # For the "~/.aws/config" file, we use the format "[profile testing]"
    # for the 'testing' profile. The credential file will just be "[testing]"
    # in that case. See https://docs.aws.amazon.com/cli/latest/userguide/cli-multiple-profiles.html
    # for more information.
    @staticmethod
    def config_profile(profile):
        if str(profile).lower() == 'default':
            return profile
        else:
            return 'profile {}'.format(str(profile))

    @property
    def max_duration(self):
        return 43200

    @property
    def credentials_file(self):
        return os.path.expanduser(self.__boto_session.get_config_variable('credentials_file'))

    @property
    def config_file(self):
        return os.path.expanduser(self.__boto_session.get_config_variable('config_file'))

    @property
    def saml_cache_file(self):
        return self.credentials_file.replace('credentials', 'saml_cache_%s.xml' % self.idp_id)

    def ensure_config_files_exist(self):
        for file in [self.config_file, self.credentials_file]:
            directory = os.path.dirname(file)
            if not os.path.exists(directory):
                os.mkdir(directory, 0o700)
            if not os.path.exists(file):
                util.Util.touch(file)

    # Will return a SAML cache, ONLY if it's valid. If invalid or not set, will
    # return None. If the SAML cache isn't valid, we'll remove it from the
    # in-memory object. On the next write(), it will be purged from disk.
    @property
    def saml_cache(self):
        if not amazon.Amazon.is_valid_saml_assertion(self.__saml_cache):
            self.__saml_cache = None

        return self.__saml_cache

    @saml_cache.setter
    def saml_cache(self, value):
        self.__saml_cache = value

    @property
    def google_cookies_file(self):
        return self.credentials_file.replace('credentials', 'google_cookies.json')

    # Will return Google cookies in a dict only when non of them have expired.
    @property
    def google_cookies(self):
        if self.__google_cookies and not all([
            datetime.timestamp(datetime.now()) < c['expires'] for c in self.__google_cookies
        ]):
            self.__google_cookies = None

        return self.__google_cookies

    @google_cookies.setter
    def google_cookies(self, value):
        self.__google_cookies = value

    # Will raise exceptions if the configuration is invalid, otherwise returns
    # None. Use this at any point to validate the configuration is in a good
    # state. There are no checks here regarding SAML caching, as that's just a
    # user-performance improvement, and an invalid cache isn't an invalid
    # configuration.
    def raise_if_invalid(self):
        # ask_role
        assert (self.ask_role.__class__ is bool), "Expected ask_role to be a boolean. Got {}.".format(self.ask_role.__class__)

        # keyring
        assert (self.keyring.__class__ is bool), "Expected keyring to be a boolean. Got {}.".format(self.keyring.__class__)

        # duration
        assert (self.duration.__class__ is int), "Expected duration to be an integer. Got {}.".format(self.duration.__class__)
        assert (self.duration >= 900), "Expected duration to be greater than or equal to 900. Got {}.".format(self.duration)
        assert (self.duration <= self.max_duration), "Expected duration to be less than or equal to max_duration ({}). Got {}.".format(self.max_duration, self.duration)

        # auto_duration
        assert (self.auto_duration.__class__ is bool), "Expected auto_duration to be a boolean. Got {}.".format(self.auto_duration.__class__)

        # profile
        assert (self.profile.__class__ is str), "Expected profile to be a string. Got {}.".format(self.profile.__class__)

        # region
        assert (self.region.__class__ is str), "Expected region to be a string. Got {}.".format(self.region.__class__)

        # idp_id
        assert (self.idp_id is not None), "Expected idp_id to be set to non-None value."

        # sp_id
        assert (self.sp_id is not None), "Expected sp_id to be set to non-None value."

        # username
        assert (self.username.__class__ is str), "Expected username to be a string. Got {}.".format(self.username.__class__)

        # password
        try:
            assert (type(self.password) in [str, unicode]), "Expected password to be a string. Got {}.".format(
                type(self.password))
        except NameError:
            assert (type(self.password) is str), "Expected password to be a string. Got {}.".format(
                type(self.password))

        # role_arn (Can be blank, we'll just prompt)
        if self.role_arn is not None:
            assert (self.role_arn.__class__ is str), "Expected role_arn to be None or a string. Got {}.".format(self.role_arn.__class__)
            assert ("arn:aws:iam::" in self.role_arn or "arn:aws-us-gov:iam::" in self.role_arn), "Expected role_arn to contain 'arn:aws:iam::'. Got '{}'.".format(self.role_arn)

        # u2f_disabled
        assert (self.u2f_disabled.__class__ is bool), "Expected u2f_disabled to be a boolean. Got {}.".format(self.u2f_disabled.__class__)

        # quiet
        assert (self.quiet.__class__ is bool), "Expected quiet to be a boolean. Got {}.".format(self.quiet.__class__)

        # account
        assert (self.account.__class__ is str), "Expected account to be string. Got {}".format(self.account.__class__)

    # Write the configuration (and credentials) out to disk. This allows for
    # regular AWS tooling (aws cli and boto) to use the credentials in the
    # profile the user specified.
    def write(self, amazon_object):
        self.ensure_config_files_exist()

        assert (self.profile is not None), "Can not store config/credentials if the AWS_PROFILE is None."

        config_file_lock = filelock.FileLock(self.config_file + '.lock')
        config_file_lock.acquire()
        try:
            # Write to the configuration file
            profile = Configuration.config_profile(self.profile)
            config_parser = configparser.RawConfigParser()
            config_parser.read(self.config_file)
            if not config_parser.has_section(profile):
                config_parser.add_section(profile)
            config_parser.set(profile, 'region', self.region)
            config_parser.set(profile, 'google_config.ask_role', self.ask_role)
            config_parser.set(profile, 'google_config.keyring', self.keyring)
            config_parser.set(profile, 'google_config.duration', self.duration)
            config_parser.set(profile, 'google_config.google_idp_id', self.idp_id)
            config_parser.set(profile, 'google_config.role_arn', self.role_arn)
            config_parser.set(profile, 'google_config.google_sp_id', self.sp_id)
            config_parser.set(profile, 'google_config.u2f_disabled', self.u2f_disabled)
            config_parser.set(profile, 'google_config.google_username', self.username)
            config_parser.set(profile, 'google_config.bg_response', self.bg_response)

            with open(self.config_file, 'w+') as f:
                config_parser.write(f)
        finally:
            config_file_lock.release()

            # Write to the credentials file (only if we have credentials)
            if amazon_object is not None:
                credentials_file_lock = filelock.FileLock(self.credentials_file + '.lock')
                credentials_file_lock.acquire()
                try:
                    credentials_parser = configparser.RawConfigParser()
                    credentials_parser.read(self.credentials_file)
                    if not credentials_parser.has_section(self.profile):
                        credentials_parser.add_section(self.profile)
                    credentials_parser.set(self.profile, 'aws_access_key_id', amazon_object.access_key_id)
                    credentials_parser.set(self.profile, 'aws_secret_access_key', amazon_object.secret_access_key)
                    credentials_parser.set(self.profile, 'aws_security_token', amazon_object.session_token)
                    credentials_parser.set(self.profile, 'aws_session_expiration', amazon_object.expiration.strftime('%Y-%m-%dT%H:%M:%S%z'))
                    credentials_parser.set(self.profile, 'aws_session_token', amazon_object.session_token)

                    with open(self.credentials_file, 'w+') as f:
                        credentials_parser.write(f)
                finally:
                    credentials_file_lock.release()

            if self.__saml_cache is not None:
                saml_cache_file_lock = filelock.FileLock(self.saml_cache_file + '.lock')
                saml_cache_file_lock.acquire()
                try:
                    with open(self.saml_cache_file, 'w') as f:
                        f.write(self.__saml_cache.decode("utf-8"))
                finally:
                    saml_cache_file_lock.release()

        if self.__google_cookies is not None:
            with open(self.google_cookies_file, 'w') as f:
                f.write(json.dumps(self.__google_cookies, indent=2))

    # Read from the configuration file and override ALL values currently stored
    # in the configuration object. As this is potentially destructive, it's
    # important to only run this in the beginning of the object initialization.
    # We do not read AWS credentials, as this tool's use case is to obtain
    # them.
    def read(self, profile):
        self.ensure_config_files_exist()

        # Shortening Convenience functions
        coalesce = util.Util.coalesce
        unicode_to_string = util.Util.unicode_to_string_if_needed

        profile_string = Configuration.config_profile(profile)
        config_parser = configparser.RawConfigParser()
        config_parser.read(self.config_file)

        if config_parser.has_section(profile_string):
            self.profile = profile

            # Ask Role
            read_ask_role = config_parser[profile_string].getboolean('google_config.ask_role', None)
            self.ask_role = coalesce(read_ask_role, self.ask_role)

            # Keyring
            read_keyring = config_parser[profile_string].getboolean('google_config.keyring', None)
            self.keyring = coalesce(read_keyring, self.keyring)

            # Duration
            read_duration = config_parser[profile_string].getint('google_config.duration', None)
            self.duration = coalesce(read_duration, self.duration)

            # IDP ID
            read_idp_id = unicode_to_string(config_parser[profile_string].get('google_config.google_idp_id', None))
            self.idp_id = coalesce(read_idp_id, self.idp_id)

            # Region
            read_region = unicode_to_string(config_parser[profile_string].get('region', None))
            self.region = coalesce(read_region, self.region)

            # Role ARN
            read_role_arn = unicode_to_string(config_parser[profile_string].get('google_config.role_arn', None))
            self.role_arn = coalesce(read_role_arn, self.role_arn)

            # SP ID
            read_sp_id = unicode_to_string(config_parser[profile_string].get('google_config.google_sp_id', None))
            self.sp_id = coalesce(read_sp_id, self.sp_id)

            # U2F Disabled
            read_u2f_disabled = config_parser[profile_string].getboolean('google_config.u2f_disabled', None)
            self.u2f_disabled = coalesce(read_u2f_disabled, self.u2f_disabled)

            # Username
            read_username = unicode_to_string(config_parser[profile_string].get('google_config.google_username', None))
            self.username = coalesce(read_username, self.username)

            # bg_response
            read_bg_response = unicode_to_string(config_parser[profile_string].get('google_config.bg_response', None))
            self.bg_response = coalesce(read_bg_response, self.bg_response)

            # Account
            read_account = unicode_to_string(config_parser[profile_string].get('account', None))
            self.account = coalesce(read_account, self.account)

        # SAML Cache
        try:
            with open(self.saml_cache_file, 'r') as f:
                self.__saml_cache = f.read().encode("utf-8")
        except IOError:
            pass

        # Google cookies
        try:
            with open(self.google_cookies_file, 'r') as f:
                self.__google_cookies = json.loads(f.read())
        except IOError:
            pass
