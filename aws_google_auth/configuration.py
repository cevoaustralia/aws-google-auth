#!/usr/bin/env python

import os
import botocore.session
import configparser

from . import util


class Configuration:

    def __init__(self, **kwargs):
        self.options = {}
        self.__boto_session = botocore.session.Session()

        # Set up some defaults. These can be overridden as fit.
        self.ask_role = False
        self.duration = self.max_duration
        self.idp_id = None
        self.password = None
        self.profile = "sts"
        self.region = "ap-southeast-2"
        self.role_arn = None
        self.sp_id = None
        self.u2f_disabled = False
        self.username = None

    @property
    def max_duration(self):
        return 3600

    @property
    def credentials_file(self):
        return os.path.expanduser(self.__boto_session.get_config_variable('credentials_file'))

    @property
    def config_file(self):
        return os.path.expanduser(self.__boto_session.get_config_variable('config_file'))

    def ensure_config_files_exist(self):
        for file in [self.config_file, self.credentials_file]:
            directory = os.path.dirname(file)
            if not os.path.exists(directory):
                os.mkdir(directory, 0o700)
            if not os.path.exists(file):
                util.Util.touch(file)

    # Will raise exeptions if the configuration is invalid, otherwise returns
    # None. Use this at any point to validate the conifguration is in a good
    # state.
    def raise_if_invalid(self):
        # ask_role
        assert (self.ask_role.__class__ is bool), "Expected ask_role to be a boolean. Got {}.".format(self.ask_role.__class__)

        # duration
        assert (self.duration.__class__ is int), "Expected duration to be an integer. Got {}.".format(self.duration.__class__)
        assert (self.duration > 0), "Expected duration to be greater than 0. Got {}.".format(self.duration)
        assert (self.duration <= self.max_duration), "Expected duration to be less than or equal to max_duration ({}). Got {}.".format(self.max_duration, self.duration)

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
        assert (self.password.__class__ is str), "Expected password to be a string. Got {}.".format(self.password.__class__)

        # role_arn (Can be blank, we'll just prompt)
        if self.role_arn is not None:
            assert (self.role_arn.__class__ is str), "Expected role_arn to be None or a string. Got {}.".format(self.role_arn.__class__)
            assert ("arn:aws:iam::" in self.role_arn), "Expected role_arn to contain 'arn:aws:iam::'. Got '{}'.".format(self.role_arn)

        # u2f_disabled
        assert (self.u2f_disabled.__class__ is bool), "Expected u2f_disabled to be a boolean. Got {}.".format(self.u2f_disabled.__class__)

    # Write the configuration (and credentials) out to disk. This allows for
    # regular AWS tooling (aws cli and boto) to use the credentials in the
    # profile the user specified.
    def write(self, amazon_object):
        self.ensure_config_files_exist()

        assert (self.profile is not None), "Can not store config/credentials if the AWS_PROFILE is None."

        # Write to the configuration file
        config_parser = configparser.RawConfigParser()
        config_parser.read(self.config_file)
        if not config_parser.has_section(self.profile):
            config_parser.add_section(self.profile)
        config_parser.set(self.profile, 'region', self.region)
        config_parser.set(self.profile, 'aws_google_auth_ask_role', self.ask_role)
        config_parser.set(self.profile, 'aws_google_auth_duration', self.duration)
        config_parser.set(self.profile, 'aws_google_auth_idp_id', self.idp_id)
        config_parser.set(self.profile, 'aws_google_auth_role_arn', self.role_arn)
        config_parser.set(self.profile, 'aws_google_auth_sp_id', self.sp_id)
        config_parser.set(self.profile, 'aws_google_auth_u2f_disabled', self.u2f_disabled)
        config_parser.set(self.profile, 'aws_google_auth_username', self.username)
        with open(self.config_file, 'w+') as f:
            config_parser.write(f)

        # Write to the credentials file (only if we have credentials)
        if amazon_object is not None:
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

    # Read from the configuration file and override ALL values currently stored
    # in the configuration object. As this is potentially destructive, it's
    # important to only run this in the beginning of the object initialization.
    # We do not read AWS credentials, as this tool's use case is to obtain
    # them.
    def read(self, profile):
        self.ensure_config_files_exist()

        profile = util.Util.default_if_none(profile, self.profile)
        config_parser = configparser.RawConfigParser()
        config_parser.read(self.config_file)
        if config_parser.has_section(profile):
            self.profile = profile
            self.ask_role = util.Util.default_if_none(config_parser[profile].getboolean('aws_google_auth_ask_role', None), self.ask_role)
            self.duration = util.Util.default_if_none(config_parser[profile].getint('aws_google_auth_duration', None), self.duration)
            self.idp_id = util.Util.default_if_none(config_parser[profile].get('aws_google_auth_idp_id', None), self.idp_id)
            self.region = util.Util.default_if_none(config_parser[profile].get('region', None), self.region)
            self.role_arn = util.Util.default_if_none(config_parser[profile].get('aws_google_auth_role_arn', None), self.role_arn)
            self.sp_id = util.Util.default_if_none(config_parser[profile].get('aws_google_auth_sp_id', None), self.sp_id)
            self.u2f_disabled = util.Util.default_if_none(config_parser[profile].getboolean('aws_google_auth_u2f_disabled', None), self.u2f_disabled)
            self.username = util.Util.default_if_none(config_parser[profile].get('aws_google_auth_username', None), self.username)
