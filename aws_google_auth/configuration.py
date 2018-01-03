#!/usr/bin/env python

import os
import botocore.session
import configparser

from . import util


class Configuration:

    def __init__(self, **kwargs):
        self.set_ask_role(kwargs.get('ask_role', None) or os.getenv("AWS_ASK_ROLE") or False)
        self.set_duration(kwargs.get('duration', None) or os.getenv("DURATION") or self.max_duration)
        self.set_u2f_disabled(kwargs.get('u2f_disabled', None) or os.getenv("U2F_DISABLED") or False)
        self.set_region(kwargs.get('region', None) or os.getenv("AWS_DEFAULT_REGION") or 'ap-southeast-2')
        self.set_profile(kwargs.get('profile', None) or os.getenv("AWS_PROFILE") or 'sts')
        self.set_role_arn(kwargs.get('role_arn', None) or os.getenv("AWS_ROLE_ARN") or None)
        self.set_idp_id(kwargs.get('idp_id', None) or os.getenv("GOOGLE_IDP_ID") or None)
        self.set_sp_id(kwargs.get('sp_id', None) or os.getenv("GOOGLE_SP_ID") or None)
        self.set_username(kwargs.get('username', None) or os.getenv("GOOGLE_USERNAME") or None)
        self.password = kwargs.get('password', None) or None
        self.__boto_session = botocore.session.Session()

    @property
    def max_duration(self):
        return 3600

    def get_ask_role(self):
        return self.__ask_role

    def set_ask_role(self, value):
        assert (value.__class__ is bool), "Expected ask_role to be a boolean. Got {}.".format(value.__class__)
        self.__ask_role = value

    ask_role = property(get_ask_role, set_ask_role)

    def get_duration(self):
        return self.__duration

    def set_duration(self, duration_seconds):
        assert (duration_seconds.__class__ is int), "Expected duration to be an integer. Got {}.".format(duration_seconds.__class__)
        assert (duration_seconds > 0), "Expected duration to be greater than 0. Got {}.".format(duration_seconds)
        assert (duration_seconds <= self.max_duration), "Expected duration to be less than or equal to max_duration ({}). Got {}.".format(self.max_duration, duration_seconds)
        self.__duration = duration_seconds

    duration = property(get_duration, set_duration)

    def get_profile(self):
        return self.__profile

    def set_profile(self, profile):
        assert (profile.__class__ is str), "Expected profile to be a string. Got {}.".format(profile.__class__)
        self.__profile = profile

    profile = property(get_profile, set_profile)

    def get_region(self):
        return self.__region

    def set_region(self, region):
        assert (region.__class__ is str), "Expected region to be a string. Got {}.".format(region.__class__)
        self.__region = region

    region = property(get_region, set_region)

    def get_idp_id(self):
        return self.__idp_id

    def set_idp_id(self, idp):
        assert (idp is not None), "Expected idp_id to be set to non-None value."
        self.__idp_id = idp

    idp_id = property(get_idp_id, set_idp_id)

    def get_sp_id(self):
        return self.__sp_id

    def set_sp_id(self, sp_id):
        assert (sp_id is not None), "Expected sp_id to be set to non-None value."
        self.__sp_id = sp_id

    sp_id = property(get_sp_id, set_sp_id)

    def get_username(self):
        return self.__username

    def set_username(self, username):
        assert (username.__class__ is str), "Expected username to be a string. Got {}.".format(username.__class__)
        self.__username = username

    username = property(get_username, set_username)

    def get_role_arn(self):
        return self.__role_arn

    def set_role_arn(self, arn):
        if arn is not None:
            assert (arn.__class__ is str), "Expected role_arn to be None or a string. Got {}.".format(arn.__class__)
            assert ("arn:aws:iam::" in arn), "Expected role_arn to contain 'arn:aws:iam::'. Got '{}'.".format(arn)
        self.__role_arn = arn

    role_arn = property(get_role_arn, set_role_arn)

    def get_u2f_disabled(self):
        return self.__u2f_disabled

    def set_u2f_disabled(self, u2f_disabled):
        assert (u2f_disabled.__class__ is bool), "Expected u2f_disabled to be a boolean. Got {}.".format(u2f_disabled.__class__)
        self.__u2f_disabled = u2f_disabled

    u2f_disabled = property(get_u2f_disabled, set_u2f_disabled)

    def get_credentials_file(self):
        return os.path.expanduser(self.__boto_session.get_config_variable('credentials_file'))

    credentials_file = property(get_credentials_file)

    def get_config_file(self):
        return os.path.expanduser(self.__boto_session.get_config_variable('config_file'))

    config_file = property(get_config_file)

    def ensure_config_files_exist(self):
        for file in [self.config_file, self.credentials_file]:
            directory = os.path.dirname(file)
            if not os.path.exists(directory):
                os.mkdir(directory, 0o700)
            if not os.path.exists(file):
                util.Util.touch(file)

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
        config_parser.set(self.profile, 'aws_google_auth_u2f_disabled', self.u2f_disabled)
        config_parser.set(self.profile, 'aws_google_auth_region', self.region)
        config_parser.set(self.profile, 'aws_google_auth_profile', self.profile)
        config_parser.set(self.profile, 'aws_google_auth_role_arn', self.role_arn)
        config_parser.set(self.profile, 'aws_google_auth_idp_id', self.idp_id)
        config_parser.set(self.profile, 'aws_google_auth_sp_id', self.sp_id)
        config_parser.set(self.profile, 'aws_google_auth_username', self.username)
        with open(self.config_file, 'w+') as f:
            config_parser.write(f)

        # Write to the credentials file
        credentials_parser = configparser.RawConfigParser()
        credentials_parser.read(self.credentials_file)
        if not credentials_parser.has_section(self.profile):
            credentials_parser.add_section(self.profile)
        credentials_parser.set(self.profile, 'aws_access_key_id', amazon_object.access_key_id)
        credentials_parser.set(self.profile, 'aws_secret_access_key', amazon_object.secret_access_key)
        credentials_parser.set(self.profile, 'aws_session_token', amazon_object.session_token)
        credentials_parser.set(self.profile, 'aws_security_token', amazon_object.session_token)
        credentials_parser.set(self.profile, 'aws_session_expiration', amazon_object.expiration.strftime('%Y-%m-%dT%H:%M:%S%z'))
        with open(self.credentials_file, 'w+') as f:
            credentials_parser.write(f)
