import ast
import configparser
import os
import botocore.session
from types import MethodType


def get_prepared_config(
        profile,
        region,
        google_username,
        google_idp_id,
        google_sp_id,
        duration
):

    def default_if_none(value, default):
        return value if value is not None else default

    google_config.profile = default_if_none(profile, google_config.profile)

    _create_base_aws_cli_config_files_if_needed(google_config)
    _load_google_config_from_stored_profile(google_config, google_config.profile)

    google_config.region = default_if_none(region, google_config.region)
    google_config.google_username = default_if_none(google_username, google_config.google_username)
    google_config.google_idp_id = default_if_none(google_idp_id, google_config.google_idp_id)
    google_config.google_sp_id = default_if_none(google_sp_id, google_config.google_sp_id)
    google_config.duration = default_if_none(duration, google_config.duration)

    return google_config


def _create_google_default_config():
    config = type('', (), {})()

    # Use botocore session API to get defaults
    session = botocore.session.Session()

    # region: The default AWS region that this script will connect
    # to for all API calls
    config.region = session.get_config_variable('region') or 'eu-central-1'

    # aws cli profile to store config and access keys into
    config.profile = session.profile or 'default'

    # output format: The AWS CLI output format that will be configured in the
    # adf profile (affects subsequent CLI calls)
    config.output_format = session.get_config_variable('format') or 'json'

    # aws credential location: The file where this script will store the temp
    # credentials under the configured profile
    config.aws_credentials_location = os.path.expanduser(session.get_config_variable('credentials_file'))
    config.aws_config_location = os.path.expanduser(session.get_config_variable('config_file'))

    config.role_arn = None
    config.provider = None

    config.google_sp_id = None
    config.google_idp_id = None
    config.google_username = None
    config.duration = 3600

    return config


def _load_google_config_from_stored_profile(google_config, profile):

    def get_or(self, profile, option, default_value):
        if self.has_option(profile, option):
            return self.get(profile, option)
        return default_value

    def load_from_config(config_location, profile, loader):
        config = configparser.RawConfigParser()
        config.read(config_location)
        if config.has_section(profile):
            setattr(config, get_or.__name__, MethodType(get_or, config))
            loader(config, profile)

        del config

    def load_config(config, profile):
        google_config.region = config.get_or(profile, 'region', google_config.region)
        google_config.output_format = config.get_or(profile, 'output', google_config.output_format)

        google_config.role_arn = config.get_or(profile, 'google_config.role_arn', google_config.role_arn)
        google_config.provider = config.get_or(profile, 'google_config.provider', google_config.provider)
        google_config.google_idp_id = config.get_or(profile, 'google_config.google_idp_id', google_config.google_idp_id)
        google_config.google_sp_id = config.get_or(profile, 'google_config.google_sp_id', google_config.google_sp_id)
        google_config.google_username = config.get_or(profile, 'google_config.google_username', google_config.google_username)

    if profile == 'default':
        load_from_config(google_config.aws_config_location, profile, load_config)
    else:
        load_from_config(google_config.aws_config_location, 'profile ' + profile, load_config)


def _create_base_aws_cli_config_files_if_needed(google_config):
    def touch(fname, mode=0o600):
        flags = os.O_CREAT | os.O_APPEND
        with os.fdopen(os.open(fname, flags, mode)) as f:
            try:
                os.utime(fname, None)
            finally:
                f.close()

    aws_config_root = os.path.dirname(google_config.aws_config_location)

    if not os.path.exists(aws_config_root):
        os.mkdir(aws_config_root, 0o700)

    if not os.path.exists(google_config.aws_credentials_location):
        touch(google_config.aws_credentials_location)

    aws_credentials_root = os.path.dirname(google_config.aws_credentials_location)

    if not os.path.exists(aws_credentials_root):
        os.mkdir(aws_credentials_root, 0o700)

    if not os.path.exists(google_config.aws_config_location):
        touch(google_config.aws_config_location)


google_config = _create_google_default_config()
