import aws_google_auth
from aws_google_auth import prepare

from os import path
from lxml import etree

import unittest
import mock


class TestPersistConfig(unittest.TestCase):

    def setUp(self):

        prepare.google_config.region = "test_region"
        prepare.google_config.role_arn = None

        prepare.google_config.profile = None

        prepare.google_config.output_format = "json"
        # prepare.google_config.aws_credentials_location = "creds"
        # prepare.google_config.aws_config_location = "config"

        prepare.google_config.role_arn = None
        prepare.google_config.provider = None

        prepare.google_config.google_sp_id = None
        prepare.google_config.google_idp_id = None
        prepare.google_config.google_username = None
        prepare.google_config.duration = 3600
        prepare.google_config.ask_role = False

    def test_when_there_is_no_profile_use_supplied_values(self):
        # given profile to read the configuration doesn't exist
        not_existing_profile = 'not_existing_profile'
        prepare.configparser = mock.Mock()
        config_without_non_existing_profile = mock.Mock()
        prepare.configparser.RawConfigParser = mock.Mock(return_value=config_without_non_existing_profile)
        config_without_non_existing_profile.has_section = mock.Mock(return_value=False)

        # and values supplied are setup as follows
        default_username = 'default_username'
        default_region = 'default_region'
        default_idp_id = 'default_idp_id'
        default_sp_id = 'default_sp_id'
        default_duration = 'default_duration'
        ask_role = 'default_ask_role'
        role_arn = 'default_role_arn'

        # when configuration is prepared for not existing profile
        config = prepare.get_prepared_config(
            not_existing_profile,
            default_region,
            default_username,
            default_idp_id,
            default_sp_id,
            default_duration,
            ask_role,
            role_arn
        )

        # then the supplied values are merged with the defaults
        self.assertTrue(config is not None)
        self.assertEquals(config.region, default_region)
        self.assertEquals(config.google_username, default_username)
        self.assertEquals(config.google_idp_id, default_idp_id)
        self.assertEquals(config.google_sp_id, default_sp_id)
        self.assertEquals(config.duration, default_duration)
        self.assertEquals(config.ask_role, ask_role)
        self.assertEquals(config.role_arn, role_arn)

    def test_when_there_is_no_profile_use_default_values(self):

        # given profile to read the configuration doesn't exist
        prepare.configparser = mock.Mock()
        config_without_non_existing_profile = mock.Mock()
        prepare.configparser.RawConfigParser = mock.Mock(return_value=config_without_non_existing_profile)
        config_without_non_existing_profile.has_section = mock.Mock(return_value=False)

        # and no values are supplied
        profile = None
        region = None
        username = None
        idp_id = None
        sp_id = None
        duration = None
        ask_role = None
        role_arn = None

        # when configuration is prepared for not existing profile
        config = prepare.get_prepared_config(
            profile,
            region,
            username,
            idp_id,
            sp_id,
            duration,
            ask_role,
            role_arn
        )

        # then the defaults are returned
        self.assertTrue(config is not None)
        self.assertEquals(config.region, "test_region")
        self.assertEquals(config.google_username, None)
        self.assertEquals(config.google_idp_id, None)
        self.assertEquals(config.google_sp_id, None)
        self.assertEquals(config.duration, 3600)
        self.assertEquals(config.ask_role, False)
        self.assertEquals(config.profile, None)
        self.assertEquals(config.role_arn, None)
