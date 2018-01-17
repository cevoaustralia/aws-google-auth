#!/usr/bin/env python

import configparser
import unittest
from aws_google_auth import configuration
from random import randint


class TestConfigurationPersistence(unittest.TestCase):

    def setUp(self):
        self.c = configuration.Configuration()

        # Pick a profile name that is clear it's for testing. We'll delete it
        # after, but in case something goes wrong we don't want to use
        # something that could clobber user input.
        self.c.profile = "aws_google_auth_test_{}".format(randint(100, 999))

        # Pick a string to do password leakage tests.
        self.c.password = "aws_google_auth_test_password_{}".format(randint(100, 999))

        self.c.region = "us-east-1"
        self.c.ask_role = False
        self.c.duration = 1234
        self.c.idp_id = "sample_idp_id"
        self.c.role_arn = "arn:aws:iam::sample_arn"
        self.c.sp_id = "sample_sp_id"
        self.c.u2f_disabled = False
        self.c.username = "sample_username"
        self.c.raise_if_invalid()
        self.c.write(None)

    def tearDown(self):
        section_name = configuration.Configuration.config_profile(self.c.profile)
        self.config_parser.remove_section(section_name)
        with open(self.c.config_file, 'w') as config_file:
            self.config_parser.write(config_file)

    def test_configuration_backwards_compatibility(self):
        # Configuration
        self.config_parser = configparser.RawConfigParser()
        self.config_parser.read(self.c.config_file)
        profile_string = configuration.Configuration.config_profile(self.c.profile)
        self.assertTrue(self.config_parser.has_section(profile_string))
        self.assertEqual(self.config_parser[profile_string].get('google_config.google_idp_id'), self.c.idp_id)
        self.assertEqual(self.config_parser[profile_string].get('google_config.role_arn'), self.c.role_arn)
        self.assertEqual(self.config_parser[profile_string].get('google_config.google_sp_id'), self.c.sp_id)
        self.assertEqual(self.config_parser[profile_string].get('google_config.google_username'), self.c.username)
        self.assertEqual(self.config_parser[profile_string].get('region'), self.c.region)
        self.assertEqual(self.config_parser[profile_string].getboolean('google_config.ask_role'), self.c.ask_role)
        self.assertEqual(self.config_parser[profile_string].getboolean('google_config.u2f_disabled'), self.c.u2f_disabled)
        self.assertEqual(self.config_parser[profile_string].getint('google_config.duration'), self.c.duration)
