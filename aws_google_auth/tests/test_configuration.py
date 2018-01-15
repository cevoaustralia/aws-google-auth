#!/usr/bin/env python

import unittest
from aws_google_auth import configuration


class TestConfigurationMethods(unittest.TestCase):

    def test_config_profile(self):
        self.assertEqual(configuration.Configuration.config_profile('default'), 'default')
        self.assertEqual(configuration.Configuration.config_profile('DEFAULT'), 'DEFAULT')
        self.assertEqual(configuration.Configuration.config_profile('testing'), 'profile testing')
        self.assertEqual(configuration.Configuration.config_profile(None), 'profile None')
        self.assertEqual(configuration.Configuration.config_profile(123456), 'profile 123456')

    def test_duration_invalid_values(self):
        # Duration must be an integer
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.password = "hunter2"
        c.sp_id = "sample_sp_id"
        c.username = "sample_username"
        c.duration = "bad_type"
        with self.assertRaises(AssertionError) as e:
            c.raise_if_invalid()
        self.assertIn("Expected duration to be an integer.", str(e.exception))

        # Duration can not be negative
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.password = "hunter2"
        c.username = "sample_username"
        c.duration = -1
        with self.assertRaises(AssertionError) as e:
            c.raise_if_invalid()
        self.assertIn("Expected duration to be greater than 0.", str(e.exception))

        # Duration can not be greater than MAX_DURATION
        valid = configuration.Configuration()
        valid.idp_id = "sample_idp_id"
        c.password = "hunter2"
        valid.sp_id = "sample_sp_id"
        valid.username = "sample_username"
        valid.duration = 100
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.password = "hunter2"
        c.username = "sample_username"
        c.duration = (valid.max_duration + 1)
        with self.assertRaises(AssertionError) as e:
            c.raise_if_invalid()
        self.assertIn("Expected duration to be less than or equal to max_duration", str(e.exception))

    def test_duration_valid_values(self):
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.password = "hunter2"
        c.username = "sample_username"
        c.duration = 100
        self.assertEqual(c.duration, 100)
        c.raise_if_invalid()
        c.duration = c.max_duration
        self.assertEqual(c.duration, c.max_duration)
        c.raise_if_invalid()
        c.duration = (c.max_duration - 1)
        self.assertEqual(c.duration, c.max_duration - 1)
        c.raise_if_invalid()

    def test_duration_defaults_to_max_duration(self):
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.password = "hunter2"
        c.username = "sample_username"
        self.assertEqual(c.duration, c.max_duration)
        c.raise_if_invalid()

    def test_ask_role_invalid_values(self):
        # ask_role must be a boolean
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.password = "hunter2"
        c.username = "sample_username"
        c.ask_role = "bad_value"
        with self.assertRaises(AssertionError) as e:
            c.raise_if_invalid()
        self.assertIn("Expected ask_role to be a boolean.", str(e.exception))

    def test_ask_role_valid_values(self):
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.password = "hunter2"
        c.username = "sample_username"
        c.ask_role = True
        self.assertTrue(c.ask_role)
        c.raise_if_invalid()
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.password = "hunter2"
        c.sp_id = "sample_sp_id"
        c.username = "sample_username"
        c.ask_role = False
        self.assertFalse(c.ask_role)
        c.raise_if_invalid()

    def test_ask_role_optional(self):
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.password = "hunter2"
        c.username = "sample_username"
        self.assertFalse(c.ask_role)
        c.raise_if_invalid()

    def test_idp_id_invalid_values(self):
        # idp_id must not be None
        c = configuration.Configuration()
        c.sp_id = "sample_sp_id"
        c.password = "hunter2"
        c.username = "sample_username"
        with self.assertRaises(AssertionError) as e:
            c.raise_if_invalid()
        self.assertIn("Expected idp_id to be set to non-None value.", str(e.exception))

    def test_idp_id_valid_values(self):
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.password = "hunter2"
        c.username = "sample_username"
        self.assertEqual(c.idp_id, "sample_idp_id")
        c.raise_if_invalid()
        c.idp_id = 123456
        self.assertEqual(c.idp_id, 123456)
        c.raise_if_invalid()

    def test_sp_id_invalid_values(self):
        # sp_id must not be None
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.password = "hunter2"
        c.username = "sample_username"
        with self.assertRaises(AssertionError) as e:
            c.raise_if_invalid()
        self.assertIn("Expected sp_id to be set to non-None value.", str(e.exception))

    def test_username_valid_values(self):
        c = configuration.Configuration()
        c.password = "hunter2"
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.username = "sample_username"
        self.assertEqual(c.username, "sample_username")
        c.raise_if_invalid()
        c.username = "123456"
        self.assertEqual(c.username, "123456")
        c.raise_if_invalid()

    def test_username_invalid_values(self):
        # username must be set
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.password = "hunter2"
        c.sp_id = "sample_sp_id"
        with self.assertRaises(AssertionError) as e:
            c.raise_if_invalid()
        self.assertIn("Expected username to be a string.", str(e.exception))
        # username must be be string
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.password = "hunter2"
        c.username = 123456
        with self.assertRaises(AssertionError) as e:
            c.raise_if_invalid()
        self.assertIn("Expected username to be a string.", str(e.exception))

    def test_password_valid_values(self):
        c = configuration.Configuration()
        c.password = "hunter2"
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.username = "sample_username"
        self.assertEqual(c.password, "hunter2")
        c.raise_if_invalid()
        c.password = "123456"
        self.assertEqual(c.password, "123456")
        c.raise_if_invalid()

    def test_password_invalid_values(self):
        # password must be set
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.username = "sample_username"
        c.sp_id = "sample_sp_id"
        with self.assertRaises(AssertionError) as e:
            c.raise_if_invalid()
        self.assertIn("Expected password to be a string.", str(e.exception))
        # password must be be string
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.password = 123456
        c.username = "sample_username"
        with self.assertRaises(AssertionError) as e:
            c.raise_if_invalid()
        self.assertIn("Expected password to be a string.", str(e.exception))

    def test_sp_id_valid_values(self):
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.username = "sample_username"
        c.password = "hunter2"
        self.assertEqual(c.sp_id, "sample_sp_id")
        c.raise_if_invalid()
        c.sp_id = 123456
        self.assertEqual(c.sp_id, 123456)
        c.raise_if_invalid()

    def test_profile_defaults_to_sts(self):
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.password = "hunter2"
        c.sp_id = "sample_sp_id"
        c.username = "sample_username"
        self.assertEqual(c.profile, "sts")
        c.raise_if_invalid()

    def test_profile_invalid_values(self):
        # profile must be a string
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.password = "hunter2"
        c.username = "sample_username"
        c.profile = 123456
        with self.assertRaises(AssertionError) as e:
            c.raise_if_invalid()
        self.assertIn("Expected profile to be a string.", str(e.exception))

    def test_profile_valid_values(self):
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.password = "hunter2"
        c.sp_id = "sample_sp_id"
        c.username = "sample_username"
        c.profile = "default"
        self.assertEqual(c.profile, "default")
        c.raise_if_invalid()
        c.profile = "sts"
        self.assertEqual(c.profile, "sts")
        c.raise_if_invalid()

    def test_profile_defaults(self):
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.password = "hunter2"
        c.sp_id = "sample_sp_id"
        c.username = "sample_username"
        self.assertEqual(c.profile, 'sts')
        c.raise_if_invalid()

    def test_region_invalid_values(self):
        # region must be a string
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.password = "hunter2"
        c.username = "sample_username"
        c.region = 1234
        with self.assertRaises(AssertionError) as e:
            c.raise_if_invalid()
        self.assertIn("Expected region to be a string.", str(e.exception))

    def test_region_valid_values(self):
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.password = "hunter2"
        c.username = "sample_username"
        c.region = "us-east-1"
        self.assertEqual(c.region, "us-east-1")
        c.raise_if_invalid()
        c.region = "us-west-2"
        self.assertEqual(c.region, "us-west-2")
        c.raise_if_invalid()

    def test_region_defaults_to_ap_southeast_2(self):
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.username = "sample_username"
        c.password = "hunter2"
        self.assertEqual(c.region, "ap-southeast-2")
        c.raise_if_invalid()

    def test_role_arn_invalid_values(self):
        # role_arn must be a string
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.password = "hunter2"
        c.username = "sample_username"
        c.role_arn = 1234
        with self.assertRaises(AssertionError) as e:
            c.raise_if_invalid()
        self.assertIn("Expected role_arn to be None or a string.", str(e.exception))

        # role_arn be a arn-looking string
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.password = "hunter2"
        c.username = "sample_username"
        c.role_arn = "bad_string"
        with self.assertRaises(AssertionError) as e:
            c.raise_if_invalid()
        self.assertIn("Expected role_arn to contain 'arn:aws:iam::'", str(e.exception))

    def test_role_arn_is_optional(self):
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.password = "hunter2"
        c.username = "sample_username"
        self.assertIsNone(c.role_arn)
        c.raise_if_invalid()

    def test_role_arn_valid_values(self):
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.username = "sample_username"
        c.password = "hunter2"
        c.role_arn = "arn:aws:iam::some_arn_1"
        self.assertEqual(c.role_arn, "arn:aws:iam::some_arn_1")
        c.raise_if_invalid()
        c.role_arn = "arn:aws:iam::some_other_arn_2"
        self.assertEqual(c.role_arn, "arn:aws:iam::some_other_arn_2")
        c.raise_if_invalid()

    def test_u2f_disabled_invalid_values(self):
        # u2f_disabled must be a boolean
        c = configuration.Configuration()
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.username = "sample_username"
        c.password = "hunter2"
        c.u2f_disabled = 1234
        with self.assertRaises(AssertionError) as e:
            c.raise_if_invalid()
        self.assertIn("Expected u2f_disabled to be a boolean.", str(e.exception))

    def test_u2f_disabled_valid_values(self):
        c = configuration.Configuration()
        c.password = "hunter2"
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.username = "sample_username"
        c.u2f_disabled = True
        self.assertTrue(c.u2f_disabled)
        c.raise_if_invalid()
        c = configuration.Configuration()
        c.password = "hunter2"
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.username = "sample_username"
        c.u2f_disabled = False
        self.assertFalse(c.u2f_disabled)
        c.raise_if_invalid()

    def test_u2f_disabled_is_optional(self):
        c = configuration.Configuration()
        c.password = "hunter2"
        c.idp_id = "sample_idp_id"
        c.sp_id = "sample_sp_id"
        c.username = "sample_username"
        self.assertFalse(c.u2f_disabled)
        c.raise_if_invalid()
