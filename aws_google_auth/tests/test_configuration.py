#!/usr/bin/env python

import unittest
from aws_google_auth import configuration


class TestConfigurationMethods(unittest.TestCase):

    def test_duration_invalid_values(self):
        # Duration must be an integer
        with self.assertRaises(AssertionError) as e:
            configuration.Configuration(
                idp_id="sample_idp_id",
                sp_id="sample_sp_id",
                username="sample_username",
                duration="bad_type")
        self.assertIn("Expected duration to be an integer.", str(e.exception))

        # Duration can not be negative
        with self.assertRaises(AssertionError) as e:
            configuration.Configuration(
                idp_id="sample_idp_id",
                sp_id="sample_sp_id",
                username="sample_username",
                duration=-1)
        self.assertIn("Expected duration to be greater than 0.", str(e.exception))

        # Duration can not be greater than MAX_DURATION
        with self.assertRaises(AssertionError) as e:
            valid = configuration.Configuration(
                idp_id="sample_idp_id",
                sp_id="sample_sp_id",
                username="sample_username",
                duration=100)
            configuration.Configuration(
                idp_id="sample_idp_id",
                sp_id="sample_sp_id",
                username="sample_username",
                duration=(valid.max_duration + 1))
        self.assertIn("Expected duration to be less than or equal to max_duration", str(e.exception))

    def test_duration_valid_values(self):
        c = configuration.Configuration(
            idp_id="sample_idp_id",
            sp_id="sample_sp_id",
            username="sample_username",
            duration=100)
        self.assertEqual(c.duration, 100)
        c.duration = c.max_duration
        self.assertEqual(c.duration, c.max_duration)
        c.duration = (c.max_duration - 1)
        self.assertEqual(c.duration, c.max_duration - 1)

    def test_duration_defaults_to_max_duration(self):
        c = configuration.Configuration(
            idp_id="sample_idp_id",
            sp_id="sample_sp_id",
            username="sample_username")
        self.assertEqual(c.duration, c.max_duration)

    def test_ask_role_invalid_values(self):
        # ask_role must be a boolean
        with self.assertRaises(AssertionError) as e:
            configuration.Configuration(
                idp_id="sample_idp_id",
                sp_id="sample_sp_id",
                username="sample_username",
                ask_role="bad_value")
        self.assertIn("Expected ask_role to be a boolean.", str(e.exception))

    def test_ask_role_valid_values(self):
        c = configuration.Configuration(
            idp_id="sample_idp_id",
            sp_id="sample_sp_id",
            username="sample_username",
            ask_role=True)
        self.assertTrue(c.ask_role)
        c = configuration.Configuration(
            idp_id="sample_idp_id",
            sp_id="sample_sp_id",
            username="sample_username",
            ask_role=False)
        self.assertFalse(c.ask_role)

    def test_ask_role_optional(self):
        c = configuration.Configuration(
            idp_id="sample_idp_id",
            sp_id="sample_sp_id",
            username="sample_username")
        self.assertFalse(c.ask_role)

    def test_idp_id_invalid_values(self):
        # idp_id must not be None
        with self.assertRaises(AssertionError) as e:
            configuration.Configuration(
                sp_id="sample_sp_id",
                username="sample_username")
        self.assertIn("Expected idp_id to be set to non-None value.", str(e.exception))

    def test_idp_id_valid_values(self):
        c = configuration.Configuration(
            idp_id="sample_idp_id",
            sp_id="sample_sp_id",
            username="sample_username")
        self.assertEqual(c.idp_id, "sample_idp_id")
        c.idp_id = 123456
        self.assertEqual(c.idp_id, 123456)

    def test_sp_id_invalid_values(self):
        # sp_id must not be None
        with self.assertRaises(AssertionError) as e:
            configuration.Configuration(
                idp_id="sample_idp_id",
                username="sample_username")
        self.assertIn("Expected sp_id to be set to non-None value.", str(e.exception))

    def test_username_valid_values(self):
        c = configuration.Configuration(
            idp_id="sample_idp_id",
            sp_id="sample_sp_id",
            username="sample_username")
        self.assertEqual(c.username, "sample_username")
        c.username = "123456"
        self.assertEqual(c.username, "123456")

    def test_username_invalid_values(self):
        # username must be set
        with self.assertRaises(AssertionError) as e:
            configuration.Configuration(
                idp_id="sample_idp_id",
                sp_id="sample_sp_id")
        self.assertIn("Expected username to be a string.", str(e.exception))
        # username must be be string
        with self.assertRaises(AssertionError) as e:
            configuration.Configuration(
                idp_id="sample_idp_id",
                sp_id="sample_sp_id",
                username=123456)
        self.assertIn("Expected username to be a string.", str(e.exception))

    def test_sp_id_valid_values(self):
        c = configuration.Configuration(
            idp_id="sample_idp_id",
            sp_id="sample_sp_id",
            username="sample_username")
        self.assertEqual(c.sp_id, "sample_sp_id")
        c.sp_id = 123456
        self.assertEqual(c.sp_id, 123456)

    def test_profile_defaults_to_sts(self):
        c = configuration.Configuration(
            idp_id="sample_idp_id",
            sp_id="sample_sp_id",
            username="sample_username")
        self.assertEqual(c.profile, "sts")

    def test_profile_invalid_values(self):
        # profile must be a string
        with self.assertRaises(AssertionError) as e:
            configuration.Configuration(
                idp_id="sample_idp_id",
                sp_id="sample_sp_id",
                username="sample_username",
                profile=123456)
        self.assertIn("Expected profile to be a string.", str(e.exception))

    def test_profile_valid_values(self):
        c = configuration.Configuration(
            idp_id="sample_idp_id",
            sp_id="sample_sp_id",
            username="sample_username",
            profile="default")
        self.assertEqual(c.profile, "default")
        c.profile = "sts"
        self.assertEqual(c.profile, "sts")

    def test_profile_defaults(self):
        c = configuration.Configuration(
            idp_id="sample_idp_id",
            sp_id="sample_sp_id",
            username="sample_username")
        self.assertEqual(c.profile, 'sts')

    def test_region_invalid_values(self):
        # region must be a string
        with self.assertRaises(AssertionError) as e:
            configuration.Configuration(
                idp_id="sample_idp_id",
                sp_id="sample_sp_id",
                username="sample_username",
                region=1234)
        self.assertIn("Expected region to be a string.", str(e.exception))

    def test_region_valid_values(self):
        c = configuration.Configuration(
            idp_id="sample_idp_id",
            sp_id="sample_sp_id",
            username="sample_username",
            region="us-east-1")
        self.assertEqual(c.region, "us-east-1")
        c.region = "us-west-2"
        self.assertEqual(c.region, "us-west-2")

    def test_region_defaults_to_ap_southeast_2(self):
        c = configuration.Configuration(
            idp_id="sample_idp_id",
            sp_id="sample_sp_id",
            username="sample_username")
        self.assertEqual(c.region, "ap-southeast-2")

    def test_role_arn_invalid_values(self):
        # role_arn must be a string
        with self.assertRaises(AssertionError) as e:
            configuration.Configuration(
                idp_id="sample_idp_id",
                sp_id="sample_sp_id",
                username="sample_username",
                role_arn=1234)
        self.assertIn("Expected role_arn to be None or a string.", str(e.exception))

        # role_arn be a arn-looking string
        with self.assertRaises(AssertionError) as e:
            configuration.Configuration(
                idp_id="sample_idp_id",
                sp_id="sample_sp_id",
                username="sample_username",
                role_arn="bad_string")
        self.assertIn("Expected role_arn to contain 'arn:aws:iam::'", str(e.exception))

    def test_role_arn_is_optional(self):
        c = configuration.Configuration(
            idp_id="sample_idp_id",
            sp_id="sample_sp_id",
            username="sample_username")
        self.assertIsNone(c.role_arn)

    def test_role_arn_valid_values(self):
        c = configuration.Configuration(
            idp_id="sample_idp_id",
            sp_id="sample_sp_id",
            username="sample_username",
            role_arn="arn:aws:iam::some_arn_1")
        self.assertEqual(c.role_arn, "arn:aws:iam::some_arn_1")
        c.role_arn = "arn:aws:iam::some_other_arn_2"
        self.assertEqual(c.role_arn, "arn:aws:iam::some_other_arn_2")

    def test_u2f_disabled_invalid_values(self):
        # u2f_disabled must be a boolean
        with self.assertRaises(AssertionError) as e:
            configuration.Configuration(
                idp_id="sample_idp_id",
                sp_id="sample_sp_id",
                username="sample_username",
                u2f_disabled=1234)
        self.assertIn("Expected u2f_disabled to be a boolean.", str(e.exception))

    def test_u2f_disabled_valid_values(self):
        c = configuration.Configuration(
            idp_id="sample_idp_id",
            sp_id="sample_sp_id",
            username="sample_username",
            u2f_disabled=True)
        self.assertTrue(c.u2f_disabled)
        c = configuration.Configuration(
            idp_id="sample_idp_id",
            sp_id="sample_sp_id",
            username="sample_username",
            u2f_disabled=False)
        self.assertFalse(c.u2f_disabled)

    def test_u2f_disabled_is_optional(self):
        c = configuration.Configuration(
            idp_id="sample_idp_id",
            sp_id="sample_sp_id",
            username="sample_username")
        self.assertFalse(c.u2f_disabled)
