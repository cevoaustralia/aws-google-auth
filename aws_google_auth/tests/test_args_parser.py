#!/usr/bin/env python

import unittest

from aws_google_auth import parse_args


class TestPythonFailOnVersion(unittest.TestCase):

    def test_no_arguments(self):
        """
        This test case exists to validate the default settings of the args parser.
        Changes that break these checks should be considered for backwards compatibility review.
        :return:
        """
        parser = parse_args([])

        self.assertTrue(parser.saml_cache)
        self.assertEqual(parser.saml_assertion, None)
        self.assertFalse(parser.ask_role)
        self.assertFalse(parser.print_creds)
        self.assertFalse(parser.keyring)
        self.assertFalse(parser.resolve_aliases)
        self.assertFalse(parser.disable_u2f, None)

        self.assertEqual(parser.duration, None)
        self.assertEqual(parser.auto_duration, False)
        self.assertEqual(parser.idp_id, None)
        self.assertEqual(parser.sp_id, None)
        self.assertEqual(parser.profile, None)
        self.assertEqual(parser.region, None)
        self.assertEqual(parser.role_arn, None)
        self.assertEqual(parser.username, None)
        self.assertEqual(parser.quiet, False)
        self.assertEqual(parser.bg_response, None)
        self.assertEqual(parser.account, None)

        self.assertFalse(parser.save_failure_html)
        self.assertFalse(parser.save_saml_flow)

        # Assert the size of the parameter so that new parameters trigger a review of this function
        # and the appropriate defaults are added here to track backwards compatibility in the future.
        self.assertEqual(len(vars(parser)), 21)

    def test_username(self):

        parser = parse_args(['-u', 'username@gmail.com'])

        self.assertTrue(parser.saml_cache)
        self.assertFalse(parser.ask_role)
        self.assertFalse(parser.keyring)
        self.assertFalse(parser.resolve_aliases)
        self.assertEqual(parser.duration, None)
        self.assertEqual(parser.auto_duration, False)
        self.assertEqual(parser.idp_id, None)
        self.assertEqual(parser.profile, None)
        self.assertEqual(parser.region, None)
        self.assertEqual(parser.role_arn, None)
        self.assertEqual(parser.username, 'username@gmail.com')
        self.assertEqual(parser.account, None)

    def test_nocache(self):

        parser = parse_args(['--no-cache'])

        self.assertFalse(parser.saml_cache)
        self.assertFalse(parser.ask_role)
        self.assertFalse(parser.keyring)
        self.assertFalse(parser.resolve_aliases)
        self.assertEqual(parser.duration, None)
        self.assertEqual(parser.auto_duration, False)
        self.assertEqual(parser.idp_id, None)
        self.assertEqual(parser.profile, None)
        self.assertEqual(parser.region, None)
        self.assertEqual(parser.role_arn, None)
        self.assertEqual(parser.username, None)
        self.assertEqual(parser.account, None)

    def test_resolvealiases(self):

        parser = parse_args(['--resolve-aliases'])

        self.assertTrue(parser.saml_cache)
        self.assertFalse(parser.ask_role)
        self.assertFalse(parser.keyring)
        self.assertTrue(parser.resolve_aliases)
        self.assertEqual(parser.duration, None)
        self.assertEqual(parser.auto_duration, False)
        self.assertEqual(parser.idp_id, None)
        self.assertEqual(parser.profile, None)
        self.assertEqual(parser.region, None)
        self.assertEqual(parser.role_arn, None)
        self.assertEqual(parser.username, None)
        self.assertEqual(parser.account, None)

    def test_ask_and_supply_role(self):

        with self.assertRaises(SystemExit):
            parse_args(['-a', '-r', 'da-role'])

    def test_invalid_duration(self):
        """
        Should fail parsing a non-int value for `-d`.
        :return:
        """

        with self.assertRaises(SystemExit):
            parse_args(['-d', 'abce'])
