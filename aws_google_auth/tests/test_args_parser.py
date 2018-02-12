from .. import parse_args

import unittest


class TestPythonFailOnVersion(unittest.TestCase):

    def test_no_arguments(self):
        parser = parse_args([])

        self.assertTrue(parser.saml_cache)
        self.assertFalse(parser.ask_role)
        self.assertFalse(parser.resolve_aliases)
        self.assertEqual(parser.duration, None)
        self.assertEqual(parser.duration, None)
        self.assertEqual(parser.idp_id, None)
        self.assertEqual(parser.profile, None)
        self.assertEqual(parser.region, None)
        self.assertEqual(parser.role_arn, None)
        self.assertEqual(parser.username, None)

    def test_username(self):

        parser = parse_args(['-u', 'username@gmail.com'])

        self.assertTrue(parser.saml_cache)
        self.assertFalse(parser.ask_role)
        self.assertFalse(parser.resolve_aliases)
        self.assertEqual(parser.duration, None)
        self.assertEqual(parser.duration, None)
        self.assertEqual(parser.idp_id, None)
        self.assertEqual(parser.profile, None)
        self.assertEqual(parser.region, None)
        self.assertEqual(parser.role_arn, None)
        self.assertEqual(parser.username, 'username@gmail.com')

    def test_nocache(self):

        parser = parse_args(['--no-cache'])

        self.assertFalse(parser.saml_cache)
        self.assertFalse(parser.ask_role)
        self.assertFalse(parser.resolve_aliases)
        self.assertEqual(parser.duration, None)
        self.assertEqual(parser.duration, None)
        self.assertEqual(parser.idp_id, None)
        self.assertEqual(parser.profile, None)
        self.assertEqual(parser.region, None)
        self.assertEqual(parser.role_arn, None)
        self.assertEqual(parser.username, None)

    def test_resolvealiases(self):

        parser = parse_args(['--resolve-aliases'])

        self.assertTrue(parser.saml_cache)
        self.assertFalse(parser.ask_role)
        self.assertTrue(parser.resolve_aliases)
        self.assertEqual(parser.duration, None)
        self.assertEqual(parser.duration, None)
        self.assertEqual(parser.idp_id, None)
        self.assertEqual(parser.profile, None)
        self.assertEqual(parser.region, None)
        self.assertEqual(parser.role_arn, None)
        self.assertEqual(parser.username, None)

    def test_ask_and_supply_role(self):

        with self.assertRaises(SystemExit) as se:
            parse_args(['-a', '-r', 'da-role'])
