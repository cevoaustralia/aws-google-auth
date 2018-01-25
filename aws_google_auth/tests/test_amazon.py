#!/usr/bin/env python

import unittest

from aws_google_auth import amazon
from aws_google_auth import configuration
from os import path


class TestAmazon(unittest.TestCase):

    @property
    def valid_config(self):
        return configuration.Configuration(
            idp_id="IDPID",
            sp_id="SPID",
            username="user@example.com",
            password="hunter2")

    def read_local_file(self, filename):
        here = path.abspath(path.dirname(__file__))
        with open(path.join(here, filename)) as fp:
            return fp.read().encode('utf-8')

    def test_sts_client(self):
        a = amazon.Amazon(self.valid_config, "dummy-encoded-saml")
        self.assertEqual(str(a.sts_client.__class__), "<class 'botocore.client.STS'>")

    def test_role_extraction(self):
        saml_xml = self.read_local_file('valid-response.xml')
        a = amazon.Amazon(self.valid_config, saml_xml)
        self.assertIsInstance(a.roles, dict)
        list_of_testing_roles = [
            "arn:aws:iam::123456789012:role/admin",
            "arn:aws:iam::123456789012:role/read-only",
            "arn:aws:iam::123456789012:role/test"]
        self.assertEqual(sorted(list(a.roles.keys())), sorted(list_of_testing_roles))

    def test_role_extraction_too_many_commas(self):
        # See https://github.com/cevoaustralia/aws-google-auth/issues/12
        saml_xml = self.read_local_file('too-many-commas.xml')
        a = amazon.Amazon(self.valid_config, saml_xml)
        self.assertIsInstance(a.roles, dict)
        list_of_testing_roles = [
            "arn:aws:iam::123456789012:role/admin",
            "arn:aws:iam::123456789012:role/read-only",
            "arn:aws:iam::123456789012:role/test"]
        self.assertEqual(sorted(list(a.roles.keys())), sorted(list_of_testing_roles))

    def test_invalid_saml_too_soon(self):
        saml_xml = self.read_local_file('saml-response-too-soon.xml')
        self.assertFalse(amazon.Amazon.is_valid_saml_assertion(saml_xml))

    def test_invalid_saml_too_late(self):
        saml_xml = self.read_local_file('saml-response-too-late.xml')
        self.assertFalse(amazon.Amazon.is_valid_saml_assertion(saml_xml))

    def test_invalid_saml_expired_before_valid(self):
        saml_xml = self.read_local_file('saml-response-expired-before-valid.xml')
        self.assertFalse(amazon.Amazon.is_valid_saml_assertion(saml_xml))

    def test_invalid_saml_bad_input(self):
        self.assertFalse(amazon.Amazon.is_valid_saml_assertion(None))
        self.assertFalse(amazon.Amazon.is_valid_saml_assertion("Malformed Base64"))
        self.assertFalse(amazon.Amazon.is_valid_saml_assertion(123456))
        self.assertFalse(amazon.Amazon.is_valid_saml_assertion(''))
        self.assertFalse(amazon.Amazon.is_valid_saml_assertion("QmFkIFhNTA=="))  # Bad XML

    def test_valid_saml(self):
        saml_xml = self.read_local_file('saml-response-no-expire.xml')
        self.assertTrue(amazon.Amazon.is_valid_saml_assertion(saml_xml))
