#!/usr/bin/env python

import base64
import unittest

from aws_google_auth import amazon
from aws_google_auth import configuration
from os import path


class TestAmazon(unittest.TestCase):

    def valid_config(self):
        return configuration.Configuration(
            idp_id="IDPID",
            sp_id="SPID",
            username="user@example.com",
            password="hunter2")

    def valid_saml_response(self):
        here = path.abspath(path.dirname(__file__))
        with open(path.join(here, 'valid-response.xml')) as fp:
            return base64.b64encode(fp.read().encode('utf-8'))
        return None

    def extra_comma_saml_response(self):
        here = path.abspath(path.dirname(__file__))
        with open(path.join(here, 'too-many-commas.xml')) as fp:
            return base64.b64encode(fp.read().encode('utf-8'))
        return None

    def test_sts_client(self):
        a = amazon.Amazon(self.valid_config(), "encoded-saml")
        self.assertEqual(str(a.sts_client.__class__), "<class 'botocore.client.STS'>")

    def test_role_extraction(self):
        a = amazon.Amazon(self.valid_config(), self.valid_saml_response())
        self.assertIsInstance(a.roles, dict)
        list_of_testing_roles = [
            "arn:aws:iam::123456789012:role/admin",
            "arn:aws:iam::123456789012:role/read-only",
            "arn:aws:iam::123456789012:role/test"]
        self.assertEqual(sorted(list(a.roles.keys())), sorted(list_of_testing_roles))

    def test_role_extraction_too_many_commas(self):
        # See https://github.com/cevoaustralia/aws-google-auth/issues/12
        a = amazon.Amazon(self.valid_config(), self.extra_comma_saml_response())
        self.assertIsInstance(a.roles, dict)
        list_of_testing_roles = [
            "arn:aws:iam::123456789012:role/admin",
            "arn:aws:iam::123456789012:role/read-only",
            "arn:aws:iam::123456789012:role/test"]
        self.assertEqual(sorted(list(a.roles.keys())), sorted(list_of_testing_roles))
