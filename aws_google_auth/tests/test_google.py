# -*- coding: utf8 -*-
import sys
import unittest
from io import open
from os import path

from bs4 import BeautifulSoup
from mock import Mock, patch, call, MagicMock

from aws_google_auth import google, u2f
from aws_google_auth import configuration


class TestGoogle(unittest.TestCase):
    @property
    def valid_config(self):
        return configuration.Configuration(
            u2f_disabled=False)

    def read_local_file(self, filename):
        here = path.abspath(path.dirname(__file__))
        with open(path.join(here, filename), encoding='utf8') as fp:
            return fp.read().encode('utf-8')

    def test_extra_step(self):
        response = self.read_local_file('google_error.html')
        response = BeautifulSoup(response, 'html.parser')
        with self.assertRaises(ValueError):
            google.Google.check_extra_step(response)

    def test_u2f_import_true(self):
        mock_config = Mock()
        mock_config.u2f_disabled = False
        google.Google(mock_config, "")

    # @patch('__builtin__.__import__')
    # def test_u2f_import_false(self):
    #     mock_config = Mock()
    #     mock_config.u2f_disabled = False
    #     sys.modules['u2f'] = MagicMock()
    #     # Method under test
    #     google.Google(mock_config, "")
    #
    #     # mock_getattr.assert_called_with(mock_import)
    #
    #     self.assert_any_call()







