# -*- coding: utf8 -*-
import unittest
from io import open
from os import path
from bs4 import BeautifulSoup

from aws_google_auth import google


class TestGoogle(unittest.TestCase):
    def read_local_file(self, filename):
        here = path.abspath(path.dirname(__file__))
        with open(path.join(here, filename), encoding='utf8') as fp:
            return fp.read().encode('utf-8')

    def test_extra_step(self):
        response = self.read_local_file('google_error.html')
        response = BeautifulSoup(response, 'html.parser')
        with self.assertRaises(ValueError):
            google.Google.check_extra_step(response)
