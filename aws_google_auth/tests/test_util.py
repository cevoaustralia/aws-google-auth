#!/usr/bin/env python

import unittest
from aws_google_auth import util


class TestUtilMethods(unittest.TestCase):

    def test_default_if_none(self):
        value = "non_none_value"
        self.assertEqual(util.Util.default_if_none(value, None), value)
        self.assertEqual(util.Util.default_if_none(None, value), value)
        self.assertEqual(util.Util.default_if_none(None, None), None)
