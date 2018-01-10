#!/usr/bin/env python

import sys
import unittest
from aws_google_auth import util


class TestUtilMethods(unittest.TestCase):

    def test_default_if_none(self):
        value = "non_none_value"
        self.assertEqual(util.Util.default_if_none(value, None), value)
        self.assertEqual(util.Util.default_if_none(None, value), value)
        self.assertEqual(util.Util.default_if_none(None, None), None)

    def test_unicode_to_string_if_needed_python_3(self):
        if sys.version_info >= (3, 0):
            value_string = "Test String!"
            self.assertIsInstance(value_string, str)
            self.assertEqual(util.Util.unicode_to_string_if_needed(value_string), value_string)

    def test_unicode_to_string_if_needed_python_2(self):
        if sys.version_info < (3, 0):
            value_string = "Test String!"
            value_unicode = value_string.decode('utf-8')
            self.assertIsInstance(value_string, str)
            self.assertIsInstance(value_unicode, unicode)
            self.assertEqual(util.Util.unicode_to_string_if_needed(value_unicode), value_string)
            self.assertEqual(util.Util.unicode_to_string_if_needed(value_string), value_string)
