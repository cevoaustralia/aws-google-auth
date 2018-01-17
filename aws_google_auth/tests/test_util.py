#!/usr/bin/env python

import sys
import unittest
from aws_google_auth import util


class TestUtilMethods(unittest.TestCase):

    def test_coalesce_no_arguments(self):
        self.assertEqual(util.Util.coalesce(), None)

    def test_coalesce_one_argument(self):
        value = "non_none_value"
        self.assertEqual(util.Util.coalesce(value), value)
        self.assertEqual(util.Util.coalesce(None), None)

    def test_coalesce_two_arguments(self):
        value = "non_none_value"
        self.assertEqual(util.Util.coalesce(value, None), value)
        self.assertEqual(util.Util.coalesce(value, value), value)
        self.assertEqual(util.Util.coalesce(None, value), value)
        self.assertEqual(util.Util.coalesce(None, None), None)

    def test_coalesce_many_arguments(self):
        self.assertEqual(util.Util.coalesce(None, "test-01", None, "test-02", None, "test-03"), "test-01")
        self.assertEqual(util.Util.coalesce("test-01", None, "test-02", None, "test-03", None), "test-01")
        self.assertEqual(util.Util.coalesce(None, None, None, None, None, None, None, None, None, None, "test-01"), "test-01")

    def test_unicode_to_string_if_needed_python_3(self):
        if sys.version_info >= (3, 0):
            value_string = "Test String!"
            self.assertIn("str", str(value_string.__class__))
            self.assertEqual(util.Util.unicode_to_string_if_needed(value_string), value_string)

    def test_unicode_to_string_if_needed_python_2(self):
        if sys.version_info < (3, 0):
            value_string = "Test String!"
            value_unicode = value_string.decode('utf-8')
            self.assertIn("str", str(value_string.__class__))
            self.assertIn("unicode", str(value_unicode.__class__))
            self.assertEqual(util.Util.unicode_to_string_if_needed(value_unicode), value_string)
            self.assertEqual(util.Util.unicode_to_string_if_needed(value_string), value_string)

    def test_unicode_to_string_if_needed(self):
        self.assertEqual(util.Util.unicode_to_string_if_needed(None), None)
        self.assertEqual(util.Util.unicode_to_string_if_needed(1234), 1234)
        self.assertEqual(util.Util.unicode_to_string_if_needed("nop"), "nop")
