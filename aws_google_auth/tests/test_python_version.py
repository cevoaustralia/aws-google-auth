from aws_google_auth import exit_if_unsupported_python

import unittest
import sys
import mock


class TestPythonFailOnVersion(unittest.TestCase):

    def test_python26(self):

        with mock.patch.object(sys, 'version_info') as v_info:
            v_info.major = 2
            v_info.minor = 6

            with self.assertRaises(SystemExit) as cm:
                exit_if_unsupported_python()

            self.assertEqual(cm.exception.code, 1)

    def test_python27(self):
        with mock.patch.object(sys, 'version_info') as v_info:
            v_info.major = 2
            v_info.minor = 7

            try:
                exit_if_unsupported_python()
            except SystemExit:
                self.fail("exit_if_unsupported_python() raised SystemExit unexpectedly!")

    def test_python30(self):
        with mock.patch.object(sys, 'version_info') as v_info:
            v_info.major = 3
            v_info.minor = 0

            try:
                exit_if_unsupported_python()
            except SystemExit:
                self.fail("exit_if_unsupported_python() raised SystemExit unexpectedly!")
