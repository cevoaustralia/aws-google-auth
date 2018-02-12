from .. import exit_if_unsupported_python

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

import unittest
import sys
import mock


class TestPythonFailOnVersion(unittest.TestCase):

    @mock.patch('sys.stdout', new_callable=StringIO)
    def test_python26(self, mock_stdout):

        with mock.patch.object(sys, 'version_info') as v_info:
            v_info.major = 2
            v_info.minor = 6

            with self.assertRaises(SystemExit):
                exit_if_unsupported_python()

            self.assertIn("aws-google-auth requires Python 2.7 or higher.", mock_stdout.getvalue())

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
