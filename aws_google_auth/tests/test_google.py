# -*- coding: utf-8 -*-
import unittest
from io import open
from os import path

import json
import base64

from bs4 import BeautifulSoup

from mock import Mock, patch
from six import StringIO

from aws_google_auth import google


class TestGoogle(unittest.TestCase):
    def read_local_file(self, filename):
        here = path.abspath(path.dirname(__file__))
        with open(path.join(here, filename), encoding='utf-8') as fp:
            return fp.read().encode('utf-8')

    def test_extra_step(self):
        response = self.read_local_file('google_error.html')
        response = BeautifulSoup(response, 'html.parser')
        with self.assertRaises(ValueError):
            google.Google.check_extra_step(response)

    def test_check_prompt_code_current_markup(self):
        # Number-matching challenge page as served in 2026:
        # the number lives in a <samp jsname="feLNVc"> element.
        # The print is the actual fix for #77/#23 (the user cannot see
        # the rendered page), so pin it alongside the return value.
        response = self.read_local_file('google_prompt_number_challenge.html')
        response = BeautifulSoup(response, 'html.parser')
        with patch('sys.stdout', new=StringIO()) as stdout:
            self.assertEqual(google.Google.check_prompt_code(response), '97')
        self.assertIn('97', stdout.getvalue())

    def test_check_prompt_code_legacy_markup(self):
        # Older challenge pages carried the number in <div jsname="EKvSSd">.
        response = self.read_local_file(
            'google_prompt_number_challenge_legacy.html')
        response = BeautifulSoup(response, 'html.parser')
        self.assertEqual(google.Google.check_prompt_code(response), '42')

    def test_check_prompt_code_text_fallback(self):
        # If the structured elements are absent, fall back to the
        # instruction sentence.
        html = (u'<html><body><p>Tap <b>Yes</b> on the notification, '
                u'then tap <b>7</b> on your phone to verify.</p>'
                u'</body></html>').encode('utf-8')
        response = BeautifulSoup(html, 'html.parser')
        self.assertEqual(google.Google.check_prompt_code(response), '7')

    def test_check_prompt_code_samp_only(self):
        # The <samp> branch must work on its own, with no instruction
        # sentence (e.g. localized pages where the text fallback cannot
        # match).
        html = (u'<html><body><samp class="IEIJ3d" jsname="feLNVc">12'
                u'</samp></body></html>').encode('utf-8')
        response = BeautifulSoup(html, 'html.parser')
        self.assertEqual(google.Google.check_prompt_code(response), '12')

    def test_check_prompt_code_non_digit_samp(self):
        # <samp> is ordinary HTML for computer output; non-numeric
        # content must not be mistaken for a challenge number.
        html = (u'<html><body><samp>Ctrl+C</samp><p>no challenge</p>'
                u'</body></html>').encode('utf-8')
        response = BeautifulSoup(html, 'html.parser')
        self.assertIsNone(google.Google.check_prompt_code(response))

    def test_check_prompt_code_skips_non_digit_samp(self):
        # A numeric <samp> must still be found when a non-numeric one
        # precedes it in document order, even without the jsname
        # attribute (exercises the generic scan branch).
        html = (u'<html><body><samp>Ctrl+C</samp>'
                u'<samp>31</samp>'
                u'</body></html>').encode('utf-8')
        response = BeautifulSoup(html, 'html.parser')
        self.assertEqual(google.Google.check_prompt_code(response), '31')

    def test_check_prompt_code_non_digit_legacy_div(self):
        # The legacy selector must also reject non-numeric content
        # rather than print it as a challenge number.
        html = (u'<html><body><div jsname="EKvSSd">N/A</div>'
                u'</body></html>').encode('utf-8')
        response = BeautifulSoup(html, 'html.parser')
        self.assertIsNone(google.Google.check_prompt_code(response))

    def test_check_prompt_code_absent(self):
        # Pages without a number-matching challenge must return None
        # and print nothing that could mislead the user.
        response = self.read_local_file('google_error.html')
        response = BeautifulSoup(response, 'html.parser')
        with patch('sys.stdout', new=StringIO()) as stdout:
            self.assertIsNone(google.Google.check_prompt_code(response))
        self.assertEqual(stdout.getvalue(), '')

    def test_find_keyhandles(self):
        challenges_txt = "RFVNTVlDSEFMTEVOR0U="

        keyHandleJSText = """{"1010":[2,true,0,false]
,"5010":[null,null,null,"https://accounts.google.com/signin/challenge/sk/5",null,["google.com","RFVNTVlDSEFMTEVOR0U\\u003d",[[2,"S0VZSEFORExFMQ\\u003d\\u003d",[1]
]
,[2,"S0VZSEFORExFMg\\u003d\\u003d",[1,2]
]
]
,"{\\"appid\\":\\"https://www.gstatic.com/securitykey/origins.json\\"}"]
]
}
"""
        keyHandleJsonPayload = json.loads(keyHandleJSText)

        keyHandles = google.Google.find_key_handles(keyHandleJsonPayload, base64.urlsafe_b64encode(base64.b64decode(challenges_txt)))
        self.assertEqual(
            [
                b"S0VZSEFORExFMQ==",
                b"S0VZSEFORExFMg==",
            ],
            keyHandles,
        )

    def test_parse_saml_without_login(self):

        mock_config = Mock()
        undertest = google.Google(config=mock_config, save_failure=False)

        with self.assertRaises(RuntimeError) as ex:
            undertest.parse_saml()

        self.assertEqual("You must use do_login() before calling parse_saml()", str(ex.exception))

    def test_parse_saml_without_save(self):
        mock_config = Mock()
        mock_config.profile = False
        mock_config.saml_cache = False
        mock_config.keyring = False
        mock_config.username = None
        mock_config.idp_id = None
        mock_config.sp_id = None
        mock_config.return_value = None
        mock_config.print_creds = True

        undertest = google.Google(config=mock_config, save_failure=False)

        undertest.session_state = Mock()
        undertest.session_state.text = "<xml></xml>"

        with self.assertRaises(google.ExpectedGoogleException) as ex:
            undertest.parse_saml()

        self.assertEqual("Something went wrong - Could not find SAML response, check your credentials "
                         "or use --save-failure-html to debug.",
                         str(ex.exception))

    def test_parse_saml_with_save(self):
        mock_config = Mock()
        mock_config.profile = False
        mock_config.saml_cache = False
        mock_config.keyring = False
        mock_config.username = None
        mock_config.idp_id = None
        mock_config.sp_id = None
        mock_config.return_value = None
        mock_config.print_creds = True

        undertest = google.Google(config=mock_config, save_failure=True)

        undertest.session_state = Mock()
        undertest.session_state.text = "<xml></xml>"

        with self.assertRaises(google.ExpectedGoogleException) as ex:
            undertest.parse_saml()

        self.assertEqual("Something went wrong - Could not find SAML response, check your credentials "
                         "or use --save-failure-html to debug.",
                         str(ex.exception))
