# -*- coding: utf8 -*-
import unittest
from io import open
from os import path

import json
import base64

from bs4 import BeautifulSoup

from mock import Mock
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
