# -*- coding: utf8 -*-
import unittest
from io import open
from os import path
from bs4 import BeautifulSoup
import mock

from aws_google_auth import google
from mock import Mock, MagicMock, call

from google import ExpectedGoogleException


class GoogleTest(unittest.TestCase):

    def test_url_generation(self):

        config = configuration.Configuration()
        config.idp_id = "idp1234"
        config.sp_id = "spid456"

        g = google.Google(config)
        self.assertEquals("https://accounts.google.com/o/saml2/initsso?idpid=idp1234&spid=spid456&forceauthn=false", g.login_url)

class TestGoogle(unittest.TestCase):
    def read_local_file(self, filename):
        here = path.abspath(path.dirname(__file__))
        with open(path.join(here, filename), encoding='utf8') as fp:
            return fp.read().encode('utf-8')

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

class GoogleCheckForFailureTest(unittest.TestCase):

    def test_valid(self):
        config = configuration.Configuration()
        g = google.Google(config)

        mock_session = Mock()

        result = g.check_for_failure(sess=mock_session)

        self.assertEquals([call.raise_for_status()],
                          mock_session.mock_calls)

        self.assertEqual(mock_session, result)

    def test_fails(self):
        config = configuration.Configuration()
        g = google.Google(config)

        mock_session = Mock()
        mock_session.raise_for_status = MagicMock()

        result = g.check_for_failure(sess=mock_session)

        self.assertEquals([call.raise_for_status()],
                          mock_session.mock_calls)

        self.assertEqual(mock_session, result)

    def test_raises_error(self):
        config = configuration.Configuration()
        g = google.Google(config)

        mock_session = Mock()

        mock_session.reason = "invalid"
        mock_session.status_code = 403
        mock_session.url = "http://theurl.com"

        with self.assertRaises(ExpectedGoogleException) as ex:
            g.check_for_failure(sess=mock_session)

        self.assertEquals([], mock_session.mock_calls)
        self.assertEqual("invalid accessing http://theurl.com", str(ex.exception))


class GoogleSAMLParseTest(unittest.TestCase):

    def test_no_session_state(self):

        config = configuration.Configuration()
        g = google.Google(config)

        with self.assertRaises(RuntimeError) as ex:
            g.parse_saml()

        self.assertEquals("You must use do_login() before calling parse_saml()", str(ex.exception.args[0]))

    def test_invalid_saml(self):

        config = configuration.Configuration()
        g = google.Google(config)

        g.session_state = Mock()
        g.session_state.text = ""

        with self.assertRaises(Exception) as ex:
            g.parse_saml()

        self.assertEquals("Something went wrong - Could not find SAML response, check your credentials or use --save-failure-html to debug.", str(ex.exception.args[0]))

    def test_valid_saml(self):
        config = configuration.Configuration()
        g = google.Google(config)

        g.session_state = Mock()
        #                                          Base64 encoded `blart\n`
        g.session_state.text = "<input name='SAMLResponse' value='YmxhcnQK'>"

        result = g.parse_saml()
        self.assertEqual(b'blart\n', result)


class GooglePromptTest(unittest.TestCase):

    def test_valid(self):

        config = configuration.Configuration()
        g = google.Google(config)

        # Mock our the response of the auth request
        response = Mock()
        response.text = '{"txToken": "txToken"}'

        # Mock out the session request
        g.session = MagicMock()
        g.session.post = MagicMock(return_value=response)

        sess = Mock()
        sess.text = "<div data-api-key='dasdataapi'/> <div data-tx-id='test-tx-id'/> " \
                    "<input name='challengeId' value='challengeId' />" \
                    "<input name='challengeType' value='challengeType' />" \
                    "<input name='continue' value='continue' />" \
                    "<input name='scc' value='scc' />" \
                    "<input name='sarp' value='sarp' />" \
                    "<input name='checkedDomains' value='checkedDomains' />" \
                    "<input name='pstMsg' value='pstMsg' />" \
                    "<input name='TL' value='TL' />" \
                    "<input name='action' value='action' />" \
                    "<input name='gxf' value='gxf' />"

        sess.url = "demourl?response"

        g.handle_prompt(sess)

        self.assertEqual(g.session.post.mock_calls,
                         [mock.call(u'https://content.googleapis.com/cryptauth/v1/authzen/awaittx?alt=json&key=dasdataapi',
                                    data=None,
                                    json={'txId': u'test-tx-id'}),
                          mock.call('demourl',
                                    data={'gxf': u'gxf',
                                          'scc': u'scc',
                                          'challengeId': u'challengeId',
                                          'pstMsg': u'pstMsg',
                                          'checkedDomains': u'checkedDomains',
                                          'challengeType': u'challengeType',
                                          'TL': u'TL',
                                          'token': u'txToken',
                                          'continue': u'continue',
                                          'action': u'action',
                                          'sarp': u'sarp',
                                          'checkConnection': 'youtube:1295:1',
                                          'TrustDevice': 'on'}, json=None)])


# class GoogleSKTest(unittest.TestCase):
#
    # @mock.patch('u2f', spec=True)
    # def test_valid(self, u2f):
    #
    #     config = configuration.Configuration()
    #     g = google.Google(config)
    #     g.util = Mock()
    #     g.util.get_input = MagicMock(return_value="x")
    #
    #     # Mock our the response of the auth request
    #     response = Mock()
    #     response.text = "{}"
    #
    #     # Mock out the session request
    #     g.session = MagicMock()
    #     g.session.post = MagicMock(return_value=response)
    #
    #     sess = Mock()
    #     sess.text = "<input name='id-challenge' value='{\"appId\":\"blart\", \"challenges\":[]}' />"
    #     sess.url = "demourl?response"
    #
    #     with mock.patch('u2f.u2f', new_callable=mock.NonCallableMock) as mock_thing:
    #         g.handle_sk(sess)
    #
    # def test_u2f_failure(self):
    #     config = configuration.Configuration()
    #     g = google.Google(config)
    #     g.util = Mock()
    #     g.util.get_input = MagicMock(return_value="x")
    #
    #     # Mock our the response of the auth request
    #     response = Mock()
    #     response.text = "{}"
    #
    #     # Mock out the session request
    #     g.session = MagicMock()
    #     g.session.post = MagicMock(return_value=response)
    #
    #     sess = Mock()
    #     sess.text = "<input name='id-challenge' value='{\"appId\":\"blart\", \"challenges\":[]}' />"
    #     sess.url = "demourl?response"
    #
    #     with self.assertRaises(ExpectedGoogleException) as ex:
    #         g.handle_sk(sess)
    #
    #     self.assertEqual("No U2F device found. Please check your setup.", str(ex.exception.args[0]))
    #     self.assertEqual(g.util.get_input.mock_calls,
    #                      [mock.call("Insert your U2F device and press enter to try again..."),
    #                       mock.call("Insert your U2F device and press enter to try again..."),
    #                       mock.call("Insert your U2F device and press enter to try again..."),
    #                       mock.call("Insert your U2F device and press enter to try again..."),
    #                       mock.call("Insert your U2F device and press enter to try again...")])


class GoogleSMSTest(unittest.TestCase):

    def test_valid(self):

        config = configuration.Configuration()
        g = google.Google(config)
        g.util = Mock()
        g.util.get_input = MagicMock(return_value="responsetoken")

        # Mock our the response of the auth request
        response = Mock()
        response.text = "{}"

        # Mock out the session request
        g.session = MagicMock()
        g.session.post = MagicMock(return_value=response)

        sess = Mock()
        sess.text = "<input name='challengeId' value='challengeId' />" \
                    "<input name='challengeType' value='challengeType' />" \
                    "<input name='continue' value='continue' />" \
                    "<input name='scc' value='scc' />" \
                    "<input name='sarp' value='sarp' />" \
                    "<input name='checkedDomains' value='checkedDomains' />" \
                    "<input name='pstMsg' value='pstMsg' />" \
                    "<input name='TL' value='TL' />" \
                    "<input name='gxf' value='gxf' />"

        sess.url = "demourl?response"

        g.handle_sms(sess)

        self.assertEqual(g.session.post.mock_calls,
                         [mock.call('demourl',
                                    data={'gxf': u'gxf',
                                          'scc': u'scc',
                                          'challengeId': u'challengeId',
                                          'pstMsg': u'pstMsg',
                                          'checkedDomains': u'checkedDomains',
                                          'challengeType': u'challengeType',
                                          'Pin': 'responsetoken',
                                          'TL': u'TL',
                                          'continue': u'continue',
                                          'sarp': u'sarp',
                                          'TrustDevice': 'on'}, json=None)])


class GoogleTOTPTest(unittest.TestCase):

    def test_valid(self):

        config = configuration.Configuration()
        g = google.Google(config)

        g.util = Mock()
        g.util.get_input = MagicMock(return_value="mfatokenresponse")

        # Mock our the response of the auth request
        response = Mock()
        response.text = "{}"

        # Mock out the session request
        g.session = MagicMock()
        g.session.post = MagicMock(return_value=response)

        sess = Mock()
        sess.text = "<input name='challengeId' value='challengeId' />" \
                    "<input name='challengeType' value='challengeType' />" \
                    "<input name='continue' value='continue' />" \
                    "<input name='scc' value='scc' />" \
                    "<input name='sarp' value='sarp' />" \
                    "<input name='checkedDomains' value='checkedDomains' />" \
                    "<input name='pstMsg' value='pstMsg' />" \
                    "<input name='TL' value='TL' />" \
                    "<input name='gxf' value='gxf' />" \

        sess.url = "demourl/totp/blart?response"

        g.handle_totp(sess)

        self.assertEqual(g.session.post.mock_calls,
                         [mock.call('demourl/totp/blart',
                                    data={'gxf': u'gxf',
                                          'scc': 1,
                                          'challengeId': 'blart',
                                          'pstMsg': 0,
                                          'checkedDomains': 'youtube',
                                          'challengeType': 6,
                                          'Pin': 'mfatokenresponse',
                                          'TL': u'TL',
                                          'continue': u'continue',
                                          'sarp': 1,
                                          'TrustDevice': 'on'}, json=None)])
