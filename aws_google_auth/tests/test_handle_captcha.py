import unittest

from mock import Mock, MagicMock, patch
from aws_google_auth import google


@patch.object(google.Image, 'open')
class HandleCaptchaTestCase(unittest.TestCase):
    def setUp(self):
        if(google.sys.version_info.major == 2):
            google.raw_input = Mock()
        else:
            google.input = Mock()
        google.os = MagicMock()
        google.os.name = 'posix'
        google.sys = MagicMock()
        google.sys.platform = 'linux'
        self.config = MagicMock()
        self.payload = MagicMock()
        self.response = MagicMock()
        self.response.text = '''<form novalidate method="post"
		        action="https://accounts.google.com/signin/v1/lookup"
		        id="gaia_loginform">
		        <input name="Page" type="hidden" value="PasswordSeparationSignIn">
		        <input type="hidden" name="GALX" value="">
		        <input type="hidden" name="gxf" value="">
		        <input type="hidden" name="ifkv" value="">
		        <input type="hidden" name="continue" value="https://accounts.google.com/o/saml2/initsso?idpid=">
		        <input type="hidden" name="flowName" value="WEB_SETUP_GLIF">
		        <input type="hidden" name="followup" value="https://accounts.google.com/o/saml2/initsso?idpid=">
		        <input type="hidden" name="faa" value="1">
		        <input type="hidden" name="oauth" value="1">
		        <input type="hidden" name="sarp" value="1">
		        <input type="hidden" name="scc" value="1">
		        <input type="hidden" name="ltmpl" value="popup">
		        <input id="profile-information" name="ProfileInformation" type="hidden" value="">
		        <div id="identifier-captcha">
		        <input type="hidden" name="identifiertoken" id="identifier-token" value="">
		        <div id="captcha-img" class="captcha-img">
		        <img src="/Captcha?v=2&amp;ctoken=" alt="Visual verification">
		        </div>
		        </div>
		        <input id="session-state" name="SessionState" type="hidden" value="">
		        <input type="hidden" id="_utf8" name="_utf8" value="&#9731;"/>
		        <input type="hidden" name="bgresponse" id="bgresponse" value="js_disabled">
		        <input id="Email" name="Email" type="email" placeholder="" value="" spellcheck="false" readonly>
		        <input id="password" name="Passwd" type="password" spellcheck="false" autofocus class="">
		        <input type="checkbox" name="TrustDevice" id="trustDevice" checked>
		        <input id="next" name="signIn" class="rc-button rc-button-submit" type="submit" value="Next">
		        </form>'''
        self.google_client = google.Google(self.config, save_failure=False, save_flow=False, view_captcha=False)
        self.google_client.post = MagicMock()
        self.google_client.post.return_value = self.response

    def test_handle_captcha_on_linux(self, mock_image_open):
        self.google_client.handle_captcha(self.response, self.payload)
        self.assertFalse(mock_image_open.called)

    def test_handle_captcha_on_macos(self, mock_image_open):
        google.sys.platform = 'darwin'
        self.google_client.handle_captcha(self.response, self.payload)
        self.assertTrue(mock_image_open.called)

    def test_handle_captcha_on_windows(self, mock_image_open):
        google.os.name = 'nt'
        google.sys.platform = 'win32'
        self.google_client.handle_captcha(self.response, self.payload)
        self.assertTrue(mock_image_open.called)

    def test_handle_captcha_on_linux_with_view_captcha(self, mock_image_open):
        self.google_client.view_captcha = True
        self.google_client.handle_captcha(self.response, self.payload)
        self.assertTrue(mock_image_open.called)

    def test_handle_captcha_on_linux_with_display_and_no_ssh_tty_in_os_environ(self, mock_image_open):
        google.os.environ = {'DISPLAY': ':0'}
        self.google_client.handle_captcha(self.response, self.payload)
        self.assertTrue(mock_image_open.called)

    def test_handle_captcha_on_linux_with_display_and_ssh_tty_in_os_environ(self, mock_image_open):
        google.os.environ = {'DISPLAY': ':0', 'SSH_TTY': '/dev/pts/1'}
        self.google_client.handle_captcha(self.response, self.payload)
        self.assertFalse(mock_image_open.called)

    def test_handle_captcha_with_image_open_exception(self, mock_image_open):
        self.google_client.view_captcha = True
        mock_image_open.side_effect = Exception
        self.assertIsNotNone(self.google_client.handle_captcha(self.response, self.payload))
