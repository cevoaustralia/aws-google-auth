import unittest
from argparse import Namespace

from mock import call, patch, Mock, MagicMock

import aws_google_auth


class TestInit(unittest.TestCase):

    def setUp(self):
        pass

    @patch('aws_google_auth.cli', spec=True)
    def test_main_method_has_no_parameters(self, mock_cli):
        """
        This is the entrypoint for the cli tool, and should require no parameters

        :param mock_cli:
        :return:
        """

        # Function under test
        aws_google_auth.main()

        self.assertTrue(mock_cli.called)

    @patch('aws_google_auth.exit_if_unsupported_python', spec=True)
    @patch('aws_google_auth.resolve_config', spec=True)
    @patch('aws_google_auth.process_auth', spec=True)
    def test_main_method_chaining(self, process_auth, resolve_config, exit_if_unsupported_python):

        # Create a mock config to be returned from the resolve_config function
        mock_config = Mock()
        # Inject the mock as the return value from the function
        aws_google_auth.resolve_config.return_value = mock_config

        # Function under test
        aws_google_auth.cli([])

        self.assertTrue(exit_if_unsupported_python.called)
        self.assertTrue(resolve_config.called)
        self.assertTrue(process_auth.called)

        self.assertEqual([call()], exit_if_unsupported_python.mock_calls)

        self.assertEqual([call(Namespace(ask_role=False,
                                         keyring=False,
                                         disable_u2f=False,
                                         duration=None,
                                         auto_duration=False,
                                         idp_id=None,
                                         profile=None,
                                         region=None,
                                         resolve_aliases=False,
                                         role_arn=None,
                                         save_failure_html=False,
                                         save_saml_flow=False,
                                         saml_cache=True,
                                         saml_assertion=None,
                                         sp_id=None,
                                         log_level='warn',
                                         print_creds=False,
                                         username=None,
                                         quiet=False,
                                         bg_response=None,
                                         account=None))
                          ],
                         resolve_config.mock_calls)

        self.assertEqual([call(Namespace(ask_role=False,
                                         keyring=False,
                                         disable_u2f=False,
                                         duration=None,
                                         auto_duration=False,
                                         idp_id=None,
                                         profile=None,
                                         region=None,
                                         resolve_aliases=False,
                                         role_arn=None,
                                         save_failure_html=False,
                                         save_saml_flow=False,
                                         saml_cache=True,
                                         saml_assertion=None,
                                         sp_id=None,
                                         log_level='warn',
                                         print_creds=False,
                                         username=None,
                                         quiet=False,
                                         bg_response=None,
                                         account=None),
                               mock_config)
                          ],
                         process_auth.mock_calls)

    @patch('aws_google_auth.util', spec=True)
    @patch('aws_google_auth.amazon', spec=True)
    @patch('aws_google_auth.google', spec=True)
    def test_process_auth_standard(self, mock_google, mock_amazon, mock_util):

        mock_config = Mock()
        mock_config.profile = False
        mock_config.saml_cache = False
        mock_config.keyring = False
        mock_config.username = None
        mock_config.idp_id = None
        mock_config.sp_id = None
        mock_config.return_value = None
        mock_config.account = None
        mock_config.region = None

        mock_amazon_client = Mock()
        mock_google_client = Mock()

        mock_amazon_client.roles = {
            'arn:aws:iam::123456789012:role/admin': 'arn:aws:iam::123456789012:saml-provider/GoogleApps',
            'arn:aws:iam::123456789012:role/read-only': 'arn:aws:iam::123456789012:saml-provider/GoogleApps'
        }

        mock_util_obj = MagicMock()
        mock_util_obj.pick_a_role = MagicMock(return_value=("da_role", "da_provider"))
        mock_util_obj.get_input = MagicMock(side_effect=["region_input", "input", "input2", "input3"])
        mock_util_obj.get_password = MagicMock(return_value="pass")

        mock_util.Util = mock_util_obj

        mock_amazon_client.resolve_aws_aliases = MagicMock(return_value=[])

        mock_amazon.Amazon = MagicMock(return_value=mock_amazon_client)
        mock_google.Google = MagicMock(return_value=mock_google_client)

        args = aws_google_auth.parse_args([])

        # Method Under Test
        aws_google_auth.process_auth(args, mock_config)

        # Assert values collected
        self.assertEqual(mock_config.region, "region_input")
        self.assertEqual(mock_config.username, "input")
        self.assertEqual(mock_config.idp_id, "input2")
        self.assertEqual(mock_config.sp_id, "input3")
        self.assertEqual(mock_config.password, "pass")
        self.assertEqual(mock_config.provider, "da_provider")
        self.assertEqual(mock_config.role_arn, "da_role")

        # Assert calls occur
        self.assertEqual([call.Util.get_input('AWS Region: '),
                          call.Util.get_input('Google username: '),
                          call.Util.get_input('Google IDP ID: '),
                          call.Util.get_input('Google SP ID: '),
                          call.Util.get_password('Google Password: '),
                          call.Util.pick_a_role({'arn:aws:iam::123456789012:role/read-only': 'arn:aws:iam::123456789012:saml-provider/GoogleApps',
                                                'arn:aws:iam::123456789012:role/admin': 'arn:aws:iam::123456789012:saml-provider/GoogleApps'}, [])],
                         mock_util.mock_calls)

        self.assertEqual([call.do_login(), call.parse_saml()],
                         mock_google_client.mock_calls)

        self.assertEqual([call.raise_if_invalid()],
                         mock_config.mock_calls)

        self.assertEqual([call({'arn:aws:iam::123456789012:role/read-only': 'arn:aws:iam::123456789012:saml-provider/GoogleApps',
                                'arn:aws:iam::123456789012:role/admin': 'arn:aws:iam::123456789012:saml-provider/GoogleApps'
                                })],
                         mock_amazon_client.resolve_aws_aliases.mock_calls)

        self.assertEqual([call({'arn:aws:iam::123456789012:role/read-only': 'arn:aws:iam::123456789012:saml-provider/GoogleApps',
                                'arn:aws:iam::123456789012:role/admin': 'arn:aws:iam::123456789012:saml-provider/GoogleApps'}, [])
                          ], mock_util_obj.pick_a_role.mock_calls)

    @patch('aws_google_auth.util', spec=True)
    @patch('aws_google_auth.amazon', spec=True)
    @patch('aws_google_auth.google', spec=True)
    def test_process_auth_print_creds(self, mock_google, mock_amazon, mock_util):
        mock_config = Mock()
        mock_config.profile = False
        mock_config.saml_cache = False
        mock_config.keyring = False
        mock_config.username = None
        mock_config.idp_id = None
        mock_config.sp_id = None
        mock_config.return_value = None
        mock_config.print_creds = True
        mock_config.account = None

        mock_amazon_client = Mock()
        mock_google_client = Mock()

        mock_amazon_client.roles = {
            'arn:aws:iam::123456789012:role/admin': 'arn:aws:iam::123456789012:saml-provider/GoogleApps',
            'arn:aws:iam::123456789012:role/read-only': 'arn:aws:iam::123456789012:saml-provider/GoogleApps'
        }

        mock_util_obj = MagicMock()
        mock_util_obj.pick_a_role = MagicMock(return_value=("da_role", "da_provider"))
        mock_util_obj.get_input = MagicMock(side_effect=["input", "input2", "input3"])
        mock_util_obj.get_password = MagicMock(return_value="pass")

        mock_util.Util = mock_util_obj

        mock_amazon_client.resolve_aws_aliases = MagicMock(return_value=[])
        mock_amazon_client.print_export_line = Mock()

        mock_amazon.Amazon = MagicMock(return_value=mock_amazon_client)
        mock_google.Google = MagicMock(return_value=mock_google_client)

        args = aws_google_auth.parse_args([])

        # Method Under Test
        aws_google_auth.process_auth(args, mock_config)

        # Assert values collected
        self.assertEqual(mock_config.username, "input")
        self.assertEqual(mock_config.idp_id, "input2")
        self.assertEqual(mock_config.sp_id, "input3")
        self.assertEqual(mock_config.password, "pass")
        self.assertEqual(mock_config.provider, "da_provider")
        self.assertEqual(mock_config.role_arn, "da_role")

        # Assert calls occur
        self.assertEqual([call.Util.get_input('Google username: '),
                          call.Util.get_input('Google IDP ID: '),
                          call.Util.get_input('Google SP ID: '),
                          call.Util.get_password('Google Password: '),
                          call.Util.pick_a_role({'arn:aws:iam::123456789012:role/read-only': 'arn:aws:iam::123456789012:saml-provider/GoogleApps',
                                                'arn:aws:iam::123456789012:role/admin': 'arn:aws:iam::123456789012:saml-provider/GoogleApps'},
                                                [])],
                         mock_util.mock_calls)

        self.assertEqual([call.do_login(), call.parse_saml()],
                         mock_google_client.mock_calls)

        self.assertEqual([call.raise_if_invalid()],
                         mock_config.mock_calls)

        self.assertEqual(
            [call({'arn:aws:iam::123456789012:role/read-only': 'arn:aws:iam::123456789012:saml-provider/GoogleApps',
                   'arn:aws:iam::123456789012:role/admin': 'arn:aws:iam::123456789012:saml-provider/GoogleApps'
                   })],
            mock_amazon_client.resolve_aws_aliases.mock_calls)

        self.assertEqual(
            [call({'arn:aws:iam::123456789012:role/read-only': 'arn:aws:iam::123456789012:saml-provider/GoogleApps',
                   'arn:aws:iam::123456789012:role/admin': 'arn:aws:iam::123456789012:saml-provider/GoogleApps'}, [])
             ], mock_util_obj.pick_a_role.mock_calls)

        self.assertEqual([call()],
                         mock_amazon_client.print_export_line.mock_calls)

    @patch('aws_google_auth.util', spec=True)
    @patch('aws_google_auth.amazon', spec=True)
    @patch('aws_google_auth.google', spec=True)
    def test_process_auth_specified_role(self, mock_google, mock_amazon, mock_util):

        mock_config = Mock()
        mock_config.saml_cache = False
        mock_config.keyring = False
        mock_config.username = None
        mock_config.idp_id = None
        mock_config.sp_id = None
        mock_config.return_value = None

        mock_config.role_arn = 'arn:aws:iam::123456789012:role/admin'
        mock_config.ask_role = False

        mock_amazon_client = Mock()
        mock_google_client = Mock()

        mock_amazon_client.roles = {
            'arn:aws:iam::123456789012:role/admin': 'arn:aws:iam::123456789012:saml-provider/GoogleApps',
            'arn:aws:iam::123456789012:role/read-only': 'arn:aws:iam::123456789012:saml-provider/GoogleApps'
        }

        mock_util_obj = MagicMock()
        mock_util_obj.pick_a_role = MagicMock(return_value=("da_role", "da_provider"))
        mock_util_obj.get_input = MagicMock(side_effect=["input", "input2", "input3"])
        mock_util_obj.get_password = MagicMock(return_value="pass")

        mock_util.Util = mock_util_obj

        mock_amazon_client.resolve_aws_aliases = MagicMock(return_value=[])

        mock_amazon.Amazon = MagicMock(return_value=mock_amazon_client)
        mock_google.Google = MagicMock(return_value=mock_google_client)

        args = aws_google_auth.parse_args([])

        # Method Under Test
        aws_google_auth.process_auth(args, mock_config)

        # Assert values collected
        self.assertEqual(mock_config.username, "input")
        self.assertEqual(mock_config.idp_id, "input2")
        self.assertEqual(mock_config.sp_id, "input3")
        self.assertEqual(mock_config.password, "pass")
        self.assertEqual(mock_config.provider, "arn:aws:iam::123456789012:saml-provider/GoogleApps")
        self.assertEqual(mock_config.role_arn, "arn:aws:iam::123456789012:role/admin")

        # Assert calls occur
        self.assertEqual([call.Util.get_input('Google username: '),
                          call.Util.get_input('Google IDP ID: '),
                          call.Util.get_input('Google SP ID: '),
                          call.Util.get_password('Google Password: ')],
                         mock_util.mock_calls)

        self.assertEqual([call.do_login(), call.parse_saml()],
                         mock_google_client.mock_calls)

        self.assertEqual([call.raise_if_invalid(),
                          call.write(mock_amazon_client)],
                         mock_config.mock_calls)

        self.assertEqual([],
                         mock_amazon_client.resolve_aws_aliases.mock_calls)

        self.assertEqual([],
                         mock_util_obj.pick_a_role.mock_calls)

    @patch('aws_google_auth.util', spec=True)
    @patch('aws_google_auth.amazon', spec=True)
    @patch('aws_google_auth.google', spec=True)
    def test_process_auth_dont_resolve_alias(self, mock_google, mock_amazon, mock_util):

        mock_config = Mock()
        mock_config.saml_cache = False
        mock_config.resolve_aliases = False
        mock_config.username = None
        mock_config.idp_id = None
        mock_config.sp_id = None
        mock_config.return_value = None
        mock_config.keyring = False
        mock_config.account = None

        mock_amazon_client = Mock()
        mock_google_client = Mock()

        mock_amazon_client.roles = {
            'arn:aws:iam::123456789012:role/admin': 'arn:aws:iam::123456789012:saml-provider/GoogleApps',
            'arn:aws:iam::123456789012:role/read-only': 'arn:aws:iam::123456789012:saml-provider/GoogleApps'
        }

        mock_util_obj = MagicMock()
        mock_util_obj.pick_a_role = MagicMock(return_value=("da_role", "da_provider"))
        mock_util_obj.get_input = MagicMock(side_effect=["input", "input2", "input3"])
        mock_util_obj.get_password = MagicMock(return_value="pass")

        mock_util.Util = mock_util_obj

        mock_amazon_client.resolve_aws_aliases = MagicMock(return_value=[])

        mock_amazon.Amazon = MagicMock(return_value=mock_amazon_client)
        mock_google.Google = MagicMock(return_value=mock_google_client)

        args = aws_google_auth.parse_args([])

        # Method Under Test
        aws_google_auth.process_auth(args, mock_config)

        # Assert values collected
        self.assertEqual(mock_config.username, "input")
        self.assertEqual(mock_config.idp_id, "input2")
        self.assertEqual(mock_config.sp_id, "input3")
        self.assertEqual(mock_config.password, "pass")
        self.assertEqual(mock_config.provider, "da_provider")
        self.assertEqual(mock_config.role_arn, "da_role")
        self.assertEqual(mock_config.account, None)

        # Assert calls occur
        self.assertEqual([call.Util.get_input('Google username: '),
                          call.Util.get_input('Google IDP ID: '),
                          call.Util.get_input('Google SP ID: '),
                          call.Util.get_password('Google Password: '),
                          call.Util.pick_a_role({'arn:aws:iam::123456789012:role/read-only': 'arn:aws:iam::123456789012:saml-provider/GoogleApps',
                                                'arn:aws:iam::123456789012:role/admin': 'arn:aws:iam::123456789012:saml-provider/GoogleApps'})],
                         mock_util.mock_calls)

        self.assertEqual([call.do_login(), call.parse_saml()],
                         mock_google_client.mock_calls)

        self.assertEqual([call.raise_if_invalid(),
                          call.write(mock_amazon_client)],
                         mock_config.mock_calls)

        self.assertEqual([],
                         mock_amazon_client.resolve_aws_aliases.mock_calls)

        self.assertEqual([call({'arn:aws:iam::123456789012:role/read-only': 'arn:aws:iam::123456789012:saml-provider/GoogleApps',
                                'arn:aws:iam::123456789012:role/admin': 'arn:aws:iam::123456789012:saml-provider/GoogleApps'})
                          ], mock_util_obj.pick_a_role.mock_calls)

    @patch('aws_google_auth.util', spec=True)
    @patch('aws_google_auth.amazon', spec=True)
    @patch('aws_google_auth.google', spec=True)
    def test_process_auth_with_profile(self, mock_google, mock_amazon, mock_util):

        mock_config = Mock()
        mock_config.saml_cache = False
        mock_config.keyring = False
        mock_config.username = None
        mock_config.idp_id = None
        mock_config.sp_id = None
        mock_config.profile = "blart"
        mock_config.return_value = None
        mock_config.role_arn = 'arn:aws:iam::123456789012:role/admin'
        mock_config.account = None

        mock_amazon_client = Mock()
        mock_google_client = Mock()

        mock_amazon_client.roles = {
            'arn:aws:iam::123456789012:role/admin': 'arn:aws:iam::123456789012:saml-provider/GoogleApps',
            'arn:aws:iam::123456789012:role/read-only': 'arn:aws:iam::123456789012:saml-provider/GoogleApps'
        }

        mock_util_obj = MagicMock()
        mock_util_obj.pick_a_role = MagicMock(return_value=("da_role", "da_provider"))
        mock_util_obj.get_input = MagicMock(side_effect=["input", "input2", "input3"])
        mock_util_obj.get_password = MagicMock(return_value="pass")

        mock_util.Util = mock_util_obj

        mock_amazon_client.resolve_aws_aliases = MagicMock(return_value=[])

        mock_amazon.Amazon = MagicMock(return_value=mock_amazon_client)
        mock_google.Google = MagicMock(return_value=mock_google_client)

        args = aws_google_auth.parse_args([])

        # Method Under Test
        aws_google_auth.process_auth(args, mock_config)

        # Assert values collected
        self.assertEqual(mock_config.username, "input")
        self.assertEqual(mock_config.idp_id, "input2")
        self.assertEqual(mock_config.sp_id, "input3")
        self.assertEqual(mock_config.password, "pass")
        self.assertEqual(mock_config.provider, "da_provider")
        self.assertEqual(mock_config.role_arn, "da_role")

        # Assert calls occur
        self.assertEqual([call.Util.get_input('Google username: '),
                          call.Util.get_input('Google IDP ID: '),
                          call.Util.get_input('Google SP ID: '),
                          call.Util.get_password('Google Password: '),
                          call.Util.pick_a_role({'arn:aws:iam::123456789012:role/read-only': 'arn:aws:iam::123456789012:saml-provider/GoogleApps',
                                                'arn:aws:iam::123456789012:role/admin': 'arn:aws:iam::123456789012:saml-provider/GoogleApps'}, [])],
                         mock_util.mock_calls)

        self.assertEqual([call.do_login(), call.parse_saml()],
                         mock_google_client.mock_calls)

        self.assertEqual([call.raise_if_invalid(),
                          call.write(mock_amazon_client)],
                         mock_config.mock_calls)

        self.assertEqual([call({'arn:aws:iam::123456789012:role/read-only': 'arn:aws:iam::123456789012:saml-provider/GoogleApps',
                                'arn:aws:iam::123456789012:role/admin': 'arn:aws:iam::123456789012:saml-provider/GoogleApps'
                                })],
                         mock_amazon_client.resolve_aws_aliases.mock_calls)

        self.assertEqual([call({'arn:aws:iam::123456789012:role/read-only': 'arn:aws:iam::123456789012:saml-provider/GoogleApps',
                                'arn:aws:iam::123456789012:role/admin': 'arn:aws:iam::123456789012:saml-provider/GoogleApps'}, [])
                          ], mock_util_obj.pick_a_role.mock_calls)

    @patch('aws_google_auth.util', spec=True)
    @patch('aws_google_auth.amazon', spec=True)
    @patch('aws_google_auth.google', spec=True)
    def test_process_auth_with_saml_cache(self, mock_google, mock_amazon, mock_util):

        mock_config = Mock()
        mock_config.saml_cache = True
        mock_config.username = None
        mock_config.idp_id = None
        mock_config.sp_id = None
        mock_config.password = None
        mock_config.return_value = None
        mock_config.role_arn = 'arn:aws:iam::123456789012:role/admin'
        mock_config.account = None

        mock_amazon_client = Mock()
        mock_google_client = Mock()

        mock_amazon_client.roles = {
            'arn:aws:iam::123456789012:role/admin': 'arn:aws:iam::123456789012:saml-provider/GoogleApps',
            'arn:aws:iam::123456789012:role/read-only': 'arn:aws:iam::123456789012:saml-provider/GoogleApps'
        }

        mock_util_obj = MagicMock()
        mock_util_obj.pick_a_role = MagicMock(return_value=("da_role", "da_provider"))
        mock_util_obj.get_input = MagicMock(side_effect=["input", "input2", "input3"])
        mock_util_obj.get_password = MagicMock(return_value="pass")

        mock_util.Util = mock_util_obj

        mock_amazon_client.resolve_aws_aliases = MagicMock(return_value=[])

        mock_amazon.Amazon = MagicMock(return_value=mock_amazon_client)
        mock_google.Google = MagicMock(return_value=mock_google_client)

        args = aws_google_auth.parse_args([])

        # Method Under Test
        aws_google_auth.process_auth(args, mock_config)

        # Assert values collected
        self.assertEqual(mock_config.username, None)
        self.assertEqual(mock_config.idp_id, None)
        self.assertEqual(mock_config.sp_id, None)
        self.assertEqual(mock_config.password, None)
        self.assertEqual(mock_config.provider, "da_provider")
        self.assertEqual(mock_config.role_arn, "da_role")

        # Assert calls occur
        self.assertEqual([call.Util.pick_a_role({'arn:aws:iam::123456789012:role/read-only': 'arn:aws:iam::123456789012:saml-provider/GoogleApps',
                                                'arn:aws:iam::123456789012:role/admin': 'arn:aws:iam::123456789012:saml-provider/GoogleApps'}, [])],
                         mock_util.mock_calls)

        # Cache means no google calls
        self.assertEqual([],
                         mock_google_client.mock_calls)

        self.assertEqual([call.write(mock_amazon_client)],
                         mock_config.mock_calls)

        self.assertEqual([call({'arn:aws:iam::123456789012:role/read-only': 'arn:aws:iam::123456789012:saml-provider/GoogleApps',
                                'arn:aws:iam::123456789012:role/admin': 'arn:aws:iam::123456789012:saml-provider/GoogleApps'
                                })],
                         mock_amazon_client.resolve_aws_aliases.mock_calls)

        self.assertEqual([call({'arn:aws:iam::123456789012:role/read-only': 'arn:aws:iam::123456789012:saml-provider/GoogleApps',
                                'arn:aws:iam::123456789012:role/admin': 'arn:aws:iam::123456789012:saml-provider/GoogleApps'}, [])
                          ], mock_util_obj.pick_a_role.mock_calls)
