import unittest
import mock
import os
from nose.tools import nottest

from .. import resolve_config, parse_args


class TestProfileProcessing(unittest.TestCase):

    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual("sts", config.profile)

    def test_cli_param_supplied(self):
        args = parse_args(['-p', 'profile'])
        config = resolve_config(args)
        self.assertEqual('profile', config.profile)

    @mock.patch.dict(os.environ, {'AWS_PROFILE': 'mytemp'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual('mytemp', config.profile)

        args = parse_args(['-p', 'profile'])
        config = resolve_config(args)
        self.assertEqual('profile', config.profile)


class TestUsernameProcessing(unittest.TestCase):

    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual(None, config.username)

    def test_cli_param_supplied(self):
        args = parse_args(['-u', 'user@gmail.com'])
        config = resolve_config(args)
        self.assertEqual('user@gmail.com', config.username)

    @mock.patch.dict(os.environ, {'GOOGLE_USERNAME': 'override@gmail.com'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual('override@gmail.com', config.username)

        args = parse_args(['-u', 'user@gmail.com'])
        config = resolve_config(args)
        self.assertEqual('user@gmail.com', config.username)


class TestDurationProcessing(unittest.TestCase):

    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual(43200, config.duration)

    def test_cli_param_supplied(self):
        args = parse_args(['-d', "500"])
        config = resolve_config(args)
        self.assertEqual(500, config.duration)

    def test_invalid_cli_param_supplied(self):

        with self.assertRaises(SystemExit):
            args = parse_args(['-d', "blart"])
            resolve_config(args)

    @mock.patch.dict(os.environ, {'DURATION': '3000'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual(3000, config.duration)

        args = parse_args(['-d', "500"])
        config = resolve_config(args)
        self.assertEqual(500, config.duration)


class TestIDPProcessing(unittest.TestCase):

    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual(None, config.idp_id)

    def test_cli_param_supplied(self):
        args = parse_args(['-I', "kjl2342"])
        config = resolve_config(args)
        self.assertEqual("kjl2342", config.idp_id)

    @mock.patch.dict(os.environ, {'GOOGLE_IDP_ID': 'adsfasf233423'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual("adsfasf233423", config.idp_id)

        args = parse_args(['-I', "kjl2342"])
        config = resolve_config(args)
        self.assertEqual("kjl2342", config.idp_id)


class TestSPProcessing(unittest.TestCase):

    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual(None, config.sp_id)

    def test_cli_param_supplied(self):
        args = parse_args(['-S', "kjl2342"])
        config = resolve_config(args)
        self.assertEqual("kjl2342", config.sp_id)

    @mock.patch.dict(os.environ, {'GOOGLE_SP_ID': 'adsfasf233423'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual("adsfasf233423", config.sp_id)

        args = parse_args(['-S', "kjl2342"])
        config = resolve_config(args)
        self.assertEqual("kjl2342", config.sp_id)


class TestRegionProcessing(unittest.TestCase):

    @nottest
    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual(None, config.region)

    def test_cli_param_supplied(self):
        args = parse_args(['--region', "ap-southeast-4"])
        config = resolve_config(args)
        self.assertEqual("ap-southeast-4", config.region)

    @mock.patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'ap-southeast-9'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual("ap-southeast-9", config.region)

        args = parse_args(['--region', "ap-southeast-4"])
        config = resolve_config(args)
        self.assertEqual("ap-southeast-4", config.region)


class TestRoleProcessing(unittest.TestCase):

    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual(None, config.role_arn)

    def test_cli_param_supplied(self):
        args = parse_args(['-r', "role1234"])
        config = resolve_config(args)
        self.assertEqual("role1234", config.role_arn)

    @mock.patch.dict(os.environ, {'AWS_ROLE_ARN': '4567-role'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertEqual("4567-role", config.role_arn)


class TestAskRoleProcessing(unittest.TestCase):

    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertFalse(config.ask_role)

    def test_cli_param_supplied(self):
        args = parse_args(['-a'])
        config = resolve_config(args)
        self.assertTrue(config.ask_role)

    @nottest
    @mock.patch.dict(os.environ, {'AWS_ASK_ROLE': 'true'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertTrue(config.ask_role)


class TestU2FDisabledProcessing(unittest.TestCase):

    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertFalse(config.u2f_disabled)

    def test_cli_param_supplied(self):
        args = parse_args(['-D'])
        config = resolve_config(args)
        self.assertTrue(config.u2f_disabled)

    @nottest
    @mock.patch.dict(os.environ, {'U2F_DISABLED': 'true'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertTrue(config.u2f_disabled)


class TestResolveAliasesProcessing(unittest.TestCase):

    def test_default(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertFalse(config.resolve_aliases)

    def test_cli_param_supplied(self):
        args = parse_args(['--resolve-aliases'])
        config = resolve_config(args)
        self.assertTrue(config.resolve_aliases)

    @nottest
    @mock.patch.dict(os.environ, {'RESOLVE_AWS_ALIASES': 'true'})
    def test_with_environment(self):
        args = parse_args([])
        config = resolve_config(args)
        self.assertTrue(config.resolve_aliases)
