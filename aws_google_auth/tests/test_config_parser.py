import unittest
import mock
import os

from .. import resolve_config


class TestProfileProcessing(unittest.TestCase):

    def test_default(self):
        config = resolve_config([])
        self.assertEqual("sts", config.profile)

    def test_cli_param_supplied(self):
        config = resolve_config(['-p', 'profile'])
        self.assertEqual('profile', config.profile)

    @mock.patch.dict(os.environ, {'AWS_PROFILE': 'mytemp'})
    def test_with_environment(self):
        config = resolve_config([])
        self.assertEqual('mytemp', config.profile)

        config = resolve_config(['-p', 'profile'])
        self.assertEqual('profile', config.profile)


class TestUsernameProcessing(unittest.TestCase):

    def test_default(self):
        config = resolve_config([])
        self.assertEqual(None, config.username)

    def test_cli_param_supplied(self):
        config = resolve_config(['-u', 'user@gmail.com'])
        self.assertEqual('user@gmail.com', config.username)

    @mock.patch.dict(os.environ, {'GOOGLE_USERNAME': 'override@gmail.com'})
    def test_with_environment(self):
        config = resolve_config([])
        self.assertEqual('override@gmail.com', config.username)

        config = resolve_config(['-u', 'user@gmail.com'])
        self.assertEqual('user@gmail.com', config.username)


class TestDurationProcessing(unittest.TestCase):

    def test_default(self):
        config = resolve_config([])
        self.assertEqual(3600, config.duration)

    def test_cli_param_supplied(self):
        config = resolve_config(['-d', "500"])
        self.assertEqual(500, config.duration)

    def test_invalid_cli_param_supplied(self):

        with self.assertRaises(SystemExit):
            resolve_config(['-d', "blart"])

    @mock.patch.dict(os.environ, {'DURATION': '3000'})
    def test_with_environment(self):
        config = resolve_config([])
        self.assertEqual(3000, config.duration)

        config = resolve_config(['-d', "500"])
        self.assertEqual(500, config.duration)


class TestIDPProcessing(unittest.TestCase):

    def test_default(self):
        config = resolve_config([])
        self.assertEqual(None, config.idp_id)

    def test_cli_param_supplied(self):
        config = resolve_config(['-I', "kjl2342"])
        self.assertEqual("kjl2342", config.idp_id)

    @mock.patch.dict(os.environ, {'GOOGLE_IDP_ID': 'adsfasf233423'})
    def test_with_environment(self):
        config = resolve_config([])
        self.assertEqual("adsfasf233423", config.idp_id)

        config = resolve_config(['-I', "kjl2342"])
        self.assertEqual("kjl2342", config.idp_id)


class TestSPProcessing(unittest.TestCase):

    def test_default(self):
        config = resolve_config([])
        self.assertEqual(None, config.sp_id)

    def test_cli_param_supplied(self):
        config = resolve_config(['-S', "kjl2342"])
        self.assertEqual("kjl2342", config.sp_id)

    @mock.patch.dict(os.environ, {'GOOGLE_SP_ID': 'adsfasf233423'})
    def test_with_environment(self):
        config = resolve_config([])
        self.assertEqual("adsfasf233423", config.sp_id)

        config = resolve_config(['-S', "kjl2342"])
        self.assertEqual("kjl2342", config.sp_id)


class TestRegionProcessing(unittest.TestCase):

    def test_default(self):
        config = resolve_config([])
        self.assertEqual(None, config.region)

    def test_cli_param_supplied(self):
        config = resolve_config(['--region', "ap-southeast-4"])
        self.assertEqual("ap-southeast-4", config.region)

    @mock.patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'ap-southeast-9'})
    def test_with_environment(self):
        config = resolve_config([])
        self.assertEqual("ap-southeast-9", config.region)

        config = resolve_config(['--region', "ap-southeast-4"])
        self.assertEqual("ap-southeast-4", config.region)


class TestRoleProcessing(unittest.TestCase):

    def test_default(self):
        config = resolve_config([])
        self.assertEqual(None, config.role_arn)

    def test_cli_param_supplied(self):
        config = resolve_config(['-r', "role1234"])
        self.assertEqual("role1234", config.role_arn)

    @mock.patch.dict(os.environ, {'AWS_ROLE_ARN': '4567-role'})
    def test_with_environment(self):
        config = resolve_config([])
        self.assertEqual("4567-role", config.role_arn)


class TestAskRoleProcessing(unittest.TestCase):

    def test_default(self):
        config = resolve_config([])
        self.assertFalse(config.ask_role)

    def test_cli_param_supplied(self):
        config = resolve_config(['-a'])
        self.assertTrue(config.ask_role)

    @mock.patch.dict(os.environ, {'AWS_ASK_ROLE': 'true'})
    def test_with_environment(self):
        config = resolve_config([])
        self.assertTrue(config.ask_role)


class TestU2FDisabledProcessing(unittest.TestCase):

    def test_default(self):
        config = resolve_config([])
        self.assertFalse(config.u2f_disabled)

    def test_cli_param_supplied(self):
        config = resolve_config(['-D'])
        self.assertTrue(config.u2f_disabled)

    @mock.patch.dict(os.environ, {'U2F_DISABLED': 'true'})
    def test_with_environment(self):
        config = resolve_config([])
        self.assertTrue(config.u2f_disabled)


class TestResolveAliasesProcessing(unittest.TestCase):

    def test_default(self):
        config = resolve_config([])
        self.assertFalse(config.resolve_aliases)

    def test_cli_param_supplied(self):
        config = resolve_config(['--resolve-aliases'])
        self.assertTrue(config.resolve_aliases)

    @mock.patch.dict(os.environ, {'RESOLVE_AWS_ALIASES': 'true'})
    def test_with_environment(self):
        config = resolve_config([])
        self.assertTrue(config.resolve_aliases)
