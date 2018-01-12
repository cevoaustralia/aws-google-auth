#!/usr/bin/env python

from . import _version
from . import configuration
from . import util
from . import google
from . import amazon

import argparse
import getpass
import os
import sys
from tzlocal import get_localzone


def parse_args(args):
    parser = argparse.ArgumentParser(
        prog="aws-google-auth",
        description="Acquire temporary AWS credentials via Google SSO",
    )

    parser.add_argument('-u', '--username', help='Google Apps username ($GOOGLE_USERNAME)')
    parser.add_argument('-I', '--idp-id', help='Google SSO IDP identifier ($GOOGLE_IDP_ID)')
    parser.add_argument('-S', '--sp-id', help='Google SSO SP identifier ($GOOGLE_SP_ID)')
    parser.add_argument('-R', '--region', help='AWS region endpoint ($AWS_DEFAULT_REGION)')
    parser.add_argument('-d', '--duration', type=int, help='Credential duration ($DURATION)')
    parser.add_argument('-p', '--profile', help='AWS profile (defaults to value of $AWS_PROFILE, then falls back to \'sts\')')
    parser.add_argument('-D', '--disable-u2f', action='store_true', help='Disable U2F functionality.')

    role_group = parser.add_mutually_exclusive_group()
    role_group.add_argument('-a', '--ask-role', action='store_true', help='Set true to always pick the role')
    role_group.add_argument('-r', '--role-arn', help='The ARN of the role to assume')
    parser.add_argument('-V', '--version', action='version',
                        version='%(prog)s {version}'.format(version=_version.__version__))

    return parser.parse_args(args)


def exit_if_unsupported_python():
    if sys.version_info[0] == 2 and sys.version_info[1] < 7:
        print("aws-google-auth requires Python 2.7 or higher. Please consider upgrading. Support "
              "for Python 2.6 and lower was dropped because this tool's dependencies dropped support.")
        print("")
        print("For debugging, it appears you're running: '{}'.".format(str(sys.version_info)))
        print("")
        print("See https://github.com/cevoaustralia/aws-google-auth/pull/38 for more information.")
        sys.exit(1)


def main():
    try:
        cli(sys.argv[1:])
    except KeyboardInterrupt:
        pass


def cli(cli_args):
    exit_if_unsupported_python()

    args = parse_args(args=cli_args)

    # Create a blank configuration object (has the defaults pre-filled)
    config = configuration.Configuration()

    # Have the configuration update itself via the ~/.aws/config on disk.
    config.read(args.profile)

    # Override anything found in the environment variables. We only want to
    # override "None" values (not "False" or "0"), hence why we're not using
    # the common "or" method here. Instead we use util.Util.default_if_none().
    config.ask_role = util.Util.default_if_none(os.getenv('AWS_ASK_ROLE'), config.ask_role)
    config.duration = util.Util.default_if_none(os.getenv('DURATION'), config.duration)
    config.idp_id = util.Util.default_if_none(os.getenv('GOOGLE_IDP_ID'), config.idp_id)
    config.profile = util.Util.default_if_none(os.getenv('AWS_PROFILE'), config.profile)
    config.region = util.Util.default_if_none(os.getenv('AWS_DEFAULT_REGION'), config.region)
    config.role_arn = util.Util.default_if_none(os.getenv('AWS_ROLE_ARN'), config.role_arn)
    config.sp_id = util.Util.default_if_none(os.getenv('GOOGLE_SP_ID'), config.sp_id)
    config.u2f_disabled = util.Util.default_if_none(os.getenv('U2F_DISABLED'), config.u2f_disabled)
    config.username = util.Util.default_if_none(os.getenv('GOOGLE_USERNAME'), config.username)

    # Override the options (again, as this is higher priority) with anything
    # the user specified on the command line.
    config.ask_role = util.Util.default_if_none(args.ask_role, config.ask_role)
    config.duration = util.Util.default_if_none(args.duration, config.duration)
    config.idp_id = util.Util.default_if_none(args.idp_id, config.idp_id)
    config.profile = util.Util.default_if_none(args.profile, config.profile)
    config.region = util.Util.default_if_none(args.region, config.region)
    config.role_arn = util.Util.default_if_none(args.role_arn, config.role_arn)
    config.sp_id = util.Util.default_if_none(args.sp_id, config.sp_id)
    config.u2f_disabled = util.Util.default_if_none(args.disable_u2f, config.u2f_disabled)
    config.username = util.Util.default_if_none(args.username, config.username)

    # There are some mandatory arguments. Make sure the user supplied them.
    if config.username is None:
        config.username = util.Util.get_input("Google username: ")
    if config.idp_id is None:
        config.idp_id = util.Util.get_input("Google IDP ID: ")
    if config.sp_id is None:
        config.sp_id = util.Util.get_input("Google SP ID: ")

    # There is no way (intentional) to pass in the password via the command
    # line nor environment variables. This prevents password leakage.
    config.password = getpass.getpass("Google Password: ")

    # Validate Options
    try:
        config.raise_if_invalid()
    except AssertionError:
        print("Invalid parameters.")
        raise

    google_client = google.Google(config)
    google_client.do_login()
    encoded_saml = google_client.parse_saml()

    amazon_client = amazon.Amazon(config, encoded_saml)
    roles = amazon_client.roles

    # Determine the provider and the role arn (if the the user provided isn't an option)
    if config.role_arn in roles and not config.ask_role:
        config.provider = roles[config.role_arn]
    else:
        config.role_arn, config.provider = util.Util.pick_a_role(roles)

    print("Assuming " + config.role_arn)
    print("Credentials Expiration: " + format(amazon_client.expiration.astimezone(get_localzone())))

    amazon_client.print_export_line()
    config.write(amazon_client)


if __name__ == '__main__':
    main()
