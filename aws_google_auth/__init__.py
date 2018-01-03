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

    role_group = parser.add_mutually_exclusive_group()
    role_group.add_argument('-a', '--ask-role', action='store_true', help='Set true to always pick the role')
    role_group.add_argument('-r', '--role-arn', help='The ARN of the role to assume')
    parser.add_argument('-V', '--version', action='version',
                        version='%(prog)s {version}'.format(version=_version.__version__))

    return parser.parse_args(args)


def main():
    try:
        cli(sys.argv[1:])
    except KeyboardInterrupt:
        pass


def cli(cli_args):
    args = parse_args(args=cli_args)

    # If there are arguments that are needed, we can interactively prompt the
    # user. Note, the environment variables here are also in configuration.py
    # but we need to check the presense here to know if we need to prompot.
    # This is intentional. Any non-required params just get passed directly in,
    # as we don't care if they were set or not.
    username = args.username or os.getenv("GOOGLE_USERNAME") or util.Util.get_input("Google username: ")
    idp_id = args.idp_id or os.getenv("GOOGLE_IDP_ID") or util.Util.get_input("Google IDP ID: ")
    sp_id = args.sp_id or os.getenv("GOOGLE_SP_ID") or util.Util.get_input("Google SP ID: ")

    # There is no way (intentional) to pass in the password via the command
    # line nor environment variables. This prevents password leakage.
    passwd = getpass.getpass("Google Password: ")

    # Build the configuration with all the user's options
    config = configuration.Configuration(
        ask_role=args.ask_role,
        duration=args.duration,
        idp_id=idp_id,
        profile=args.profile,
        region=args.region,
        role_arn=args.role_arn,
        sp_id=sp_id,
        username=username,
        password=passwd)

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
