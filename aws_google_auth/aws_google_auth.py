#!/usr/bin/env python

import argparse
import getpass
import base64
import boto3
import os
import sys
from keyme import KeyMe
from lxml import etree

REGION = os.getenv("AWS_DEFAULT_REGION") or "ap-southeast-2"
IDP_ID = os.getenv("GOOGLE_IDP_ID")
SP_ID = os.getenv("GOOGLE_SP_ID")
USERNAME = os.getenv("GOOGLE_USERNAME")
DURATION = os.getenv("DURATION")

def pick_one(roles):
    while True:
        for i, role in enumerate(roles):
            print "[{:d}] {}".format(i, role)
        choice = raw_input("Choose role to assume: ")
        try:
            num = int(choice)
            return roles.items()[num]
        except:
            print "Invalid choice, try again"

def main():
    parser = argparse.ArgumentParser(description="Acquire temporary AWS credentials via Google SSO")
    parser.add_argument('-u', '--username', default=USERNAME, help='Google Apps username ($GOOGLE_USERNAME)')
    parser.add_argument('-I', '--idp-id', default=IDP_ID, help='Google SSO IDP identifier ($GOOGLE_IDP_ID)')
    parser.add_argument('-S', '--sp-id', default=SP_ID, help='Google SSO SP identifier ($GOOGLE_SP_ID)')
    parser.add_argument('-R', '--region', default=REGION, help='AWS region endpoint ($AWS_DEFAULT_REGION)')
    parser.add_argument('-d', '--duration', default=DURATION, help='Credential duration ($DURATION)')

    args = parser.parse_args()

    if args.username is None:
        args.username = raw_input("Google username: ")

    if args.idp_id is None or args.sp_id is None:
        print "Must set both GOOGLE_IDP_ID and GOOGLE_SP_ID"
        parser.print_help()
        sys.exit(1)

    if args.duration is None:
        print "Setting duration to 3600 seconds"
        args.duration = 3600

    if args.duration > 3600:
        print "Duration must be less than or equal to 3600"
        duration = 3600

    passwd = getpass.getpass()
    mfa_token  = raw_input("MFA token: ") or None

    google = KeyMe(
        username=args.username,
        password=passwd,
        idp=args.idp_id,
        sp=args.sp_id,
        region=args.region,
        mfa_code=mfa_token,
        role="",
        principal="",
    )

    # oh, yuck
    google.session = google.login_to_google()
    encoded_saml = google.parse_google_saml()

    # Parse out the roles from the SAML so we can offer them as a choice
    doc = etree.fromstring(base64.b64decode(encoded_saml))
    roles = dict([x.split(',') for x in doc.xpath('//*[@Name = "https://aws.amazon.com/SAML/Attributes/Role"]//text()')])

    role, provider = pick_one(roles)

    print "Assuming " + role

    sts = boto3.client('sts', region_name=REGION)
    token = sts.assume_role_with_saml(
                RoleArn=role,
                PrincipalArn=provider,
                SAMLAssertion=encoded_saml,
                DurationSeconds=args.duration)

    print "export AWS_ACCESS_KEY_ID='{}'".format(token['Credentials']['AccessKeyId'])
    print "export AWS_SECRET_ACCESS_KEY='{}'".format(token['Credentials']['SecretAccessKey'])
    print "export AWS_SESSION_TOKEN='{}'".format(token['Credentials']['SessionToken'])
    print "export AWS_SESSION_EXPIRATION='{}'".format(token['Credentials']['Expiration'])
