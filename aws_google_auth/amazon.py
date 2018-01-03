#!/usr/bin/env python

import boto3
import base64
from lxml import etree


class Amazon:

    def __init__(self, config, encoded_saml):
        self.config = config
        self.encoded_saml = encoded_saml
        self.__token = None

    @property
    def sts_client(self):
        return boto3.client('sts', region_name=self.config.region)

    @property
    def decoded_saml(self):
        return base64.b64decode(self.encoded_saml)

    @property
    def token(self):
        if self.__token is None:
            self.__token = self.sts_client.assume_role_with_saml(
                RoleArn=self.config.role_arn,
                PrincipalArn=self.config.provider,
                SAMLAssertion=self.encoded_saml,
                DurationSeconds=self.config.duration)
        return self.__token

    @property
    def access_key_id(self):
        return self.token['Credentials']['AccessKeyId']

    @property
    def secret_access_key(self):
        return self.token['Credentials']['SecretAccessKey']

    @property
    def session_token(self):
        return self.token['Credentials']['SessionToken']

    @property
    def expiration(self):
        return self.token['Credentials']['Expiration']

    def print_export_line(self):
        export_template = "export AWS_ACCESS_KEY_ID='{}' AWS_SECRET_ACCESS_KEY='{}' AWS_SESSION_TOKEN='{}' AWS_SESSION_EXPIRATION='{}'"

        formatted = export_template.format(
            self.access_key_id,
            self.secret_access_key,
            self.session_token,
            self.expiration.strftime('%Y-%m-%dT%H:%M:%S%z'))

        print(formatted)

    @property
    def roles(self):
        doc = etree.fromstring(self.decoded_saml)
        roles = {}
        for x in doc.xpath('//*[@Name = "https://aws.amazon.com/SAML/Attributes/Role"]//text()'):
            if "arn:aws:iam:" in x:
                res = x.split(',')
                roles[res[0]] = res[1]
        return roles
