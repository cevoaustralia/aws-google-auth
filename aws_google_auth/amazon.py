#!/usr/bin/env python

import boto3
import base64
from lxml import etree
from datetime import datetime


class Amazon:

    def __init__(self, config, saml_xml):
        self.config = config
        self.saml_xml = saml_xml
        self.__token = None

    @property
    def sts_client(self):
        return boto3.client('sts', region_name=self.config.region)

    @property
    def base64_encoded_saml(self):
        return base64.b64encode(self.saml_xml).decode("utf-8")

    @property
    def token(self):
        if self.__token is None:
            self.__token = self.sts_client.assume_role_with_saml(
                RoleArn=self.config.role_arn,
                PrincipalArn=self.config.provider,
                SAMLAssertion=self.base64_encoded_saml,
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
        doc = etree.fromstring(self.saml_xml)
        roles = {}
        for x in doc.xpath('//*[@Name = "https://aws.amazon.com/SAML/Attributes/Role"]//text()'):
            if "arn:aws:iam:" in x:
                res = x.split(',')
                roles[res[0]] = res[1]
        return roles

    @staticmethod
    def is_valid_saml_assertion(saml_xml):
        if saml_xml is None:
            return False

        try:
            doc = etree.fromstring(saml_xml)
            conditions = list(doc.iter(tag='{urn:oasis:names:tc:SAML:2.0:assertion}Conditions'))
            not_before_str = conditions[0].get('NotBefore')
            not_on_or_after_str = conditions[0].get('NotOnOrAfter')

            now = datetime.utcnow()
            not_before = datetime.strptime(not_before_str, "%Y-%m-%dT%H:%M:%S.%fZ")
            not_on_or_after = datetime.strptime(not_on_or_after_str, "%Y-%m-%dT%H:%M:%S.%fZ")

            if not_before <= now < not_on_or_after:
                return True
            else:
                return False
        except Exception:
            return False
