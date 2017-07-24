import aws_google_auth
from os import path
from lxml import etree

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'valid-response.xml')) as fp:
    VALID_DOC = etree.fromstring(fp.read().encode('utf-8'))

with open(path.join(here, 'too-many-commas.xml')) as fp:
    TOO_MANY_COMMAS_DOC = etree.fromstring(fp.read().encode('utf-8'))

VALID_ROLE_ARN = "arn:aws:iam::123456789012:role/admin"

def test_parsing_valid_response():
    roles = aws_google_auth.parse_roles(VALID_DOC)
    assert(VALID_ROLE_ARN in roles)

def test_parsing_extra_commas():
    roles = aws_google_auth.parse_roles(TOO_MANY_COMMAS_DOC)
    assert(VALID_ROLE_ARN in roles)

