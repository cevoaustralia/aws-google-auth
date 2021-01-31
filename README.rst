aws-google-auth
===============

|github-badge| |docker-badge| |pypi-badge| |coveralls-badge|

.. |github-badge| image:: https://github.com/cevoaustralia/aws-google-auth/workflows/Python%20package/badge.svg
   :target: https://github.com/cevoaustralia/aws-google-auth/actions
   :alt: GitHub build badge

.. |docker-badge| image:: https://img.shields.io/docker/build/cevoaustralia/aws-google-auth.svg
   :target: https://hub.docker.com/r/cevoaustralia/aws-google-auth/
   :alt: Docker build status badge

.. |pypi-badge| image:: https://img.shields.io/pypi/v/aws-google-auth.svg
   :target: https://pypi.python.org/pypi/aws-google-auth/
   :alt: PyPI version badge

.. |coveralls-badge| image:: https://coveralls.io/repos/github/cevoaustralia/aws-google-auth/badge.svg?branch=master
   :target: https://coveralls.io/github/cevoaustralia/aws-google-auth?branch=master

This command-line tool allows you to acquire AWS temporary (STS)
credentials using Google Apps as a federated (Single Sign-On, or SSO)
provider.

Setup
-----

You'll first have to set up Google Apps as a SAML identity provider
(IdP) for AWS. There are tasks to be performed on both the Google Apps
and the Amazon sides; these references should help you with those
configurations:

-  `How to Set Up Federated Single Sign-On to AWS Using Google
   Apps <https://aws.amazon.com/blogs/security/how-to-set-up-federated-single-sign-on-to-aws-using-google-apps/>`__
-  `Using Google Apps SAML SSO to do one-click login to
   AWS <https://blog.faisalmisle.com/2015/11/using-google-apps-saml-sso-to-do-one-click-login-to-aws/>`__

If you need a fairly simple way to assign users to roles in AWS
accounts, we have another tool called `Google AWS
Federator <https://github.com/cevoaustralia/google-aws-federator>`__
that might help you.

Important Data
~~~~~~~~~~~~~~

You will need to know Google's assigned Identity Provider ID, and the ID
that they assign to the SAML service provider.

Once you've set up the SAML SSO relationship between Google and AWS, you
can find the SP ID by drilling into the Google Apps console, under
``Apps > SAML Apps > Settings for AWS SSO`` -- the URL will include a
component that looks like ``...#AppDetails:service=123456789012...`` --
that number is ``GOOGLE_SP_ID``

You can find the ``GOOGLE_IDP_ID``, again from the admin console, via
``Security > Set up single sign-on (SSO)`` -- the ``SSO URL`` includes a
string like ``https://accounts.google.com/o/saml2/idp?idpid=aBcD01AbC``
where the last bit (after the ``=``) is the IDP ID.

Installation
------------

You can install quite easily via ``pip``, if you want to have it on your
local system:

.. code:: shell

    # For basic installation
    localhost$ sudo pip install aws-google-auth

    # For installation with U2F support
    localhost$ sudo pip install aws-google-auth[u2f]


*Note* If using ZSH you will need to quote the install, as below:

.. code:: shell

   localhost$ sudo pip install "aws-google-auth[u2f]"

If you don't want to have the tool installed on your local system, or if
you prefer to isolate changes, there is a Dockerfile provided, which you
can build with:

.. code:: shell

    # Perform local build
    localhost$ cd ..../aws-google-auth && docker build -t aws-google-auth .

    # Use the Docker Hub version
    localhost$ docker pull cevoaustralia/aws-google-auth

Development
-----------

If you want to develop the AWS-Google-Auth tool itself, we thank you! In order
to help you get rolling, you'll want to install locally with pip. Of course,
you can use your own regular workflow, with tools like `virtualenv <https://virtualenv.pypa.io/en/stable/>`__.

.. code:: shell

    # Install (without U2F support)
    pip install -e .

    # Install (with U2F support)
    pip install -e .[u2f]

We welcome you to review our `code of conduct <CODE_OF_CONDUCT.md>`__ and
`contributing <CONTRIBUTING.md>`__ documents.

Usage
-----

.. code:: shell

    $ aws-google-auth -h
    usage: aws-google-auth [-h] [-u USERNAME] [-I IDP_ID] [-S SP_ID] [-R REGION]
                           [-d DURATION] [-p PROFILE] [-D] [-q]
                           [--bg-response BG_RESPONSE]
                           [--saml-assertion SAML_ASSERTION] [--no-cache]
                           [--print-creds] [--resolve-aliases]
                           [--save-failure-html] [--save-saml-flow] [-a | -r ROLE_ARN] [-k]
                           [-l {debug,info,warn}] [-V]

    Acquire temporary AWS credentials via Google SSO

    optional arguments:
      -h, --help            show this help message and exit
      -u USERNAME, --username USERNAME
                            Google Apps username ($GOOGLE_USERNAME)
      -I IDP_ID, --idp-id IDP_ID
                            Google SSO IDP identifier ($GOOGLE_IDP_ID)
      -S SP_ID, --sp-id SP_ID
                            Google SSO SP identifier ($GOOGLE_SP_ID)
      -R REGION, --region REGION
                            AWS region endpoint ($AWS_DEFAULT_REGION)
      -d DURATION, --duration DURATION
                            Credential duration (defaults to value of $DURATION, then
                            falls back to 43200)
      -p PROFILE, --profile PROFILE
                            AWS profile (defaults to value of $AWS_PROFILE, then
                            falls back to 'sts')
      -D, --disable-u2f     Disable U2F functionality.
      -q, --quiet           Quiet output
      --bg-response BG_RESPONSE
                            Override default bgresponse challenge token ($GOOGLE_BG_RESPONSE).
      --saml-assertion SAML_ASSERTION
                            Base64 encoded SAML assertion to use.
      --no-cache            Do not cache the SAML Assertion.
      --print-creds         Print Credentials.
      --resolve-aliases     Resolve AWS account aliases.
      --save-failure-html   Write HTML failure responses to file for
                            troubleshooting.
      --save-saml-flow      Write all GET and PUT requests and HTML responses to/from Google to files for troubleshooting.
      -a, --ask-role        Set true to always pick the role
      -r ROLE_ARN, --role-arn ROLE_ARN
                            The ARN of the role to assume ($AWS_ROLE_ARN)
      -k, --keyring         Use keyring for storing the password.
      -l {debug,info,warn}, --log {debug,info,warn}
                            Select log level (default: warn)
      -V, --version         show program's version number and exit


**Note** If you want a longer session than the AWS default 3600 seconds (1 hour)
duration, you must also modify the IAM Role to permit this. See
`the AWS documentation <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_manage_modify.html>`__
for more information.

Native Python
~~~~~~~~~~~~~

1. Execute ``aws-google-auth``
2. You will be prompted to supply each parameter

*Note* You can skip prompts by either passing parameters to the command, or setting the specified Environment variables.

Via Docker
~~~~~~~~~~~~~

1. Set environment variables for anything listed in Usage with ``($VARIABLE)`` after command line option:

   ``GOOGLE_USERNAME``, ``GOOGLE_IDP_ID``, and ``GOOGLE_SP_ID``
   (see above under "Important Data" for how to find the last two; the first one is usually your email address)

   ``AWS_PROFILE``: Optional profile name you want the credentials set for (default is 'sts')

   ``ROLE_ARN``: Optional ARN of the role to assume

2. For Docker:
   ``docker run -it -e GOOGLE_USERNAME -e GOOGLE_IDP_ID -e GOOGLE_SP_ID -e AWS_PROFILE -e ROLE_ARN -v ~/.aws:/root/.aws cevoaustralia/aws-google-auth``

You'll be prompted for your password. If you've set up an MFA token for
your Google account, you'll also be prompted for the current token
value.

If you have a U2F security key added to your Google account, you won't
be able to use this via Docker; the Docker container will not be able to
access any devices connected to the host ports. You will likely see the
following error during runtime: "RuntimeWarning: U2F Device Not Found".

If you have more than one role available to you (and you haven't set up ROLE_ARN),
you'll be prompted to choose the role from a list.

Feeding password from stdin
~~~~~~~~~~~~~~~~~~~~~~~~~~~

To enhance usability when using third party tools for managing passwords (aka password manager) you can feed data in
``aws-google-auth`` from ``stdin``.

When receiving data from ``stdin`` ``aws-google-auth`` disables the interactive prompt and uses ``stdin`` data.

Before `#82 <https://github.com/cevoaustralia/aws-google-auth/issues/82>`_, all interactive prompts could be fed from ``stdin`` already apart from the ``Google Password:`` prompt.

Example usage:
```
$ password-manager show password | aws-google-auth
Google Password: MFA token:
Assuming arn:aws:iam::123456789012:role/admin
Credentials Expiration: ...
```

**Note:** this feature is intended for password manager integration, not for passing passwords from command line.
Please use interactive prompt if you need to pass the password manually, as this provide enhanced security avoid
password leakage to shell history.

Storage of profile credentials
------------------------------

Through the use of AWS profiles, using the ``-p`` or ``--profile`` flag, the ``aws-google-auth`` utility will store the supplied username, IDP and SP details in your ``./aws/config`` files.

When re-authenticating using the same profile, the values will be remembered to speed up the re-authentication process.
This enables an approach that enables you to enter your username, IPD and SP values once and then after only need to re-enter your password (and MFA if enabled).

Creating an alias as below can be a quick and easy way to re-authenticate with a simple command shortcut.

```
alias aws-development='unset AWS_PROFILE; aws-google-auth -I $GOOGLE_IDP_ID -S $GOOGLE_SP_ID -u $USERNAME -p aws-dev ; export AWS_PROFILE=aws-dev'
```

Or, if you've alredy established a profile with valid cached values:

```
alias aws-development='unset AWS_PROFILE; aws-google-auth -p aws-dev ; export AWS_PROFILE=aws-dev'
```


Notes on Authentication
-----------------------

Google supports a number of 2-factor authentication schemes. Each of these
results in a slightly different "next" URL, if they're enabled, during ``do_login``

Google controls the preference ordering of these schemes in the case that
you have multiple ones defined.

The varying 2-factor schemes and their representative URL fragments handled
by this tool are:

+------------------+-------------------------------------+
| Method           | URL Fragment                        |
+==================+=====================================+
| No second factor | (none)                              |
+------------------+-------------------------------------+
| TOTP (eg Google  | ``.../signin/challenge/totp/...``   |
|  Authenticator   |                                     |
|  or Authy)       |                                     |
+------------------+-------------------------------------+
| SMS (or voice    | ``.../signin/challenge/ipp/...``    |
|  call)           |                                     |
+------------------+-------------------------------------+
| SMS (or voice    | ``.../signin/challenge/iap/...``    |
|  call) with      |                                     |
|  number          |                                     |
|  submission      |                                     |
+------------------+-------------------------------------+
| Google Prompt    | ``.../signin/challenge/az/...``     |
|  (phone app)     |                                     |
+------------------+-------------------------------------+
| Security key     | ``.../signin/challenge/sk/...``     |
|  (eg yubikey)    |                                     |
+------------------+-------------------------------------+
| Dual prompt      | ``.../signin/challenge/dp/...``     |
|  (Validate 2FA ) |                                     |
+------------------+-------------------------------------+
| Backup code      | ``... (unknown yet) ...``           |
|  (printed codes) |                                     |
+------------------+-------------------------------------+

Acknowledgments
----------------

This work is inspired by `keyme <https://github.com/wheniwork/keyme>`__
-- their digging into the guts of how Google SAML auth works is what's
enabled it.

The attribute management and credential injection into AWS configuration files
was heavily borrowed from `aws-adfs <https://github.com/venth/aws-adfs>`
