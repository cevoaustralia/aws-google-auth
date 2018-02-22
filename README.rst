aws-google-auth
===============

|travis-badge| |docker-badge| |pypi-badge| |coveralls-badge|

.. |travis-badge| image:: https://img.shields.io/travis/cevoaustralia/aws-google-auth.svg
   :target: https://travis-ci.org/cevoaustralia/aws-google-auth
   :alt: Travis build badge

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

If you don't want to have the tool installed on your local system, or if
you prefer to isolate changes, there is a Dockerfile provided, which you
can build with:

.. code:: shell

    # Perform local build
    localhost$ cd ..../aws-google-auth && docker build -t aws-google-auth .

    # Use the Docker Hub version
    localhost$ docker pull cevoaustralia/aws-google-auth

Usage
-----

.. code:: shell

    $ aws-google-auth -h
    usage: aws-google-auth [-h] [-u USERNAME] [-I IDP_ID] [-S SP_ID] [-R REGION]
                           [-d DURATION] [-p PROFILE] [-D] [--no-cache]
                           [-a | -r ROLE_ARN] [-V]

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
                            Credential duration ($DURATION)
      -p PROFILE, --profile PROFILE
                            AWS profile (defaults to value of $AWS_PROFILE, then
                            falls back to 'sts')
      -D, --disable-u2f     Disable U2F functionality.
      --no-cache            Do not cache the SAML Assertion.
      -a, --ask-role        Set true to always pick the role
      -r ROLE_ARN, --role-arn ROLE_ARN
                            The ARN of the role to assume
      -V, --version         show program's version number and exit


Native Python
~~~~~~~~~~~~~

1. Execute ``aws-google-auth``
2. You will be prompted to supply each parameter

*Note* You can skip prompts by either passing parameters to the command, or setting the specified Environment variables.

Via Docker
~~~~~~~~~~~~~

1. Set environment variables for ``GOOGLE_USERNAME``, ``GOOGLE_IDP_ID``,
   and ``GOOGLE_SP_ID`` (see above under "Important Data" for how to
   find the last two; the first one is usually your email address)
2. For Docker:
   ``docker run -it -e GOOGLE_USERNAME -e GOOGLE_IDP_ID -e GOOGLE_SP_ID cevoaustralia/aws-google-auth``

You'll be prompted for your password. If you've set up an MFA token for
your Google account, you'll also be prompted for the current token
value.

If you have more than one role available to you, you'll be prompted to
choose the role from a list; otherwise, if your credentials are correct,
you'll just see the AWS keys printed on stdout.

If you have a U2F security key added to your Google account, you won't
be able to use this via Docker; the Docker container will not be able to
access any devices connected to the host ports. You will likely see the
following error during runtime: "RuntimeWarning: U2F Device Not Found".


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
| TOTP (eg Google  | ``.../signin/challenge/totp/2?...`` |
|  Authenticator   |                                     |
|  or Authy)       |                                     |
+------------------+-------------------------------------+
| SMS (or voice    | ``.../signin/challenge/ipp/2?...``  |
|  call)           |                                     |
+------------------+-------------------------------------+
| SMS (or voice    | ``.../signin/challenge/iap/...``    |
|  call) with      |                                     |
|  number          |                                     |
|  submission      |                                     |
+------------------+-------------------------------------+
| Google Prompt    | ``.../signin/challenge/az/2?...``   |
|  (phone app)     |                                     |
+------------------+-------------------------------------+
| Security key     | ``.../signin/challenge/sk/...``     |
|  (eg yubikey)    |                                     |
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
