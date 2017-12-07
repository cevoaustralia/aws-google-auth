from aws_google_auth import GoogleAuth, _store, prepare


# Test that when no AWS_PROFILE (-p) is set that the config writer will raise
# an AssersionError. It doesn't make sense to write credentials without
# a profile, so the running of the store function implies the profile is set.
#
# See: https://github.com/cevoaustralia/aws-google-auth/issues/22
def test_write_config_no_profile():
    try:
        config = prepare.get_prepared_config(
            None,               # Profile
            "aws-region",       # AWS Region
            "user@example.com", # User
            "789xyz",           # IDP ID
            "abc123",           # SP ID
            60,                 # Credential Duration
            False               # Ask Role
        )
        token = "Some_Token_String"
        _store(config, token)
    except AssertionError as e:
        assert(str(e) == 'Can not store config/credentials if the '
                         'AWS_PROFILE is None.')
