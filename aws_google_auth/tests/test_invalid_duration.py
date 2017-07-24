from aws_google_auth import GoogleAuth

def test_non_int():
    try:
        foo = GoogleAuth(
            username='foo',
            password='bar',
            idp_id='banana',
            sp_id='potato',
            duration_seconds='cheese',
        )
    except ValueError as e:
        assert(str(e) == 'GoogleAuth: duration_seconds must be an integer')
