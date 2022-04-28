#!/bin/sh

set -e -o pipefail

aws-google-auth --bg-response js_enabled

echo "" >> /work/.env
echo AWS_ACCESS_KEY_ID=$(aws configure get sts.aws_access_key_id) >> /work/.env
echo AWS_SECRET_ACCESS_KEY=$(aws configure get sts.aws_secret_access_key) >> /work/.env
echo AWS_SECURITY_TOKEN=$(aws configure get sts.aws_security_token) >> /work/.env
echo AWS_SESSION_EXPIRATION=$(aws configure get sts.aws_session_expiration) >> /work/.env
echo AWS_SESSION_TOKEN=$(aws configure get sts.aws_session_token) >> /work/.env