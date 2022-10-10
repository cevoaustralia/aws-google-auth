FROM python:3.10-alpine3.16

# RUN apk add --update-cache py3-pip ca-certificates py3-certifi py3-lxml\
#                            python3-dev cython cython-dev libusb-dev build-base \
#                            eudev-dev linux-headers libffi-dev openssl-dev \
#                            jpeg-dev zlib-dev freetype-dev lcms2-dev openjpeg-dev \
#                            tiff-dev tk-dev tcl-dev \
#                            py3-cryptography py3-wheel py3-pillow

RUN apk add --update-cache py3-pip ca-certificates py3-certifi py3-lxml\
                           py3-cryptography py3-wheel py3-pillow py3-hidapi

COPY setup.py README.rst requirements.txt /build/
RUN pip3 install -r /build/requirements.txt

COPY aws_google_auth /build/aws_google_auth
RUN pip3 install -e /build/[u2f]

ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV TZ=UTC
ENTRYPOINT ["aws-google-auth"]
