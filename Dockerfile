FROM python:3-alpine

ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

COPY setup.py README.rst requirements.txt /build/
COPY aws_google_auth /build/aws_google_auth

RUN apk add --update --no-cache \
        ca-certificates \
        libxml2 \
        libxslt \
        eudev-libs \
        libffi \
        openssl \
        jpeg \
        zlib \
        freetype \
        lcms2 \
        openjpeg \
        libusb \
        tiff \
        tk \
        tcl && \
    apk add --update --no-cache --virtual .builddeps \
        build-base \
        cython-dev \
        libxml2-dev \
        libxslt-dev \
        eudev-dev \
        libffi-dev \
        openssl-dev \
        jpeg-dev \
        zlib-dev \
        freetype-dev \
        lcms2-dev \
        openjpeg-dev \
        libusb-dev \
        tiff-dev \
        tk-dev \
        tcl-dev && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/apk/* && \
    pip install -Ur /build/requirements.txt && \
    pip install -Ue /build/[u2f] && \
    apk del .builddeps && \
    rm -rf .builddeps

ENTRYPOINT ["aws-google-auth"]
