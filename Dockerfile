FROM alpine:3.13

RUN apk --no-cache update && \
    apk add --no-cache \
    py3-pip=20.3.4-r0 \
    ca-certificates=20211220-r0 \
    py3-certifi=2020.6.20-r0 \
    py3-lxml=4.6.3-r0 \
    python3-dev=3.8.10-r0 \
    cython=0.29.21-r1 \
    libusb-dev=1.0.24-r1 \
    build-base=0.5-r2 \
    eudev-dev=3.2.9-r3 \
    linux-headers=5.7.8-r0 \
    libffi-dev=3.3-r2 \
    openssl-dev=1.1.1n-r0 \
    jpeg-dev=9d-r1 \
    zlib-dev=1.2.12-r0 \
    freetype-dev=2.10.4-r1 \
    lcms2-dev=2.11-r0 \
    openjpeg-dev=2.4.0-r1 \
    tiff-dev=4.2.0-r0 \
    tk-dev=8.6.10-r1 \
    tcl-dev=8.6.10-r1 \
    rust=1.47.0-r2 \
    cargo=1.47.0-r2 \
    tzdata=2022a-r0

COPY setup.py README.rst requirements.txt /build/
RUN pip3 --no-cache-dir install -r /build/requirements.txt

COPY aws_google_auth /build/aws_google_auth
RUN pip3 --no-cache-dir install -e /build/[u2f] && \
    cp /usr/share/zoneinfo/UTC /etc/localtime && echo UTC > /etc/timezone && apk del --no-cache tzdata

COPY entrypoint.sh /bin
RUN chmod +x /bin/entrypoint.sh

RUN mkdir /work

WORKDIR /work

ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

ENTRYPOINT ["/bin/entrypoint.sh"]