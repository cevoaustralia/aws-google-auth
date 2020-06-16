FROM alpine:3.5

RUN apk --no-cache update && \
    apk add --no-cache \
    ca-certificates=20161130-r1 \
    py3-certifi=2016.9.26-r0 \
    py3-lxml=3.6.4-r0 \
    python3-dev=3.5.6-r0 \
    cython=0.25.1-r0 \
    cython-dev=0.25.1-r0 \
    libusb-dev=1.0.20-r0 \
    build-base=0.4-r1 \
    eudev-dev=3.2.1-r1 \
    linux-headers=4.4.6-r1 \
    libffi-dev=3.2.1-r2 \
    openssl-dev=1.0.2q-r0 \
    jpeg-dev=8-r6 \
    zlib-dev=1.2.11-r0 \
    freetype-dev=2.7-r2 \
    lcms2-dev=2.8-r1 \
    openjpeg-dev=2.3.0-r0 \
    tiff-dev=4.0.9-r6 \
    tk-dev=8.6.6-r1 \
    tcl-dev=8.6.6-r0 && \
    pip3 --no-cache-dir install --upgrade pip==20.1.1

COPY setup.py README.rst requirements.txt /build/
RUN pip3 --no-cache-dir install -r /build/requirements.txt

COPY aws_google_auth /build/aws_google_auth
RUN pip3 --no-cache-dir install -e /build/[u2f]

COPY entrypoint.sh /bin
RUN chmod +x /bin/entrypoint.sh

RUN mkdir /work

WORKDIR /work

ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

ENTRYPOINT ["/bin/entrypoint.sh"]
