FROM alpine:3.13

RUN apk --no-cache update && \
    apk add --no-cache \
    py3-pip \
    ca-certificates \
    py3-certifi \
    py3-lxml \
    python3-dev \
    cython \
    cython-dev \
    libusb-dev \
    build-base \
    eudev-dev \
    linux-headers \
    libffi-dev \
    openssl-dev \
    jpeg-dev \
    zlib-dev \
    freetype-dev \
    lcms2-dev \
    openjpeg-dev \
    tiff-dev \
    tk-dev \
    tcl-dev \
    rust \
    cargo \
    tzdata

RUN pip3 --no-cache-dir install --upgrade pip

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