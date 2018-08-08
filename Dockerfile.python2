FROM alpine:3.5

RUN apk add --update-cache py2-pip ca-certificates py2-certifi py2-lxml \
                           python-dev cython cython-dev libusb-dev build-base \
                           eudev-dev linux-headers libffi-dev openssl-dev \
                           jpeg-dev zlib-dev freetype-dev lcms2-dev openjpeg-dev \
                           tiff-dev tk-dev tcl-dev

ADD . /build/
RUN pip install -e /build/[u2f]

ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["aws-google-auth"]
