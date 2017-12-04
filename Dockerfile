FROM alpine:3.5

RUN apk add --update-cache py3-pip ca-certificates py3-certifi py3-lxml\
                           python3-dev cython cython-dev libusb-dev build-base \
                           eudev-dev linux-headers

ADD . /build/
RUN pip3 install -e /build/[u2f]

ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["aws-google-auth"]

