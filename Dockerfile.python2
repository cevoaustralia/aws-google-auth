FROM alpine:3.5

RUN apk add --update-cache py2-pip ca-certificates py2-certifi py2-lxml

ADD . /build/
RUN pip install /build/

ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["aws-google-auth"]

