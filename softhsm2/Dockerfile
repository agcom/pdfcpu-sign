FROM alpine:3.19.0 AS builder

ARG SOFTHSM_V2_VERSION=2.6.1

RUN apk --update add \
    git \
    openssl-dev \
    automake autoconf libtool pkgconfig \
    alpine-sdk

RUN git clone -b ${SOFTHSM_V2_VERSION} https://github.com/opendnssec/SoftHSMv2.git /tmp/SoftHSMv2/
WORKDIR /tmp/SoftHSMv2/

RUN sh ./autogen.sh \
    && ./configure \
    && make \
    && make install

FROM alpine:3.19.0

RUN apk --no-cache add libstdc++ openssl musl opensc

COPY --from=builder /usr/local/lib/softhsm/ /usr/local/lib/softhsm/
COPY --from=builder /usr/local/bin/softhsm* /usr/local/bin/
COPY --from=builder /etc/softhsm* /etc/
COPY --from=builder /var/lib/softhsm/ /var/lib/softhsm/
# Manual (man) documents not copied over.

VOLUME /var/lib/softhsm/

CMD softhsm2-util --help