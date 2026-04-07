FROM alpine:3.22 AS builder

RUN apk add --no-cache \
    build-base \
    cmake \
    boost-dev \
    libevent-dev \
    sqlite-dev \
    zeromq-dev \
    coreutils \
    binutils

WORKDIR /opt/btx

COPY . .

WORKDIR /opt/btx/build

RUN cmake .. \
    -DCMAKE_INSTALL_PREFIX="/usr/local/" \
    -DBUILD_DAEMON="ON" \
    -DBUILD_CLI="ON" \
    -DENABLE_WALLET="ON" \
    -DWITH_ZMQ="ON" \
    -DBUILD_TESTS="OFF" \
    -DBUILD_GUI="OFF" \
    -DBUILD_TX="OFF" \
    -DBUILD_UTIL="OFF" \
    -DBUILD_WALLET_TOOL="OFF" \
    -DBUILD_BENCH="OFF" \
    -DBUILD_FUZZ_BINARY="OFF" \
    -DBUILD_UTIL_CHAINSTATE="OFF" \
    -DWITH_BDB="OFF" \
    -DWITH_USDT="OFF" \
    -DINSTALL_MAN="OFF" \
    -DWITH_CCACHE="OFF"

RUN cmake --build . --parallel $(nproc)
RUN cmake --install .

RUN strip --strip-unneeded /usr/local/bin/*

FROM alpine:3.22 AS final

RUN apk add --no-cache \
    libevent \
    sqlite-libs \
    zeromq \
    boost-system \
    boost-filesystem \
    boost-program_options

COPY --from=builder /usr/local/bin/btxd     /usr/local/bin/btxd
COPY --from=builder /usr/local/bin/btx-cli  /usr/local/bin/btx-cli

RUN addgroup -S btx && \
    adduser -S -G btx -H -s /bin/false btx

WORKDIR /var/lib/btxd
EXPOSE 19335 19334
USER btx
VOLUME ["/var/lib/btxd", "/etc/btx/btx.conf"]

ENTRYPOINT ["btxd", "-conf=/etc/btx/btx.conf", "-datadir=/var/lib/btxd"]

HEALTHCHECK --interval=5m --timeout=15s --start-period=2m \
    CMD ["btx-cli", "-conf=/etc/btx/btx.conf", "-datadir=/var/lib/btxd", "getblockchaininfo"]
