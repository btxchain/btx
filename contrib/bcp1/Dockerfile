# Monetary-only BTX node image for BCP/1 certification.
# Build from the repository root:
#   docker build -f contrib/bcp1/Dockerfile -t btx:exchange-local .
# No CUDA. No btx-modeld. No GUI. Isolated regtest only.

FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build pkg-config python3 \
    libevent-dev libboost-dev libsqlite3-dev libzmq3-dev \
    ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B build-exchange -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DWITH_MODELNET=OFF \
      -DBUILD_GUI=OFF \
      -DBUILD_BENCH=OFF \
      -DBUILD_TESTS=OFF \
      -DBUILD_FUZZ_BINARY=OFF \
    && cmake --build build-exchange -j"$(nproc)" --target bitcoind bitcoin-cli \
    && mkdir -p /opt/btx/bin \
    && cp build-exchange/bin/btxd /opt/btx/bin/btxd \
    && cp build-exchange/bin/btx-cli /opt/btx/bin/btx-cli

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libevent-2.1-7 libsqlite3-0 libzmq5 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/btx/bin/btxd /opt/btx/bin/btxd
COPY --from=build /opt/btx/bin/btx-cli /opt/btx/bin/btx-cli
COPY contrib/bcp1/mock_signer.py /opt/bcp1/mock_signer.py
EXPOSE 39443 39444
VOLUME ["/bcp1/data"]
ENTRYPOINT ["/opt/btx/bin/btxd"]
CMD ["-regtest","-datadir=/bcp1/data","-server=1","-exchange-watchonly=1","-txindex=1"]
