FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates cmake flex git libc-ares-dev libgcrypt20-dev \
    libglib2.0-dev libpcap-dev libpcre2-dev libxml2-dev ninja-build python3 zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
ARG REVISION=1e2c175c21c8ced022763ae7e8c4f2a133913fac
RUN git init && git remote add origin https://github.com/wireshark/wireshark.git \
    && git fetch --depth=1 origin "$REVISION" && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "$REVISION"
RUN cmake -S . -B /build -G Ninja -DBUILD_wireshark=OFF -DBUILD_stratoshark=OFF \
    -DBUILD_sharkd=OFF -DCMAKE_BUILD_TYPE=Release \
    '-DCMAKE_C_FLAGS_RELEASE=-O0 -DNDEBUG' '-DCMAKE_CXX_FLAGS_RELEASE=-O0 -DNDEBUG' \
    && cmake --build /build --target tshark --parallel 4
ENV WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1
ENTRYPOINT ["/build/run/tshark"]
