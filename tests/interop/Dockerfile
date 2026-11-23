# lib60870-C as the interop peer of the iec60870 test suite.
#
# The library is GPL-3 and is never vendored: it is cloned here, at a pinned commit, when the
# image is built. peer.c (MIT, part of this crate's tests) links against it; its role and
# behaviour are chosen by its arguments, so new scenarios need new arguments, not new images.
FROM debian:bookworm-slim

# The commit is pinned in one place, tests/interop/LIB60870_COMMIT, and passed by the test
# harness as a build argument; there is deliberately no default here.
ARG LIB60870_COMMIT

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN test -n "$LIB60870_COMMIT" \
 && git clone https://github.com/mz-automation/lib60870.git /opt/lib60870 \
 && cd /opt/lib60870 \
 && git checkout --detach "$LIB60870_COMMIT" \
 && test "$(git rev-parse HEAD)" = "$LIB60870_COMMIT" \
 && make -C lib60870-C -j"$(nproc)"

COPY peer.c /opt/peer/peer.c
RUN cd /opt/lib60870/lib60870-C \
 && gcc -O1 -g -Wall -o /usr/local/bin/iec104-peer /opt/peer/peer.c \
      -Isrc/inc/api -Isrc/hal/inc -Isrc/tls build/liblib60870.a -lpthread

ENTRYPOINT ["/usr/local/bin/iec104-peer"]
