# lib60870-C as the IEC 60870-5-101 interop peer of the iec60870 test suite.
#
# The library is GPL-3 and is never vendored: it is cloned here, at a pinned commit, when the
# image is built. peer101.c (MIT, part of this crate's tests) links against it. socat exposes
# the peer's pseudo-terminal as TCP port 2405, so a test on the host drives the same octets a
# serial line would carry (a pty cannot cross the container boundary; TCP can).
FROM debian:bookworm-slim

# The commit is pinned in one place, tests/interop/LIB60870_COMMIT, and passed by the test
# harness as a build argument; there is deliberately no default here.
ARG LIB60870_COMMIT

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential git ca-certificates socat \
 && rm -rf /var/lib/apt/lists/*

RUN test -n "$LIB60870_COMMIT" \
 && git clone https://github.com/mz-automation/lib60870.git /opt/lib60870 \
 && cd /opt/lib60870 \
 && git checkout --detach "$LIB60870_COMMIT" \
 && test "$(git rev-parse HEAD)" = "$LIB60870_COMMIT" \
 && make -C lib60870-C -j"$(nproc)"

COPY peer101.c /opt/peer/peer101.c
COPY run.sh /usr/local/bin/iec101-run
RUN chmod +x /usr/local/bin/iec101-run \
 && cd /opt/lib60870/lib60870-C \
 && gcc -O1 -g -Wall -o /usr/local/bin/iec101-peer /opt/peer/peer101.c \
      -Isrc/inc/api -Isrc/hal/inc -Isrc/tls build/liblib60870.a -lpthread

EXPOSE 2405
ENTRYPOINT ["/usr/local/bin/iec101-run"]
