#!/bin/sh
# Bridges a pseudo-terminal to TCP port 2405 (TCP-as-serial), then runs the 101 peer on it.
set -e
socat pty,raw,echo=0,link=/tmp/ttyS tcp-listen:2405,reuseaddr &
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -e /tmp/ttyS ] && break; sleep 0.1; done
exec /usr/local/bin/iec101-peer "$@" --port /tmp/ttyS
