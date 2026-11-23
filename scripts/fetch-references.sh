#!/usr/bin/env bash
# Fetch the freely available reference material into $IEC60870_REFERENCE (default: a
# git-ignored directory in the checkout; the tests use the same default). Idempotent.
# Public material only: Wireshark's IEC 60870-5 dissector (GPL-2, reference only), the
# lib60870-C source (GPL-3, reference and interop peer only), RFCs for the TLS profile, and
# sample captures. Paid IEC standards and the IEC webstore previews must be obtained manually.
# Nothing fetched here is ever committed or redistributed.
set -euo pipefail
cd "$(dirname "$0")/.."
R="${IEC60870_REFERENCE:-concepts/reference}"
mkdir -p "$R"/{wireshark,rfc,pcap,iec-previews,standards}

dl() { # url dest
  if [ -s "$2" ]; then echo "skip   $2"; return; fi
  if curl -fsSL --retry 3 --max-time 180 -o "$2" "$1"; then echo "ok     $2"; else echo "FAILED $2 ($1)" >&2; rm -f "$2"; fi
}
clone() { # url dest
  if [ -d "$2/.git" ]; then echo "skip   $2"; return; fi
  git clone --depth 1 --quiet "$1" "$2" && echo "ok     $2" || echo "FAILED $2 ($1)" >&2
}
rfc() { dl "https://www.rfc-editor.org/rfc/rfc$1.txt" "$R/rfc/rfc$1-$2.txt"; }

# Wireshark: the third-party reader of every frame this crate emits (101, 104 and the ASDU).
dl "https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-iec104.c" \
   "$R/wireshark/packet-iec104.c"

# The second stack: lib60870-C (and its .NET sibling) — read for behaviour, run for interop.
clone https://github.com/mz-automation/lib60870.git "$R/lib60870"
clone https://github.com/mz-automation/lib60870.NET.git "$R/lib60870.NET"

# TLS for IEC 60870-5-104 (IEC 62351-3 profiles TLS 1.2/1.3).
rfc 5246 tls12
rfc 8446 tls13
rfc 5746 tls-renegotiation-indication

# Sample captures (Wireshark wiki).
dl "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/iec104.pcap" \
   "$R/pcap/iec104.pcap"

cat <<EOF

Manual (paid or bot-protected) — see the REFERENCES index in the architecture notes:
  IEC 60870-5-101, -104, -5-7, IEC 62351-3, IEC 62351-5, IEC TS 60870-5-601/-604
  into $R/standards/ ; the free webstore previews into $R/iec-previews/
EOF
