#!/bin/sh
# Terminal build stage. Seals the plaintext configuration seed under a key
# derived from the finalized module script set and the shipped decryptor binary
# (AES-256-GCM). A post-seal authenticated round-trip gates the build so that a
# seal inconsistent with the staging tree fails on the workstation rather than
# on device.
#
# Positional arguments:
#   STAGING        Finalized module tree that will be packaged. STAGING/bin/pifcrypt
#                  MUST already be the target-architecture (device, aarch64)
#                  binary that ships. It is a hashed manifest input; its bytes
#                  must equal the on-device binary exactly. Staging the host
#                  binary here causes every device to fail authentication.
#   PLAINTEXT_SEED Out-of-repo plaintext pif.prop to seal.
#   HOST_PIFCRYPT  Host-architecture pifcrypt executable used to run this stage.
#                  Execution vehicle only; not hashed. Key derivation reads the
#                  file at STAGING/bin/pifcrypt regardless of which binary runs.
#
# Ordering requirement: all hashed inputs must be in shipped byte state before
# invocation. Any post-seal edit to a manifest file invalidates the seal.
set -eu

STAGING="${1:?usage: seal_pif.sh STAGING PLAINTEXT_SEED HOST_PIFCRYPT}"
SEED="${2:?usage: seal_pif.sh STAGING PLAINTEXT_SEED HOST_PIFCRYPT}"
HOST="${3:?usage: seal_pif.sh STAGING PLAINTEXT_SEED HOST_PIFCRYPT}"
ENC="$STAGING/pif.prop.enc"

[ -x "$HOST" ]                 || { echo "seal_pif: host executor '$HOST' not executable" >&2; exit 1; }
[ -f "$STAGING/bin/pifcrypt" ] || { echo "seal_pif: '$STAGING/bin/pifcrypt' (device binary) missing" >&2; exit 1; }
[ -f "$SEED" ]                 || { echo "seal_pif: seed '$SEED' not found" >&2; exit 1; }

# Plaintext seed must never ship.
rm -f "$STAGING/pif.prop"

echo "seal_pif: build-time key = $("$HOST" derive-key --moddir "$STAGING")"
"$HOST" encrypt --moddir "$STAGING" "$SEED" "$ENC"
echo "seal_pif: sealed $(stat -c%s "$ENC") bytes -> $ENC"

# Terminal gate: authenticated round-trip against the finalized staging tree.
# Failure here indicates the seal does not match current manifest bytes.
V="$(mktemp)"
if ! "$HOST" decrypt --moddir "$STAGING" "$ENC" "$V" 2>/dev/null; then
    rm -f "$V"
    echo "seal_pif: FAIL round-trip did not authenticate; seal is stale vs staging" >&2
    exit 1
fi
if ! cmp -s "$SEED" "$V"; then
    rm -f "$V"
    echo "seal_pif: FAIL round-trip content mismatch" >&2
    exit 1
fi
rm -f "$V"
echo "seal_pif: round-trip verified; seal is consistent with staging"
