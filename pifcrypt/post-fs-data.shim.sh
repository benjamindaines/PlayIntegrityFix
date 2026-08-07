# ---------------------------------------------------------------------------
# Integrity-bound configuration seed (insert near the top of post-fs-data.sh,
# immediately after `. "$MODPATH"/common_func.sh`, before the action.sh rename).
#
# $MODPATH/pif.prop.enc is sealed at build time under a key derived from the
# module script set and the decryptor binary. Runtime re-derivation reproduces
# the key only when those inputs are byte-identical to the build inputs; a
# modification produces an AES-256-GCM authentication failure and no plaintext.
#
# A provisioned /data/adb/pif.prop is authority and is never overwritten. The
# seed is materialized only when no valid provisioned config is present. On
# authentication failure no plaintext is written, and the service.sh FINGERPRINT
# guard falls through to autopif per existing fallback behavior.
#
# Decryption targets /data/adb/pif.prop directly via temp-write-and-rename
# (atomic within the same filesystem); no plaintext is written into the module
# directory.
# ---------------------------------------------------------------------------
if { [ ! -s /data/adb/pif.prop ] || ! grep -q '^FINGERPRINT=..*' /data/adb/pif.prop; } \
   && [ -x "$MODPATH/bin/pifcrypt" ] && [ -f "$MODPATH/pif.prop.enc" ]; then
    "$MODPATH/bin/pifcrypt" decrypt --moddir "$MODPATH" \
        "$MODPATH/pif.prop.enc" /data/adb/pif.prop 2>/dev/null || true
fi
