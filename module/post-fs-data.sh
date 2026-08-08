#!/system/bin/sh

MODDIR=${0%/*}

ENC="$MODDIR/pif.prop.enc"
DEC="$MODDIR/pif.prop"
TMP="$MODDIR/pif.prop.$$.tmp"
BIN="$MODDIR/bin/pifcrypt"

# pfcrypt has to be first marked exec, annoying but it be like that.

chmod +x "$BIN"

if [ -x "$BIN" ] && [ -f "$ENC" ]; then
    if "$BIN" decrypt --moddir "$MODDIR" "$ENC" "$TMP" 2>/dev/null; then
        mv -f "$TMP" "$DEC"
	#chmod 400 "$DEC"
    else
        rm -f "$TMP"
    fi
fi

# --- Existing boot-state hardening (resetprop of verifiedbootstate, etc.) ---
# Append the resetprop block from the current post-fs-data.sh below this line if
# it is still required. Only the decryption path above was redesigned; the
# integrity-related property hardening is unchanged and independent of it.
