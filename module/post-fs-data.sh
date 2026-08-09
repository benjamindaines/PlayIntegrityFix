#!/system/bin/sh

MODDIR=${0%/*}
BIN="$MODDIR/bin/pifcrypt"

chmod +x "$BIN" 2>/dev/null

rm -f "$MODDIR/pif.prop" "$MODDIR/pif.prop."*".tmp" /data/adb/pif.prop 2>/dev/null
