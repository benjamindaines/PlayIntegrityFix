#!/bin/bash
set -eu

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_ylw=$'\033[33m'; c_blu=$'\033[34m'; c_rst=$'\033[0m'
log()  { printf '%s[*]%s %s\n' "$c_blu" "$c_rst" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$c_grn" "$c_rst" "$*"; }
warn() { printf '%s[!]%s %s\n' "$c_ylw" "$c_rst" "$*" >&2; }
die()  { printf '%s[x]%s %s\n' "$c_red" "$c_rst" "$*" >&2; exit 1; }


HERE="$(pwd)"
STAGING="module"
SEED="/home/ben/Documents/pif.prop"
HOST="pifcrypt/target/release/pifcrypt"
LOCAL="module/bin/pifcrypt"
ENC="$STAGING/pif.prop.enc"

#---------------------------------------------------------------------------------------------------------------------
#                                                                                                                     
#	Check for the things that need to be built, and build them if need be.                                               
#---------------------------------------------------------------------------------------------------------------------

[[ " $* " == *" clean "* ]] && gradle clean


while true; do
	[[ ! -f "$HOST" ]] && { \
		warn "x64.pifcrypt not found..."
		log "attempting to build"
		${ cd "$HERE/pifcrypt" && cargo build --release; yay=$?; cd "$HERE" || return; }
		[[ $yay -gt 0 ]] && die "Failed to build x86.pifcrypt"
		unset yay
		}

	[[ -x "$HOST" ]] && { \
		ok "Found x86.pifcrypt"
	} || \
		die "x86.pifcrypt not executable"
	break
done


while true; do
	[[ ! -f "$LOCAL" ]] && { \
		warn "a64.pifcrypt not found..."
		log "attempting to build"
		${ cd "$HERE/pifcrypt" && cargo zigbuild --release --target aarch64-unknown-linux-musl; \
			yay=$?; cd "$HERE" || return; }
		[[ $yay -gt 0 ]] && die "Failed to build a64.pifcrypt"
		unset yay
		log "built... moving to staging directory"
		cp "$HERE/pifcrypt/target/aarch64-unknown-linux-musl/release/pifcrypt" "$LOCAL" \
		       || die "couldn't do so..."
		} || ok "a64.pifcrypt found"
	break
done


[[ -f "$SEED" ]] && { \
	ok "Seed pif found"
} || \
	die "Seed pif not found"


# Plaintext seed must never ship.
rm -f "$STAGING/pif.prop"

#---------------------------------------------------------------------------------------------------------------------
#                                                                                                                     
#	Seal the props for maximum "shhh" and then do the actula building / packaging. Also, the usability of the 
#	prop values depends on the .sh script files not being tampered with... ya know, upstream's implementation 
#	should have been, rather than calling you a tamperer if you edit their module.prop file while allowing
#	for any amount of code injection where it actually matters.
#                                                                                                                     
#---------------------------------------------------------------------------------------------------------------------


ok "seal_pif: build-time key = $("$HOST" derive-key --moddir "$STAGING")"
"$HOST" encrypt --moddir "$STAGING" "$SEED" "$ENC" || die "::encryption.OOPS"
ok "seal_pif: sealed $(stat -c%s "$ENC") bytes -> $ENC"


V="$(mktemp)"
if ! "$HOST" decrypt --moddir "$STAGING" "$ENC" "$V" 2>/dev/null; then
    rm -f "$V"
    die "seal_pif: FAIL round-trip did not authenticate; seal is stale vs staging" >&2
    exit 1
fi
if ! cmp -s "$SEED" "$V"; then
    rm -f "$V"
    die "seal_pif: FAIL round-trip content mismatch" >&2
    exit 1
fi
rm -f "$V"
ok "seal_pif: round-trip verified; seal is consistent with staging"

log "Normalizing module.prop to UTF-8/LF"

#---------------------------------------------------------------------------------------------------------------------
#                                                                                                                     
#	I kept screwing up the encoding of the module.prop file somehow...                                            
#                                                                                                                     
#---------------------------------------------------------------------------------------------------------------------

# normalize module.prop to UTF-8/LF and fail the build if id won't parse
if file "$STAGING/module.prop" | grep -qiE 'UTF-16|BOM|\bdata\b'; then
    iconv -f UTF-16LE -t UTF-8 "$STAGING/module.prop" 2>/dev/null | tr -d '\r' > "$STAGING/module.prop.fix" \
        && mv "$STAGING/module.prop.fix" "$STAGING/module.prop"
fi
sed -i '1s/^\xEF\xBB\xBF//' "$STAGING/module.prop"
grep -q '^id=' "$STAGING/module.prop" || die "module.prop id unparseable (encoding); aborting"

#---------------------------------------------------------------------------------------------------------------------
#                                                                                                                     
#	Gradle handles the final build & pack                                                                         
#                                                                                                                     
#---------------------------------------------------------------------------------------------------------------------

log "Packing...."
./gradlew assembleRelease || die "::build.OOPS"

printf "\n"

ok "All set, ready In Through the Out Door 🎸"


exit 0
