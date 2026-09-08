#!/bin/bash
#set -eu
ARGS=("$@")
_i=0
c_red=$'\033[31m'; c_grn=$'\033[32m'; c_ylw=$'\033[33m'; c_blu=$'\033[34m'; c_rst=$'\033[0m'
log()  { printf '%s[*]%s %s\n' "$c_blu" "$c_rst" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$c_grn" "$c_rst" "$*"; }
warn() { printf '%s[!]%s %s\n' "$c_ylw" "$c_rst" "$*" >&2; }
die()  { printf '%s[x]%s %s\n' "$c_red" "$c_rst" "$*" >&2; exit 1; }

debug() {
    [[ " $* " == *"--debug"* ]] && { \
        cp "$HERE/action.sh" "$STAGING/action.sh"
        warn "DEBUG BUILD: Contains action.sh that prints the whole everything in plain text!!"
        warn "Confirm this is what you want? (y/n)"
        read -r _input && CONFIRM=${_input^^}
        [[ $CONFIRM !=  "Y" ]] && ${ rm "$STAGING/action.sh"; die "Removing action.sh from the staging dir. Run build again.";  } 
        }
}

while [ $_i -lt ${#ARGS[@]} ]; do
	[[ ${ARGS[$_i]} == "--rom-keyfile" ]] && { \
		_i=$((_i + 1))
		ROM_KEYFILE="${ARGS[$_i]}"
	}
	_i=$((_i + 1))
done && _i=0

while [ $_i -lt ${#ARGS[@]} ]; do
	[[ ${ARGS[$_i]} == "--pif" ]] && { \
		_i=$((_i + 1))
		SEED="${ARGS[$_i]}"
		log "Using $SEED as seed file"
		break 2
	} || log "Using pre-set default from build script for seed file"
	_i=$((_i + 1))
done && _i=0

[[ " $* " == *" clean "* ]] && gradle clean && exit 0

HERE="$(pwd)"
STAGING="module"
SEED="${SEED:-/home/ben/Documents/pif2.prop}"
HOST="pifcrypt/target/release/pifcrypt"
LOCAL="module/bin/pifcrypt"
ENC="$STAGING/pif.prop.enc"

while true; do 
	warn "View seed file? (y/n)"
	read confirm
	CONFIRM="${confirm^^}"
	[[ $CONFIRM != "Y" ]] && break
	#cat "$SEED"
	while read line; do
		printf "\t%s\n" "$line"
	done < $SEED
	echo
	break
done

# Optional ROM-locked seal. When "--keyfile PATH" is supplied, PATH is folded
# into the key derivation for every pifcrypt invocation below, binding the seal
# to the byte content of that file. The same PATH content must be present on the
# device at the compiled KEYFILE_PATH (see zygisk.cpp) for the companion to
# reproduce the key. Absent this flag, the seal is manifest-only and portable
# (installable as an ordinary KernelSU module). Only file content is bound, so
# the build-time PATH and the on-device path may differ.
KFARGS=()
_args=("$@")
_i=0
while [ $_i -lt ${#_args[@]} ]; do
    if [ "${_args[$_i]}" = "--keyfile" ]; then
        _i=$((_i + 1))
        [ $_i -lt ${#_args[@]} ] || die "--keyfile requires a value"
        KEYFILE="${_args[$_i]}"
        [ -s "$KEYFILE" ] || die "keyfile '$KEYFILE' missing or empty"
        KFARGS=(--keyfile "$KEYFILE")
        ok "ROM-locked seal: binding keyfile content ($(stat -c%s "$KEYFILE") bytes)"
    elif [ "${_args[$_i]}" = "--keyfile-device-path" ]; then
        _i=$((_i + 1))
        [ $_i -lt ${#_args[@]} ] || die "--keyfile-device-path requires a value"
        KEYFILE_DEVICE_PATH="${_args[$_i]}"
        case "$KEYFILE_DEVICE_PATH" in *[[:space:]]*) die "--keyfile-device-path must not contain spaces";; esac
    fi
    _i=$((_i + 1))
done

sed -i 's|KEYFILE_PATH ""|KEYFILE_PATH "'$ROM_KEYFILE'"|g' zygisk/src/main/cpp/zygisk.cpp
ok "device key-file path -> $ROM_KEYFILE "

#---------------------------------------------------------------------------------------------------------------------
#                                                                                                                     
#	Check for the things that need to be built, and build them if need be.                                               
#---------------------------------------------------------------------------------------------------------------------



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


ok "seal_pif: build-time key = $("$HOST" derive-key --moddir "$STAGING" "${KFARGS[@]+"${KFARGS[@]}"}")"
"$HOST" encrypt --moddir "$STAGING" "${KFARGS[@]+"${KFARGS[@]}"}" "$SEED" "$ENC" || die "::encryption.OOPS"
ok "seal_pif: sealed $(stat -c%s "$ENC") bytes -> $ENC"


V="$(mktemp)"
if ! "$HOST" decrypt --moddir "$STAGING" "${KFARGS[@]+"${KFARGS[@]}"}" "$ENC" "$V" 2>/dev/null; then
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
debug $*
log "Packing...."
./gradlew assembleRelease || die "::build.OOPS"
printf "\n"

[[ -f "$STAGING/action.sh" ]] && rm "$STAGING/action.sh" && log "action.sh stashed away"
sed -i 's|KEYFILE_PATH "'$ROM_KEYFILE'"|KEYFILE_PATH ""|g' zygisk/src/main/cpp/zygisk.cpp
ok "All set, ready In Through the Out Dir 🎸"


exit 0
