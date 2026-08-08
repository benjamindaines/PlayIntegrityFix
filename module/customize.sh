# don't flash in recovery!
if ! $bootmode; then
    ui_print "*********************************************************"
    ui_print "! install from recovery is not supported"
    ui_print "! recovery sucks"
    ui_print "! please install from magisk / kernelsu / apatch app"
    abort    "*********************************************************"
fi

# error on < android 8
if [ "$api" -lt 26 ]; then
    abort "! you can't use this module on android < 8.0"
fi

check_zygisk() {
    local magisk_dir="/data/adb/magisk"
    local zygisk_msg="zygisk is not enabled. please either:
    - enable zygisk in magisk settings
    - install zygisknext or rezygisk module"

    # check if zygisk module exists
    if find /data/adb/modules /data/adb/modules_update -name "libzygisk.so" | grep -q .; then
        return 0
    fi

    # if magisk is installed, check zygisk settings
    if [ -d "$magisk_dir" ]; then
        # query zygisk status from magisk database
        local zygisk_status
        zygisk_status=$(magisk --sqlite "select value from settings where key='zygisk';")

        # check if zygisk is disabled
        if [ "$zygisk_status" = "value=0" ]; then
            abort "$zygisk_msg"
        fi
    else
        abort "$zygisk_msg"
    fi
}

# module requires zygisk to work
check_zygisk
chmod +x /data/adb/modules/playintegrityfix-benos/bin/pifcrypt

# Clean up
for pkg in com.google.android.gms com.android.vending; do
	pm clean $"pkg" && sync; sleep 3
done



