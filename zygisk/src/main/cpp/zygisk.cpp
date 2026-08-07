#include "zygisk.hpp"
#include "checksum.h"
#include "Dobby/include/dobby.h"
#include "pif_config.hpp"

#include <algorithm>
#include <android/log.h>
#include <array>
#include <jni.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/system_properties.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <vector>
#include <cstdio>

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "PIF", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "PIF", __VA_ARGS__)

#define DEX_PATH "/data/adb/modules/playintegrityfix-benos/classes.dex"
#define MODULE_PROP "/data/adb/modules/playintegrityfix-benos/module.prop"
#define DEFAULT_PIF "/data/adb/modules/playintegrityfix-benos/pif.prop"
#define CUSTOM_PIF "/data/adb/pif.prop"

#define VENDING_PACKAGE "com.android.vending"

namespace {

constexpr uint8_t COMMAND_LOAD_PAYLOAD = 1;
constexpr int PAYLOAD_TIMEOUT_MS = 5000;

// Package-directory pre-filter. The companion connection and profile lookup
// occur only for processes whose app_data_dir belongs to one of these
// packages; every other specialized process short-circuits with no IPC. Any
// process within these packages is routable by exact name from pif.prop. To
// make a process in a different package routable, add its data-dir suffix
// here. (Note: system/vendor IMS daemons such as com.mediatek.ims read native
// build properties rather than the Java Build fields set here, and are not
// generally zygote-forked app processes, so routing them has no effect.)
constexpr std::array<std::string_view, 3> ALLOWED_PACKAGE_DIRS = {
        "/com.google.android.gms",
        "/com.android.vending",
        "/com.google.android.apps.messaging",
};

JNIEnv *gEnv = nullptr;
pif::Config gConfig;
std::vector<uint8_t> gDexBytes;

using T_Callback = void (*)(void *, const char *, const char *, uint32_t);

T_Callback o_callback = nullptr;
void (*o_system_property_read_callback)(prop_info *, T_Callback, void *) = nullptr;

ssize_t xread(int fd, void *buffer, size_t countToRead) {
    ssize_t totalRead = 0;
    char *currentBuf = static_cast<char *>(buffer);
    size_t remainingBytes = countToRead;

    while (remainingBytes > 0) {
        const ssize_t ret = TEMP_FAILURE_RETRY(read(fd, currentBuf, remainingBytes));
        if (ret < 0) {
            return -1;
        }
        if (ret == 0) {
            break;
        }

        currentBuf += ret;
        totalRead += ret;
        remainingBytes -= ret;
    }

    return totalRead;
}

ssize_t xwrite(int fd, const void *buffer, size_t countToWrite) {
    ssize_t totalWritten = 0;
    const char *currentBuf = static_cast<const char *>(buffer);
    size_t remainingBytes = countToWrite;

    while (remainingBytes > 0) {
        const ssize_t ret = TEMP_FAILURE_RETRY(write(fd, currentBuf, remainingBytes));
        if (ret < 0) {
            return -1;
        }
        if (ret == 0) {
            break;
        }

        currentBuf += ret;
        totalWritten += ret;
        remainingBytes -= ret;
    }

    return totalWritten;
}

bool readExact(int fd, void *buffer, size_t size) {
    return xread(fd, buffer, size) == static_cast<ssize_t>(size);
}

bool writeExact(int fd, const void *buffer, size_t size) {
    return xwrite(fd, buffer, size) == static_cast<ssize_t>(size);
}

void applySocketTimeout(int fd) {
    const timeval timeout{
            .tv_sec = PAYLOAD_TIMEOUT_MS / 1000,
            .tv_usec = static_cast<suseconds_t>((PAYLOAD_TIMEOUT_MS % 1000) * 1000),
    };

    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

bool readFileBytes(const char *path, std::vector<uint8_t> &out) {
    out.clear();

    const int file = open(path, O_RDONLY | O_CLOEXEC);
    if (file < 0) {
        return false;
    }

    std::vector<uint8_t> buffer(4096);
    ssize_t bytes = 0;
    while ((bytes = TEMP_FAILURE_RETRY(read(file, buffer.data(), buffer.size()))) > 0) {
        out.insert(out.end(), buffer.begin(), buffer.begin() + bytes);
    }

    close(file);
    return bytes == 0 && !out.empty();
}

bool loadPropBytes(std::vector<uint8_t> &out) {
    if (readFileBytes(CUSTOM_PIF, out)) {
        return true;
    }
    return readFileBytes(DEFAULT_PIF, out);
}

bool writeVector(int fd, const std::vector<uint8_t> &buffer) {
    const uint32_t size = static_cast<uint32_t>(buffer.size());
    if (!writeExact(fd, &size, sizeof(size))) {
        return false;
    }
    return size == 0 || writeExact(fd, buffer.data(), size);
}

bool readVector(int fd, std::vector<uint8_t> &buffer) {
    uint32_t size = 0;
    if (!readExact(fd, &size, sizeof(size))) {
        return false;
    }

    buffer.resize(size);
    return size == 0 || readExact(fd, buffer.data(), size);
}

bool writeString(int fd, const std::string &value) {
    const std::vector<uint8_t> bytes(value.begin(), value.end());
    return writeVector(fd, bytes);
}

bool readString(int fd, std::string &value) {
    std::vector<uint8_t> bytes;
    if (!readVector(fd, bytes)) {
        return false;
    }
    value.assign(bytes.begin(), bytes.end());
    return true;
}

uint32_t crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j) {
            crc = (crc >> 1) ^ (0xEDB88320U & (-(crc & 1)));
        }
    }
    return ~crc;
}

std::string propMapToJson() {
    std::string json = "{";
    bool first = true;
    for (const auto &[key, value] : gConfig.propMap) {
        if (!first) {
            json += ",";
        }
        first = false;
        json += "\"" + key + "\":\"" + value + "\"";
    }
    json += "}";
    return json;
}

void modifyCallback(void *cookie, const char *name, const char *value, uint32_t serial) {
    if (!cookie || !name || !value || !o_callback) {
        return;
    }

    const char *oldValue = value;
    const std::string_view prop(name);

    if (prop == "init.svc.adbd") {
        value = "stopped";
    } else if (prop == "sys.usb.state") {
        value = "mtp";
    } else if (prop.ends_with("api_level")) {
        if (!gConfig.deviceInitialSdkInt.empty()) {
            value = gConfig.deviceInitialSdkInt.c_str();
        }
    } else if (prop.ends_with(".security_patch")) {
        if (!gConfig.securityPatch.empty()) {
            value = gConfig.securityPatch.c_str();
        }
    } else if (prop.ends_with(".build.id")) {
        if (!gConfig.buildId.empty()) {
            value = gConfig.buildId.c_str();
        }
    }

    if (strcmp(oldValue, value) == 0) {
        if (gConfig.debug) {
            LOGD("[%s]: %s (unchanged)", name, oldValue);
        }
    } else {
        LOGD("[%s]: %s -> %s", name, oldValue, value);
    }

    o_callback(cookie, name, value, serial);
}

void systemPropertyReadCallback(prop_info *pi, T_Callback callback, void *cookie) {
    if (pi && callback && cookie) {
        o_callback = callback;
    }
    o_system_property_read_callback(pi, modifyCallback, cookie);
}

bool doHook() {
    void *ptr = DobbySymbolResolver(nullptr, "__system_property_read_callback");
    if (ptr && DobbyHook(ptr, reinterpret_cast<void *>(systemPropertyReadCallback),
                         reinterpret_cast<void **>(&o_system_property_read_callback)) == 0) {
        LOGD("hook __system_property_read_callback successful at %p", ptr);
        return true;
    }

    LOGE("hook __system_property_read_callback failed!");
    return false;
}

void doSpoofVending() {
    constexpr int requestSdk = 32;

    jclass buildVersionClass = gEnv->FindClass("android/os/Build$VERSION");
    if (buildVersionClass == nullptr) {
        LOGE("Build.VERSION class not found");
        gEnv->ExceptionClear();
        return;
    }

    jfieldID sdkIntFieldId = gEnv->GetStaticFieldID(buildVersionClass, "SDK_INT", "I");
    if (sdkIntFieldId == nullptr) {
        LOGE("SDK_INT field not found");
        gEnv->ExceptionClear();
        gEnv->DeleteLocalRef(buildVersionClass);
        return;
    }

    const int oldValue = gEnv->GetStaticIntField(buildVersionClass, sdkIntFieldId);
    const int targetSdk = std::min(oldValue, requestSdk);
    if (oldValue == targetSdk) {
        gEnv->DeleteLocalRef(buildVersionClass);
        return;
    }

    gEnv->SetStaticIntField(buildVersionClass, sdkIntFieldId, targetSdk);
    if (gEnv->ExceptionCheck()) {
        gEnv->ExceptionDescribe();
        gEnv->ExceptionClear();
        LOGE("SDK_INT field not accessible (JNI Exception)");
    } else {
        LOGD("[SDK_INT]: %d -> %d", oldValue, targetSdk);
    }

    gEnv->DeleteLocalRef(buildVersionClass);
}

void updateBuildFields() {
    jclass buildClass = gEnv->FindClass("android/os/Build");
    jclass versionClass = gEnv->FindClass("android/os/Build$VERSION");
    if (buildClass == nullptr || versionClass == nullptr) {
        gEnv->ExceptionClear();
        return;
    }

    for (const auto &[key, value] : gConfig.propMap) {
        jclass targetClass = buildClass;
        jfieldID fieldId = gEnv->GetStaticFieldID(buildClass, key.c_str(), "Ljava/lang/String;");
        if (gEnv->ExceptionCheck()) {
            gEnv->ExceptionClear();
            fieldId = gEnv->GetStaticFieldID(versionClass, key.c_str(), "Ljava/lang/String;");
            targetClass = versionClass;
            if (gEnv->ExceptionCheck()) {
                gEnv->ExceptionClear();
                continue;
            }
        }

        jstring jValue = gEnv->NewStringUTF(value.c_str());
        gEnv->SetStaticObjectField(targetClass, fieldId, jValue);
        if (gEnv->ExceptionCheck()) {
            gEnv->ExceptionClear();
            gEnv->DeleteLocalRef(jValue);
            continue;
        }

        LOGD("Set '%s' to '%s'", key.c_str(), value.c_str());
        gEnv->DeleteLocalRef(jValue);
    }

    gEnv->DeleteLocalRef(versionClass);
    gEnv->DeleteLocalRef(buildClass);
}

void injectDex() {
    if (gDexBytes.empty()) {
        LOGD("[INJECT] No dex payload available");
        return;
    }

    jclass classLoaderClass = gEnv->FindClass("java/lang/ClassLoader");
    jmethodID getSystemClassLoader = gEnv->GetStaticMethodID(
            classLoaderClass, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
    jobject systemClassLoader = gEnv->CallStaticObjectMethod(classLoaderClass, getSystemClassLoader);
    if (gEnv->ExceptionCheck()) {
        gEnv->ExceptionDescribe();
        gEnv->ExceptionClear();
        return;
    }

    jobject dexBuffer = gEnv->NewDirectByteBuffer(gDexBytes.data(), static_cast<jlong>(gDexBytes.size()));
    jclass inMemoryClassLoaderClass = gEnv->FindClass("dalvik/system/InMemoryDexClassLoader");
    jmethodID inMemoryClassLoaderInit = gEnv->GetMethodID(
            inMemoryClassLoaderClass, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    jobject dexClassLoader = gEnv->NewObject(
            inMemoryClassLoaderClass, inMemoryClassLoaderInit, dexBuffer, systemClassLoader);
    if (gEnv->ExceptionCheck()) {
        gEnv->ExceptionDescribe();
        gEnv->ExceptionClear();
        return;
    }

    jmethodID loadClass = gEnv->GetMethodID(
            classLoaderClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    jstring entryClassName = gEnv->NewStringUTF("es.chiteroman.playintegrityfix.EntryPoint");
    jobject entryClassObject = gEnv->CallObjectMethod(dexClassLoader, loadClass, entryClassName);
    if (gEnv->ExceptionCheck()) {
        gEnv->ExceptionDescribe();
        gEnv->ExceptionClear();
        return;
    }

    jclass entryPointClass = static_cast<jclass>(entryClassObject);
    jmethodID entryInit = gEnv->GetStaticMethodID(entryPointClass, "init", "(Ljava/lang/String;ZZZ)V");
    const std::string json = propMapToJson();
    jstring jsonString = gEnv->NewStringUTF(json.c_str());
    gEnv->CallStaticVoidMethod(entryPointClass, entryInit, jsonString, gConfig.spoofProvider,
                               gConfig.spoofSignature, gConfig.spoofBuild);
    if (gEnv->ExceptionCheck()) {
        gEnv->ExceptionDescribe();
        gEnv->ExceptionClear();
    }

    gEnv->DeleteLocalRef(jsonString);
    gEnv->DeleteLocalRef(entryClassObject);
    gEnv->DeleteLocalRef(entryClassName);
    gEnv->DeleteLocalRef(dexClassLoader);
    gEnv->DeleteLocalRef(inMemoryClassLoaderClass);
    gEnv->DeleteLocalRef(dexBuffer);
    gEnv->DeleteLocalRef(systemClassLoader);
    gEnv->DeleteLocalRef(classLoaderClass);
}

// Requests the profile routed to processName. Returns false when the process
// is unrouted (companion reports no match) or on any transport error; the
// caller then unloads the module from this process.
bool requestPayload(int fd, const std::string &processName) {
    if (fd < 0) {
        return false;
    }

    applySocketTimeout(fd);

    bool ok = writeExact(fd, &COMMAND_LOAD_PAYLOAD, sizeof(COMMAND_LOAD_PAYLOAD));
    ok = ok && writeString(fd, processName);
    bool companionOk = false;
    ok = ok && readExact(fd, &companionOk, sizeof(companionOk));
    if (!ok || !companionOk) {
        close(fd);
        return false;
    }

    ok = readConfig(fd, gConfig);
    if (ok && gConfig.needsDex()) {
        ok = readVector(fd, gDexBytes);
    } else {
        gDexBytes.clear();
    }

    close(fd);
    if (!ok) {
        gDexBytes.clear();
        gConfig = {};
        return false;
    }
    return true;
}

void companion(int fd) {
    applySocketTimeout(fd);

    bool ok = true;
    uint8_t command = 0;
    std::string processName;
    ok = ok && readExact(fd, &command, sizeof(command));
    ok = ok && command == COMMAND_LOAD_PAYLOAD;
    ok = ok && readString(fd, processName);

    std::vector<uint8_t> propBytes;
    std::vector<uint8_t> dexBytes;
    pif::Config config;
    bool routed = false;

    if (ok) {
        ok = loadPropBytes(propBytes);
    }
    if (ok) {
        const std::string_view propView(reinterpret_cast<const char *>(propBytes.data()), propBytes.size());
        const pif::ConfigBundle bundle = pif::parseBundle(propView);
        routed = bundle.routes.find(processName) != bundle.routes.end();
        if (routed) {
            config = pif::selectConfig(bundle, processName);
        }
    }
    if (ok && routed && config.needsDex()) {
        ok = readFileBytes(DEX_PATH, dexBytes);
    }

    // A false result (transport failure OR no route for this process) tells the
    // module to unload from the process without applying anything.
    const bool result = ok && routed;
    writeExact(fd, &result, sizeof(result));
    if (!result) {
        return;
    }

    ok = writeConfig(fd, config);
    if (ok && config.needsDex()) {
        ok = writeVector(fd, dexBytes);
    }

    if (!ok) {
        LOGE("[COMPANION] failed to send payload");
    }
}

}

using namespace zygisk;

class PlayIntegrityFix : public ModuleBase {
public:
    void onLoad(Api *api_, JNIEnv *env_) override {
        api = api_;
        env = env_;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        payloadLoaded = false;
        isVending = false;
        processName.clear();
        gConfig = {};
        gDexBytes.clear();

        if (!args) {
            api->setOption(DLCLOSE_MODULE_LIBRARY);
            return;
        }

        if (access("/data/adb/pif_script_only", F_OK) == 0) {
            api->setOption(DLCLOSE_MODULE_LIBRARY);
            return;
        }

        std::string dir;
        std::string name;

        const char *rawDir = env->GetStringUTFChars(args->app_data_dir, nullptr);
        if (rawDir) {
            dir = rawDir;
            env->ReleaseStringUTFChars(args->app_data_dir, rawDir);
        }

        const char *rawName = env->GetStringUTFChars(args->nice_name, nullptr);
        if (rawName) {
            name = rawName;
            env->ReleaseStringUTFChars(args->nice_name, rawName);
        }

        const std::string_view appDir(dir);
        bool inScope = false;
        for (const auto suffix : ALLOWED_PACKAGE_DIRS) {
            if (appDir.ends_with(suffix)) {
                inScope = true;
                break;
            }
        }
        if (!inScope) {
            api->setOption(DLCLOSE_MODULE_LIBRARY);
            return;
        }

        processName = name;
        isVending = processName == VENDING_PACKAGE;

        // The companion decides whether this exact process is routed; unrouted
        // processes yield payloadLoaded == false and are unloaded below.
        payloadLoaded = requestPayload(api->connectCompanion(), processName);
        if (!payloadLoaded) {
            api->setOption(DLCLOSE_MODULE_LIBRARY);
            return;
        }

        api->setOption(FORCE_DENYLIST_UNMOUNT);
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (!payloadLoaded) {
            return;
        }

        gEnv = env;

        if (isVending) {
            // Play Store certification path retains the SDK-clamp option.
            if (gConfig.spoofVendingBuild) {
                updateBuildFields();
            } else if (gConfig.spoofVendingSdk) {
                doSpoofVending();
            }
            return;
        }

        // Standard build-field path for every other routed process
        // (DroidGuard integrity, Messages RCS provisioning, etc.). Dex/provider
        // injection occurs only when the routed profile requests it, which the
        // RCS profile does not.
        if (gConfig.spoofBuild) {
            updateBuildFields();
        }

        if (gConfig.needsDex()) {
            injectDex();
        } else {
            LOGD("[INJECT] Dex payload skipped because spoofProvider and spoofSignature are false");
        }

        if (gConfig.spoofProps) {
            doHook();
        }
    }

    void preServerSpecialize(ServerSpecializeArgs *args) override {
        api->setOption(DLCLOSE_MODULE_LIBRARY);
    }

private:
    Api *api = nullptr;
    JNIEnv *env = nullptr;
    bool payloadLoaded = false;
    bool isVending = false;
    std::string processName;
};

REGISTER_ZYGISK_MODULE(PlayIntegrityFix)
REGISTER_ZYGISK_COMPANION(companion)
