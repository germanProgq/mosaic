#include <algorithm>
#include <jni.h>
#include <android/multinetwork.h>
#include <string>
#include <vector>
extern "C" {
#include "Bridge.h"
}

static std::vector<uint8_t> data(JNIEnv *env, jbyteArray value) {
    jsize size = env->GetArrayLength(value);
    if (size < 0 || size > 98304) { return {}; }
    std::vector<uint8_t> bytes(size);
    env->GetByteArrayRegion(value, 0, size, reinterpret_cast<jbyte *>(bytes.data()));
    return bytes;
}

extern "C" JNIEXPORT jboolean JNICALL Java_net_mosaic_client_Native_validate(JNIEnv *env, jclass, jbyteArray value) {
    auto bytes = data(env, value);
    return mosaic_validate_profile(bytes.data(), bytes.size()) == 1;
}

extern "C" JNIEXPORT jlong JNICALL Java_net_mosaic_client_Native_start(JNIEnv *env, jclass, jbyteArray value, jstring directory) {
    auto bytes = data(env, value);
    const char *path = env->GetStringUTFChars(directory, nullptr);
    if (!path) { return 0; }
    std::string storage(path);
    env->ReleaseStringUTFChars(directory, path);
    auto handle = mosaic_start_in(bytes.data(), bytes.size(), reinterpret_cast<const uint8_t *>(storage.data()), storage.size());
    std::fill(bytes.begin(), bytes.end(), 0);
    return handle;
}

extern "C" JNIEXPORT void JNICALL Java_net_mosaic_client_Native_stop(JNIEnv *, jclass, jlong handle) { mosaic_stop(handle); }
extern "C" JNIEXPORT jint JNICALL Java_net_mosaic_client_Native_socket(JNIEnv *, jclass, jlong handle) { return mosaic_socket(handle); }
extern "C" JNIEXPORT void JNICALL Java_net_mosaic_client_Native_socketReady(JNIEnv *, jclass, jlong handle, jint socket, jboolean ready) { mosaic_socket_ready(handle, socket, ready ? 1 : -1); }
extern "C" JNIEXPORT jboolean JNICALL Java_net_mosaic_client_Native_bindNetwork(JNIEnv *, jclass, jint socket, jlong network) { return android_setsocknetwork(network, socket) == 0; }
extern "C" JNIEXPORT jboolean JNICALL Java_net_mosaic_client_Native_needsNetwork(JNIEnv *, jclass, jlong handle) { return mosaic_needs_network(handle) == 1; }
extern "C" JNIEXPORT void JNICALL Java_net_mosaic_client_Native_networkReady(JNIEnv *, jclass, jlong handle, jboolean ready) { mosaic_network_ready(handle, ready ? 1 : -1); }
extern "C" JNIEXPORT void JNICALL Java_net_mosaic_client_Native_pathChanged(JNIEnv *, jclass, jlong handle) { mosaic_path_changed(handle); }

static jstring text(JNIEnv *env, jlong handle, bool settings) {
    uint8_t bytes[4096] = {};
    int count = settings ? mosaic_settings(handle, bytes, sizeof(bytes) - 1) : mosaic_status(handle, bytes, sizeof(bytes) - 1);
    if (count < 0) { return env->NewStringUTF("Connection unavailable"); }
    bytes[count] = 0;
    return env->NewStringUTF(reinterpret_cast<const char *>(bytes));
}

extern "C" JNIEXPORT jstring JNICALL Java_net_mosaic_client_Native_settings(JNIEnv *env, jclass, jlong handle) { return text(env, handle, true); }
extern "C" JNIEXPORT jstring JNICALL Java_net_mosaic_client_Native_status(JNIEnv *env, jclass, jlong handle) { return text(env, handle, false); }
extern "C" JNIEXPORT void JNICALL Java_net_mosaic_client_Native_writePacket(JNIEnv *env, jclass, jlong handle, jbyteArray value, jint length) {
    if (length <= 0 || length > 1100 || length > env->GetArrayLength(value)) { return; }
    uint8_t bytes[1100];
    env->GetByteArrayRegion(value, 0, length, reinterpret_cast<jbyte *>(bytes));
    mosaic_write_packet(handle, bytes, length);
}

extern "C" JNIEXPORT jint JNICALL Java_net_mosaic_client_Native_readPacket(JNIEnv *env, jclass, jlong handle, jbyteArray value) {
    uint8_t bytes[1100];
    if (env->GetArrayLength(value) < 1100) { return -1; }
    int count = mosaic_read_packet(handle, bytes, sizeof(bytes));
    if (count > 0) { env->SetByteArrayRegion(value, 0, count, reinterpret_cast<jbyte *>(bytes)); }
    return count;
}
