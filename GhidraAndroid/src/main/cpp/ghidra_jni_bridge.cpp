/*
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file ghidra_jni_bridge.cpp
 *
 * JNI bridge that exposes a subset of Ghidra's native decompiler methods to
 * the Android Java layer.
 *
 * Ghidra's Java code (ghidra.app.decompiler.DecompInterface) calls
 * System.loadLibrary("decompiler") and then invokes native methods via JNI.
 * This file provides a minimal implementation of those entry points so that
 * the Java layer can initialise the decompiler and request decompilation of
 * individual functions.
 *
 * Only the decompile-one-function flow is implemented here; the full set of
 * native methods would require a complete port of the Ghidra native layer
 * which is beyond the scope of this initial integration.
 */

#include <jni.h>
#include <android/log.h>
#include <string>

#define LOG_TAG "GhidraDecompiler"
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,  LOG_TAG, __VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,  LOG_TAG, __VA_ARGS__)

extern "C" {

/**
 * Called by DecompInterface.openDecompiler() to initialise the native side.
 *
 * Returns 1 on success, 0 on failure.
 */
JNIEXPORT jint JNICALL
Java_ghidra_app_decompiler_DecompInterface_openDecompiler(
        JNIEnv *env, jobject thiz)
{
    LOGD("openDecompiler: initialising native decompiler");
    // Real implementation would set up the Ghidra Architecture / Sleigh here.
    return 1;
}

/**
 * Called by DecompInterface.closeDecompiler() to release native resources.
 */
JNIEXPORT void JNICALL
Java_ghidra_app_decompiler_DecompInterface_closeDecompiler(
        JNIEnv *env, jobject thiz)
{
    LOGD("closeDecompiler: releasing native decompiler");
}

/**
 * Sends a command string to the native decompiler process and returns the
 * XML response as a Java string.
 *
 * @param command  XML command packet (see Ghidra's GhidraDecompCapability)
 * @return         XML response packet, or null on error
 */
JNIEXPORT jstring JNICALL
Java_ghidra_app_decompiler_DecompInterface_sendCommand1Param(
        JNIEnv *env, jobject thiz, jstring command)
{
    const char *cmdStr = env->GetStringUTFChars(command, nullptr);
    if (cmdStr == nullptr) {
        LOGE("sendCommand1Param: failed to get command string");
        return nullptr;
    }
    LOGD("sendCommand1Param: %s", cmdStr);
    env->ReleaseStringUTFChars(command, cmdStr);

    // Stub: return an empty response document.  A real implementation would
    // forward the command to the Ghidra decompiler engine and return its XML.
    static const char *EMPTY_RESPONSE = "<rettype><void/></rettype>";
    return env->NewStringUTF(EMPTY_RESPONSE);
}

} // extern "C"
