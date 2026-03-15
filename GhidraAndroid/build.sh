#!/usr/bin/env bash
# build.sh – Build the GhidraDroid APK using Android SDK tools directly.
#
# This script compiles the GhidraDroid Android application without the
# Android Gradle Plugin (AGP), using only the command-line tools bundled
# with the Android SDK.  It is the fallback build path for environments
# where Google Maven (dl.google.com) is not accessible and AGP cannot be
# downloaded.
#
# Prerequisites:
#   - ANDROID_HOME or ANDROID_SDK_ROOT must point to the Android SDK.
#   - Android SDK Platform 34 must be installed.
#   - Android SDK Build-Tools 34.0.0 (or later) must be installed.
#   - Java 11+ (javac, keytool) must be on PATH.
#
# Usage:
#   cd GhidraAndroid
#   ./build.sh
#
# The signed debug APK is written to build/manual/GhidraDroid-debug.apk.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# -----------------------------------------------------------------------
# Resolve Android SDK
# -----------------------------------------------------------------------
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [ -z "$SDK" ]; then
    echo "ERROR: ANDROID_HOME (or ANDROID_SDK_ROOT) is not set." >&2
    exit 1
fi
if [ ! -d "$SDK" ]; then
    echo "ERROR: Android SDK directory not found: $SDK" >&2
    exit 1
fi

# Build-tools 34.0.0 (prefer the highest available 34.x)
BUILD_TOOLS_DIR=""
for bt in "$SDK/build-tools/34.0.0" "$SDK/build-tools/34.0.1" \
          "$SDK/build-tools/35.0.0" "$SDK/build-tools/35.0.1"; do
    if [ -d "$bt" ]; then
        BUILD_TOOLS_DIR="$bt"
        break
    fi
done
if [ -z "$BUILD_TOOLS_DIR" ]; then
    echo "ERROR: No suitable build-tools found under $SDK/build-tools." >&2
    exit 1
fi

# Android platform jar (compile against API 34)
ANDROID_JAR=""
for platform in "$SDK/platforms/android-34" "$SDK/platforms/android-33"; do
    if [ -f "$platform/android.jar" ]; then
        ANDROID_JAR="$platform/android.jar"
        break
    fi
done
if [ -z "$ANDROID_JAR" ]; then
    echo "ERROR: android.jar not found. Install platform android-34 via sdkmanager." >&2
    exit 1
fi

AIDL="$BUILD_TOOLS_DIR/aidl"
AAPT2="$BUILD_TOOLS_DIR/aapt2"
D8="$BUILD_TOOLS_DIR/d8"
APKSIGNER="$BUILD_TOOLS_DIR/apksigner"

echo "=== GhidraDroid Build ==="
echo "SDK:          $SDK"
echo "Build-tools:  $BUILD_TOOLS_DIR"
echo "android.jar:  $ANDROID_JAR"
echo ""

# -----------------------------------------------------------------------
# Directory layout
# -----------------------------------------------------------------------
SRC_MAIN="$SCRIPT_DIR/src/main"
JAVA_SRC="$SRC_MAIN/java"
AIDL_SRC="$SRC_MAIN/aidl"
RES_DIR="$SRC_MAIN/res"
MANIFEST="$SRC_MAIN/AndroidManifest.xml"

BUILD_DIR="$SCRIPT_DIR/build/manual"
GEN_DIR="$BUILD_DIR/gen"         # AIDL-generated Java
COMPILED_RES="$BUILD_DIR/res_compiled"
R_JAVA_DIR="$BUILD_DIR/R"
CLASSES_DIR="$BUILD_DIR/classes"
APK_UNSIGNED="$BUILD_DIR/GhidraDroid-unsigned.apk"
APK_ALIGNED="$BUILD_DIR/GhidraDroid-aligned.apk"
APK_SIGNED="$BUILD_DIR/GhidraDroid-debug.apk"
KEYSTORE="$BUILD_DIR/debug.keystore"

rm -rf "$BUILD_DIR"
mkdir -p "$GEN_DIR" "$COMPILED_RES" "$R_JAVA_DIR" "$CLASSES_DIR"

# -----------------------------------------------------------------------
# Step 1 – Compile AIDL interface
# -----------------------------------------------------------------------
echo "[1/7] Compiling AIDL..."
AIDL_FILE="$AIDL_SRC/ghidra/android/IGhidraAnalysisService.aidl"
"$AIDL" -I"$AIDL_SRC" -p"$SDK/platforms/android-34/framework.aidl" \
    "$AIDL_FILE" -o "$GEN_DIR"
echo "      OK – generated Java stubs in $GEN_DIR"

# -----------------------------------------------------------------------
# Step 2 – Compile resources with aapt2
# -----------------------------------------------------------------------
echo "[2/7] Compiling resources..."
# Collect all layout, menu, values XML files
find "$RES_DIR" \( -name "*.xml" -o -name "*.png" -o -name "*.9.png" \) | while read -r res_file; do
    "$AAPT2" compile "$res_file" -o "$COMPILED_RES"
done
echo "      OK – compiled resources in $COMPILED_RES"

# -----------------------------------------------------------------------
# Step 3 – Link resources and generate R.java
# -----------------------------------------------------------------------
echo "[3/7] Linking resources (aapt2 link)..."
FLAT_FILES=$(find "$COMPILED_RES" -name "*.flat" | tr '\n' ' ')
"$AAPT2" link \
    -o "$APK_UNSIGNED" \
    -I "$ANDROID_JAR" \
    --manifest "$MANIFEST" \
    --java "$R_JAVA_DIR" \
    --min-sdk-version 26 \
    --target-sdk-version 34 \
    --version-code 1 \
    --version-name "1.0" \
    $FLAT_FILES
echo "      OK – unsigned APK skeleton: $APK_UNSIGNED"
echo "      OK – R.java generated in $R_JAVA_DIR"

# -----------------------------------------------------------------------
# Step 4 – Compile Java sources
# -----------------------------------------------------------------------
echo "[4/7] Compiling Java sources..."

# Collect all Java source files (main + AIDL-generated + R.java)
JAVA_FILES=$(find "$JAVA_SRC" "$GEN_DIR" "$R_JAVA_DIR" -name "*.java" | tr '\n' ' ')

# Note: We use -source 8 -target 8 without -bootclasspath so that
# the JDK's java.lang.invoke.LambdaMetafactory is available for lambda
# compilation.  The android.jar is provided via -classpath which supplies
# all android.* and remaining java.* stubs.
javac \
    -source 8 -target 8 \
    -classpath "$ANDROID_JAR" \
    -d "$CLASSES_DIR" \
    -encoding UTF-8 \
    -Xlint:none \
    $JAVA_FILES
echo "      OK – compiled .class files in $CLASSES_DIR"

# -----------------------------------------------------------------------
# Step 5 – Convert class files to DEX (d8)
# -----------------------------------------------------------------------
echo "[5/7] Converting to DEX..."
CLASS_FILES=$(find "$CLASSES_DIR" -name "*.class" | tr '\n' ' ')
"$D8" \
    --output "$BUILD_DIR" \
    --lib "$ANDROID_JAR" \
    --min-api 26 \
    $CLASS_FILES
echo "      OK – classes.dex in $BUILD_DIR"

# -----------------------------------------------------------------------
# Step 6 – Add DEX to APK
# -----------------------------------------------------------------------
echo "[6/7] Packaging DEX into APK..."
cp "$APK_UNSIGNED" "$APK_ALIGNED"
# aapt2 link already created the APK; we just need to add classes.dex
(cd "$BUILD_DIR" && zip -j "$APK_ALIGNED" classes.dex)
echo "      OK – DEX added to APK"

# -----------------------------------------------------------------------
# Step 7 – Sign the APK with a debug key
# -----------------------------------------------------------------------
echo "[7/7] Signing APK..."

# Create a debug keystore if one doesn't already exist
if [ ! -f "$KEYSTORE" ]; then
    keytool -genkey -v \
        -keystore "$KEYSTORE" \
        -alias androiddebugkey \
        -storepass android \
        -keypass android \
        -keyalg RSA \
        -keysize 2048 \
        -validity 10000 \
        -dname "CN=Android Debug,O=Android,C=US" \
        2>/dev/null
fi

"$APKSIGNER" sign \
    --ks "$KEYSTORE" \
    --ks-key-alias androiddebugkey \
    --ks-pass pass:android \
    --key-pass pass:android \
    --out "$APK_SIGNED" \
    "$APK_ALIGNED"

echo ""
echo "=== Build successful! ==="
echo "APK: $APK_SIGNED"
du -h "$APK_SIGNED"

# -----------------------------------------------------------------------
# Bonus: Run unit tests if JUnit is available
# -----------------------------------------------------------------------
TEST_SRC="$SCRIPT_DIR/src/test/java"
if [ -d "$TEST_SRC" ]; then
    JUNIT_JAR=""
    HAMCREST_JAR=""
    # Look for JUnit 4 JARs in common locations
    for dir in "$HOME/.m2/repository/junit/junit/4.13.2" \
               "$SCRIPT_DIR" /tmp; do
        [ -f "$dir/junit-4.13.2.jar" ]    && JUNIT_JAR="$dir/junit-4.13.2.jar"
        [ -f "$dir/hamcrest-core-1.3.jar" ] && HAMCREST_JAR="$dir/hamcrest-core-1.3.jar"
    done

    if [ -n "$JUNIT_JAR" ] && [ -n "$HAMCREST_JAR" ]; then
        echo ""
        echo "=== Running unit tests ==="
        TEST_CLASSES="$BUILD_DIR/test_classes"
        mkdir -p "$TEST_CLASSES"
        javac -source 8 -target 8 \
            -classpath "$ANDROID_JAR:$CLASSES_DIR:$JUNIT_JAR" \
            -d "$TEST_CLASSES" -Xlint:none \
            $(find "$TEST_SRC" -name "*.java")
        java -cp "$ANDROID_JAR:$CLASSES_DIR:$TEST_CLASSES:$JUNIT_JAR:$HAMCREST_JAR" \
            org.junit.runner.JUnitCore \
            ghidra.android.GhidraAnalysisServiceTest \
            ghidra.android.BinaryInfoActivityTest \
            ghidra.android.DecompilerViewActivityTest
    else
        echo ""
        echo "Tip: Place junit-4.13.2.jar and hamcrest-core-1.3.jar in /tmp to run unit tests."
    fi
fi
