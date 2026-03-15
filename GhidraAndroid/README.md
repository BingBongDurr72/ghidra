# GhidraDroid – Ghidra on Android

GhidraDroid is an Android application that embeds Ghidra's headless reverse
engineering engine so users can load, analyze, and decompile Android binaries
(APK, DEX, ELF `.so`, firmware images) directly on their device without
requiring a separate desktop or server.

---

## Architecture

GhidraDroid follows the **Headless Backend + Native UI** approach (Option B
from the feasibility study):

```
┌─────────────────────────────────────────────────┐
│  Android UI layer (Activities)                  │
│   GhidraAndroidActivity   – launcher + file pick│
│   ProjectDashboardActivity – project management │
│   BinaryInfoActivity       – binary metadata    │
│   DecompilerViewActivity   – decompiled C code  │
└──────────────────┬──────────────────────────────┘
                   │  AIDL (IGhidraAnalysisService)
┌──────────────────▼──────────────────────────────┐
│  GhidraAnalysisService (foreground Service)     │
│   • Copies binary to app-private storage        │
│   • Calls GhidraLauncher.launch() (headless)    │
│   • Caches analysis results (JSON)              │
│   • Memory-guard via ActivityManager            │
└──────────────────┬──────────────────────────────┘
                   │  JNI
┌──────────────────▼──────────────────────────────┐
│  libdecompiler.so (NDK, C++11)                  │
│   • Built from Ghidra's decompiler sources      │
│   • Provides JNI bridge for DecompInterface     │
└─────────────────────────────────────────────────┘
```

### Key design decisions

| Concern | Decision |
|---|---|
| **Swing / AWT** | Not available on Android ART; only Ghidra's headless path is used. |
| **File access** | Android Storage Access Framework (SAF) → file copied to app-private cache. |
| **IPC** | AIDL (`IGhidraAnalysisService`) so that multiple Activities can query the running service. |
| **Background work** | Foreground `Service` + single-threaded `ExecutorService` – prevents ANR and OS kill. |
| **Memory safety** | `ActivityManager.getMemoryInfo()` check before analysis; warn user if RAM is low. |
| **Security** | Path sanitisation (`sanitizeProjectName`), no remote URLs in WebView, scoped storage. |
| **Native decompiler** | C++ sources compiled for `arm64-v8a` and `armeabi-v7a` via CMake + Android NDK. |

---

## Prerequisites

| Tool | Version |
|---|---|
| Android SDK | API 34 (compileSdk) |
| Android Gradle Plugin | 8.2.0 |
| Android NDK | r25 or later (optional, for native decompiler only) |
| Java | 17 |
| Ghidra | Build the main project first to produce the framework JARs |

Set `ANDROID_HOME` (or `ANDROID_SDK_ROOT`) and `ANDROID_NDK_HOME` before
building.

---

## Building

### 1. Build the main Ghidra project

GhidraDroid depends on Ghidra's headless JARs. Build the full Ghidra
distribution first:

```bash
# From the repository root
./gradlew buildGhidra
```

The JARs are placed under `build/dist/`. The `GhidraAndroid/build.gradle`
picks them up automatically from that location.

### 2. Build the Android APK

```bash
# From the GhidraAndroid directory (uses the bundled Gradle wrapper)
cd GhidraAndroid && ./gradlew assembleDebug

# Or from the repository root
GhidraAndroid/gradlew -p GhidraAndroid assembleDebug
```

The APK is written to:
```
GhidraAndroid/build/outputs/apk/debug/GhidraAndroid-debug.apk
```

#### Optional: Native decompiler

The C++ JNI bridge (`libdecompiler.so`) is disabled by default. To enable it,
pass `-PbuildNativeDecompiler=true` and ensure the Android NDK is installed:

```bash
cd GhidraAndroid && ./gradlew assembleDebug -PbuildNativeDecompiler=true
```

### 3. Install on a device

```bash
adb install GhidraAndroid/build/outputs/apk/debug/GhidraAndroid-debug.apk
```

---

## Usage

1. **Launch** the *Ghidra* app on your Android device.
2. Tap **Select Binary File…** and choose an APK, DEX, or ELF binary using
   the system file picker.  Alternatively, share a file from another app using
   Android's *Share* sheet (the app registers as a handler for
   `application/octet-stream`).
3. Tap **Analyze** – the app copies the file to private storage and starts
   Ghidra's headless analysis in a foreground service.  A notification is
   shown while analysis runs.
4. When analysis completes, tap **View Binary Info** to see the binary's
   architecture, endianness, entry point, and size.
5. From the binary info screen, tap **View Decompiled Code**, enter a function
   address (hex, e.g. `0x00401000`), and tap **Go** to see Ghidra's
   decompiled C output rendered with syntax highlighting.
6. Tap **Manage Projects** from the main screen to list, open, or delete
   saved Ghidra projects.

---

## Running the unit tests

The non-instrumented JVM tests (no Android device required) can be run with:

```bash
./gradlew :GhidraAndroid:test
```

These tests cover:

* `GhidraAnalysisServiceTest` – project-name sanitisation and path-traversal
  protection.
* `BinaryInfoActivityTest` – human-readable file-size formatting.
* `DecompilerViewActivityTest` – HTML escaping and template generation.

---

## Module structure

```
GhidraAndroid/
├── build.gradle                          Android application build script
├── settings.gradle                       Standalone build settings
├── gradlew                               Gradle wrapper (Gradle 8.14)
├── gradle/wrapper/                       Gradle wrapper binaries
├── proguard-rules.pro                    R8/ProGuard keep rules
├── README.md                             This file
└── src/
    ├── main/
    │   ├── AndroidManifest.xml           Permissions, activities, service
    │   ├── aidl/ghidra/android/
    │   │   └── IGhidraAnalysisService.aidl  IPC interface
    │   ├── cpp/
    │   │   ├── CMakeLists.txt            NDK build for libdecompiler.so
    │   │   └── ghidra_jni_bridge.cpp     JNI entry points
    │   ├── java/ghidra/android/
    │   │   ├── GhidraAndroidActivity.java   Launcher
    │   │   ├── GhidraAnalysisService.java   Headless analysis service
    │   │   ├── ProjectDashboardActivity.java  Project management
    │   │   ├── BinaryInfoActivity.java       Binary metadata view
    │   │   └── DecompilerViewActivity.java   Decompiler WebView
    │   └── res/
    │       ├── layout/                   XML layouts for each Activity
    │       ├── menu/                     Context menus
    │       └── values/                   strings.xml, themes.xml
    └── test/java/ghidra/android/
        ├── GhidraAnalysisServiceTest.java
        ├── BinaryInfoActivityTest.java
        └── DecompilerViewActivityTest.java
```

---

## Supported file formats

| Format | Notes |
|---|---|
| ELF (`.so`, bare ELF) | ARM, ARM64, x86, x86-64 |
| DEX | Android Dalvik / ART bytecode |
| APK | ZIP container; Ghidra extracts and analyzes `classes.dex` and native libs |
| Raw firmware | Analysed as raw binary; processor must be set manually |

---

## Permissions

| Permission | Reason |
|---|---|
| `READ_EXTERNAL_STORAGE` (API ≤ 32) | Legacy storage read for older Android versions |
| `READ_MEDIA_IMAGES` (API ≥ 33) | Granular media permission on Android 13+ |
| `FOREGROUND_SERVICE` | Keep analysis service alive during long analysis runs |
| `FOREGROUND_SERVICE_DATA_SYNC` | Required foreground service type on API 34+ |
| `INTERNET` / `ACCESS_NETWORK_STATE` | Optional: remote GhidraServer connectivity |

---

## Limitations

* **Swing / AWT not available** – only Ghidra's headless analysis pipeline is
  supported.  No interactive listing, no docking UI, no plugins that depend on
  `javax.swing`.
* **Memory** – Ghidra's analysis can require several hundred MB of RAM.
  GhidraDroid warns the user when available RAM drops below 64 MB and the app
  requests `android:largeHeap="true"`.  Very large binaries (> 100 MB) may
  cause OOM on low-end devices.
* **Decompiler output** – The current `IGhidraAnalysisService.getDecompiledFunction`
  implementation returns the cached result of a previous analysis run.  A
  full round-trip to the native decompiler (via the JNI bridge) requires
  completing the integration of `libdecompiler.so` with Ghidra's Java
  `DecompInterface`.
* **No disassembly listing** – A scrollable listing view (Phase 3, item 3
  from the design specification) is not yet implemented.  Use the decompiler
  view as an alternative.
* **No CFG / graph view** – Control-flow graph rendering (Phase 3, item 6)
  is listed as a future improvement (see below).
* **No settings screen** – Analysis depth, decompiler options, and theme
  customisation are not yet exposed in the UI.

---

## Future improvements

- [ ] Integrate `libdecompiler.so` fully with `ghidra.app.decompiler.DecompInterface`
      to decompile arbitrary functions at runtime.
- [ ] Add a scrollable disassembly listing (RecyclerView or WebView-based).
- [ ] Control-flow graph view using a JavaScript graph library (e.g. vis.js)
      embedded in a WebView.
- [ ] Settings screen: analysis options, decompiler timeout, light/dark theme.
- [ ] Implement cross-reference navigation (XREFs to/from functions).
- [ ] Support opening multiple projects simultaneously.
- [ ] Add Kotlin coroutine-based UI for smoother async progress updates.
- [ ] Publish signed APK to GitHub Releases.

---

## License

GhidraDroid is part of the Ghidra project and is released under the
[Apache License, Version 2.0](../LICENSE).
