# ProGuard rules for GhidraDroid
#
# These rules prevent ProGuard/R8 from stripping classes that are loaded
# reflectively by Ghidra's module system or the Android framework.

# ---------------------------------------------------------------------------
# Ghidra module system uses Class.forName() and reflection extensively.
# Preserve all public Ghidra API classes.
# ---------------------------------------------------------------------------
-keep class ghidra.** { *; }
-keep interface ghidra.** { *; }
-keepclassmembers class ghidra.** { *; }

# ---------------------------------------------------------------------------
# AIDL-generated stub classes must not be renamed.
# ---------------------------------------------------------------------------
-keep class ghidra.android.IGhidraAnalysisService { *; }
-keep class ghidra.android.IGhidraAnalysisService$** { *; }

# ---------------------------------------------------------------------------
# Android framework – keep Activity / Service / BroadcastReceiver subclasses
# so the manifest declarations remain valid after shrinking.
# ---------------------------------------------------------------------------
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceiver

# ---------------------------------------------------------------------------
# AndroidX AppCompat – required for theme inheritance.
# Uncomment if AndroidX is re-enabled (see build.gradle dependencies).
# ---------------------------------------------------------------------------
# -keep class androidx.appcompat.** { *; }
# -dontwarn androidx.appcompat.**

# ---------------------------------------------------------------------------
# Material Components – required for button / text-appearance styles.
# Uncomment if Material Components are re-enabled (see build.gradle).
# ---------------------------------------------------------------------------
# -keep class com.google.android.material.** { *; }
# -dontwarn com.google.android.material.**

# ---------------------------------------------------------------------------
# WebView JavaScript interface (if added in future).
# ---------------------------------------------------------------------------
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}

# ---------------------------------------------------------------------------
# Suppress warnings for packages that are intentionally absent on Android
# (Swing, AWT, desktop-only JAXB, etc.).
# ---------------------------------------------------------------------------
-dontwarn javax.swing.**
-dontwarn java.awt.**
-dontwarn sun.**
-dontwarn com.sun.**
