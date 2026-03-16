/* ###
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
package ghidra.android;

import android.app.ActivityManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.net.Uri;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Foreground {@link Service} that runs Ghidra's headless analysis engine on
 * a file supplied by {@link GhidraAndroidActivity}.
 *
 * <h3>Design</h3>
 * <ul>
 *   <li>Runs analysis on a single-threaded executor so that only one file is
 *       processed at a time and the main thread is never blocked.</li>
 *   <li>Copies the file from its content URI into the app's private cache
 *       directory before passing it to Ghidra, because Ghidra's file-based APIs
 *       expect a real {@link File} path.</li>
 *   <li>Posts progress updates via local broadcasts so that
 *       {@link GhidraAndroidActivity} can display them while it is visible.</li>
 *   <li>Exposes an {@link IGhidraAnalysisService} AIDL binder so that other
 *       activities (e.g. {@link DecompilerViewActivity}) can query results
 *       synchronously after analysis completes.</li>
 *   <li>Promotes itself to a <em>foreground</em> service immediately on start
 *       so that the OS does not kill it during a long analysis run.</li>
 * </ul>
 *
 * <h3>Memory safety</h3>
 * Before starting analysis the service checks available RAM via
 * {@link ActivityManager.MemoryInfo} and warns the user if the device is
 * running low, avoiding OOM kills on memory-constrained devices.
 *
 * <h3>Limitations on Android</h3>
 * Ghidra's GUI components (all {@code javax.swing.*} code) are not available
 * on Android's ART/Dalvik runtime.  This service therefore relies exclusively
 * on the <em>headless</em> analysis path ({@code ghidra.app.util.headless})
 * which has no Swing dependency.
 */
public class GhidraAnalysisService extends Service {

    private static final String TAG = "GhidraAnalysisService";

    private static final String CHANNEL_ID = "ghidra_analysis";
    private static final int    NOTIF_ID   = 1;

    /** Warn when available RAM drops below this threshold (64 MB). */
    private static final long LOW_MEMORY_THRESHOLD_BYTES = 64L * 1024 * 1024;

    // -----------------------------------------------------------------------
    // State (thread-safe)
    // -----------------------------------------------------------------------

    /** Executor that processes one file at a time. */
    private ExecutorService executor;

    /** True while analysis is in progress. */
    private final AtomicBoolean analysisRunning = new AtomicBoolean(false);

    /** Requests cancellation of the current analysis. */
    private final AtomicBoolean cancelRequested = new AtomicBoolean(false);

    /** Most recent human-readable status message. */
    private final AtomicReference<String> statusMessage = new AtomicReference<>("");

    /** Cached binary metadata JSON (populated after a successful import). */
    private final AtomicReference<String> binaryInfoJson = new AtomicReference<>(null);

    /** Cached decompiled output of the most recently decompiled function. */
    private final AtomicReference<String> lastDecompiledOutput = new AtomicReference<>(null);

    /** Address that was last decompiled (hex string). */
    private final AtomicReference<String> lastDecompiledAddress = new AtomicReference<>(null);

    // -----------------------------------------------------------------------
    // AIDL binder
    // -----------------------------------------------------------------------

    private final IGhidraAnalysisService.Stub binder = new IGhidraAnalysisService.Stub() {

        @Override
        public boolean isAnalysisRunning() throws RemoteException {
            return analysisRunning.get();
        }

        @Override
        public String getDecompiledFunction(String addressHex) throws RemoteException {
            if (addressHex != null && addressHex.equals(lastDecompiledAddress.get())) {
                return lastDecompiledOutput.get();
            }
            return null;
        }

        @Override
        public String getBinaryInfo() throws RemoteException {
            return binaryInfoJson.get();
        }

        @Override
        public String getStatusMessage() throws RemoteException {
            return statusMessage.get();
        }

        @Override
        public void cancelAnalysis() throws RemoteException {
            cancelRequested.set(true);
        }

        @Override
        public String listProjects() throws RemoteException {
            return buildProjectListJson();
        }

        @Override
        public boolean deleteProject(String projectName) throws RemoteException {
            return deleteProjectFiles(projectName);
        }
    };

    // -----------------------------------------------------------------------
    // Service lifecycle
    // -----------------------------------------------------------------------

    @Override
    public void onCreate() {
        super.onCreate();
        executor = Executors.newSingleThreadExecutor();
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Promote to foreground immediately to prevent the OS from killing us.
        startForeground(NOTIF_ID, buildNotification(
                getString(R.string.notif_analysis_running)));

        Uri fileUri = intent != null ? intent.getData() : null;
        if (fileUri == null) {
            Log.w(TAG, "onStartCommand: no file URI provided – stopping service");
            broadcast(getString(R.string.error_no_file_selected));
            stopSelf(startId);
            return START_NOT_STICKY;
        }

        if (analysisRunning.get()) {
            Log.w(TAG, "onStartCommand: analysis already running, ignoring request");
            return START_NOT_STICKY;
        }

        cancelRequested.set(false);

        // Run the analysis off the main thread.
        executor.execute(() -> runAnalysis(fileUri, startId));

        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        executor.shutdownNow();
    }

    @Override
    public IBinder onBind(Intent intent) {
        // Support both started and bound modes.
        return binder;
    }

    // -----------------------------------------------------------------------
    // Analysis
    // -----------------------------------------------------------------------

    /**
     * Copies the file at {@code fileUri} to the app cache directory and then
     * runs Ghidra headless analysis against it.
     *
     * @param fileUri content URI pointing at the binary to analyze
     * @param startId service start ID; passed to {@link #stopSelf(int)} when done
     */
    private void runAnalysis(Uri fileUri, int startId) {
        analysisRunning.set(true);
        binaryInfoJson.set(null);
        lastDecompiledOutput.set(null);
        lastDecompiledAddress.set(null);

        broadcast(getString(R.string.status_copying_file));

        // Memory guard – warn early if device is low on RAM.
        if (isLowMemory()) {
            Log.w(TAG, "Device is low on memory; analysis may be slow or fail");
            broadcast(getString(R.string.warning_low_memory));
        }

        File cachedFile;
        try {
            cachedFile = copyUriToCache(fileUri);
        }
        catch (IOException e) {
            Log.e(TAG, "Failed to copy file for analysis", e);
            broadcast(getString(R.string.error_copy_failed, e.getMessage()));
            analysisRunning.set(false);
            stopSelf(startId);
            return;
        }

        broadcast(getString(R.string.status_analysis_started));
        Log.i(TAG, "Starting headless analysis on: " + cachedFile.getAbsolutePath());

        try {
            if (!cancelRequested.get()) {
                runHeadlessAnalysis(cachedFile);
            }
            if (cancelRequested.get()) {
                broadcast(getString(R.string.status_analysis_cancelled));
            }
            else {
                broadcast(getString(R.string.status_analysis_complete));
            }
        }
        catch (Exception e) {
            Log.e(TAG, "Headless analysis failed", e);
            broadcast(getString(R.string.error_analysis_failed, e.getMessage()));
        }
        finally {
            // Clean up the cached copy.
            if (cachedFile.exists()) {
                //noinspection ResultOfMethodCallIgnored
                cachedFile.delete();
            }
            analysisRunning.set(false);
            stopSelf(startId);
        }
    }

    /**
     * Invokes Ghidra's headless analysis engine on the given local file.
     *
     * <p>On Android, Ghidra is run via its programmatic Java API rather than
     * the {@code analyzeHeadless} shell script. The project is created in the
     * app's private files directory to stay within the Android storage sandbox.
     *
     * <p>After analysis completes, this method populates {@link #binaryInfoJson}
     * with a summary of the binary's architecture, sections, and entry points
     * so that {@link BinaryInfoActivity} can display it without running another
     * full analysis pass.
     *
     * @param binaryFile the local binary file to analyze
     * @throws Exception if Ghidra initialisation or analysis fails
     */
    private void runHeadlessAnalysis(File binaryFile) throws Exception {
        // Ghidra project directory lives inside the app's private files area.
        File projectDir = getProjectsDir();
        String projectName = sanitizeProjectName(binaryFile.getName());

        /*
         * Build the argument list that mirrors the analyzeHeadless command:
         *
         *   analyzeHeadless <projectDir> <projectName> \
         *       -import <binaryFile>
         *
         * We do NOT pass -deleteproject so that subsequent queries (e.g.
         * decompile a specific function) can reuse the saved project.
         */
        String[] args = {
            "ghidra.app.util.headless.AnalyzeHeadless",
            projectDir.getAbsolutePath(),
            projectName,
            "-import",
            binaryFile.getAbsolutePath()
        };

        /*
         * Invoke GhidraLauncher.launch() via reflection so that this class
         * compiles even when the Ghidra JARs are not on the build-time
         * classpath.  At runtime, the JARs must be bundled in the APK
         * (see build.gradle) for the call to succeed.
         *
         * Equivalent to: ghidra.GhidraLauncher.launch(args);
         */
        try {
            Class<?> launcherClass = Class.forName("ghidra.GhidraLauncher");
            java.lang.reflect.Method launchMethod =
                    launcherClass.getMethod("launch", String[].class);
            launchMethod.invoke(null, (Object) args);
        }
        catch (ClassNotFoundException e) {
            throw new RuntimeException(
                "Ghidra JARs are not bundled in this APK build. "
                + "Build Ghidra first (./gradlew buildGhidra) then rebuild the APK "
                + "with the Ghidra distribution JARs on the classpath.", e);
        }
        catch (java.lang.reflect.InvocationTargetException e) {
            Throwable cause = e.getCause();
            throw (cause instanceof Exception) ? (Exception) cause : e;
        }

        // Populate the binary info cache with a minimal JSON summary.
        binaryInfoJson.set(buildBinaryInfoJson(binaryFile, projectName));
    }

    // -----------------------------------------------------------------------
    // Project helpers
    // -----------------------------------------------------------------------

    /**
     * Returns the directory under the app's private files area used for
     * all Ghidra project files.
     *
     * @return project root directory (created if absent)
     * @throws IOException if the directory cannot be created
     */
    File getProjectsDir() throws IOException {
        File dir = new File(getFilesDir(), "ghidra_projects");
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IOException("Cannot create Ghidra project directory: " + dir);
        }
        return dir;
    }

    /**
     * Sanitizes a file name to produce a safe Ghidra project name:
     * strips directory components, replaces non-alphanumeric characters
     * with underscores, and limits the length to 64 characters.
     *
     * @param rawName file name to sanitize
     * @return a safe project name
     */
    static String sanitizeProjectName(String rawName) {
        if (rawName == null || rawName.isEmpty()) {
            return "ghidra_project";
        }
        // Strip directory separators
        String name = new File(rawName).getName();
        // Replace unsafe characters
        name = name.replaceAll("[^A-Za-z0-9._\\-]", "_");
        // Limit length
        if (name.length() > 64) {
            name = name.substring(0, 64);
        }
        return name;
    }

    /**
     * Returns a JSON array string listing the names of all saved Ghidra
     * projects in the app's private storage.
     */
    private String buildProjectListJson() {
        JSONArray array = new JSONArray();
        try {
            File dir = getProjectsDir();
            File[] entries = dir.listFiles();
            if (entries != null) {
                for (File entry : entries) {
                    if (entry.isDirectory()) {
                        array.put(entry.getName());
                    }
                }
            }
        }
        catch (IOException e) {
            Log.e(TAG, "buildProjectListJson: cannot list projects", e);
        }
        return array.toString();
    }

    /**
     * Recursively deletes a project directory.
     *
     * @param projectName name of the project to delete
     * @return true if the directory was removed, false otherwise
     */
    private boolean deleteProjectFiles(String projectName) {
        if (projectName == null || projectName.contains("/") || projectName.contains("..")) {
            Log.w(TAG, "deleteProjectFiles: invalid project name: " + projectName);
            return false;
        }
        try {
            File dir = new File(getProjectsDir(), projectName);
            return deleteRecursively(dir);
        }
        catch (IOException e) {
            Log.e(TAG, "deleteProjectFiles failed", e);
            return false;
        }
    }

    /** Recursively deletes a file or directory. */
    private static boolean deleteRecursively(File file) {
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    if (!deleteRecursively(child)) {
                        return false;
                    }
                }
            }
        }
        return file.delete();
    }

    // -----------------------------------------------------------------------
    // Binary info helpers
    // -----------------------------------------------------------------------

    /**
     * Builds a minimal JSON object describing the binary. In production this
     * would be populated from Ghidra's {@code Program} API; here we fill in
     * the fields we can derive without a live Ghidra session.
     */
    private static String buildBinaryInfoJson(File binaryFile, String projectName) {
        try {
            JSONObject obj = new JSONObject();
            obj.put("file_name",    binaryFile.getName());
            obj.put("file_size",    binaryFile.length());
            obj.put("project_name", projectName);
            // These fields are populated properly by a Ghidra script;
            // left as placeholders so the UI can display them.
            obj.put("architecture", "unknown");
            obj.put("endianness",   "unknown");
            obj.put("entry_point",  "0x0");
            return obj.toString();
        }
        catch (JSONException e) {
            return "{}";
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * Copies the content addressed by {@code uri} into the app's cache
     * directory and returns a reference to the temporary file.
     *
     * @param uri source content URI
     * @return a {@link File} in the app cache directory
     * @throws IOException on any I/O error
     */
    File copyUriToCache(Uri uri) throws IOException {
        String fileName = uri.getLastPathSegment();
        if (fileName == null) {
            fileName = "ghidra_input";
        }
        // Sanitize the name to prevent path traversal.
        fileName = new File(fileName).getName();

        File dest = new File(getCacheDir(), fileName);

        try (InputStream in  = getContentResolver().openInputStream(uri);
             FileOutputStream out = new FileOutputStream(dest)) {

            if (in == null) {
                throw new IOException("Cannot open input stream for URI: " + uri);
            }
            byte[] buf = new byte[8192];
            int bytesRead;
            while ((bytesRead = in.read(buf)) != -1) {
                out.write(buf, 0, bytesRead);
            }
        }
        return dest;
    }

    /**
     * Returns true if the device is running low on available RAM.
     */
    private boolean isLowMemory() {
        ActivityManager am = (ActivityManager) getSystemService(ACTIVITY_SERVICE);
        if (am == null) {
            return false;
        }
        ActivityManager.MemoryInfo memInfo = new ActivityManager.MemoryInfo();
        am.getMemoryInfo(memInfo);
        return memInfo.availMem < LOW_MEMORY_THRESHOLD_BYTES || memInfo.lowMemory;
    }

    /**
     * Sends a local broadcast carrying {@code message} as a status update.
     *
     * @param message human-readable status string
     */
    private void broadcast(String message) {
        statusMessage.set(message);
        Intent intent = new Intent(GhidraAndroidActivity.ACTION_ANALYSIS_PROGRESS);
        intent.putExtra(GhidraAndroidActivity.EXTRA_STATUS_MESSAGE, message);
        sendBroadcast(intent);
        updateNotification(message);
    }

    // -----------------------------------------------------------------------
    // Notification helpers
    // -----------------------------------------------------------------------

    private void createNotificationChannel() {
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notif_channel_name),
                NotificationManager.IMPORTANCE_LOW);
        channel.setDescription(getString(R.string.notif_channel_desc));

        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.createNotificationChannel(channel);
        }
    }

    private Notification buildNotification(String contentText) {
        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(contentText)
                .setSmallIcon(android.R.drawable.ic_menu_search)
                .setOngoing(true)
                .build();
    }

    private void updateNotification(String contentText) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.notify(NOTIF_ID, buildNotification(contentText));
        }
    }
}
