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

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.net.Uri;
import android.os.IBinder;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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
 *   <li>Promotes itself to a <em>foreground</em> service immediately on start
 *       so that the OS does not kill it during a long analysis run.</li>
 * </ul>
 *
 * <h3>Limitations on Android</h3>
 * Ghidra's GUI components (all {@code javax.swing.*} code) are not available
 * on Android's ART/Dalvik runtime.  This service therefore relies exclusively
 * on the <em>headless</em> analysis path ({@code ghidra.app.util.headless})
 * which has no Swing dependency.
 */
public class GhidraAnalysisService extends Service {

    private static final String TAG = "GhidraAnalysisService";

    private static final String CHANNEL_ID   = "ghidra_analysis";
    private static final int    NOTIF_ID     = 1;

    /** Executor that processes one file at a time. */
    private ExecutorService executor;

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

        // Run the analysis off the main thread.
        executor.execute(() -> runAnalysis(fileUri, startId));

        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        executor.shutdownNow();
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null; // Not a bound service
    }

    // -----------------------------------------------------------------------
    // Analysis
    // -----------------------------------------------------------------------

    /**
     * Copies the file at {@code fileUri} to the app cache directory and then
     * runs Ghidra headless analysis against it.
     *
     * @param fileUri  content URI pointing at the binary to analyze
     * @param startId  service start ID; passed to {@link #stopSelf(int)} when done
     */
    private void runAnalysis(Uri fileUri, int startId) {
        broadcast(getString(R.string.status_copying_file));

        File cachedFile;
        try {
            cachedFile = copyUriToCache(fileUri);
        }
        catch (IOException e) {
            Log.e(TAG, "Failed to copy file for analysis", e);
            broadcast(getString(R.string.error_copy_failed, e.getMessage()));
            stopSelf(startId);
            return;
        }

        broadcast(getString(R.string.status_analysis_started));
        Log.i(TAG, "Starting headless analysis on: " + cachedFile.getAbsolutePath());

        try {
            runHeadlessAnalysis(cachedFile);
            broadcast(getString(R.string.status_analysis_complete));
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
            stopSelf(startId);
        }
    }

    /**
     * Invokes Ghidra's headless analysis engine on the given local file.
     *
     * <p>On Android, Ghidra is run via its programmatic Java API rather than
     * the {@code analyzeHeadless} shell script.  The project is created in the
     * app's private files directory to stay within the Android storage sandbox.
     *
     * @param binaryFile the local binary file to analyze
     * @throws Exception if Ghidra initialisation or analysis fails
     */
    private void runHeadlessAnalysis(File binaryFile) throws Exception {
        // Ghidra project directory lives inside the app's private files area.
        File projectDir = new File(getFilesDir(), "ghidra_projects");
        if (!projectDir.exists() && !projectDir.mkdirs()) {
            throw new IOException("Cannot create Ghidra project directory: " + projectDir);
        }

        String projectName = "android_analysis";

        /*
         * Build the argument list that mirrors the analyzeHeadless command:
         *
         *   analyzeHeadless <projectDir> <projectName> \
         *       -import <binaryFile> \
         *       -deleteproject
         *
         * The -deleteproject flag ensures no leftover project files accumulate
         * in the app's storage between runs.
         */
        String[] args = {
            "ghidra.app.util.headless.AnalyzeHeadless",
            projectDir.getAbsolutePath(),
            projectName,
            "-import",
            binaryFile.getAbsolutePath(),
            "-deleteproject"
        };

        /*
         * GhidraLauncher.launch() discovers all modules on the classpath and
         * then delegates to the AnalyzeHeadless entry point.  On Android, the
         * Ghidra JARs must be bundled inside the APK (see build.gradle) and
         * placed on the class path before this call.
         */
        ghidra.GhidraLauncher.launch(args);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * Copies the content addressed by {@code uri} into the app's cache
     * directory and returns a reference to the temporary file.
     *
     * @param uri  source content URI
     * @return     a {@link File} in the app cache directory
     * @throws IOException on any I/O error
     */
    private File copyUriToCache(Uri uri) throws IOException {
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
     * Sends a local broadcast carrying {@code message} as a status update.
     *
     * @param message human-readable status string
     */
    private void broadcast(String message) {
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
