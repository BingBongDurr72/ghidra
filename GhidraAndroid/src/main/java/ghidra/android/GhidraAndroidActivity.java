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

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

/**
 * Main entry-point Activity for Ghidra on Android (GhidraDroid).
 *
 * <p>This Activity provides a minimal UI that lets the user:
 * <ul>
 *   <li>Pick a binary file via the system file picker or receive one via an
 *       incoming {@link Intent#ACTION_VIEW} / {@link Intent#ACTION_SEND} intent.</li>
 *   <li>Submit the selected file to {@link GhidraAnalysisService} for headless
 *       analysis.</li>
 *   <li>Navigate to the {@link ProjectDashboardActivity} to manage saved
 *       Ghidra projects.</li>
 *   <li>Navigate to the {@link BinaryInfoActivity} or
 *       {@link DecompilerViewActivity} once analysis is complete.</li>
 * </ul>
 *
 * <p>All heavy analysis work is intentionally kept out of the UI thread;
 * progress and results are delivered back via {@link BroadcastReceiver}
 * that this Activity registers while it is in the started state.
 */
public class GhidraAndroidActivity extends AppCompatActivity {

    /** Broadcast action sent by {@link GhidraAnalysisService} with progress updates. */
    public static final String ACTION_ANALYSIS_PROGRESS =
            "ghidra.android.ACTION_ANALYSIS_PROGRESS";

    /** Broadcast extra key carrying a human-readable status message. */
    public static final String EXTRA_STATUS_MESSAGE = "status_message";

    // -----------------------------------------------------------------------
    // UI elements
    // -----------------------------------------------------------------------
    private TextView statusTextView;
    private Button selectFileButton;
    private Button analyzeButton;
    private Button projectsButton;
    private Button viewResultsButton;

    /** URI of the binary selected for analysis (may be null). */
    private Uri selectedFileUri;

    /** True once analysis has completed at least once this session. */
    private boolean analysisComplete = false;

    // -----------------------------------------------------------------------
    // BroadcastReceiver – receives status updates from GhidraAnalysisService
    // -----------------------------------------------------------------------

    private final BroadcastReceiver analysisProgressReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (!ACTION_ANALYSIS_PROGRESS.equals(intent.getAction())) {
                return;
            }
            String message = intent.getStringExtra(EXTRA_STATUS_MESSAGE);
            if (message != null) {
                statusTextView.setText(message);
            }
            // Re-enable the analyze button and reveal the results button
            // when analysis has finished (either successfully or with an error).
            if (message != null &&
                    (message.equals(getString(R.string.status_analysis_complete)) ||
                     message.equals(getString(R.string.status_analysis_cancelled)) ||
                     message.startsWith(getString(R.string.error_analysis_failed_prefix)))) {
                analyzeButton.setEnabled(selectedFileUri != null);
                if (message.equals(getString(R.string.status_analysis_complete))) {
                    analysisComplete = true;
                    viewResultsButton.setEnabled(true);
                }
            }
        }
    };

    // -----------------------------------------------------------------------
    // File-picker launcher
    // -----------------------------------------------------------------------
    private final ActivityResultLauncher<Intent> filePickerLauncher =
            registerForActivityResult(
                    new ActivityResultContracts.StartActivityForResult(),
                    result -> {
                        if (result.getResultCode() == Activity.RESULT_OK &&
                                result.getData() != null) {
                            selectedFileUri = result.getData().getData();
                            if (selectedFileUri != null) {
                                analyzeButton.setEnabled(true);
                                String fileName = selectedFileUri.getLastPathSegment();
                                statusTextView.setText(
                                        getString(R.string.status_file_selected, fileName));
                            }
                        }
                    });

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_ghidra_android);

        statusTextView   = findViewById(R.id.text_status);
        selectFileButton = findViewById(R.id.button_select_file);
        analyzeButton    = findViewById(R.id.button_analyze);
        projectsButton   = findViewById(R.id.button_projects);
        viewResultsButton = findViewById(R.id.button_view_results);

        analyzeButton.setEnabled(false);
        viewResultsButton.setEnabled(false);

        selectFileButton.setOnClickListener(v -> openFilePicker());
        analyzeButton.setOnClickListener(v -> startAnalysis());
        projectsButton.setOnClickListener(v -> openProjectDashboard());
        viewResultsButton.setOnClickListener(v -> openBinaryInfo());

        // Handle binary files shared from other apps (VIEW / SEND intent)
        handleIncomingIntent(getIntent());
    }

    @Override
    protected void onStart() {
        super.onStart();
        // Register the receiver while the Activity is at least started so
        // that updates received in the background still reach us when the
        // user returns to the app.
        IntentFilter filter = new IntentFilter(ACTION_ANALYSIS_PROGRESS);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(analysisProgressReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
        }
        else {
            registerReceiver(analysisProgressReceiver, filter);
        }
    }

    @Override
    protected void onStop() {
        super.onStop();
        unregisterReceiver(analysisProgressReceiver);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleIncomingIntent(intent);
    }

    // -----------------------------------------------------------------------
    // Navigation helpers
    // -----------------------------------------------------------------------

    /** Opens the {@link ProjectDashboardActivity}. */
    private void openProjectDashboard() {
        startActivity(new Intent(this, ProjectDashboardActivity.class));
    }

    /** Opens the {@link BinaryInfoActivity} to display metadata. */
    private void openBinaryInfo() {
        startActivity(new Intent(this, BinaryInfoActivity.class));
    }

    // -----------------------------------------------------------------------
    // File picking & analysis
    // -----------------------------------------------------------------------

    /**
     * Opens the system file picker so the user can choose a binary to analyze.
     */
    private void openFilePicker() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("application/octet-stream");
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        filePickerLauncher.launch(Intent.createChooser(intent,
                getString(R.string.chooser_title)));
    }

    /**
     * Handles an incoming {@link Intent#ACTION_VIEW} or {@link Intent#ACTION_SEND}
     * that carries a binary file URI from another app.
     *
     * @param intent the received intent; may be null
     */
    private void handleIncomingIntent(Intent intent) {
        if (intent == null) {
            return;
        }
        String action = intent.getAction();
        if (Intent.ACTION_VIEW.equals(action) || Intent.ACTION_SEND.equals(action)) {
            Uri uri = intent.getData();
            if (uri == null && Intent.ACTION_SEND.equals(action)) {
                uri = intent.getParcelableExtra(Intent.EXTRA_STREAM);
            }
            if (uri != null) {
                selectedFileUri = uri;
                analyzeButton.setEnabled(true);
                statusTextView.setText(
                        getString(R.string.status_file_selected,
                                uri.getLastPathSegment()));
            }
        }
    }

    /**
     * Sends the selected file URI to {@link GhidraAnalysisService} for
     * headless analysis.
     */
    private void startAnalysis() {
        if (selectedFileUri == null) {
            Toast.makeText(this, R.string.error_no_file_selected, Toast.LENGTH_SHORT).show();
            return;
        }

        analyzeButton.setEnabled(false);
        viewResultsButton.setEnabled(false);
        analysisComplete = false;
        statusTextView.setText(R.string.status_analysis_started);

        Intent serviceIntent = new Intent(this, GhidraAnalysisService.class);
        serviceIntent.setData(selectedFileUri);
        startForegroundService(serviceIntent);
    }
}
