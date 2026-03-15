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
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

/**
 * Main entry-point Activity for Ghidra on Android.
 *
 * <p>This Activity provides a minimal UI that lets the user pick a binary
 * file and submit it to {@link GhidraAnalysisService} for headless analysis.
 * The analysis runs in a foreground {@link android.app.Service} so that it
 * is not killed when the user switches apps.
 *
 * <p>All heavy analysis work is intentionally kept out of the UI thread;
 * progress and results are delivered back via {@link android.content.Intent}
 * broadcasts that this Activity listens for while visible.
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

    /** URI of the binary selected for analysis (may be null). */
    private Uri selectedFileUri;

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

        statusTextView  = findViewById(R.id.text_status);
        selectFileButton = findViewById(R.id.button_select_file);
        analyzeButton   = findViewById(R.id.button_analyze);

        analyzeButton.setEnabled(false);

        selectFileButton.setOnClickListener(v -> openFilePicker());
        analyzeButton.setOnClickListener(v -> startAnalysis());

        // Handle binary files shared from other apps (VIEW / SEND intent)
        handleIncomingIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleIncomingIntent(intent);
    }

    // -----------------------------------------------------------------------
    // Helpers
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
        statusTextView.setText(R.string.status_analysis_started);

        Intent serviceIntent = new Intent(this, GhidraAnalysisService.class);
        serviceIntent.setData(selectedFileUri);
        startForegroundService(serviceIntent);
    }
}
