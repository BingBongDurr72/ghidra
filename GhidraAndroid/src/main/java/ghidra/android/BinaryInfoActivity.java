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

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * Activity that displays binary metadata retrieved from
 * {@link GhidraAnalysisService} after analysis completes.
 *
 * <p>Metadata is presented in a simple key–value list:
 * <ul>
 *   <li>File name and size</li>
 *   <li>Architecture and endianness</li>
 *   <li>Entry point address</li>
 *   <li>Associated Ghidra project name</li>
 * </ul>
 *
 * <p>A "View Decompiled Code" button launches {@link DecompilerViewActivity}
 * so the user can navigate functions.
 */
public class BinaryInfoActivity extends AppCompatActivity {

    private static final String TAG = "BinaryInfoActivity";

    /** Optional extra: name of the project to display info for. */
    public static final String EXTRA_PROJECT_NAME = "project_name";

    private TextView textFileName;
    private TextView textFileSize;
    private TextView textArchitecture;
    private TextView textEndianness;
    private TextView textEntryPoint;
    private TextView textProjectName;
    private Button   buttonOpenDecompiler;

    private IGhidraAnalysisService analysisService;
    private boolean serviceBound = false;

    private final ServiceConnection serviceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            analysisService = IGhidraAnalysisService.Stub.asInterface(service);
            serviceBound = true;
            loadBinaryInfo();
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            analysisService = null;
            serviceBound = false;
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_binary_info);

        textFileName       = findViewById(R.id.text_file_name);
        textFileSize       = findViewById(R.id.text_file_size);
        textArchitecture   = findViewById(R.id.text_architecture);
        textEndianness     = findViewById(R.id.text_endianness);
        textEntryPoint     = findViewById(R.id.text_entry_point);
        textProjectName    = findViewById(R.id.text_project_name);
        buttonOpenDecompiler = findViewById(R.id.button_open_decompiler);

        buttonOpenDecompiler.setOnClickListener(v -> openDecompilerView());
    }

    @Override
    protected void onStart() {
        super.onStart();
        Intent intent = new Intent(this, GhidraAnalysisService.class);
        bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE);
    }

    @Override
    protected void onStop() {
        super.onStop();
        if (serviceBound) {
            unbindService(serviceConnection);
            serviceBound = false;
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private void loadBinaryInfo() {
        if (!serviceBound || analysisService == null) {
            return;
        }
        try {
            String json = analysisService.getBinaryInfo();
            if (json == null || json.equals("{}")) {
                Toast.makeText(this, R.string.error_no_binary_info, Toast.LENGTH_SHORT).show();
                return;
            }
            populateViews(json);
        }
        catch (RemoteException e) {
            Log.e(TAG, "loadBinaryInfo: remote exception", e);
            Toast.makeText(this, R.string.error_service_unavailable, Toast.LENGTH_SHORT).show();
        }
    }

    private void populateViews(String json) {
        try {
            JSONObject obj = new JSONObject(json);
            textFileName.setText(obj.optString("file_name",   getString(R.string.value_unknown)));
            long sizeBytes = obj.optLong("file_size", -1);
            textFileSize.setText(sizeBytes >= 0
                    ? formatFileSize(sizeBytes)
                    : getString(R.string.value_unknown));
            textArchitecture.setText(obj.optString("architecture", getString(R.string.value_unknown)));
            textEndianness.setText(obj.optString("endianness",     getString(R.string.value_unknown)));
            textEntryPoint.setText(obj.optString("entry_point",    getString(R.string.value_unknown)));
            textProjectName.setText(obj.optString("project_name",  getString(R.string.value_unknown)));
        }
        catch (JSONException e) {
            Log.e(TAG, "populateViews: malformed JSON", e);
            Toast.makeText(this, R.string.error_malformed_binary_info, Toast.LENGTH_SHORT).show();
        }
    }

    /**
     * Formats a byte count as a human-readable string (e.g. "1.4 MB").
     */
    static String formatFileSize(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        else if (bytes < 1024 * 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        }
        else if (bytes < 1024L * 1024 * 1024) {
            return String.format("%.1f MB", bytes / (1024.0 * 1024));
        }
        else {
            return String.format("%.1f GB", bytes / (1024.0 * 1024 * 1024));
        }
    }

    private void openDecompilerView() {
        startActivity(new Intent(this, DecompilerViewActivity.class));
    }
}
