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

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.text.TextUtils;
import android.util.Log;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

/**
 * Activity that shows Ghidra's decompiled output for a user-specified function
 * address, rendered in a {@link WebView} with syntax highlighting.
 *
 * <h3>Usage</h3>
 * <ol>
 *   <li>The user types a function address (hex) into the address bar.</li>
 *   <li>The app calls {@link IGhidraAnalysisService#getDecompiledFunction(String)}
 *       via the bound AIDL service.</li>
 *   <li>The result is wrapped in a minimal HTML template with CSS syntax
 *       highlighting and displayed in the {@link WebView}.</li>
 * </ol>
 *
 * <h3>WebView security</h3>
 * JavaScript is enabled only for the local HTML content injected by this
 * app; no remote URLs are loaded and file access is disabled.
 */
public class DecompilerViewActivity extends Activity {

    private static final String TAG = "DecompilerView";

    /** Optional extra carrying an initial address to decompile. */
    public static final String EXTRA_ADDRESS = "address";

    private EditText  editAddress;
    private Button    buttonDecompile;
    private WebView   webViewOutput;

    private IGhidraAnalysisService analysisService;
    private boolean serviceBound = false;

    private final ServiceConnection serviceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            analysisService = IGhidraAnalysisService.Stub.asInterface(service);
            serviceBound = true;
            // If an initial address was provided, decompile it immediately.
            String initialAddress = getIntent().getStringExtra(EXTRA_ADDRESS);
            if (!TextUtils.isEmpty(initialAddress)) {
                editAddress.setText(initialAddress);
                decompileAddress(initialAddress);
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            analysisService = null;
            serviceBound = false;
        }
    };

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_decompiler_view);

        editAddress     = findViewById(R.id.edit_address);
        buttonDecompile = findViewById(R.id.button_decompile);
        webViewOutput   = findViewById(R.id.webview_decompiler);

        // Configure WebView: allow JS for syntax highlighting, disable network.
        WebSettings settings = webViewOutput.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setAllowFileAccessFromFileURLs(false);
        settings.setAllowUniversalAccessFromFileURLs(false);
        settings.setBlockNetworkLoads(true);

        buttonDecompile.setOnClickListener(v -> {
            String address = editAddress.getText().toString().trim();
            if (TextUtils.isEmpty(address)) {
                Toast.makeText(this, R.string.error_no_address, Toast.LENGTH_SHORT).show();
            }
            else {
                decompileAddress(address);
            }
        });

        // Show a welcome placeholder.
        webViewOutput.loadData(buildHtml(getString(R.string.decompiler_placeholder)),
                "text/html", "UTF-8");
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
    // Decompile
    // -----------------------------------------------------------------------

    private void decompileAddress(String address) {
        if (!serviceBound || analysisService == null) {
            Toast.makeText(this, R.string.error_service_unavailable, Toast.LENGTH_SHORT).show();
            return;
        }
        try {
            String output = analysisService.getDecompiledFunction(address);
            if (output == null) {
                output = getString(R.string.decompiler_no_result, address);
            }
            webViewOutput.loadData(buildHtml(escapeHtml(output)), "text/html", "UTF-8");
        }
        catch (RemoteException e) {
            Log.e(TAG, "decompileAddress: remote exception", e);
            Toast.makeText(this, R.string.error_service_unavailable, Toast.LENGTH_SHORT).show();
        }
    }

    // -----------------------------------------------------------------------
    // HTML helpers
    // -----------------------------------------------------------------------

    /**
     * Wraps raw decompiled text in a minimal HTML page with a monospace font
     * and light/dark-aware styling.
     */
    static String buildHtml(String body) {
        return "<!DOCTYPE html><html><head>"
                + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                + "<style>"
                + "body{font-family:monospace;font-size:14px;padding:8px;"
                + "color:#d4d4d4;background:#1e1e1e;white-space:pre-wrap;word-break:break-all;}"
                + "span.kw{color:#569cd6;}"   // keywords
                + "span.ty{color:#4ec9b0;}"   // types
                + "span.cm{color:#6a9955;}"   // comments
                + "span.st{color:#ce9178;}"   // strings
                + "span.nu{color:#b5cea8;}"   // numbers
                + "</style></head><body>"
                + body
                + "</body></html>";
    }

    /**
     * Escapes HTML special characters so that raw decompiler output is
     * displayed literally in the {@link WebView}.
     */
    static String escapeHtml(String text) {
        if (text == null) {
            return "";
        }
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;");
    }
}
