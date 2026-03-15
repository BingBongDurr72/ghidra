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
import android.app.AlertDialog;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;
import android.view.ContextMenu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONException;

import java.util.ArrayList;
import java.util.List;

/**
 * Activity that displays the list of saved Ghidra projects stored in the
 * app's private files directory.
 *
 * <p>Users can:
 * <ul>
 *   <li>See all existing projects.</li>
 *   <li>Open a project to navigate to {@link BinaryInfoActivity}.</li>
 *   <li>Delete a project via a context menu (long-press).</li>
 * </ul>
 *
 * <p>The project list is fetched from {@link GhidraAnalysisService} via the
 * {@link IGhidraAnalysisService} AIDL interface.
 */
public class ProjectDashboardActivity extends Activity {

    private static final String TAG = "ProjectDashboard";

    private TextView emptyView;
    private ListView projectListView;
    private ArrayAdapter<String> projectAdapter;
    private final List<String> projectNames = new ArrayList<>();

    private IGhidraAnalysisService analysisService;
    private boolean serviceBound = false;

    private final ServiceConnection serviceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            analysisService = IGhidraAnalysisService.Stub.asInterface(service);
            serviceBound = true;
            refreshProjectList();
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
        setContentView(R.layout.activity_project_dashboard);

        emptyView       = findViewById(R.id.text_no_projects);
        projectListView = findViewById(R.id.list_projects);

        projectAdapter = new ArrayAdapter<>(this,
                android.R.layout.simple_list_item_1, projectNames);
        projectListView.setAdapter(projectAdapter);

        projectListView.setOnItemClickListener((parent, view, position, id) ->
                openProject(projectNames.get(position)));

        registerForContextMenu(projectListView);
    }

    @Override
    protected void onStart() {
        super.onStart();
        // Bind to the service to fetch the project list via AIDL.
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
    // Context menu (long-press on list item)
    // -----------------------------------------------------------------------

    @Override
    public void onCreateContextMenu(ContextMenu menu, View v,
            ContextMenu.ContextMenuInfo menuInfo) {
        super.onCreateContextMenu(menu, v, menuInfo);
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.menu_project_context, menu);
    }

    @Override
    public boolean onContextItemSelected(MenuItem item) {
        AdapterView.AdapterContextMenuInfo info =
                (AdapterView.AdapterContextMenuInfo) item.getMenuInfo();
        if (info == null) {
            return super.onContextItemSelected(item);
        }
        String projectName = projectNames.get(info.position);
        if (item.getItemId() == R.id.action_delete_project) {
            confirmDeleteProject(projectName);
            return true;
        }
        return super.onContextItemSelected(item);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private void refreshProjectList() {
        if (!serviceBound || analysisService == null) {
            return;
        }
        try {
            String json = analysisService.listProjects();
            parseAndDisplayProjects(json);
        }
        catch (RemoteException e) {
            Log.e(TAG, "refreshProjectList: remote exception", e);
            Toast.makeText(this, R.string.error_service_unavailable, Toast.LENGTH_SHORT).show();
        }
    }

    private void parseAndDisplayProjects(String json) {
        projectNames.clear();
        if (json != null) {
            try {
                JSONArray array = new JSONArray(json);
                for (int i = 0; i < array.length(); i++) {
                    projectNames.add(array.getString(i));
                }
            }
            catch (JSONException e) {
                Log.e(TAG, "parseAndDisplayProjects: invalid JSON", e);
            }
        }
        projectAdapter.notifyDataSetChanged();
        boolean empty = projectNames.isEmpty();
        emptyView.setVisibility(empty ? View.VISIBLE : View.GONE);
        projectListView.setVisibility(empty ? View.GONE : View.VISIBLE);
    }

    private void openProject(String projectName) {
        Intent intent = new Intent(this, BinaryInfoActivity.class);
        intent.putExtra(BinaryInfoActivity.EXTRA_PROJECT_NAME, projectName);
        startActivity(intent);
    }

    private void confirmDeleteProject(String projectName) {
        new AlertDialog.Builder(this)
                .setTitle(R.string.dialog_delete_title)
                .setMessage(getString(R.string.dialog_delete_message, projectName))
                .setPositiveButton(R.string.action_delete, (dialog, which) ->
                        deleteProject(projectName))
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void deleteProject(String projectName) {
        if (!serviceBound || analysisService == null) {
            Toast.makeText(this, R.string.error_service_unavailable, Toast.LENGTH_SHORT).show();
            return;
        }
        try {
            boolean success = analysisService.deleteProject(projectName);
            if (success) {
                Toast.makeText(this,
                        getString(R.string.status_project_deleted, projectName),
                        Toast.LENGTH_SHORT).show();
                refreshProjectList();
            }
            else {
                Toast.makeText(this, R.string.error_delete_failed, Toast.LENGTH_SHORT).show();
            }
        }
        catch (RemoteException e) {
            Log.e(TAG, "deleteProject: remote exception", e);
            Toast.makeText(this, R.string.error_service_unavailable, Toast.LENGTH_SHORT).show();
        }
    }
}
