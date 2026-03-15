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

/**
 * AIDL interface for the GhidraAnalysisService.
 *
 * Clients bind to GhidraAnalysisService and use this interface to:
 *  - Import and analyze a binary file
 *  - Query analysis results (decompiled output, binary metadata)
 *  - Cancel running operations
 *
 * All long-running calls are asynchronous; callers should listen for
 * ACTION_ANALYSIS_PROGRESS broadcasts to track progress.
 */
interface IGhidraAnalysisService {

    /**
     * Returns true if an analysis is currently in progress.
     */
    boolean isAnalysisRunning();

    /**
     * Returns the decompiled text of a function identified by its address
     * (hex string, e.g. "0x00401000"), or null if not yet available.
     */
    String getDecompiledFunction(String addressHex);

    /**
     * Returns a JSON string describing the binary metadata (architecture,
     * entry points, sections, imports/exports), or null if not yet available.
     */
    String getBinaryInfo();

    /**
     * Returns the current status message.
     */
    String getStatusMessage();

    /**
     * Requests cancellation of any in-progress analysis. Non-blocking.
     */
    void cancelAnalysis();

    /**
     * Lists all project names stored in the app's private files directory,
     * as a JSON array of strings.
     */
    String listProjects();

    /**
     * Deletes the named project and all its associated files.
     * Returns true on success, false otherwise.
     */
    boolean deleteProject(String projectName);
}
