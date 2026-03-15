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

import ghidra.GhidraApplicationLayout;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.util.Locale;
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
    private static final String VALUE_NOT_AVAILABLE = "Not available";
    private static final String VALUE_NOT_APPLICABLE = "Not applicable";
    private static final Object GHIDRA_INIT_LOCK = new Object();

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

    /** Name of the project containing the most recently analyzed program. */
    private final AtomicReference<String> lastProjectName = new AtomicReference<>(null);

    /** Name of the most recently analyzed program file in the project. */
    private final AtomicReference<String> lastProgramName = new AtomicReference<>(null);

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
            String projectName = lastProjectName.get();
            String programName = lastProgramName.get();
            if (addressHex == null || projectName == null || programName == null) {
                return null;
            }
            try {
                String decompiled = decompileFunctionFromProject(projectName, programName, addressHex);
                if (decompiled != null) {
                    lastDecompiledAddress.set(addressHex);
                    lastDecompiledOutput.set(decompiled);
                }
                return decompiled;
            }
            catch (Exception e) {
                Log.e(TAG, "Failed to decompile function at " + addressHex, e);
                return null;
            }
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
        lastProjectName.set(null);
        lastProgramName.set(null);

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
        ensureGhidraInitialized();

        // Ghidra project directory lives inside the app's private files area.
        File projectDir = getProjectsDir();
        String projectName = sanitizeProjectName(binaryFile.getName());
        GhidraProject project = null;
        Program program = null;
        try {
            project = GhidraProject.createProject(projectDir.getAbsolutePath(), projectName, false);
            program = project.importProgram(binaryFile);
            GhidraProject.analyze(program);
            project.save(program);

            String programName = program.getDomainFile().getName();
            lastProjectName.set(projectName);
            lastProgramName.set(programName);
            binaryInfoJson.set(buildBinaryInfoJson(program, binaryFile, projectName));

            Address defaultEntryPoint = findPreferredEntryPoint(program);
            if (defaultEntryPoint != null) {
                String addressHex = defaultEntryPoint.toString();
                String decompiled = decompileProgramFunction(program, addressHex);
                if (decompiled != null) {
                    lastDecompiledAddress.set(addressHex);
                    lastDecompiledOutput.set(decompiled);
                }
            }
        }
        finally {
            if (project != null && program != null) {
                project.close(program);
            }
            if (project != null) {
                project.close();
            }
        }
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
     * Builds a JSON object describing the binary using lightweight header
     * inspection that works even before a full Ghidra program object is
     * available.
     */
    static String buildBinaryInfoJson(File binaryFile, String projectName) {
        try {
            BinaryMetadata metadata = inspectBinary(binaryFile);
            JSONObject obj = new JSONObject();
            obj.put("file_name",    binaryFile.getName());
            obj.put("file_size",    binaryFile.length());
            obj.put("format",       metadata.format);
            obj.put("project_name", projectName);
            obj.put("architecture", metadata.architecture);
            obj.put("endianness",   metadata.endianness);
            obj.put("entry_point",  metadata.entryPoint);
            return obj.toString();
        }
        catch (JSONException e) {
            return "{}";
        }
    }

    private static String buildBinaryInfoJson(Program program, File binaryFile, String projectName) {
        try {
            BinaryMetadata fallback = inspectBinary(binaryFile);
            JSONObject obj = new JSONObject();
            obj.put("file_name", binaryFile.getName());
            obj.put("file_size", binaryFile.length());
            obj.put("format", coalesce(program.getExecutableFormat(), fallback.format));
            obj.put("project_name", projectName);
            obj.put("architecture", program.getLanguage().getProcessor().toString());
            obj.put("endianness", program.getLanguage().isBigEndian()
                    ? "Big endian"
                    : "Little endian");
            Address entryPoint = findPreferredEntryPoint(program);
            obj.put("entry_point", entryPoint != null
                    ? entryPoint.toString()
                    : fallback.entryPoint);
            return obj.toString();
        }
        catch (JSONException e) {
            return "{}";
        }
    }

    private static String coalesce(String primary, String fallback) {
        return (primary == null || primary.isBlank()) ? fallback : primary;
    }

    private void ensureGhidraInitialized() throws IOException {
        synchronized (GHIDRA_INIT_LOCK) {
            if (!Application.isInitialized()) {
                Application.initializeApplication(
                        new GhidraApplicationLayout(),
                        new HeadlessGhidraApplicationConfiguration());
            }
        }
    }

    private static Address findPreferredEntryPoint(Program program) {
        AddressIterator entryPoints = program.getSymbolTable().getExternalEntryPointIterator();
        if (entryPoints.hasNext()) {
            return entryPoints.next();
        }

        FunctionIterator functions = program.getFunctionManager().getFunctions(true);
        if (functions.hasNext()) {
            return functions.next().getEntryPoint();
        }

        return program.getImageBase();
    }

    private String decompileFunctionFromProject(String projectName, String programName, String addressHex)
            throws Exception {
        ensureGhidraInitialized();
        GhidraProject project = null;
        Program program = null;
        try {
            project = GhidraProject.openProject(getProjectsDir().getAbsolutePath(), projectName);
            program = project.openProgram("/", programName, true);
            return decompileProgramFunction(program, addressHex);
        }
        finally {
            if (project != null && program != null) {
                project.close(program);
            }
            if (project != null) {
                project.close();
            }
        }
    }

    private static String decompileProgramFunction(Program program, String addressHex) {
        Address address = program.getAddressFactory().getAddress(addressHex);
        if (address == null) {
            return null;
        }

        Function function = program.getFunctionManager().getFunctionContaining(address);
        if (function == null) {
            function = program.getFunctionManager().getFunctionAt(address);
        }
        if (function == null) {
            return null;
        }

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.setOptions(new DecompileOptions());
            decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(false);
            decompiler.setSimplificationStyle("decompile");
            if (!decompiler.openProgram(program)) {
                Log.w(TAG, "Decompiler failed to open program: " + decompiler.getLastMessage());
                return null;
            }

            DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
            if (!results.decompileCompleted()) {
                Log.w(TAG, "Decompiler did not complete: " + results.getErrorMessage());
                return null;
            }

            DecompiledFunction decompiledFunction = results.getDecompiledFunction();
            return decompiledFunction != null ? decompiledFunction.getC() : null;
        }
        finally {
            decompiler.dispose();
        }
    }

    private static BinaryMetadata inspectBinary(File binaryFile) {
        try (RandomAccessFile file = new RandomAccessFile(binaryFile, "r")) {
            long length = file.length();
            if (length < 4) {
                return BinaryMetadata.unknown();
            }

            byte[] magic = readBytes(file, 0, (int) Math.min(length, 16));
            if (isElf(magic)) {
                return inspectElf(file);
            }
            if (isDex(magic)) {
                return inspectDex(file);
            }

            BinaryMetadata peMetadata = inspectPe(file, magic);
            if (peMetadata != null) {
                return peMetadata;
            }

            BinaryMetadata machOMetadata = inspectMachO(file, magic);
            if (machOMetadata != null) {
                return machOMetadata;
            }

            if (isZip(magic)) {
                String archiveFormat =
                        binaryFile.getName().toLowerCase(Locale.US).endsWith(".apk")
                                ? "APK archive"
                                : "ZIP archive";
                return new BinaryMetadata(
                        archiveFormat,
                        VALUE_NOT_APPLICABLE,
                        VALUE_NOT_APPLICABLE,
                        VALUE_NOT_APPLICABLE);
            }
        }
        catch (IOException e) {
            Log.w(TAG, "inspectBinary: failed to read " + binaryFile, e);
        }
        return BinaryMetadata.unknown();
    }

    private static BinaryMetadata inspectElf(RandomAccessFile file) throws IOException {
        if (file.length() < 64) {
            return BinaryMetadata.unknown();
        }
        byte[] header = readBytes(file, 0, 64);
        boolean is64Bit = header[4] == 2;
        boolean littleEndian = header[5] != 2;
        int machine = readUnsignedShort(header, 18, littleEndian);
        long entryPoint = is64Bit
                ? readUnsignedLong(header, 24, littleEndian)
                : readUnsignedInt(header, 24, littleEndian);
        return new BinaryMetadata(
                is64Bit ? "ELF 64-bit" : "ELF 32-bit",
                describeElfMachine(machine),
                littleEndian ? "Little endian" : "Big endian",
                formatAddress(entryPoint, is64Bit ? 16 : 8));
    }

    private static BinaryMetadata inspectDex(RandomAccessFile file) throws IOException {
        if (file.length() < 44) {
            return BinaryMetadata.unknown();
        }
        byte[] header = readBytes(file, 0, 44);
        long endianTag = readUnsignedInt(header, 40, true);
        String endianness;
        if (endianTag == 0x12345678L) {
            endianness = "Little endian";
        }
        else if (endianTag == 0x78563412L) {
            endianness = "Big endian";
        }
        else {
            endianness = VALUE_NOT_AVAILABLE;
        }
        return new BinaryMetadata("DEX bytecode", "Dalvik/ART bytecode", endianness,
                VALUE_NOT_APPLICABLE);
    }

    private static BinaryMetadata inspectPe(RandomAccessFile file, byte[] magic) throws IOException {
        if (magic[0] != 'M' || magic[1] != 'Z') {
            return null;
        }
        if (file.length() < 64) {
            return null;
        }

        byte[] mzHeader = readBytes(file, 0, 64);
        long peOffset = readUnsignedInt(mzHeader, 0x3c, true);
        if (peOffset < 0 || peOffset + 44 > file.length()) {
            return null;
        }

        byte[] peHeader = readBytes(file, peOffset, 44);
        if (peHeader[0] != 'P' || peHeader[1] != 'E' || peHeader[2] != 0 || peHeader[3] != 0) {
            return null;
        }

        int machine = readUnsignedShort(peHeader, 4, true);
        int optionalMagic = readUnsignedShort(peHeader, 24, true);
        long entryPointRva = readUnsignedInt(peHeader, 40, true);
        String format;
        if (optionalMagic == 0x20b) {
            format = "PE32+";
        }
        else if (optionalMagic == 0x10b) {
            format = "PE32";
        }
        else {
            format = "Portable Executable";
        }

        return new BinaryMetadata(
                format,
                describePeMachine(machine),
                "Little endian",
                "RVA " + formatAddress(entryPointRva, 8));
    }

    private static BinaryMetadata inspectMachO(RandomAccessFile file, byte[] magic) throws IOException {
        long magicValue = readUnsignedInt(magic, 0, false);
        boolean littleEndian;
        boolean is64Bit;
        switch ((int) magicValue) {
            case 0xFEEDFACE:
                littleEndian = false;
                is64Bit = false;
                break;
            case 0xCEFAEDFE:
                littleEndian = true;
                is64Bit = false;
                break;
            case 0xFEEDFACF:
                littleEndian = false;
                is64Bit = true;
                break;
            case 0xCFFAEDFE:
                littleEndian = true;
                is64Bit = true;
                break;
            case 0xCAFEBABE:
            case 0xBEBAFECA:
                return new BinaryMetadata("Mach-O universal binary", VALUE_NOT_AVAILABLE,
                        magicValue == 0xBEBAFECA ? "Little endian" : "Big endian",
                        VALUE_NOT_AVAILABLE);
            default:
                return null;
        }

        if (file.length() < (is64Bit ? 32 : 28)) {
            return BinaryMetadata.unknown();
        }
        byte[] header = readBytes(file, 0, is64Bit ? 32 : 28);
        int cpuType = (int) readUnsignedInt(header, 4, littleEndian);
        return new BinaryMetadata(
                is64Bit ? "Mach-O 64-bit" : "Mach-O 32-bit",
                describeMachOCpu(cpuType),
                littleEndian ? "Little endian" : "Big endian",
                VALUE_NOT_AVAILABLE);
    }

    private static boolean isElf(byte[] magic) {
        if (magic.length < 4) {
            return false;
        }
        return magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F';
    }

    private static boolean isDex(byte[] magic) {
        if (magic.length < 4) {
            return false;
        }
        return magic[0] == 'd' && magic[1] == 'e' && magic[2] == 'x' && magic[3] == '\n';
    }

    private static boolean isZip(byte[] magic) {
        if (magic.length < 4) {
            return false;
        }
        return magic[0] == 'P' && magic[1] == 'K' &&
                (magic[2] == 3 || magic[2] == 5 || magic[2] == 7) &&
                (magic[3] == 4 || magic[3] == 6 || magic[3] == 8);
    }

    private static byte[] readBytes(RandomAccessFile file, long offset, int length) throws IOException {
        byte[] data = new byte[length];
        file.seek(offset);
        file.readFully(data);
        return data;
    }

    private static int readUnsignedShort(byte[] data, int offset, boolean littleEndian) {
        if (littleEndian) {
            return (data[offset] & 0xff) | ((data[offset + 1] & 0xff) << 8);
        }
        return ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
    }

    private static long readUnsignedInt(byte[] data, int offset, boolean littleEndian) {
        if (littleEndian) {
            return (data[offset] & 0xffL) |
                    ((data[offset + 1] & 0xffL) << 8) |
                    ((data[offset + 2] & 0xffL) << 16) |
                    ((data[offset + 3] & 0xffL) << 24);
        }
        return ((data[offset] & 0xffL) << 24) |
                ((data[offset + 1] & 0xffL) << 16) |
                ((data[offset + 2] & 0xffL) << 8) |
                (data[offset + 3] & 0xffL);
    }

    private static long readUnsignedLong(byte[] data, int offset, boolean littleEndian) {
        if (littleEndian) {
            return (data[offset] & 0xffL) |
                    ((data[offset + 1] & 0xffL) << 8) |
                    ((data[offset + 2] & 0xffL) << 16) |
                    ((data[offset + 3] & 0xffL) << 24) |
                    ((data[offset + 4] & 0xffL) << 32) |
                    ((data[offset + 5] & 0xffL) << 40) |
                    ((data[offset + 6] & 0xffL) << 48) |
                    ((data[offset + 7] & 0xffL) << 56);
        }
        return ((data[offset] & 0xffL) << 56) |
                ((data[offset + 1] & 0xffL) << 48) |
                ((data[offset + 2] & 0xffL) << 40) |
                ((data[offset + 3] & 0xffL) << 32) |
                ((data[offset + 4] & 0xffL) << 24) |
                ((data[offset + 5] & 0xffL) << 16) |
                ((data[offset + 6] & 0xffL) << 8) |
                (data[offset + 7] & 0xffL);
    }

    private static String describeElfMachine(int machine) {
        switch (machine) {
            case 0x03:
                return "x86";
            case 0x08:
                return "MIPS";
            case 0x14:
                return "PowerPC";
            case 0x28:
                return "ARM";
            case 0x3e:
                return "x86-64";
            case 0xb7:
                return "AArch64";
            case 0xf3:
                return "RISC-V";
            default:
                return String.format(Locale.US, "Machine 0x%04X", machine);
        }
    }

    private static String describePeMachine(int machine) {
        switch (machine) {
            case 0x014c:
                return "x86";
            case 0x01c0:
            case 0x01c4:
                return "ARM";
            case 0x8664:
                return "x86-64";
            case 0xaa64:
                return "AArch64";
            default:
                return String.format(Locale.US, "Machine 0x%04X", machine);
        }
    }

    private static String describeMachOCpu(int cpuType) {
        switch (cpuType) {
            case 7:
                return "x86";
            case 0x01000007:
                return "x86-64";
            case 12:
                return "ARM";
            case 0x0100000c:
                return "AArch64";
            case 18:
                return "PowerPC";
            default:
                return String.format(Locale.US, "CPU type 0x%08X", cpuType);
        }
    }

    private static String formatAddress(long address, int width) {
        return String.format(Locale.US, "0x%0" + width + "X", address);
    }

    private static final class BinaryMetadata {
        private final String format;
        private final String architecture;
        private final String endianness;
        private final String entryPoint;

        private BinaryMetadata(String format, String architecture, String endianness,
                String entryPoint) {
            this.format = format;
            this.architecture = architecture;
            this.endianness = endianness;
            this.entryPoint = entryPoint;
        }

        private static BinaryMetadata unknown() {
            return new BinaryMetadata("Unknown file type", VALUE_NOT_AVAILABLE,
                    VALUE_NOT_AVAILABLE, VALUE_NOT_AVAILABLE);
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
