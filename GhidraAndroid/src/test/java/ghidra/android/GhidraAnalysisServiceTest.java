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

import org.json.JSONObject;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;

import static org.junit.Assert.*;

/**
 * Unit tests for {@link GhidraAnalysisService} helper methods that can be
 * exercised on a standard JVM (no Android runtime or Ghidra jars required).
 */
public class GhidraAnalysisServiceTest {

    // -----------------------------------------------------------------------
    // sanitizeProjectName
    // -----------------------------------------------------------------------

    @Test
    public void sanitizeProjectName_normalName_unchanged() {
        assertEquals("mybinary.apk", GhidraAnalysisService.sanitizeProjectName("mybinary.apk"));
    }

    @Test
    public void sanitizeProjectName_pathTraversal_stripped() {
        // Directory separators must be removed so a caller cannot escape the
        // project directory by supplying something like "../../etc/passwd".
        String result = GhidraAnalysisService.sanitizeProjectName("../../etc/passwd");
        assertFalse("result should not contain '/'", result.contains("/"));
        assertFalse("result should not contain '..'", result.contains(".."));
    }

    @Test
    public void sanitizeProjectName_specialChars_replaced() {
        String result = GhidraAnalysisService.sanitizeProjectName("my binary (test).elf");
        // Spaces and parentheses should be replaced with underscores.
        assertFalse(result.contains(" "));
        assertFalse(result.contains("("));
        assertFalse(result.contains(")"));
    }

    @Test
    public void sanitizeProjectName_longName_truncated() {
        String longName = "a".repeat(100) + ".bin";
        String result = GhidraAnalysisService.sanitizeProjectName(longName);
        assertTrue("sanitized name must not exceed 64 chars", result.length() <= 64);
    }

    @Test
    public void sanitizeProjectName_nullInput_returnsDefault() {
        String result = GhidraAnalysisService.sanitizeProjectName(null);
        assertNotNull(result);
        assertFalse(result.isEmpty());
    }

    @Test
    public void sanitizeProjectName_emptyInput_returnsDefault() {
        String result = GhidraAnalysisService.sanitizeProjectName("");
        assertNotNull(result);
        assertFalse(result.isEmpty());
    }

    @Test
    public void sanitizeProjectName_alphanumericAndDots_kept() {
        // Dots, dashes and underscores are safe and should be preserved.
        assertEquals("lib-foo_1.2.3.so",
                GhidraAnalysisService.sanitizeProjectName("lib-foo_1.2.3.so"));
    }

    // -----------------------------------------------------------------------
    // buildBinaryInfoJson
    // -----------------------------------------------------------------------

    @Test
    public void buildBinaryInfoJson_elfHeader_reportsDetectedMetadata() throws Exception {
        File binary = writeTempBinary("sample", ".elf", new byte[] {
                0x7f, 'E', 'L', 'F',
                2, 1, 1, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                2, 0,
                (byte) 0xb7, 0x00,
                1, 0, 0, 0,
                0x00, 0x10, 0x40, 0x00, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0
        });

        JSONObject info = new JSONObject(GhidraAnalysisService.buildBinaryInfoJson(binary, "demo"));

        assertEquals("ELF 64-bit", info.getString("format"));
        assertEquals("AArch64", info.getString("architecture"));
        assertEquals("Little endian", info.getString("endianness"));
        assertEquals("0x0000000000401000", info.getString("entry_point"));
    }

    @Test
    public void buildBinaryInfoJson_peHeader_reportsDetectedMetadata() throws Exception {
        byte[] data = new byte[256];
        data[0] = 'M';
        data[1] = 'Z';
        data[0x3c] = (byte) 0x80;
        data[0x80] = 'P';
        data[0x81] = 'E';
        data[0x84] = 0x64;
        data[0x85] = (byte) 0x86;
        data[0x98] = 0x0b;
        data[0x99] = 0x02;
        data[0xa8] = 0x34;
        data[0xa9] = 0x12;
        File binary = writeTempBinary("sample", ".exe", data);

        JSONObject info = new JSONObject(GhidraAnalysisService.buildBinaryInfoJson(binary, "demo"));

        assertEquals("PE32+", info.getString("format"));
        assertEquals("x86-64", info.getString("architecture"));
        assertEquals("Little endian", info.getString("endianness"));
        assertEquals("RVA 0x00001234", info.getString("entry_point"));
    }

    @Test
    public void buildBinaryInfoJson_apkHeader_reportsArchiveMetadata() throws Exception {
        File binary = writeTempBinary("sample", ".apk", new byte[] { 'P', 'K', 3, 4, 0, 0, 0, 0 });

        JSONObject info = new JSONObject(GhidraAnalysisService.buildBinaryInfoJson(binary, "demo"));

        assertEquals("APK archive", info.getString("format"));
        assertEquals("Not applicable", info.getString("architecture"));
        assertEquals("Not applicable", info.getString("endianness"));
        assertEquals("Not applicable", info.getString("entry_point"));
    }

    private static File writeTempBinary(String prefix, String suffix, byte[] data) throws Exception {
        File file = File.createTempFile(prefix, suffix);
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(data);
        }
        file.deleteOnExit();
        return file;
    }
}
