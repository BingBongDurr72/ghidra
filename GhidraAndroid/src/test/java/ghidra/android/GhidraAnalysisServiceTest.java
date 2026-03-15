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

import org.junit.Test;

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
}
