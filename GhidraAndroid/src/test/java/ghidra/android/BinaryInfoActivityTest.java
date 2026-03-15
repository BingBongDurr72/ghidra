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
 * Unit tests for {@link BinaryInfoActivity} helper methods that can be
 * exercised on a standard JVM without an Android device.
 */
public class BinaryInfoActivityTest {

    // -----------------------------------------------------------------------
    // formatFileSize
    // -----------------------------------------------------------------------

    @Test
    public void formatFileSize_bytes() {
        assertEquals("512 B", BinaryInfoActivity.formatFileSize(512));
    }

    @Test
    public void formatFileSize_kilobytes() {
        String result = BinaryInfoActivity.formatFileSize(1536); // 1.5 KB
        assertTrue("expected KB unit", result.endsWith("KB"));
        assertTrue("expected 1.5", result.contains("1.5"));
    }

    @Test
    public void formatFileSize_megabytes() {
        long onePointFiveMB = 1536L * 1024;
        String result = BinaryInfoActivity.formatFileSize(onePointFiveMB);
        assertTrue("expected MB unit", result.endsWith("MB"));
        assertTrue("expected 1.5", result.contains("1.5"));
    }

    @Test
    public void formatFileSize_gigabytes() {
        long oneGB = 1024L * 1024 * 1024;
        String result = BinaryInfoActivity.formatFileSize(oneGB);
        assertTrue("expected GB unit", result.endsWith("GB"));
        assertTrue("expected 1.0", result.contains("1.0"));
    }

    @Test
    public void formatFileSize_zero() {
        assertEquals("0 B", BinaryInfoActivity.formatFileSize(0));
    }
}
