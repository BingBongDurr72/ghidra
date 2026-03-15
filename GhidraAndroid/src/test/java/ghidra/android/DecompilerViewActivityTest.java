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
 * Unit tests for {@link DecompilerViewActivity} HTML-generation helpers.
 *
 * These tests run on the host JVM (no Android runtime required) and verify
 * that the HTML escaping and template functions are correct.
 */
public class DecompilerViewActivityTest {

    // -----------------------------------------------------------------------
    // escapeHtml
    // -----------------------------------------------------------------------

    @Test
    public void escapeHtml_null_returnsEmpty() {
        assertEquals("", DecompilerViewActivity.escapeHtml(null));
    }

    @Test
    public void escapeHtml_ampersand() {
        assertEquals("a &amp; b", DecompilerViewActivity.escapeHtml("a & b"));
    }

    @Test
    public void escapeHtml_lessThan() {
        assertEquals("a &lt; b", DecompilerViewActivity.escapeHtml("a < b"));
    }

    @Test
    public void escapeHtml_greaterThan() {
        assertEquals("a &gt; b", DecompilerViewActivity.escapeHtml("a > b"));
    }

    @Test
    public void escapeHtml_quote() {
        assertEquals("&quot;hello&quot;", DecompilerViewActivity.escapeHtml("\"hello\""));
    }

    @Test
    public void escapeHtml_noSpecialChars_unchanged() {
        String input = "int foo(int x) { return x + 1; }";
        assertEquals(input, DecompilerViewActivity.escapeHtml(input));
    }

    @Test
    public void escapeHtml_complexSnippet_allEntitiesEscaped() {
        String input = "if (a < b && c > d) { x = \"hello\"; }";
        String escaped = DecompilerViewActivity.escapeHtml(input);
        assertFalse(escaped.contains("<"));
        assertFalse(escaped.contains(">"));
        assertFalse(escaped.contains("&b"));   // raw ampersand from &&
        assertFalse(escaped.contains("\""));
        assertTrue(escaped.contains("&lt;"));
        assertTrue(escaped.contains("&gt;"));
        assertTrue(escaped.contains("&amp;"));
        assertTrue(escaped.contains("&quot;"));
    }

    // -----------------------------------------------------------------------
    // buildHtml
    // -----------------------------------------------------------------------

    @Test
    public void buildHtml_containsDoctype() {
        String html = DecompilerViewActivity.buildHtml("test");
        assertTrue(html.startsWith("<!DOCTYPE html>"));
    }

    @Test
    public void buildHtml_bodyContentIncluded() {
        String body = "int main() {}";
        String html = DecompilerViewActivity.buildHtml(body);
        assertTrue(html.contains(body));
    }

    @Test
    public void buildHtml_containsMonospaceStyle() {
        String html = DecompilerViewActivity.buildHtml("");
        assertTrue("CSS should specify monospace font",
                html.contains("monospace"));
    }
}
