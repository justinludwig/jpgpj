package org.c02e.jpgpj.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

class UtilTest {

    @Nested
    class IsEmpty {

        @Test
        void charArrayIsEmptyWhenNullOrBlank() {
            assertTrue(Util.isEmpty((char[]) null));
            assertTrue(Util.isEmpty(new char[0]));
        }

        @Test
        void charArrayIsNotEmptyWhenNotBlank() {
            assertFalse(Util.isEmpty(new char[] { 0 }));
        }

        @Test
        void stringIsEmptyWhenNullOrBlank() {
            assertTrue(Util.isEmpty((String) null));
            assertTrue(Util.isEmpty(""));
        }

        @Test
        void stringIsNotEmptyWhenNotBlank() {
            assertFalse(Util.isEmpty("0"));
        }

        @Test
        void collectionIsEmptyWhenNullOrEmpty() {
            assertTrue(Util.isEmpty((java.util.Collection<?>) null));
            assertTrue(Util.isEmpty(Collections.emptyList()));
        }

        @Test
        void collectionIsNotEmptyWhenNotEmpty() {
            assertFalse(Util.isEmpty(List.of(0)));
        }

        @Test
        void mapIsEmptyWhenNullOrEmpty() {
            assertTrue(Util.isEmpty((Map<?, ?>) null));
            assertTrue(Util.isEmpty(Collections.emptyMap()));
        }

        @Test
        void mapIsNotEmptyWhenNotEmpty() {
            Map<String, Object> map = new HashMap<>();
            map.put("", null);
            assertFalse(Util.isEmpty(map));
        }
    }

    @Nested
    class FormatAsHex {

        @Test
        void nullOrEmptyReturnsEmptyString() {
            assertEquals("", Util.formatAsHex(null));
            assertEquals("", Util.formatAsHex(new byte[0]));
        }

        @Test
        void encodesBytesAsUpperCaseHex() {
            assertEquals("0F10", Util.formatAsHex(new byte[] {0x0f, 0x10}));
        }
    }

    @Nested
    class FormatKeyId {

        @Test
        void nullKeyFormatsAsZero() {
            assertEquals("0x0000000000000000", Util.formatKeyId(null));
        }

        @Test
        void zeroKeyFormatsAsZero() {
            assertEquals("0x0000000000000000", Util.formatKeyId(0L));
        }

        @Test
        void keyFormatsAsUpperCaseHexPaddedTo16Chars() {
            assertEquals("0x00000000000004D2", Util.formatKeyId(1234L));
        }

        @Test
        void biggestKeyFormatsCorrectly() {
            assertEquals("0xFFFFFFFFFFFFFFFF", Util.formatKeyId(0xffffffffffffffffL));
        }
    }

    @Nested
    class BestFileBufferSize {

        @ParameterizedTest(name = "fileSize={0}, maxSize={1} -> {2}")
        @CsvSource({
                "-1, -1, 1",
                "-1, 0, 1",
                "-1, 1, 1",
                "0, -1, 1",
                "0, 0, 1",
                "0, 1, 1",
                "1, -1, 1",
                "1, 0, 1",
                "1, 1, 1",
        })
        void isNoSmallerThanOne(long fileSize, int maxSize, int expectedSize) {
            assertEquals(expectedSize, Util.bestFileBufferSize(fileSize, maxSize));
        }

        @ParameterizedTest(name = "fileSize={0}, maxSize={1} -> {2}")
        @MethodSource("noLargerThanFileSizeCases")
        void isNoLargerThanFileSize(long fileSize, int maxSize, int expectedSize) {
            assertEquals(expectedSize, Util.bestFileBufferSize(fileSize, maxSize));
        }

        static Stream<Arguments> noLargerThanFileSizeCases() {
            int max = Integer.MAX_VALUE;
            return Stream.of(
                    Arguments.of(-1L, max, 1),
                    Arguments.of(0L, max, 1),
                    Arguments.of(1L, max, 1),
                    Arguments.of(0x1000L, max, 0x1000),
                    Arguments.of(0xffffL, max, 0xffff),
                    Arguments.of(0x10000L, max, 0x10000),
                    Arguments.of(0xfffffL, max, 0xfffff),
                    Arguments.of(0x100000L, max, 0x100000),
                    Arguments.of(0x100001L, max, 0x100001),
                    Arguments.of(0x10000000L, max, 0x10000000),
                    Arguments.of(0xffffffffL, max, Integer.MAX_VALUE),
                    Arguments.of(0x100000000000L, max, Integer.MAX_VALUE)
            );
        }

        @ParameterizedTest(name = "fileSize={0}, maxSize={1} -> {2}")
        @MethodSource("noLargerThanMaxBufferSizeCases")
        void isNoLargerThanMaxBufferSize(long fileSize, int maxSize, int expectedSize) {
            assertEquals(expectedSize, Util.bestFileBufferSize(fileSize, maxSize));
        }

        static Stream<Arguments> noLargerThanMaxBufferSizeCases() {
            long fileSize = Long.MAX_VALUE;
            return Stream.of(
                    Arguments.of(fileSize, -1, 1),
                    Arguments.of(fileSize, 0, 1),
                    Arguments.of(fileSize, 1, 1),
                    Arguments.of(fileSize, 0x1000, 0x1000),
                    Arguments.of(fileSize, 0xffff, 0xffff),
                    Arguments.of(fileSize, 0x10000, 0x10000),
                    Arguments.of(fileSize, 0xfffff, 0xfffff),
                    Arguments.of(fileSize, 0x100000, 0x100000),
                    Arguments.of(fileSize, 0x100001, 0x100001),
                    Arguments.of(fileSize, 0x10000000, 0x10000000),
                    Arguments.of(fileSize, Integer.MAX_VALUE, Integer.MAX_VALUE),
                    Arguments.of(fileSize, Integer.MIN_VALUE, 1)
            );
        }
    }
}
